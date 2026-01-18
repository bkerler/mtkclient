#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import logging
from binascii import hexlify
from struct import pack, unpack

from mtkclient.Library.exploit_handler import Exploitation
from mtkclient.Library.gui_utils import LogBase, progress


class Amonet(Exploitation, metaclass=LogBase):

    def __init__(self, mtk, loglevel=logging.INFO):
        super().__init__(mtk, loglevel)

    def exploit(self, payload, payloadaddr):
        pass

    def da_read_write(self, address, length, data=None, check_result=True):
        if self.chipconfig.blacklist:
            self.hwcrypto.disable_range_blacklist("gcpu", self.mtk)
        if data is None:
            data = bytearray()
            pg = progress(total=length, prefix='Read:')
            for addr in range(address, address + length, 16):
                data.extend(self.hwcrypto.gcpu.aes_read_cbc(addr))
                pg.update(16)
            return data
        else:
            pg = progress(total=length, prefix='Write:')
            for addr in range(address, address + length, 4):
                self.write32(data[addr - address:(addr - address) + 4])
                pg.update(4)

    def bruteforce(self, args, startaddr=0x9900):
        pass

    def newbrute(self, dump_ptr, dump=False):
        pass

    def payload(self, payload, daaddr):
        ptype = "gcpu"
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
        self.info("Amonet Run")
        if addr is None:
            addr = self.chipconfig.da_payload_addr
        if self.payload(payload, addr):
            if dontack:
                return ack
            result = self.usbread(4)
            if result == pack(">I", ack):
                return ack
            else:
                self.info("Error, payload answered instead: " + hexlify(result).decode('utf-8'))
        return None

    def dump_preloader(self, filename=None):
        btype = "gcpu"
        if filename is None:
            return None
        if self.chipconfig.gcpu_base is None:
            self.error("Chipconfig has no gcpu_base field for this cpu")
            return False
        if self.chipconfig.blacklist:
            self.hwcrypto.disable_range_blacklist(btype, self.mtk)
        self.info("Dump preloader")
        if filename is None:
            data = bytearray()
            for addr in range(0x200000, 0x240000, 16):
                if not self.chipconfig.blacklist:
                    data.extend(self.hwcrypto.gcpu.aes_read_cbc(addr))
                else:
                    data.extend(self.hwcrypto.gcpu.aes_read_cbc(addr))
            return data, filename
        else:
            pg = progress(total=0x40000, prefix='Dump preloader:')
            with open(filename, 'wb') as wf:
                for addr in range(0x200000, 0x240000, 16):
                    wf.write(self.hwcrypto.gcpu.aes_read_cbc(addr))
                    pg.update(16)
            pg.done()
            return True

    def dump_brom(self, filename, dump_ptr=None, length=0x20000):
        btype = "gcpu"
        if self.chipconfig.gcpu_base is None:
            self.error("Chipconfig has no gcpu_base field for this cpu")
            return False
        if self.chipconfig.blacklist:
            self.hwcrypto.disable_range_blacklist(btype, self.mtk)
        self.info("Dump bootrom")
        pg = progress(total=length, prefix='Dump brom:')
        with open(filename, 'wb') as wf:
            for addr in range(0x0, length, 16):
                wf.write(self.hwcrypto.gcpu.aes_read_cbc(addr))
                pg.update(16)
        pg.done()
        return True
