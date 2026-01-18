#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import logging
from struct import pack, unpack

from mtkclient.Library.exploit_handler import Exploitation
from mtkclient.Library.gui_utils import LogBase, progress


class Hashimoto(Exploitation, metaclass=LogBase):

    def __init__(self, mtk, loglevel=logging.INFO):
        super().__init__(mtk, loglevel)

    def exploit(self, payload, payloadaddr):
        pass

    def da_read_write(self, address, length, data=None, check_result=True):
        pass

    def bruteforce(self, args, startaddr=0x9900):
        pass

    def newbrute(self, dump_ptr, dump=False):
        pass

    def payload(self, payload, daaddr):
        ptype = "cqdma"
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
        self.info("Hashimoto Run")
        if addr is None:
            addr = self.chipconfig.da_payload_addr
        if self.payload(payload, addr):
            if dontack or self.usbread(4) == pack(">I", ack):
                return ack
        return None

    def dump_preloader(self, filename=None):
        btype = "cqdma"
        if self.chipconfig.cqdma_base is None or self.chipconfig.ap_dma_mem is None:
            self.error("Chipconfig has no cqdma_base and/or ap_dma_mem field for this cpu")
            return False
        if self.chipconfig.blacklist:
            self.hwcrypto.disable_range_blacklist(btype, self.mtk)
        self.info("Dump preloader")
        if filename is None:
            data = bytearray()
            for addr in range(0x200000, 0x240000, 16):
                data.extend(self.hwcrypto.Cqdma.mem_read(addr, 16, not self.chipconfig.blacklist))
            return data, filename
        else:
            pg = progress(prefix='Progress:', total=0x40000)
            with open(filename, 'wb') as wf:
                for addr in range(0x200000, 0x240000, 16):
                    wf.write(self.hwcrypto.Cqdma.mem_read(addr, 16, not self.chipconfig.blacklist))
                    pg.update(16)
            pg.done()
            return True

    def dump_brom(self, filename, dump_ptr=None, length=0x20000):
        btype = "cqdma"
        if self.chipconfig.cqdma_base is None or self.chipconfig.ap_dma_mem is None:
            self.error("Chipconfig has no cqdma_base and/or ap_dma_mem field for this cpu")
            return False
        if self.chipconfig.blacklist:
            self.hwcrypto.disable_range_blacklist(btype, self.mtk)
        self.info("Dump bootrom")
        pg = progress(prefix='Progress:', total=length)
        with open(filename, 'wb') as wf:
            for addr in range(0x0, length, 16):
                wf.write(self.hwcrypto.Cqdma.mem_read(addr, 16, not self.chipconfig.blacklist))
                pg.update(16)
        pg.done()
        return True
