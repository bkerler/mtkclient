#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2023
# GPLv3 License
import logging
import os
from io import BytesIO

from mtkclient.Library.gui_utils import structhelper_io
from mtkclient.Library.Partitions import generic


class bpi(generic):
    def __init__(self, rf, filesize: int, num_part_entries=0, part_entry_size=0, part_entry_start_lba=0,
                 loglevel=logging.INFO, *args, **kwargs):

        super().__init__(rf, filesize, num_part_entries, part_entry_size, part_entry_start_lba, loglevel, *args,
                         **kwargs)

    def parse(self) -> bool:
        hdr = self.rf.bytes(4)
        if hdr == b"BPI\x00":
            class partf:
                unique = b""
                first_lba = 0
                last_lba = 0
                flags = 0
                sector = 0
                sectors = 0
                type = b""
                name = ""
                entryoffset = 0

            self.sectorsize = 0x200
            self.totalsectors = 0
            self.partentries = []
            for pos in range(0x800, self.filesize, 0x80):
                self.rf.seek(pos)
                data = self.rf.bytes(0x80)
                if int(data[16:32].hex(), 16) == 0:
                    break

                rf = BytesIO(bytearray(data))
                pf = partf()
                rf.read(16)
                guid1 = int.from_bytes(rf.read(4), 'little')
                guid2 = int.from_bytes(rf.read(2), 'little')
                guid3 = int.from_bytes(rf.read(2), 'little')
                guid4 = int.from_bytes(rf.read(2), 'little')
                guid5 = bytearray(rf.read(6)).hex()
                pf.unique = "{:08x}-{:04x}-{:04x}-{:04x}-{}".format(guid1, guid2, guid3, guid4, guid5)
                pf.first_lba = int.from_bytes(rf.read(8), 'little')
                pf.last_lba = int.from_bytes(rf.read(8), 'little')
                pf.sector = pf.first_lba
                pf.sectors = pf.last_lba - pf.first_lba + 1
                pf.flags = int.from_bytes(rf.read(8), 'little')
                pf.name = rf.read(0x48).replace(b"\x00\x00", b"").decode("utf-16")
                pf.type = 0
                if pf.last_lba > self.totalsectors:
                    self.totalsectors = pf.last_lba
                self.partentries.append(pf)
            return True
        return False

    def printfile(self, filename):
        try:
            filesize = os.stat(filename).st_size
            with open(filename, "rb") as rf:
                size = min(32 * 4096, filesize)
                data = rf.read(size)
                self.rf = structhelper_io(data)
                self.filesize = size
                for sectorsize in [512, 4096]:
                    self.sectorsize = sectorsize
                    result = self.parse()
                    if result:
                        break
                if result:
                    print(self.tostring())
                return result
        except Exception as e:
            self.error(str(e))
        return ""

    def get_flag(self, imagename):
        if "." in imagename:
            imagename = imagename[:imagename.find(".")]
        try:
            return self.get_flag_data(imagename)
        except Exception:
            return None, None

    def get_flag_data(self, imagename: str):
        pos = self.rf.getpos()
        for sectorsize in [512, 4096]:
            try:
                self.rf.seek(pos)
                self.sectorsize = sectorsize
                result = self.parse()
            except Exception:
                return None, None
            if result:
                for partition in self.partentries:
                    if imagename in partition.name.lower():
                        return partition.sector, sectorsize
        return None, None
