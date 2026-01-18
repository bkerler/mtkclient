#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2023
# GPLv3 License
import logging
import os
from mtkclient.Library.gui_utils import structhelper_io
from mtkclient.Library.Partitions import generic


class pmt(generic):

    def __init__(self, rf, filesize: int, num_part_entries=0, part_entry_size=0, part_entry_start_lba=0,
                 loglevel=logging.INFO, *args, **kwargs):

        super().__init__(rf, filesize, num_part_entries, part_entry_size, part_entry_start_lba, loglevel, *args,
                         **kwargs)
        self.parttype = "pmt"

    class pt_resident:
        def __init__(self, data):
            sh = structhelper_io(data)
            self.name = sh.bytes(64)
            self.size = sh.qword()
            self.part_id = sh.qword()
            self.offset = sh.qword()
            self.mask_flags = sh.qword()

    class pt_resident1:
        def __init__(self, data):
            sh = structhelper_io(data)
            self.name = sh.bytes(66)
            self.size = sh.qword()
            self.offset = sh.qword()
            self.mask_flags = sh.dword()

    class pt_info:
        def __init__(self, data):
            sh = structhelper_io(data)
            self.sequencenumber = sh.bytes(1)
            self.tool_or_sd_update = sh.bytes(1)
            tmp = sh.bytes(1)
            self.mirror_pt_dl = (tmp >> 4) & 0xF
            self.mirror_pt_has_space = tmp & 0xF
            tmp = sh.bytes(1)
            self.pt_changed = (tmp >> 4) & 0xF
            self.pt_has_space = tmp & 0xF

    class pmt_header:
        def __init__(self, data):
            sh = structhelper_io(data)
            self.signature = sh.bytes(8)
            self.revision = sh.dword()
            self.header_size = sh.dword()
            self.crc32 = sh.dword()
            self.reserved = sh.dword()
            self.current_lba = sh.qword()
            self.backup_lba = sh.qword()
            self.first_usable_lba = sh.qword()
            self.last_usable_lba = sh.qword()
            self.disk_guid = sh.bytes(16)
            self.part_entry_start_lba = sh.qword()
            self.num_part_entries = sh.dword()
            self.part_entry_size = sh.dword()

    def print_file(self, filename):
        self.rf = open(filename, "rb")
        self.filesize = os.stat(filename).st_size
        try:
            for sectorsize in [0x10000]:
                self.rf.seek(self.filesize - 0x100000)
                self.sectorsize = sectorsize
                result = self.parse
                if result:
                    break
            if result:
                print(self.tostring())
            self.rf.close()
            return result
        except Exception as e:
            self.error(str(e))
            self.rf.close()
        return ""

    def parse_file(self, filename):
        self.rf = open(filename, "rb")
        self.filesize = os.stat(filename).st_size
        try:
            for sectorsize in [0x10000]:
                self.sectorsize = sectorsize
                self.rf.seek(self.filesize - 0x100000)
                result = self.parse
                if result:
                    self.rf.close()
                    return True
        except Exception:
            pass
        self.rf.close()
        return False

    @property
    def parse(self) -> bool:
        # "PTv1", "PTv3", "MPT3"
        hdr = self.rf.bytes(4)
        if hdr == b"1vTP":
            self.parttype = "PMTv1"

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

            # flashsize - 0x100000
            self.totalsectors = 0
            self.partentries = []
            for i in range(40):
                pos = 0x8 + (i * 0x58)
                self.rf.seek(pos)
                data = self.rf.bytes(0x58)
                if int(data[0:16].hex(), 16) == 0:
                    break

                part = self.pt_resident1(bytearray(data))
                pt = partf()
                pt.first_lba = part.offset - 0x88 if part.offset != 0 else 0
                pt.last_lba = part.offset + part.size - 0x88 if part.offset != 0 else part.offset + part.size
                pt.sector = part.offset - 0x88 if part.offset != 0 else 0
                pt.sectors = part.size
                pt.name = part.name.rstrip(b"\x00").decode('utf-8')
                if pt.name != "BMTPOOL":
                    self.partentries.append(pt)
            return True
        elif hdr == b"3vTP":
            self.parttype = "PMTv3"

            # toDo
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

            self.sectorsize = 0x10000
            self.totalsectors = 0
            self.partentries = []
            for pos in range(0x8, self.filesize, 0x58):
                self.rf.seek(pos)
                data = self.rf.bytes(58)
                if int(data[0:16].hex(), 16) == 0:
                    break

                part = self.pt_resident(bytearray(data))
                pt = partf()
                pt.first_lba = part.offset
                pt.last_lba = part.offset + part.size
                pt.sector = part.offset
                pt.sectors = part.size
                pt.name = part.name.rstrip(b"\x00").decode('utf-8')
                self.partentries.append(pt)
            return True

        return False
