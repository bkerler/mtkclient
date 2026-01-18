#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2023
# GPLv3 License

import logging
import logging.config
from io import BytesIO
import os
import sys

try:
    from mtkclient.Library.gui_utils import LogBase, structhelper_io, progress
except ImportError:
    script_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    sys.path.insert(0, script_path)
    from mtkclient.Library.gui_utils import LogBase, structhelper_io, progress


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


class generic(metaclass=LogBase):

    def __init__(self, rf, filesize: int = 32 * 4096, num_part_entries: int = 0, part_entry_size: int = 0,
                 part_entry_start_lba: int = 0,
                 loglevel=logging.INFO, *args,
                 **kwargs):
        self.rf = structhelper_io(rf)
        self.filesize = filesize
        self.num_part_entries = num_part_entries
        self.__logger = self.__logger
        self.part_entry_size = part_entry_size
        self.part_entry_start_lba = part_entry_start_lba
        self.totalsectors = None
        self.header = None
        self.sectorsize = None
        self.partentries = []
        self.parttype = "GPT"
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename, encoding="utf-8")
            self.__logger.addHandler(fh)

    def parseheader(self):
        assert "Not implemented"

    def parse(self) -> bool:
        assert "Not implemented"
        return False

    def print(self):
        print(self.tostring())

    def parse_file(self, filename):
        if not os.path.exists(filename):
            print(f"File {filename} does not exist. Aborting.")
            return False
        filesize = os.stat(filename).st_size
        with open(filename, "rb", buffering=1024 * 1024) as rf:
            data = rf.read(min(32 * 4096, filesize))
            self.rf = structhelper_io(BytesIO(bytearray(data)))
            try:
                for sectorsize in [512, 4096]:
                    self.sectorsize = sectorsize
                    result = self.parse()
                    if result:
                        return True
            except Exception:
                pass
        return False

    def printfile(self, filename):
        try:
            filesize = os.stat(filename).st_size
            with open(filename, "rb") as rf:
                size = min(32 * 4096, filesize)
                self.filesize = size
                self.rf = structhelper_io(BytesIO(bytearray(rf.read(size))))
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

    def tostring(self):
        mstr = f"\n{self.parttype} Table:\n-------------\n"
        id = 0
        for partition in self.partentries:
            name = partition.name if partition.name != "" else str(id)
            id += 1
            mstr += ("{:20} Offset 0x{:016x}, Length 0x{:016x}, Flags 0x{:016x}").format(
                name + ":", partition.sector * self.sectorsize, partition.sectors * self.sectorsize,
                partition.flags)
            if partition.unique != b"":
                mstr += f", UUID {partition.unique}"
            if partition.type != "":
                mstr += f", Type {partition.type}"
            mstr += "\n"
        mstr += ("\nTotal disk size:0x{:016x}, sectors:0x{:016x}\n".format(self.totalsectors * self.sectorsize,
                                                                           self.totalsectors))
        return mstr

    def generate_rawprogram(self, lun, sectorsize, directory):
        assert "Not implemented"

    def test(self):
        assert "Not implemented"

    def patch(self, data: bytes, partitionname="boot", active: bool = True):
        assert "Not implemented"

    def get_flag(self, imagename: str):
        assert "Not implemented"

    def get_flag_data(self, imagename: str):
        assert "Not implemented"

    def extract(self, out, partitionname=None):
        if self.sectorsize is not None:
            if partitionname == "gpt":
                print(f"Extracting gpt to gpt.bin at {hex(0)}, length {hex(32 * self.sectorsize)}")
                self.rf.seek(0)
                data = self.rf.bytes(32 * self.sectorsize)
                with open("gpt.bin", "wb") as wf:
                    wf.write(data)
            if partitionname != "gpt":
                for partition in self.partentries:
                    if partitionname is not None:
                        if partition.name.lower() != partitionname:
                            continue
                    name = partition.name
                    start = partition.sector * self.sectorsize
                    length = partition.sectors * self.sectorsize
                    if out == "":
                        out = "."
                    else:
                        if out != ".":
                            if out is None:
                                out = ""
                            else:
                                if not os.path.exists(out):
                                    os.makedirs(out)
                    filename = os.path.join(out, name) + ".bin"
                    print(f"Extracting {name} to {filename} at {hex(start)}, length {hex(length)}")
                    self.rf.seek(start)
                    bytestoread = length
                    pg = progress(total=bytestoread, pagesize=1, prefix="Progress")
                    with open(filename, "wb", buffering=1024 * 1024) as wf:
                        while bytestoread > 0:
                            size = min(bytestoread, 0x200000)
                            data = self.rf.bytes(size)
                            wf.write(data)
                            pg.update(len(data))
                            bytestoread -= len(data)
                    pg.done()
