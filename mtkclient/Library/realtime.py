#!/usr/bin/env python3
import logging
from io import BytesIO
from mtkclient.Library.DA.mtk_da_handler import DaHandler


class RealTimeHandler:

    def __init__(self, preoffset: int = 0, maxoffset: int = -1,
                 outdir=".", loglevel=logging.INFO, **args):
        self.lastsector = None
        self.gpttable = None
        self.curoffset = preoffset
        self.preoffset = preoffset
        self.filesize = maxoffset
        self.outdir = outdir
        self.loglevel = loglevel
        self.mtk_pos = preoffset
        self.lastpartition = ""
        self.partitionname = ""

    def close(self):
        pass

    def seek(self, pos: int) -> bool:
        pass

    def read_rpmb(self):
        pass

    def generate_keys(self):
        pass

    def select_partition(self, partitionname):
        pass

    def get_gpt(self):
        pass

    def readblock(self, sector: int, sectors: int) -> bytes:
        pass

    def readdata(self, length: int = 0) -> bytes:
        pass

    def read(self, length: int = None) -> bytes:
        if length is None:
            length = self.filesize
        return self.readdata(length)


class MTKFileHandler(RealTimeHandler):

    def __init__(self, mtk, preoffset: int = 0, maxoffset: int = -1, loglevel=logging.INFO, outdir=".",
                 preloader: str = None, loader: str = None, stock: bool = False, parttype="user", serialport=None):
        super().__init__(preoffset=preoffset, maxoffset=maxoffset, loglevel=loglevel, outdir=outdir,
                         preloader=preloader, loader=loader, serialport=serialport)
        self.lastsector = None
        self.lastsectors = None
        self.gpttable = None
        self.parttype = parttype
        self.curoffset = preoffset
        self.da_handler = DaHandler(mtk, loglevel)
        self.mtk = mtk
        self.preoffset = preoffset
        self.filesize = maxoffset

    def close(self):
        self.mtk.port.cdc.disconnect()

    def seek(self, pos: int) -> bool:
        if pos <= self.filesize:
            self.mtk_pos = self.preoffset
            self.curoffset = pos
            self.curblock = pos // self.mtk.config.pagesize
            return True
        return False

    def read_rpmb(self):
        return self.mtk.daloader.read_rpmb("", 0, 0x40000)

    def generate_keys(self):
        return self.mtk.daloader.keys()

    def select_partition(self, partitionname):
        if self.gpttable is None:
            self.get_gpt()
        if partitionname == "gpt":
            self.preoffset = 0
            self.filesize = 0x22 * self.mtk.config.pagesize
            self.seek(0)
            return self.preoffset, self.filesize
        else:
            for gptentry in self.gpttable:
                if gptentry.name.lower() == partitionname.lower():
                    rpartition = gptentry
                    self.lastpartition = self.partitionname
                    self.preoffset = rpartition.sector * self.mtk.config.pagesize
                    self.filesize = rpartition.sectors * self.mtk.config.pagesize
                    self.seek(0)
                    self.partitionname = partitionname
                    return True
        return False

    def get_gpt(self):
        if self.gpttable is None:
            self.gpttable = self.mtk.daloader.get_partition_data(parttype=self.parttype)
        return self.gpttable

    def readblock(self, sector: int, sectors: int) -> bytes:
        return self.mtk.daloader.readflash(addr=sector * self.mtk.config.pagesize,
                                           length=sectors * self.mtk.config.pagesize,
                                           filename="", parttype=self.parttype,
                                           display=False)

    def readdata(self, length: int = 0) -> bytes:
        sector = (self.mtk_pos + self.curoffset) // self.mtk.config.pagesize
        offset = self.curoffset % self.mtk.config.pagesize
        sectors = (offset + length) // self.mtk.config.pagesize
        if (offset + length) % self.mtk.config.pagesize:
            sectors += 1
        if self.lastsector != sector or self.lastpartition != self.partitionname or sectors > self.lastsectors:
            self.lastpartition = self.partitionname
            self.lastsector = sector
            self.lastsectors = sectors
            self.buffer = BytesIO()
            bw = self.buffer.write
            bw(self.readblock(sector, sectors))
            self.curblock = sector + sectors
        self.curoffset += length
        self.buffer.seek(offset)
        return self.buffer.read(length)

    def read(self, length: int = None) -> bytes:
        if length is None:
            length = self.filesize
        return self.readdata(length)


def main():
    fh = MTKFileHandler(preoffset=0, maxoffset=-1)
    # fh.select_partition("metadata")
    # fh.seek(0x8E8)
    # data = fh.read(4)
    # print(data.hex())
    fh.select_partition("userdata")
    fh.seek(fh.filesize - 0x2000)
    data = fh.read(0x2000)
    fh.seek(0)
    data = fh.read(0x2000)
    print(data.hex())


if __name__ == '__main__':
    main()
