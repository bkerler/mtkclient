#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import logging

from mtkclient.Library.Partitions.bpi import bpi
from mtkclient.Library.Partitions.mbr import mbr
from mtkclient.Library.Partitions.pmt import pmt
from mtkclient.Library.gui_utils import LogBase, logsetup
from mtkclient.Library.Partitions.gpt import gpt
from mtkclient.Library.realtime import MTKFileHandler


class Partition(metaclass=LogBase):
    def __init__(self, mtk, readflash, read_pmt, loglevel=logging.INFO):
        self.mtk = mtk
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.config = self.mtk.config
        self.readflash = readflash
        self.read_pmt = read_pmt
        if self.config.gpt_file is not None:
            self.gptfilename = self.config.gpt_file
            self.readflash = self.readflash_override

    def readflash_override(self, addr: int, length: int, filename: str = "", parttype: str = "",
                           display: bool = False) -> bytes:
        with open(self.gptfilename, "rb") as rf:
            rf.seek(addr)
            data = rf.read(length)
            if filename == "":
                return data
        return b""

    def parse_gpt(self, fh, gpt_settings):
        guid_gpt = gpt(rf=fh, filesize=self.mtk.daloader.daconfig.storage.flashsize,
                       num_part_entries=gpt_settings.gpt_num_part_entries,
                       part_entry_size=gpt_settings.gpt_part_entry_size,
                       part_entry_start_lba=gpt_settings.gpt_part_entry_start_lba,
                       )
        guid_gpt.sectorsize = self.config.pagesize
        fh.seek(0)
        header = guid_gpt.parseheader()
        if header.signature == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            fh.seek(self.mtk.daloader.daconfig.storage.flashsize - 0x4000)
            guid_gpt = gpt(rf=fh, filesize=self.mtk.daloader.daconfig.storage.flashsize,
                           num_part_entries=gpt_settings.gpt_num_part_entries,
                           part_entry_size=gpt_settings.gpt_part_entry_size,
                           part_entry_start_lba=gpt_settings.gpt_part_entry_start_lba,
                           )
            guid_gpt.sectorsize = self.config.pagesize
            header = guid_gpt.parseheader()
            if header.signature == b'\x00\x00\x00\x00\x00\x00\x00\x00':
                return None, None
        sectors = header.first_usable_lba
        if sectors == 0:
            return None, None
        fh.seek(0)
        guid_gpt = gpt(rf=fh, filesize=self.mtk.daloader.daconfig.storage.flashsize,
                       num_part_entries=gpt_settings.gpt_num_part_entries,
                       part_entry_size=gpt_settings.gpt_part_entry_size,
                       part_entry_start_lba=gpt_settings.gpt_part_entry_start_lba,
                       )
        guid_gpt.sectorsize = self.config.pagesize
        guid_gpt.parse()
        return guid_gpt

    def get_pmt(self, backup: bool = False, parttype: str = "user") -> tuple:
        fh = MTKFileHandler(mtk=self.mtk, parttype=parttype)
        fh.filesize = self.mtk.daloader.daconfig.storage.flashsize
        fh.pagesize = self.config.pagesize
        pt = pmt(rf=fh, filesize=fh.filesize)
        blocksize = self.mtk.daloader.daconfig.pagesize
        if not backup:
            addr = self.mtk.daloader.daconfig.storage.flashsize - (2 * blocksize)
        else:
            addr = self.mtk.daloader.daconfig.storage.flashsize - (2 * blocksize) + blocksize
        fh.seek(addr)
        data = fh.read(2 * self.config.pagesize)
        magic = int.from_bytes(data[:4], 'little')
        if magic in [b"PTv3", b"MPT3"]:
            partdata = data[8:]
            partitions = []
            for partpos in range(128):
                partinfo = pt.PtResident(partdata[partpos * 96:(partpos * 96) + 96])
                if partinfo[:4] == b"\x00\x00\x00\x00":
                    break

                class Partf:
                    unique = b""
                    first_lba = 0
                    last_lba = 0
                    flags = 0
                    sector = 0
                    sectors = 0
                    type = b""
                    name = ""

                pm = Partf()
                pm.name = partinfo.name.rstrip(b"\x00").decode('utf-8')
                pm.sector = partinfo.offset // self.config.pagesize
                pm.sectors = partinfo.size // self.config.pagesize
                pm.type = 1
                pm.flags = partinfo.mask_flags
                partitions.append(pm)
            return data, partitions
        return b"", None

    def parse_mbr(self, fh, gpt_settings, offset:int=0):
        fh.seek(offset)
        data = fh.read(2 * self.config.pagesize)
        if data[0x1FE:0x200] == b"\x55\xAA":
            fh.pagesize = self.config.pagesize
            fh.seek(offset)
            mt = mbr(rf=fh)
            if mt.parse():
                partentries = mt.partentries
                if len(partentries) == 1:
                    fh.seek(partentries[0].sector * self.config.pagesize)
                    hdr = fh.read(2 * self.config.pagesize)
                    fh.seek(partentries[0].sector * self.config.pagesize)
                    if hdr[:8]==b"EFI PART":
                        poffset = partentries[0].sector * self.config.pagesize
                        fh.seek(poffset + offset)
                        partentries = self.parse_gpt(fh, gpt_settings)
                        fh.seek(offset)
                        data = fh.read(poffset + (32 * self.config.pagesize))
                        return data, partentries
                    else:
                        mt2 = mbr(rf=fh)
                        if mt.parse():
                            return data, mt2
                elif len(partentries) == 0:
                    fh.seek((1 * self.config.pagesize) + offset)
                    data = fh.read(2 * self.config.pagesize)
                    fh.seek((1 * self.config.pagesize) + offset)
                    if data[:7] == b"EFI PART":
                        poffset = 1 * self.config.pagesize
                        partentries = self.parse_gpt(fh, gpt_settings)
                        fh.seek(poffset + offset)
                        data = fh.read(32 * self.config.pagesize)
                        return data, partentries
                    else:
                        mt2 = mbr(rf=fh)
                        if mt.parse():
                            return data, mt2
                else:
                    fh.seek(offset)
                    data = fh.read(32 * self.config.pagesize)
                    return data, mt
        return data, None

    def get_gpt(self, gpt_settings, parttype: str = "user") -> tuple:
        fh = MTKFileHandler(mtk=self.mtk, parttype=parttype)
        fh.pagesize = self.config.pagesize
        fh.filesize = self.mtk.daloader.daconfig.storage.flashsize
        fh.seek(0)
        data = fh.read(2 * self.config.pagesize)
        if not data:
            return None, None
        if data[:4] == b"BPI\x00":
            fh.seek(0)
            _bpi = bpi(rf=fh, filesize=self.mtk.daloader.daconfig.storage.flashsize,
                       num_part_entries=gpt_settings.gpt_num_part_entries,
                       part_entry_size=gpt_settings.gpt_part_entry_size,
                       part_entry_start_lba=gpt_settings.gpt_part_entry_start_lba,
                       )
            if data == b"":
                return None, None
            _bpi.parse()
            return data, _bpi
        if data[:9] == b"EMMC_BOOT" and self.read_pmt is not None:
            partdata, partentries = self.read_pmt()
            if partdata == b"":
                return None, None
            else:
                return partdata, partentries
        elif data[:8] == b"UFS_BOOT" and self.read_pmt is not None:
            partdata, partentries = self.read_pmt()
            if partdata == b"":
                return None, None
            else:
                return partdata, partentries
        elif data[0x1FE:0x200] == b"\x55\xAA" and self.read_pmt is not None:
            return self.parse_mbr(fh, gpt_settings, offset=0)
        else:
            return self.parse_mbr(fh, gpt_settings, offset=0x380000)
        return data, None

    def get_backup_gpt(self, lun, gpt_num_part_entries, gpt_part_entry_size, gpt_part_entry_start_lba,
                       parttype="user") -> bytes:
        fh = MTKFileHandler(mtk=self.mtk, parttype=parttype)
        fh.seek(0)
        fh.pagesize = self.config.pagesize
        fh.filesize = self.mtk.daloader.daconfig.storage.flashsize
        guid_gpt = gpt(rf=fh, filesize=self.mtk.daloader.daconfig.storage.flashsize,
                       num_part_entries=gpt_num_part_entries,
                       part_entry_size=gpt_part_entry_size,
                       part_entry_start_lba=gpt_part_entry_start_lba,
                       )
        header = guid_gpt.parseheader()
        sectors = header.first_usable_lba - 1
        fh.seek(header.backup_lba * self.config.pagesize)
        fh.filesize = (header.backup_lba * self.config.pagesize) + sectors * self.config.pagesize
        data = fh.read(sectors * self.config.pagesize)
        return data
