#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2021 GPLv3 License
import logging
import os
from struct import unpack
from mtkclient.Library.utils import LogBase, read_object, logsetup
from mtkclient.config.payloads import pathconfig
from mtkclient.config.brom_config import damodes
from mtkclient.Library.utils import structhelper

class Storage:
    MTK_DA_HW_STORAGE_NOR = 0
    MTK_DA_HW_STORAGE_NAND = 1
    MTK_DA_HW_STORAGE_EMMC = 2
    MTK_DA_HW_STORAGE_SDMMC = 3
    MTK_DA_HW_STORAGE_UFS = 4


class DaStorage:
    MTK_DA_STORAGE_EMMC = 0x1
    MTK_DA_STORAGE_SDMMC = 0x2
    MTK_DA_STORAGE_UFS = 0x30
    MTK_DA_STORAGE_NAND = 0x10
    MTK_DA_STORAGE_NAND_SLC = 0x11
    MTK_DA_STORAGE_NAND_MLC = 0x12
    MTK_DA_STORAGE_NAND_TLC = 0x13
    MTK_DA_STORAGE_NAND_AMLC = 0x14
    MTK_DA_STORAGE_NAND_SPI = 0x15
    MTK_DA_STORAGE_NOR = 0x20
    MTK_DA_STORAGE_NOR_SERIAL = 0x21
    MTK_DA_STORAGE_NOR_PARALLEL = 0x22


class EMMC_PartitionType:
    MTK_DA_EMMC_PART_BOOT1 = 1
    MTK_DA_EMMC_PART_BOOT2 = 2
    MTK_DA_EMMC_PART_RPMB = 3
    MTK_DA_EMMC_PART_GP1 = 4
    MTK_DA_EMMC_PART_GP2 = 5
    MTK_DA_EMMC_PART_GP3 = 6
    MTK_DA_EMMC_PART_GP4 = 7
    MTK_DA_EMMC_PART_USER = 8
    MTK_DA_EMMC_PART_END = 9
    MTK_DA_EMMC_BOOT1_BOOT2 = 10


class UFS_PartitionType:
    UFS_LU0 = 0
    UFS_LU1 = 1
    UFS_LU2 = 2
    UFS_LU3 = 3
    UFS_LU4 = 4
    UFS_LU5 = 5
    UFS_LU6 = 6
    UFS_LU7 = 7
    UFS_LU8 = 8


class Memory:
    M_EMMC = 1
    M_NAND = 2
    M_NOR = 3


class NandCellUsage:
    CELL_UNI = 0,
    CELL_BINARY = 1
    CELL_TRI = 2
    CELL_QUAD = 3
    CELL_PENTA = 4
    CELL_HEX = 5
    CELL_HEPT = 6
    CELL_OCT = 7


class entry_region:
    m_buf = None
    m_len = None
    m_start_addr = None
    m_start_offset = None
    m_sig_len = None
    def __init__(self, data):
        sh = structhelper(data)
        self.m_buf = sh.dword()
        self.m_len = sh.dword()
        self.m_start_addr = sh.dword()
        self.m_start_offset = sh.dword()
        self.m_sig_len = sh.dword()

class DA:
    def __init__(self,data):
        self.loader = None
        sh = structhelper(data)
        self.magic = sh.short()
        self.hw_code = sh.short()
        self.hw_sub_code = sh.short()
        self.hw_version = sh.short()
        self.sw_version = sh.short()
        self.reserved1 = sh.short()
        self.pagesize = sh.short()
        self.reserved3 = sh.short()
        self.entry_region_index = sh.short()
        self.entry_region_count = sh.short()
        self.region = []
        for _ in range(self.entry_region_count):
            entry_tmp = entry_region(sh.bytes(20))
            self.region.append(entry_tmp)

    def setfilename(self, loaderfilename: str):
        self.loader = loaderfilename

class DAconfig(metaclass=LogBase):
    def __init__(self, mtk, loader=None, preloader=None, loglevel=logging.INFO):
        self.__logger = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.mtk = mtk
        self.pathconfig = pathconfig()
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.flashsize = 0
        self.rpmbsize = 0
        self.boot1size = 0
        self.boot2size = 0
        self.flashtype = "emmc"
        self.sparesize = 0
        self.readsize = 0
        self.pagesize = 512
        self.da_loader = None
        self.da2 = None
        self.dasetup = {}
        self.loader = loader
        self.extract_emi(preloader)
        self.blver = None
        self.bromver = None

        if loader is None:
            loaders = []
            for root, dirs, files in os.walk(self.pathconfig.get_loader_path(), topdown=False):
                for file in files:
                    if "MTK_AllInOne_DA" in file:
                        loaders.append(os.path.join(root, file))
            loaders = sorted(loaders)[::-1]
            for loader in loaders:
                self.parse_da_loader(loader)
        else:
            if not os.path.exists(loader):
                self.warning("Couldn't open " + loader)
            else:
                self.info("Using custom loader: "+loader)
                self.parse_da_loader(loader)

    def m_extract_emi(self, data):
        idx = data.find(b"\x4D\x4D\x4D\x01\x38\x00\x00\x00")
        siglen = 0
        if idx != -1:
            data = data[idx:]
            mlen = unpack("<I", data[0x20:0x20 + 4])[0]
            siglen = unpack("<I", data[0x2C:0x2C + 4])[0]
            data = data[:mlen-siglen]
            dramsize = unpack("<I",data[-4:])[0]
            data = data[-dramsize-4:-4]
        bldrstring = b"MTK_BLOADER_INFO_v"
        len_bldrstring = len(bldrstring)
        idx = data.find(bldrstring)
        if idx == -1:
            return None
        elif idx == 0 and self.config.chipconfig.damode == damodes.XFLASH:
            ver = int(data[idx + len_bldrstring:idx + len_bldrstring + 2].rstrip(b"\x00"))
            return ver, data
        else:
            if data.find(b"MTK_BIN") != -1:
                emi = data[data.find(b"MTK_BIN") + 0xC:]
                ver = int(data[idx + len_bldrstring:idx + len_bldrstring + 2].rstrip(b"\x00"))
                return ver, emi
        return None

    def extract_emi(self, preloader=None) -> bytearray:
        if preloader is None:
            self.emi = None
            return b""
        if isinstance(preloader, bytearray) or isinstance(preloader, bytes):
            data = bytearray(preloader)
        elif isinstance(preloader, str):
            if os.path.exists(preloader):
                with open(preloader, "rb") as rf:
                    data = rf.read()
            else:
                self.error("Preloader : " + preloader + " doesn't exist. Aborting.")
                exit(1)
        try:
            self.emiver, self.emi = self.m_extract_emi(data)
        except:
            self.emiver = 0
            self.emi = None

    def parse_da_loader(self, loader):
        try:
            with open(loader, 'rb') as bootldr:
                # data = bootldr.read()
                # self.debug(hexlify(data).decode('utf-8'))
                bootldr.seek(0x68)
                count_da = unpack("<I", bootldr.read(4))[0]
                for i in range(0, count_da):
                    bootldr.seek(0x6C + (i * 0xDC))
                    da = DA(bootldr.read(0xDC))
                    da.setfilename(loader)
                    if da.hw_code not in self.dasetup:
                        self.dasetup[da.hw_code] = [da]
                    else:
                        for ldr in self.dasetup[da.hw_code]:
                            found = False
                            if da.hw_version == ldr.hw_version:
                                if da.sw_version == ldr.sw_version:
                                    if da.hw_sub_code == da.hw_sub_code:
                                        found = True
                                        break
                        if not found:
                            self.dasetup[da.hw_code].append(da)
                return True
        except Exception as e:
            self.error("Couldn't open loader: " + loader + ". Reason: " + str(e))
        return False

    def setup(self):
        dacode = self.config.chipconfig.dacode
        if dacode in self.dasetup:
            loaders = self.dasetup[dacode]
            for loader in loaders:
                if loader.hw_version <= self.config.hwver:
                    if loader.sw_version <= self.config.swver:
                        if self.da_loader is None:
                            self.da_loader = loader
                            self.loader = loader.loader

        if self.da_loader is None:
            self.error("No da_loader config set up")
        return self.da_loader
