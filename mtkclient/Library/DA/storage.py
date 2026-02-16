import logging
from mtkclient.Library.gui_utils import logsetup, LogBase
from mtkclient.Library.DA.legacy.dalegacy_flash_param import (Legacy_NandInfo64, Legacy_NorInfo,
                                                              Legacy_EmmcInfo, Legacy_SdcInfo)
from mtkclient.config.brom_config import DAmodes


class StorageType:
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


class EmmcPartitionType:
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


class UFSPartitionType:
    BOOT1 = 1
    BOOT2 = 2
    USER = 3
    RPMB = 4


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


class EmmcInfo:
    type = 1  # emmc or sdmmc or none
    block_size = 0x200
    boot1_size = 0
    boot2_size = 0
    rpmb_size = 0
    gp1_size = 0
    gp2_size = 0
    gp3_size = 0
    gp4_size = 0
    user_size = 0
    cid = b""
    fwver = 0
    unknown = b""


class NandInfo:
    type = 1  # slc, mlc, spi, none
    page_size = 0
    block_size = 0x200
    spare_size = 0
    total_size = 0
    available_size = 0
    nand_bmt_exist = 0
    nand_id = 0


class NorInfo:
    type = 1  # nor, none
    page_size = 0
    available_size = 0


class UfsInfo:
    type = 1  # nor, none
    block_size = 0
    lu0_size = 0
    lu1_size = 0
    lu2_size = 0
    lu3_size = 0
    cid = b""
    fwver = b""
    serial = b""


class RamInfo:
    type = 0
    base_address = 0
    size = 0


class Legacy_Storage(metaclass=LogBase):
    nor = Legacy_NorInfo()
    nand = Legacy_NandInfo64()
    emmc = Legacy_EmmcInfo()
    sdc = Legacy_SdcInfo()
    flashtype = None
    flashsize = None
    flashconfig = None

    def __init__(self, mtk, daconfig, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.daconfig = daconfig
        self.mtk = mtk

    def partitiontype_and_size(self, parttype=None, length=0):
        if self.daconfig.storage.flashtype == "emmc":
            if parttype is None or parttype == "user" or parttype == "":
                length = min(length, self.daconfig.legacy_storage.emmc.m_emmc_ua_size)
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            elif parttype == "boot1":
                length = min(length, self.daconfig.legacy_storage.emmc.m_emmc_boot1_size)
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_BOOT1
            elif parttype == "boot2":
                length = min(length, self.daconfig.legacy_storage.emmc.m_emmc_boot2_size)
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_BOOT2
            elif parttype == "gp1":
                length = min(length, self.daconfig.legacy_storage.emmc.m_emmc_gp_size[0])
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP1
            elif parttype == "gp2":
                length = min(length, self.daconfig.legacy_storage.emmc.m_emmc_gp_size[1])
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP2
            elif parttype == "gp3":
                length = min(length, self.daconfig.legacy_storage.emmc.m_emmc_gp_size[2])
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP3
            elif parttype == "gp4":
                length = min(length, self.daconfig.legacy_storage.emmc.m_emmc_gp_size[3])
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP4
            elif parttype == "rpmb":
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_RPMB
        elif self.daconfig.storage.flashtype == "nand":
            parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            length = min(length, self.daconfig.legacy_storage.nand.m_nand_flash_size)
        elif self.daconfig.storage.flashtype == "nor":
            parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            length = min(length, self.daconfig.legacy_storage.nor.m_nor_flash_size)
        else:
            parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            length = min(length, self.daconfig.legacy_storage.sdc.m_sdmmc_ua_size)
        return length, parttype


class Storage(metaclass=LogBase):
    emmc = EmmcInfo()
    ufs = UfsInfo()
    nand = NandInfo()
    nor = NorInfo()
    flashtype = None
    flashsize = None
    sram = RamInfo()
    dram = RamInfo()

    def __init__(self, mtk, daconfig, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.daconfig = daconfig
        self.mtk = mtk

    def get_storage(self, parttype, length):
        if self.flashtype == "nor":
            storage = DaStorage.MTK_DA_STORAGE_NOR
        elif self.flashtype == "nand":
            storage = DaStorage.MTK_DA_STORAGE_NAND
        elif self.flashtype == "ufs":
            storage = DaStorage.MTK_DA_STORAGE_UFS
        elif self.flashtype == "sdc":
            storage = DaStorage.MTK_DA_STORAGE_SDMMC
        else:
            storage = DaStorage.MTK_DA_STORAGE_EMMC

        part_info = self.partitiontype_and_size(storage, parttype, length)
        return part_info

    def set_flash_size(self):
        if self.flashtype == "emmc":
            ms = [self.emmc.gp1_size, self.emmc.gp2_size, self.emmc.gp3_size, self.emmc.gp4_size,
                  self.emmc.user_size]
            self.flashsize = max(ms)
        elif self.flashtype == "ufs":
            ms = [self.ufs.lu0_size, self.ufs.lu1_size, self.ufs.lu2_size, self.ufs.lu3_size]
            self.flashsize = max(ms)
        elif self.flashtype == "nand":
            self.flashsize = self.nand.total_size
        elif self.flashtype == "nor":
            self.flashsize = self.nor.available_size

    def partitiontype_and_size(self, storage=None, parttype=None, length=0):
        xml = self.mtk.config.chipconfig.damode == DAmodes.XML
        if storage is None:
            if self.flashtype == "sdc":
                storage = DaStorage.MTK_DA_STORAGE_SDMMC
            elif self.flashtype == "ufs":
                storage = DaStorage.MTK_DA_STORAGE_UFS
            elif self.flashtype == "nor":
                storage = DaStorage.MTK_DA_STORAGE_NOR
            elif self.flashtype == "nand":
                storage = DaStorage.MTK_DA_STORAGE_NAND
            else:
                storage = DaStorage.MTK_DA_STORAGE_EMMC

        if storage == DaStorage.MTK_DA_STORAGE_EMMC or storage == DaStorage.MTK_DA_STORAGE_SDMMC:
            storage = 1
            if self.flashtype == "emmc":
                ms = [self.emmc.gp1_size, self.emmc.gp2_size, self.emmc.gp3_size, self.emmc.gp4_size,
                      self.emmc.user_size]
                self.flashsize = max(ms)
                if parttype is None or parttype == "user":
                    idx = ms.index(self.flashsize) + 1
                    if xml:
                        if idx == 5:
                            parttype = "EMMC-USER"
                        else:
                            parttype = f"EMMC-GP{idx}"
                    else:
                        parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
                elif parttype == "boot1":
                    if xml:
                        parttype = "EMMC-BOOT1"
                    else:
                        parttype = EmmcPartitionType.MTK_DA_EMMC_PART_BOOT1
                    length = min(length, self.emmc.boot1_size)
                elif parttype == "boot2":
                    if xml:
                        parttype = "EMMC-BOOT2"
                    else:
                        parttype = EmmcPartitionType.MTK_DA_EMMC_PART_BOOT2
                    length = min(length, self.emmc.boot2_size)
                elif parttype == "gp1":
                    if xml:
                        parttype = "EMMC-GP1"
                    else:
                        parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP1
                    length = min(length, self.emmc.gp1_size)
                elif parttype == "gp2":
                    if xml:
                        parttype = "EMMC-GP2"
                    else:
                        parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP2
                    length = min(length, self.emmc.gp2_size)
                elif parttype == "gp3":
                    if xml:
                        parttype = "EMMC-GP3"
                    else:
                        parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP3
                    length = min(length, self.emmc.gp3_size)
                elif parttype == "gp4":
                    if xml:
                        parttype = "EMMC-GP4"
                    else:
                        parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP4
                    length = min(length, self.emmc.gp4_size)
                elif parttype == "rpmb":
                    if xml:
                        parttype = "EMMC-RPMB"
                    else:
                        parttype = EmmcPartitionType.MTK_DA_EMMC_PART_RPMB
                    length = min(length, self.emmc.rpmb_size)
            else:
                self.error(
                    "Unknown parttype. Known parttypes are \"boot1\",\"boot2\",\"gp1\",\"gp2\",\"gp3\",\"gp4\",\"rpmb\"")
                return []
        elif storage == DaStorage.MTK_DA_STORAGE_UFS:
            if parttype == "user" or parttype is None:
                if not xml:
                    parttype = UFSPartitionType.USER
                    self.flashsize = self.ufs.lu0_size
                else:
                    parttype = "UFS-LUA2"
                    self.flashsize = self.ufs.lu2_size
            elif parttype == "boot1":
                if not xml:
                    parttype = UFSPartitionType.BOOT1
                    self.flashsize = self.ufs.lu1_size
                else:
                    parttype = "UFS-LUA0"
                    self.flashsize = self.ufs.lu0_size
            elif parttype == "boot2":
                if not xml:
                    parttype = UFSPartitionType.BOOT2
                    self.flashsize = self.ufs.lu2_size
                else:
                    parttype = "UFS-LUA1"
                    self.flashsize = self.ufs.lu0_size
            elif parttype == "rpmb":
                if not xml:
                    parttype = UFSPartitionType.RPMB
                    self.flashsize = self.ufs.lu3_size
                else:
                    parttype = "UFS-LUA3"
                    self.flashsize = self.ufs.lu3_size
            else:
                if not xml:
                    parttype = UFSPartitionType.USER
                if parttype == "lu0":
                    if xml:
                        parttype = "UFS-LUA0"
                    self.flashsize = self.ufs.lu0_size
                elif parttype == "lu1":  # BOOT1
                    if xml:
                        parttype = "UFS-LUA1"
                    self.flashsize = self.ufs.lu1_size
                elif parttype == "lu2":  # BOOT2
                    if xml:
                        parttype = "UFS-LUA2"
                    self.flashsize = self.ufs.lu2_size
                elif parttype == "lu3":
                    if xml:
                        parttype = "UFS-LUA3"
                    self.flashsize = self.ufs.lu3_size
                else:
                    self.error("Unknown parttype. Known parttypes are \"lu1\",\"lu2\",\"lu3\",\"lu4\"")
                    return []
        elif storage in [DaStorage.MTK_DA_STORAGE_NAND, DaStorage.MTK_DA_STORAGE_NAND_MLC,
                         DaStorage.MTK_DA_STORAGE_NAND_SLC, DaStorage.MTK_DA_STORAGE_NAND_TLC,
                         DaStorage.MTK_DA_STORAGE_NAND_SPI, DaStorage.MTK_DA_STORAGE_NAND_AMLC]:
            if xml:
                parttype = "NAND-WHOLE"  # NAND-AREA0
            else:
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            self.flashsize = self.nand.total_size
        elif storage in [DaStorage.MTK_DA_STORAGE_NOR, DaStorage.MTK_DA_STORAGE_NOR_PARALLEL,
                         DaStorage.MTK_DA_STORAGE_NOR_SERIAL]:
            if xml:
                parttype = "NOR-WHOLE"  # NOR-AREA0
            else:
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            self.flashsize = self.nor.available_size
        length = min(length, self.flashsize)
        return [storage, parttype, length]
