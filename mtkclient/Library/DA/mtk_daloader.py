#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import json
import logging
import os
import hashlib
from binascii import hexlify

from mtkclient.Library.DA.xmlflash.xml_lib import DAXML
from mtkclient.Library.gui_utils import LogBase, logsetup, progress
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.DA.daconfig import DAconfig
from mtkclient.Library.DA.legacy.dalegacy_lib import DALegacy
from mtkclient.Library.DA.legacy.dalegacy_flash_param import Legacy_NorInfo, Legacy_EmmcInfo, Legacy_SdcInfo, \
    Legacy_NandInfo64
from mtkclient.Library.DA.xflash.xflash_lib import DAXFlash
from mtkclient.config.brom_config import DAmodes
from mtkclient.Library.DA.xflash.extension.xflash import XFlashExt
from mtkclient.Library.DA.legacy.extension.legacy import LegacyExt
from mtkclient.Library.DA.xmlflash.extension.v6 import XmlFlashExt
from mtkclient.Library.settings import HwParam


class DAloader(metaclass=LogBase):
    def __init__(self, mtk, loglevel=logging.INFO):
        self.xmlft = None
        self.patch = False
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.mtk = mtk
        self.config = mtk.config
        self.loglevel = loglevel
        self.eh = ErrorHandler()
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.echo = self.mtk.port.echo
        self.rbyte = self.mtk.port.rbyte
        self.rdword = self.mtk.port.rdword
        self.rword = self.mtk.port.rword
        self.daconfig = DAconfig(mtk=self.mtk, loader=self.mtk.config.loader,
                                 preloader=self.mtk.config.preloader, loglevel=loglevel)
        self.xft = None
        self.lft = None
        self.da = None
        self.flashmode = None

    def writestate(self):
        config = {}
        if self.mtk.config.chipconfig.damode == DAmodes.LEGACY:
            config["flashmode"] = "LEGACY"
        elif self.mtk.config.chipconfig.damode == DAmodes.XFLASH:
            config["flashmode"] = "XFLASH"
        elif self.mtk.config.chipconfig.damode == DAmodes.XML:
            config["flashmode"] = "XML"
        config["patched"] = self.mtk.daloader.patch
        config["hwcode"] = self.config.hwcode
        if self.config.meid is not None:
            config["meid"] = hexlify(self.config.meid).decode('utf-8')
        if self.config.socid is not None:
            config["socid"] = hexlify(self.config.socid).decode('utf-8')
        config["flashtype"] = self.daconfig.storage.flashtype
        config["flashsize"] = self.daconfig.storage.flashsize
        if config["flashmode"] == "LEGACY":
            if self.mtk.config.chipconfig.dacode in [0x2625, 0x2523, 0x7682, 0x7686, 0x5932]:
                config["m_nor_flash_size"] = self.daconfig.legacy_storage.nor.m_nor_flash_size
                config["m_nor_physical_offset"] = self.daconfig.legacy_storage.nor.m_nor_base_addr
            else:
                config["m_emmc_ua_size"] = self.daconfig.legacy_storage.emmc.m_emmc_ua_size
                config["m_emmc_boot1_size"] = self.daconfig.legacy_storage.emmc.m_emmc_boot1_size
                config["m_emmc_boot2_size"] = self.daconfig.legacy_storage.emmc.m_emmc_boot2_size
                config["m_emmc_gp_size"] = self.daconfig.legacy_storage.emmc.m_emmc_gp_size
                config["m_nand_flash_size"] = self.daconfig.legacy_storage.nand.m_nand_flash_size
                config["m_nor_flash_size"] = self.daconfig.legacy_storage.nor.m_nor_flash_size
                if not self.mtk.config.iot:
                    config["m_sdmmc_ua_size"] = self.daconfig.legacy_storage.sdc.m_sdmmc_ua_size
        if not os.path.exists(self.mtk.config.hwparam_path):
            os.mkdir(self.mtk.config.hwparam_path)
        open(os.path.join(self.mtk.config.hwparam_path, ".state"), "w").write(json.dumps(config))

    def compute_hash_pos(self, da1, da2, da1sig_len, da2sig_len, v6):
        hashlen = len(da2) - da2sig_len
        hashmode, idx = self.calc_da_hash(da1, da2[:hashlen])
        if idx == -1:
            hashlen = len(da2)
            hashmode, idx = self.calc_da_hash(da1, da2[:hashlen])
            if idx == -1 and not v6:
                hashlen = len(da2) - da2sig_len
                idx, hashmode = self.find_da_hash_v5(da1)
            elif idx == -1 and v6:
                hashlen = len(da2) - da2sig_len
                idx, hashmode = self.find_da_hash_v6(da1, da1sig_len)
                if idx == -1:
                    self.error("Hash computation failed.")
                    return None, None, None
            return idx, hashmode, hashlen
        return idx, hashmode, hashlen

    @staticmethod
    def find_da_hash_v6(da1, siglen):
        pos = len(da1) - siglen - 0x30
        _hash = da1[pos:pos + 0x30]
        if _hash[-4:] == b"\x00\x00\x00\x00":
            return pos, 2
        return -1, -1

    def find_da_hash_v5(self, da1):
        idx1 = da1.find(b"MMU MAP: VA")
        if idx1 != -1:
            hashed = da1[idx1 - 0x30:idx1]
            if hashed[-4:] == b"\x00\x00\x00\x00":
                self.debug(f"SHA256({hashed[:0x20].hex()})")
                return idx1 - 0x30, 2
            else:
                self.debug(f"SHA1({hashed[-0x14:].hex()})")
                return idx1 - 0x14, 1
        else:
            self.debug("Error: No hash found")
        return -1, -1

    @staticmethod
    def calc_da_hash(da1, da2):
        hashdigestmd5 = hashlib.md5(da2).digest()
        hashdigest = hashlib.sha1(da2).digest()
        hashdigest256 = hashlib.sha256(da2).digest()
        idx = da1.find(hashdigestmd5)
        hashmode = 0
        if idx == -1:
            idx = da1.find(hashdigest)
            hashmode = 1
            if idx == -1:
                idx = da1.find(hashdigest256)
                hashmode = 2
                if idx == -1:
                    hashmode = -1
        return hashmode, idx

    @staticmethod
    def fix_hash(da1, da2, hashpos, hashmode, hashlen):
        da1 = bytearray(da1)
        dahash = None
        if hashmode == 0:
            dahash = hashlib.md5(da2[:hashlen]).digest()
        elif hashmode == 1:
            dahash = hashlib.sha1(da2[:hashlen]).digest()
        elif hashmode == 2:
            dahash = hashlib.sha256(da2[:hashlen]).digest()
        else:
            return da1
        orighash = da1[hashpos:hashpos + len(dahash)]
        _ = orighash
        da1[hashpos:hashpos + len(dahash)] = dahash
        return da1

    def reinit(self):
        if os.path.exists(os.path.join(self.mtk.config.hwparam_path, ".state")):
            config = json.loads(open(os.path.join(self.mtk.config.hwparam_path, ".state"), "r").read())
            self.config.hwcode = config["hwcode"]
            meid_val = None
            if hasattr(config, 'meid') and config.meid is not None:
                self.config.meid = bytes.fromhex(config["meid"])
                meid_val = self.config.meid.hex()
            if "socid" in config:
                self.config.socid = bytes.fromhex(config["socid"])
            self.config.hwparam = HwParam(self.mtk.config, meid_val, self.mtk.config.hwparam_path)
            if config["flashmode"] == "LEGACY":
                self.mtk.config.chipconfig.damode = DAmodes.LEGACY
                self.flashmode = DAmodes.LEGACY
            elif config["flashmode"] == "XFLASH":
                self.mtk.config.chipconfig.damode = DAmodes.XFLASH
                self.flashmode = DAmodes.XFLASH
            elif config["flashmode"] == "XML":
                self.mtk.config.chipconfig.damode = DAmodes.XML
                self.flashmode = DAmodes.XML
            self.config.init_hwcode(self.config.hwcode)
            if self.flashmode == DAmodes.XML:
                self.da = DAXML(self.mtk, self.daconfig, self.loglevel)
                self.daconfig.storage.flashtype = config["flashtype"]
                self.daconfig.storage.flashsize = config["flashsize"]
                self.da.reinit()
                self.xmlft = XmlFlashExt(self.mtk, self.da, self.loglevel)
                self.xft = None
                self.lft = None
            elif self.flashmode == DAmodes.XFLASH:
                self.da = DAXFlash(self.mtk, self.daconfig, self.loglevel)
                self.daconfig.storage.flashtype = config["flashtype"]
                self.daconfig.storage.flashsize = config["flashsize"]
                self.da.reinit()
                self.xft = XFlashExt(self.mtk, self.da, self.loglevel)
                self.lft = None
                self.xmlft = None
            elif self.flashmode == DAmodes.LEGACY:
                self.da = DALegacy(self.mtk, self.daconfig, self.loglevel)
                self.daconfig.storage.flashtype = config["flashtype"]
                self.daconfig.storage.flashsize = config["flashsize"]
                self.daconfig.legacy_storage.nor = Legacy_NorInfo()
                self.daconfig.legacy_storage.nand = Legacy_NandInfo64()
                self.daconfig.legacy_storage.emmc = Legacy_EmmcInfo(self.config)
                self.daconfig.legacy_storage.sdc = Legacy_SdcInfo(self.config)
                self.lft = LegacyExt(self.mtk, self.da, self.loglevel)
                self.daconfig.legacy_storage.emmc.m_emmc_ua_size = config["m_emmc_ua_size"]
                self.daconfig.legacy_storage.emmc.m_emmc_boot1_size = config["m_emmc_boot1_size"]
                self.daconfig.legacy_storage.emmc.m_emmc_boot2_size = config["m_emmc_boot2_size"]
                self.daconfig.legacy_storage.emmc.m_emmc_gp_size = config["m_emmc_gp_size"]
                self.daconfig.legacy_storage.nand.m_nand_flash_size = config["m_nand_flash_size"]
                if not self.mtk.config.iot:
                    self.daconfig.legacy_storage.sdc.m_sdmmc_ua_size = config["m_sdmmc_ua_size"]
                self.daconfig.legacy_storage.nor.m_nor_flash_size = config["m_nor_flash_size"]
                self.xft = None
                self.xmlft = None
            if "patched" in config:
                self.mtk.daloader.patch = config["patched"]
            return True
        return False

    def patch_da2(self, da2):
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.patch_da2(da2)
        elif self.flashmode == DAmodes.LEGACY:
            return self.lft.patch_da2(da2)
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.patch_da2(da2)
        return False

    def set_da(self):
        self.flashmode = DAmodes.LEGACY
        if self.mtk.config.plcap is not None:
            PL_CAP0_XFLASH_SUPPORT = (0x1 << 0)
            if (self.mtk.config.plcap[0] & PL_CAP0_XFLASH_SUPPORT == PL_CAP0_XFLASH_SUPPORT and
                    self.mtk.config.blver > 1):
                self.flashmode = DAmodes.XFLASH
        if self.mtk.config.chipconfig.damode == DAmodes.XFLASH:
            self.flashmode = DAmodes.XFLASH
        elif self.mtk.config.chipconfig.damode == DAmodes.XML or (
                self.daconfig.da_loader is not None and self.daconfig.da_loader.v6):
            self.flashmode = DAmodes.XML
        if self.flashmode == DAmodes.XFLASH:
            self.da = DAXFlash(self.mtk, self.daconfig, self.loglevel)
            self.da.patch = self.patch
            self.xft = XFlashExt(self.mtk, self.da, self.loglevel)
        elif self.flashmode == DAmodes.LEGACY:
            self.da = DALegacy(self.mtk, self.daconfig, self.loglevel)
            self.da.patch = self.patch
            self.lft = LegacyExt(self.mtk, self.da, self.loglevel)
        elif self.flashmode == DAmodes.XML:
            self.da = DAXML(self.mtk, self.daconfig, self.loglevel)
            self.da.patch = self.patch
            self.xmlft = XmlFlashExt(self.mtk, self.da, self.loglevel)

    def setmetamode(self, porttype: str):
        if self.mtk.config.chipconfig.damode == DAmodes.XFLASH:
            self.da = DAXFlash(self.mtk, self.daconfig, self.loglevel)
            if porttype not in ["off", "usb", "uart"]:
                self.error('Only "off","usb" or "uart" are allowed.')
            if self.da.set_meta(porttype):
                self.info(f"Successfully set meta mode to {porttype}")
                return True
            else:
                self.error("Setting meta mode in xflash failed.")
        self.error("Device is not in xflash mode, cannot run meta cmd.")
        return False

    def detect_partition(self, partitionname, parttype=None):
        if self.partition_table_category() == "GPT":
            fpartitions = []
            data, guid_gpt = self.da.partition.get_gpt(self.mtk.config.gpt_settings, parttype)
            if guid_gpt is None:
                return [False, fpartitions]
            else:
                for partition in guid_gpt.partentries:
                    fpartitions.append(partition)
                    if partition.name.lower() == partitionname.lower():
                        return [True, partition]
            return [False, fpartitions]
        else:
            data, partitions = self.da.partition.read_pmt()
            return [True, partitions]

    def get_partition_data(self, parttype=None):
        if self.partition_table_category() == "GPT":
            fpartitions = []
            data, guid_gpt = self.da.partition.get_gpt(self.mtk.config.gpt_settings, parttype)
            if guid_gpt is None:
                return [False, fpartitions]
            else:
                return guid_gpt.partentries
        else:
            data, partitions = self.da.partition.read_pmt()
            return [True, partitions]

    def get_gpt(self, parttype=None) -> tuple:
        if self.partition_table_category() == "GPT":
            data, guid_gpt = self.da.partition.get_gpt(self.mtk.config.gpt_settings, parttype)
            return data, guid_gpt
        else:
            data, partitions = self.da.partition.read_pmt()
            return data, partitions

    def upload(self):
        return self.da.upload_da1()

    class ShutDownModes:
        NORMAL = 0
        HOME_SCREEN = 1
        FASTBOOT = 2

    def shutdown(self, bootmode=ShutDownModes.NORMAL):
        return self.da.shutdown(async_mode=0, dl_bit=0, bootmode=bootmode)

    def upload_da(self, preloader=None):
        self.daconfig.setup()
        self.daconfig.extract_emi(preloader)
        self.set_da()
        return self.da.upload_da()

    def boot_to(self, addr, data, display=True, timeout=0.5):
        if self.da.boot_to(addr, data, display=display):
            return True
        return False

    def writeflash(self, addr, length, filename: str = "", offset=0, parttype=None, wdata=None, display=True):
        return self.da.writeflash(addr=addr, length=length, filename=filename, offset=offset,
                                  parttype=parttype, wdata=wdata, display=display)

    def formatflash(self, addr, length, partitionname, parttype, display=True):
        return self.da.formatflash(addr=addr, length=length, parttype=parttype, display=display)

    def readflash(self, addr, length, filename, parttype, display=True):
        return self.da.readflash(addr=addr, length=length, filename=filename, parttype=parttype, display=display)

    def get_packet_length(self):
        if self.flashmode == DAmodes.XFLASH:
            pt = self.da.get_packet_length()
            return pt.read_packet_length
        else:
            return 512

    def peek(self, addr: int, length: int, registers: bool = True):
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.custom_read(addr=addr, length=length, registers=registers)
        elif self.flashmode == DAmodes.LEGACY:
            return self.lft.custom_read(addr=addr, length=length, registers=registers)
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.custom_read(addr=addr, length=length, registers=registers)

    def peek_reg(self, addr: int, length: int):
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.custom_read_reg(addr=addr, length=length)
        elif self.flashmode == DAmodes.LEGACY:
            return self.lft.custom_read_reg(addr=addr, length=length)
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.custom_read_reg(addr=addr, length=length)

    def dump_brom(self, filename):
        rm = None
        if self.flashmode == DAmodes.XFLASH:
            rm = self.xft.readmem
        elif self.flashmode == DAmodes.LEGACY:
            rm = self.lft.readmem
        elif self.flashmode == DAmodes.XML:
            rm = self.xmlft.readmem

        with open(filename, "wb") as wf:
            length = 0x200000
            bytesread = 0
            pg = progress(total=length, prefix="Dump")
            for addr in range(0x0, length, 0x40):
                tmp = rm(addr, 0x10)
                bytesread += 0x40
                pg.update(0x40)
                dtmp = b"".join([int.to_bytes(val, 4, 'little') for val in tmp])
                wf.write(dtmp)
            pg.done()

    def partition_table_category(self):
        # if self.flashmode == damodes.XFLASH:
        #    return self.xft.get_partition_table_category()
        return "GPT"

    def poke(self, addr: int, data: bytes or bytearray):
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.custom_write(addr=addr, data=data)
        elif self.flashmode == DAmodes.LEGACY:
            return self.lft.custom_write(addr=addr, data=data)
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.custom_write(addr=addr, data=data)

    def keys(self):
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.generate_keys()
        elif self.flashmode == DAmodes.LEGACY:
            return self.lft.generate_keys()
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.generate_keys()

    def keyserver(self):
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.keyserver()
        elif self.flashmode == DAmodes.LEGACY:
            return self.lft.keyserver()
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.keyserver()

    def readfuses(self):
        if self.flashmode == DAmodes.XFLASH:
            pass
        elif self.flashmode == DAmodes.LEGACY:
            pass
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.readfuses()

    def is_patched(self):
        return self.da.patch

    def seccfg(self, lockflag):
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.seccfg(lockflag)
        elif self.flashmode == DAmodes.LEGACY:
            return self.lft.seccfg(lockflag)
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.seccfg(lockflag)

    def nvitem(self, data=None, filename=None, encrypt=False, otp=None, seed=None, aeskey=None, display: bool = True):
        if data:
            if self.flashmode == DAmodes.XFLASH:
                return self.xft.nvitem(data=data,
                                       encrypt=encrypt,
                                       otp=otp,
                                       seed=seed,
                                       aeskey=aeskey,
                                       display=display)
            elif self.flashmode == DAmodes.XML:
                return self.xmlft.nvitem(data=data,
                                         encrypt=encrypt,
                                         otp=otp,
                                         seed=seed,
                                         aeskey=aeskey,
                                         display=display)
        elif filename != "":
            with open(filename, "rb") as rf:
                if self.flashmode == DAmodes.XFLASH:
                    return self.xft.nvitem(data=rf.read(),
                                           encrypt=encrypt,
                                           otp=otp,
                                           seed=seed,
                                           aeskey=aeskey,
                                           display=display)
                elif self.flashmode == DAmodes.XML:
                    return self.xmlft.nvitem(data=rf.read(),
                                             encrypt=encrypt,
                                             otp=otp,
                                             seed=seed,
                                             aeskey=aeskey,
                                             display=display)

    def encrypt_nvitem(self, filename=None, otp=None, seed=None, aeskey=None):
        with open(filename, "rb") as rf:
            if self.flashmode == DAmodes.XFLASH:
                return self.xmlft.encrypt_nvitem(data=rf.read(), encrypt=False,
                                                 otp=otp,
                                                 seed=seed,
                                                 aeskey=aeskey)
            elif self.flashmode == DAmodes.XML:
                return self.xmlft.encrypt_nvitem(data=rf.read(),
                                                 otp=otp,
                                                 seed=seed,
                                                 aeskey=aeskey)

    def str_to_int(self, arg):
        if arg is not None:
            if "0x" in arg:
                value = int(arg, 16)
            else:
                value = int(arg, 10)
        else:
            value = 0
        return value

    def read_rpmb(self, filename=None, sector: str = None, sectors: str = None):
        sector = self.str_to_int(sector)
        sectors = self.str_to_int(sectors)
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.read_rpmb(filename, sector, sectors)
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.read_rpmb(filename, sector, sectors)
        self.error("Device is not in xflash/xml mode, cannot run read rpmb cmd.")
        return False

    def write_rpmb(self, filename=None, sector: int = 0, sectors: int = None):
        sector = self.str_to_int(sector)
        sectors = self.str_to_int(sectors)
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.write_rpmb(filename, sector, sectors)
        elif self.flashmode == DAmodes.XML:
            return self.xmlft.write_rpmb(filename, sector, sectors)
        self.error("Device is not in xflash/xml mode, cannot run write rpmb cmd.")
        return False

    def erase_rpmb(self, sector: int = 0, sectors: int = None):
        sector = self.str_to_int(sector)
        sectors = self.str_to_int(sectors)
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.erase_rpmb(sector, sectors)
        if self.flashmode == DAmodes.XML:
            return self.xmlft.erase_rpmb(sector, sectors)
        self.error("Device is not in xflash/xml mode, cannot run erase rpmb cmd.")
        return False

    def auth_rpmb(self, rpmbkey: bytes = None):
        if self.flashmode == DAmodes.XFLASH:
            return self.xft.auth_rpmb(rpmbkey)
        if self.flashmode == DAmodes.XML:
            return self.xmlft.auth_rpmb(rpmbkey)
        self.error("Device is not in xflash/xml mode, cannot run erase rpmb cmd.")
        return False
