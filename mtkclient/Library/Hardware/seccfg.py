from struct import pack
import os
import hashlib
import logging
from io import BytesIO

from mtkclient.Library.Hardware.hwcrypto_sej import sej_cryptmode
from mtkclient.Library.gui_utils import structhelper_io, logsetup, LogBase
from mtkclient.config.mtk_config import MtkConfig


class SecCfgV4(metaclass=LogBase):
    def __init__(self, _hwc, mtk, custom_sej_hw=None, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.hwtype = None
        self.hwc = _hwc
        self.mtk = mtk
        self.magic = 0x4D4D4D4D
        self.seccfg_ver = None
        self.seccfg_size = None
        self.lock_state = None
        self.critical_lock_state = None
        self.sboot_runtime = None
        self.endflag = 0x45454545
        self.hash = b""
        self.custom_sej_hw = custom_sej_hw
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

    def protect(self, data):
        return data
        """
        data=bytearray(data)
        hrid = self.mtk.daloader.peek(self.mtk.config.chipconfig.efuse_addr + 0x140, 8)
        hwcode = int.to_bytes(self.mtk.config.hwcode, 4, 'little')
        for i in range(len(data)):
            data[i] = data[i] ^ hrid[i % 8]
        for i in range(len(data)):
            data[i] = data[i] ^ hwcode[i % 4]
        return data
        """

    def parse(self, indata) -> bool:
        rrf = structhelper_io(BytesIO(bytearray(indata)))
        self.magic = rrf.dword()
        self.seccfg_ver = rrf.dword()
        self.seccfg_size = rrf.dword()
        self.lock_state = rrf.dword()
        self.critical_lock_state = rrf.dword()
        self.sboot_runtime = rrf.dword()
        self.endflag = rrf.dword()
        rrf.seek(self.seccfg_size - 0x20)
        self.hash = rrf.bytes(0x20)
        if self.magic != 0x4D4D4D4D or self.endflag != 0x45454545:
            self.error("Unknown V4 seccfg structure !")
            return False
        seccfg_data = pack("<IIIIIII", self.magic, self.seccfg_ver, self.seccfg_size, self.lock_state,
                           self.critical_lock_state, self.sboot_runtime, 0x45454545)
        _hash = hashlib.sha256(seccfg_data).digest()
        dec_hash = self.hwc.sej.sej_sec_cfg_sw(self.hash, False)
        if _hash == dec_hash:
            self.hwtype = "SW"
        else:
            if self.custom_sej_hw is not None:
                # ddata = self.protect(self.hash)
                status, dec_hash = self.custom_sej_hw(encrypt=False,
                                                      data=self.hash,
                                                      cryptmode=sej_cryptmode.UNLOCK,
                                                      otp=self.mtk.config.get_otp(),
                                                      seed=b"12abcdef",
                                                      aeskey=bytes.fromhex(
                                                          "0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000"),
                                                      enxor=False)
                # dec_hash = self.protect(dec_hash)
                if _hash == dec_hash:
                    self.hwtype = "HW"
                else:
                    status, dec_hash = self.custom_sej_hw(encrypt=False,
                                                          data=self.hash,
                                                          cryptmode=sej_cryptmode.UNLOCK,
                                                          otp=self.mtk.config.get_otp(),
                                                          seed=b"12abcdef",
                                                          aeskey=bytes.fromhex(
                                                              "0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000"),
                                                          enxor=True)
                    # dec_hash = self.protect(dec_hash)
                    if _hash == dec_hash:
                        self.hwtype = "HWXOR"
            else:
                dec_hash = self.hwc.sej.sej_sec_cfg_hw_V3(self.hash, False)
                if _hash == dec_hash:
                    self.hwtype = "V3"
                else:
                    dec_hash = self.hwc.sej.sej_sec_cfg_hw_V3(self.hash, False, legacy=True)
                    if _hash == dec_hash:
                        self.hwtype = "V4"
                    else:
                        dec_hash = self.hwc.sej.sej_sec_cfg_hw(self.hash, False)
                        if _hash == dec_hash:
                            self.hwtype = "V2"
                        else:
                            return False
            if self.hwtype is None:
                self.info(f"hwtype not supported: {self.hwtype}")
                return False
            self.info(f"hwtype found: {self.hwtype}")
        """
        LKS_DEFAULT = 0x01
        LKS_MP_DEFAULT = 0x02
        LKS_UNLOCK = 0x03
        LKS_LOCK = 0x04
        LKS_VERIFIED = 0x05
        LKS_CUSTOM = 0x06
        LKCS_UNLOCK = 0x01
        LKCS_LOCK = 0x02
        SBOOT_RUNTIME_OFF = 0
        SBOOT_RUNTIME_ON  = 1
        """
        return True

    def create(self, lockflag: str = "unlock"):
        if lockflag == "lock" and self.lock_state == 1:
            return False, "Device is already locked"
        elif lockflag == "unlock" and self.lock_state == 3:
            return False, "Device is already unlocked"
        if lockflag == "unlock":
            self.lock_state = 3
            self.critical_lock_state = 1
        elif lockflag == "lock":
            self.lock_state = 1
            self.critical_lock_state = 0
        seccfg_data = pack("<IIIIIII", self.magic, self.seccfg_ver, self.seccfg_size, self.lock_state,
                           self.critical_lock_state, self.sboot_runtime, 0x45454545)
        dec_hash = hashlib.sha256(seccfg_data).digest()
        enc_hash = b""
        if self.hwtype == "SW":
            enc_hash = self.hwc.sej.sej_sec_cfg_sw(dec_hash, encrypt=True)
        elif self.hwtype == "HW":
            status, enc_hash = self.custom_sej_hw(encrypt=False,
                                                  data=dec_hash,
                                                  cryptmode=sej_cryptmode.UNLOCK,
                                                  otp=self.mtk.config.get_otp(),
                                                  seed=b"12abcdef",
                                                  aeskey=bytes.fromhex(
                                                      "0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000"),
                                                  enxor=False)
        elif self.hwtype == "HWXOR":
            status, enc_hash = self.custom_sej_hw(encrypt=False,
                                                  data=dec_hash,
                                                  cryptmode=sej_cryptmode.UNLOCK,
                                                  otp=self.mtk.config.get_otp(),
                                                  seed=b"12abcdef",
                                                  aeskey=bytes.fromhex(
                                                      "0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000"),
                                                  enxor=True)
        elif self.hwtype == "V2":
            enc_hash = self.hwc.sej.sej_sec_cfg_hw(dec_hash, encrypt=True)
        elif self.hwtype == "V3":
            enc_hash = self.hwc.sej.sej_sec_cfg_hw_V3(dec_hash, encrypt=True)
        elif self.hwtype == "V4":
            enc_hash = self.hwc.sej.sej_sec_cfg_hw_V3(dec_hash, encrypt=True, legacy=True)
        indata = seccfg_data + enc_hash
        while len(indata) % 0x200 != 0:
            indata += b"\x00"
        return True, bytearray(indata)


class SeccfgStatus:
    SEC_CFG_COMPLETE_NUM = 0x43434343  # CCCC
    SEC_CFG_INCOMPLETE_NUM = 0x49494949  # IIII


class SeccfgAttr:
    ATTR_LOCK = 0x6000
    ATTR_VERIFIED = 0x6001
    ATTR_CUSTOM = 0x6002
    ATTR_MP_DEFAULT = 0x6003
    ATTR_DEFAULT = 0x33333333
    ATTR_UNLOCK = 0x44444444


class SiuStatus:
    UBOOT_UPDATED_BY_SIU = 0x0001
    BOOT_UPDATED_BY_SIU = 0x0010
    RECOVERY_UPDATED_BY_SIU = 0x0100
    SYSTEM_UPDATED_BY_SIU = 0x1000


class RomType:
    NORMAL_ROM = 0x01
    YAFFS_IMG = 0x08


class SecImgAttr:
    ATTR_SEC_IMG_UPDATE = 0x10,
    ATTR_SEC_IMG_COMPLETE = 0x43434343,  # CCCC
    ATTR_SEC_IMG_INCOMPLETE = 0x49494949,  # IIII
    ATTR_SEC_IMG_FORCE_UPDATE = 0x46464646  # FFFF


class SecCfgV3(metaclass=LogBase):
    def __init__(self, _hwc, mtk, custom_sej_hw=None, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.hwtype = None
        self.data = None
        self.org_data = None
        self.hwc = _hwc
        self.mtk = mtk
        self.info_header = b"AND_SECCFG_v\x00\x00\x00\x00"
        self.magic = 0x4D4D4D4D
        self.seccfg_ver = 3
        self.seccfg_size = 0x1860
        self.seccfg_enc_len = 0x01000000  # 0x07F20000 for unlocked
        self.seccfg_enc_offset = 0
        self.endflag = 0x45454545
        self.sw_sec_lock_try = 0
        self.sw_sec_lock_done = 0
        self.page_size = 0
        self.page_count = 0
        self.imginfo = b"\x00" * (0x68 * 20)
        self.siu_status = 0
        self.custom_sej_hw = custom_sej_hw
        self.seccfg_status = SeccfgStatus.SEC_CFG_COMPLETE_NUM
        self.seccfg_attr = SeccfgAttr.ATTR_DEFAULT
        self.seccfg_ext = b"\x00" * 0x1004
        if self.hwc.read32 is not None:
            self.setotp(_hwc)
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

    def setotp(self, _hwc):
        otp = None
        if self.mtk.config.preloader is not None:
            idx = self.mtk.config.preloader.find(b"\x4D\x4D\x4D\x01\x30")
            if idx != -1:
                otp = self.mtk.config.preloader[idx + 0xC:idx + 0xC + 32]
        if otp is None:
            otp = 32 * b"\x00"
        _hwc.sej.sej_set_otp(otp)

    def parse(self, indata) -> bool:
        if indata[:0x10] != b"AND_SECCFG_v\x00\x00\x00\x00":
            return False
        rrf = structhelper_io(BytesIO(bytearray(indata)))
        self.info_header = rrf.bytes(0x10)
        self.magic = rrf.dword()
        self.seccfg_ver = rrf.dword()
        self.seccfg_size = rrf.dword()
        self.seccfg_enc_offset = rrf.dword()
        self.seccfg_enc_len = rrf.dword()  # 0x1 = Locked, 0xF207 = Unlocked
        self.sw_sec_lock_try = rrf.bytes(1)
        self.sw_sec_lock_done = rrf.bytes(1)
        self.page_size = rrf.short()
        self.page_count = rrf.dword()
        self.data = rrf.bytes(self.seccfg_size - 0x2C - 4)
        self.endflag = rrf.dword()
        if self.magic != 0x4D4D4D4D or self.endflag != 0x45454545:
            self.error("Unknown V3 seccfg structure !")
            return False
        err = self.hwc.sej.sej_sec_cfg_sw(self.data, encrypt=False)
        if err[:4] not in [b"IIII", b"CCCC", b"\x00\x00\x00\x00"]:
            err = self.hwc.sej.sej_sec_cfg_hw_V3(self.data, encrypt=False)
            if err[:4] not in [b"IIII", b"CCCC", b"\x00\x00\x00\x00"]:
                err = self.hwc.sej.sej_sec_cfg_hw(self.data, encrypt=False)
                if err[:4] not in [b"IIII", b"CCCC", b"\x00\x00\x00\x00"]:
                    err = self.hwc.sej.sej_sec_cfg_hw_V3(self.data, encrypt=False, legacy=True)
                    if err[:4] not in [b"IIII", b"CCCC", b"\x00\x00\x00\x00"]:
                        self.error("Unknown V3 seccfg encryption !")
                        return False
                    else:
                        self.hwtype = "V4"
                else:
                    self.hwtype = "V3"
            else:
                self.hwtype = "V2"
        else:
            self.hwtype = "SW"
        self.org_data = err
        ed = structhelper_io(BytesIO(bytearray(err)))
        self.imginfo = [ed.bytes(0x68) for _ in range(20)]
        self.siu_status = ed.dword()
        self.seccfg_status = ed.dword()
        if self.seccfg_status not in [SeccfgStatus.SEC_CFG_COMPLETE_NUM, SeccfgStatus.SEC_CFG_INCOMPLETE_NUM]:
            return False
        self.seccfg_attr = ed.dword()
        if self.seccfg_attr not in [SeccfgAttr.ATTR_DEFAULT, SeccfgAttr.ATTR_UNLOCK, SeccfgAttr.ATTR_MP_DEFAULT,
                                    SeccfgAttr.ATTR_LOCK, SeccfgAttr.ATTR_CUSTOM, SeccfgAttr.ATTR_VERIFIED]:
            return False
        self.seccfg_ext = ed.bytes(0x1000 + 4)
        return True

    def create(self, lockflag: str = "unlock"):
        seccfg_attr_new = SeccfgAttr.ATTR_DEFAULT
        if lockflag == "unlock":
            self.seccfg_enc_len = 0x07F20000
            seccfg_attr_new = SeccfgAttr.ATTR_UNLOCK
        elif lockflag == "lock":
            self.seccfg_enc_len = 0x01000000
            seccfg_attr_new = SeccfgAttr.ATTR_DEFAULT
        if lockflag == "lock" and self.seccfg_attr in [SeccfgAttr.ATTR_LOCK, SeccfgAttr.ATTR_DEFAULT]:
            return False, "Device is already locked !"
        elif lockflag == "unlock" and self.seccfg_attr == SeccfgAttr.ATTR_UNLOCK:
            return False, "Device is already unlocked !"
        elif lockflag == "lock" and self.seccfg_attr != SeccfgAttr.ATTR_UNLOCK:
            return False, "Can't find lock state, current (%#x)" % self.seccfg_attr
        elif lockflag == "unlock" and self.seccfg_attr != SeccfgAttr.ATTR_DEFAULT \
                and self.seccfg_attr != SeccfgAttr.ATTR_MP_DEFAULT \
                and self.seccfg_attr != SeccfgAttr.ATTR_CUSTOM \
                and self.seccfg_attr != SeccfgAttr.ATTR_VERIFIED \
                and self.seccfg_attr != SeccfgAttr.ATTR_LOCK:
            return False, "Can't find unlock state, current (%#x)" % self.seccfg_attr

        indata = bytearray()
        wf = BytesIO(indata)
        wf.write(self.info_header)
        wf.write(int.to_bytes(self.magic, 4, 'little'))
        wf.write(int.to_bytes(self.seccfg_ver, 4, 'little'))
        wf.write(int.to_bytes(self.seccfg_size, 4, 'little'))
        wf.write(int.to_bytes(self.seccfg_enc_offset, 4, 'little'))
        wf.write(int.to_bytes(self.seccfg_enc_len, 4, 'little'))
        wf.write(int.to_bytes(self.sw_sec_lock_try, 1, 'little'))
        wf.write(int.to_bytes(self.sw_sec_lock_done, 1, 'little'))
        wf.write(int.to_bytes(self.page_size, 2, 'little'))
        wf.write(int.to_bytes(self.page_count, 4, 'little'))

        ed = BytesIO()
        for imginfo in self.imginfo:
            ed.write(bytearray(imginfo))
        ed.write(int.to_bytes(self.siu_status, 4, 'little'))
        ed.write(int.to_bytes(self.seccfg_status, 4, 'little'))
        ed.write(int.to_bytes(seccfg_attr_new, 4, 'little'))
        ed.write(self.seccfg_ext)
        indata = ed.getbuffer()
        if self.hwtype == "SW":
            indata = self.hwc.sej.sej_sec_cfg_sw(indata, encrypt=True)
        elif self.hwtype == "V2":
            indata = self.hwc.sej.sej_sec_cfg_hw(indata, encrypt=True)
        elif self.hwtype == "V3":
            indata = self.hwc.sej.sej_sec_cfg_hw_V3(indata, encrypt=True)
        elif self.hwtype == "V4":
            indata = self.hwc.sej.sej_sec_cfg_hw_V3(indata, encrypt=True, legacy=True)
        else:
            return False, "Unknown error"
        wf.write(indata)
        wf.write(int.to_bytes(self.endflag, 4, 'little'))

        indata = bytearray(wf.getbuffer())
        while len(indata) % 0x200 != 0:
            indata += b"\x00"
        return True, bytearray(indata)


if __name__ == "__main__":
    with open("seccfg.bin", "rb") as rf:
        data = rf.read()
    from hwcrypto import HwCrypto, CryptoSetup

    setup = CryptoSetup()
    hwc = HwCrypto(setup)

    class MTK:
        config = MtkConfig()
        sej_base = None

    v3 = SecCfgV3(hwc, MTK, None)
    v3.parse(data)
    v4 = SecCfgV4(hwc, MTK, None)
    v4.parse(data)
    ret, newdata = v4.create("lock")
    print(newdata.hex())
