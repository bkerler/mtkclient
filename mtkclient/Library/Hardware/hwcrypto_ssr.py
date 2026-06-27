#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License

# SSR = Scalable Security Root

import logging
import struct
from enum import Enum
from types import SimpleNamespace
from typing import Callable, Optional, Tuple
import time

try:
    from Crypto.Util.number import long_to_bytes
except ModuleNotFoundError:
    def long_to_bytes(value: int, blocksize: int = 0) -> bytes:
        if value < 0:
            raise ValueError("long_to_bytes only supports non-negative integers")
        if value == 0:
            raw = b"\x00"
        else:
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if blocksize > 0 and len(raw) % blocksize:
            raw = b"\x00" * (blocksize - (len(raw) % blocksize)) + raw
        return raw

from mtkclient.Library.Hardware import RegisterMap
from mtkclient.Library.gui_utils import LogBase, logsetup

ecc_domain_p256 = [
    0xd835c65a, 0xe7933aaa, 0x55bdebb3, 0xbc869876,
    0xb0061d65, 0xf6b053cc, 0x3e3cce3b, 0x4b60d227
]

ecc_domain_p384 = [
    0xa72f31b3, 0xe4e73ee2, 0x6b058e98, 0x192df8e3,
    0x6e9c1d18, 0x124181fe, 0x8f081403, 0x5a871350,
    0x8d3956c6, 0x9dd12e8a, 0xedc8852a, 0xef2aecd3
]

def genmask(h: int, l: int) -> int:
    if not (0 <= l <= h <= 63):
        raise ValueError("GENMASK: must satisfy 0 <= l <= h <= 63 (64-bit macro)")
    width = h - l + 1
    return ((1 << width) - 1) << l


SSR_KDF_HKDF_CMD_START = 0
SSR_KDF_HKDF_CMD_FIXED = (1 << 5 | 1 << 1)
SSR_KDF_HKDF_CMD_NO_SALT = 1 << 3
SSR_KDF_HKDF_CMD_IKM_LEN = genmask(15, 8)
SSR_KDF_HKDF_CMD_SALT_LEN = genmask(23, 16)
SSR_KDF_HKDF_CMD_INFO_LEN = genmask(31, 24)
SSR_KDF_HKDF_STS_ERR = genmask(4, 0)
SSR_CLK_RNG = (1 << 0)
SSR_CLK_CCC = (1 << 8)
SSR_CLK_KDF = (1 << 16)
SSR_CLK_PKA = (1 << 24)
SSR_KDF_CMAC_ST_DONE = 0x80000000
SSR_INIT_MAGIC1 = 0x35003400
SSR_INIT_MAGIC2 = 0x06BF3701
SSR_TIMEOUT = 5000

class RpmbType(Enum):
    RPMB = 0
    FDE = 1
    TEE = 2
    AES_IMG_ENC = 3
    AES_CUSTOM = 4
    MOTOROLA = 5
    ROT = 6
    CUSTOM1 = 7
    CUSTOM2 = 8


class KDFType(Enum):
    SW_KEY = 0
    INT_REG0 = 2
    FUSE_KDR = 4


class AESType(Enum):
    AES_256 = 0
    AES_128 = 1
    AES_192 = 2


class AESKeyLen(Enum):
    AES_256 = 0x20
    AES_128 = 0x10
    AES_192 = 0x18


class PKA_ECC(Enum):
    ECC_CURVE_NIST_P256 = 0
    ECC_CURVE_NIST_P384 = 4


class PKA_RSA(Enum):
    RSA_1024 = 0
    RSA_2048 = 1
    RSA_3072 = 2
    RSA_4096 = 3


class PKA_OP(Enum):
    RSA_MODEXP = 2
    ECC_GENKEY = 5
    ECC_SIGN_P256 = 6
    ECC_SIGN_P384 = 7
    ECC_VERIFY_P256 = 8
    ECC_VERIFY_P384 = 9

SSR_PKA_ECC_P256_WORDS      =8
SSR_PKA_ECC_P384_WORDS      =12
PKA_RSA_SIGN_TIMEOUT        =10000


class CCC_SHAType(Enum):
    SHA256 = 0
    SHA384 = 6

clk_regs = {
    "CFG_UPDATE_OFFSET" : 0xC,
    "CFG_SET_OFFSET" : 0x104,
    "CFG_CLR_OFFSET" : 0x108,
    "CFG_16_SET" : 0x114,
    "CFG_16_CLR" : 0x118,
    "CFG_17_SET" : 0x124,
    "CFG_17_CLR" : 0x128,
    "CFG_CMAC_SET": 0x184,
    "CFG_CMAC_CLR": 0x188,
}

ccc_regs = {
    "BASE": 0,
    "CTRL": 0x08,
    "STATUS0": 0x14,
    "STATUS1": 0x18,
    "CMAC_OUT0": 0x1C,
    "CMAC_OUT1": 0x20,
    "CMAC_OUT2": 0x24,
    "CMAC_OUT3": 0x28,
    "SHA_JOB_ID": 0x2C,
    "JOB_ID": 0x54,
    "SHA_OUT": 0x34,
    "QUEUE_AVAILABLE": 0x100,
    "QUEUE": 0x104,
    "HW_INIT_CFG0": 0x2AC,
    "HW_INIT_CFG1": 0x2B0,
    "SKIP_KS_INIT": 0x2D4,
    "HW_ERROR2": 0x2D8,
    "SSR_BOOT": 0x2F8
}

kdf_regs = {
    "SSR_BASE": 0x0000,
    "SSR_KDF_CMAC_OUT0": 0x000,
    "SSR_KDF_CMAC_OUT1": 0x004,
    "SSR_KDF_CMAC_OUT2": 0x008,
    "SSR_KDF_CMAC_OUT3": 0x00C,
    "SSR_KDF_CMAC_OUT4": 0x010,
    "SSR_KDF_CMAC_OUT5": 0x014,
    "SSR_KDF_CMAC_OUT6": 0x018,
    "SSR_KDF_CMAC_OUT7": 0x01C,
    "SSR_KDF_CMAC_OUT8": 0x020,
    "SSR_KDF_CMAC_OUT9": 0x024,
    "SSR_KDF_CMAC_OUT10": 0x028,
    "SSR_KDF_CMAC_OUT11": 0x02C,
    "SSR_KDF_CMAC_OUT12": 0x030,
    "SSR_KDF_CMAC_OUT13": 0x034,
    "SSR_KDF_CMAC_OUT14": 0x038,
    "SSR_KDF_CMAC_OUT15": 0x03C,
    "SSR_KDF_CMAC_FIN0": 0x040,
    "SSR_KDF_CMAC_FIN1": 0x044,
    "SSR_KDF_CMAC_FIN2": 0x048,
    "SSR_KDF_CMAC_FIN3": 0x04C,
    "SSR_KDF_CMAC_FIN4": 0x050,
    "SSR_KDF_CMAC_FIN5": 0x054,
    "SSR_KDF_CMAC_FIN6": 0x058,
    "SSR_KDF_CMAC_FIN7": 0x05C,
    "SSR_KDF_CMAC_FIN8": 0x060,
    "SSR_KDF_CMAC_FIN9": 0x064,
    "SSR_KDF_CMAC_FIN10": 0x068,
    "SSR_KDF_CMAC_FIN11": 0x06C,
    "SSR_KDF_CMAC_FIN12": 0x070,
    "SSR_KDF_CMAC_FIN13": 0x074,
    "SSR_KDF_CMAC_FIN14": 0x078,
    "SSR_KDF_CMAC_FIN15": 0x07C,
    "SSR_KDF_CMAC_FIN16": 0x080,
    "SSR_KDF_CMAC_CMD": 0x084,
    "SSR_KDF_CMAC_STS": 0x08C,  # status
    "SSR_KDF_CMAC_LBL0": 0x0A0,
    "SSR_KDF_CMAC_LBL1": 0x0A4,
    "SSR_KDF_CMAC_LBL2": 0x0A8,
    "SSR_KDF_CMAC_LBL3": 0x0AC,
    "SSR_KDF_CMAC_LBL4": 0x0B0,
    "SSR_KDF_CMAC_LBL5": 0x0B4,
    "SSR_KDF_CMAC_LBL6": 0x0B8,
    "SSR_KDF_CMAC_LBL7": 0x0BC,
    "SSR_KDF_CMAC_ST": 0x0CC,  # self-test
    "SSR_KDF_HKDF_IKM0": 0x100,
    "SSR_KDF_HKDF_IKM1": 0x104,
    "SSR_KDF_HKDF_IKM2": 0x108,
    "SSR_KDF_HKDF_IKM3": 0x10C,
    "SSR_KDF_HKDF_IKM4": 0x110,
    "SSR_KDF_HKDF_IKM5": 0x114,
    "SSR_KDF_HKDF_IKM6": 0x118,
    "SSR_KDF_HKDF_IKM7": 0x11C,
    "SSR_KDF_HKDF_IKM8": 0x120,
    "SSR_KDF_HKDF_IKM9": 0x124,
    "SSR_KDF_HKDF_IKM10": 0x128,
    "SSR_KDF_HKDF_IKM11": 0x12C,
    "SSR_KDF_HKDF_IKM12": 0x130,
    "SSR_KDF_HKDF_IKM13": 0x134,
    "SSR_KDF_HKDF_IKM14": 0x138,
    "SSR_KDF_HKDF_IKM15": 0x13C,
    "SSR_KDF_HKDF_SALT0": 0x140,
    "SSR_KDF_HKDF_SALT1": 0x144,
    "SSR_KDF_HKDF_SALT2": 0x148,
    "SSR_KDF_HKDF_SALT3": 0x14C,
    "SSR_KDF_HKDF_SALT4": 0x150,
    "SSR_KDF_HKDF_SALT5": 0x154,
    "SSR_KDF_HKDF_SALT6": 0x158,
    "SSR_KDF_HKDF_SALT7": 0x15C,
    "SSR_KDF_HKDF_INFO0": 0x160,
    "SSR_KDF_HKDF_INFO1": 0x164,
    "SSR_KDF_HKDF_INFO2": 0x168,
    "SSR_KDF_HKDF_INFO3": 0x16C,
    "SSR_KDF_HKDF_INFO4": 0x170,
    "SSR_KDF_HKDF_INFO5": 0x174,
    "SSR_KDF_HKDF_INFO6": 0x178,
    "SSR_KDF_HKDF_INFO7": 0x17C,
    "SSR_KDF_HKDF_INFO8": 0x180,
    "SSR_KDF_HKDF_INFO9": 0x184,
    "SSR_KDF_HKDF_INFO10": 0x188,
    "SSR_KDF_HKDF_INFO11": 0x18C,
    "SSR_KDF_HKDF_STS": 0x198,
    "SSR_KDF_HKDF_CMD": 0x19C,
    "SSR_KDF_HKDF_OUT0": 0x1C0,
    "SSR_KDF_HKDF_OUT1": 0x1C4,
    "SSR_KDF_HKDF_OUT2": 0x1C8,
    "SSR_KDF_HKDF_OUT3": 0x1CC,
    "SSR_KDF_HKDF_OUT4": 0x1D0,
    "SSR_KDF_HKDF_OUT5": 0x1D4,
    "SSR_KDF_HKDF_OUT6": 0x1D8,
    "SSR_KDF_HKDF_OUT7": 0x1DC,
    "SSR_KDF_HKDF_OUT8": 0x1E0,
    "SSR_KDF_HKDF_OUT9": 0x1E4,
    "SSR_KDF_HKDF_OUT10": 0x1E8,
    "SSR_KDF_HKDF_OUT11": 0x1EC,
    "SSR_KDF_HKDF_OUT12": 0x1F0,
    "SSR_KDF_HKDF_OUT13": 0x1F4,
    "SSR_KDF_HKDF_OUT14": 0x1F8,
    "SSR_KDF_HKDF_OUT15": 0x1FC,
}

pka_regs = {
    "SSR_PKA_CTRL":0,
    "SSR_PKA_CFG":0x010,
    "SSR_PKA_START":0x100,
    "SSR_PKA_DONE":0x200,
    "SSR_PKA_RESULT_ACK":0x204,
    "SSR_PKA_STATUS_MASK":0x208,
    "SSR_PKA_OP_TYPE":0x20C,
    "SSR_PKA_RSA_KEY_IDX":0x26C,
    "SSR_PKA_RSA_KEY_ZERO":0x270,
    "SSR_PKA_ECC_CURVE":0x2B8,
    "SSR_PKA_ECC_OP_FIFO"  :0x2CC,
    "SSR_PKA_ECC_DOM_FIFO" :0x2D0,
    "SSR_PKA_ECC_OP_B_FIFO":0x2D4,
    "SSR_PKA_ECC_OP_C_FIFO":0x2D8,
    "SSR_PKA_ECC_OP_D_FIFO":0x2DC,
    "SSR_PKA_ECC_OP_E_FIFO":0x2F8,
    "SSR_PKA_OP_A"         :0x400,
    "SSR_PKA_OP_B"         :0x800,
    "SSR_PKA_OP_C"         :0xC00
}

class SSR(metaclass=LogBase):
    def __init__(self, setup, loglevel=logging.INFO, gui: bool = False):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger, loglevel, gui)
        self.hwcode = setup.hwcode
        self.ssr_base = setup.ssr_base
        self.ssr_clk_base = setup.ssr_clk_base
        self.read32 = setup.read32
        self.write32 = setup.write32
        self.writemem = setup.writemem
        self.da_payload_addr = setup.da_payload_addr
        self.ssr = SSRCrypto(read32=self.read32, write32=self.write32, setup=setup, loglevel=loglevel, gui=gui)
        self.aes = SSR_AES(read32=self.read32, write32=self.write32, setup=setup, loglevel=loglevel, gui=gui)
        self.sha256 = SSR_SHA(read32=self.read32, write32=self.write32, setup=setup, loglevel=loglevel, gui=gui)

    def key_derive(
            self,
            kdf_slot_idx: int,
            key_len_bytes: int,
            label: bytes,
            context: bytes) -> Tuple[int, bytes]:
        """
        Generic key-derivation dispatcher used across observed firmware
        variants.

        Args:
            kdf_slot_idx: Derivation mode. `1` follows the source-ELF
                `crypto_hw_key_derive()` KBKDF-CMAC path, while `2` keeps the
                older CCC AES-CMAC expansion path seen in the ATF-style binary.
            key_len_bytes: Desired key length in bytes. The ROM requires a
                multiple of 16 bytes.
            label: Historical parameter name for the first input buffer. On the
                source-backed slot-1 path this behaves as the `label` argument.

        Returns:
            Tuple of (return_code, derived_key_bytes)
        """
        if label is None or context is None or (len(label) + len(context)) > 0x40:
            ret = CRYPTO_HW_KEY_DERIVE_INVALID_PARAM
            self.debug("key_derive fails(0x%x)", ret)
            return ret, b'\x00' * key_len_bytes
        if kdf_slot_idx == 1:
            ret, derived = self.ssr._kbkdf_cmac_counter_derive(key_len_bytes=key_len_bytes, label=label, context=context)
        elif kdf_slot_idx == 2:
            ret, derived = self.aes._ccc_cmac_expand_derive(key_len_bytes=key_len_bytes, label=label, context=context)
        else:
            ret, derived = CRYPTO_HW_KEY_DERIVE_INVALID_MODE, b'\x00' * key_len_bytes
        if ret != 0:
            self.debug("key_derive fails(0x%x)", ret)
        return ret, derived

    def generate_rpmb(self, level=0):
        label = bytearray(b"RPMB KEY")
        context = bytearray(b"SASI")
        slot = 1
        keylen = 16
        for i in range(len(label)):
            label[i] = label[i] + level
        for i in range(len(context)):
            context[i] = context[i] + level
        if level == RpmbType.AES_IMG_ENC.value:
            # AES_IMG_ENC
            label = bytearray(b"FIRMWARE")
            context = bytearray(b"ENCC")
            slot = 2
            keylen = 32
        elif level == RpmbType.MOTOROLA.value:
            # Motorola
            label = bytearray(b"CCUSTOMM")
            context = bytearray(b"MOTO")
            slot = 1
            keylen = 32
        elif level == RpmbType.ROT.value:
            # Base_Key
            label = bytearray(b"BASE_KEY")
            context = bytearray(b"9527")
            slot = 1
            keylen = 32
        elif level == RpmbType.CUSTOM1.value:
            label = bytearray(b"CBTFZ\xAB\x65\x60")
            context = bytearray(b"8638")
            slot = 1
            keylen = 32
        elif level == RpmbType.CUSTOM2.value:
            label = bytearray(b"A@RD^JDX")
            context = bytearray(b"8416")
            slot = 1
            keylen = 32

        ret, derived = self.key_derive(kdf_slot_idx=slot, key_len_bytes=keylen, label=label,
                                       context=context)

        return derived

    def aes128_cmac_ccc(self, data: bytes, key: Optional[bytes] = None) -> Tuple[int, bytes]:
        return self.aes.aes128_cmac_ccc(data, key)

    def generate_aes_cmac(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        ret, mac = self.aes.aes128_cmac_ccc(data, key)
        if ret != 0:
            self.error(f"SSR AES128 CMAC failed: 0x{ret:X}")
            return b""
        return mac



    def generate_sha256(self, data: bytes) -> bytes:
        self.sha256.ssr_ccc_clk(enable=True)
        ret = self.sha256.ssr_ccc_hw_init()
        if ret != 0:
            self.error(f"SSR CCC hw init failed: 0x{ret:X}")
            return b""
        digest = self.sha256.ssr_ccc_sha256(data)
        self.sha256.ssr_ccc_clk(enable=False)
        if isinstance(digest, int):
            self.error(f"SSR SHA256 failed: 0x{digest:X}")
            return b""
        return digest


class SSR_PKA_ERROR(Enum):
    TIMEOUT = 0x7241
    MODE_OUT_OF_RANGE = 0x7242
    ECC_INVALID_CURVE = 0x725A


class SSR_CCC_ERROR(Enum):
    TIMEOUT = 0x7275
    ERROR = 0x724E


CRYPTO_HW_KEY_DERIVE_INVALID_PARAM = -1
CRYPTO_HW_KEY_DERIVE_INVALID_INPUT = 0x10200F
CRYPTO_HW_KEY_DERIVE_INVALID_MODE = 0x10200E


_CCC_STATUS0_ERRORS = (
    (2, 0x72D0),
    (6, 0x72D1),
    (7, 0x72D2),
    (8, 0x72D3),
    (10, 0x72D4),
    (11, 0x72D5),
    (12, 0x72D6),
    (13, 0x72D7),
    (19, 0x72D7),
    (25, 0x72D9),
    (26, 0x72DA),
    (27, 0x72DB),
    (28, 0x72DC),
    (29, 0x72DD),
    (30, 0x72DE),
    (31, 0x72DF),
)

_CCC_STATUS1_ERRORS = (
    (8, 0x72E2),
    (28, 0x72E3),
    (29, 0x72E4),
    (30, 0x72E5),
    (31, 0x72E6),
    (6, 0x72E0),
    (7, 0x72E1),
)


class SSR_ERROR(Enum):
    INVALID_PARAM = 0x7245
    INVALID_KEY_LEN = 0x7246
    NULL_POINTER = 0x7247
    INVALID_MODE = 0x724C
    INVALID_RANGE = 0x7256
    TIMEOUT = 0x7262
    SELFTEST_FAIL = 0x7268


class SSR_KDF_ERROR(Enum):
    TIMEOUT = 0x7262
    SELFTEST_FAIL = 0x7268
    NULL_PTR = 0x7247
    BAD_SIZE = 0x7246
    BAD_CONFIG = 0x724C
    HW_UNKNOWN = 0x724B


class SSRCrypto(metaclass=LogBase):
    """
    SSR Hardware Crypto class for key derivation operations.
    
    This class implements the key derivation function (KDF) found in SSR
    hardware
    """

    # KDF hardware to software error mapping
    # Maps hardware status bit index to software error code
    KDF_HW2SW_ERROR = {
        0: 0,  # No error (shouldn't happen if status_lower != 0)
        1: 0x7249,  # Status bit 0 set
        2: 0x724A,  # Status bit 1 set
        3: 0x724B,  # Status bit 2 set
        4: 0x724C,  # Status bit 3 set
        5: 0x724D,  # Status bit 4 set
        6: 0x724E,  # Status bit 5 set
        7: 0x724F,  # Status bit 6 set
        8: 0x7250,  # Status bit 7/8 set
    }

    # Derive length lookup table for different modes
    maxlength = [AESKeyLen.AES_256.value, AESKeyLen.AES_128.value,
                 AESKeyLen.AES_192.value]  # Index by derive_mode (0, 1, 2)
    _SSR_KDF_CLK_SHIFT = 16
    _SSR_KDF_CLK_MAX_MODE = 5
    _SSR_KDF_CMAC_SHIFT = 8

    def __init__(self, read32: Optional[Callable[[int], int]] = None,
                 write32: Optional[Callable[[int, int], None]] = None,
                 setup=None,
                 loglevel=logging.INFO, gui: bool = False):
        """
        Initialize SSR hardware crypto
        
        Args:
            read32: Function to read 32-bit value from address
            write32: Function to write 32-bit value to address
        """
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger, loglevel, gui)
        self.ssr_clk_base = setup.ssr_clk_base
        self.ssr_base = setup.ssr_base
        self.writemem = setup.writemem
        self.da_payload_addr = setup.da_payload_addr
        if self.ssr_clk_base is not None:
            self.ssr_clk_cfg = self.ssr_clk_base
            self.ssr_clk_cfg_1 = self.ssr_clk_base + 0x4
            self.ssr_clk_cfg_2 = self.ssr_clk_base + 0x8
        if self.ssr_base is not None:
            self.ssr_lcs_base = self.ssr_base + 0x18
            self.ssr_rng_base = self.ssr_base + 0x1000
            self.ssr_kdf_base = self.ssr_base + 0x3000
            self.ssr_ccc_base = self.ssr_base + 0x5000
            self.ssr_pka_base = self.ssr_base + 0xA000
            self.ssr_dxcc_base = self.ssr_base + 0xC000
            self.ccc = RegisterMap(ccc_regs, setup.read32, setup.write32, self.ssr_ccc_base)
            self.kdf = RegisterMap(kdf_regs, setup.read32, setup.write32, self.ssr_kdf_base)
            self.clk = RegisterMap(clk_regs, setup.read32, setup.write32, self.ssr_clk_base)
            self.pka = RegisterMap(pka_regs, setup.read32, setup.write32, self.ssr_pka_base)
        self.read32 = read32
        self.write32 = write32

    def setbits(self, addr: int, mask: int) -> None:
        reg = self.read32(addr)
        self.write32(addr, reg | mask)

    def clrbits(self, addr: int, mask: int) -> None:
        reg = self.read32(addr)
        self.write32(addr, reg & (~mask & 0xFFFFFFFF))

    def set_bit_mask(self, addr: int, val: int, mask: int) -> int:
        if val > 1:
            return -1

        if val:
            self.setbits(addr, mask)
        else:
            self.clrbits(addr, mask)
        return 0

    def ssr_ccc_hw_init(self):
        self.ccc.HW_INIT_CFG0 = SSR_INIT_MAGIC1
        self.ccc.HW_INIT_CFG1 = SSR_INIT_MAGIC2
        self.ccc.HW_INIT_CFG1.value |= 0x80000000
        if self.ssr_polling_until(self.ccc.SSR_BOOT.addr, 0x80000000, 0x80000000, 5000):
            return 0x7261
        elif (self.ccc.SSR_BOOT.value & 0x1FFFFFFF) != 0 or self.ccc.HW_ERROR2.value & 0xFFFF != 0:
            return 0x7267
        else:
           self.ccc.CTRL.value |= 4
        return 0


    def ssr_cc_skip_keyslot_init(self):
        val = self.ccc.SKIP_KS_INIT.value | 1
        self.ccc.SKIP_KS_INIT = val

    def ssr_rng_clk(self, enable:bool):
        return self.set_bit_mask(self.ssr_clk_base, enable, SSR_CLK_RNG)

    def ssr_ccc_clk(self, enable:bool):
        return self.set_bit_mask(self.ssr_clk_base, enable, SSR_CLK_CCC)

    def ssr_kdf_clk(self, enable:bool):
        return self.set_bit_mask(self.ssr_clk_base, enable, SSR_CLK_KDF)

    def ssr_pka_clk(self, enable:bool):
        return self.set_bit_mask(self.ssr_clk_base, enable, SSR_CLK_PKA)

    def ssr_rng_set_clk_rate(self, rate:int):
        if rate > 3:
            return SSR_ERROR.INVALID_RANGE
        self.clk.CFG_17_CLR = 0x7F
        if rate != 0:
            self.clk.CLK_17_SET = rate
        self.clk.CFG_UPDATE_OFFSET = 0x40

    def ssr_ccc_set_clk_rate(self, rate:int):
        if rate > 5:
            return SSR_ERROR.INVALID_RANGE
        self.clk.CFG_16_CLR = 0x7F0000
        if rate != 0:
            self.clk.CLK_16_SET = (rate<<16)&0xFFFFFFFF
        self.clk.CFG_UPDATE_OFFSET = 0x10

    def ssr_kdf_set_clk_rate(self, rate: int):
        if rate > 5:
            return SSR_ERROR.INVALID_RANGE
        self.clk.CFG_16_CLR = 0x7F000000
        if rate != 0:
            self.clk.CLK_16_SET = (rate << 24) & 0xFFFFFFFF
        self.clk.CFG_UPDATE_OFFSET = 0x20

    def ssr_pka_set_clk_rate(self, rate:int):
        if rate > 5:
            return SSR_ERROR.INVALID_RANGE
        self.clk.CFG_16_CLR = 0x7F00
        if rate != 0:
            self.clk.CLK_16_SET = (rate << 8) & 0xFFFFFFFF
        self.clk.CFG_UPDATE_OFFSET = 0x08

    def ssr_lcs_get(self):
        self.ssr_ccc_clk(enable=True)
        self.ssr_kdf_clk(enable=True)
        val = self.ssr_get_lcs()
        self.ssr_ccc_clk(enable=False)
        self.ssr_kdf_clk(enable=False)
        return val

    def ssr_get_lcs(self):
        return (self.read32(self.ssr_lcs_base) >> 13) & 0xF

    def bytes_to_dword(self, data):
        if len(data) % 4:
            data += b'\x00' * (4 - (len(data) % 4))
        return [int.from_bytes(data[i * 4:i * 4 + 4], 'little') for i in range(len(data) // 4)]

    def data_to_paddr(self, paddr: int = 0, data: bytes = b""):
        values = self.bytes_to_dword(data)
        for i in range(len(values)):
            self.write32(paddr + i * 4, values[i])

    def write_scratch(self, paddr: int, data: bytes) -> None:
        if self.writemem is not None:
            self.writemem(paddr, data)
        else:
            self.data_to_paddr(paddr, data)

    def _clock_field_update(self, base: int, value: int, settings) -> int:
        _ = base
        if value > settings.max_value:
            return SSR_ERROR.INVALID_KEY_LEN.value
        val = self.read32(base + settings.clr)
        self.write32(base + settings.clr, val | (0x7F << settings.shift))
        if value != 0:
            val2 = self.read32(base + settings.set)
            self.write32(base + settings.set, val2 | (value << settings.shift))
        val3 = self.read32(base + settings.update)
        self.write32(base + settings.update,val3 | (1 << settings.offset))
        return 0

    def SSR_CCC_SetClkRate(self, base: int, value: int) -> int:
        settings = SimpleNamespace(clr=0x108,
                                   set=0x104,
                                   shift=0x10,
                                   max_value=5,
                                   update=0xC,
                                   offset=0)
        return self._clock_field_update(base, value, settings)

    def ssr_trng_enclk(self, base: int, value: int) -> int:
        settings = SimpleNamespace(clr=self.clk.CFG_CMAC_CLR.addr,
                                   set=self.clk.CFG_CMAC_SET.addr,
                                   shift=0x18,
                                   max_value=3,
                                   update=self.clk.CFG_UPDATE_OFFSET.addr,
                                   offset=9)
        return self._clock_field_update(base, value, settings)

    def ssr_polling_when(self, reg_addr: int, mask: int, value: int, timeout: int) -> int:
        """
        Poll register while condition is met or timeout
        
        Args:
            reg_addr: Register address to poll
            mask: Bit mask to check
            value: value after applying mask
            timeout: timeout in milliseconds
            
        Returns:
            0 on success, non-zero on timeout
        """
        start = time.time()
        timeout_sec = timeout / 1000.0

        while time.time() - start < timeout_sec:
            val = self.read32(reg_addr)
            if (val & mask) != value:
                return 0
            time.sleep(0.001)

        return 1  # Timeout

    def ssr_polling_until(self, reg_addr: int, mask: int, value: int, timeout: int) -> int:
        """
        Poll register until condition is met or timeout

        Args:
            reg_addr: Register address to poll
            mask: Bit mask to check
            value: value after applying mask
            timeout: timeout in milliseconds

        Returns:
            0 on success, non-zero on timeout
        """
        import time
        start = time.time()
        timeout_sec = timeout / 1000.0

        while time.time() - start < timeout_sec:
            val = self.read32(reg_addr)
            if (val & mask) == value:
                return 0
            time.sleep(0.001)

        return 1  # Timeout

    def kdf_write_window(self, dst: int, data, words, rtl: bool):
        staging = bytearray(17 * 4)
        if rtl:
            wc = words
            staging[(wc * 4) - len(data):(wc * 4)] = data
        else:
            wc = len(data) + 3 // 4
            staging[:len(data)] = data
        for i in range(wc):
            self.write32(dst + i * 4, self._bswap32(staging[wc - 1 - i]))

    def field_prep(self, mask: int, val: int) -> int:
        """
        - Shifts `val` to the position of the lowest set bit in `mask`
        - Masks the result so it only occupies the bits defined by `mask`
        - Works with any mask size (Python integers are arbitrary precision)
        - Identical behaviour to __builtin_ctzll for 64-bit masks
        """
        if mask == 0:
            return 0  # avoid division-by-zero / undefined behaviour

        # Compute ctz (count trailing zeros) using the classic mask & -mask trick
        # This is the Python equivalent of __builtin_ctzll(mask)
        lowest_set_bit = mask & -mask
        shift = lowest_set_bit.bit_length() - 1

        # Apply the same operations as the C macro
        return (val << shift) & mask

    def field_get(self, mask: int, reg: int) -> int:
        """
        Python equivalent of the Linux kernel macro:

        #define FIELD_GET(mask, reg) \
            (((reg) & (mask)) >> (__builtin_ctzll(mask)))

        Extracts the value of a bitfield from a register.

        - Isolates the bits defined by `mask`
        - Shifts them right so the field value starts at bit 0
        - Identical behaviour to __builtin_ctzll for any mask size

        Works with FIELD_PREP from the previous conversion:
            reg = FIELD_PREP(GENMASK(15, 8), 0xAB)
            value = FIELD_GET(GENMASK(15, 8), reg)   # → 0xAB
        """
        if mask == 0:
            return 0  # avoid undefined behaviour

        # Same ctz trick used in FIELD_PREP (Python equivalent of __builtin_ctzll)
        lowest_set_bit = mask & -mask
        shift = lowest_set_bit.bit_length() - 1

        # Literal translation of the C macro
        return (reg & mask) >> shift

    def ssr_kdf_hkdf_sha256(self, ikm, info, salt=None, derive_len: int = 0x20):
        if salt is not None:
            self.kdf_write_window(self.kdf.SSR_KDF_HKDF_SALT7.addr, salt, 0, False)
        self.kdf_write_window(self.kdf.SSR_KDF_HKDF_IKM15, ikm, 0, False)
        self.kdf_write_window(self.kdf.SSR_KDF_HKDF_INFO11, info, 0, False)
        cmd = (SSR_KDF_HKDF_CMD_START |
               SSR_KDF_HKDF_CMD_FIXED |
               SSR_KDF_HKDF_CMD_NO_SALT if salt is None else 0 |
                                                             self.field_prep(SSR_KDF_HKDF_CMD_IKM_LEN, len(ikm)) |
                                                             self.field_prep(SSR_KDF_HKDF_CMD_SALT_LEN,
                                                                             0 if salt is None else len(salt)) |
                                                             self.field_prep(SSR_KDF_HKDF_CMD_INFO_LEN, len(info)))

        self.kdf.SSR_KDF_HKDF_CMD = cmd
        if self.ssr_polling_when(self.kdf.SSR_KDF_HKDF_CMD.addr, 0, 0, 5000):
            return SSR_KDF_ERROR.TIMEOUT
        status = self.kdf.SSR_KDF_HKDF_STS
        if self.field_get(SSR_KDF_HKDF_STS_ERR, status):
            return SSR_KDF_ERROR.HW_UNKNOWN
        out = []
        for n in range(derive_len // 4):
            out = self._bswap32(self.kdf.SSR_KDF_HKDF_OUT0.addr + 4)
        return b"".join(out)

    def ssr_kdf_kbkdf_cmac_counter(
            self,
            hw_ctx_base: int,
            key_type: int,
            label: Optional[bytes],
            derive_mode: int,
            key_material: bytes,
            key_material_len: int,
            derived_key_len: int
    ) -> Tuple[int, bytes]:
        """
        Perform KBKDF CMAC Counter mode key derivation
        
        This implements the hardware KDF operation using CMAC counter mode,
        matching the C implementation's register operations and byte ordering.
        
        Args:
            hw_ctx_base: Hardware context base address
            key_type: Key type (0-15)
            label: Label bytes (required if key_type is 0)
            derive_mode: Derivation mode (0-2)
            key_material: Input key material
            key_material_len: Length of key material
            derived_key_len: Desired derived key length in bytes
            
        Returns:
            Tuple of (error_code, derived_key_bytes)
        """
        if derive_mode > 2:
            return SSR_ERROR.INVALID_MODE.value, b''

        if derived_key_len == 0 or derived_key_len > 0x40:
            return SSR_ERROR.INVALID_KEY_LEN.value, b''

        context_len = self.maxlength[derive_mode]
        length_mode = derive_mode

        # Calculate block count (derived_key_len / 16, rounded up)
        if (derived_key_len & 0xF) != 0:
            block_count = (derived_key_len >> 4) + 1
        else:
            block_count = derived_key_len >> 4

        # Validate key material
        if not key_material:
            return SSR_ERROR.NULL_POINTER.value, b''

        if key_material_len >= 0x44:
            return SSR_ERROR.INVALID_KEY_LEN.value, b''

        enabled_kdf_clk = False
        if self.ssr_clk_base is not None and (self.read32(self.ssr_clk_base) & SSR_CLK_KDF) == 0:
            self.ssr_kdf_clk(enable=True)
            enabled_kdf_clk = True

        try:
            # Initialize IO buffer (68 bytes)
            io_buffer = bytearray(0x44)

            # Copy key material to end of io_buffer (right-aligned at offset 68 - key_material_len)
            end_offset = 0x44 - key_material_len
            io_buffer[end_offset:0x44] = key_material[:key_material_len]

            # IDA shows the KDF engine consuming a 68-byte buffer as 17 descending
            # dwords: FIN0 gets bytes[64:68], ... FIN16 gets (bytes[0:4] | len).
            fin_words = list(struct.unpack('<17I', io_buffer))
            fin_words[0] |= key_material_len
            for reg_idx, word in enumerate(reversed(fin_words)):
                self.write32(self.kdf.SSR_KDF_CMAC_FIN0.addr + reg_idx * 4, self._bswap32(word))

            # Handle label if key_type is 0
            if key_type == KDFType.SW_KEY.value:
                if label is None:
                    return SSR_ERROR.NULL_POINTER.value, b''

                # Initialize label buffer (32 bytes)
                label_buffer = bytearray(32)

                # Copy label to end of label_buffer (right-aligned by context_len)
                # memcpy((char *)&io_buffer[4] - context_len, label, context_len)
                label_copy_len = min(len(label), context_len)
                label_start = 32 - context_len
                label_buffer[label_start:label_start + label_copy_len] = label[:label_copy_len]

                # IDA writes the label/context words as descending dwords as well:
                # LBL0 gets bytes[28:32], ... LBL7 gets bytes[0:4].
                label_words = struct.unpack('<8I', label_buffer)
                for reg_idx, word in enumerate(reversed(label_words)):
                    self.write32(self.kdf.SSR_KDF_CMAC_LBL0.addr + reg_idx * 4, self._bswap32(word))

            control_val = ((length_mode & 3) << 6) | ((key_type & 0xF) << 8) | (block_count << 16) | 1
            self.kdf.SSR_KDF_CMAC_CMD = control_val

            # Poll for completion (wait for bit 0 to be set)
            if self.ssr_polling_when(self.kdf.SSR_KDF_CMAC_CMD.addr, 1, 1, 0x1388):
                self.error("Timeout when trying to run ssr crypto engine")
                return 0x7262, b''

            # Read and check status register
            status_reg = self.kdf.SSR_KDF_CMAC_STS.value
            status_lower = status_reg & 0x7FF

            if status_lower != 0:
                # Determine error code from status bits
                if status_reg & 1:
                    errorcode = 0
                elif status_reg & 2:
                    errorcode = 1
                elif status_reg & 4:
                    errorcode = 2
                elif status_reg & 8:
                    errorcode = 3
                elif status_reg & 0x10:
                    errorcode = 4
                elif status_reg & 0x20:
                    errorcode = 5
                elif status_reg & 0x40:
                    errorcode = 6
                elif status_reg & 0x80:
                    errorcode = 7
                elif status_reg & 0x100:
                    errorcode = 8
                else:
                    return 0x724B, b''

                return self.KDF_HW2SW_ERROR.get(errorcode, 0x724B), b''

            derived_key = bytearray(64)
            dst_idx = 0

            for base in [self.kdf.SSR_KDF_CMAC_OUT3.addr, self.kdf.SSR_KDF_CMAC_OUT7.addr,
                         self.kdf.SSR_KDF_CMAC_OUT11.addr, self.kdf.SSR_KDF_CMAC_OUT15.addr]:
                regs = []
                for offset in range(-3, 1):
                    regs.append(self.read32(base + (offset * 4)))

                for i in range(3, -1, -1):
                    val = regs[i]
                    # 32-bit byte swap: B0 B1 B2 B3 -> B3 B2 B1 B0
                    swapped = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | \
                              ((val & 0xFF0000) >> 8) | ((val >> 24) & 0xFF)

                    if dst_idx + 4 <= len(derived_key):
                        derived_key[dst_idx:dst_idx + 4] = swapped.to_bytes(4, 'little')
                        dst_idx += 4

            return 0, bytes(derived_key[:derived_key_len])
        finally:
            if enabled_kdf_clk:
                self.ssr_kdf_clk(enable=False)

    def _bswap32(self, value: int) -> int:
        """
        Byte swap 32-bit integer (little-endian <-> big-endian)
        B0 B1 B2 B3 -> B3 B2 B1 B0
        """
        value = value & 0xFFFFFFFF
        return ((value & 0xFF) << 24) | ((value & 0xFF00) << 8) | \
            ((value & 0xFF0000) >> 8) | ((value >> 24) & 0xFF)

    def _kbkdf_cmac_counter_derive(self, key_len_bytes: int, label: bytes, context: bytes) -> Tuple[int, bytes]:
        total_len = len(label) + len(context)
        if (key_len_bytes & 0xF) != 0 or total_len > 61:
            return CRYPTO_HW_KEY_DERIVE_INVALID_INPUT, b'\x00' * key_len_bytes
        if key_len_bytes == 0:
            return 1, b""

        kdf_input_buf = bytearray(64)
        buf_pos = 0
        if label:
            kdf_input_buf[:len(label)] = label
            buf_pos = len(label)
        kdf_input_buf[buf_pos] = 0
        buf_pos += 1
        if context:
            kdf_input_buf[buf_pos:buf_pos + len(context)] = context
            buf_pos += len(context)
        kdf_input_buf[buf_pos] = (8 * key_len_bytes) & 0xFF
        kdf_input_len = buf_pos + 1

        # ATF crypto_derive() gates the KDF block with tz_clk_en(base, 1),
        # which directly toggles bit 16 on the base clock register.
        clk_ret = self.ssr_kdf_clk(enable=True)
        if clk_ret != 0:
            return clk_ret, b'\x00' * key_len_bytes
        try:
            ret, derived_key = self.ssr_kdf_kbkdf_cmac_counter(
                hw_ctx_base=self.ssr_kdf_base,
                key_type=4,
                label=label,
                derive_mode=0,
                key_material=bytes(kdf_input_buf[:kdf_input_len]),
                key_material_len=kdf_input_len,
                derived_key_len=key_len_bytes
            )
        finally:
            self.ssr_kdf_clk(enable=False)

        if ret != 0:
            return ret, b'\x00' * key_len_bytes
        return 0, derived_key


class SSR_PKA(SSRCrypto):
    def __init__(self, setup, loglevel=logging.INFO, gui=False):
        super(SSR_PKA, self).__init__(setup, loglevel=loglevel, gui=gui)
        self.data_len = 0
        self.buf = bytearray(64)
        self.paddr = 0x69000000

    def pka_write(self, base:int, data:list, nwords:int):
        for i in range(nwords-1,0,-1):
            self.write32(base+(i*4),self._bswap32(data[i]))

    def pka_read(self, base, nwords:int):
        dst = []
        for i in range(nwords-1,0,-1):
            dst.append(self._bswap32(self.read32(base+(i*4))))
        return dst

    def pka_rsa_modexp(self, mode:int, base:int, exponent:int, modulus:int, timeout:int):
        if mode >= 4:
            return SSR_PKA_ERROR.MODE_OUT_OF_RANGE
        key_words = (mode+1)*32
        self.pka.SSR_PKA_OP_TYPE = PKA_OP.RSA_MODEXP.value
        self.pka.SSR_PKA_RSA_KEY_IDX = mode
        self.pka.SSR_PKA_RSA_KEY_ZERO = 0
        self.pka_write(self.pka.SSR_PKA_OP_A.addr, self.bytes_to_dword(long_to_bytes(exponent)), key_words)
        self.pka_write(self.pka.SSR_PKA_OP_B.addr, self.bytes_to_dword(long_to_bytes(modulus)), key_words)
        self.pka_write(self.pka.SSR_PKA_OP_C.addr, self.bytes_to_dword(long_to_bytes(base)), key_words)
        self.pka.SSR_PKA_START = 0
        if self.ssr_polling_until(self.pka.SSR_PKA_DONE.addr, 1, 1, timeout):
            return SSR_PKA_ERROR.TIMEOUT
        self.pka.SSR_PKA_RESULT_ACK = 1
        result = b"".join(self.pka_read(self.pka.SSR_PKA_OP_C.addr, key_words))
        ctrl = self.pka.SSR_PKA_CTRL.value
        self.pka.SSR_PKA_CTRL = ctrl & ((~2)&0xFFFFFFFF)
        self.pka.SSR_PKA_CTRL = ctrl & ((~2)&0xFFFFFFFF) | 2
        return result

    def pka_ecc_push_operant(self, fifo:int, src:list, nwords:int):
        for i in range(nwords-1,0,-1):
            self.write32(fifo, self._bswap32(src[i]))
        for i in range(13):
            self.write32(fifo,0)

    def pka_ecc_push_domain(self, table:list, word_count:int):
        for i in range(word_count-1,0,-1):
            self.write32(self.pka.SSR_PKA_ECC_DOM_FIFO, self._bswap32(table[i]))
        for i in range(19):
            self.write32(self.pka.SSR_PKA_ECC_DOM_FIFO, 0)

    def pka_ecc_pop_operand(self, fifo:int, nwords:int):
        dst = []
        for i in range(nwords-1,0,-1):
            dst.append(self._bswap32(self.read32(fifo)))
        return dst

    def pka_ecc_op(self, curve:int, op_code:int, operands:list):
        if curve == PKA_ECC.ECC_CURVE_NIST_P256:
            dom = ecc_domain_p256
            wc = SSR_PKA_ECC_P256_WORDS
        elif curve == PKA_ECC.ECC_CURVE_NIST_P384:
            dom = ecc_domain_p384
            wc = SSR_PKA_ECC_P384_WORDS
        else:
            raise NotImplementedError
        self.pka.SSR_PKA_OP_TYPE = op_code
        self.pka.SSR_PKA_ECC_CURVE = curve
        for operand in operands:
            self.pka_ecc_push_operant(self.pka.SSR_PKA_ECC_DOM_FIFO.addr,operand, wc)
        self.pka_ecc_push_domain(dom, wc)
        self.pka.SSR_PKA_START = 0
        if self.ssr_polling_until(self.pka.SSR_PKA_DONE.addr, 1, 1, SSR_TIMEOUT):
            return SSR_PKA_ERROR.TIMEOUT
        self.pka.SSR_PKA_RESULT_ACK = 1
        out_x = self.pka_ecc_pop_operand(self.pka.SSR_PKA_ECC_OP_FIFO.addr, wc)
        out_y = self.pka_ecc_pop_operand(self.pka.SSR_PKA_ECC_DOM_FIFO.addr, wc)
        ctrl = self.pka.SSR_PKA_CTRL.value
        self.SSR_PKA_CTRL = ctrl & ((~2)&0xFFFFFFFF)
        self.SSR_PKA_CTRL = ctrl & ((~2)&0xFFFFFFFF) | 2
        return out_x, out_y

class SSR_AES(SSRCrypto):
    def __init__(self, read32, write32, setup, loglevel=logging.INFO, gui=False):
        super(SSR_AES, self).__init__(read32=read32, write32=write32, setup=setup, loglevel=loglevel, gui=gui)
        self.data_len = 0
        self.buf = bytearray(64)
        self.paddr = 0x69000000
        self.setup = setup

    def _ccc_cmac_expand_derive(self, key_len_bytes: int, label: bytes, context: bytes) -> Tuple[int, bytes]:
        total_len = len(label) + len(context)
        if (key_len_bytes & 0xF) != 0 or total_len > 60:
            return CRYPTO_HW_KEY_DERIVE_INVALID_INPUT, b'\x00' * key_len_bytes

        kdf_input_buf = bytearray(64)
        kdf_input_buf[0] = 1
        buf_pos = 1
        if label:
            kdf_input_buf[buf_pos:buf_pos + len(label)] = label
            buf_pos += len(label)
        kdf_input_buf[buf_pos] = 0
        buf_pos += 1
        if context:
            kdf_input_buf[buf_pos:buf_pos + len(context)] = context
            buf_pos += len(context)
        kdf_input_buf[buf_pos] = (8 * key_len_bytes) & 0xFF
        kdf_input_len = buf_pos + 1

        zero_key = bytes(AESKeyLen.AES_128.value)
        cmac_key: Optional[bytes]
        ret, _ = self.aes128_cmac_ccc(bytes(kdf_input_buf[:kdf_input_len]))
        if ret != 0:
            self.debug("aes128 cmac ret :%x", ret)
            cmac_key = zero_key
            derived = bytearray()
            counter = 1
            remaining = key_len_bytes
            while remaining:
                kdf_input_buf[0] = counter & 0xFF
                ret, block = self.aes128_cmac_ccc(bytes(kdf_input_buf[:kdf_input_len]), cmac_key)
                if ret != 0:
                    return ret, b'\x00' * key_len_bytes
                derived.extend(block)
                counter = (counter + 1) & 0xFF
                remaining -= 16
            return 0, bytes(derived[:key_len_bytes])
        return ret, b""

    def _ccc_next_seq(self) -> int:
        seq = (self.ccc.JOB_ID.value + 1) & 0xFFFF
        return 1 if seq == 0 else seq

    def _ccc_wait_queue(self, minimum: int = 0x17, timeout: int = SSR_TIMEOUT) -> int:
        start = time.time()
        timeout_sec = timeout / 1000.0
        while time.time() - start < timeout_sec:
            if (self.ccc.QUEUE_AVAILABLE.value & 0xFF) >= minimum:
                return 0
            time.sleep(0.001)
        return SSR_CCC_ERROR.TIMEOUT.value

    def _ccc_queue_submit(self, words) -> int:
        avail = self.ccc.QUEUE_AVAILABLE.value & 0xFF
        if avail < len(words):
            return SSR_CCC_ERROR.TIMEOUT.value
        for word in words:
            self.ccc.QUEUE = word & 0xFFFFFFFF
        self.ccc.QUEUE_AVAILABLE = (avail - len(words)) & 0xFF
        return 0

    def _ccc_post_wait_cleanup(self) -> None:
        self.setbits(self.ccc.CTRL.addr, 0x80000)
        self.clrbits(self.ccc.CTRL.addr, 0x80000)
        self.ssr_polling_until(self.ccc.STATUS0.addr, 0xFFFFFFFF, 0, 2500)
        self.ssr_polling_until(self.ccc.STATUS1.addr, 0xF0000000, 0, 2500)

    def _ccc_map_status_error(self, status: int, table) -> int:
        for bit_index, error_code in table:
            if status & (1 << bit_index):
                return error_code
        return 0

    def _ccc_wait_job(self, seq: int) -> int:
        job_ready = self.ssr_polling_until(self.ccc.JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT) == 0
        job_status = self.ccc.JOB_ID.value
        status0 = self.ccc.STATUS0.value
        status1 = self.ccc.STATUS1.value
        self._ccc_post_wait_cleanup()

        mapped_error = self._ccc_map_status_error(status0, _CCC_STATUS0_ERRORS)
        if mapped_error == 0:
            mapped_error = self._ccc_map_status_error(status1, _CCC_STATUS1_ERRORS)
        if mapped_error != 0:
            return mapped_error
        if job_status & 0x40000000:
            return 0x72E7
        if not job_ready:
            return SSR_CCC_ERROR.TIMEOUT.value
        if job_status & 0x80000000:
            return 0
        return SSR_CCC_ERROR.ERROR.value

    def ccc_wait_func(self, base: Optional[int] = None) -> int:
        base = self.ssr_ccc_base if base is None else base
        if self.ssr_polling_until(base + ccc_regs["SSR_BOOT"], 0x80000000, 0x80000000, SSR_TIMEOUT):
            return 0x7261
        if (self.read32(base + ccc_regs["SSR_BOOT"]) & 0x1FFFFFFF) != 0:
            return 0x7267
        if (self.read32(base + ccc_regs["HW_ERROR2"]) & 0xFFF) != 0:
            return 0x7267
        self.setbits(base + ccc_regs["CTRL"], 0x4)
        return 0

    def mask_and_wait(self, base: Optional[int] = None) -> int:
        base = self.ssr_ccc_base if base is None else base
        self.setbits(base + ccc_regs["CTRL"], 0x1)
        self.clrbits(base + ccc_regs["CTRL"], 0x1)
        return self.ccc_wait_func(base)

    def _ccc_read_cmac_output(self) -> bytes:
        output = bytearray()
        for reg in (self.ccc.CMAC_OUT3.addr, self.ccc.CMAC_OUT2.addr, self.ccc.CMAC_OUT1.addr, self.ccc.CMAC_OUT0.addr):
            output.extend(self._bswap32(self.read32(reg)).to_bytes(4, "little"))
        return bytes(output)

    def poll_until_3a0(self) -> int:
        self.write32(self.ssr_ccc_base + 0x4, 0x101)
        if self.ssr_polling_until(self.ssr_ccc_base + 0xE8, 0x80000, 1, 5):
            return 0x7261
        return 0

    def _ccc_append_sw_key(self, words, key: Optional[bytes]) -> None:
        if key is None:
            return
        for word in struct.unpack("<4I", key):
            words.append(self._bswap32(word))

    def _ccc_aes_cmac_hw(self, data_addr: int, data_len: int, key: Optional[bytes], out_addr: int) -> int:
        wait_ret = self._ccc_wait_queue()
        if wait_ret != 0:
            return wait_ret

        seq = self._ccc_next_seq()
        setup_words = [
            0x100A8040 | (0x80 if key is not None else 0),
            0x01000000 | seq,
            0,
            0,
            0x10,
            0,
            0x0F,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
        self._ccc_append_sw_key(setup_words, key)
        submit_ret = self._ccc_queue_submit(setup_words)
        if submit_ret != 0:
            return submit_ret
        wait_ret = self._ccc_wait_job(seq)
        if wait_ret != 0:
            return wait_ret

        wait_ret = self._ccc_wait_queue()
        if wait_ret != 0:
            return wait_ret

        seq = self._ccc_next_seq()
        descriptor_c = 0x03000000 | seq
        descriptor_a = 0
        if ((data_addr | data_len) >> 32) != 0:
            descriptor_c = 0x03400000 | seq
            descriptor_a |= 0x20

        data_words = [
            0x100B0040 | (0x80 if key is not None else 0),
            descriptor_c,
            0,
            data_addr,
            data_len,
            out_addr,
            (out_addr + 0x10 - 1) & 0xFFFFFFFF,
            0,
            0,
            0,
            0,
        ]
        if descriptor_a != 0:
            data_words.insert(3, descriptor_a)
        self._ccc_append_sw_key(data_words, key)
        submit_ret = self._ccc_queue_submit(data_words)
        if submit_ret != 0:
            return submit_ret
        return self._ccc_wait_job(seq)

    def aes128_cmac_ccc(self, data: bytes, key: Optional[bytes] = None) -> Tuple[int, bytes]:
        self.ssr_ccc_hw_init()
        self.ssr_ccc_clk(enable=True)
        """
        Run the reduced AES-128 CMAC path used by the SSR ROM wrapper.

        Args:
            data: Input buffer to authenticate.
            key: Optional 16-byte software key. When omitted, the hardware
                keyslot path is used.

        Returns:
            Tuple of `(status, cmac_bytes)`.
        """
        if data is None:
            return 2, b""
        if len(data) == 0:
            return 1, b""
        if self.ssr_ccc_base is None or self.ssr_clk_base is None:
            return SSR_ERROR.INVALID_PARAM.value, b""
        if self.da_payload_addr is None:
            return SSR_ERROR.NULL_POINTER.value, b""
        if key is not None and len(key) != AESKeyLen.AES_128.value:
            return SSR_ERROR.INVALID_KEY_LEN.value, b""

        data_addr = self.da_payload_addr - 0x200
        data_len_aligned = (len(data) + 0xF) & ~0xF
        out_addr = data_addr + data_len_aligned + 0x10
        self.write_scratch(data_addr, data)
        self.write_scratch(out_addr, b"\x00" * 0x10)

        """
        value = 4
        base = 0x10000000
        val = self.read32(base+0x188)
        self.write32(base+0x188, val | 0x7F00)
        val2 = self.read32(base+0x184)
        self.write32(base+0x184, val2 | value << 8)
        val3 = self.read32(base + 0xC)
        self.write32(base + 0x184, val3 | 0x80)

        base = 0x10405000
        while True:
            t = self.read32(base + 0x100)
            if t&0xF8 != 0:
                break
        """
        ##
        clk_ret = self.SSR_CCC_SetClkRate(self.setup.cc_clk_base, 3)
        if clk_ret != 0:
            return clk_ret, b""

        try:
            ret = self._ccc_aes_cmac_hw(data_addr, len(data), key, out_addr)
            if ret == 0x72D1:
                self.mask_and_wait(self.ssr_ccc_base)
                self.ccc_wait_func(self.ssr_ccc_base)
            if ret != 0:
                return ret, b""
            return 0, self._ccc_read_cmac_output()
        finally:
            self.ssr_ccc_clk(enable=False)
            self.SSR_CCC_SetClkRate(self.setup.cc_clk_base, 0)

class SSR_SHA(SSRCrypto):
    def __init__(self, read32, write32, setup, loglevel=logging.INFO, gui=False):
        super(SSR_SHA, self).__init__(read32=read32, write32=write32, setup=setup, loglevel=loglevel, gui=gui)
        self.data_len = 0
        self.buf = bytearray(64)
        self.paddr = 0x69000000
        self.read32 = read32
        self.write32 = write32

    def ssr_ccc_sha256_compress(self, length: int):
        first = self.ccc.BASE.value == 0
        bit_len = length * 8
        high_paddr = (self.paddr >> 32) != 0
        high_bitlen = (bit_len >> 32) != 0
        while self.ccc.QUEUE_AVAILABLE.value & 0xFF < 6:
            pass
        cmd0 = 0x30000000 if first else 0x31000000 | high_bitlen << 7 | high_paddr << 8
        seq = (self.ccc.SHA_JOB_ID.value + 1) & 0xFFFF
        if seq == 0:
            seq = 1
        self.ccc.QUEUE = cmd0
        self.ccc.QUEUE = seq | 0 if first else 0x20000000
        self.ccc.QUEUE = (self.paddr >> 16) & 0xF0000 if high_paddr else 0
        self.ccc.QUEUE = bit_len
        self.ccc.QUEUE = self.paddr & 0xFFFFFF
        nwords = 5
        if high_bitlen:
            self.ccc.QUEUE = (bit_len >> 32)
            nwords = 6
        self.ccc.QUEUE_AVAILABLE = nwords
        if self.ssr_polling_when(self.ccc.SHA_JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT):
            return SSR_CCC_ERROR.TIMEOUT.value
        if self.ccc.SHA_JOB_ID.value < 0:
            return SSR_CCC_ERROR.ERROR.value
        return 0

    def ssr_ccc_sha384_compress(self, length: int):
        first = self.ccc.BASE.value == 0
        bit_len = length * 8
        high_paddr = (self.paddr >> 32) != 0
        high_bitlen = (bit_len >> 32) != 0
        while self.ccc.QUEUE_AVAILABLE.value & 0xFF < 6:
            pass
        cmd0 = (0x30000000 if first else 0x31000000 |
                                         0x2000880 if high_bitlen else 0x2000800 |
                                                                       (high_paddr & 0xFFFFFFFF) << 8)
        seq = (self.ccc.SHA_JOB_ID.value + 1) & 0xFFFF
        if seq == 0:
            seq = 1
        self.ccc.QUEUE = cmd0
        self.ccc.QUEUE = seq | 0 if first else 0x20000000
        self.ccc.QUEUE = (self.paddr >> 16) & 0xF0000 if high_paddr else 0
        self.ccc.QUEUE = bit_len
        self.ccc.QUEUE = self.paddr & 0xFFFFFF
        nwords = 5
        if high_bitlen:
            self.ccc.QUEUE = (bit_len >> 32)
            nwords = 6
        self.ccc.QUEUE_AVAILABLE = nwords
        if self.ssr_polling_when(self.ccc.SHA_JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT):
            return SSR_CCC_ERROR.TIMEOUT.value
        if self.ccc.SHA_JOB_ID.value < 0:
            return SSR_CCC_ERROR.ERROR.value
        return 0

    def ssr_ccc_sha_read_output(self, count):
        dst = bytearray()
        for i in range(count):
            word = self.read32(self.ccc.SHA_OUT.addr + ((count - 1 - i) * 4))
            dst.extend(struct.pack(">I", word & 0xFFFFFFFF))
        return bytes(dst)

    def ssr_ccc_sha256_init(self):
        self.buf = bytearray(64)

    def ssr_ccc_sha256_update(self, data: bytes):
        inlen = len(data)
        pos = inlen & 0x3F
        if pos != 0:
            fill = 64 - pos
            if inlen < fill:
                self.buf[pos:pos + inlen] = data[:inlen]
                return 0
            self.buf[pos:pos + fill] = data[:fill]
            status = self.ssr_ccc_sha256_compress(64)
            if status > 0:
                return status
            data = data[fill:]
            inlen -= fill
        if inlen >= 64:
            full = inlen & ((~0x3F) & 0xFFFFFFFF)
            status = self.ssr_ccc_sha256_compress(64)
            if status > 0:
                return status
            data = data[full:]
            inlen -= full
        if inlen:
            self.buf[:inlen] = data[:inlen]
        return 0

    def ssr_ccc_sha256_done(self):
        pos = self.data_len & 0x3F
        pad_len = 64 if pos < 56 else 128
        len_off = pad_len - 8
        total = self.data_len
        pad = bytearray(128)
        pad[:len(self.buf)] = self.buf
        pad[pos] = 0x80
        bits = total * 8
        for i in range(7, 0, -1):
            pad[len_off + i] = bits & 0xFF
            bits >>= 8
        self.data_to_paddr(self.paddr, pad)
        status = self.ssr_ccc_sha256_compress(pad_len)
        if status > 0:
            return status
        dst = self.ssr_ccc_sha_read_output(8)
        return dst

    def ssr_ccc_sha256(self, data: bytes):
        inlen = len(data)
        bit_len = inlen * 8
        high_paddr = (self.paddr >> 32) != 0
        high_bitlen = (bit_len >> 32) != 0
        shatype = CCC_SHAType.SHA256.value

        self.write_scratch(self.paddr, data)
        while self.ccc.QUEUE_AVAILABLE.value & 0xF8 == 0:
            pass
        queue_space = self.ccc.QUEUE_AVAILABLE.value & 0xFF

        cmd0 = (0x30000000 |
                ((shatype & 3) << 25) & 0xFFFFFFFF |
                ((shatype >> 2 & 1) << 11) |
                high_bitlen << 7 |
                high_paddr << 8)

        seq = (self.ccc.SHA_JOB_ID.value + 1) & 0xFFFF
        if seq == 0:
            seq = 1
        self.ccc.QUEUE = cmd0
        self.ccc.QUEUE = seq | 0x80000000
        self.ccc.QUEUE = (self.paddr >> 16) & 0xF0000 if high_paddr else 0
        self.ccc.QUEUE = bit_len
        self.ccc.QUEUE = self.paddr & 0xFFFFFFFF
        consumed = 5
        if high_bitlen:
            self.ccc.QUEUE = (bit_len >> 32)
            consumed = 6
        self.ccc.QUEUE_AVAILABLE = (queue_space - consumed) & 0xFF
        if self.ssr_polling_until(self.ccc.SHA_JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT):
            return SSR_CCC_ERROR.TIMEOUT.value
        if self.ccc.SHA_JOB_ID.value < 0:
            return SSR_CCC_ERROR.ERROR.value
        retval = self.ssr_ccc_sha_read_output(8)
        return retval

    def ssr_ccc_sha384_init(self):
        self.buf = bytearray(128)

    def ssr_ccc_sha384_update(self, data: bytes):
        inlen = len(data)
        pos = inlen & 0x7F
        if pos != 0:
            fill = 128 - pos
            if inlen < fill:
                self.buf[pos:pos + inlen] = data[:inlen]
                return 0
            self.buf[pos:pos + fill] = data[:fill]
            status = self.ssr_ccc_sha384_compress(128)
            if status > 0:
                return status
            data = data[fill:]
            inlen -= fill
        if inlen >= 64:
            full = inlen & ((~0x7F) & 0xFFFFFFFF)
            status = self.ssr_ccc_sha384_compress(128)
            if status > 0:
                return status
            data = data[full:]
            inlen -= full
        if inlen:
            self.buf[:inlen] = data[:inlen]
        return 0

    def ssr_ccc_sha384_done(self):
        pos = self.data_len & 0x7F
        pad_len = 128 if pos < 112 else 256
        len_off = pad_len - 8
        total = self.data_len
        pad = bytearray(256)
        pad[:len(self.buf)] = self.buf
        pad[pos] = 0x80
        bits = total * 8
        for i in range(7, 0, -1):
            pad[len_off + i] = bits & 0xFF
            bits >>= 8
        self.data_to_paddr(self.paddr, pad)
        status = self.ssr_ccc_sha384_compress(pad_len)
        if status > 0:
            return status
        dst = self.ssr_ccc_sha_read_output(8)
        return dst

    def ssr_ccc_sha384(self, data: bytes):
        inlen = len(data)
        bit_len = inlen * 8
        high_paddr = (self.paddr >> 32) != 0
        high_bitlen = (bit_len >> 32) != 0
        shatype = CCC_SHAType.SHA384.value

        while (self.ccc.QUEUE_AVAILABLE.value & 0xF8) == 0:
            pass

        cmd0 = (0x30000000 |
                ((shatype & 3) << 25) & 0xFFFFFFFF |
                ((shatype >> 2 & 1) << 11) |
                high_bitlen << 7 |
                high_paddr << 8)

        seq = (self.ccc.SHA_JOB_ID.value + 1) & 0xFFFF
        if seq == 0:
            seq = 1
        self.ccc.QUEUE = cmd0
        self.ccc.QUEUE = seq | 0x80000000
        self.ccc.QUEUE = (self.paddr >> 16) & 0xF0000 if high_paddr else 0
        self.ccc.QUEUE = bit_len
        self.ccc.QUEUE = self.paddr & 0xFFFFFF
        nwords = 5
        if high_bitlen:
            self.ccc.QUEUE = (bit_len >> 32)
            nwords = 6
        self.ccc.QUEUE_AVAILABLE = nwords
        if self.ssr_polling_until(self.ccc.SHA_JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT):
            return SSR_CCC_ERROR.TIMEOUT.value
        if self.ccc.SHA_JOB_ID.value < 0:
            return SSR_CCC_ERROR.ERROR.value
        retval = self.ssr_ccc_sha_read_output(8)
        return retval


# Example/test code
if __name__ == "__main__":
    # Example usage without hardware (for testing structure)
    """
    # Mock read/write functions for testing
    registers = {}
    KDF_CTX_BASE = 0x14003000


    def mock_read32(addr):
        return registers.get(addr, 0)


    def mock_write32(addr, value):
        registers[addr] = value
        # Simulate status register being set after control write
        if addr == KDF_CTX_BASE + 0x84:
            # Set status to indicate success
            registers[KDF_CTX_BASE + 0x8C] = 0


    # Create instance
    ssr = SSRCrypto(mock_read32, mock_write32, setup)

    # Register key materials for slot 0
    label = b'RPMB_KEY'
    context = b'SASI'

    # Derive a 16-byte key through the source-backed key_derive() path
    ret, derived = ssr.key_derive(key_len_bytes=16, label=label, context=context)
    print(f"Return code: {ret}")
    print(f"Derived key length: {len(derived)}")
    print(f"Derived key (hex): {derived.hex()}")
    """
