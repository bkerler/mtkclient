import hashlib
import logging
import os
from struct import unpack, pack

from Cryptodome.Cipher import AES

from mtkclient.Library.Hardware.hwcrypto_sej import sej_cryptmode
from mtkclient.Library.mtk_crypto import verify_checksum, SST_Get_NVRAM_SW_Key, nvram_keys
from mtkclient.config.payloads import PathConfig
from mtkclient.config.brom_config import Efuse
from mtkclient.Library.error import ErrorHandler, ErrorCodes_XFlash
from mtkclient.Library.Hardware.hwcrypto import CryptoSetup, HwCrypto
from mtkclient.Library.utils import find_binary, do_tcp_keyserver
from mtkclient.Library.gui_utils import LogBase, progress, logsetup
from mtkclient.Library.Hardware.seccfg import SecCfgV3, SecCfgV4
from mtkclient.Library.utils import MTKTee
import json


class XCmd:
    CUSTOM_ACK = 0x0F0000
    CUSTOM_READMEM = 0x0F0001
    CUSTOM_READREGISTER = 0x0F0002
    CUSTOM_WRITEMEM = 0x0F0003
    CUSTOM_WRITEREGISTER = 0x0F0004
    CUSTOM_SET_STORAGE = 0x0F0005
    CUSTOM_RPMB_SET_KEY = 0x0F0006
    CUSTOM_RPMB_PROG_KEY = 0x0F0007
    CUSTOM_RPMB_INIT = 0x0F0008
    CUSTOM_RPMB_READ = 0x0F0009
    CUSTOM_RPMB_WRITE = 0x0F000A
    CUSTOM_SEJ_HW = 0x0F000B


rpmb_error = [
    "",
    "General failure",
    "Authentication failure",
    "Counter failure",
    "Address failure",
    "Write failure",
    "Read failure",
    "Authentication key not yet programmed"
]


class XFlashExt(metaclass=LogBase):
    def __init__(self, mtk, xflash, loglevel):
        self.lasterror = None
        self.pathconfig = PathConfig()
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.mtk = mtk
        self.loglevel = loglevel
        self.__logger = self.__logger
        self.eh = ErrorHandler()
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.echo = self.mtk.port.echo
        self.rbyte = self.mtk.port.rbyte
        self.rdword = self.mtk.port.rdword
        self.rword = self.mtk.port.rword
        self.xflash = xflash
        self.xsend = self.xflash.xsend
        self.send_devctrl = self.xflash.send_devctrl
        self.xread = self.xflash.xread
        self.status = self.xflash.status
        self.da2 = None
        self.da2address = None

    def patch(self):
        self.da2 = self.xflash.daconfig.da2
        self.da2address = self.xflash.daconfig.da_loader.region[2].m_start_addr  # at_address
        daextensions = os.path.join(self.pathconfig.get_payloads_path(), "da_x.bin")
        if os.path.exists(daextensions):
            daextdata = bytearray(open(daextensions, "rb").read())

            register_devctrl = find_binary(self.da2, b"\x38\xB5\x05\x46\x0C\x20")

            # EMMC
            mmc_get_card = find_binary(self.da2, b"\x4B\x4F\xF4\x3C\x72")
            if mmc_get_card is not None:
                mmc_get_card -= 1
            else:
                mmc_get_card = find_binary(self.da2, b"\xA3\xEB\x00\x13\x18\x1A\x02\xEB\x00\x10")
                if mmc_get_card is not None:
                    mmc_get_card -= 10
            pos = 0
            while True:
                mmc_set_part_config = find_binary(self.da2, b"\xC3\x69\x0A\x46\x10\xB5", pos)
                if mmc_set_part_config is None:
                    break
                else:
                    pos = mmc_set_part_config + 1
                    if self.da2[mmc_set_part_config + 20:mmc_set_part_config + 22] == b"\xb3\x21":
                        break
            if mmc_set_part_config is None:
                mmc_set_part_config = find_binary(self.da2, b"\xC3\x69\x13\xF0\x01\x03")
            mmc_rpmb_send_command = find_binary(self.da2, b"\xF8\xB5\x06\x46\x9D\xF8\x18\x50")
            if mmc_rpmb_send_command is None:
                mmc_rpmb_send_command = find_binary(self.da2, b"\x2D\xE9\xF0\x41\x4F\xF6\xFD\x74")

            # UFS
            # ptr is right after ufshcd_probe_hba and at the beginning
            g_ufs_hba = None
            ptr_g_ufs_hba = find_binary(self.da2, b"\x20\x46\x0B\xB0\xBD\xE8\xF0\x83\x00\xBF")
            if ptr_g_ufs_hba is not None:
                g_ufs_hba = int.from_bytes(self.da2[ptr_g_ufs_hba + 10:ptr_g_ufs_hba + 10 + 4], 'little')
            else:
                # 6833 -> ufshcd_probe_hba
                ptr_g_ufs_hba = find_binary(self.da2, b"\x20\x46\x0D\xB0\xBD\xE8\xF0\x83")
                if ptr_g_ufs_hba is not None:
                    g_ufs_hba = int.from_bytes(self.da2[ptr_g_ufs_hba + 8:ptr_g_ufs_hba + 8 + 4], 'little')
                else:
                    ptr_g_ufs_hba = find_binary(self.da2, b"\x21\x46\x02\xF0\x02\xFB\x1B\xE6\x00\xBF")
                    if ptr_g_ufs_hba is not None:
                        g_ufs_hba = int.from_bytes(self.da2[ptr_g_ufs_hba + 10 + 0x8:ptr_g_ufs_hba + 10 + 0x8 + 4],
                                                   'little')

            if ptr_g_ufs_hba is not None:
                ufshcd_get_free_tag = find_binary(self.da2, b"\xB5.\xB1\x90\xF8")
                ufshcd_queuecommand = find_binary(self.da2, b"\x2D\xE9\xF8\x43\x01\x27")
            else:
                g_ufs_hba = None
                ufshcd_get_free_tag = None
                ufshcd_queuecommand = None

            register_ptr = daextdata.find(b"\x11\x11\x11\x11")
            mmc_get_card_ptr = daextdata.find(b"\x22\x22\x22\x22")
            mmc_set_part_config_ptr = daextdata.find(b"\x33\x33\x33\x33")
            mmc_rpmb_send_command_ptr = daextdata.find(b"\x44\x44\x44\x44")
            ufshcd_queuecommand_ptr = daextdata.find(b"\x55\x55\x55\x55")
            ufshcd_get_free_tag_ptr = daextdata.find(b"\x66\x66\x66\x66")
            ptr_g_ufs_hba_ptr = daextdata.find(b"\x77\x77\x77\x77")
            efuse_addr_ptr = daextdata.find(b"\x88\x88\x88\x88")

            if register_ptr != -1 and mmc_get_card_ptr != -1:
                if register_devctrl:
                    register_devctrl = register_devctrl + self.da2address | 1
                else:
                    register_devctrl = 0
                if mmc_get_card:
                    mmc_get_card = mmc_get_card + self.da2address | 1
                else:
                    mmc_get_card = 0
                if mmc_set_part_config:
                    mmc_set_part_config = mmc_set_part_config + self.da2address | 1
                else:
                    mmc_set_part_config = 0
                if mmc_rpmb_send_command:
                    mmc_rpmb_send_command = mmc_rpmb_send_command + self.da2address | 1
                else:
                    mmc_rpmb_send_command = 0

                if ufshcd_get_free_tag:
                    ufshcd_get_free_tag = ufshcd_get_free_tag + (self.da2address - 1) | 1
                else:
                    ufshcd_get_free_tag = 0

                if ufshcd_queuecommand:
                    ufshcd_queuecommand = ufshcd_queuecommand + self.da2address | 1
                else:
                    ufshcd_queuecommand = 0

                if g_ufs_hba is None:
                    g_ufs_hba = 0

                efuse_addr = self.config.chipconfig.efuse_addr

                # Patch the addr
                daextdata[register_ptr:register_ptr + 4] = pack("<I", register_devctrl)
                daextdata[mmc_get_card_ptr:mmc_get_card_ptr + 4] = pack("<I", mmc_get_card)
                daextdata[mmc_set_part_config_ptr:mmc_set_part_config_ptr + 4] = pack("<I", mmc_set_part_config)
                daextdata[mmc_rpmb_send_command_ptr:mmc_rpmb_send_command_ptr + 4] = pack("<I", mmc_rpmb_send_command)
                daextdata[ufshcd_get_free_tag_ptr:ufshcd_get_free_tag_ptr + 4] = pack("<I", ufshcd_get_free_tag)
                daextdata[ufshcd_queuecommand_ptr:ufshcd_queuecommand_ptr + 4] = pack("<I", ufshcd_queuecommand)
                daextdata[ptr_g_ufs_hba_ptr:ptr_g_ufs_hba_ptr + 4] = pack("<I", g_ufs_hba)
                if efuse_addr_ptr != -1:
                    daextdata[efuse_addr_ptr:efuse_addr_ptr + 4] = pack("<I", efuse_addr)

                # print(hexlify(daextdata).decode('utf-8'))
                # open("daext.bin","wb").write(daextdata)
                return daextdata
        return None

    def patch_da1(self, da1):
        # Patch error 0xC0020039
        self.info("Patching da1 ...")
        da1patched = None
        if da1 is not None:
            da1patched = bytearray(da1)
            da1patched = self.mtk.patch_preloader_security_da1(da1patched)
            # Patch security

            da_version_check = find_binary(da1, b"\x1F\xB5\x00\x23\x01\xA8\x00\x93\x00\xF0")
            if da_version_check is not None:
                da1patched = bytearray(da1patched)
                da1patched[da_version_check:da_version_check + 4] = b"\x00\x20\x70\x47"
            else:
                self.warning("Error on patching da1 version check...")
        else:
            print("Error, couldn't find da1.")
        return da1patched

    def patch_da2(self, da2):
        da2 = self.mtk.patch_preloader_security_da2(da2)
        # Patch error 0xC0030007
        self.info("Patching da2 ...")
        # open("da2.bin","wb").write(da2)
        da2patched = bytearray(da2)
        # Patch huawei security, rma state
        pos = 0
        huawei = find_binary(da2, b"\x01\x2B\x03\xD1\x01\x23", pos)
        if huawei is not None:
            da2patched[huawei:huawei + 4] = b"\x00\x00\x00\x00"
        if find_binary(da2, b"[oplus]") or find_binary(da2, b"[OPPO]"):
            # Patch oppo security mt6765
            flag = False
            oppo = find_binary(da2, b"\x0A\x00\x00\xE0.\x00\x00\xE0")
            if oppo is not None:
                auth_flag_ptr = int.from_bytes(da2patched[oppo - 4:oppo], 'little')
                auth_flag_offset = auth_flag_ptr - self.mtk.daloader.daconfig.da_loader.region[2].m_start_addr
                if int.from_bytes(da2patched[auth_flag_offset:auth_flag_offset + 4], 'little') == 3:
                    da2patched[auth_flag_offset:auth_flag_offset + 1] = b"\x01"
                    self.info("Oppo g_oppo_auth_status patched.")
                    flag = True
            if not flag:
                oppo = find_binary(da2, b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")
                if oppo is not None:
                    da2patched[oppo + 0x10:oppo + 0x10 + 1] = b"\x01"
                    self.info("Oppo g_oppo_auth_status patched.")
                else:
                    # 20271
                    oppo = find_binary(da2, b"\x63\x88\x74\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")
                    if oppo is not None:
                        da2patched[oppo + 0x10:oppo + 0x10 + 1] = b"\x01"
                        self.info("Oppo g_oppo_auth_status patched.")

            # Patch oppo security
            oppo = 0
            pos = 0
            while oppo is not None:
                oppo = find_binary(da2, b"\x01\x3B\x01\x2B\x08\xD9", pos)
                if oppo is not None:
                    da2patched[oppo:oppo + 4] = b"\x01\x20\x08\xBD"
                    pos = oppo + 1

        # Patch hash binding 0xC0020004 or 0xC0020005
        hashbind = find_binary(da2, b"\x01\x23\x03\x60\x00\x20\x70\x47\x70\xB5")
        if hashbind is not None:
            da2patched[hashbind:hashbind + 1] = b"\x00"
        else:
            # Patch hash binding Techno
            hashbind = find_binary(da2, b"\x01\x10\xA0\xE3\x00\x10\x80\xE5\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1")
            if hashbind is not None:
                da2patched[hashbind:hashbind + 1] = b"\x00"
                buf_chk = find_binary(da2, b"\xF0\x4F\x2D\xE9\x1C\xB0\x8D\xE2\x54\xD0\x4D\xE2\x00\x50\xA0\xE1")
                if buf_chk is not None:
                    patch = b"\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1"
                    da2patched[buf_chk:buf_chk + len(patch)] = patch
                    general_check = find_binary(da2, b"\x01\x50\x82\xE1\x7A\x00\x00\x0A\x08\x00\xA0\xE1")
                    if general_check is not None:
                        patch_gen = b"\x00\x50\xA0\xE3\x7A\x00\x00\xEA"
                        da2patched[general_check + len(patch_gen)] = patch_gen
            else:
                self.warning("Hash binding not patched.")

        # Patch hash check cmd_boot_to
        authaddr = find_binary(da2, int.to_bytes(0xC0070004, 4, 'little'))
        if authaddr:
            da2patched[authaddr:authaddr + 4] = int.to_bytes(0, 4, 'little')
        elif authaddr is None:
            authaddr = find_binary(da2, b"\x4F\xF0\x04\x09\xCC\xF2\x07\x09")
            if authaddr:
                da2patched[authaddr:authaddr + 8] = b"\x4F\xF0\x00\x09\x4F\xF0\x00\x09"
            else:
                authaddr = find_binary(da2, b"\x4F\xF0\x04\x09\x32\x46\x01\x98\x03\x99\xCC\xF2\x07\x09")
                if authaddr:
                    da2patched[authaddr:authaddr + 14] = b"\x4F\xF0\x00\x09\x32\x46\x01\x98\x03\x99\x4F\xF0\x00\x09"
                else:
                    self.warning("Hash check not patched.")
        # Disable security checks
        security_check = find_binary(da2, b"\x01\x23\x03\x60\x00\x20\x70\x47\x70\xB5")
        if security_check:
            da2patched[security_check:security_check + 2] = b"\x00\x23"
            self.info("Security check patched")
        # Disable da anti rollback version check
        antirollback = find_binary(da2, int.to_bytes(0xC0020053, 4, 'little'))
        if antirollback:
            da2patched[antirollback:antirollback + 4] = int.to_bytes(0, 4, 'little')
            self.info("DA version anti-rollback patched")
        disable_sbc = find_binary(da2, b"\x02\x4B\x18\x68\xC0\xF3\x40\x00\x70\x47")
        if disable_sbc:
            # MOV R0, #0
            da2patched[disable_sbc + 4:disable_sbc + 8] = b"\x4F\xF0\x00\x00"
            self.info("SBC patched to be disabled")
        moto_disable_sla = find_binary(da2, b"\x01\x00\x01\xC0\x01\x20\x70\x47")
        if moto_disable_sla:
            da2patched[moto_disable_sla + 4:moto_disable_sla + 6] = b"\x00\x20"
            self.info("DA2 sla patched to be disabled")
        register_readwrite = find_binary(da2, int.to_bytes(0xC004000D, 4, 'little'))
        if register_readwrite:
            da2patched[register_readwrite:register_readwrite + 4] = int.to_bytes(0, 4, 'little')
            self.info("Register read/write not allowed patched")
        # Patch write not allowed
        # open("da2.bin","wb").write(da2patched)
        idx = 0
        patched = False
        while idx != -1:
            idx = da2patched.find(b"\x37\xB5\x00\x23\x04\x46\x02\xA8")
            if idx != -1:
                da2patched[idx:idx + 8] = b"\x37\xB5\x00\x20\x03\xB0\x30\xBD"
                patched = True
            else:
                idx = da2patched.find(b"\x0C\x23\xCC\xF2\x02\x03")
                if idx != -1:
                    da2patched[idx:idx + 6] = b"\x00\x23\x00\x23\x00\x23"
                    idx2 = da2patched.find(b"\x2A\x23\xCC\xF2\x02\x03")
                    if idx2 != -1:
                        da2patched[idx2:idx2 + 6] = b"\x00\x23\x00\x23\x00\x23"
                    """
                    idx3 = da2patched.find(b"\x2A\x24\xE4\xF7\x89\xFB\xCC\xF2\x02\x04")
                    if idx3 != -1:
                        da2patched[idx3:idx3 + 10] = b"\x00\x24\xE4\xF7\x89\xFB\x00\x24\x00\x24"
                    """
                    patched = True
        if not patched:
            self.warning("Write not allowed not patched.")
        return da2patched

    def cmd(self, cmd):
        if self.xsend(self.xflash.cmd.DEVICE_CTRL):
            status = self.status()
            if status == 0x0:
                if self.xsend(cmd):
                    status = self.status()
                    if status == 0x0:
                        return True
                    else:
                        self.error(ErrorCodes_XFlash[status])

        return False

    def custom_read(self, addr, length, registers=True):
        data = bytearray()
        pos = 0
        while pos < length:
            if self.cmd(XCmd.CUSTOM_READMEM):
                self.xsend(data=addr + pos, is64bit=True)
                sz = min(length, 0x10000)
                self.xsend(sz)
                tmp = self.xread()
                data.extend(tmp)
                pos += len(tmp)
                status = self.status()
                if status != 0:
                    break
        return data[:length]

    def custom_set_storage(self, ufs: bool = False):
        if self.cmd(XCmd.CUSTOM_SET_STORAGE):
            if ufs:
                self.xsend(int.to_bytes(1, 4, 'little'))
            else:
                # EMMC
                self.xsend(int.to_bytes(0, 4, 'little'))
            status = self.status()
            if status == 0:
                return True
        return False

    def custom_readregister(self, addr, dwords=1):
        if self.cmd(XCmd.CUSTOM_READREGISTER):
            self.xsend(addr)
            self.xsend(dwords)
            data = self.xread()
            status = self.status()
            if status == 0:
                if dwords == 1:
                    return int.from_bytes(data, 'little')
                else:
                    return [int.from_bytes(data[pos:pos + 4], 'little') for pos in range(0, len(data), 4)]
        return b""

    def custom_write(self, addr, data):
        if self.cmd(XCmd.CUSTOM_WRITEMEM):
            self.xsend(data=addr, is64bit=True)
            self.xsend(len(data))
            self.xsend(data)
            status = self.status()
            if status == 0:
                return True
        return False

    def custom_sej_hw(self, encrypt: bool, data: bytes, cryptmode: int = sej_cryptmode.HW_ENCRYPTED_5G, otp=None,
                      seed=None,
                      aeskey: bytes = None, swcrypt: int = 0, enxor: bool = False):
        if aeskey is None:
            aeskey = bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")
        if otp is None:
            otp = b"\x00" * 32
        if seed is None:
            seed = b"12abcdef"
        if self.cmd(XCmd.CUSTOM_SEJ_HW):
            val = ((enxor & 0xFF) << 24) | ((encrypt & 0xFF) << 16) | ((swcrypt & 0xFF) << 8) | cryptmode & 0xFF
            flags = int.to_bytes(val, 4, 'little')
            dlen = len(data)
            self.xsend(flags)
            self.xsend(otp)
            self.xsend(seed[:8])
            if cryptmode != sej_cryptmode.UNLOCK:
                self.xsend(aeskey)
            self.xsend(int.to_bytes(dlen, 4, 'little'))
            self.xsend(data)
            # data1 = self.xread()
            status = self.status()
            if status == 0:
                data = self.xread()
        status = self.status()
        if status == 0:
            return status, data
        return status, b""

    def custom_writeregister(self, addr, data):
        if self.cmd(XCmd.CUSTOM_WRITEREGISTER):
            self.xsend(addr)
            self.xsend(data)
            status = self.status()
            if status == 0:
                return True
        return False

    def readmem(self, addr, dwords=1):
        if dwords < 0x20:
            res = self.custom_readregister(addr, dwords)
        else:
            res = self.custom_read(addr, dwords * 4)
            res = [unpack("<I", res[i:i + 4])[0] for i in range(0, len(res), 4)]
        if isinstance(res, list):
            self.debug(f"RX: {hex(addr)} -> " + bytearray(b"".join(pack("<I", val) for val in res)).hex())
        else:
            self.debug(f"RX: {hex(addr)} -> {hex(res)}")
        return res

    def writeregister(self, addr, dwords):
        if isinstance(dwords, int):
            dwords = [dwords]
        pos = 0
        if len(dwords) < 0x20:
            for val in dwords:
                self.debug(f"TX: {hex(addr + pos)} -> " + hex(val))
                if not self.custom_writeregister(addr + pos, val):
                    return False
                pos += 4
        else:
            dat = b"".join([pack("<I", val) for val in dwords])
            self.custom_write(addr, dat)
        return True

    def writemem(self, addr, data):
        for i in range(0, len(data), 4):
            value = data[i:i + 4]
            while len(value) < 4:
                value += b"\x00"
            self.writeregister(addr + i, unpack("<I", value))
        return True

    def custom_rpmb_read(self, sector, sectors):
        data = bytearray()
        cmd = XCmd.CUSTOM_RPMB_READ
        if self.cmd(cmd):
            self.xsend(sector)
            self.xsend(sectors)
            for i in range(sectors):
                tmp = self.xread()
                if len(tmp) != 0x100:
                    resp = int.from_bytes(tmp, 'little')
                    if resp in rpmb_error:
                        msg = rpmb_error[resp]
                    else:
                        msg = f"Error: {hex(resp)}"
                    self.error(f"Error on sector {hex(sector)}: {msg})")
                    return b""
                else:
                    data.extend(tmp)
        status = self.status()
        if status == 0:
            return data
        else:
            return b""

    def custom_rpmb_write(self, sector, sectors, data: bytes):
        if len(data) % 0x100 != 0:
            self.error("Incorrect rpmb frame length. Aborting")
            return False
        cmd = XCmd.CUSTOM_RPMB_WRITE
        if self.cmd(cmd):
            self.xsend(sector)
            self.xsend(sectors)
            for i in range(sectors):
                self.xsend(data[i * 0x100:(i * 0x100) + 0x100])
                resp = unpack("<H", self.xread())[0]
                if resp != 0:
                    if resp in rpmb_error:
                        self.error(rpmb_error[resp])
                        status = self.status()
                        return False
            status = self.status()
            if status == 0:
                return True

        status = self.status()
        return False

    def custom_rpmb_init(self, rpmbkey: bytes = None):
        hwc = self.cryptosetup()
        if self.config.chipconfig.meid_addr:
            meid = self.config.get_meid()
            otp = self.config.get_otp()
            if meid != b"\x00" * 16:
                # self.config.set_meid(meid)
                self.info("Generating sej rpmbkey...")
                if rpmbkey is None:
                    rpmbkey = hwc.aes_hwcrypt(mode="rpmb", data=meid, btype="sej", otp=otp)
                if rpmbkey is not None:
                    if self.cmd(XCmd.CUSTOM_RPMB_SET_KEY):
                        self.xsend(rpmbkey)
                        read_key = self.xread()
                        if self.status() == 0x0:
                            if rpmbkey == read_key:
                                self.info("Setting rpmbkey: ok")
        cmd = XCmd.CUSTOM_RPMB_INIT
        if self.cmd(cmd):
            if self.config.hwcode in [0x1209, 0x1129]:
                mode = 1
            else:
                mode = 0
            self.xsend(mode)
            status = self.status()
            if status == 0:
                derivedrpmb = self.xread()
                self.status()
                if status == 0:
                    self.info("Derived rpmb key: " + derivedrpmb.hex())
                    return True
            else:
                if status in rpmb_error:
                    print(rpmb_error[status])
                    return False
                elif status == 0xfffe:
                    self.error("Failed to derive a valid rpmb key.")
        return False

    def setotp(self, hwc):
        otp = None
        if self.mtk.config.preloader is not None:
            idx = self.mtk.config.preloader.find(b"\x4D\x4D\x4D\x01\x30")
            if idx != -1:
                otp = self.mtk.config.preloader[idx + 0xC:idx + 0xC + 32]
        if otp is None:
            otp = 32 * b"\x00"
        hwc.sej.sej_set_otp(otp)

    def protect(self, data):
        return data
        hrid = self.mtk.daloader.peek(self.config.chipconfig.efuse_addr + 0x140, 8)
        hwcode = int.to_bytes(self.config.hwcode, 4, 'little')
        for i in range(len(data)):
            data[i] = data[i] ^ hrid[i % 8]
        for i in range(len(data)):
            data[i] = data[i] ^ hwcode[i % 4]
        return data

    def nvitem(self, data: bytes, encrypt: bool = False, otp: bytes = None, seed: bytes = None, aeskey: bytes = None,
               display: bool = True):
        if otp is None:
            otp = 32 * b"\x00"
        if seed is None:
            seed = b"12abcdef"
        data = bytearray(data)
        # data[0x40:] = self.protect(data[0x40:])
        lid = int.from_bytes(data[4:6], 'little')
        if display:
            print("LID: " + hex(lid))
            print("Items: " + hex(int.from_bytes(data[6:8], 'little')))
        itemsize = int.from_bytes(data[8:0xc], 'little')
        nvitemsize = 0x20
        if display:
            print("Itemsize: " + hex(itemsize))
        attr = int.from_bytes(data[0xc:0xf], 'little')
        if display:
            print("Attribute: " + hex(attr))
        swcrypt = 0
        cryptmode = sej_cryptmode.SW_ENCRYPTED
        if attr & 0x8:
            if display:
                print("SW AES Encrypted")
            swcrypt = 1
            if len(aeskey) == 0x20:
                swcrypt = 1
        if attr & 0x20:
            if display:
                print("HW AES Encrypted")
            cryptmode = sej_cryptmode.HW_ENCRYPTED_5G
        outdata = bytearray()
        items = len(data[0x40:]) // nvitemsize
        if display:
            print("Encrypted data: " + data[0x40:].hex())
        hwc = self.cryptosetup()
        sw = False
        for x in range(items):
            if sw:
                if cryptmode == sej_cryptmode.HW_ENCRYPTED:
                    ddata = hwc.aes_hwcrypt(mode="sst_4g",
                                            data=data[0x40 + (x * nvitemsize):0x40 + (x * nvitemsize) + nvitemsize],
                                            btype="sej", encrypt=encrypt, otp=otp)
                elif cryptmode == sej_cryptmode.HW_ENCRYPTED_5G:
                    ddata = hwc.aes_hwcrypt(mode="sst_5g",
                                            data=data[0x40 + (x * nvitemsize):0x40 + (x * nvitemsize) + nvitemsize],
                                            btype="sej", encrypt=encrypt, otp=otp)
                elif cryptmode == sej_cryptmode.SW_ENCRYPTED:
                    nvramkey = SST_Get_NVRAM_SW_Key(nvram_keys["mtk"], 0x256)
                    ddata = AES.new(nvramkey[:0x10], AES.MODE_ECB).decrypt(
                        data[0x40 + (x * nvitemsize):0x40 + (x * nvitemsize) + nvitemsize])
            else:
                status, ddata = self.custom_sej_hw(encrypt=encrypt,
                                                   data=data[
                                                       0x40 + (x * nvitemsize):0x40 + (x * nvitemsize) + nvitemsize],
                                                   cryptmode=cryptmode, swcrypt=swcrypt, otp=otp, seed=seed,
                                                   aeskey=aeskey)
            # ddata = self.protect(ddata)
            if attr & 0x20 and not encrypt:
                if not verify_checksum(ddata):
                    cryptmode = sej_cryptmode.HW_ENCRYPTED
                    status, ddata = self.custom_sej_hw(encrypt=encrypt,
                                                       data=data[0x40 + (x * nvitemsize):
                                                                 0x40 + (x * nvitemsize) + nvitemsize],
                                                       cryptmode=cryptmode, swcrypt=swcrypt, otp=otp, seed=seed,
                                                       aeskey=aeskey)
                    # ddata = self.protect(ddata)
                    if not verify_checksum(ddata):
                        if display:
                            print("Error on verifying checksum")
                        break
            if ddata == b"":
                if display:
                    print("Error on hw crypto")
                return b""
            else:
                outdata.extend(ddata)
        if display:
            print("Decrypted data: " + outdata.hex())
        return outdata

    def read_rpmb(self, filename=None, sector: int = None, sectors: int = None, display=True):
        # val = self.custom_rpmb_init()
        if sector is None:
            sector = 0
        if sectors == 0:
            if self.mtk.daloader.daconfig.storage.flashtype == "emmc":
                sectors = self.xflash.emmc.rpmb_size // 0x100
            elif self.mtk.daloader.daconfig.storage.flashtype == "ufs":
                sectors = (512 * 256)
        progressbar = progress(total=sectors * 256, guiprogress=self.mtk.config.guiprogress, prefix="RPMB read:")
        if filename is None:
            filename = "rpmb.bin"
        if sectors > 0:
            with open(filename, "wb") as wf:
                pos = 0
                toread = sectors
                while toread > 0:
                    sz = min(sectors - pos, 0x10)
                    data = self.custom_rpmb_read(sector=sector + pos, sectors=sz)
                    if data == b"":
                        progressbar.done()
                        self.error("Couldn't read rpmb.")
                        return False
                    if display:
                        progressbar.update(sz * 256)
                    wf.write(data)
                    pos += sz
                    toread -= sz
            if display:
                progressbar.done()
            self.info(f"Done reading rpmb to {filename}")
            return True
        return False

    def write_rpmb(self, filename=None, sector: int = None, sectors: int = None, display=True):
        if filename is None:
            self.error("Filename has to be given for writing to rpmb")
            return False
        if not os.path.exists(filename):
            self.error(f"Couldn't find {filename} for writing to rpmb.")
            return False
        if sectors == 0:
            if self.mtk.daloader.daconfig.storage.flashtype == "emmc":
                max_sector_size = self.xflash.emmc.rpmb_size // 0x100
            elif self.mtk.daloader.daconfig.storage.flashtype == "ufs":
                max_sector_size = (512 * 256)
        else:
            max_sector_size = sectors
        filesize = os.path.getsize(filename)
        sectors = min(filesize // 256, max_sector_size)
        progressbar = progress(total=sectors * 256, guiprogress=self.mtk.config.guiprogress, prefix="RPMB write:")
        if self.custom_rpmb_init():
            if sectors > 0:
                with open(filename, "rb") as rf:
                    pos = 0
                    towrite = sectors
                    while towrite > 0:
                        sz = min(sectors - pos, 0x10)
                        if not self.custom_rpmb_write(sector=sector + pos, sectors=sz, data=rf.read(0x100 * sz)):
                            progressbar.done()
                            self.error(f"Couldn't write rpmb at sector {sector + pos}.")
                            return False
                        if display:
                            progressbar.update(sz * 256)
                        pos += sz
                        towrite -= sz
                if display:
                    progressbar.done()
                self.info(f"Done writing {filename} to rpmb")
                return True
        return False

    def auth_rpmb(self, rpmbkey: bytes = None):
        if self.custom_rpmb_init(rpmbkey):
            return True
        return False

    def erase_rpmb(self, sector: int = None, sectors: int = None, display=True):
        if sector is None:
            sector = 0
        if sectors is None:
            if self.xflash.emmc is not None:
                sectors = self.xflash.emmc.rpmb_size // 0x100
            else:
                sectors = (512 * 256)
        progressbar = progress(total=sectors * 256, guiprogress=self.mtk.config.guiprogress, prefix="RPMB erase:")
        if self.custom_rpmb_init():
            if sectors > 0:
                pos = 0
                towrite = sectors
                while towrite > 0:
                    sz = min(sectors - pos, 0x10)
                    if not self.custom_rpmb_write(sector=sector + pos, sectors=sz, data=b"\x00" * 0x100 * sz):
                        progressbar.done()
                        self.error(f"Couldn't erase rpmb at sector {sector + pos}.")
                        return False
                    if display:
                        progressbar.update(sz * 256)
                    pos += sz
                    towrite -= sz
                if display:
                    progressbar.done()
                self.info("Done erasing rpmb")
                return True
        return False

    def cryptosetup(self):
        setup = CryptoSetup()
        setup.blacklist = self.config.chipconfig.blacklist
        setup.gcpu_base = self.config.chipconfig.gcpu_base
        setup.dxcc_base = self.config.chipconfig.dxcc_base
        setup.efuse_base = self.config.chipconfig.efuse_addr
        setup.da_payload_addr = self.config.chipconfig.da_payload_addr
        setup.sej_base = self.config.chipconfig.sej_base
        setup.read32 = self.readmem
        setup.write32 = self.writeregister
        setup.writemem = self.writemem
        setup.hwcode = self.config.hwcode
        return HwCrypto(setup, self.loglevel, self.config.gui)

    def seccfg(self, lockflag):
        if lockflag not in ["unlock", "lock"]:
            return False, "Valid flags are: unlock, lock"
        data, guid_gpt = self.xflash.partition.get_gpt(self.mtk.config.gpt_settings, "user")
        seccfg_data = None
        partition = None
        if guid_gpt is None:
            return False, "Error getting the partition table."
        for rpartition in guid_gpt.partentries:
            if rpartition.name == "seccfg":
                partition = rpartition
                seccfg_data = self.xflash.readflash(
                    addr=partition.sector * self.mtk.daloader.daconfig.pagesize,
                    length=partition.sectors * self.mtk.daloader.daconfig.pagesize,
                    filename="", parttype="user", display=False)
                break
        if seccfg_data is None:
            return False, "Couldn't detect existing seccfg partition. Aborting unlock."
        if seccfg_data[:4] != pack("<I", 0x4D4D4D4D):
            return False, "Unknown seccfg partition header. Aborting unlock."
        hwc = self.cryptosetup()
        if seccfg_data[:0xC] == b"AND_SECCFG_v":
            self.info("Detected V3 Lockstate")
            sc_org = SecCfgV3(hwc, self.mtk, self.custom_sej_hw)
            if not sc_org.parse(seccfg_data):
                return False, "Device has is either already unlocked or algo is unknown. Aborting."
        elif seccfg_data[:4] == b"\x4D\x4D\x4D\x4D":
            self.info("Detected V4 Lockstate")
            sc_org = SecCfgV4(hwc, self.mtk, self.custom_sej_hw)
            if not sc_org.parse(seccfg_data):
                return False, "Device has is either already unlocked or algo is unknown. Aborting."
        else:
            res = input(
                "Unknown lockstate or no lockstate. Shall I write a new one ?\n" +
                "Dangerous !! Type \"v3\" or \"v4\" for a new state. Press just enter to cancel.")
            if res == "v3":
                sc_org = SecCfgV3(hwc, self.mtk, self.custom_sej_hw)
            elif res == "v4":
                sc_org = SecCfgV4(hwc, self.mtk, self.custom_sej_hw)
            else:
                return False, "Unknown lockstate or no lockstate"
        ret, writedata = sc_org.create(lockflag=lockflag)
        if ret is False:
            return False, writedata
        if self.xflash.writeflash(addr=partition.sector * self.mtk.daloader.daconfig.pagesize,
                                  length=len(writedata),
                                  filename="", wdata=writedata, parttype="user", display=True):
            return True, "Successfully wrote seccfg."
        return False, "Error on writing seccfg config to flash."

    def decrypt_tee(self, filename="tee1.bin", aeskey1: bytes = None, aeskey2: bytes = None):
        hwc = self.cryptosetup()
        with open(filename, "rb") as rf:
            data = rf.read()
            idx = 0
            while idx != -1:
                idx = data.find(b"EET KTM ", idx + 1)
                if idx != -1:
                    mt = MTKTee()
                    mt.parse(data[idx:])
                    rdata = hwc.mtee(data=mt.data, keyseed=mt.keyseed, ivseed=mt.ivseed,
                                     aeskey1=aeskey1, aeskey2=aeskey2)
                    open("tee_" + hex(idx) + ".dec", "wb").write(rdata)

    def read_fuse(self, idx):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            if idx < len(efuseconfig.efuses):
                addr = efuseconfig.efuses[idx]
                if addr < 0x1000:
                    return int.to_bytes(addr, 4, 'little')
                data = bytearray(self.mtk.daloader.peek(addr=addr, length=4, registers=True))
                return data
        return None

    def read_pubk(self):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            addr = base + 0x90
            data = bytearray(self.mtk.daloader.peek(addr=addr, length=0x30, registers=True))
            return data
        return None

    def read_fuses(self):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            data = []
            for idx in range(len(efuseconfig.efuses)):
                addr = efuseconfig.efuses[idx]
                if addr < 0x1000:
                    data.append(int.to_bytes(addr, 4, 'little'))
                else:
                    data.append(bytearray(self.mtk.daloader.peek(addr=addr, length=4, registers=True)))
            return data

    def custom_read_reg(self, addr: int, length: int) -> bytes:
        tmp = self.custom_readregister(addr, length // 4)
        if isinstance(tmp, int):
            return int.to_bytes(tmp, 4, 'little')
        else:
            data = bytearray(b"".join([tmp[i].to_bytes(4, 'little') for i in range(len(tmp))]))
        return data

    def keyserver(self):
        hwc = self.cryptosetup()
        if self.config.chipconfig.dxcc_base is not None:
            self.info("Starting key server...")
            do_tcp_keyserver(hwc)
        return

    def generate_keys(self):
        if not self.mtk.daloader.patch:
            self.error("DA loader isn't patched .. cannot generate keys :(")
            return {}

        if self.config.hwcode in [0x2601, 0x6572]:
            base = 0x11141000
        elif self.config.hwcode == 0x6261:
            base = 0x70000000
        elif self.config.hwcode in [0x8172, 0x8176]:
            base = 0x122000
        else:
            base = 0x100000
        retval = {}
        if self.config.meid is None:
            try:
                data = b"".join([pack("<I", val) for val in self.readmem(base + 0x8EC, 0x10 // 4)])
                self.config.meid = data
                self.config.set_meid(data)
            except Exception as err:
                self.lasterror = err
                return retval
        if self.config.socid is None:
            try:
                data = b"".join([pack("<I", val) for val in self.readmem(base + 0x934, 0x20 // 4)])
                self.config.socid = data
                self.config.set_socid(data)
            except Exception as err:
                self.lasterror = err
                return retval
        hwc = self.cryptosetup()
        meid = self.config.get_meid()
        socid = self.config.get_socid()
        hwcode = self.config.get_hwcode()
        cid = self.config.get_cid()
        otp = self.config.get_otp()
        # data=hwc.aes_hwcrypt(data=bytes.fromhex("A9 E9 DC 38 BF 6B BD 12 CC 2E F9 E6 F5 65 E8 C6 88 F7 14 11 80 " +
        # "2E 4D 91 8C 2B 48 A5 BB 03 C3 E5"), mode="sst", btype="sej",
        #                encrypt=False)
        # self.info(data.hex())
        pubk = self.read_pubk()
        if pubk is not None:
            retval["pubkey"] = pubk.hex()
            self.info(f"PUBK        : {pubk.hex()}")
            self.config.hwparam.writesetting("pubkey", pubk.hex())
        if meid is not None:
            self.info(f"MEID        : {meid.hex()}")
            retval["meid"] = meid.hex()
            self.config.hwparam.writesetting("meid", meid.hex())
        if socid is not None:
            self.info(f"SOCID       : {socid.hex()}")
            retval["socid"] = socid.hex()
            self.config.hwparam.writesetting("socid", socid.hex())
        if hwcode is not None:
            self.info(f"HWCODE      : {hex(hwcode)}")
            retval["hwcode"] = hex(hwcode)
            self.config.hwparam.writesetting("hwcode", hex(hwcode))
        if cid is not None:
            self.info(f"CID         : {cid}")
            retval["cid"] = cid
        if self.config.chipconfig.dxcc_base is not None:
            self.info("Generating dxcc rpmbkey...")
            rpmbkey = hwc.aes_hwcrypt(btype="dxcc", mode="rpmb")
            self.info("Generating dxcc mirpmbkey...")
            mirpmbkey = hwc.aes_hwcrypt(btype="dxcc", mode="mirpmb")
            self.info("Generating dxcc fdekey...")
            fdekey = hwc.aes_hwcrypt(btype="dxcc", mode="fde")
            self.info("Generating dxcc rpmbkey2...")
            rpmb2key = hwc.aes_hwcrypt(btype="dxcc", mode="rpmb2")
            self.info("Generating dxcc moto...")
            motokey = hwc.aes_hwcrypt(btype="dxcc", mode="moto")
            self.info("Generating dxcc km key...")
            ikey = hwc.aes_hwcrypt(btype="dxcc", mode="itrustee", data=self.config.hwparam.appid)
            # self.info("Generating dxcc platkey + provkey key...")
            # platkey, provkey = hwc.aes_hwcrypt(btype="dxcc", mode="prov")
            # self.info("Provkey     : " + provkey.hex())
            # self.info("Platkey     : " + platkey.hex())
            if mirpmbkey is not None:
                self.info(f"MIRPMB      : {mirpmbkey.hex()}")
                self.config.hwparam.writesetting("mirpmbkey", mirpmbkey.hex())
                retval["mirpmbkey"] = mirpmbkey.hex()
            if rpmbkey is not None:
                self.info(f"RPMB        : {rpmbkey.hex()}")
                self.config.hwparam.writesetting("rpmbkey", rpmbkey.hex())
                retval["rpmbkey"] = rpmbkey.hex()
            if rpmb2key is not None:
                self.info(f"RPMB2       : {rpmb2key.hex()}")
                self.config.hwparam.writesetting("rpmb2key", rpmb2key.hex())
                retval["rpmb2key"] = rpmb2key.hex()
            if motokey is not None:
                self.info(f"MOTO        : {motokey.hex()}")
                self.config.hwparam.writesetting("motokey", motokey.hex())
                retval["motokey"] = motokey.hex()
            if fdekey is not None:
                self.info(f"FDE         : {fdekey.hex()}")
                self.config.hwparam.writesetting("fdekey", fdekey.hex())
                retval["fdekey"] = fdekey.hex()
            if ikey is not None:
                self.info(f"iTrustee    : {ikey.hex()}")
                self.config.hwparam.writesetting("kmkey", ikey.hex())
                retval["kmkey"] = ikey.hex()
            if self.config.chipconfig.prov_addr:
                provkey = self.custom_read(self.config.chipconfig.prov_addr, 16)
                self.info(f"PROV        : {provkey.hex()}")
                self.config.hwparam.writesetting("provkey", provkey.hex())
                retval["provkey"] = provkey.hex()
            hrid = self.xflash.get_hrid()
            rid = self.xflash.get_random_id()
            if hrid is not None:
                self.info(f"HRID XFLASH : {hrid.hex()}")
                self.config.hwparam.writesetting("hrid", hrid.hex())
                retval["hrid"] = hrid.hex()
            else:
                val = self.read_fuse(0xC)
                if val is not None:
                    val += self.read_fuse(0xD)
                    val += self.read_fuse(0xE)
                    val += self.read_fuse(0xF)
                    self.info(f"HRID FUSE  : {val.hex()}")
                    self.config.hwparam.writesetting("hrid", val.hex())
                    retval["hrid"] = val.hex()
            if "hrid" in retval:
                hrid = bytes.fromhex(retval["hrid"])
                hrid_md5 = hashlib.md5(hrid + hrid).hexdigest()
                hrid_sha256 = hashlib.sha256(hrid).hexdigest()
                retval["hrid_md5"] = hrid_md5
                retval["hrid_sha256"] = hrid_sha256
                self.info("HRID MD5    : " + hrid_md5)
                self.info("HRID SHA256 : " + hrid_sha256)
                self.config.hwparam.writesetting("hrid_md5", hrid_md5)
                self.config.hwparam.writesetting("hrid_sha256", hrid_sha256)
            if rid is not None:
                self.info(f"RID         : {rid.hex()}")
                self.config.hwparam.writesetting("rid", rid.hex())
                retval["rid"] = rid.hex()
            if hwcode == 0x699 and self.config.chipconfig.sej_base is not None:
                mtee3 = hwc.aes_hwcrypt(mode="mtee3", btype="sej")
                if mtee3:
                    self.config.hwparam.writesetting("mtee3", mtee3.hex())
                    self.info(f"MTEE3       : {mtee3.hex()}")
                    retval["mtee3"] = mtee3.hex()
            return retval
        elif self.config.chipconfig.sej_base is not None:
            if os.path.exists("tee.json"):
                val = json.loads(open("tee.json", "r").read())
                self.decrypt_tee(val["filename"], bytes.fromhex(val["data"]), bytes.fromhex(val["data2"]))
            if meid == b"":
                meid = self.custom_read(0x1008ec, 16)
            if meid != b"":
                # self.config.set_meid(meid)
                self.info("Generating sej rpmbkey...")
                self.setotp(hwc)
                rpmbkey = hwc.aes_hwcrypt(mode="rpmb", data=meid, btype="sej", otp=otp)
                if rpmbkey:
                    self.info(f"RPMB        : {rpmbkey.hex()}")
                    self.config.hwparam.writesetting("rpmbkey", rpmbkey.hex())
                    retval["rpmbkey"] = rpmbkey.hex()
                rpmbkey6580 = hwc.aes_hwcrypt(mode="rpmb6580", btype="sej", otp=otp)
                if rpmbkey6580:
                    self.info(f"RPMB_6580        : {rpmbkey6580.hex()}")
                    self.config.hwparam.writesetting("rpmbkey6580", rpmbkey6580.hex())
                    retval["rpmbkey6580"] = rpmbkey6580.hex()
                self.info("Generating sej mtee...")
                mtee = hwc.aes_hwcrypt(mode="mtee", btype="sej", otp=otp)
                if mtee:
                    self.config.hwparam.writesetting("mtee", mtee.hex())
                    self.info(f"MTEE        : {mtee.hex()}")
                    retval["mtee"] = mtee.hex()
                mtee3 = hwc.aes_hwcrypt(mode="mtee3", btype="sej", otp=otp)
                if mtee3:
                    self.config.hwparam.writesetting("mtee3", mtee3.hex())
                    self.info(f"MTEE3       : {mtee3.hex()}")
                    retval["mtee3"] = mtee3.hex()
            else:
                self.info("SEJ Mode: No meid found. Are you in brom mode ?")
        if self.config.chipconfig.gcpu_base is not None:
            if self.config.hwcode in [0x335, 0x8167, 0x8168, 0x8163, 0x8176]:
                self.info("Generating gcpu mtee2 key...")
                mtee2 = hwc.aes_hwcrypt(btype="gcpu", mode="mtee")
                if mtee2 is not None:
                    self.info(f"MTEE2       : {mtee2.hex()}")
                    self.config.hwparam.writesetting("mtee2", mtee2.hex())
                    retval["mtee2"] = mtee2.hex()
        return retval
