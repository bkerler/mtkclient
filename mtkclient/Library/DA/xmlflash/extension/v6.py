import hashlib
import logging
import os
import sys
import json
from struct import unpack, pack
from Cryptodome.Cipher import AES
# from keystone.keystone import Ks
# from keystone.keystone_const import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

from mtkclient.Library.Hardware.hwcrypto_sej import sej_cryptmode
from mtkclient.Library.mtk_crypto import verify_checksum, nvram_keys, SST_Get_NVRAM_SW_Key
from mtkclient.config.payloads import PathConfig
from mtkclient.config.brom_config import Efuse
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.Hardware.hwcrypto import CryptoSetup, HwCrypto
from mtkclient.Library.utils import find_binary, do_tcp_keyserver
from mtkclient.Library.gui_utils import LogBase, progress, logsetup
from mtkclient.Library.Hardware.seccfg import SecCfgV3, SecCfgV4
from mtkclient.Library.utils import MTKTee
from mtkclient.Library.Exploit.exptools.aarch_tools import Aarch64Tools

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


class XmlFlashExt(metaclass=LogBase):
    def __init__(self, _mtk, _xmlflash, loglevel):
        self.pathconfig = PathConfig()
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, _mtk.config.gui)
        self.mtk = _mtk
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
        self.xflash = _xmlflash
        self.xsend = self.xflash.xsend
        self.xread = self.xflash.xread
        self.da2 = None
        self.da2address = None

    def patch_custom_command(self, _da2):
        self.da2address = self.xflash.daconfig.da_loader.region[2].m_start_addr  # at_address
        data = bytearray(_da2)
        idx = data.find(b"\x00CMD:SET-HOST-INFO\x00")
        if idx == -1:
            return None
        base = self.da2address
        entry = int.from_bytes(_da2[4:8], byteorder='little')
        if entry & 0xF0 == 0xC0:
            self.is_arm64 = True
        else:
            self.is_arm64 = False

        if self.is_arm64:
            at = Aarch64Tools(_da2, self.da2address)
            ref_offset = at.find_string_xref("CMD:SET-HOST-INFO")
            if ref_offset is None:
                print("Error finding CMD:SET-HOST-INFO")
                return None
            bl_offset = at.get_next_bl_from_off(ref_offset)
            if bl_offset is None:
                print("Error finding xml_register_cmd")
                return None
            cmd_set_host = at.resolve_register_value_back(bl_offset, reg=2, lookback=5)
            if cmd_set_host is None:
                print("Error finding cmd_set_host_info")
                return None
            cmd_set_host_offset = cmd_set_host - self.da2address
            # Patch CMD:SET-HOST-INFO to point to our loader
            newcmd = b"CMD:CUSTOM\x00"
            data[idx + 1: idx + 1 + len(newcmd)] = newcmd
            # Now patch the existing SET-HOST-INFO command
            # ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            content = """
            STP             X29, X30, [SP,#-0x30]!
            STR             X21, [SP,#0x10]
            MOV             X29, SP
            STP             X20, X19, [SP,#0x20]
            MOV             X19, X0
            LDR             X21, [X19]
            # Receive length 4 bytes
            ADRP            X0, #0x68000000
            ADD             X0, X0, #0xF000
            MOV             X1, #4
            BLR             X21
            # Receive data
            ADRP            X0, #0x68000000
            MOV             X1, X0
            ADD             X1, X1, #0xF000
            LDR             X1, [X1]
            BLR             X21
            # Jump to payload
            ADRP            X0, #0x68000000
            BLR             X0

            MOV             W0, WZR
            LDP             X20, X19, [SP,#0x20]
            LDR             X21, [SP,#0x10]
            LDP             X29, X30, [SP],#0x30
            RET
            """
            _ = content
            # encoding, length = ks.asm(content, addr=cmd_set_host)
            # newdata = b"".join(int.to_bytes(val, 1, 'little') for val in encoding)
            # print(newdata.hex())
            newdata = bytes.fromhex(
                "fd7bbda9f50b00f9fd030091f44f02a9f30300aa750240f9e0ff13b0003c4091810080d2a0023fd6e0ff13b0e10300aa213c4091210040f9a0023fd6e0ff13b000003fd6e0031f2af44f42a9f50b40f9fd7bc3a8c0035fd6")
            sys.stdout.flush()
            data[cmd_set_host_offset:cmd_set_host_offset + len(newdata)] = newdata
            return data
        else:
            first_op, second_op = offset_to_op_mov(idx + 1, 0, base)
            first_op = int.to_bytes(first_op, 4, 'little')
            second_op = int.to_bytes(second_op, 4, 'little')
            midx = data.find(first_op)
            midx2 = data.find(second_op, midx)
            if midx + 8 == midx2:
                instr1 = int.from_bytes(data[midx + 4:midx + 8], 'little')
                instr2 = int.from_bytes(data[midx2 + 4:midx2 + 8], 'little')
                addr = op_mov_to_offset(instr1, instr2, 2) - base
                # rw_primitive = bytes.fromhex("FF412DE90040A0E30460A0E30C708DE20050A0E10710A0E1003090E508008DE200408" +
                # "DE506808DE004408DE508408DE50C608DE533FF2FE108309DE50710A0E10D00A0E10C608DE5040053E1003095E50A00001" +
                # "A33FF2FE100309DE50610A0E10C608DE50800A0E1003093E504308DE5043095E533FF2FE110D08DE2F081BDE833FF2FE10" +
                # "03095E50710A0E10800A0E10C608DE533FF2FE100309DE50400A0E104209DE5002083E5F2FFFFEA")
                # ks = Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_LITTLE_ENDIAN)
                # content =
                """
                PUSH            {R4-R6,R10,R11,LR}
                ADD             R11, SP, #0x10
                MOV             R8, R0
                MOVW            R0, #0xF000
                MOVT            R0, #0x6800
                MOV             R1, #4
                LDR             R2, [R8]
                BLX             R2

                MOVW            R0, #0xF000
                MOVT            R0, #0x6800
                MOV             R1, [R0]
                MOVW            R0, #0x0000
                MOVT            R0, #0x6800
                LDR             R2, [R8]
                BLX             R2

                MOVW            R0, #0x0000
                MOVT            R0, #0x6800
                BLX             R0

                POP             {R4-R6,R10,R11,PC}
                """
            # encoding, length = ks.asm(content, addr=addr)
            # newdata = b"".join(int.to_bytes(val, 1, 'little') for val in encoding)

            newdata = bytes.fromhex(
                "704c2de910b08de20080a0e100000fe3000846e30410a0e3002098e532ff2fe100000fe3000846e3000000e3000846e3" +
                "002098e532ff2fe1000000e3000846e330ff2fe1708cbde8")
            sys.stdout.flush()
            data[addr:addr + len(newdata)] = newdata
            newcmd = b"CMD:CUSTOM\x00"
            data[idx + 1:idx + 1 + len(newcmd)] = newcmd
            return data
        return _da2

    def ack(self):
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMACK")
        if self.xsend(xmlcmd):
            # result =
            result = self.xflash.get_response()
            _ = result
            # DATA data =
            data = self.xflash.get_response(raw=True)
            # CMD:END result =
            result2 = self.xflash.get_response()
            _ = result2
            self.xflash.ack()
            # CMD:START result =
            resp = self.xflash.get_response()
            _ = resp
            self.xflash.ack()
            if data == b"\xA4\xA3\xA2\xA1":
                return True
        return False

    def patch(self):
        self.da2 = self.xflash.daconfig.da2
        self.da2address = self.xflash.daconfig.da_loader.region[2].m_start_addr  # at_address
        base = self.da2address
        entry = int.from_bytes(self.da2[4:8], byteorder='little')
        if entry & 0xF0 == 0xC0:
            self.is_arm64 = True
        else:
            self.is_arm64 = False

        if self.is_arm64:
            daextensions = os.path.join(self.pathconfig.get_payloads_path(), "da_xml_64.bin")
        else:
            daextensions = os.path.join(self.pathconfig.get_payloads_path(), "da_xml.bin")

        if os.path.exists(daextensions):
            daextdata = bytearray(open(daextensions, "rb").read())

            if self.is_arm64:
                register_ptr = daextdata.find(b"\x11\x11\x11\x11")
                mmc_get_card_ptr = daextdata.find(b"\x22\x22\x22\x22\x22\x22\x22\x22")
                mmc_set_part_config_ptr = daextdata.find(b"\x33\x33\x33\x33\x33\x33\x33\x33")
                mmc_rpmb_send_command_ptr = daextdata.find(b"\x44\x44\x44\x44\x44\x44\x44\x44")
                ufshcd_queuecommand_ptr = daextdata.find(b"\x55\x55\x55\x55\x55\x55\x55\x55")
                ufshcd_get_free_tag_ptr = daextdata.find(b"\x66\x66\x66\x66\x66\x66\x66\x66")
                ptr_g_ufs_hba_ptr = daextdata.find(b"\x77\x77\x77\x77\x77\x77\x77\x77")
                efuse_addr_ptr = daextdata.find(b"\x88\x88\x88\x88")

                register_xml_cmd = find_binary(self.da2,
                                               b"\xFD\x7B\xBD\xA9\xF5\x0B\x00\xF9\xFD\x03\x00\x91\xF4\x4F\x02\xA9\xF5\x03\x00\xAA\x00\x05\x80\x52")
                # UFS
                ar = Aarch64Tools(self.da2, self.da2address)
                ufs_controller_enable_offset = ar.find_function_from_string("Controller enable failed\n")
                instr = int.from_bytes(self.da2[ufs_controller_enable_offset + 0xC:ufs_controller_enable_offset + 0x10],
                                       'little')
                g_ufs_hba = ar.decode_adrp(instr, ufs_controller_enable_offset + 0xC + self.da2address)[0]
                ufshcd_queuecommand = 0
                ufshcd_get_free_tag = 0
                ufshcd_queuecommand = find_binary(self.da2,
                                                  b"\xFD\x7B\xBC\xA9\xF7\x0B\x00\xF9\xFD\x03\x00\x91\xF6\x57\x02\xA9\xF4\x4F\x03\xA9\x14\x34\x40\xF9\xF5\x03\x01\xAA")
                if ufshcd_queuecommand is None:
                    ufshcd_queuecommand = 0
                else:
                    ufshcd_queuecommand = ufshcd_queuecommand + self.da2address

                ufshcd_get_free_tag = ar.find_function_from_string("[UFS] ufshcd_get_free_tag fail\n")
                if ufshcd_get_free_tag is None:
                    ufshcd_get_free_tag = 0
                else:
                    ufshcd_get_free_tag = ufshcd_get_free_tag + self.da2address

                # EMMC
                mmc_switch_part_offset = ar.find_function_from_string("mmc_switch_part")
                mmc_get_card_ptr2 = ar.get_next_bl_from_off(mmc_switch_part_offset)
                mmc_get_card = ar.get_bl_target(mmc_get_card_ptr2)
                mmc_set_part_config = find_binary(self.da2, b"\x08\x80\x40\x39\x88\x00\x08\x37\x08\xB4\x49\x39")
                if mmc_set_part_config is None:
                    mmc_set_part_config = 0

                mmc_rpmb_offs = ar.find_function_from_string("%sreq/1 fail %d\n")
                logl = ar.get_next_bl_from_off(mmc_rpmb_offs)
                mmc_rpmb_send_command_ptr2 = ar.get_next_bl_from_off(logl + 0x8)
                mmc_rpmb_send_command = ar.get_bl_target(mmc_rpmb_send_command_ptr2)
                if mmc_rpmb_send_command is None:
                    mmc_rpmb_send_command = 0
            else:
                register_ptr = daextdata.find(b"\x11\x11\x11\x11")
                mmc_get_card_ptr = daextdata.find(b"\x22\x22\x22\x22")
                mmc_set_part_config_ptr = daextdata.find(b"\x33\x33\x33\x33")
                mmc_rpmb_send_command_ptr = daextdata.find(b"\x44\x44\x44\x44")
                ufshcd_queuecommand_ptr = daextdata.find(b"\x55\x55\x55\x55")
                ufshcd_get_free_tag_ptr = daextdata.find(b"\x66\x66\x66\x66")
                ptr_g_ufs_hba_ptr = daextdata.find(b"\x77\x77\x77\x77")
                efuse_addr_ptr = daextdata.find(b"\x88\x88\x88\x88")

                # 32bit
                # register_xml_cmd("CMD:GET-SYS-PROPERTY", & a1, cmd_get_sys_property);

                # open("out" + hex(self.da2address) + ".da", "wb").write(da2)
                register_xml_cmd = find_binary(self.da2,
                                               b"\x70\x4C\x2D\xE9\x10\xB0\x8D\xE2\x00\x50\xA0\xE1\x14\x00\xA0\xE3")

                # UFS
                idx = self.da2.find(b"\x00\x00\x94\xE5\x34\x10\x90\xE5\x01\x00\x11\xE3\x03\x00\x00\x0A")
                g_ufs_hba = 0
                ufshcd_queuecommand = 0
                ufshcd_get_free_tag = 0
                if idx != -1:
                    instr1 = int.from_bytes(self.da2[idx - 0x8:idx - 0x4], 'little')
                    instr2 = int.from_bytes(self.da2[idx - 0x4:idx], 'little')
                    g_ufs_hba = op_mov_to_offset(instr1, instr2, 4)
                    ufshcd_queuecommand = find_binary(self.da2,
                                                      b"\xF0\x4D\x2D\xE9\x18\xB0\x8D\xE2\x08\xD0\x4D\xE2\x48\x40\x90\xE5")
                    if ufshcd_queuecommand is None:
                        ufshcd_queuecommand = find_binary(self.da2,
                                                          b"\xF0\x4F\x2D\xE9\x1C\xB0\x8D\xE2\x0C\xD0\x4D\xE2\x48\xA0\x90\xE5\x00\x80\xA0\xE1")
                        if ufshcd_queuecommand is None:
                            ufshcd_queuecommand = 0
                        else:
                            ufshcd_queuecommand = ufshcd_queuecommand + self.da2address
                    else:
                        ufshcd_queuecommand = ufshcd_queuecommand + self.da2address

                    ufshcd_get_free_tag = find_binary(self.da2,
                                                      b"\x10\x4C\x2D\xE9\x08\xB0\x8D\xE2\x00\x40\xA0\xE3\x00\x00\x51\xE3")
                    if ufshcd_get_free_tag is None:
                        ufshcd_get_free_tag = 0
                    else:
                        ufshcd_get_free_tag = ufshcd_get_free_tag + self.da2address

                # EMMC
                mmc_get_card = find_binary(self.da2, b"\x90\x12\x20\xE0\x1E\xFF\x2F\xE1")
                if mmc_get_card is not None:
                    mmc_get_card -= 0xC
                else:
                    mmc_get_card = 0

                mmc_set_part_config = find_binary(self.da2, b"\xF0\x4B\x2D\xE9\x18\xB0\x8D\xE2\x23\xDE\x4D\xE2")
                if mmc_set_part_config is None:
                    mmc_set_part_config = find_binary(self.da2, b"\xF0\x4B\x2D\xE9\x18\xB0\x8D\xE2\x8E\xDF\x4D\xE2")
                    if mmc_set_part_config is None:
                        mmc_set_part_config = 0

                mmc_rpmb_send_command = find_binary(self.da2, b"\xF0\x48\x2D\xE9\x10\xB0\x8D\xE2\x08\x70\x9B\xE5")
                if mmc_rpmb_send_command is None:
                    mmc_rpmb_send_command = 0

            efuse_addr = self.config.chipconfig.efuse_addr
            if register_ptr != -1:
                if register_xml_cmd:
                    register_xml_cmd = register_xml_cmd + self.da2address
                else:
                    register_xml_cmd = 0

                length = 4
                if self.is_arm64:
                    # Patch the addr
                    length = 8
                    daextdata[register_ptr:register_ptr + 4] = pack("<I", register_xml_cmd)
                    daextdata[mmc_get_card_ptr:mmc_get_card_ptr + length] = pack("<Q", mmc_get_card)
                    daextdata[mmc_set_part_config_ptr:mmc_set_part_config_ptr + length] = pack("<Q",
                                                                                               mmc_set_part_config)
                    daextdata[mmc_rpmb_send_command_ptr:mmc_rpmb_send_command_ptr + length] = pack("<Q",
                                                                                                   mmc_rpmb_send_command)
                    daextdata[ufshcd_get_free_tag_ptr:ufshcd_get_free_tag_ptr + length] = pack("<Q",
                                                                                               ufshcd_get_free_tag)
                    daextdata[ufshcd_queuecommand_ptr:ufshcd_queuecommand_ptr + length] = pack("<Q",
                                                                                               ufshcd_queuecommand)
                    daextdata[ptr_g_ufs_hba_ptr:ptr_g_ufs_hba_ptr + length] = pack("<Q", g_ufs_hba)
                    if efuse_addr_ptr != -1 and efuse_addr is not None:
                        daextdata[efuse_addr_ptr:efuse_addr_ptr + 4] = pack("<I", efuse_addr)
                else:
                    length = 4
                    daextdata[register_ptr:register_ptr + length] = pack("<I", register_xml_cmd)
                    daextdata[mmc_get_card_ptr:mmc_get_card_ptr + length] = pack("<I", mmc_get_card)
                    daextdata[mmc_set_part_config_ptr:mmc_set_part_config_ptr + length] = pack("<I",
                                                                                               mmc_set_part_config)
                    daextdata[mmc_rpmb_send_command_ptr:mmc_rpmb_send_command_ptr + length] = pack("<I",
                                                                                                   mmc_rpmb_send_command)
                    daextdata[ufshcd_get_free_tag_ptr:ufshcd_get_free_tag_ptr + length] = pack("<I",
                                                                                               ufshcd_get_free_tag)
                    daextdata[ufshcd_queuecommand_ptr:ufshcd_queuecommand_ptr + length] = pack("<I",
                                                                                               ufshcd_queuecommand)
                    daextdata[ptr_g_ufs_hba_ptr:ptr_g_ufs_hba_ptr + length] = pack("<I", g_ufs_hba)
                    if efuse_addr_ptr != -1 and efuse_addr is not None:
                        daextdata[efuse_addr_ptr:efuse_addr_ptr + length] = pack("<I", efuse_addr)
                # print(hexlify(daextdata).decode('utf-8'))
                # open("daext.bin","wb").write(daextdata)
                return daextdata
        return None

    def patch_da1(self, _da1):
        return _da1

    def patch_da2(self, _da2):
        self.info("Patching da2 ...")
        patched = False
        da2patched = bytearray(_da2)
        pos = 0
        idx = 0
        while idx is not None:
            idx = find_binary(_da2, b"\x00\x00\xA0\xE3\x04\x10\xA0\xE1\x00\x20\xA0\xE3..\x00\xEB\x01\x40\x00\xE3",
                              pos)
            if idx is not None:
                offset = int.from_bytes(da2patched[idx + 0xC:idx + 0xE], 'little') - 1
                da2patched[idx:idx + 0x14] = (b"\x00\x00\xA0\xE3\x04\x10\xA0\xE1\x2C\x22\x0E\xE3\x00\x20\x44\xE3" +
                                              offset.to_bytes(2, 'little') + b"\x00\xEB")
                patched = True
                pos += idx
            pos += 0x14
        if not patched:
            idx = find_binary(_da2,
                              b"\x20\x00\x80\x52\xC0\x03\x5F\xD6\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6\xE0\x03\x1F\x2A\xC0\x03\x5F\xD6")
            if idx is not None:
                da2patched[idx:idx + 0x18] = (
                    b"\x20\x00\x80\x52\xC0\x03\x5F\xD6\x20\x00\x80\x52\xC0\x03\x5F\xD6\x20\x00\x80\x52\xC0\x03\x5F\xD6")
                patched = True
        if not patched:
            # TCL 50 5G
            idx = find_binary(_da2,
                              b"\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1")
            if idx is not None:
                da2patched[idx:idx + 0x18] = (
                    b"\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1")
                patched = True

        if patched:
            self.info("Patched read_register / write_register")
            patch_custom = self.patch_custom_command(_da2)
            if patch_custom is not None:
                self.info("Patched CUSTOM command")
                da2patched = patch_custom

        idx = find_binary(da2patched,
                          b"\x00\xA0\xE3\x1E\xFF\x2F\xE1.\x00\xA0\xE3\x1E\xFF\x2F\xE1." +
                          b"\x00\xA0\xE3\x1E\xFF\x2F\xE1\x70\x4C")
        if idx is not None:
            da2patched[idx - 1:idx - 1 + (3 * 8)] = (b"\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1\x01\x00\xA0" +
                                                     b"\xE3\x1E\xFF\x2F\xE1\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1")
            patched = True
            self.info("Patched write partitions / allow_read / allow_write")
        if not patched:
            self.warning("Write not allowed not patched.")

        idx = find_binary(da2patched, b"\x01\x10\xA0\xE3\x00\x10\x80\xE5")
        if idx is not None:
            da2patched[idx:idx + 8] = b"\x00\x10\xA0\xE3\x00\x10\x80\xE5"
            patched = True
            self.info("Patched hash binding")
        if not patched:
            self.warning("Hash binding not patched.")

        idx = find_binary(da2patched, b"\xC4\x08\x04\xE3\x05\x00\x44\xE3")
        if idx is not None:
            da2patched[idx + 8:idx + 8 + 4] = b"\x00\x00\xA0\xE3"
        """idx = find_binary(da2patched,b"\xA4\x43\x00\xEB\x66\x18\x00\xEB")
        if idx is not None:
            da2patched[idx:idx+8] = b"\xA4\x43\x00\xEB\x08\x00\x00\xEB"
            patched = True
            self.info("Bypass SEC policy")
        if not patched:
            self.warning("SEC policy bypass not patched.")
        """

        idx = da2patched.find(
            b"\x30\x48\x2D\xE9\x08\xB0\x8D\xE2\x08\xD0\x4D\xE2\x00\x40\xA0\xE1\x04\x00\x8D\xE2\x00\x50\xA0\xE3")
        if idx != -1:
            patch = b"\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1"
            da2patched[idx:idx + len(patch)] = patch
            self.info("Patched generic Partition sgpt verification.")

        idx3 = find_binary(da2patched, b"\x32\x00\x00\xE3\x02\x00\x4C\xE3")
        if idx3 is not None:
            da2patched[idx3:idx3 + 12] = b"\x00\x00\xA0\xE3\x00\x00\xA0\xE3\x00\x40\xA0\xE3"
            self.info("Patched SLA signature check 1")
            idx4 = find_binary(da2patched, b"\x32\x40\x00\xE3\x02\x40\x4C\xE3")
            if idx4 is not None:
                da2patched[idx4:idx4 + 8] = b"\x00\x40\xA0\xE3\x00\x40\xA0\xE3"
                self.info("Patched SLA signature check 2")
        else:
            idx2 = find_binary(da2patched, b"\xF0\x4D\x2D\xE9\x18\xB0\x8D\xE2\xF0\xD0\x4D\xE2\x01\x50\xA0\xE1")
            if idx2 is not None:
                self.info("Patched Infinix Remote SLA v3 authentification.")
                da2patched[idx2:idx2 + 0x8] = b"\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1"
            else:
                idx2 = find_binary(da2patched, b"\x70\x4C\x2D\xE9\x10\xB0\x8D\xE2\x00\x60\xA0\xE1\x02\x06\xA0\xE3")
                if idx2 is None:
                    idx2 = find_binary(da2patched,
                                       b"\x70\x4C\x2D\xE9\x10\xB0\x8D\xE2\x01\x40\xA0\xE1\x00\x50\xA0\xE1\x7F\x00\x00\xEB")
                if idx2 is not None:
                    da2patched[idx2:idx2 + 8] = b"\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1"
                    self.info("Patched Oppo Remote SLA authentification.")
                    idx3 = find_binary(da2patched, b"\x03\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x01\x00\x00\x00")
                    if idx3 is not None:
                        da2patched[idx3:idx3 + 4] = b"\xFF\x00\x00\x00"
                        self.info("Patched Oppo Allowance flag.")
                    idx4 = find_binary(da2patched, b"\x4C\x08\x04\xE3\x03\x10\xA0\xE3\x05\x00\x44\xE3\x2E\x62\xA0\xE3")
                    if idx4 is not None:
                        da2patched[idx4:idx4 + 16] = b"\x4C\x08\x04\xE3\x05\x10\xA0\xE3\x05\x00\x44\xE3\x00\x60\xA0\xE3"
                        self.info("Patched cust_security_get_dev_fw_info.")
                else:
                    idx2 = find_binary(da2patched,
                                       b"\xFD\x7B\xBD\xA9\xF6\x57\x01\xA9\xF4\x4F\x02\xA9\xFD\x03\x00\x91\xF5\x03\x02\xAA\xF3\x03\x01\x2A")
                    if idx2 is not None:
                        da2patched[idx2:idx2 + 8] = b"\x20\x00\x80\x52\xC0\x03\x5F\xD6"
                        idx3 = find_binary(da2patched,
                                           b"\x03\x00\x00\x00\xFF\xFF\xFF\xFF\x01\x00\x00\x00\x08\x00\x00\x00")
                        if idx3 is not None:
                            da2patched[idx3:idx3 + 4] = b"\xFF\x00\x00\x00"
                            self.info("Patched Oppo Allowance V2 flag.")
                    else:
                        idx2 = find_binary(da2patched,
                                           b"\xF0\x4D\x2D\xE9\x18\xB0\x8D\xE2\x82\xDF\x4D\xE2\x01\x60\xA0\xE1\x38\x19\x0F\xE3\x00\x70\xA0\xE1\x42\x0F\x8D\xE2")
                        if idx2 is not None:
                            da2patched[idx2:idx2 + 8] = b"\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1"
                            self.info("Patched Vivo Remote SLA authentification.")

        idx = da2patched.find(b"DA.SLA\x00ENABLED")
        if idx != -1:
            patch = b"DA.SLA\x00DISABLE"
            da2patched[idx:idx + len(patch)] = patch
            self.info("Patched generic Remote SLA authentification.")
            """
            n = "9BB734774443D77557A76E24B10733787750D90D09C869CD606D54F28978EA6220DC9948B3C9E89284F8551D6166F3754B6A3B890AC9CDA9E37DFAA0C1317E351CE5107C4273795949C6CCE638314AB1A345385D7642CB8D055A1F410C7D7E24A6F0A2AAB8184E773D21B3754A947541680F2C1A8D6BA5BEFD3B6E1FC28EC0B61D55B1454383F2C3E8BD27170A25978608F6788B90A2FC34F0CE35056BF7520795C8C60232CBBC0B0399367AF937869CA45CF737A8A066127893E93166C433298DD6FD009E6790E743B3392ACA8EA99F61DFC77BD99416DDA4B8A9D7E4DA24217427F3584119A4932016F1735CC63B12650FDDDA73C8FCFBC79E058F36219D3D"
            pubkey = bytes.fromhex(n)
            # Generic SLA patch, just replace the public key with a known one
            idx2 = da2patched.rfind(b"\x01\x00\x01\x00")
            # Infinix / Tecno
            if idx2 is not None:
                da2patched[idx2 - 0x100:idx2] = pubkey
            else:
                # Oppo / Oneplus
                idx2 = find_binary(da2patched, b"0123456789ABCDEF0123456789abcdef")
                if idx2 is not None:
                    da2patched[idx2 - 0x100:idx2] = pubkey
                self.warning("SLA authentification not patched.")
            """
        # open("da.patched.bin",
        # "wb").write(da2patched)
        return da2patched

    def custom_set_storage(self, ufs: bool = False):
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMSTORAGE")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                if ufs:
                    self.xsend(int.to_bytes(1, 4, 'little'))
                else:
                    # EMMC
                    self.xsend(int.to_bytes(0, 4, 'little'))
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
                return True
        return False

    def custom_rpmb_read(self, sector, sectors):
        data = bytearray()
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMRPMBR")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                self.xsend(sector)
                self.xsend(sectors)
                for i in range(sectors):
                    tmp = self.xflash.get_response(raw=True)
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
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
        return data

    def custom_rpmb_write(self, sector, sectors, data: bytes):
        if len(data) % 0x100 != 0:
            self.error("Incorrect rpmb frame length. Aborting")
            return False
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMRPMBW")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                self.xsend(sector)
                self.xsend(sectors)
                for i in range(sectors):
                    self.xsend(data[i * 0x100:(i * 0x100) + 0x100])
                    resp = unpack("<H", self.xflash.get_response(raw=True))[0]
                    if resp != 0:
                        if resp in rpmb_error:
                            self.error(rpmb_error[resp])
                        result = self.xflash.get_response()
                        self.xflash.ack()
                        # CMD:START
                        result = self.xflash.get_response()
                        self.xflash.ack()
                        return False
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
                return True
        # CMD:END
        result = self.xflash.get_response()
        self.xflash.ack()
        # CMD:START
        result = self.xflash.get_response()
        self.xflash.ack()
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
                    xmlcmd = self.xflash.cmd.create_cmd("CUSTOMRPMBK")
                    if self.xsend(xmlcmd):
                        result = self.xflash.get_response()
                        if result == "OK":
                            self.xsend(rpmbkey)
                            read_key = self.xflash.get_response(raw=True)
                            # CMD:END
                            result = self.xflash.get_response()
                            self.xflash.ack()
                            # CMD:START
                            result = self.xflash.get_response()
                            self.xflash.ack()
                            if rpmbkey == read_key:
                                self.info("Setting rpmbkey: ok")
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMRPMBI")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                if self.config.hwcode in [0x1209, 0x1129]:
                    mode = 1
                else:
                    mode = 0
                self.xsend(mode)
                status = int.from_bytes(self.xflash.get_response(raw=True), 'little')
                if status == 0:
                    derivedrpmb = self.xflash.get_response(raw=True)
                    self.info("Derived rpmb key: " + derivedrpmb.hex())
                    # CMD:END
                    result = self.xflash.get_response()
                    self.xflash.ack()
                    # CMD:START
                    result = self.xflash.get_response()
                    self.xflash.ack()
                    return True
            self.error("Failed to derive a valid rpmb key.")
        # CMD:END
        result = self.xflash.get_response()
        self.xflash.ack()
        # CMD:START
        result = self.xflash.get_response()
        self.xflash.ack()
        return False

    def custom_rpmb_prog(self, rpmbkey):
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMRPMBP")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                self.xsend(rpmbkey)
                status = self.xflash.get_response(raw=True)
                res = int.from_bytes(status, 'little')
                if res == 1:
                    self.warning("Key already programmed :(")
                elif res == 0:
                    self.info("Key successfully programmed :)")
                else:
                    self.error(f"Issue on programming Key: {hex(res)}")
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
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

    def read_rpmb(self, filename=None, sector: int = None, sectors: int = None, display=True):
        # self.custom_rpmb_prog(b"vutsrqponmlkjihgfedcba9876543210")
        # self.custom_rpmb_init()
        if sectors == 0:
            if self.xflash.daconfig.storage.emmc.rpmb_size != 0:
                sectors = self.xflash.daconfig.storage.emmc.rpmb_size // 0x100
            elif self.xflash.daconfig.storage.ufs.lu1_size != 0:
                sectors = (512 * 256)
        progressbar = progress(total=sectors * 256, pagesize=1, guiprogress=self.mtk.config.guiprogress,
                               prefix="RPMB read:")
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
                        if display:
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
            max_sector_size = (512 * 256)
            if self.xflash.daconfig.storage.emmc is not None:
                max_sector_size = self.xflash.daconfig.storage.emmc.rpmb_size // 0x100
        else:
            max_sector_size = sectors
        filesize = os.path.getsize(filename)
        sectors = min(filesize // 256, max_sector_size)
        progressbar = progress(total=sectors * 256, pagesize=1, guiprogress=self.mtk.config.guiprogress,
                               prefix="RPMB write:")
        if self.custom_rpmb_init():
            if sectors > 0:
                with open(filename, "rb") as rf:
                    pos = 0
                    towrite = sectors
                    while towrite > 0:
                        sz = min(sectors - pos, 0x10)
                        if not self.custom_rpmb_write(sector=sector + pos, sectors=sz, data=rf.read(0x100 * sz)):
                            if display:
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
            if self.xflash.daconfig.storage.emmc is not None:
                sectors = self.xflash.daconfig.storage.emmc.rpmb_size // 0x100
            elif self.xflash.daconfig.storage.ufs.block_size != 0:
                sectors = (512 * 256)
        progressbar = progress(total=sectors * 256, pagesize=1, guiprogress=self.mtk.config.guiprogress,
                               prefix="RPMB erase:")
        if self.custom_rpmb_init():
            if sectors > 0:
                pos = 0
                towrite = sectors
                while towrite > 0:
                    sz = min(sectors - pos, 0x10)
                    if not self.custom_rpmb_write(sector=sector + pos, sectors=sz, data=b"\x00" * 0x100 * sz):
                        if display:
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

    def custom_read(self, addr, length, registers=True) -> bytes:
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMMEMR")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                # DATA
                self.xsend(data=addr, is64bit=True)
                self.xsend(length)
                data = self.xflash.get_response(raw=True)
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
                return data
        return b""

    def custom_read_reg(self, addr: int, length: int) -> bytes:
        tmp = self.custom_readregister(addr, length // 4)
        if isinstance(tmp, int):
            return int.to_bytes(tmp, 4, 'little')
        else:
            data = bytearray(b"".join([tmp[i].to_bytes(4, 'little') for i in range(len(tmp))]))
        return data

    def custom_readregister(self, addr, dwords=1) -> (int, None):
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMREGR")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                # DATA
                self.xsend(data=addr)
                self.xsend(data=dwords)
                data = self.xflash.get_response(raw=True)
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
                if dwords == 1:
                    return int.from_bytes(data, 'little')
                else:
                    return [int.from_bytes(data[pos:pos + 4], 'little') for pos in range(0, len(data), 4)]
        return None

    def custom_write(self, addr, data) -> bool:
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMMEMR")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                # DATA
                self.xsend(data=addr, is64bit=True)
                self.xsend(len(data))
                self.xsend(data)
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
                return True
        return False

    def custom_writeregister(self, addr: int, data: int):
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMREGW")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                # DATA
                self.xsend(addr)
                self.xsend(data)
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
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

    def custom_sej_hw(self, encrypt: bool, data: bytes, cryptmode: int = sej_cryptmode.HW_ENCRYPTED_5G,
                      swcrypt: int = 0,
                      otp=None, seed=None,
                      unlock: bool = False, aeskey: bytes = None, enxor: bool = False):
        if aeskey is None:
            aeskey = bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")
        if otp is None:
            otp = b"\x00" * 32
        if seed is None:
            seed = b"12abcdef"
        xmlcmd = self.xflash.cmd.create_cmd("CUSTOMSEJ")
        if self.xsend(xmlcmd):
            result = self.xflash.get_response()
            if result == "OK":
                val = ((enxor & 0xFF) << 24) | ((encrypt & 0xFF) << 16) | ((swcrypt & 0xFF) << 8) | (cryptmode & 0xFF)
                flags = int.to_bytes(val, 4, 'little')
                self.xsend(flags)
                self.xsend(otp)
                self.xsend(seed[:8])
                if cryptmode != sej_cryptmode.UNLOCK:
                    self.xsend(aeskey)
                self.xsend(int.to_bytes(len(data), 4, 'little'))
                self.xsend(data)
                status = unpack("<H", self.xflash.get_response(raw=True))[0]
                data = b""
                if status == 0:
                    # CMD:END
                    data = self.xflash.get_response(raw=True)
                # CMD:END
                result = self.xflash.get_response()
                self.xflash.ack()
                # CMD:START
                result = self.xflash.get_response()
                self.xflash.ack()
                return status, data
        return -1, b""

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
                    addr=partition.sector * guid_gpt.sectorsize,
                    length=partition.sectors * guid_gpt.sectorsize,
                    filename="", parttype="user", display=False)
                break
        if seccfg_data is None:
            return False, "Couldn't detect existing seccfg partition. Aborting unlock."
        if seccfg_data.find(b"\x4D\x4D\x4D\x4D") == -1:
            return False, "SecCfg is empty. Aborting unlock."
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
        cryptmode = sej_cryptmode.SW_ENCRYPTED
        swcrypt = 0
        if attr & 0x8:
            if display:
                print("SW Encrypted")
            swcrypt = 1
            if len(aeskey) == 0x20:
                swcrypt = 1
        if attr & 0x20:
            if display:
                print("HW Encrypted")
            cryptmode = sej_cryptmode.HW_ENCRYPTED_5G
        outdata = bytearray()
        items = len(data[0x40:]) // nvitemsize
        sw = False
        hwc = self.cryptosetup()
        if display:
            print("Encrypted data: " + data[0x40:].hex())
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
                                                       data=data[0x40 + (x * nvitemsize):0x40 + (x * nvitemsize) +
                                                                                         nvitemsize],
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

    def read_fuse(self, idx):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            if idx < len(efuseconfig.efuses):
                addr = efuseconfig.efuses[idx]
                if addr < 0x1000:
                    return int.to_bytes(addr, 4, 'little')
                data = bytearray(self.mtk.daloader.peek_reg(addr=addr, length=4))
                return data
        return None

    def read_pubk(self):
        if self.config.hwcode == 0x1209:
            return None
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            addr = base + 0x90
            data = bytearray(self.mtk.daloader.peek_reg(addr=addr, length=0x30))
            return data
        return None

    def readfuses(self):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            data = []
            for idx in range(len(efuseconfig.efuses)):
                addr = efuseconfig.efuses[idx]
                if addr < 0x1000:
                    return data.append(int.to_bytes(addr, 4, 'little'))
                else:
                    data.append(bytearray(self.mtk.daloader.peek(addr=addr, length=4, registers=True)))
            return data

    def keyserver(self):
        hwc = self.cryptosetup()
        if self.config.chipconfig.dxcc_base is not None:
            self.info("Starting key server...")
            do_tcp_keyserver(hwc)
        return

    def generate_keys(self):
        if self.config.hwcode in [0x2601, 0x6572]:
            base = 0x11141000
        elif self.config.hwcode == 0x6261:
            base = 0x70000000
        elif self.config.hwcode in [0x8172, 0x8176]:
            base = 0x122000
        else:
            base = 0x100000
        if self.config.meid is None:
            try:
                data = b"".join([pack("<I", val) for val in self.readmem(base + 0x8EC, 0x10 // 4)])
                self.config.meid = data
                self.config.set_meid(data)
            except Exception:
                return
        if self.config.socid is None:
            try:
                data = b"".join([pack("<I", val) for val in self.readmem(base + 0x934, 0x20 // 4)])
                self.config.socid = data
                self.config.set_socid(data)
            except Exception:
                return
        hwc = self.cryptosetup()
        meid = self.config.get_meid()
        socid = self.config.get_socid()
        hwcode = self.config.get_hwcode()
        cid = self.config.get_cid()
        otp = self.config.get_otp()
        retval = {}
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
            # self.info("Generating provision key...")
            # platkey, provkey = hwc.aes_hwcrypt(btype="dxcc", mode="prov")
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

            ctx = self.xflash.get_dev_info()
            if "socid" in ctx:
                if "socid" not in retval:
                    retval["socid"] = ctx["socid"].hex()
            if "rid" in ctx:
                retval["cid"] = ctx["rid"].hex()
            if "hrid" in ctx:
                retval["hrid"] = ctx["hrid"].hex()
            else:
                val = self.read_fuse(0xC)
                if val is not None:
                    val += self.read_fuse(0xD)
                    val += self.read_fuse(0xE)
                    val += self.read_fuse(0xF)
                    self.info(f"HRID        : {val.hex()}")
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


def offset_to_op_mov(addr, register, base):
    offset = addr + base
    low = (((offset & 0xFFFF) >> 12) & 0xF) << 16 | (register << 14) | offset & 0xFFF
    offset = (offset >> 16)
    shift = 4
    high = (((offset & 0xFFFF) >> 12) & 0xF) << 16 | (register << 14) | offset & 0xFFF | (shift << 20)
    first_op = (0xE3 << 24) + low
    second_op = (0xE3 << 24) + high
    return first_op, second_op


def op_mov_to_offset(first_op, second_op, register):
    reglo = (first_op & 0xF000) >> 12
    reghi = (second_op & 0xF000) >> 12
    shiftlo = (first_op & 0xF00000) >> 20
    shifthi = (second_op & 0xF00000) >> 20
    hi = ((second_op & 0xF0000) >> 4 | second_op & 0xFFF) << shifthi * 4
    lo = ((first_op & 0xF0000) >> 4 | first_op & 0xFFF) << shiftlo * 4
    if reglo == reghi == register:
        return hi | lo
    return None


