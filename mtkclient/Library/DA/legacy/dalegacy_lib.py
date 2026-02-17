#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import logging
import os
import sys
import time
from struct import pack, unpack
from binascii import hexlify
from mtkclient.Library.DA.legacy.dalegacy_flash_param import (Legacy_NandInfo64, Legacy_NorInfo, Legacy_NandInfo32,
                                                              Legacy_EmmcInfo, Legacy_NandInfo2, Legacy_SdcInfo,
                                                              Legacy_ConfigInfo)
from mtkclient.Library.DA.legacy.dalegacy_iot_flash_param import (NorInfoIoT, NandInfoIoT, EmmcInfoIoT, ConfigInfoIoT,
                                                                  NorInfoIoT2523)

from mtkclient.Library.DA.legacy.dalegacy_param import PortValues, Rsp, Cmd
from mtkclient.Library.DA.legacy.extension.legacy import LegacyExt
from mtkclient.Library.DA.storage import DaStorage
from mtkclient.Library.gui_utils import LogBase, logsetup, structhelper_io, progress
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.partition import Partition
from mtkclient.config.payloads import PathConfig
from mtkclient.Library.thread_handling import writedata
from queue import Queue
from threading import Thread


class PassInfo:
    ack = None
    m_download_status = None
    m_boot_style = None
    soc_ok = None

    def __init__(self, data):
        sh = structhelper_io(data)
        self.ack = sh.bytes()
        self.m_download_status = sh.dword(direction='big')
        self.m_boot_style = sh.dword(direction='big')
        self.soc_ok = sh.bytes()


def crc_word(data, chs=0):
    return (sum(data) + chs) & 0xFFFF


class DALegacy(metaclass=LogBase):

    def __init__(self, mtk, daconfig, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.Cmd = Cmd()
        self.Rsp = Rsp()
        self.PortValues = PortValues()
        self.mtk = mtk
        self.daconfig = daconfig
        self.eh = ErrorHandler()
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.echo = self.mtk.port.echo
        self.rbyte = self.mtk.port.rbyte
        self.rdword = self.mtk.port.rdword
        self.rword = self.mtk.port.rword
        self.sectorsize = self.daconfig.pagesize
        self.totalsectors = self.daconfig.storage.flashsize
        self.partition = Partition(self.mtk, self.readflash, self.read_pmt, loglevel)
        self.pathconfig = PathConfig()
        self.generatekeys = self.mtk.config.generatekeys
        if self.generatekeys:
            self.mtk.daloader.patch = True
        self.mtk.daloader.lft = LegacyExt(self.mtk, self, loglevel)

    def boot_to(self, addr, data, display=True, timeout=0.5):
        pass

    def get_fat_info(self, addr: int, dwords: int):
        if self.usbwrite(self.Cmd.GET_FAT_INFO_CMD):  # 0xF0
            self.usbwrite(pack(">I", addr))
            self.usbwrite(pack(">I", dwords))
            res = [unpack(">I", self.usbread(4))[0] for _ in range(dwords)]
            ack = self.usbread(1)
            if ack == self.Rsp.ACK:
                return res

    def read_reg32(self, addr: int):
        if self.usbwrite(self.Cmd.READ_REG32_CMD):  # 0x7A
            self.usbwrite(pack(">I", addr))
            value = unpack(">I", self.usbread(4))[0]
            ack = self.usbread(1)
            if ack == self.Rsp.ACK:
                return value
        return None

    def write_reg32(self, addr: int, data: int):
        self.usbwrite(self.Cmd.WRITE_REG32_CMD)  # 0x7B
        self.usbwrite(pack(">I", addr))
        self.usbwrite(pack(">I", data))
        ack = self.usbread(1)
        if ack == self.Rsp.ACK:
            return True
        return False

    def read_pmt(self) -> tuple:  # A5
        class GptEntries:
            partentries = []

            def __init__(self, sectorsize, totalsectors):
                self.sectorsize = sectorsize
                self.totalsectors = totalsectors

            def print(self):
                print("\nGPT Table:\n-------------")
                for partition in self.partentries:
                    print("{:20} Offset 0x{:016x}, Length 0x{:016x}, Flags 0x{:08x}, UUID {}, Type {}".format(
                        partition.name + ":", partition.sector * self.sectorsize, partition.sectors * self.sectorsize,
                        partition.flags, partition.unique, partition.type))
                print("\nTotal disk size:0x{:016x}, sectors:0x{:016x}".format(self.totalsectors * self.sectorsize,
                                                                              self.totalsectors))

        gpt = GptEntries(self.sectorsize, self.totalsectors)

        class PartitionLegacy:
            type = 0
            unique = b""
            sector = 0
            sectors = 0
            flags = 0
            name = ""

        if self.usbwrite(self.Cmd.SDMMC_READ_PMT_CMD):
            ack = unpack(">B", self.usbread(1))[0]
            if ack == 0x5a:
                datalength = unpack(">I", self.usbread(4))[0]
                if self.usbwrite(self.Rsp.ACK):
                    partdata = self.usbread(datalength)
                    if self.usbwrite(self.Rsp.ACK):
                        if partdata[0x48] == 0xFF:
                            for pos in range(0, datalength, 0x60):
                                partname = partdata[pos:pos + 0x40].rstrip(b"\x00").decode('utf-8')
                                size = unpack("<Q", partdata[pos + 0x40:pos + 0x48])[0]
                                mask_flags = unpack("<Q", partdata[pos + 0x48:pos + 0x50])[0]
                                offset = unpack("<Q", partdata[pos + 0x50:pos + 0x58])[0]
                                p = PartitionLegacy()
                                p.name = partname
                                p.type = 1
                                p.sector = offset // self.daconfig.pagesize
                                p.sectors = size // self.daconfig.pagesize
                                p.flags = mask_flags
                                p.unique = b""
                                gpt.partentries.append(p)
                        else:
                            mask_flags = unpack("<Q", partdata[0x48:0x4C])[0]
                            if 0xA > mask_flags > 0:
                                # 64Bit
                                for pos in range(0, datalength, 0x58):
                                    partname = partdata[pos:pos + 0x40].rstrip(b"\x00").decode('utf-8')
                                    size = unpack("<Q", partdata[pos + 0x40:pos + 0x48])[0]
                                    offset = unpack("<Q", partdata[pos + 0x48:pos + 0x50])[0]
                                    mask_flags = unpack("<Q", partdata[pos + 0x50:pos + 0x58])[0]
                                    p = PartitionLegacy()
                                    p.name = partname
                                    p.type = 1
                                    p.sector = offset // self.daconfig.pagesize
                                    p.sectors = size // self.daconfig.pagesize
                                    p.flags = mask_flags
                                    p.unique = b""
                                    gpt.partentries.append(p)
                            else:
                                # 32Bit
                                for pos in range(0, datalength, 0x4C):
                                    partname = partdata[pos:pos + 0x40]
                                    size = unpack("<Q", partdata[pos + 0x40:pos + 0x44])[0]
                                    offset = unpack("<Q", partdata[pos + 0x44:pos + 0x48])[0]
                                    mask_flags = unpack("<Q", partdata[pos + 0x48:pos + 0x4C])[0]
                                    p = PartitionLegacy()
                                    p.name = partname
                                    p.type = 1
                                    p.sector = offset // self.daconfig.pagesize
                                    p.sectors = size // self.daconfig.pagesize
                                    p.flags = mask_flags
                                    p.unique = b""
                                    gpt.partentries.append(p)
                        return partdata, gpt
        return b"", []

    def get_part_info(self):
        res = self.mtk.port.mtk_cmd(self.Cmd.SDMMC_READ_PMT_CMD, 1 + 4)  # 0xA5
        value, length = unpack(">BI", res)
        self.usbwrite(self.Rsp.ACK)
        data = self.usbread(length)
        self.usbwrite(self.Rsp.ACK)
        return data

    def sdmmc_switch_partition(self, partition):
        if self.usbwrite(self.Cmd.SDMMC_SWITCH_PART_CMD):
            ack = self.usbread(1)
            if ack == self.Rsp.ACK:
                self.usbwrite(pack(">B", partition))
                res = self.usbread(1)
                return not res < 0
        return False

    def check_security(self):
        cmd = self.Cmd.CHK_PC_SEC_INFO_CMD + pack(">I", 0)  # E0
        ack = self.mtk.port.mtk_cmd(cmd, 1)
        if ack == self.Rsp.ACK:
            return True
        return False

    def sec_usb_recheck(self):  # If Preloader is needed
        # toDo / sha1 hash
        sec_info_len = 0
        cmd = self.Cmd.SECURE_USB_RECHECK_CMD + pack(">I", sec_info_len)  # B4
        status = unpack(">I", self.mtk.port.mtk_cmd(cmd, 1))[0]
        if status == 0x1799:
            self.info("S-USBDL disabled")
            return True
        elif status == 0x179A:
            self.info("S-USBDL enabled")
        buffer1 = bytearray()
        buffer2 = bytearray()
        for i in range(0x100):
            buffer1.append(self.rbyte(1))
        for i in range(0x5):
            buffer2.append(self.rbyte(1))
        return True

    def set_stage2_config(self, hwcode):
        # m_nor_chip_select[0]="CS_0"(0x00), m_nor_chip_select[1]="CS_WITH_DECODER"(0x08)
        self.config.set_da_config(self.daconfig)
        self.usbwrite(pack("B", self.mtk.config.bromver))
        self.usbwrite(pack("B", self.mtk.config.blver))
        m_nor_chip = 0x08
        self.usbwrite(pack(">H", m_nor_chip))
        m_nor_chip_select = 0x00
        self.usbwrite(pack("B", m_nor_chip_select))
        m_nand_acccon = 0x7007FFFF
        self.usbwrite(pack(">I", m_nand_acccon))
        self.config.bmtsettings(self.config.hwcode)
        self.usbwrite(pack("B", self.config.bmtflag))
        self.usbwrite(pack(">I", self.config.bmtpartsize))
        # unsigned char force_charge=0x02; //Setting in tool: 0x02=Auto, 0x01=On
        force_charge = 0x01
        self.usbwrite(pack("B", force_charge))
        resetkeys = 0x01  # default
        if hwcode == 0x6583:
            resetkeys = 0
        self.usbwrite(pack("B", resetkeys))
        # EXT_CLOCK: ext_clock(0x02)="EXT_26M".
        extclock = 0x02
        self.usbwrite(pack("B", extclock))
        msdc_boot_ch = 0
        self.usbwrite(pack("B", msdc_boot_ch))
        toread = 4
        if hwcode == 0x6592:
            is_gpt_solution = 0
            self.usbwrite(pack(">I", is_gpt_solution))
        elif hwcode == 0x6580 or hwcode == 0x8163 or hwcode == 0x8127:
            if hwcode == 0x8127:
                is_gpt_solution = 0
                self.usbwrite(pack(">I", is_gpt_solution))
            slc_percent = 0x1
            self.usbwrite(pack(">I", slc_percent))
            unk = b"\x46\x46\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x00\x00\x00"
            self.usbwrite(unk)
        elif hwcode in [0x6583, 0x6589]:
            forcedram = 0
            if hwcode == 0x6583:
                forcedram = 0
            elif hwcode == 0x6589:
                forcedram = 1
            self.usbwrite(pack(">I", forcedram))
        elif hwcode == 0x8127:
            skipdl = 0
            self.usbwrite(pack(">I", skipdl))
        elif hwcode == 0x6582:
            newcombo = 1
            self.usbwrite(pack(">I", newcombo))
        time.sleep(0.350)
        buffer = self.usbread(toread)
        if len(buffer) < 4:
            self.error("Didn't receive Stage2 dram info, please check usb cable/hub and retry.")
            return False
        errorcode = int.from_bytes(buffer, 'big')
        if errorcode == 0x0:
            if hwcode == 0x6592:
                tmp1 = self.usbread(4)
                tmp2 = self.usbread(4)
                tmp3 = self.usbread(4)
                tmp4 = self.usbread(4)
                tmp5 = self.usbread(4)
                _ = tmp1, tmp2, tmp3, tmp4, tmp5
            return True
        if errorcode != 0xBC3:
            self.error(self.eh.status(errorcode))
            return False
        if toread == 4 and errorcode == 0xBC3:
            buffer += self.usbread(4)
            pdram = [b"", b""]
            draminfo = self.usbread(16)
            pdram[0] = draminfo[:9]
            draminfo = draminfo[:4][::-1] + draminfo[4:8][::-1] + draminfo[8:12][::-1] + draminfo[12:16][::-1]
            pdram[1] = draminfo[:9]
            self.info(f"DRAM config needed for : {hexlify(draminfo).decode('utf-8')}")
            if self.daconfig.emi is None:
                found = False
                for root, dirs, files in os.walk(os.path.join(self.pathconfig.get_loader_path(), 'Preloader')):
                    for file in files:
                        with open(os.path.join(root, file), "rb") as rf:
                            data = rf.read()
                            if pdram[0] in data or pdram[1] in data:
                                preloader = os.path.join(root, file)
                                print(f"Detected preloader: {preloader}")
                                self.daconfig.extract_emi(preloader)
                                found = True
                                break
                    if found:
                        break
            returnval = self.usbread(4)
            if len(returnval) != 4:
                self.error("Didn't get a response on dram read")
                return False
            errorval = int.from_bytes(returnval, 'big')
            if errorval != 0xBC4:
                self.error(self.eh.status(errorval))
                return False
            else:
                nand_id_count = unpack(">H", self.usbread(2))[0]
                self.info("Reading dram nand info ...")
                nand_ids = []
                for i in range(0, nand_id_count):
                    nand_ids.append(unpack(">H", self.usbread(2))[0])
                if self.daconfig.emi is not None:  # toDo
                    self.usbwrite(self.Cmd.ENABLE_DRAM)  # E8
                    if self.daconfig.emiver == 0:
                        self.usbwrite(pack(">I", 0xFFFFFFFF))
                    else:
                        self.usbwrite(pack(">I", self.daconfig.emiver))
                    ret = self.usbread(1)
                    if ret == self.Rsp.NACK:
                        self.error("EMI Config not accepted :( Make sure to provide a valid preloader.")
                        sys.exit()
                    if ret == self.Rsp.ACK:
                        self.info(f"Sending dram info ... EMI-Version {hex(self.daconfig.emiver)}")
                        if self.daconfig.emiver in [0xF, 0x10, 0x11, 0x14, 0x15]:
                            dramlength = unpack(">I", self.usbread(0x4))[0]  # 0x000000BC
                            self.info(f"RAM-Length: {hex(dramlength)}")
                            self.usbwrite(self.Rsp.ACK)
                            lendram = len(self.daconfig.emi)
                            if hwcode != 0x8127:
                                self.usbwrite(pack(">I", lendram))
                        elif self.daconfig.emiver in [0x0A, 0x0B]:
                            info = self.usbread(0x10)  # 0x000000BC
                            self.info(f"RAM-Info: {hexlify(info).decode('utf-8')}")
                            dramlength = unpack(">I", self.usbread(0x4))[0]
                            self.usbwrite(self.Rsp.ACK)
                        elif self.daconfig.emiver in [0x0C, 0x0D]:
                            dramlength = unpack(">I", self.usbread(0x4))[0]
                            self.info(f"RAM-Length: {hex(dramlength)}")
                            self.usbwrite(self.Rsp.ACK)
                            self.daconfig.emi = self.daconfig.emi[:dramlength]
                            self.daconfig.emi = pack(">I", 0x100) + self.daconfig.emi[0x4:dramlength]
                        elif self.daconfig.emiver in [0x00]:
                            dramlength = unpack(">I", self.usbread(0x4))[0]  # 0x000000B0
                            self.info(f"RAM-Length: {hex(dramlength)}")
                            self.usbwrite(self.Rsp.ACK)
                            lendram = len(self.daconfig.emi)
                            self.daconfig.emi = self.daconfig.emi[:dramlength]
                            self.usbwrite(pack(">I", dramlength))
                        else:
                            self.warning("Unknown emi version: %d" % self.daconfig.emiver)
                        self.usbwrite(self.daconfig.emi)
                        checksum = unpack(">H", self.usbread(2))[0]  # 0x440C
                        self.info("Checksum: %04X" % checksum)
                        self.usbwrite(self.Rsp.ACK)
                        self.usbwrite(pack(">I", 0x80000001))  # Send DRAM config
                        m_ext_ram_ret = unpack(">I", self.usbread(4))[0]  # 0x00000000 S_DONE
                        self.info(f"M_EXT_RAM_RET : {m_ext_ram_ret}")
                        if m_ext_ram_ret != 0:
                            self.error("Preloader error: 0x%X => %s" % (m_ext_ram_ret, self.eh.status(m_ext_ram_ret)))
                            self.mtk.port.close(reset=False)
                            return False
                        m_ext_ram_type = self.usbread(1)[0]  # 0x02 HW_RAM_DRAM
                        self.info(f"M_EXT_RAM_TYPE : {hex(m_ext_ram_type)}")
                        m_ext_ram_chip_select = self.usbread(1)[0]  # 0x00 CS_0
                        self.info(f"M_EXT_RAM_CHIP_SELECT : {hex(m_ext_ram_chip_select)}")
                        m_ext_ram_size = unpack(">Q", self.usbread(8))[0]  # 0x80000000
                        self.info(f"M_EXT_RAM_SIZE : {hex(m_ext_ram_size)}")
                        if self.daconfig.emiver in [0x0D]:
                            self.usbread(4)  # 00000003
                            # Raw_0
                            self.usbread(4)  # 1C004004
                            # Raw_1
                            self.usbread(4)  # aa080033
                            # CJ_0
                            self.usbread(4)  # 00000013
                            # CJ_1
                            self.usbread(4)  # 00000010
                else:
                    self.error("Preloader needed due to dram config.")
                    self.mtk.port.close(reset=True)
                    return False
        return True

    def set_speed_iot(self):
        self.usbwrite(b"\x59")
        # ack
        self.usbread(1)
        self.usbwrite(b"\xF0")
        # ret
        self.usbread(28)
        self.usbwrite(self.Cmd.SPEED_CMD + b"\x01\x01")
        ack = self.usbread(1)
        if ack != b"\x5A":
            return False
        self.usbwrite(b"\x5A")
        # try:
        #    self.mtk.port.cdc.setcontrollinestate(RTS=True,DTR=True)
        # except:
        #    pass
        try:
            self.mtk.port.cdc.set_line_coding(baudrate=921600, parity=None, databits=8, stopbits=1)
        except Exception as err:
            print(err)
            pass

        time.sleep(0.1)
        for i in range(10):
            self.usbwrite(b"\xC0")
            ack = self.usbread(1)
            if ack == b"\xC0":
                break
            time.sleep(0.02)
        self.usbwrite(b"\x5A")
        ack = self.usbread(1)
        if ack == b"\x5A":
            for i in range(256):
                loop_val = pack(">B", i)
                self.usbwrite(loop_val)
                if self.usbread(1) != loop_val:
                    return False
        else:
            return False
        return True

    def set_speed(self):
        self.usbwrite(self.Cmd.SPEED_CMD)
        self.usbwrite(int.to_bytes(921600, 4, 'big'))
        ack = self.usbread(1)
        if ack != b"\x5A":
            return False
        time.sleep(0.2)
        for i in range(10):
            self.usbwrite(b"\xC0")
            ack = self.usbread(1)
            if ack == b"\xC0":
                break
            time.sleep(0.02)
        self.usbwrite(b"\x5A")
        ack = self.usbread(1)
        if ack == b"\x5A":
            for i in range(256):
                loop_val = pack(">B", i)
                self.usbwrite(loop_val)
                if self.usbread(1) != loop_val:
                    return False
        else:
            return False
        return True

    def read_flash_info_iot_2523(self):
        v = self.usbread(0x42 - 0x4)
        self.daconfig.legacy_storage.nor = NorInfoIoT2523(v)
        self.daconfig.storage.flashtype = "nor"

    def mt2523_handshake(self):
        self.usbwrite(b"\x3F")
        v = self.usbread(1)  # 0xC
        self.usbwrite(b"\xF3")
        v = self.usbread(1)  # 0x3F
        self.usbwrite(b"\xC0")
        v = self.usbread(1)  # 0xF3
        self.usbwrite(b"\x0C")
        v = self.usbread(1)  # 0x5A
        _ = v

    def read_flash_info_iot(self):
        self.daconfig.legacy_storage.nor = NorInfoIoT(self.usbread(0x36))
        self.daconfig.legacy_storage.nand = NandInfoIoT(self.usbread(0x23))
        self.daconfig.legacy_storage.emmc = EmmcInfoIoT(self.config, self.usbread(0x2C))
        self.daconfig.legacy_storage.flashconfig = ConfigInfoIoT(self.usbread(0x1E))
        if self.config.hwcode & 0xFF00 == 0x6200:
            data = self.usbread(0x18)
            _ = data
        # ack 0x5A
        self.usbread(1)
        # ack 0x5A
        self.usbread(1)
        # m_download_status
        int.from_bytes(self.usbread(4), 'big')
        # m_boot_style
        int.from_bytes(self.usbread(4), 'big')
        soc_ok = self.usbread(1)
        if soc_ok == b"\xC1":
            # Security pre-process
            self.usbwrite(b"\x59")
            ack2 = self.usbread(1)
            if ack2 == b"\xA5":
                # Get Fat Info:
                self.usbwrite(b"\xF0")
                # status
                self.usbread(4)
                nor_addr = int.from_bytes(self.usbread(4), 'big')
                nor_len = int.from_bytes(self.usbread(4), 'big')
                nand_addr = int.from_bytes(self.usbread(4), 'big')
                nand_len = int.from_bytes(self.usbread(4), 'big')
                emmc_addr = int.from_bytes(self.usbread(4), 'big')
                emmc_len = int.from_bytes(self.usbread(4), 'big')
                print(f"Nor addr/len: {hex(nor_addr)}/{hex(nor_len)}")
                print(f"Nand addr/len: {hex(nand_addr)}/{hex(nand_len)}")
                print(f"EMMC addr/len: {hex(emmc_addr)}/{hex(emmc_len)}")
                sys.stdout.flush()
                return True
        return False

    def read_flash_info(self):
        self.daconfig.legacy_storage.nor = Legacy_NorInfo(self.usbread(0x1C))
        data = self.usbread(0x11)
        self.daconfig.legacy_storage.nand = Legacy_NandInfo64(data)
        nandcount = self.daconfig.legacy_storage.nand.m_nand_flash_id_count
        if nandcount == 0:
            self.daconfig.legacy_storage.nand = Legacy_NandInfo32(data)
            nandcount = self.daconfig.legacy_storage.nand.m_nand_flash_id_count
            nc = data[-4:] + self.usbread(nandcount * 2 - 4)
        else:
            nc = self.usbread(nandcount * 2)
        m_nand_dev_code = unpack(">" + str(nandcount) + "H", nc)
        self.daconfig.legacy_storage.nand.m_nand_flash_dev_code = m_nand_dev_code
        self.daconfig.legacy_storage.nand.info2 = Legacy_NandInfo2(self.usbread(9))
        self.daconfig.legacy_storage.emmc = Legacy_EmmcInfo(self.config, self.usbread(0x5C))
        self.daconfig.legacy_storage.sdc = Legacy_SdcInfo(self.config, self.usbread(0x1C))
        self.daconfig.legacy_storage.flashconfig = Legacy_ConfigInfo(self.usbread(0x26))
        if self.config.hwcode == 0x8163:
            status = self.usbread(4)
            _ = status
        pi = PassInfo(self.usbread(0xA))
        if pi.ack == 0x5A:
            return True
        elif pi.m_download_status & 0xFF == 0x5A:
            self.usbread(1)
            return True
        return False

    def upload_da1(self):
        if not self.config.iot:
            if self.daconfig.da_loader is None:
                self.error("No valid da loader found... aborting.")
                return False
            loader = self.daconfig.loader
            self.info(f"Uploading legacy stage 1 from {os.path.basename(loader)}")
            with open(loader, 'rb') as bootldr:
                # stage 1
                da1offset = self.daconfig.da_loader.region[1].m_buf
                da1size = self.daconfig.da_loader.region[1].m_len
                da1address = self.daconfig.da_loader.region[1].m_start_addr
                da1sig_len = self.daconfig.da_loader.region[1].m_sig_len
                bootldr.seek(da1offset)
                da1 = bootldr.read(da1size)
                # ------------------------------------------------
                da2offset = self.daconfig.da_loader.region[2].m_buf
                da2sig_len = self.daconfig.da_loader.region[2].m_sig_len
                bootldr.seek(da2offset)
                da2 = bootldr.read(self.daconfig.da_loader.region[2].m_len)
                if self.mtk.config.is_brom or not self.mtk.config.target_config["sbc"] and not self.mtk.config.stock:
                    hashaddr, hashmode, hashlen = self.mtk.daloader.compute_hash_pos(da1, da2, da1sig_len, da2sig_len,
                                                                                     self.daconfig.da_loader.v6)
                    if hashaddr is not None:
                        da2patched = self.mtk.daloader.lft.patch_da2(da2)
                        if da2patched != da2:
                            tda1 = self.mtk.daloader.fix_hash(da1, da2patched, hashaddr, hashmode, hashlen)
                            if tda1 != da1:
                                self.mtk.daloader.patch = True
                                self.daconfig.da2 = da2patched[:hashlen] + da2[hashlen:hashlen + da2sig_len]
                                da1 = tda1
                            else:
                                self.mtk.daloader.patch = False
                                self.daconfig.da2 = da2[:hashlen] + da2[hashlen:hashlen + da2sig_len]
                        else:
                            self.daconfig.da2 = da2[:hashlen] + da2[hashlen:hashlen + da2sig_len]
                    else:
                        self.daconfig.da2 = da2
                else:
                    self.daconfig.da2 = da2
                if self.mtk.preloader.send_da(da1address, da1size, da1sig_len, da1):
                    if self.mtk.preloader.jump_da(da1address):
                        sync = self.usbread(1)
                        if sync != b"\xC0":
                            self.error("Error on DA sync")
                            return False
                        else:
                            self.info("Got loader sync !")
                    else:
                        return False
                else:
                    return False

            self.info("Reading nand info")
            nandinfo = unpack(">I", self.usbread(4))[0]  # 0xBC4
            self.debug(f"NAND_INFO: {hex(nandinfo)}")
            ids = unpack(">H", self.usbread(2))[0]
            nandids = []
            for i in range(0, ids):
                tmp = unpack(">H", self.usbread(2))[0]
                nandids.append(tmp)
            self.info("Reading emmc info")
            emmcinfolegacy = unpack(">I", self.usbread(4))[0]
            self.debug(f"EMMC_INFO: {hex(emmcinfolegacy)}")
            emmcids = []
            for i in range(0, 4):
                tmp = unpack(">I", self.usbread(4))[0]
                emmcids.append(tmp)

            if len(nandids) > 0 and nandids[0] != 0:
                self.daconfig.storage.flashtype = "nand"
            elif len(emmcids) > 0 and emmcids[0] != 0:
                self.daconfig.storage.flashtype = "emmc"
            else:
                self.daconfig.storage.flashtype = "nor"

            self.usbwrite(self.Rsp.ACK)
            ackval = self.usbread(1)
            ackval += self.usbread(1)
            ackval += self.usbread(1)
            self.info(f"ACK: {hexlify(ackval).decode('utf-8')}")
            self.info("Setting stage 2 config ...")
            if self.set_stage2_config(self.config.hwcode):
                self.info("Uploading stage 2...")
                # stage 2
                if self.brom_send(self.daconfig, self.daconfig.da2, 2):
                    if self.read_flash_info():
                        if self.daconfig.storage.flashtype == "nand":
                            self.daconfig.storage.flashsize = self.daconfig.legacy_storage.nand.m_nand_flash_size
                        elif self.daconfig.storage.flashtype == "emmc" or self.daconfig.legacy_storage.emmc.m_emmc_ua_size != 0:
                            self.daconfig.storage.flashsize = self.daconfig.legacy_storage.emmc.m_emmc_ua_size
                            self.daconfig.storage.flashtype = "emmc"
                            if self.daconfig.storage.flashsize == 0:
                                self.daconfig.storage.flashsize = self.daconfig.legacy_storage.sdc.m_sdmmc_ua_size
                        elif self.daconfig.storage.flashtype == "nor":
                            self.daconfig.storage.flashsize = self.daconfig.legacy_storage.nor.m_nor_flash_size
                        self.info("Connected to stage2")
                        speed = self.check_usb_cmd()
                        if speed[0] == 0 and self.daconfig.reconnect:  # 1 = USB High Speed, 2= USB Ultra high speed
                            self.info("Reconnecting to stage2 with higher speed")
                            self.config.set_gui_status(self.config.tr("Reconnecting to stage2 with higher speed"))
                            self.set_usb_cmd()
                            self.mtk.port.close(reset=True)
                            time.sleep(1)
                            while not self.mtk.port.cdc.connect():
                                self.info("Waiting for reconnection")
                                time.sleep(0.5)
                            if self.check_usb_cmd():
                                self.info("Connected to stage2 with higher speed")
                                self.config.set_gui_status(self.config.tr("Connected to stage2 with higher speed"))
                                self.mtk.port.cdc.set_fast_mode(True)
                            else:
                                return False
                        return True
            return False
        else:  # MT6261 / MT2523
            if self.daconfig.da_loader is None:
                self.error("No valid da loader found... aborting.")
                return False
            loader = self.daconfig.loader
            with open(loader, 'rb') as bootldr:
                if self.config.hwcode in [0x2625, 0x2523, 0x7682, 0x7686, 0x5932]:
                    envoffset = self.daconfig.da_loader.region[0].m_buf
                    envsize = self.daconfig.da_loader.region[0].m_len
                    envaddress = self.daconfig.da_loader.region[0].m_start_addr
                    bootldr.seek(envoffset)
                    envdata = bootldr.read(envsize)
                    if not self.mtk.preloader.send_env_prepare(envaddress, envsize, envdata):
                        return False
                    self.info(f"Uploading legacy stage 1 from {os.path.basename(loader)}")
                    stage1 = self.daconfig.da_loader.entry_region_index
                    # stage 1
                    da1offset = self.daconfig.da_loader.region[stage1].m_buf
                    da1size = self.daconfig.da_loader.region[stage1].m_len
                    da1address = self.daconfig.da_loader.region[stage1].m_start_addr
                    da1sig_len = self.daconfig.da_loader.region[stage1].m_sig_len
                    bootldr.seek(da1offset)
                    da1 = bootldr.read(da1size)
                    if not self.mtk.preloader.send_da(da1address, da1size, da1sig_len, da1):
                        return False
                    if self.mtk.preloader.jump_da(da1address):
                        sync = self.usbread(1)
                        if sync != b"\xC0":
                            self.error("Error on DA sync")
                            return False
                        else:
                            self.info("Got loader sync !")
                    self.mt2523_handshake()
                    self.usbwrite(b"\x00")
                    v = self.usbread(1)  # 0x69 CONF
                    # DA logging channel setting
                    self.usbwrite(b"\x01")
                    v = self.usbread(1)  # 0x69 CONF
                    _ = v
                    self.usbwrite(b"Z")  # ACK
                    chipid = b"".join([int.to_bytes(v, 2, 'big') for v in self.rword(3)])

                    chipdboffset = self.daconfig.da_loader.region[4].m_buf
                    chipdbsize = self.daconfig.da_loader.region[4].m_len
                    bootldr.seek(chipdboffset)
                    chipdb = bootldr.read(chipdbsize)
                    env5size = self.daconfig.da_loader.region[5].m_len  # 0x24
                    for offs in range(0, len(chipdb), env5size):
                        data = chipdb[offs:offs + env5size]
                        if chipid == data[0x11:0x11 + len(chipid)]:
                            self.usbwrite(int.to_bytes(env5size, 1, byteorder='little'))
                            ack = self.usbread(1)
                            if ack == b"Z":
                                self.usbwrite(data)
                                status = self.rdword()
                                if status == 0:
                                    self.read_flash_info_iot_2523()
                                    ack = self.usbread(1)
                                    if ack == b"Z":
                                        self.usbwrite(b"Z")
                                        self.cmd_nwdm_info()
                                else:
                                    print("Bad chip setup")
                                    sys.stdout.flush()
                                    return False
                                return True
                    return False
                else:
                    self.info(f"Uploading legacy stage 1 from {os.path.basename(loader)}")
                    stage1 = self.daconfig.da_loader.entry_region_index
                    # stage 1
                    da1offset = self.daconfig.da_loader.region[stage1].m_buf
                    da1size = self.daconfig.da_loader.region[stage1].m_len
                    da1address = self.daconfig.da_loader.region[stage1].m_start_addr
                    da1sig_len = self.daconfig.da_loader.region[stage1].m_sig_len
                    bootldr.seek(da1offset)
                    da1 = bootldr.read(da1size)
                    # ------------------------------------------------
                    da2address = self.daconfig.da_loader.region[stage1 + 1].m_start_addr
                    da2offset = self.daconfig.da_loader.region[stage1 + 1].m_buf
                    da2size = self.daconfig.da_loader.region[stage1 + 1].m_len
                    da2sig_len = self.daconfig.da_loader.region[stage1 + 1].m_sig_len
                    bootldr.seek(da2offset)
                    da2 = bootldr.read(da2size)
                    # ------------------------------------------------
                    da3offset = self.daconfig.da_loader.region[stage1 + 2].m_buf
                    da3size = self.daconfig.da_loader.region[stage1 + 2].m_len
                    bootldr.seek(da3offset)
                    da3 = bootldr.read(da3size)
                    if self.mtk.preloader.send_da(da1address, da1size, da1sig_len, da1):
                        if not self.mtk.preloader.send_da(da2address, da2size, da2sig_len, da2):
                            self.error("DA2 not accepted :(")
                            return False
                    else:
                        self.error("DA1 not accepted :(")
                        return False
                if self.mtk.preloader.jump_da(da1address):
                    sync = self.usbread(1)
                    if sync != b"\xC0":
                        self.error("Error on DA sync")
                        return False
                    else:
                        self.info("Got loader sync !")
                else:
                    return False
            # da_maj
            self.usbread(1)
            # da_min
            self.usbread(1)
            # baseband_chip
            self.usbread(1)
            # Disable Download Without Battery
            self.usbwrite(b"\xA5")
            # Brom Version
            self.usbwrite(b"\x05")
            # BLOADER Version
            self.usbwrite(b"\xFE")
            # NOR_CFG: m_nor_chip_select, CS0 (0), CS_WITH_DECODER (08)
            self.usbwrite(b"\x00\x08")
            # m_nand_chip_select CS0
            self.usbwrite(b"\x00")
            # m_nand_acccon
            self.usbwrite(int.to_bytes(0x7007FFFF, 4, 'big'))
            # ext_clock(0x02)="EXT_26M"
            self.usbwrite(b"\x02")

            self.usbwrite(b"\x00\x00\x01\x03")
            ack = self.usbread(1)
            if ack != b"Z":
                self.error("No ack on setup.")
                return False
            bytestosend = len(da3)
            i = 0
            tmp = b""
            while bytestosend > 0:
                data = da3[i:i + 0x24]
                self.usbwrite(data)
                i += 0x24
                bytestosend -= 0x24
                if bytestosend <= 0:
                    break
                tmp = self.usbread(1)
                if tmp != b"i":
                    break
                elif tmp not in [b"i", b"\x5A"]:
                    self.error("No ack on dram.")
                    return False
            if tmp != b"\x5A":
                ack1 = self.usbread(1)
                if ack1 != b"\x5A":
                    self.error("No ack after dram.")
                    return False
            ack2 = self.usbread(1)
            if ack2 != b"\xA5":
                self.error("No ack after dram 2.")
                return False
            if self.config.hwcode == 0x6261:
                ack = b""
                while ack == b"":
                    ack = self.usbread(1)  # 0x69
                    if ack == b"":
                        time.sleep(0.005)
            # Begin address of BMT Pool 0x00000000
            self.usbwrite(b"\x00\x00\x00\x00")
            # info
            if self.config.hwcode == 0x6261:
                while True:
                    val = int.from_bytes(self.usbread(4), 'little')  # 0xa20c0000 - 0xC0000a5
                    if val != 0:
                        break
                    time.sleep(0.01)
            time.sleep(0.5)
            if self.read_flash_info_iot():
                if self.daconfig.legacy_storage.nand.m_nand_flash_size != 0:
                    self.daconfig.storage.flashtype = "nand"
                elif self.daconfig.legacy_storage.emmc.m_emmc_ua_size != 0:
                    self.daconfig.storage.flashtype = "emmc"
                else:
                    self.daconfig.storage.flashtype = "nor"

                if self.daconfig.storage.flashtype == "nand":
                    self.daconfig.storage.flashsize = self.daconfig.legacy_storage.nand.m_nand_flash_size
                elif self.daconfig.storage.flashtype == "emmc" or self.daconfig.legacy_storage.emmc.m_emmc_ua_size != 0:
                    self.daconfig.storage.flashsize = self.daconfig.legacy_storage.emmc.m_emmc_ua_size
                    self.daconfig.storage.flashtype = "emmc"
                    if self.daconfig.storage.flashsize == 0:
                        self.daconfig.storage.flashsize = self.daconfig.legacy_storage.sdc.m_sdmmc_ua_size
                elif self.daconfig.storage.flashtype == "nor":
                    self.daconfig.storage.flashsize = self.daconfig.legacy_storage.nor.m_nor_flash_size
                self.set_speed_iot()
                return True
            self.error("Init timeout.")
            return False

    def cmd_nwdm_info(self):
        if self.config.hwcode in [0x2625]:
            self.usbwrite(self.Cmd.DA_NWDM_INFO)
            for i in range(256):
                ack = self.usbread(1)
                if ack == b"\x5A":
                    self.usbwrite(b"")
                    self.daconfig.legacy_storage.nor.nvdm_addr = int.from_bytes(
                        self.usbread(4), 'big')
                    self.usbwrite(b"")
                    self.daconfig.legacy_storage.nor.nvdm_length = int.from_bytes(
                        self.usbread(4), 'big')
                    self.info(
                        f"NVDM addr: {hex(self.daconfig.legacy_storage.nor.nvdm_addr)} length: {hex(self.daconfig.legacy_storage.nor.nvdm_length)}")
                    break

    def upload_da(self):
        self.info("Uploading legacy da...")
        if self.upload_da1():
            self.info(self.daconfig.legacy_storage.flashconfig)
            if self.daconfig.storage.flashtype == "emmc":
                self.info(self.daconfig.legacy_storage.emmc)
            elif self.daconfig.storage.flashtype == "nand":
                self.info(self.daconfig.legacy_storage.nand)
            elif self.daconfig.storage.flashtype == "nor":
                self.info(self.daconfig.legacy_storage.nor)
            elif self.daconfig.storage.flashtype == "sdc":
                self.info(self.daconfig.legacy_storage.sdc)
            return True
        return False

    class ShutDownModes:
        NORMAL = 0
        HOME_SCREEN = 1
        FASTBOOT = 2

    def shutdown(self, async_mode: int = 0, dl_bit: int = 0, bootmode: ShutDownModes = ShutDownModes.NORMAL):
        self.finish(bootmode)  # DISCONNECT_USB_AND_RELEASE_POWERKEY
        self.mtk.port.close(reset=True)

    def brom_send(self, dasetup, dadata, stage, packetsize=0x1000):
        # offset = dasetup.da_loader.region[stage].m_buf
        size = dasetup.da_loader.region[stage].m_len
        address = dasetup.da_loader.region[stage].m_start_addr
        pg = progress(total=size, prefix=f"Stage {stage}:", guiprogress=self.mtk.config.guiprogress)
        self.usbwrite(pack(">I", address))
        self.usbwrite(pack(">I", size))
        self.usbwrite(pack(">I", packetsize))
        buffer = self.usbread(1)
        if buffer == self.Rsp.ACK:
            for pos in range(0, size, packetsize):
                self.usbwrite(dadata[pos:pos + packetsize])
                buffer = self.usbread(1)
                if buffer != self.Rsp.ACK:
                    self.error(
                        f"Error on sending brom stage {stage} addr {hex(address + pos)}: " +
                        f"{hexlify(buffer).decode('utf-8')}")
                    self.config.set_gui_status(self.config.tr("Error on sending brom stage"))
                    break
                else:
                    pg.update(len(dadata[pos:pos + packetsize]))
            pg.done()
            time.sleep(0.5)
            self.usbwrite(self.Rsp.ACK)
            self.info("Waiting for response ...")
            buffer = self.usbread(1)
            if buffer == self.Rsp.ACK:
                self.info(f"Successfully uploaded stage {stage}")
                self.config.set_gui_status(self.config.tr(f"Successfully uploaded stage {stage}"))
                return True
        else:
            self.error(f"Error on sending brom stage {stage} : {hexlify(buffer).decode('utf-8')}")
            self.config.set_gui_status(self.config.tr("Error on sending brom stage"))
        return False

    def check_usb_cmd(self):
        if self.usbwrite(self.Cmd.USB_CHECK_STATUS):  # 72
            res = self.usbread(1)
            if res == self.Rsp.ACK:
                speed = self.usbread(1)
                if speed[0] > 0:
                    self.mtk.port.cdc.set_fast_mode(True)
                return speed
        return None

    def set_usb_cmd(self):
        if self.usbwrite(self.Cmd.USB_SETUP_PORT):  # 72
            if self.usbwrite(b"\x01"):  # USB_HIGH_SPEED
                res = self.usbread(1)
                if len(res) > 0:
                    if res[0] is self.Rsp.ACK[0]:
                        return True
        return False

    def sdmmc_switch_part(self, partition=0x8):
        self.usbwrite(self.Cmd.SDMMC_SWITCH_PART_CMD)  # 60
        ack = self.usbread(1)
        if ack == self.Rsp.ACK:
            # partition = 0x8  # EMMC_Part_User = 0x8, sonst 0x0
            self.usbwrite(pack("B", partition))
            ack = self.usbread(1)
            if ack == self.Rsp.ACK:
                return True
        return False

    def finish(self, value):
        self.usbwrite(self.Cmd.FINISH_CMD)  # D9
        ack = self.usbread(1)[0]
        if ack is self.Rsp.ACK:
            self.usbwrite(pack(">I", value))
            ack = self.usbread(1)[0]
            if ack is self.Rsp.ACK:
                return True
        return False

    def sdmmc_write_data(self, addr: int, length: int, filename: str, offset=0, parttype=None, wdata=None,
                         display=True):
        length, parttype = self.daconfig.legacy_storage.partitiontype_and_size(parttype=parttype, length=length)
        if self.daconfig.storage.flashtype == "sdc":
            storage = DaStorage.MTK_DA_STORAGE_SDMMC
        elif self.daconfig.storage.flashtype == "ufs":
            storage = DaStorage.MTK_DA_STORAGE_UFS
        elif self.daconfig.storage.flashtype == "nor":
            storage = DaStorage.MTK_DA_STORAGE_NOR
        elif self.daconfig.storage.flashtype == "nand":
            storage = DaStorage.MTK_DA_STORAGE_NAND
        else:
            storage = DaStorage.MTK_DA_STORAGE_EMMC
        fh = False
        fill = 0
        if filename != '':
            fh = open(filename, "rb")
            fsize = os.stat(filename).st_size
            length = min(fsize, length)
            if length % 512 != 0:
                fill = 512 - (length % 512)
                length += fill
            fh.seek(offset)
        pg = progress(total=length, prefix="Write:", guiprogress=self.mtk.config.guiprogress)
        self.usbwrite(self.Cmd.SDMMC_WRITE_DATA_CMD)
        self.usbwrite(pack(">B", storage))
        self.usbwrite(pack(">B", parttype))
        self.usbwrite(pack(">Q", addr))
        self.usbwrite(pack(">Q", length))
        self.usbwrite(pack(">I", 0x100000))
        if self.usbread(1) != self.Rsp.ACK:
            self.error("Couldn't send sdmmc_write_data header")
            return False
        offset = 0
        while offset < length:
            self.usbwrite(self.Rsp.ACK)
            count = min(0x100000, length - offset)
            if fh:
                data = bytearray(fh.read(count))
            else:
                data = wdata[offset:offset + count]
            if len(data) < count:
                data.extend(b"\x00" * fill)
            if len(data) % 512 != 0:
                fill = 512 - (len(data) % 512)
                data += fill*b"\x00"
            self.usbwrite(data)
            chksum = sum(data) & 0xFFFF
            self.usbwrite(pack(">H", chksum))
            if self.usbread(1) != self.Rsp.CONT_CHAR:
                self.error("Data ack failed for sdmmc_write_data")
                return False
            if display:
                pg.update(len(data))
            offset += count
        if fh:
            fh.close()
        if display:
            pg.done()
        return True

    def sdmmc_write_image(self, addr, length, filename, display=True):
        if filename != "":
            pg = progress(total=length, prefix="Write:", guiprogress=self.mtk.config.guiprogress)
            with open(filename, "rb") as rf:
                if self.daconfig.storage.flashtype == "emmc":
                    self.usbwrite(self.Cmd.SDMMC_WRITE_IMAGE_CMD)  # 61
                    self.usbwrite(b"\x00")  # checksum level 0
                    self.usbwrite(b"\x08")  # EMMC_PART_USER
                    self.usbwrite(pack(">Q", addr))
                    self.usbwrite(pack(">Q", length))
                    self.usbwrite(b"\x08")  # index 8
                    self.usbwrite(b"\x03")
                    packetsize = unpack(">I", self.usbread(4))[0]
                    ack = unpack(">B", self.usbread(1))[0]
                    if ack == self.Rsp.ACK[0]:
                        self.usbwrite(self.Rsp.ACK)
                checksum = 0
                bytestowrite = length
                while bytestowrite > 0:
                    size = min(bytestowrite, packetsize)
                    for i in range(0, size, 0x400):
                        data = bytearray(rf.read(size))
                        if self.usbwrite(data):
                            bytestowrite -= size
                            if bytestowrite == 0:
                                checksum = 0
                                for val in data:
                                    checksum += val
                                checksum = checksum & 0xFFFF
                                self.usbwrite(pack(">H", checksum))
                            if self.usbread(1) == b"\x69":
                                if bytestowrite == 0:
                                    self.usbwrite(pack(">H", checksum))
                                if self.usbread(1) == self.Rsp.ACK:
                                    if display:
                                        pg.done()
                                    return True
                                else:
                                    self.usbwrite(self.Rsp.ACK)
                        if display:
                            pg.update(len(data))
                if display:
                    pg.done()
                return True
        return True

    def writeflash(self, addr: int, length: int, filename: str = "", offset=0, parttype=None, wdata=None, display=True):
        return self.sdmmc_write_data(addr=addr, length=length, filename=filename, offset=offset, parttype=parttype,
                                     wdata=wdata, display=display)

    def formatflash(self, addr, length, parttype=None, display=True):
        length, parttype = self.daconfig.legacy_storage.partitiontype_and_size(parttype=parttype, length=length)
        self.check_usb_cmd()
        if self.daconfig.storage.flashtype == "emmc":
            self.sdmmc_switch_part(parttype)
            self.usbwrite(self.Cmd.FORMAT_CMD)  # D6
            self.usbwrite(b"\x02")  # Storage-Type: EMMC
            self.usbwrite(b"\x00")  # 0x00 Nutil erase
            self.usbwrite(b"\x00")  # Validation false
            self.usbwrite(b"\x00")  # NUTL_ADDR_LOGICAL
            self.usbwrite(pack(">Q", addr))
            self.usbwrite(pack(">Q", length))
            progress = 0
            while progress != 100:
                ack = self.usbread(1)[0]
                if ack is not self.Rsp.ACK[0]:
                    self.error(f"Error on sending emmc format command, response: {hex(ack)}")
                    exit(1)
                ack = self.usbread(1)[0]
                if ack is not self.Rsp.ACK[0]:
                    self.error(f"Error on sending emmc format command, response: {hex(ack)}")
                    exit(1)
                # data
                self.usbread(4)[0]  # PROGRESS_INIT
                progress = self.usbread(1)[0]
                self.usbwrite(b"\x5A")  # Send ACK
                if progress == 0x64:
                    ack = self.usbread(1)[0]
                    if ack is not self.Rsp.ACK[0]:
                        self.error(f"Error on sending emmc format command, response: {hex(ack)}")
                        exit(1)
                    ack = self.usbread(1)[0]
                    if ack is not self.Rsp.ACK[0]:
                        self.error(f"Error on sending emmc format command, response: {hex(ack)}")
                        exit(1)
                    return True
            return False

    def readflash(self, addr: int, length: int, filename: str, parttype=None, display=True) -> (bytes, bool):
        rq = Queue()
        pg = progress(total=length, prefix="Read:", guiprogress=self.mtk.config.guiprogress)
        length, parttype = self.daconfig.legacy_storage.partitiontype_and_size(parttype=parttype, length=length)
        if not self.config.iot:
            self.check_usb_cmd()
        packetsize = 0x0
        if self.daconfig.storage.flashtype == "emmc":
            self.sdmmc_switch_part(parttype)
            packetsize = 0x100000
            self.usbwrite(self.Cmd.READ_CMD)  # D6
            self.usbwrite(b"\x0C")  # Host:Linux, 0x0B=Windows
            self.usbwrite(b"\x02")  # Storage-Type: EMMC
            self.usbwrite(pack(">Q", addr))
            self.usbwrite(pack(">Q", length))
            self.usbwrite(pack(">I", packetsize))
            ack = self.usbread(1)[0]
            if ack is not self.Rsp.ACK[0]:
                self.usbwrite(b"\xA5")
                res = unpack("<I", self.usbread(4))[0]
                self.error(f"Error on sending emmc read command, response: {hex(ack)}, status: {hex(res)}")
                exit(1)
            self.daconfig.readsize = self.daconfig.storage.flashsize
        elif self.daconfig.storage.flashtype == "nand":
            self.usbwrite(self.Cmd.NAND_READPAGE_CMD)  # DF
            self.usbwrite(b"\x0C")  # Host:Linux, 0x0B=Windows
            self.usbwrite(b"\x00")  # Storage-Type: NUTL_READ_PAGE_SPARE
            self.usbwrite(b"\x01")  # Addr-Type: NUTL_ADDR_LOGICAL
            self.usbwrite(pack(">I", addr))
            self.usbwrite(pack(">I", length))
            self.usbwrite(pack(">I", 0))
            ack = self.usbread(1)[0]
            if ack is not self.Rsp.ACK:
                self.error(f"Error on sending nand read command, response: {hex(ack)}")
                exit(1)
            self.daconfig.pagesize = unpack(">I", self.usbread(4))[0]
            self.daconfig.sparesize = unpack(">I", self.usbread(4))[0]
            packetsize = unpack(">I", self.usbread(4))[0]
            pagestoread = 1
            self.usbwrite(pack(">I", pagestoread))
            self.usbread(4)
            self.daconfig.readsize = (self.daconfig.storage.flashsize //
                                      self.daconfig.pagesize * (self.daconfig.pagesize + self.daconfig.sparesize))
        elif self.daconfig.storage.flashtype == "nor":
            packetsize = 0x1000
            self.usbwrite(self.Cmd.READ_CMD)  # D6
            if not self.config.iot and self.config.hwcode not in [0x2625, 0x2523, 0x7682, 0x7686, 0x5932]:
                self.usbwrite(b"\x0C")  # Host:Linux, 0x0B=Windows
            if self.config.hwcode not in [0x2625, 0x2523, 0x7682, 0x7686, 0x5932]:
                self.usbwrite(b"\x00")  # Storage-Type: NOR
            if self.config.iot:
                self.usbwrite(pack(">I", addr))
                self.usbwrite(pack(">I", length))
                self.usbwrite(pack(">I", packetsize))
            else:
                self.usbwrite(pack(">Q", addr))
                self.usbwrite(pack(">Q", length))
                self.usbwrite(pack(">I", packetsize))
            ack = self.usbread(1)[0]
            if ack is not self.Rsp.ACK[0]:
                self.usbwrite(b"\xA5")
                res = unpack("<I", self.usbread(4))[0]
                self.error(f"Error on sending emmc read command, response: {hex(ack)}, status: {hex(res)}")
                exit(1)
            self.daconfig.readsize = self.daconfig.storage.flashsize
        if filename != "":
            worker = Thread(target=writedata, args=(filename, rq), daemon=True)
            worker.start()
            bytestoread = length
            curpos = 0
            while bytestoread > 0:
                size = bytestoread
                if bytestoread > packetsize:
                    size = packetsize
                tmp = self.usbread(size, w_max_packet_size=size)
                rq.put(tmp[:size])
                bytestoread -= size
                curpos += size
                checksum = unpack(">H", self.usbread(2))[0]
                self.debug("Checksum: %04X" % checksum)
                self.usbwrite(self.Rsp.ACK)
                if display:
                    pg.update(len(tmp))
            if display:
                pg.done()
            rq.put(None)
            worker.join(60)
            return True
        else:
            buffer = bytearray()
            bytestoread = length
            while bytestoread > 0:
                size = bytestoread
                if bytestoread > packetsize:
                    size = packetsize
                buffer.extend(self.usbread(size, w_max_packet_size=size))
                bytestoread = len(buffer) - length
                checksum = unpack(">H", self.usbread(2))[0]
                self.debug("Checksum: %04X" % checksum)
                self.usbwrite(self.Rsp.ACK)
                if display:
                    pg.update(length - bytestoread)
            if display:
                pg.done()
            return bytes(buffer)


if __name__ == "__main__":
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.config.mtk_config import MtkConfig

    config = MtkConfig(logging.INFO)
    config.init_hwcode(0x6575)
    config.hwver = 0x0
    config.swver = 0
    # config.loader = open("../../../../DA_Loader/V5/htc/MTK_AllInOne_DA_SWSEC_HTC.9286c98a.bin","rb").read()
    mtk = Mtk(config=config, loglevel=logging.INFO,
              serialportname=None)
    from mtkclient.Library.DA.daconfig import DAconfig
    daconfig = DAconfig(mtk=mtk, loader=mtk.config.loader,
                        preloader=mtk.config.preloader, loglevel=logging.INFO)
    daconfig.setup()
    """daconfig.parse_da_loader("../../../../DA_Loader/V5/htc/MTK_AllInOne_DA_SWSEC_HTC.9286c98a.bin", daconfig.dasetup)
    mtk.daloader.daconfig.setup()
    from mtkclient.Library.DA.legacy.extension.legacy import LegacyExt

    legacy = DALegacy(mtk, daconfig, logging.INFO)
    da2 = open("/home/bjk/Projects/DA_Loader/V5/oppo_realme/MT6877_stock/loaders/6877_40000000DA_BR_MT6877.bin",
               "rb").read()
    xf = LegacyExt(mtk, legacy, logging.INFO)
    da2_patched = xf.patch_da2(da2)
    """
