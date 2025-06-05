#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 GPLv3 License
import logging
import os
import sys
import time
from struct import pack, unpack
from binascii import hexlify

from mtkclient.Library.DA.legacy.dalegacy_flash_param import NandInfo64, NorInfo, NandInfo32, EmmcInfo, NandInfo2, \
    SdcInfo, \
    ConfigInfo
from mtkclient.Library.DA.legacy.dalegacy_iot_flash_param import NorInfoIoT, NandInfoIoT, EmmcInfoIoT, ConfigInfoIoT
from mtkclient.Library.DA.legacy.dalegacy_param import PortValues, Rsp, Cmd
from mtkclient.Library.utils import LogBase, logsetup, Structhelper
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.DA.daconfig import DaStorage, EmmcPartitionType
from mtkclient.Library.partition import Partition
from mtkclient.config.payloads import PathConfig
from mtkclient.Library.DA.legacy.extension.legacy import LegacyExt
from mtkclient.Library.thread_handling import writedata
from queue import Queue
from threading import Thread

rq = Queue()


class PassInfo:
    ack = None
    m_download_status = None
    m_boot_style = None
    soc_ok = None

    def __init__(self, data):
        sh = Structhelper(data)
        self.ack = sh.bytes()
        self.m_download_status = sh.dword(True)
        self.m_boot_style = sh.dword(True)
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
        self.emmc = None
        self.nand = None
        self.nor = None
        self.sdc = None
        self.flashconfig = None
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
        self.totalsectors = self.daconfig.flashsize
        self.partition = Partition(self.mtk, self.readflash, self.read_pmt, loglevel)
        self.pathconfig = PathConfig()
        self.patch = False
        self.generatekeys = self.mtk.config.generatekeys
        if self.generatekeys:
            self.patch = True
        self.lft = LegacyExt(self.mtk, self, loglevel)

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
                tmp1=self.usbread(4)
                tmp2=self.usbread(4)
                tmp3=self.usbread(4)
                tmp4 = self.usbread(4)
                tmp5 = self.usbread(4)
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
                        self.error("EMI Config not accepted :(")
                        return False
                    if ret == self.Rsp.ACK:
                        self.info(f"Sending dram info ... EMI-Version {hex(self.daconfig.emiver)}")
                        if self.daconfig.emiver in [0xF, 0x10, 0x11, 0x14, 0x15]:
                            dramlength = unpack(">I", self.usbread(0x4))[0]  # 0x000000BC
                            self.info(f"RAM-Length: {hex(dramlength)}")
                            self.usbwrite(self.Rsp.ACK)
                            lendram = len(self.daconfig.emi)
                            if hwcode != 0x8127:
                                self.usbwrite(pack(">I", lendram))
                        elif self.daconfig.emiver in [0x0B]:
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
            self.mtk.port.cdc.set_line_coding(baudrate=921600, parity=0, databits=8, stopbits=1)
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

    def read_flash_info_iot(self):
        self.nor = NorInfoIoT(self.usbread(0x36))
        self.nand = NandInfoIoT(self.usbread(0x23))
        self.emmc = EmmcInfoIoT(self.config, self.usbread(0x2C))
        self.flashconfig = ConfigInfoIoT(self.usbread(0x1E))
        # ack
        self.usbread(1)
        # ack
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
        self.nor = NorInfo(self.usbread(0x1C))
        data = self.usbread(0x11)
        self.nand = NandInfo64(data)
        nandcount = self.nand.m_nand_flash_id_count
        if nandcount == 0:
            self.nand = NandInfo32(data)
            nandcount = self.nand.m_nand_flash_id_count
            nc = data[-4:] + self.usbread(nandcount * 2 - 4)
        else:
            nc = self.usbread(nandcount * 2)
        m_nand_dev_code = unpack(">" + str(nandcount) + "H", nc)
        self.nand.m_nand_flash_dev_code = m_nand_dev_code
        self.nand.info2 = NandInfo2(self.usbread(9))
        self.emmc = EmmcInfo(self.config, self.usbread(0x5C))
        self.sdc = SdcInfo(self.config, self.usbread(0x1C))
        self.flashconfig = ConfigInfo(self.usbread(0x26))
        if self.config.hwcode == 0x8163:
            status=self.usbread(4)
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
                if self.mtk.config.is_brom or not self.mtk.config.target_config["sbc"]:
                    hashaddr, hashmode, hashlen = self.mtk.daloader.compute_hash_pos(da1, da2, da1sig_len, da2sig_len,
                                                                                     self.daconfig.da_loader.v6)
                    if hashaddr is not None:
                        da2patched = self.lft.patch_da2(da2)
                        if da2patched != da2:
                            da1 = self.mtk.daloader.fix_hash(da1, da2patched, hashaddr, hashmode, hashlen)
                            self.patch = True
                            self.daconfig.da2 = da2patched[:hashlen] + da2[hashlen:hashlen + da2sig_len]
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
            nandinfo = unpack(">I", self.usbread(4))[0]
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

            if nandids[0] != 0:
                self.daconfig.flashtype = "nand"
            elif emmcids[0] != 0:
                self.daconfig.flashtype = "emmc"
            else:
                self.daconfig.flashtype = "nor"

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
                        if self.daconfig.flashtype == "nand":
                            self.daconfig.flashsize = self.nand.m_nand_flash_size
                        elif self.daconfig.flashtype == "emmc" or self.emmc.m_emmc_ua_size != 0:
                            self.daconfig.flashsize = self.emmc.m_emmc_ua_size
                            self.daconfig.flashtype = "emmc"
                            if self.daconfig.flashsize == 0:
                                self.daconfig.flashsize = self.sdc.m_sdmmc_ua_size
                        elif self.daconfig.flashtype == "nor":
                            self.daconfig.flashsize = self.nor.m_nor_flash_size
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
        else:  # MT6261
            if self.daconfig.da_loader is None:
                self.error("No valid da loader found... aborting.")
                return False
            loader = self.daconfig.loader
            self.info(f"Uploading legacy stage 1 from {os.path.basename(loader)}")
            with open(loader, 'rb') as bootldr:
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
                if self.mtk.preloader.send_da(da2address, da2size, da2sig_len, da2):
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
                return False
            bytestosend = 0x1D4
            i = 0
            while bytestosend > 0:
                data = da3[i:i + 0x24]
                self.usbwrite(data)
                i += 0x24
                bytestosend -= 0x24
                if bytestosend <= 0:
                    break
                if self.usbread(1) != b"i":
                    return False
            ack1 = self.usbread(1)
            if ack1 != b"\x5A":
                return False
            ack2 = self.usbread(1)
            if ack2 != b"\xA5":
                return False
            # Begin address of BMT Pool 0x00000000
            self.usbwrite(b"\x00\x00\x00\x00")
            # info
            int.from_bytes(self.usbread(4), 'little')  # 0xa20c0000 - 0xC0000a5
            if self.read_flash_info_iot():
                if self.nand.m_nand_flash_size != 0:
                    self.daconfig.flashtype = "nand"
                elif self.emmc.m_emmc_ua_size != 0:
                    self.daconfig.flashtype = "emmc"
                else:
                    self.daconfig.flashtype = "nor"

                if self.daconfig.flashtype == "nand":
                    self.daconfig.flashsize = self.nand.m_nand_flash_size
                elif self.daconfig.flashtype == "emmc" or self.emmc.m_emmc_ua_size != 0:
                    self.daconfig.flashsize = self.emmc.m_emmc_ua_size
                    self.daconfig.flashtype = "emmc"
                    if self.daconfig.flashsize == 0:
                        self.daconfig.flashsize = self.sdc.m_sdmmc_ua_size
                elif self.daconfig.flashtype == "nor":
                    self.daconfig.flashsize = self.nor.m_nor_flash_size
                self.set_speed_iot()
                return True

            return False

    def upload_da(self):
        self.info("Uploading legacy da...")
        if self.upload_da1():
            self.info(self.flashconfig)
            if self.daconfig.flashtype == "emmc":
                print(self.emmc)
            elif self.daconfig.flashtype == "nand":
                print(self.nand)
            elif self.daconfig.flashtype == "nor":
                print(self.nor)
            elif self.daconfig.flashtype == "sdc":
                print(self.sdc)
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
                        f"Error on sending brom stage {stage} addr {hex(address+pos)}: " +
                        f"{hexlify(buffer).decode('utf-8')}")
                    self.config.set_gui_status(self.config.tr("Error on sending brom stage"))
                    break
            time.sleep(0.5)
            self.usbwrite(self.Rsp.ACK)
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

    def sdmmc_write_data(self, addr, length, filename, offset=0, parttype=None, wdata=None, display=True):
        length, parttype = self.get_parttype(length, parttype)
        storage = self.get_storage()
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
        self.mtk.daloader.progress.show_progress("Write", 0, length, display)
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
                if len(data) < count:
                    data.extend(b"\x00" * fill)
            else:
                data = wdata[offset:offset + count]
            self.usbwrite(data)
            chksum = sum(data) & 0xFFFF
            self.usbwrite(pack(">H", chksum))
            if self.usbread(1) != self.Rsp.CONT_CHAR:
                self.error("Data ack failed for sdmmc_write_data")
                return False
            self.mtk.daloader.progress.show_progress("Write", offset, length, display)
            offset += count
        if fh:
            fh.close()
        self.mtk.daloader.progress.show_progress("Write", length, length, display)
        return True

    def get_storage(self):
        if self.daconfig.flashtype == "nor":
            storage = DaStorage.MTK_DA_STORAGE_NOR
        elif self.daconfig.flashtype == "nand":
            storage = DaStorage.MTK_DA_STORAGE_NAND
        elif self.daconfig.flashtype == "ufs":
            storage = DaStorage.MTK_DA_STORAGE_UFS
        elif self.daconfig.flashtype == "sdc":
            storage = DaStorage.MTK_DA_STORAGE_SDMMC
        else:
            storage = DaStorage.MTK_DA_STORAGE_EMMC
        return storage

    def sdmmc_write_image(self, addr, length, filename, display=True):
        if filename != "":
            with open(filename, "rb") as rf:
                if self.daconfig.flashtype == "emmc":
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
                self.mtk.daloader.progress.show_progress("Write", 0, length, display)
                checksum = 0
                bytestowrite = length
                while bytestowrite > 0:
                    size = min(bytestowrite, packetsize)
                    for i in range(0, size, 0x400):
                        data = bytearray(rf.read(size))
                        pos = length - bytestowrite
                        self.mtk.daloader.progress.show_progress("Write", pos, length, display)
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
                                    return True
                                else:
                                    self.usbwrite(self.Rsp.ACK)
                self.mtk.daloader.progress.show_progress("Write", length, length, display)
                return True
        return True

    def writeflash(self, addr, length, filename: str = "", offset=0, parttype=None, wdata=None, display=True):
        self.mtk.daloader.progress.clear()
        return self.sdmmc_write_data(addr=addr, length=length, filename=filename, offset=offset, parttype=parttype,
                                     wdata=wdata, display=display)

    def formatflash(self, addr, length, parttype=None, display=True):
        self.mtk.daloader.progress.clear()
        length, parttype = self.get_parttype(length, parttype)
        self.check_usb_cmd()
        if self.daconfig.flashtype == "emmc":
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

    def get_parttype(self, length, parttype):
        if self.daconfig.flashtype == "emmc":
            if parttype is None or parttype == "user" or parttype == "":
                length = min(length, self.emmc.m_emmc_ua_size)
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            elif parttype == "boot1":
                length = min(length, self.emmc.m_emmc_boot1_size)
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_BOOT1
            elif parttype == "boot2":
                length = min(length, self.emmc.m_emmc_boot2_size)
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_BOOT2
            elif parttype == "gp1":
                length = min(length, self.emmc.m_emmc_gp_size[0])
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP1
            elif parttype == "gp2":
                length = min(length, self.emmc.m_emmc_gp_size[1])
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP2
            elif parttype == "gp3":
                length = min(length, self.emmc.m_emmc_gp_size[2])
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP3
            elif parttype == "gp4":
                length = min(length, self.emmc.m_emmc_gp_size[3])
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_GP4
            elif parttype == "rpmb":
                parttype = EmmcPartitionType.MTK_DA_EMMC_PART_RPMB
        elif self.daconfig.flashtype == "nand":
            parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            length = min(length, self.nand.m_nand_flash_size)
        elif self.daconfig.flashtype == "nor":
            parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            length = min(length, self.nor.m_nor_flash_size)
        else:
            parttype = EmmcPartitionType.MTK_DA_EMMC_PART_USER
            length = min(length, self.sdc.m_sdmmc_ua_size)
        return length, parttype

    def readflash(self, addr: int, length: int, filename: str, parttype=None, display=True) -> (bytes, bool):
        global rq
        self.mtk.daloader.progress.clear()
        length, parttype = self.get_parttype(length, parttype)
        if not self.config.iot:
            self.check_usb_cmd()
        packetsize = 0x0
        if self.daconfig.flashtype == "emmc":
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
            self.daconfig.readsize = self.daconfig.flashsize
        elif self.daconfig.flashtype == "nand":
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
            self.daconfig.readsize = self.daconfig.flashsize // self.daconfig.pagesize * (
                    self.daconfig.pagesize + self.daconfig.sparesize)
        elif self.daconfig.flashtype == "nor":
            packetsize = 0x1000
            self.usbwrite(self.Cmd.READ_CMD)  # D6
            if not self.config.iot:
                self.usbwrite(b"\x0C")  # Host:Linux, 0x0B=Windows
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
            self.daconfig.readsize = self.daconfig.flashsize
        if display:
            self.mtk.daloader.progress.show_progress("Read", 0, length, display)
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
                if length > bytestoread:
                    rpos = length - bytestoread
                else:
                    rpos = 0
                self.usbwrite(self.Rsp.ACK)
                self.mtk.daloader.progress.show_progress("Read", rpos, length, display)
            self.mtk.daloader.progress.show_progress("Read", length, length, display)
            rq.put(None)
            worker.join(60)
            return True
        else:
            buffer = bytearray()
            bytestoread = length
            if display:
                self.mtk.daloader.progress.show_progress("Read", 0, length, display)
            while bytestoread > 0:
                size = bytestoread
                if bytestoread > packetsize:
                    size = packetsize
                buffer.extend(self.usbread(size, w_max_packet_size=size))
                bytestoread = len(buffer)-length
                checksum = unpack(">H", self.usbread(2))[0]
                self.debug("Checksum: %04X" % checksum)
                self.usbwrite(self.Rsp.ACK)
                if length > bytestoread:
                    rpos = length - bytestoread
                else:
                    rpos = 0
                if display:
                    self.mtk.daloader.progress.show_progress("Read", rpos, length, display)
            if display:
                self.mtk.daloader.progress.show_progress("Read", length, length, display)
            return bytes(buffer)
