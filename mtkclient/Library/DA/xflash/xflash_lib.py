#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License
import logging
import time
import os
import sys
from binascii import hexlify
from struct import pack, unpack
from queue import Queue
from threading import Thread
from Cryptodome.Util.number import long_to_bytes

from mtkclient.Library.Auth.sla import generate_da_sla_signature
from mtkclient.Library.DA.storage import (UfsInfo, NorInfo, NandInfo,
                                          EmmcInfo, RamInfo, DaStorage, EmmcPartitionType)
from mtkclient.Library.DA.xflash.xflash_flash_param import NandExtension
from mtkclient.Library.DA.xflash.xflash_param import Cmd, ChecksumAlgorithm, FtSystemOSE, DataType
from mtkclient.Library.gui_utils import LogBase, logsetup, progress
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.DA.daconfig import DAconfig
from mtkclient.Library.partition import Partition
from mtkclient.config.payloads import PathConfig
from mtkclient.Library.DA.xflash.extension.xflash import XFlashExt, XCmd
from mtkclient.Library.thread_handling import writedata


class DAXFlash(metaclass=LogBase):
    """ Handles XFlash protocol """

    def __init__(self, mtk, daconfig, loglevel=logging.INFO):
        # self.extensions_address = 0x68000000
        self.extensions_address = 0x4FFF0000
        self.daversion = None
        (self.__logger, self.info, self.debug, self.warning,
         self.error) = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.cmd = Cmd()
        self.checksum_algorithm = ChecksumAlgorithm()
        self.ft_system_ose = FtSystemOSE()
        self.data_type = DataType()
        self.mtk = mtk
        self.loglevel = loglevel
        self.daext = False
        self.sram = None
        self.dram = None
        self.emmc = None
        self.nand = None
        self.nor = None
        self.ufs = None
        self.chipid = None
        self.randomid = None
        self.__logger = self.__logger
        self.eh = ErrorHandler()
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.echo = self.mtk.port.echo
        self.rbyte = self.mtk.port.rbyte
        self.rdword = self.mtk.port.rdword
        self.daconfig = daconfig
        self.partition = Partition(self.mtk, self.readflash, self.read_pmt, loglevel)
        self.pathconfig = PathConfig()
        self.generatekeys = self.mtk.config.generatekeys
        if self.generatekeys:
            self.mtk.daloader.patch = True
        self.xft = XFlashExt(self.mtk, self, loglevel)

        try:
            # from mtkclient.Library.Exploit.kamakiripl import KamakiriPl
            # self.kamakiri_pl = KamakiriPl(self.mtk, loglevel)
            self.kamakiri_pl = None
        except Exception:
            self.kamakiri_pl = None

        try:
            from mtkclient.Library.Exploit.carbonara import Carbonara
            self.carbonara = Carbonara(self.mtk, loglevel)
        except Exception:
            self.carbonara = None

    @staticmethod
    def usleep(usec):
        time.sleep(usec / 100000)

    def ack(self, rstatus=True):
        try:
            if self.mtk.config.chipconfig.dacode in [0x6781,0x6785]:
                stmp = pack("<IIII", self.cmd.MAGIC, self.data_type.DT_PROTOCOL_FLOW, 4, 0)
                self.usbwrite(stmp)
            else: # needed for 0x6750, 0x6762, 0x6785, 0x6761
                stmp = pack("<III", self.cmd.MAGIC, self.data_type.DT_PROTOCOL_FLOW, 4)
                self.usbwrite(stmp)
                stmp = pack("<I", 0)
                self.usbwrite(stmp)
            if rstatus:
                status = self.status()
                return status
            return True
        except Exception:
            return -1

    def xsend(self, data, datatype=DataType.DT_PROTOCOL_FLOW, is64bit: bool = False):
        if isinstance(data, int):
            if is64bit:
                data = pack("<Q", data)
                length = 8
            else:
                data = pack("<I", data)
                length = 4
        else:
            length = len(data)
        tmp = pack("<III", self.cmd.MAGIC, datatype, length)
        if self.usbwrite(tmp):
            return self.usbwrite(data)
        return False

    def xread(self):
        try:
            hdr = self.usbread(4 + 4 + 4)
            magic, _, length = unpack("<III", hdr)
        except Exception as err:
            self.error(f"xread error: {str(err)}")
            return -1
        if magic != 0xFEEEEEEF:
            self.error("xread error: Wrong magic")
            return -1
        resp = self.usbread(length)
        return resp

    def rdword(self, count=1):
        data = []
        for _ in range(count):
            data.append(unpack("<I", self.xread())[0])
        if count == 1:
            return data[0]
        return data

    def status(self):
        hdr = self.usbread(4 + 4 + 4)
        magic, _, length = unpack("<III", hdr)
        if magic != 0xFEEEEEEF:
            self.error("Status error: Wrong magic")
            return -1
        tmp = self.usbread(length)
        if len(tmp) < length:
            self.error(f"Status length error: Too few data {hex(len(hdr))}")
            return -1
        if length == 2:
            status = unpack("<H", tmp)[0]
            if status == 0x0:
                return 0
        elif length == 4:
            status = unpack("<I", tmp)[0]
            if status == 0xFEEEEEEF:
                return 0
        else:
            status = unpack("<" + str(length // 4) + "I", tmp)[0]
        return status

    def read_pmt(self) -> tuple:
        return self.partition.get_pmt()

    def send_param(self, params):
        if isinstance(params, bytes):
            params = [params]
        for param in params:
            pkt = pack("<III", self.cmd.MAGIC, self.data_type.DT_PROTOCOL_FLOW, len(param))
            if self.usbwrite(pkt):
                length = len(param)
                pos = 0
                while length > 0:
                    dsize = min(length, 0x200)
                    if not self.usbwrite(param[pos:pos + dsize]):
                        break
                    pos += dsize
                    length -= dsize
        status = self.status()
        if status == 0:
            return True
        if status != 0xc0040050:
            self.error(f"Error on sending parameter: {self.eh.status(status)}")
            if status == 0xc0020053:
                # Anti roll back DA error
                sys.exit(1)
        return False

    def send_devctrl(self, cmd, param=None, status=None):
        if status is None:
            status = [0]
        if self.xsend(self.cmd.DEVICE_CTRL):
            status[0] = self.status()
            if status[0] == 0x0:
                if self.xsend(cmd):
                    status[0] = self.status()
                    if status[0] == 0x0:
                        if param is None:
                            return self.xread()
                        return self.send_param(param)
        if status[0] != 0xC0010004:
            self.error(f"Error on sending dev ctrl {hex(cmd)}: " + self.eh.status(status[0]))
        return b""

    def set_reset_key(self, reset_key=0x68):
        # default:0x0,one:0x50,two:0x68
        param = pack("<I", reset_key)
        return self.send_devctrl(self.cmd.SET_RESET_KEY, param)

    def set_meta(self, porttype="off"):
        class MtkBootModeFlag:
            boot_mode = b"\x00"  # 0:normal, 1:meta
            com_type = b"\x00"  # 0:unknown, 1:uart, 2:usb
            com_id = b"\x00"  # 0:single interface device (meta,adb)

            # 1:composite device (meta, adb disable)
            # 2:no meta, adb enable
            # 3:no meta, adb disable

            def __init__(self, mode="off"):
                if mode == "off":
                    self.boot_mode = b"\x00"
                    self.com_type = b"\x00"
                    self.com_id = b"\x00"
                elif mode == "uart":
                    self.boot_mode = b"\x01"
                    self.com_type = b"\x01"
                    self.com_id = b"\x00"
                elif mode == "usb":
                    self.boot_mode = b"\x01"
                    self.com_type = b"\x02"
                    self.com_id = b"\x00"

            def get(self):
                return self.boot_mode + self.com_type + self.com_id

        metamode = MtkBootModeFlag(porttype).get()
        return self.send_devctrl(self.cmd.SET_META_BOOT_MODE, metamode)

    def set_checksum_level(self, checksum_level=0x0):
        param = pack("<I", checksum_level)
        # none[0x0]. USB[0x1]. storage[0x2], both[0x3]
        return self.send_devctrl(self.cmd.SET_CHECKSUM_LEVEL, param)

    def set_battery_opt(self, option=0x2):
        param = pack("<I", option)
        # battery[0x0]. USB power[0x1]. auto[0x2]
        return self.send_devctrl(self.cmd.SET_BATTERY_OPT, param)

    def send_emi(self, emi):
        if self.xsend(self.cmd.INIT_EXT_RAM):
            status = self.status()
            if status == 0:
                try:
                    time.sleep(0.01)
                    if self.xsend(pack("<I", len(emi))):
                        try:
                            if self.send_param([emi]):
                                self.info("DRAM setup passed.")
                                return True
                        except Exception as err:
                            self.info(f"DRAM setup failed: {str(err)}")
                            return False
                except Exception as err:
                    self.error(f"Error on sending emi: {str(err)}")
                    return False
            else:
                self.error(f"Error on sending emi: {self.eh.status(status)}")
        return False

    def send_data(self, data):
        pkt2 = pack("<III", self.cmd.MAGIC, self.data_type.DT_PROTOCOL_FLOW, len(data))
        if self.usbwrite(pkt2):
            bytestowrite = len(data)
            maxoutsize = self.mtk.port.cdc.EP_OUT.wMaxPacketSize
            pos = 0
            while bytestowrite > 0:
                if self.usbwrite(data[pos:pos + maxoutsize]):
                    pos += maxoutsize
                    bytestowrite -= maxoutsize
            status = self.status()  # 0xC0070004
            if status == 0x0:
                return True
            self.error(f"Error on sending data: {self.eh.status(status)}")
        return False

    def boot_to(self, addr, da, display=True, timeout=0.5):  # =0x40000000
        if self.xsend(self.cmd.BOOT_TO):
            if self.status() == 0:
                param = pack("<QQ", addr, len(da))
                pkt1 = pack("<III", self.cmd.MAGIC, self.data_type.DT_PROTOCOL_FLOW, len(param))
                if self.usbwrite(pkt1):
                    if self.usbwrite(param):
                        if self.send_data(da):
                            # if addr == 0x68000000:
                            if addr == self.extensions_address:
                                if display:
                                    self.info("Extensions were accepted. Jumping to extensions...")
                            else:
                                if display:
                                    self.info("Upload data was accepted. Jumping to stage 2...")
                            if timeout:
                                time.sleep(timeout)
                            status = -1
                            try:
                                status = self.status()
                            except Exception:
                                if status == -1:
                                    self.error("Stage was't executed. Maybe dram issue ?.")
                                    return False
                                self.error(f"Error on boot to: {self.eh.status(status)}")
                                return False

                            if status == 0x434E5953 or status == 0x0:
                                if display:
                                    self.info("Boot to succeeded.")
                                return True
                            self.error(f"Error on boot to: {self.eh.status(status)}, addr: {hex(addr)}")
                        else:
                            self.error(f"Error on boot to send_data, addr: {hex(addr)}")
                    else:
                        self.error(f"Error on boot usbwrite, addr: {hex(addr)}")
                else:
                    self.error(f"Error on boot usbwrite, addr: {hex(addr)}")
            else:
                self.error(f"Error on boot to, addr: {hex(addr)}")
        return False

    def get_connection_agent(self):
        # brom
        res = self.send_devctrl(self.cmd.GET_CONNECTION_AGENT)
        if res != b"":
            status = self.status()
            if status == 0x0:
                return res
            self.error(f"Error on getting connection agent: {self.eh.status(status)}")
        return None

    """
    def get_dram_type(self):
        res = self.send_devctrl(self.Cmd.GET_DRAM_TYPE)
        status = self.status()
        if status == 0x0:
            return res
    """

    def formatflash(self, addr, length, storage=None,
                    parttype=None, display=False):
        part_info = self.daconfig.storage.get_storage(parttype, length)
        if not part_info:
            return False
        storage, parttype, length = part_info
        pg = progress(total=length, prefix="Erasing:", guiprogress=self.mtk.config.guiprogress)
        if display:
            self.info(f"Formatting addr {hex(addr)} with length {hex(length)}, please standby....")
        if self.xsend(self.cmd.FORMAT):
            status = self.status()
            if status == 0:
                # storage: emmc:1,slc,nand,nor,ufs
                # section: boot,user of emmc:8, LU1, LU2

                ne = NandExtension()
                param = pack("<IIQQ", storage, parttype, addr, length)
                param += pack("<IIIIIIII", ne.cellusage, ne.addr_type, ne.bin_type, ne.region,
                              ne.format_level, ne.sys_slc_percent, ne.usr_slc_percent, ne.phy_max_size)
                if self.send_param(param):
                    status = self.status()
                    while status == 0x40040004:  # STATUS_CONTINUE
                        # it receive some data maybe sleep in ms time,
                        time.sleep(self.status() / 1000.0)
                        status = self.ack()
                    if status == 0x40040005:  # STATUS_COMPLETE
                        if display:
                            pg.update(length)
                            self.info(f"Successsfully formatted addr {hex(addr)} with length {length}.")
                        return True

            if status != 0x0:
                self.error(f"Error on format: {self.eh.status(status)}")
        return False

    def get_da_version(self, display=True):
        data = self.send_devctrl(self.cmd.GET_DA_VERSION)
        if data != b"":
            status = self.status()
            if status == 0:
                if display:
                    self.info(f"DA-VERSION:       {data.decode('utf-8')}")
                return data
            if display:
                self.error(f"Error on getting chip id: {self.eh.status(status)}")
            return None
        return None

    def get_chip_id(self, display=True):
        class Chipid:
            hw_code = 0
            hw_sub_code = 0
            hw_version = 0
            sw_version = 0
            chip_evolution = 0

        chipid = Chipid
        data = self.send_devctrl(self.cmd.GET_CHIP_ID)
        if data != b"":
            (chipid.hw_code, chipid.hw_sub_code, chipid.hw_version,
             chipid.sw_version, chipid.chip_evolution) = (unpack("<HHHHH", data[:(5 * 2)]))
            status = self.status()
            if status == 0:
                if display:
                    self.info(f"HW-CODE:          {hex(chipid.hw_code)}")
                    self.info(f"HWSUB-CODE:       {hex(chipid.hw_sub_code)}")
                    self.info(f"HW-VERSION:       {hex(chipid.hw_version)}")
                    self.info(f"SW-VERSION:       {hex(chipid.sw_version)}")
                    self.info(f"CHIP-EVOLUTION:   {hex(chipid.chip_evolution)}")
                return chipid
            self.error(f"Error on getting chip id: {self.eh.status(status)}")
        return None

    def get_ram_info(self):
        resp = self.send_devctrl(self.cmd.GET_RAM_INFO)
        if resp != b"":
            status = self.status()
            if status == 0x0:
                sram = RamInfo()
                dram = RamInfo()
                if len(resp) == 24:
                    (sram.type, sram.base_address, sram.size, dram.type,
                     dram.base_address, dram.size) = unpack("<IIIIII", resp)
                elif len(resp) == 48:
                    (sram.type, sram.base_address, sram.size, dram.type,
                     dram.base_address, dram.size) = unpack("<QQQQQQ", resp)
                self.daconfig.storage.sram = sram
                self.daconfig.storage.dram = dram
                return sram, dram
            self.error(f"Error on getting ram info: {self.eh.status(status)}")
        return None, None

    def get_emmc_info(self, display=True):
        resp = self.send_devctrl(self.cmd.GET_EMMC_INFO)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            emmc = EmmcInfo()
            pos = 0
            emmc.type, emmc.block_size = unpack("<II", resp[pos:pos + 8])
            pos += 8
            (emmc.boot1_size, emmc.boot2_size, emmc.rpmb_size, emmc.gp1_size,
             emmc.gp2_size, emmc.gp3_size, emmc.gp4_size, emmc.user_size) = (
                unpack("<QQQQQQQQ", resp[pos:pos + (8 * 8)]))
            pos += 8 * 8
            emmc.cid = resp[pos:pos + (4 * 4)]
            pos += (4 * 4)
            emmc.fwver = unpack("<Q", resp[pos:pos + 8])[0]
            pos += 8
            emmc.unknown = resp[pos:]
            if emmc.type != 0 and display:
                self.info(f"EMMC FWVer:      {hex(emmc.fwver)}")
                try:
                    self.info(f"EMMC ID:         {emmc.cid[3:9].decode('utf-8')}")
                except Exception:
                    pass
                self.info(f"EMMC CID:        {hexlify(emmc.cid).decode('utf-8')}")
                if self.config.hwparam is not None:
                    self.config.set_cid(emmc.cid)
                self.info(f"EMMC Boot1 Size: {hex(emmc.boot1_size)}")
                self.info(f"EMMC Boot2 Size: {hex(emmc.boot2_size)}")
                self.info(f"EMMC GP1 Size:   {hex(emmc.gp1_size)}")
                self.info(f"EMMC GP2 Size:   {hex(emmc.gp2_size)}")
                self.info(f"EMMC GP3 Size:   {hex(emmc.gp3_size)}")
                self.info(f"EMMC GP4 Size:   {hex(emmc.gp4_size)}")
                self.info(f"EMMC RPMB Size:  {hex(emmc.rpmb_size)}")
                self.info(f"EMMC USER Size:  {hex(emmc.user_size)}")
            return emmc
        self.error(f"Error on getting emmc info: {self.eh.status(status)}")
        return None

    def get_nand_info(self, display=True):
        resp = self.send_devctrl(self.cmd.GET_NAND_INFO)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            nand = NandInfo()
            pos = 0
            nand.type, nand.page_size, nand.block_size, nand.spare_size = (
                unpack("<IIII", resp[pos:pos + 16]))
            pos += 16
            nand.total_size, nand.available_size = unpack("<QQ", resp[pos:pos + (2 * 8)])
            pos += 2 * 8
            nand.nand_bmt_exist = resp[pos:pos + 1]
            pos += 1
            nand.nand_id = bytearray(resp[pos:pos + 12])
            if nand.type != 0:
                self.mtk.config.pagesize = nand.page_size
                self.mtk.daloader.daconfig.pagesize = nand.page_size
                if display:
                    self.info(f"NAND Pagesize:   {hex(nand.page_size)}")
                    self.info(f"NAND Blocksize:  {hex(nand.block_size)}")
                    self.info(f"NAND Sparesize:  {hex(nand.spare_size)}")
                    self.info(f"NAND Total size: {hex(nand.total_size)}")
                    self.info(f"NAND Avail:      {hex(nand.available_size)}")
                    self.info(f"NAND ID:         {nand.nand_id.hex()}")
            return nand
        self.error(f"Error on getting nand info: {self.eh.status(status)}")
        return None

    def get_rpmb_status(self):
        resp = self.send_devctrl(self.cmd.GET_RPMB_STATUS)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            return resp
        return None

    def get_nor_info(self, display=True):
        resp = self.send_devctrl(self.cmd.GET_NOR_INFO)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            nor = NorInfo()
            nor.type, nor.page_size, nor.available_size = unpack("<IIQ", resp[:16])
            if nor.type != 0:
                if display:
                    self.info(f"NOR Pagesize: {hex(nor.page_size)}")
                    self.info(f"NOR Size:     {hex(nor.available_size)}")
            return nor
        self.error(f"Error on getting nor info: {self.eh.status(status)}")
        return None

    def get_ufs_info(self, display=True):
        resp = self.send_devctrl(self.cmd.GET_UFS_INFO)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            ufs = UfsInfo()
            ufs.type, ufs.block_size, ufs.lu2_size, ufs.lu1_size, ufs.lu0_size = (
                unpack("<IIQQQ", resp[:(2 * 4) + (3 * 8)]))
            pos = (2 * 4) + (3 * 8)
            buf = resp[pos:]
            ufs.cid = buf[:16]
            ufs.fwver = buf[22:22 + 4]
            ufs.serial = buf[30:30 + 0xC]
            if ufs.type != 0:
                if display:
                    self.info(f"UFS Blocksize: {hex(ufs.block_size)}")
                    try:
                        self.info(f"UFS ID:       {ufs.cid[2:].decode('utf-8')}")
                    except Exception:
                        pass
                    self.info(f"UFS MID:      {hex(ufs.cid[0])}")
                    self.info(f"UFS CID:      {hexlify(ufs.cid).decode('utf-8')}")
                    self.info(f"UFS FWVer:    {hexlify(ufs.fwver).decode('utf-8')}")
                    self.info(f"UFS Serial:   {hexlify(ufs.serial).decode('utf-8')}")
                    self.info(f"UFS LU0 Size: {hex(ufs.lu0_size)}")
                    self.info(f"UFS LU1 Size: {hex(ufs.lu1_size)}")
                    self.info(f"UFS LU2 Size: {hex(ufs.lu2_size)}")
                if self.config.hwparam is not None:
                    self.config.set_cid(buf[:0x11 + 2] + buf[0x16:0x16 + 4 + 1] + buf[0x1E:0x1E + 0xC])
                self.mtk.config.pagesize = ufs.block_size
                self.mtk.daloader.daconfig.pagesize = ufs.block_size
            return ufs
        self.error(f"Error on getting ufs info: {self.eh.status(status)}")
        return None

    def get_expire_date(self):
        res = self.send_devctrl(self.cmd.GET_EXPIRE_DATE)
        if res != b"":
            status = self.status()
            if status == 0x0:
                return res
            self.error(f"Error on getting expire date: {self.eh.status(status)}")
        return None

    def get_random_id(self):
        res = self.send_devctrl(self.cmd.GET_RANDOM_ID)
        if res != b"":
            status = self.status()
            if status == 0:
                return res
            self.error(f"Error on getting random id: {self.eh.status(status)}")
        return None

    def get_hrid(self):
        res = self.send_devctrl(self.cmd.GET_HRID)
        if res != b"":
            status = self.status()
            if status == 0:
                return res
            self.error(f"Error on getting hrid info: {self.eh.status(status)}")
        return None

    def get_dev_fw_info(self):
        res = self.send_devctrl(self.cmd.GET_DEV_FW_INFO)
        if res != b"":
            status = self.status()
            if status == 0:
                return res
            self.error(f"Error on getting dev fw info: {self.eh.status(status)}")
        return None

    def get_da_stor_life_check(self):
        res = self.send_devctrl(self.cmd.DA_STOR_LIFE_CYCLE_CHECK)
        if res != b"":
            return unpack("<I", res)[0]
        return 0

    def get_partition_table_category(self):
        res = self.send_devctrl(self.cmd.GET_PARTITION_TBL_CATA)
        if res != b"":
            value = unpack("<I", res)[0]
            if value == 0x64:
                return "GPT"
            if value == 0x65:
                return "PMT"
        return 0

    def get_packet_length(self):
        resp = self.send_devctrl(self.cmd.GET_PACKET_LENGTH)
        if resp != b"":
            status = self.status()
            if status == 0:
                class Packetlen:
                    write_packet_length = 0
                    read_packet_length = 0

                plen = Packetlen()
                plen.write_packet_length, plen.read_packet_length = unpack("<II", resp)
                return plen
            self.error(f"Error on getting packet length: {self.eh.status(status)}")
        return None

    def get_sla_status(self):
        resp = self.send_devctrl(self.cmd.SLA_ENABLED_STATUS)
        if resp != b"":
            status = self.status()
            if status == 0:
                return int.from_bytes(resp, 'little')
            self.error(f"Error on getting sla enabled status: {self.eh.status(status)}")
        return None

    def get_usb_speed(self):
        resp = self.send_devctrl(self.cmd.GET_USB_SPEED)
        if resp != b"":
            status = self.status()
            if status == 0:
                # full-speed, high-speed, hyper-speed
                return resp
            self.error(f"Error on getting usb speed: {self.eh.status(status)}")
        return None

    def set_usb_speed(self):
        resp = self.xsend(self.cmd.SWITCH_USB_SPEED)
        if resp != b"":
            status = self.status()
            if status == 0:
                if self.xsend(pack("<I", 0x0E8D2001)):
                    status = self.status()
                    if status == 0:
                        return True
            else:
                self.error(f"Error on getting usb speed: {self.eh.status(status)}")
        return False

    def cmd_write_data(self, addr, size, storage=DaStorage.MTK_DA_STORAGE_EMMC,
                       parttype=EmmcPartitionType.MTK_DA_EMMC_PART_USER):
        if self.xsend(self.cmd.WRITE_DATA):
            status = self.status()
            if status == 0:
                # storage: emmc:1,slc,nand,nor,ufs
                # section: boot,user of emmc:8, LU1, LU2
                ne = NandExtension()
                param = pack("<IIQQ", storage, parttype, addr, size)
                param += pack("<IIIIIIII", ne.cellusage, ne.addr_type, ne.bin_type, ne.region,
                              ne.format_level, ne.sys_slc_percent, ne.usr_slc_percent, ne.phy_max_size)
                if self.send_param(param):
                    return True
            else:
                self.error(f"Error on writing data: {self.eh.status(status)}")
        return False

    def cmd_read_data(self, addr, size, storage=DaStorage.MTK_DA_STORAGE_EMMC,
                      parttype=EmmcPartitionType.MTK_DA_EMMC_PART_USER):
        if self.xsend(self.cmd.READ_DATA):
            status = self.status()
            if status == 0:
                # storage: emmc:1,slc,nand,nor,ufs
                # section: boot,user of emmc:8, LU1, LU2
                ne = NandExtension()
                param = pack("<IIQQ", storage, parttype, addr, size)
                param += pack("<IIIIIIII", ne.cellusage, ne.addr_type, ne.bin_type, ne.region,
                              ne.format_level, ne.sys_slc_percent, ne.usr_slc_percent, ne.phy_max_size)
                self.send_param(param)
                status = self.status()
                if status == 0x0:
                    return True
            if status != 0x0:
                self.error(f"Error on reading data: {self.eh.status(status)}")
        return False

    def readflash(self, addr, length, filename, parttype=None, display=True) -> (bytes, bool):
        partinfo = self.daconfig.storage.get_storage(parttype, length)
        rq = None
        buffer = None
        if filename:
            if not partinfo:
                return False
            rq = Queue(maxsize=32)
            worker = Thread(target=writedata, args=(filename, rq), daemon=True)
            worker.start()
        else:
            if not partinfo:
                return b""
            buffer = bytearray()
        storage, parttype, length = partinfo
        pg = progress(total=length, prefix="Read:", guiprogress=self.mtk.config.guiprogress)
        # Get optimal packet sizes
        plen = self.get_packet_length()
        read_packet_length = plen.read_packet_length if plen else 0x100000  # fallback 1MB
        max_usb_packet = self.mtk.port.cdc.EP_IN.wMaxPacketSize
        bytesread = 0
        try:
            if self.cmd_read_data(addr=addr, size=length, storage=storage, parttype=parttype):
                bytestoread = length
                while bytestoread > 0:
                    status = self.usbread(12, maxtimeout=5000)
                    if len(status) != 12:
                        self.error(f"Timeout or short read on header at {hex(bytesread)}")
                        break
                    magic, _, slength = unpack("<III", status)
                    if magic != 0xFEEEEEEF:
                        self.error(f"Invalid magic in data packet: {hex(magic)}")
                        break
                    remaining = slength
                    chunk_buffer = bytearray()
                    while remaining > 0:
                        # Read as much as possible in one USB transaction
                        to_read = min(remaining, read_packet_length, 0x400000)  # cap at 4MB chunks
                        data = self.usbread(to_read, w_max_packet_size=remaining)
                        if not data:
                            self.error("USB read failed mid-packet")
                            raise IOError("USB read failure")
                        chunk_buffer.extend(data)
                        remaining -= len(data)
                    if slength > 4:
                        if filename:
                            rq.put(bytes(chunk_buffer))
                        else:
                            buffer.extend(chunk_buffer)
                        self.ack(rstatus=False)
                        ld = len(chunk_buffer)
                        bytestoread -= ld
                        bytesread += ld
                        if display:
                            pg.update(ld)
                    elif slength == 4:
                        flag = unpack("<I", chunk_buffer)[0]
                        if flag != 0:
                            self.error("Read completed with error status")
                            break
                    else:
                        print("Error: Invalid slength")
                        break
            # Final acknowledge
            status = self.usbread(12, maxtimeout=5000)
            magic, _, slength = unpack("<III", status)
            if magic == 0xFEEEEEEF:
                resdata = self.usbread(slength, w_max_packet_size=slength)
                if slength == 4:
                    if unpack("<I", resdata)[0] != 0:
                        self.error("Read completed with error status")
            if filename:
                rq.put(None)
                worker.join(timeout=30)
                if display:
                    pg.done()
                if worker.is_alive():
                    self.warning("Writer thread didn't finish cleanly")
                    return False
                return True
            else:
                if display:
                    pg.done()
                return buffer
        except Exception as e:
            self.error(f"Exception during readflash: {str(e)}")
        finally:
            if filename and 'rq' in locals():
                try:
                    rq.put(None, timeout=1)
                except Exception:
                    pass
                if 'worker' in locals():
                    worker.join(timeout=10)
        # Cleanup on failure
        if filename:
            rq.put(None)
            worker.join(timeout=10)
        if display:
            pg.done()
        return buffer if filename == "" else False

    class ShutDownModes:
        NORMAL = 0
        HOME_SCREEN = 1
        FASTBOOT = 2

    def shutdown(self, async_mode: int = 0, dl_bit: int = 0, bootmode: ShutDownModes = ShutDownModes.NORMAL):
        if self.xsend(self.cmd.SHUTDOWN):
            status = self.status()
            if status == 0:
                hasflags = 0
                # bootmode 0: shutdown 1: home screen, 2: fastboot
                if async_mode or dl_bit or bootmode != self.ShutDownModes.NORMAL:
                    hasflags = 1
                enablewdt = 0  # Disable wdt
                dont_resetrtc = 0  # Reset RTC
                leaveusb = 0  # Disconnect usb
                if self.xsend(pack("<IIIIIIII", hasflags, enablewdt, async_mode, bootmode, dl_bit,
                                   dont_resetrtc, leaveusb, 0)):
                    status = self.status()
                    if status == 0:
                        self.mtk.port.close(reset=True)
                        return True
            else:
                self.error(f"Error on sending shutdown: {self.eh.status(status)}")
        self.mtk.port.close(reset=True)
        return False

    def writeflash(self, addr, length, filename: str = "", offset=0, parttype=None, wdata=None, display=True):
        fh = None
        fill = 0
        if filename != "":
            if os.path.exists(filename):
                fsize = os.stat(filename).st_size
                length = min(fsize, length)
                fh = open(filename, "rb")
                fh.seek(offset)
            else:
                self.error(f"Filename doesn't exists: {filename}, aborting flash write.")
                return False
        if length % 512 != 0:
            fill = 512 - (length % 512)
            length += fill
        partinfo = self.daconfig.storage.get_storage(parttype, length)
        if not partinfo:
            return False
        storage, parttype, plength = partinfo
        length = min(length, plength)
        pg = progress(total=length, prefix="Write:", guiprogress=self.mtk.config.guiprogress)
        # self.send_devctrl(self.Cmd.START_DL_INFO)
        plen = self.get_packet_length()
        write_packet_size = plen.write_packet_length

        bytestowrite = length
        if self.cmd_write_data(addr, length, storage, parttype):
            try:
                pos = 0
                while bytestowrite > 0:
                    dsize = min(write_packet_size, bytestowrite)
                    if fh:
                        data = bytearray(fh.read(dsize))
                        if len(data) < dsize:
                            data.extend(b"\x00" * fill)
                    else:
                        data = wdata[pos:pos + dsize]
                    if len(data) % 512 != 0:
                        fill = 512 - (len(data) % 512)
                        data += fill * b"\x00"
                    if display:
                        pg.update(len(data))
                    checksum = sum(data) & 0xFFFF
                    if not self.send_param([pack("<I", 0x0), pack("<I", checksum), data]):
                        self.error("Error on writing pos 0x%08X" % pos)
                        return False
                    bytestowrite -= dsize
                    pos += dsize
                status = self.status()
                if status == 0x0:
                    self.send_devctrl(self.cmd.CC_OPTIONAL_DOWNLOAD_ACT)
                    if display:
                        pg.done()
                    if fh:
                        fh.close()
                    return True
                if display:
                    pg.done()
                self.error(f"Error on writeflash: {self.eh.status(status)}")
            except Exception as e:
                self.error(str(e))
                if fh:
                    fh.close()
                return False
        if fh:
            fh.close()
        return False

    def sync(self):
        """ XFlash Sync command """
        if self.xsend(self.cmd.SYNC_SIGNAL):
            return True
        return False

    def setup_env(self):
        """ XFlash Setup environment command """
        if self.xsend(self.cmd.SETUP_ENVIRONMENT):
            da_log_level = int(self.daconfig.uartloglevel)
            log_channel = 1
            system_os = self.ft_system_ose.OS_LINUX
            ufs_provision = 0x0
            param = pack("<IIIII", da_log_level, log_channel, system_os, ufs_provision, 0x0)
            if self.send_param(param):
                return True
        return False

    def setup_hw_init(self):
        """ XFlash Setup Hardware Init command """
        if self.xsend(self.cmd.SETUP_HW_INIT_PARAMS):
            param = pack("<I", 0x0)  # No config
            if self.send_param(param):
                return True
        return False

    def patch_da(self, da1, da2):
        """ XFlash patch da1 and da2 """
        da1sig_len = self.daconfig.da_loader.region[1].m_sig_len
        # ------------------------------------------------
        da2sig_len = self.daconfig.da_loader.region[2].m_sig_len
        hashaddr, hashmode, hashlen = self.mtk.daloader.compute_hash_pos(da1, da2, da1sig_len, da2sig_len,
                                                                         self.daconfig.da_loader.v6)
        if hashaddr is not None:
            da1 = self.xft.patch_da1(da1)
            da2 = self.xft.patch_da2(da2)
            da1 = self.mtk.daloader.fix_hash(da1, da2, hashaddr, hashmode, hashlen)
            self.mtk.daloader.patch = True
            self.daconfig.da2 = da2[:hashlen]
        else:
            self.mtk.daloader.patch = False
            self.daconfig.da2 = da2[:-da2sig_len]
        return da1, da2

    def upload_da1(self):
        if self.daconfig.da_loader is None:
            self.error("No valid da loader found... aborting.")
            return False
        loader = self.daconfig.loader
        self.info(f"Uploading xflash stage 1 from {os.path.basename(loader)}")
        if not os.path.exists(loader):
            self.info(f"Couldn't find {loader}, aborting.")
            return False
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
            if self.mtk.daloader.patch or not self.config.target_config["sbc"] and not self.config.stock:
                da1, da2 = self.patch_da(da1, da2)
            else:
                self.mtk.daloader.patch = False
                self.daconfig.da2 = da2[:-da2sig_len]
            if self.mtk.preloader.send_da(da1address, da1size, da1sig_len, da1):
                self.info("Successfully uploaded stage 1, jumping ..")
                if self.mtk.preloader.jump_da(da1address):
                    sync = self.usbread(1)
                    if sync != b"\xC0":
                        self.error("Error on DA sync")
                        return False
                    self.sync()
                    # if self.kamakiri_pl is not None:
                    #    self.kamakiri_pl.bypass2ndDA()
                    self.setup_env()
                    self.setup_hw_init()
                    res = self.xread()
                    if res == pack("<I", self.cmd.SYNC_SIGNAL):
                        self.info("Successfully received DA sync")
                        return True
                    self.error(f"Error jumping to DA: {res}")
                else:
                    self.error("Error on jumping to DA.")
            else:
                self.error("Error on sending DA.")
        return False

    def reinit(self, display=False):
        self.config.sram, self.config.dram = self.get_ram_info()
        self.emmc = self.get_emmc_info(display)
        self.nand = self.get_nand_info(display)
        self.nor = self.get_nor_info(display)
        self.ufs = self.get_ufs_info(display)
        if self.emmc is not None and self.emmc.type != 0:
            self.daconfig.storage.flashtype = "emmc"
            self.daconfig.storage.emmc = self.emmc
        elif self.nand is not None and self.nand.type != 0:
            self.daconfig.storage.flashtype = "nand"
            self.daconfig.storage.nand = self.nand
        elif self.nor is not None and self.nor.type != 0:
            self.daconfig.storage.flashtype = "nor"
            self.daconfig.storage.nor = self.nor
        elif self.ufs is not None and self.ufs.type != 0:
            self.daconfig.storage.flashtype = "ufs"
            self.daconfig.storage.ufs = self.ufs
        self.chipid = self.get_chip_id(display=False)
        self.daversion = self.get_da_version(display=False)
        self.randomid = self.get_random_id()
        self.daconfig.storage.set_flash_size()
        speed = self.get_usb_speed()
        if speed == b"full-speed" and self.daconfig.reconnect:
            self.info("Reconnecting to stage2 with higher speed")
            self.config.set_gui_status(self.config.tr("Reconnecting to stage2 with higher speed"))
            self.set_usb_speed()
            self.mtk.port.close(reset=True)
            time.sleep(2)
            while not self.mtk.port.cdc.connect():
                time.sleep(0.5)
            self.info("Connected to stage2 with higher speed")
            self.mtk.port.cdc.set_fast_mode(True)
            self.config.set_gui_status(self.config.tr("Connected to stage2 with higher speed"))

    def set_remote_sec_policy(self, data):
        return self.send_devctrl(self.cmd.SET_REMOTE_SEC_POLICY, data)

    def handle_sla(self, da2):
        rsakey = None
        from mtkclient.Library.Auth.sla_keys import da_sla_keys
        for key in da_sla_keys:
            if da2.find(long_to_bytes(key.n)) != -1:
                rsakey = key
                break
        if "_lake" in self.mtk.loader or "_tides" in self.mtk.loader or "_moon" in self.mtk.loader:
            print("Trying lake ....")
            # Xiaomi Redmi 14C
            res = self.get_dev_fw_info()
            if res != b"":
                sla_signature = bytes.fromhex(
                    "62737010D445F66526F0F52BACBCF1E8FE6522CC50617E7B20098E6243DE2E5D7BB71D3607BD8DBADA63521B9EA99EDEA069DCAD9F04D622AE62AC594010D62BEE7AF4B325115C6F0457238BE8D4CB89A7CD1EAF56ACB0C0A16EE016A6B9B030C5794C3B761999E9B684B7B3760B914571DE060FFB07182056F889DD047E3689FB14EFDEBC3CEACE9864E074534DFC5DBF23BCBAD571258CF48C61D7DCAF6ECC8BF908F7F6E0B841A8A7E11D2F64CA40CED98013A9FB381215E7B0051ACAB2C3ACDDD3D08F34FA38AEE8FAD02C9B9EB402750124727EA37B532100C329AF123FA702495740FD1FDBD9EC6EF32D8A76C1767F97986E83E9CE3EFB8E29D5803D84")
                if self.set_remote_sec_policy(data=sla_signature):
                    print("SLA Signature was accepted.")
                    return True
        if rsakey is None:
            print("No valid sla key found, trying dummy auth ....")
            # Xiaomi
            sla_signature = b"\x00" * 0x100
            if self.set_remote_sec_policy(data=sla_signature):
                print("SLA Signature was accepted.")
                return True
        else:
            res = self.get_dev_fw_info()
            if res != b"":
                data = res[4:4 + 0x10]
                sla_signature = generate_da_sla_signature(data=data, key=rsakey.key)
                if self.set_remote_sec_policy(data=sla_signature):
                    print("SLA Signature was accepted.")
                    return True
        return False

    def upload_da(self):
        if not self.mtk.daloader.patch:
            if (self.kamakiri_pl is not None and not self.mtk.config.chipconfig.damode == 6 and
                    self.mtk.config.target_config["sbc"]):
                self.kamakiri_pl.initbrom()
        if self.upload_da1():
            self.get_expire_date()
            self.set_reset_key(0x68)
            # self.set_battery_opt(0x2)
            self.set_checksum_level(0x0)
            connagent = self.get_connection_agent()
            # dev_fw_info=self.get_dev_fw_info()
            # dramtype = self.get_dram_type()
            stage = None
            if connagent == b"brom":
                stage = 1
                if self.daconfig.emi is None:
                    emmc_info = self.get_emmc_info(False)
                    if emmc_info is not None and emmc_info.user_size != 0:
                        self.info(f"DRAM config needed for: {hexlify(emmc_info.cid[:8]).decode('utf-8')}")
                    else:
                        ufs_info = self.get_ufs_info()
                        if ufs_info is not None and ufs_info.block_size != 0:
                            self.info(f"DRAM config needed for: {hexlify(ufs_info.cid).decode('utf-8')}")
                    self.info("No preloader given. Searching for preloader")
                    found = False
                    for root, _, files in os.walk(os.path.join(self.pathconfig.get_loader_path(), 'Preloader')):
                        for file in files:
                            with open(os.path.join(root, file), "rb") as rf:
                                data = rf.read()
                                if emmc_info is not None:
                                    if emmc_info.cid[:8] in data:
                                        preloader = os.path.join(root, file)
                                        self.daconfig.extract_emi(preloader)
                                        self.info("Sending emi data ...")
                                        if not self.send_emi(self.daconfig.emi):
                                            self.info("Emi data NOT accepted ...")
                                            continue
                                        self.info("Emi data accepted ...")
                                        found = True
                                        self.info("Detected working preloader: " + preloader)
                                        break
                                else:
                                    self.warning("No emmc info, can't parse existing preloaders.")
                                if found:
                                    break
                    if not found:
                        self.warning("No preloader given. Operation may fail due to missing dram setup.")
                else:
                    self.info("Sending emi data ...")
                    if not self.send_emi(self.daconfig.emi):
                        return False
                    self.info("Sending emi data succeeded.")
            elif connagent == b"preloader":
                stage = 1
            if stage == 1:
                self.info("Uploading stage 2...")
                stage = stage + 1
                loaded = False
                if not self.mtk.daloader.patch and not self.mtk.config.stock and connagent == b"preloader":
                    if (self.carbonara is not None and
                            self.mtk.config.target_config["sbc"]):
                        # Do NOT patch da1 on usage of carbonara
                        loaded = self.carbonara.patchda1_and_upload_da2()
                        if not loaded:
                            self.mtk.daloader.patch = False
                if not loaded:
                    loaded = self.boot_to(self.daconfig.da_loader.region[stage].m_start_addr, self.daconfig.da2)
                if loaded:
                    self.info("Successfully uploaded stage 2")
                    sla_enabled = self.get_sla_status()
                    if sla_enabled:
                        self.info("DA SLA is enabled")
                        if not self.handle_sla(self.daconfig.da2):
                            self.error("Can't bypass DA SLA")
                    else:
                        self.info("DA SLA is disabled")
                    self.reinit(True)
                    if self.mtk.daloader.patch:
                        daextdata = self.xft.patch()
                    else:
                        daextdata = None
                    if daextdata is not None:
                        self.daext = False
                        if self.boot_to(addr=self.extensions_address, da=daextdata):
                            ret = self.send_devctrl(XCmd.CUSTOM_ACK)
                            status = self.status()
                            if status == 0x0 and unpack("<I", ret)[0] == 0xA1A2A3A4:
                                self.info(f"DA Extensions successfully added at {hex(self.extensions_address)}")
                                self.daext = True
                                self.xft.custom_set_storage(ufs=self.daconfig.storage.flashtype == "ufs")
                        if not self.daext:
                            self.warning("DA Extensions failed to enable")

                        if self.generatekeys:
                            self.xft.generate_keys()
                    return True
                self.error("Error on booting to da (xflash)")
                return False
            self.error(f"Didn't get brom connection, got instead: {hexlify(connagent).decode('utf-8')}")
        return False


def main():
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.config.mtk_config import MtkConfig
    config = MtkConfig(logging.INFO)
    config.init_hwcode(0x717)
    config.hwver = 0xca00
    config.swver = 0
    mtk = Mtk(config=config, loglevel=logging.INFO,
              serialportname=None)
    daconfig = DAconfig(mtk=mtk, loader=mtk.config.loader,
                        preloader=mtk.config.preloader, loglevel=logging.INFO)
    daconfig.setup()
    dax = DAXFlash(mtk, daconfig, loglevel=logging.INFO)
    loader = daconfig.loader

    print(f"Uploading xflash stage 1 from {os.path.basename(loader)}")
    if not os.path.exists(loader):
        print(f"Couldn't find {loader}, aborting.")
        return False
    with open(loader, 'rb') as bootldr:
        # stage 1
        da1offset = daconfig.da_loader.region[1].m_buf
        da1size = daconfig.da_loader.region[1].m_len
        bootldr.seek(da1offset)
        da1 = bootldr.read(da1size)
        # ------------------------------------------------
        da2offset = daconfig.da_loader.region[2].m_buf
        bootldr.seek(da2offset)
        da2 = bootldr.read(daconfig.da_loader.region[2].m_len)
        dax.patch_da(da1, da2)
    return True


if __name__ == "__main__":
    main()
