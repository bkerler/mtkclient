#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 GPLv3 License
import logging
import os
from queue import Queue
from struct import pack, unpack
from threading import Thread

from Cryptodome.Util.number import long_to_bytes
from Cryptodome.Util.number import size

from mtkclient.Library.Auth.sla import generate_da_sla_signature
from mtkclient.Library.DA.daconfig import EmmcPartitionType, UFSPartitionType, DaStorage
from mtkclient.Library.DA.xml.extension.v6 import XmlFlashExt
from mtkclient.Library.DA.xml.xml_cmd import XMLCmd, BootModes
from mtkclient.Library.DA.xml.xml_param import DataType, FtSystemOSE, LogLevel
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.partition import Partition
from mtkclient.Library.thread_handling import writedata
from mtkclient.Library.utils import logsetup, LogBase
from mtkclient.config.payloads import PathConfig

rq = Queue()


class ShutDownModes:
    TEST = 3
    META = 4
    NORMAL = 0
    HOME_SCREEN = 1
    FASTBOOT = 2


def get_field(data, fieldname):
    if isinstance(data, bytes) or isinstance(data, bytearray):
        data = data.decode('utf-8')
    start = data.find(f"<{fieldname}>")
    if start != -1:
        end = data.find(f"</{fieldname}>", start + len(fieldname) + 2)
        if start != -1 and end != -1:
            return data[start + len(fieldname) + 2:end]
    return ""


class FileSysOp:
    key = None
    file_path = None

    def __init__(self, key, file_path):
        self.key = key
        self.file_path = file_path


class UpFile:
    checksum = None
    info = None
    source_file = None
    packet_length = None

    def __init__(self, checksum, info, target_file, packet_length):
        self.checksum = checksum
        self.info = info
        self.target_file = target_file
        self.packet_length = packet_length


class DwnFile:
    checksum = None
    info = None
    source_file = None
    packet_length = None

    def __init__(self, checksum: str, info: str, source_file: str, packet_length: int):
        self.checksum = checksum
        self.info = info
        self.source_file = source_file
        self.packet_length = packet_length


class DAXML(metaclass=LogBase):
    def __init__(self, mtk, daconfig, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.Cmd = XMLCmd(mtk)
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
        self.rword = self.mtk.port.rword
        self.daconfig = daconfig
        self.partition = Partition(self.mtk, self.readflash, self.read_partition_table, loglevel)
        self.pathconfig = PathConfig()
        self.patch = False
        self.generatekeys = self.mtk.config.generatekeys
        if self.generatekeys:
            self.patch = True
        try:
            from mtkclient.Library.Exploit.carbonara import Carbonara
            self.carbonara = Carbonara(self.mtk, loglevel)
        except Exception:
            self.carbonara = None

        self.xmlft = XmlFlashExt(self.mtk, self, loglevel)

    def xread(self):
        try:
            hdr = self.usbread(4 + 4 + 4)
            magic, datatype, length = unpack("<III", hdr)
        except Exception as err:
            self.error("xread error: " + str(err))
            return -1
        if magic != 0xFEEEEEEF:
            self.error("xread error: Wrong magic")
            return -1
        resp = self.usbread(length)
        return resp

    def xsend(self, data, datatype=DataType.DT_PROTOCOL_FLOW, is64bit: bool = False):
        if isinstance(data, int):
            if is64bit:
                data = pack("<Q", data)
                length = 8
            else:
                data = pack("<I", data)
                length = 4
        else:
            if type(data) is str:
                length = len(data) + 1
            else:
                length = len(data)
        tmp = pack("<III", self.Cmd.MAGIC, datatype, length)
        if self.usbwrite(tmp):
            if type(data) is str:
                return self.usbwrite(bytes(data, 'utf-8') + b"\x00")
            else:
                return self.usbwrite(data)
        return False

    def ack(self):
        return self.xsend("OK")

    def ack_value(self, length):
        return self.xsend(f"OK@{hex(length)}")

    def ack_text(self, text):
        return self.xsend(f"OK@{text}")

    def setup_env(self):
        da_log_level = int(self.daconfig.uartloglevel)
        loglevel = "INFO"
        if da_log_level == 0:
            loglevel = LogLevel().TRACE
        elif da_log_level == 1:
            loglevel = LogLevel().DEBUG
        elif da_log_level == 2:
            loglevel = LogLevel().INFO
        elif da_log_level == 3:
            loglevel = LogLevel().WARN
        elif da_log_level == 4:
            loglevel = LogLevel().ERROR
        system_os = FtSystemOSE.OS_LINUX
        res = self.send_command(self.Cmd.cmd_set_runtime_parameter(da_log_level=loglevel, system_os=system_os))
        return res

    def send_command(self, xmldata, noack: bool = False):
        if self.xsend(xmldata):
            result = self.get_response()
            if result == "OK":
                if noack:
                    return True
                cmd, result = self.get_command_result()
                if cmd == "CMD:END":
                    self.ack()
                    if result == '2nd DA address is invalid. reset.\r\n':
                        self.error(result)
                        exit(1)
                    scmd, sresult = self.get_command_result()
                    if scmd == "CMD:START":
                        if result == "OK":
                            return True
                        else:
                            self.error(result)
                            return False
                else:
                    return result
            elif result == "ERR!UNSUPPORTED":
                scmd, sresult = self.get_command_result()
                self.ack()
                tcmd, tresult = self.get_command_result()
                if tcmd == "CMD:START":
                    return False
            elif "ERR!" in result:
                return result
        return False

    def get_response(self, raw: bool = False) -> str:
        sync = self.usbread(4 * 3)
        if len(sync) == 4 * 3:
            if int.from_bytes(sync[:4], 'little') == 0xfeeeeeef:
                if int.from_bytes(sync[4:8], 'little') == 0x1:
                    length = int.from_bytes(sync[8:12], 'little')
                    data = self.usbread(length)
                    if len(data) == length:
                        if raw:
                            return data
                        return data.rstrip(b"\x00").decode('utf-8')
        return ""

    def get_response_data(self) -> bytes:
        sync = self.usbread(4 * 3)
        if len(sync) == 4 * 3:
            if int.from_bytes(sync[:4], 'little') == 0xfeeeeeef:
                if int.from_bytes(sync[4:8], 'little') == 0x1:
                    length = int.from_bytes(sync[8:12], 'little')
                    usbepsz = self.mtk.port.cdc.get_read_packetsize()
                    data = bytearray()
                    bytestoread = length
                    while bytestoread > 0:
                        sz = min(usbepsz, bytestoread)
                        data.extend(self.usbread(sz,w_max_packet_size=sz))
                        bytestoread -= sz
                    if len(data) == length:
                        return data
        return b""

    def patch_da(self, da1, da2):
        da1sig_len = self.daconfig.da_loader.region[1].m_sig_len
        # ------------------------------------------------
        da2sig_len = self.daconfig.da_loader.region[2].m_sig_len
        hashaddr, hashmode, hashlen = self.mtk.daloader.compute_hash_pos(da1, da2, da1sig_len, da2sig_len,
                                                                         self.daconfig.da_loader.v6)
        if hashaddr is not None:
            da1 = self.xmlft.patch_da1(da1)
            da2 = self.xmlft.patch_da2(da2)
            da1 = self.mtk.daloader.fix_hash(da1, da2, hashaddr, hashmode, hashlen)
            self.mtk.daloader.patch = True
            self.daconfig.da2 = da2[:hashlen]
            # open("/tmp/_da1","wb").write(da1)
            # open("/tmp/_da2", "wb").write(self.daconfig.da2)
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
            bootldr.seek(da1offset)
            # ------------------------------------------------
            da2offset = self.daconfig.da_loader.region[2].m_buf
            bootldr.seek(da2offset)
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
            if self.patch or not self.config.target_config["sbc"] and not self.config.stock:
                da1, da2 = self.patch_da(da1, da2)
                self.patch = True
                self.daconfig.da2 = da2
            else:
                self.patch = False
            self.daconfig.da2 = da2[:-da2sig_len]

            if self.mtk.preloader.send_da(da1address, da1size, da1sig_len, da1):
                self.info("Successfully uploaded stage 1, jumping ..")
                if self.mtk.preloader.jump_da(da1address):
                    cmd, result = self.get_command_result()
                    if cmd == "CMD:START":
                        self.setup_env()
                        self.setup_hw_init()
                        self.setup_host_info()
                        return True
                    else:
                        return False
                else:
                    self.error("Error on jumping to DA.")
            else:
                self.error("Error on sending DA.")
        return False

    def setup_hw_init(self):
        self.send_command(self.Cmd.cmd_host_supported_commands(
            host_capability="CMD:DOWNLOAD-FILE^1@CMD:FILE-SYS-OPERATION^1@CMD:PROGRESS-REPORT^1@CMD:UPLOAD-FILE^1@"))
        self.send_command(self.Cmd.cmd_notify_init_hw())
        return True

    def setup_host_info(self, hostinfo: str = ""):
        res = self.send_command(self.Cmd.cmd_set_host_info(hostinfo))
        return res

    def write_register(self, addr, data):
        result = self.send_command(self.Cmd.cmd_write_reg(bit_width=32, base_address=addr))
        if type(result) is DwnFile:
            if self.upload(result, data):
                self.info("Successfully wrote data.")
                return True
        return False

    def read_efuse(self):
        tmp = self.Cmd.cmd_read_efuse()
        self.send_command(tmp)
        cmd, result = self.get_command_result()
        # CMD:END
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                return result
        return None

    def read_register(self, addr):
        tmp = self.Cmd.cmd_read_reg(base_address=addr)
        if self.send_command(tmp):
            cmd, data = self.get_command_result()
            if cmd != '':
                return False
            # CMD:END
            scmd, sresult = self.get_command_result()
            self.ack()
            if sresult == "OK":
                tcmd, tresult = self.get_command_result()
                if tresult == "START":
                    return data
            return None

    def get_command_result(self):
        data = self.get_response()
        cmd = get_field(data, "command")
        result = ""
        if cmd == '' and "OK@" in data:
            tmp = data.split("@")[1]
            length = int(tmp[2:], 16)
            self.ack()
            sresp = self.get_response()
            if "OK" in sresp:
                self.ack()
                data = bytearray()
                bytesread = 0
                bytestoread = length
                while bytestoread > 0:
                    tmp = self.get_response_data()
                    bytestoread -= len(tmp)
                    bytesread += len(tmp)
                    data.extend(tmp)
                self.ack()
                return cmd, data
        if cmd == "CMD:PROGRESS-REPORT":
            """
            <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version>
            <command>CMD:PROGRESS-REPORT</command>
            <arg>
                <message>init-hw</message>
            </arg></host>
            """
            self.ack()
            data = ""
            while data != "OK!EOT":
                data = self.get_response()
                self.ack()
            data = self.get_response()
            cmd = get_field(data, "command")
        if cmd == "CMD:START":
            self.ack()
            return cmd, "START"
        if cmd == "CMD:DOWNLOAD-FILE":
            """
            <?xml version="1.0" encoding="utf-8"?><host><version>1.0</version>
            <command>CMD:DOWNLOAD-FILE</command>
            <arg>
                <checksum>CHK_NO</checksum>
                <info>2nd-DA</info>
                <source_file>MEM://0x7fe83c09a04c:0x50c78</source_file>
                <packet_length>0x1000</packet_length>
            </arg></host>
            """
            checksum = get_field(data, "checksum")
            info = get_field(data, "info")
            source_file = get_field(data, "source_file")
            packet_length = int(get_field(data, "packet_length"), 16)
            self.ack()
            return cmd, DwnFile(checksum, info, source_file, packet_length)
        elif cmd == "CMD:UPLOAD-FILE":
            checksum = get_field(data, "checksum")
            info = get_field(data, "info")
            target_file = get_field(data, "target_file")
            packet_length = get_field(data, "packet_length")
            self.ack()
            return cmd, UpFile(checksum, info, target_file, packet_length)
        elif cmd == "CMD:FILE-SYS-OPERATION":
            """
            '<?xml version="1.0" encoding="utf-8"?>
            <host><version>1.0</version>
            <command>CMD:FILE-SYS-OPERATION</command>
            <arg><key>FILE-SIZE</key><file_path>MEM://0x8000000:0x4000000</file_path></arg>
            </host>'
            """
            key = get_field(data, "key")
            file_path = get_field(data, "file_path")
            self.ack()
            return cmd, FileSysOp(key, file_path)
        if cmd == "CMD:END":
            result = get_field(data, "result")
            if "message" in data and result != "OK":
                message = get_field(data, "message")
                return cmd, message
        return cmd, result

    def upload(self, result: DwnFile, data, display=True, raw=False):
        if type(result) is DwnFile:
            # checksum = result.checksum
            # info = result.info
            source_file = result.source_file
            packet_length = result.packet_length
            tmp = source_file.split(":")[2]
            length = int(tmp[2:], 16)
            self.ack_value(length)
            if display:
                self.mtk.daloader.progress.clear()
            resp = self.get_response()
            pos = 0
            bytestowrite=length
            if resp == "OK":
                while bytestowrite>0:
                    self.ack_value(0)
                    resp = self.get_response()
                    if "OK" not in resp:
                        rmsg = get_field(resp, "message")
                        self.error(f"Error on writing stage2 ACK0 at pos {hex(pos)}")
                        self.error(rmsg)
                        return False
                    tmp = data[pos:pos + packet_length]
                    tmplen = len(tmp)
                    self.xsend(data=tmp)
                    resp = self.get_response()
                    if "OK" not in resp:
                        self.error(f"Error on writing stage2 at pos {hex(pos)}")
                        return False
                    pos += tmplen
                    if display:
                        self.mtk.daloader.progress.show_progress("Written", pos, length, display)
                    bytestowrite-=packet_length
                if raw:
                    self.ack()
                cmd, result = self.get_command_result()
                self.ack()
                if cmd == "CMD:END" and result == "OK":
                    cmd, result = self.get_command_result()
                    if cmd == "CMD:START":
                        return True
                else:
                    cmd, startresult = self.get_command_result()
                    self.error(result)
            return False
        else:
            self.error("No upload data received. Aborting.")
            return False

    def download_raw(self, result, filename: str = "", display: bool = False):
        global rq
        if display:
            self.mtk.daloader.progress.clear()
        if type(result) is UpFile:
            # checksum = result.checksum
            # info = result.info
            # target_file = result.target_file
            # packet_length = int(result.packet_length, 16)
            resp = self.get_response()
            if "OK@" in resp:
                tmp = resp.split("@")[1]
                length = int(tmp[2:], 16)
                self.ack()
                sresp = self.get_response()
                if "OK" in sresp:
                    self.ack()
                    data = bytearray()
                    bytesread = 0
                    bytestoread = length
                    worker = None
                    if filename != "":
                        worker = Thread(target=writedata, args=(filename, rq), daemon=True)
                        worker.start()
                    while bytestoread > 0:
                        tmp = self.get_response_data()
                        bytestoread -= len(tmp)
                        bytesread += len(tmp)
                        if filename != "":
                            rq.put(tmp)
                        else:
                            data.extend(tmp)
                        if display:
                            self.mtk.daloader.progress.show_progress("Read", bytesread, length, display)
                        self.ack()
                        sresp = self.get_response()
                        if "OK" not in sresp:
                            break
                        else:
                            self.ack()
                    if filename != "":
                        rq.put(None)
                        worker.join(60)
                        return True
                    return data
            self.error("Error on downloading data:" + resp)
            return False
        else:
            self.error("No download data received. Aborting.")
            return False

    def download(self, result):
        if type(result) is UpFile:
            # checksum = result.checksum
            # info = result.info
            # target_file = result.target_file
            # packet_length = int(result.packet_length, 16)
            resp = self.get_response()
            if "OK@" in resp:
                tmp = resp.split("@")[1]
                length = int(tmp[2:], 16)
                self.ack()
                sresp = self.get_response()
                if "OK" in sresp:
                    self.ack()
                    data = bytearray()
                    bytesread = 0
                    bytestoread = length
                    while bytestoread > 0:
                        tmp = self.get_response_data()
                        bytestoread -= len(tmp)
                        bytesread += len(tmp)
                        data.extend(tmp)
                    self.ack()
                    return data
            self.error("Error on downloading data:" + resp)
            return False
        else:
            self.error("No download data received. Aborting.")
            return False

    def boot_to(self, addr, data, display=True, timeout=0.5):
        result = self.send_command(self.Cmd.cmd_boot_to(at_addr=addr, jmp_addr=addr, length=len(data)))
        if type(result) is DwnFile:
            self.info("Uploading stage 2...")
            if self.upload(result, data):
                self.info("Successfully uploaded stage 2.")
                return True
        else:
            self.error("Wrong boot_to response :(")
        return False

    def handle_sla(self, data=b"\x00" * 0x100, display=True, timeout=0.5):
        result = self.send_command(self.Cmd.cmd_security_set_flash_policy(host_offset=0x8000000, length=len(data)))
        if type(result) is DwnFile:
            self.info("Running sla auth...")
            if self.upload(result, data):
                self.info("Successfully uploaded sla auth.")
                return True
        return False

    def upload_da(self):
        self.daext = False
        loaded = False
        if self.upload_da1():
            self.info("Stage 1 successfully loaded.")
            da2 = self.daconfig.da2
            da2offset = self.daconfig.da_loader.region[2].m_start_addr
            if not self.mtk.daloader.patch and not self.mtk.config.stock:
                if self.carbonara is not None and self.mtk.config.target_config["sbc"]:
                    loaded = self.boot_to(da2offset, da2)
                    if loaded:
                        self.patch = True
                else:
                    loaded = self.boot_to(da2offset, da2)
                    if not loaded:
                        self.daext = False
                        self.patch = False
                    elif self.mtk.config.target_config["sbc"]:
                        self.patch = True
            else:
                loaded = self.boot_to(da2offset, da2)
            if loaded:
                self.info("Successfully uploaded stage 2")
                self.setup_hw_init()
                self.change_usb_speed()
                res = self.check_sla()
                if isinstance(res, bool):
                    if not res:
                        self.info("SLA is disabled")
                    else:
                        self.info("SLA is enabled")
                        rsakey = None
                        from mtkclient.Library.Auth.sla_keys import da_sla_keys, SlaKey
                        for key in da_sla_keys:
                            if isinstance(key, SlaKey):
                                if da2.find(long_to_bytes(key.n)) != -1:
                                    rsakey = key
                        if rsakey is None:
                            print("No valid sla key found, using dummy auth ....")
                            sla_signature = b"\x00" * 0x100
                            if not self.handle_sla(data=sla_signature):
                                print("SLA Key wasn't accepted.")
                        else:
                            self.dev_info = self.get_dev_info()
                            sla_signature = generate_da_sla_signature(data=self.dev_info["rnd"], key=rsakey.key)
                            if not self.handle_sla(data=sla_signature):
                                print("SLA Key wasn't accepted.")
            self.reinit(True)
            self.check_lifecycle()
            if self.patch:
                xmlcmd = self.Cmd.create_cmd("CUSTOM")
                if self.xsend(xmlcmd):
                    # result =
                    data = self.get_response()
                    if data == 'OK':
                        # OUTPUT
                        xdata = self.xmlft.patch()
                        self.xsend(int.to_bytes(len(xdata), 4, 'little'))
                        self.xsend(xdata)
                        # CMD:END
                        # result =
                        self.get_response()
                        self.ack()
                        # CMD:START
                        # result =
                        self.get_response()
                        self.ack()

                        if self.xmlft.ack():
                            self.info("DA XML Extensions successfully loaded.")
                            self.daext = True
                            # self.xmlft.custom_set_storage(ufs=self.daconfig.flashtype == "ufs")
                        else:
                            self.error("DA XML Extensions failed.")
                            self.daext = False
                    else:
                        self.error("DA XML Extensions failed.")
                        self.daext = False
                # parttbl = self.read_partition_table()
                self.config.hwparam.writesetting("hwcode", hex(self.config.hwcode))
                return True
            else:
                return True
        return False

    def get_dev_info(self):
        self.send_command(self.Cmd.cmd_get_dev_info(), noack=True)
        cmd, result = self.get_command_result()
        if not isinstance(result, UpFile):
            return False
        data = self.download(result)
        # CMD:END
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            content = {}
            if b"rnd" in data:
                content["rnd"] = bytes.fromhex(get_field(data, "rnd"))
            if b"hrid" in data:
                content["hrid"] = bytes.fromhex(get_field(data, "hrid"))
            if b"socid" in data:
                content["socid"] = bytes.fromhex(get_field(data, "socid"))
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                return content
        return None

    def get_hw_info(self):
        self.send_command(self.Cmd.cmd_get_hw_info(), noack=True)
        cmd, result = self.get_command_result()
        if not isinstance(result, UpFile):
            return False
        data = self.download(result)
        """
        <?xml version="1.0" encoding="utf-8"?>
        <da_hw_info>
        <version>1.2</version>
        <ram_size>0x100000000</ram_size>
        <battery_voltage>3810</battery_voltage>
        <random_id>4340bfebf6ace4e325f71f7d37ab15aa</random_id>
        <storage>UFS</storage>
        <ufs>
            <block_size>0x1000</block_size>
            <lua0_size>0x400000</lua0_size>
            <lua1_size>0x400000</lua1_size>
            <lua2_size>0xee5800000</lua2_size>
            <lua3_size>0</lua3_size>
            <id>4D54303634474153414F32553231202000000000</id>
        </ufs>
        <product_id></product_id>
        </da_hw_info>
        """
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                storage = get_field(data, "storage")

                class StorageInfo:
                    def __init__(self, storagetype, data):
                        self.storagetype = storagetype
                        if self.storagetype == "UFS":
                            self.block_size = int(get_field(data, "block_size"), 16)
                            self.lua0_size = int(get_field(data, "lua0_size"), 16)
                            self.lua1_size = int(get_field(data, "lua1_size"), 16)
                            self.lua2_size = int(get_field(data, "lua2_size"), 16)
                            self.lua3_size = int(get_field(data, "lua3_size"), 16)
                            self.cid = get_field(data, "id")  # this doesn't exists in Xiaomi DA
                            if not self.cid:
                                self.cid = get_field(data, "ufs_cid")
                        elif self.storagetype == "EMMC":
                            self.block_size = int(get_field(data, "block_size"), 16)
                            self.boot1_size = int(get_field(data, "boot1_size"), 16)
                            self.boot2_size = int(get_field(data, "boot2_size"), 16)
                            self.rpmb_size = int(get_field(data, "rpmb_size"), 16)
                            self.user_size = int(get_field(data, "user_size"), 16)
                            self.gp1_size = int(get_field(data, "gp1_size"), 16)
                            self.gp2_size = int(get_field(data, "gp2_size"), 16)
                            self.gp3_size = int(get_field(data, "gp3_size"), 16)
                            self.gp4_size = int(get_field(data, "gp4_size"), 16)
                            self.cid = get_field(data, "id")  # this doesn't exists in Xiaomi DA
                            if not self.cid:
                                self.cid = get_field(data, "emmc_cid")
                        elif self.storagetype == "NAND":
                            self.block_size = int(get_field(data, "block_size"), 16)
                            self.page_size = int(get_field(data, "page_size"), 16)
                            self.spare_size = int(get_field(data, "spare_size"), 16)
                            self.total_size = int(get_field(data, "total_size"), 16)
                            self.cid = get_field(data, "id")
                            self.page_parity_size = int(get_field(data, "page_parity_size"), 16)
                            self.sub_type = get_field(data, "sub_type")
                        else:
                            self.error(f"Unknown storage type: {storage}")

                return StorageInfo(storagetype=storage, data=data)

    def check_sla(self):
        """
        int RSA_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
                                    0x10,                                                 , 1
        """
        data = self.get_sys_property(key="DA.SLA", length=0x200000)
        data = data.decode('utf-8')
        if "item key=" in data:
            tmp = data[data.find("item key=") + 8:]
            res = tmp[tmp.find(">") + 1:tmp.find("<")]
            return res != "DISABLED"
        else:
            self.error("Couldn't find item key")
        return data

    def get_sys_property(self, key: str = "DA.SLA", length: int = 0x200000):
        self.send_command(self.Cmd.cmd_get_sys_property(key=key, length=length), noack=True)
        cmd, result = self.get_command_result()
        if type(result) is not UpFile:
            return False
        data = self.download(result)
        # CMD:END
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                return data
        return None

    def change_usb_speed(self):
        resp = self.send_command(self.Cmd.cmd_can_higher_usb_speed())
        if not resp:
            return False

    def read_partition_table(self) -> tuple:
        self.send_command(self.Cmd.cmd_read_partition_table(), noack=True)
        cmd, result = self.get_command_result()
        if type(result) is not UpFile:
            return b"", None
        data = self.download(result)
        # CMD:END
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()

            class PartitionTable:
                def __init__(self, name, start, size):
                    self.name = name
                    self.start = start
                    self.size = size

            if tresult == "START":
                parttbl = []
                data = data.decode('utf-8')
                for item in data.split("<pt>"):
                    name = get_field(item, "name")
                    if name != '':
                        start = get_field(item, "start")
                        rsize = get_field(item, "size")
                        if size == "":
                            continue
                        rsize = int(rsize, 16)
                        start = int(start, 16)
                        parttbl.append(
                            PartitionTable(name, start // self.config.pagesize, rsize // self.config.pagesize))
                return data, parttbl
        return b"", None

    def partitiontype_and_size(self, storage=None, parttype=None, length=0):
        if length < 0x20000:
            length = 0x20000
        if storage == DaStorage.MTK_DA_STORAGE_EMMC or storage == DaStorage.MTK_DA_STORAGE_SDMMC:
            storage = 1
            if parttype is None or parttype == "user":
                parttype = "EMMC-USER"
            elif parttype == "boot1":
                parttype = "EMMC-BOOT1"
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.boot1_size)
            elif parttype == "boot2":
                parttype = "EMMC-BOOT2"
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.boot2_size)
            elif parttype == "gp1":
                parttype = "EMMC-GP1"
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.gp1_size)
            else:
                self.error("Unknown parttype. Known parttypes are \"boot1\",\"boot2\",\"gp1\",\"gp2\",\"gp3\",\"gp4\",\"rpmb\"")
                return []
        elif storage == DaStorage.MTK_DA_STORAGE_UFS:
            if parttype is None or parttype == "lu3" or parttype == "user":  # USER
                parttype = "UFS-LUA2"
                length = min(length, self.ufs.lu3_size)
            elif parttype in ["lu1", "boot1"]:  # BOOT1
                parttype = "UFS-LUA0"
                length = min(length, self.ufs.lu1_size)
            elif parttype in ["lu2", "boot2"]:  # BOOT2
                parttype = "UFS-LUA1"
                length = min(length, self.ufs.lu2_size)
            elif parttype in ["lu4", "rpmb"]:  # RPMB
                parttype = "UFS-LUA3"
                length = min(length, self.ufs.lu4_size)
            else:
                self.error("Unknown parttype. Known parttypes are \"lu1\",\"lu2\",\"lu3\",\"lu4\"")
                return []
        elif storage in [DaStorage.MTK_DA_STORAGE_NAND, DaStorage.MTK_DA_STORAGE_NAND_MLC,
                         DaStorage.MTK_DA_STORAGE_NAND_SLC, DaStorage.MTK_DA_STORAGE_NAND_TLC,
                         DaStorage.MTK_DA_STORAGE_NAND_SPI, DaStorage.MTK_DA_STORAGE_NAND_AMLC]:
            parttype = "NAND-WHOLE"  # NAND-AREA0
            length = min(length, self.nand.total_size)
        elif storage in [DaStorage.MTK_DA_STORAGE_NOR, DaStorage.MTK_DA_STORAGE_NOR_PARALLEL,
                         DaStorage.MTK_DA_STORAGE_NOR_SERIAL]:
            parttype = "NOR-WHOLE"  # NOR-AREA0
            length = min(length, self.nor.available_size)
        return [storage, parttype, length]

    def getstorage(self, parttype, length):
        if self.daconfig.flashtype == "nor":
            storage = DaStorage.MTK_DA_STORAGE_NOR
        elif self.daconfig.flashtype == "nand":
            storage = DaStorage.MTK_DA_STORAGE_NAND
        elif self.daconfig.flashtype == "ufs":
            storage = DaStorage.MTK_DA_STORAGE_UFS
            if parttype == EmmcPartitionType.MTK_DA_EMMC_PART_USER:
                parttype = UFSPartitionType.UFS_LU3
        elif self.daconfig.flashtype == "sdc":
            storage = DaStorage.MTK_DA_STORAGE_SDMMC
        else:
            storage = DaStorage.MTK_DA_STORAGE_EMMC

        part_info = self.partitiontype_and_size(storage, parttype, length)
        return part_info

    def readflash(self, addr, length, filename, parttype=None, display=True) -> (bytes, bool):
        global rq
        if parttype is None:
            if self.daconfig.flashtype == "emmc":
                parttype = "user"
            elif self.daconfig.flashtype == "ufs":
                parttype = "lu3"
        partinfo = self.getstorage(parttype, length)
        if not partinfo:
            return b""
        self.mtk.daloader.progress.clear()
        storage, parttype, length = partinfo

        if self.send_command(self.Cmd.cmd_read_flash(parttype, addr, length), noack=True):
            cmd, result = self.get_command_result()
            if type(result) is not UpFile:
                return b""
            data = self.download_raw(result=result, filename=filename, display=display)
            scmd, sresult = self.get_command_result()
            if sresult == "START":
                if not filename:
                    return data
                else:
                    return True
            if not filename:
                return b""
            return False
        else:
            self.error("Read flash isn't supported")
            return False

    def writeflash(self, addr, length, filename, offset=0, parttype=None, wdata=None, display=True):
        self.mtk.daloader.progress.clear()
        fh = None
        if filename != "":
            if os.path.exists(filename):
                fsize = os.stat(filename).st_size
                length = min(fsize, length)
                if length % 512 != 0:
                    fill = 512 - (length % 512)
                    length += fill
                fh = open(filename, "rb")
                fh.seek(offset)
            else:
                self.error(f"Filename doesn't exists: {filename}, aborting flash write.")
                return False

        if parttype is None:
            if self.daconfig.flashtype == "emmc":
                parttype = "user"
            elif self.daconfig.flashtype == "ufs":
                parttype = "lu3"
        partinfo = self.getstorage(parttype, length)
        if not partinfo:
            return False
        storage, parttype, rlength = partinfo

        self.send_command(self.Cmd.cmd_write_flash(partition=parttype, offset=addr, mem_length=length), noack=True)
        cmd, fileopresult = self.get_command_result()
        if type(fileopresult) is FileSysOp:
            if fileopresult.key != "FILE-SIZE":
                return False
            self.ack_value(length)
            cmd, result = self.get_command_result()
            if type(result) is DwnFile:
                if fh:
                    data = fh.read(length)
                else:
                    data = wdata
                if not self.upload(result, data, raw=True):
                    self.error("Error on writing flash at 0x%08X" % addr)
                    return False
                if fh:
                    fh.close()
                return True
        if fh:
            fh.close()
        return False

    def check_lifecycle(self):
        self.send_command(self.Cmd.cmd_emmc_control(function="LIFE-CYCLE-STATUS"), noack=True)
        cmd, result = self.get_command_result()
        if not isinstance(result, UpFile):
            if cmd == 'CMD:END':
                self.ack()
                scmd, sresult = self.get_command_result()
            return False
        data = self.download(result)
        scmd, sresult = self.get_command_result()
        self.ack()
        if sresult == "OK":
            tcmd, tresult = self.get_command_result()
            if tresult == "START":
                return data == b"OK\x00"
        return False

    def reinit(self, display=False):
        """
        self.config.sram, self.config.dram = self.get_ram_info()
        self.emmc = self.get_emmc_info(display)
        self.nand = self.get_nand_info(display)
        self.nor = self.get_nor_info(display)
        self.ufs = self.get_ufs_info(display)
        """
        self.storage = self.get_hw_info()
        display = display
        if isinstance(self.storage, bool):
            self.error("Error: Cannot Reinit daconfig")
            return
        if self.storage.storagetype == "EMMC":
            self.daconfig.flashtype = "emmc"
            self.daconfig.flashsize = self.storage.user_size
            self.daconfig.rpmbsize = self.storage.rpmb_size
            self.daconfig.boot1size = self.storage.boot1_size
            self.daconfig.boot2size = self.storage.boot2_size

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

            self.emmc = EmmcInfo()
            self.emmc.gp1_size = self.storage.gp1_size
            self.emmc.gp2_size = self.storage.gp2_size
            self.emmc.gp3_size = self.storage.gp3_size
            self.emmc.gp4_size = self.storage.gp4_size
            self.emmc.rpmb_size = self.storage.rpmb_size
            self.emmc.boot1_size = self.storage.boot1_size
            self.emmc.boot2_size = self.storage.boot2_size
        elif self.storage.storagetype == "NAND":
            self.daconfig.flashtype = "nand"
            self.daconfig.flashsize = self.storage.total_size
            self.daconfig.rpmbsize = 0
            self.daconfig.boot1size = 0x400000
            self.daconfig.boot2size = 0x400000
        elif self.storage.storagetype == "UFS":
            self.daconfig.flashtype = "ufs"
            self.daconfig.flashsize = self.storage.lua0_size
            self.daconfig.rpmbsize = self.storage.lua1_size
            self.daconfig.boot1size = self.storage.lua1_size
            self.daconfig.boot2size = self.storage.lua2_size
            self.config.pagesize = 4096

            class UfsInfo:
                type = 1  # nor, none
                block_size = 0
                lu1_size = 0
                lu2_size = 0
                lu3_size = 0
                lu4_size = 0
                cid = b""
                fwver = b""
                serial = b""

            self.ufs = UfsInfo()
            self.ufs.lu1_size = self.storage.lua0_size
            self.ufs.lu2_size = self.storage.lua1_size
            self.ufs.lu3_size = self.storage.lua2_size
            self.ufs.lu4_size = self.storage.lua3_size
        """
        self.chipid = self.get_chip_id()
        self.daversion = self.get_da_version()
        self.randomid = self.get_random_id()
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
        """

    def formatflash(self, addr, length, storage=None,
                    parttype=None, display=False):
        self.mtk.daloader.progress.clear()
        part_info = self.getstorage(parttype, length)
        if not part_info:
            return False
        storage, parttype, length = part_info
        if display:
            self.info(f"Formatting addr {hex(addr)} with length {hex(length)}, please standby....")
        self.mtk.daloader.progress.show_progress("Erasing", 0, length, True)
        self.send_command(self.Cmd.cmd_erase_flash(partition=parttype, offset=addr, length=length))
        result = self.get_response()
        if result == "OK":
            if display:
                self.info(f"Successsfully formatted addr {hex(addr)} with length {length}.")
            return True
        if display:
            self.error("Error on format.")
        return False

    def shutdown(self, async_mode: int = 0, dl_bit: int = 0, bootmode: ShutDownModes = ShutDownModes.NORMAL):
        if bootmode == ShutDownModes.FASTBOOT:
            self.send_command(self.Cmd.cmd_set_boot_mode(mode=BootModes.fastboot))
        elif bootmode == ShutDownModes.TEST:
            self.send_command(self.Cmd.cmd_set_boot_mode(mode=BootModes.testmode))
        elif bootmode == ShutDownModes.META:
            self.send_command(self.Cmd.cmd_set_boot_mode(mode=BootModes.meta))
        if self.send_command(self.Cmd.cmd_reboot(disconnect=False)):
            self.mtk.port.close(reset=True)
            return True
        else:
            self.error("Error on sending reboot")
        self.mtk.port.close(reset=True)
        return False
