import os
import time
import sys
import logging
from struct import pack, unpack
from binascii import hexlify

from mtkclient.Library.mtk_crypto import calc_checksum, decode_imei, is_luhn_valid, encode_imei, decrypt_cssd, \
    create_cssd, patch_md1img, make_luhn_checksum
from mtkclient.Library.utils import getint, find_binary
from mtkclient.Library.gui_utils import LogBase, logsetup, progress
from mtkclient.config.payloads import PathConfig
from mtkclient.Library.error import ErrorHandler
from mtkclient.config.brom_config import Efuse, DAmodes
from mtkclient.Library.Filesystem.mtkdafs import MtkDaFS

try:
    from fuse import FUSE
except ImportError:
    FUSE = None


class efuse_runtime_def:
    addr = None
    mask = None
    ecc_type = None
    ecc_group = None
    ecc_dw = None
    ecc_address = None
    ecc_mask = None
    field_type = None

    def __init__(self, fields):
        self.addr = fields[0]
        self.mask = fields[1]
        dd = bytearray(int.to_bytes(fields[2], 4, 'little'))
        self.ecc_type = dd[1]
        self.ecc_group = dd[2]
        self.ecc_dw = dd[3]
        self.ecc_address = fields[3]
        self.ecc_mask = fields[4]
        self.field_type = fields[5]


class DaHandler(metaclass=LogBase):
    def __init__(self, mtk, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.config = mtk.config
        self.loader = mtk.config.loader
        self.vid = mtk.config.vid
        self.pid = mtk.config.pid
        self.interface = mtk.config.interface
        self.pathconfig = PathConfig()
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.eh = ErrorHandler()
        self.mtk = mtk

    @staticmethod
    def close():
        sys.exit(0)

    def dump_preloader_ram(self, write_preloader_to_file: bool = False):
        try:
            data = (b"".join([pack("<I", val) for val in self.mtk.preloader.read32(0x200000, 0x10000 // 4)]))
            idx = data.find(b"\x4D\x4D\x4D\x01\x38\x00\x00\x00")
            if idx != -1:
                data = data[idx:]
                length = unpack("<I", data[0x20:0x24])[0]
                time.sleep(0.15)
                data = bytearray()
                startidx = idx
                multiplier = 32
                while True:
                    try:
                        data.extend(b"".join(
                            [pack("<I", val) for val in self.mtk.preloader.read32(0x200000 + idx, (4 * multiplier))]))
                        idx = idx + (16 * multiplier)
                        # sys.stdout.write("\r"+str(length-(idx-startidx)))
                        # sys.stdout.flush()                        sys.stdout.write("\r"+str(length-(idx-startidx)))
                        if (idx - startidx) > length:
                            # done reading
                            break
                    except Exception as err:
                        self.error(str(err))
                        break
                data = bytes(data)
                preloader = data[:length]
                idx = data.find(b"MTK_BLOADER_INFO")
                if idx != -1:
                    filename = data[idx + 0x1B:idx + 0x1B + 0x30].rstrip(b"\x00").decode('utf-8')
                    if preloader is not None:
                        if not os.path.exists(filename) and write_preloader_to_file:
                            try:
                                with open(filename, "wb") as wf:
                                    wf.write(preloader)
                                    print(f"Successfully extracted preloader for this device to: {filename}")
                            except Exception as err:
                                self.error(err)
                                pass
                return preloader
        except Exception as err:
            self.error(str(err))
            return None

    def configure_da(self, mtk, directory: str = None):
        if directory is None:
            directory = "."
        mtk.port.cdc.connected = mtk.port.cdc.connect()
        if mtk.port.cdc.connected is None or not mtk.port.cdc.connected or mtk.serialportname is not None:
            mtk.preloader.init(directory=directory)
        else:
            if mtk.serialportname is not None:
                mtk.preloader.init()
            if directory:
                self.mtk.config.hwparam_path = directory
            if mtk.port.cdc.connected and os.path.exists(os.path.join(mtk.config.hwparam_path, ".state")):
                mtk.daloader.reinit()
                return mtk
        if mtk.config.target_config is None:
            self.info("Please disconnect, start mtkclient and reconnect.")
            return None
        if mtk.config.target_config["sbc"] and not mtk.config.is_brom and mtk.config.loader is None:
            mtk = mtk.bypass_security()
            self.mtk = mtk
            if self.mtk.daloader.patch:
                self.info("Device was protected. Successfully bypassed security.")
            else:
                self.info("Device is still protected, trying to boot to brom")
                try:
                    if not mtk.config.loader:
                        if not mtk.config.is_brom:
                            self.mtk.preloader.reset_to_brom()
                except Exception:
                    pass
            if mtk is not None:
                if mtk.config.is_brom and self.mtk.daloader.patch:
                    self.info("Device is in BROM mode. Trying to dump preloader.")
                    if mtk.config.preloader is None:
                        mtk.config.preloader = self.dump_preloader_ram(
                                                    write_preloader_to_file=self.mtk.config.write_preloader_to_file)
        else:
            if mtk.config.target_config["sbc"]:
                self.info("Device is protected.")
            else:
                self.info("Device is unprotected.")
            if mtk.config.is_brom and not mtk.config.iot:
                self.info("Device is in BROM-Mode. Bypassing security.")
                mtk.daloader.patch = False
                hassecurity = (self.mtk.config.target_config["sla"] or self.mtk.config.target_config["daa"] or
                               self.mtk.config.target_config["sbc"])
                bypassedsecurity = False
                if not hassecurity:
                    mtk.daloader.patch = True
                    self.info("Unprotected device, we assume we can patch directly !")
                else:
                    if not self.mtk.config.stock:
                        mtk = mtk.bypass_security()  # Needed for dumping preloader
                        bypassedsecurity = True
                    else:
                        self.info("Using supplied preloader. Skipping exploitation!")

                if mtk is not None:
                    self.mtk = mtk
                    if mtk.config.preloader is None:
                        if self.mtk.config.chipconfig.damode != 6 and self.mtk.config.is_brom and bypassedsecurity:
                            self.warning(
                                "Device is in BROM mode. No preloader given, trying to dump preloader from ram.")
                            preloader = self.dump_preloader_ram(
                                        write_preloader_to_file=self.mtk.config.write_preloader_to_file)
                            if preloader is None:
                                self.error("Failed to dump preloader from ram, provide a valid one " +
                                           "via --preloader option")
                                mtk.daloader.patch = False
                            else:
                                mtk.daloader.patch = True
                                mtk.config.preloader = preloader
                        else:
                            self.error("Failed to dump preloader from ram, provide a valid one " +
                                       "via --preloader option")
            elif not mtk.config.is_brom:
                self.info("Device is in Preloader-Mode.")
                mtk.daloader.patch = False
            else:
                self.info("Device is in BROM-Mode - Iot Mode.")
                mtk.daloader.patch = False

        if not mtk.daloader.upload_da(preloader=mtk.config.preloader):
            self.error("Failed to upload da.")
            sys.exit(1)
        else:
            mtk.daloader.writestate()
            return mtk

    def patch_vbmeta(self, vbmeta: bytes, vbmode: int):
        vbmeta = bytearray(vbmeta)
        DISABLE_VERITY = 1
        DISABLE_VERIFICATION = 2
        if vbmode == DISABLE_VERIFICATION:
            self.info("Patching verification")
        elif vbmode == DISABLE_VERITY:
            self.info("Patching verity")
        elif vbmode == DISABLE_VERIFICATION | DISABLE_VERITY:
            self.info("Patching verification + verity")
        elif vbmode == 0:
            self.info("Enable verification + verity")
        else:
            self.error(f"Invalid mode: {vbmode}")
            return None
        vbmeta[0x78:0x78 + 4] = int.to_bytes(vbmode, 4, 'big')
        return vbmeta

    def da_vbmeta(self, vbmode: int = 3, display: bool = True):
        gpttable = self.mtk.daloader.get_partition_data(parttype="user")
        slot = self.get_current_slot()
        partition = "vbmeta" + slot
        rpartition = None
        for gptentry in gpttable:
            if gptentry.name.lower() == partition.lower():
                rpartition = gptentry
                break
        if rpartition is not None:
            if display:
                self.info(f'Dumping partition "{rpartition.name}"')
            vbmeta = self.mtk.daloader.readflash(addr=rpartition.sector * self.config.pagesize,
                                                 length=rpartition.sectors * self.config.pagesize,
                                                 filename="", parttype="user",
                                                 display=display)
            if vbmeta != b"":
                if display:
                    self.info(f'Patching {partition}"')
                patched_vbmeta = self.patch_vbmeta(vbmeta, vbmode)
                if display:
                    self.info(f'Writing partition "{rpartition.name}"')
                if self.mtk.daloader.writeflash(addr=rpartition.sector * self.config.pagesize,
                                                length=rpartition.sectors * self.config.pagesize,
                                                wdata=patched_vbmeta, parttype="user",
                                                display=display):
                    if display:
                        self.info("Successfully patched vbmeta :)")
                else:
                    if display:
                        self.error("Error on patching vbmeta :(")

    def da_gpt(self, directory: str, display: bool = True):
        if directory is None:
            directory = ""

        sfilename = os.path.join(directory, "gpt.bin")
        data, guid_gpt = self.mtk.daloader.get_gpt()
        if guid_gpt is None:
            self.error("Error reading gpt")
            self.close()
        else:
            with open(sfilename, "wb") as wf:
                wf.write(data)

            if display:
                print(f"Dumped GPT from to {sfilename}")
            sfilename = os.path.join(directory, "gpt_backup.bin")
            with open(sfilename, "wb") as wf:
                wf.write(data[self.mtk.daloader.daconfig.pagesize:])
            if display:
                print(f"Dumped Backup GPT to {sfilename}")

    def da_read_partition(self, partitionname, parttype="user", display: bool = True):
        rpartition = None
        gpttable = self.mtk.daloader.get_partition_data(parttype=parttype)
        for gptentry in gpttable:
            if gptentry.name.lower() == partitionname.lower():
                rpartition = gptentry
                break
        if rpartition is not None:
            if display:
                self.info(f'Dumping partition "{rpartition.name}"')
            data = self.mtk.daloader.readflash(addr=rpartition.sector * self.config.pagesize,
                                               length=rpartition.sectors * self.config.pagesize,
                                               filename="", parttype=parttype, display=display)
            return data
        return b""

    def da_write_partition(self, partitionname, data: bytes = None, parttype="user", display: bool = True):
        rpartition = None
        gpttable = self.mtk.daloader.get_partition_data(parttype=parttype)
        for gptentry in gpttable:
            if gptentry.name.lower() == partitionname.lower():
                rpartition = gptentry
                break
        if rpartition is not None:
            if display:
                self.info(f'Writing partition "{rpartition.name}"')
            res = self.mtk.daloader.writeflash(addr=rpartition.sector * self.config.pagesize,
                                               length=rpartition.sectors * self.config.pagesize,
                                               filename="", parttype=parttype, wdata=data, display=display)
            return res
        return None

    def da_read(self, partitionname, parttype, filename, offset: int = None, length: int = None, display: bool = True):
        if offset is None:
            offset = 0
        filenames = filename.split(",")
        partitions = partitionname.split(",")
        if len(partitions) != len(filenames):
            if display:
                self.error("You need to gives as many filenames as given partitions.")
            self.close()
        if parttype == "user" or parttype is None:
            i = 0
            count_dump = 0
            if display:
                self.info("Requesting available partitions ....")
            gpttable = self.mtk.daloader.get_partition_data(parttype=parttype)
            for partition in partitions:
                partfilename = filenames[i]
                i += 1
                if partition == "gpt":
                    self.mtk.daloader.readflash(addr=0,
                                                length=0x16000,
                                                filename=partfilename,
                                                parttype=parttype,
                                                display=display)
                    count_dump += 1
                    continue
                else:
                    rpartition = None
                    for gptentry in gpttable:
                        if gptentry.name.lower() == partition.lower():
                            rpartition = gptentry
                            break
                    if rpartition is not None:
                        if length is None:
                            length = rpartition.sectors * self.config.pagesize
                        if display:
                            self.info(f'Dumping partition "{rpartition.name}"')
                        if self.mtk.daloader.readflash(addr=(rpartition.sector * self.config.pagesize) + offset,
                                                       length=length,
                                                       filename=partfilename, parttype=parttype, display=display):
                            if display:
                                self.info(f"Dumped sector {str(rpartition.sector)} with sector count " +
                                          f"{str(rpartition.sectors)} as {partfilename}.")
                            count_dump += 1
                        else:
                            if display:
                                self.info(f"Failed to dump sector {str(rpartition.sector)} with sector count " +
                                          f"{str(rpartition.sectors)} as {partfilename}.")
                            count_dump += 1
                    else:
                        if display:
                            self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                        for rpartition in gpttable:
                            if display:
                                self.info(rpartition.name)
            if count_dump > 1 and count_dump == len(filenames):
                if display:
                    self.info("All partitions were dumped")
            elif count_dump > 1 and count_dump != len(filenames):
                if display:
                    self.info("Failed to dump some partitions")
        else:
            i = 0
            for partfilename in filenames:
                pos = 0
                if self.mtk.daloader.readflash(addr=pos, length=0xFFFFFFFF, filename=partfilename,
                                               parttype=parttype, display=display):
                    if display:
                        print(f"Dumped partition {str(partitionname)} as {partfilename}.")
                else:
                    if display:
                        print(f"Failed to dump partition {str(partitionname)} as {partfilename}.")
                i += 1

    def da_rl(self, directory, parttype, skip, display: bool = True):
        if not os.path.exists(directory):
            os.mkdir(directory)
        data, guid_gpt = self.mtk.daloader.get_gpt(parttype=parttype)
        if not guid_gpt:
            if display:
                self.error("Couldn't get gpt :(")
            # No partitions detected, try reading flash
            filename = os.path.join(directory, "flash.bin")
            if display:
                self.warning(f"No partition table detected, reading flash instead to {filename}...")
            return self.da_rf(filename=filename, parttype="user", display=True)
        storedir = directory
        if not os.path.exists(storedir):
            os.mkdir(storedir)
        sfilename = os.path.join(storedir, "gpt.bin")
        with open(sfilename, "wb") as wf:
            wf.write(data)

        sfilename = os.path.join(storedir, "gpt_backup.bin")
        with open(sfilename, "wb") as wf:
            wf.write(data)

        count_gpt = 0
        for partition in guid_gpt.partentries:
            partitionname = partition.name
            if partition.name in skip:
                continue
            filename = os.path.join(storedir, partitionname + ".bin")
            if display:
                self.info(
                    f"Dumping partition {str(partition.name)} with sector count {str(partition.sectors)} " +
                    f"as {filename}.")

            if self.mtk.daloader.readflash(addr=partition.sector * self.config.pagesize,
                                           length=partition.sectors * self.config.pagesize,
                                           filename=filename,
                                           parttype=parttype,
                                           display=display):

                count_gpt += 1
                if display:
                    self.info(f"Dumped partition {str(partition.name)} as {str(filename)}.")
            else:
                count_gpt -= 1
                if display:
                    self.error(f"Failed to dump partition {str(partition.name)} as {str(filename)}.")

        partitions_for_read = len(guid_gpt.partentries) - len(skip)
        if count_gpt == partitions_for_read:
            if display:
                self.info("All Dumped partitions success.")
        else:
            if display:
                self.error("Failed to dump all partitions")

    def da_rf(self, filename, parttype, offset: int = None, length: int = None, display: bool = True):
        if length is None:
            if self.mtk.daloader.daconfig.storage.flashtype == "ufs":
                if parttype == "lu0":
                    length = self.mtk.daloader.daconfig.storage.ufs.lu0_size
                elif parttype == "lu1":
                    length = self.mtk.daloader.daconfig.storage.ufs.lu1_size
                elif parttype == "lu2":
                    length = self.mtk.daloader.daconfig.storage.ufs.lu2_size
                elif parttype == "user":
                    length = self.mtk.daloader.daconfig.storage.flashsize
                else:
                    if self.mtk.daloader.daconfig.storage.flashsize > self.mtk.daloader.daconfig.storage.ufs.lu3_size:
                        length = self.mtk.daloader.daconfig.storage.flashsize
                    else:
                        length = self.mtk.daloader.daconfig.storage.ufs.lu3_size
            else:
                length = self.mtk.daloader.daconfig.storage.flashsize
            if self.mtk.config.hwcode in [0x2625, 0x2523, 0x7682, 0x7686, 0x5932]:
                length = self.mtk.daloader.daconfig.legacy_storage.nor.m_nor_flash_size
        if offset is None:
            if self.mtk.config.hwcode in [0x2625, 0x2523, 0x7682, 0x7686, 0x5932]:
                length = self.mtk.daloader.daconfig.legacy_storage.nor.m_nor_flash_size
                addr = self.mtk.daloader.daconfig.legacy_storage.nor.m_nor_base_addr
            else:
                addr = 0
        else:
            addr = offset
        if display:
            print(
                f"Dumping sector {addr // self.config.pagesize}/addr {hex(addr)} with flash size {hex(length)} as {filename}.")
        sys.stdout.flush()
        if self.mtk.daloader.readflash(addr=addr, length=length, filename=filename, parttype=parttype, display=display):
            if display:
                print(
                    f"Dumped sector {addr // self.config.pagesize}/addr {hex(addr)} with flash size {hex(length)} as {filename}.")
        else:
            if display:
                print(
                    f"Failed to dump sector {addr // self.config.pagesize}/addr {hex(addr)} with flash size {hex(length)} as {filename}.")

    def da_rs(self, start: int, sectors: int, filename: str, parttype: str, display: bool = True):
        return self.mtk.daloader.readflash(addr=start * self.config.pagesize,
                                           length=sectors * self.config.pagesize,
                                           filename=filename, parttype=parttype, display=display)

    def da_ro(self, start: int, length: int, filename: str, parttype: str, display: bool = True):
        return self.mtk.daloader.readflash(addr=start,
                                           length=length,
                                           filename=filename, parttype=parttype, display=display)

    def da_footer(self, filename: str):
        data, guid_gpt = self.mtk.daloader.get_gpt()
        if guid_gpt is None:
            self.error("Error reading gpt")
            return
        else:
            pnames = ["userdata2", "metadata", "userdata", "reserved1", "reserved2", "reserved3"]
            for partition in guid_gpt.partentries:
                if partition.name in pnames:
                    print(f"Detected partition: {partition.name}")
                    if partition.name in ["userdata2", "userdata"]:
                        data = self.mtk.daloader.readflash(
                            addr=(partition.sector + partition.sectors) * self.config.pagesize - 0x4000,
                            length=0x4000, filename="", parttype="user", display=False)
                    else:
                        data = self.mtk.daloader.readflash(addr=partition.sector * self.config.pagesize,
                                                           length=0x4000, filename="", parttype="user",
                                                           display=False)
                    if data == b"":
                        continue
                    val = unpack("<I", data[:4])[0]
                    if (val & 0xFFFFFFF0) == 0xD0B5B1C0:
                        with open(filename, "wb") as wf:
                            wf.write(data)
                            print(f"Dumped footer from {partition.name} as {filename}.")
                            return
        self.error("Error: Couldn't detect footer partition.")

    def da_write(self, parttype: str, filenames: list, partitions: list):
        if len(partitions) != len(filenames):
            self.error("You need to gives as many filenames as given partitions.")
            self.close()
            exit(0)
        if parttype == "user" or parttype is None:
            i = 0
            for partition in partitions:
                partfilename = filenames[i]
                i += 1
                if partition == "gpt":
                    self.mtk.daloader.writeflash(addr=0,
                                                 length=os.stat(partfilename).st_size,
                                                 filename=partfilename,
                                                 parttype=parttype)
                    continue
                res = self.mtk.daloader.detect_partition(partition, parttype)
                if res[0]:
                    rpartition = res[1]
                    if self.mtk.daloader.writeflash(addr=rpartition.sector * self.config.pagesize,
                                                    length=rpartition.sectors * self.config.pagesize,
                                                    filename=partfilename,
                                                    parttype=parttype):
                        print(
                            f"Wrote {partfilename} to sector {str(rpartition.sector)} with " +
                            f"sector count {str(rpartition.sectors)}.")
                    else:
                        print(
                            f"Failed to write {partfilename} to sector {str(rpartition.sector)} with " +
                            f"sector count {str(rpartition.sectors)}.")
                else:
                    self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for rpartition in res[1]:
                        self.info(rpartition.name)
        else:
            pos = 0
            for partfilename in filenames:
                size = os.stat(partfilename).st_size
                if self.mtk.daloader.writeflash(addr=pos, length=size, filename=partfilename,
                                                parttype=parttype):
                    print(f"Wrote {partfilename} to sector {str(pos // 0x200)} with " +
                          f"sector count {str(size)}.")
                else:
                    print(f"Failed to write {partfilename} to sector {str(pos // 0x200)} with " +
                          f"sector count {str(size)}.")
                psize = size // 0x200 * 0x200
                if size % 0x200 != 0:
                    psize += 0x200
                pos += psize

    def da_wl(self, parttype: str, directory: str):
        filenames = []
        for dirName, subdirList, fileList in os.walk(directory):
            for fname in fileList:
                filenames.append(os.path.join(dirName, fname))

        if parttype == "user" or parttype is None:
            i = 0
            for partfilename in filenames:
                partition = os.path.basename(partfilename)
                partition = os.path.splitext(partition)[0]
                i += 1
                if partition == "gpt":
                    self.info(f"Writing partition {partition}")
                    if self.mtk.daloader.writeflash(addr=0,
                                                    length=os.stat(partfilename).st_size,
                                                    filename=partfilename,
                                                    parttype=parttype):
                        print(f"Wrote {partition} to sector {str(0)}")
                    else:
                        print(f"Failed to write {partition} to sector {str(0)}")
                    continue
                res = self.mtk.daloader.detect_partition(partition, parttype)
                if res[0]:
                    rpartition = res[1]
                    if self.mtk.daloader.writeflash(addr=rpartition.sector * self.config.pagesize,
                                                    length=rpartition.sectors * self.config.pagesize,
                                                    filename=partfilename,
                                                    parttype=parttype):
                        print(
                            f"Wrote {partfilename} to sector {str(rpartition.sector)} with " +
                            f"sector count {str(rpartition.sectors)}.")
                    else:
                        print(
                            f"Failed to write {partfilename} to sector {str(rpartition.sector)} with " +
                            f"sector count {str(rpartition.sectors)}.")
                else:
                    self.error(f"Error: Couldn't detect partition: {partition}\n, skipping")
        else:
            pos = 0
            for partfilename in filenames:
                size = os.stat(partfilename).st_size
                partition = os.path.basename(partfilename)
                partition = os.path.splitext(partition)[0]
                self.info(f"Writing filename {partfilename}")
                if self.mtk.daloader.writeflash(addr=pos, length=size, filename=partfilename,
                                                partitionname=partition,
                                                parttype=parttype):
                    print(f"Wrote {partfilename} to sector {str(pos // 0x200)} with " +
                          f"sector count {str(size)}.")
                else:
                    print(f"Failed to write {partfilename} to sector {str(pos // 0x200)} with " +
                          f"sector count {str(size)}.")
                psize = size // 0x200 * 0x200
                if size % 0x200 != 0:
                    psize += 0x200
                pos += psize

    def da_wo(self, start: int, length: int, filename: str, parttype: str):
        return self.mtk.daloader.writeflash(addr=start,
                                            length=length,
                                            filename=filename,
                                            parttype=parttype)

    def da_erase(self, partitions: list, parttype: str):
        count_fp = 0
        if parttype == "user" or parttype is None:
            i = 0
            for partition in partitions:
                i += 1
                res = self.mtk.daloader.detect_partition(partition, parttype)
                if res[0]:
                    rpartition = res[1]
                    if self.mtk.daloader.formatflash(addr=rpartition.sector * self.config.pagesize,
                                                     length=rpartition.sectors * self.config.pagesize,
                                                     partitionname=partition, parttype=parttype):
                        print(
                            f"Formatted sector {str(rpartition.sector)} with " +
                            f"sector count {str(rpartition.sectors)}.")
                        count_fp += 1
                    else:
                        print(
                            f"Failed to format sector {str(rpartition.sector)} with " +
                            f"sector count {str(rpartition.sectors)}.")
                        count_fp -= 1
                else:
                    self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for rpartition in res[1]:
                        self.info(rpartition.name)
        elif parttype in ["boot1","boot2"]:
            if self.mtk.daloader.formatflash(addr=0,
                                             length=0x40000,
                                             partitionname=parttype, parttype=parttype):
                print(
                    f"Formatted {parttype}.")
                count_fp += 1
        if count_fp == len(partitions) and count_fp > 1:
            print("All partitions formatted.")
        elif count_fp != len(partitions) and count_fp > 1:
            print("Failed to format all partitions.")

    def da_ess(self, sector: int, sectors: int, parttype: str):
        if parttype == "user" or parttype is None:
            wipedata = b"\x00" * 0x200000
            error = False
            while sectors:
                sectorsize = sectors * self.config.pagesize
                wsize = min(sectorsize, 0x200000)
                if self.mtk.daloader.writeflash(addr=sector * self.config.pagesize,
                                                length=wsize,
                                                filename="",
                                                wdata=wipedata[:wsize],
                                                parttype="user"):
                    print(
                        f"Failed to format sector {str(sector)} with " +
                        f"sector count {str(sectors)}.")
                    error = True
                    break
                sectors -= (wsize // self.config.pagesize)
                sector += (wsize // self.config.pagesize)
            if not error:
                print(
                    f"Formatted sector {str(sector)} with sector count {str(sectors)}.")
        else:
            pos = 0
            self.mtk.daloader.formatflash(addr=sector * self.config.pagesize,
                                          length=min(sectors * self.config.pagesize, 0xF000000),
                                          partitionname=None,
                                          parttype=parttype,
                                          display=True)
            print(f"Formatted sector {str(pos // 0x200)}")

    def da_es(self, partitions: list, parttype: str, sectors: int):
        if parttype == "user" or parttype is None:
            i = 0
            for partition in partitions:
                i += 1
                res = self.mtk.daloader.detect_partition(partition, parttype)
                if res[0]:
                    rpartition = res[1]
                    rsectors = min(sectors * self.config.pagesize,
                                   rpartition.sectors * self.config.pagesize)
                    if sectors > rsectors:
                        self.error(f"Partition {partition} only has {rsectors}, you were using {sectors}. " +
                                   "Aborting")
                        continue
                    wipedata = b"\x00" * 0x200000
                    error = False
                    sector = rpartition.sector
                    while sectors:
                        sectorsize = sectors * self.mtk.daloader.daconfig.pagesize
                        wsize = min(sectorsize, 0x200000)
                        if self.mtk.daloader.writeflash(addr=sector * self.config.pagesize,
                                                        length=wsize,
                                                        filename="",
                                                        wdata=wipedata[:wsize],
                                                        parttype=parttype):
                            print(
                                f"Failed to format sector {str(sector)} with " +
                                f"sector count {str(sectors)}.")
                            error = True
                            break
                        sectors -= (wsize // self.config.pagesize)
                        sector += (wsize // self.config.pagesize)
                    if not error:
                        print(
                            f"Formatted sector {str(rpartition.sector)} with " +
                            f"sector count {str(sectors)}.")
                else:
                    self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for rpartition in res[1]:
                        self.info(rpartition.name)
        else:
            pos = 0
            for partitionname in partitions:
                self.mtk.daloader.formatflash(addr=pos,
                                              length=min(sectors * self.config.pagesize, 0xF000000),
                                              partitionname=partitionname,
                                              parttype=parttype,
                                              display=True)
                print(f"Formatted sector {str(pos // 0x200)}")

    def da_wf(self, filenames: list, parttype: str):
        pos = 0
        for partfilename in filenames:
            size = os.stat(partfilename).st_size // 0x200 * 0x200
            if self.mtk.daloader.writeflash(addr=pos,
                                            length=size,
                                            filename=partfilename,
                                            parttype=parttype):
                print(f"Wrote {partfilename} to sector {str(pos // 0x200)} with " +
                      f"sector count {str(size // 0x200)}.")
            else:
                print(f"Failed to write {partfilename} to sector {str(pos // 0x200)} with " +
                      f"sector count {str(size // 0x200)}.")

    def da_efuse(self):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            for idx in range(len(efuseconfig.efuses)):
                addr = efuseconfig.efuses[idx]
                if addr < 0x1000:
                    data = int.to_bytes(addr, 4, 'little')
                else:
                    data = bytearray(self.mtk.daloader.peek(addr=addr, length=4, registers=True))
                self.info(f"EFuse Idx {hex(idx)}: {data.hex()}")

    def efuse_wait_for_mask(self, mask, value, timeout):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            while value != (self.mtk.daloader.peek(base) & mask):
                timeout -= 1
                if timeout <= 0:
                    return 0x1000000
        return 0

    def efuse_blow_protect(self, lock):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            if lock:
                value = 0
            else:
                value = 0x6B32970A
            self.mtk.daloader.poke(base + 8, value)
            if self.efuse_wait_for_mask(2, 0, 4096) == 0:
                return True
        return False

    def pwrap_swinf_acc(self, swinf_no, cmd, write, pmifid, slvid, addr, bytecnt, wdata):
        rdata = 0
        peek = self.mtk.daloader.peek
        poke = self.mtk.daloader.poke
        E_PWR_INVALID_RW = 2
        E_PWR_INVALID_ADDR = 3
        E_PWR_INVALID_WDAT = 4
        E_PWR_NOT_INIT_DONE = 7
        E_PWR_INVALID_SWINF = 4
        E_PWR_INVALID_CMD = 5
        E_PWR_INVALID_PMIFID = 6
        E_PWR_INVALID_SLVID = 7
        E_PWR_INVALID_BYTECNT = 8

        TIMEOUT_READ = (0x2710)  # 10000us
        TIMEOUT_WAIT_IDLE = (0x2710)  # 10000us

        WACS_FSM_IDLE = 0
        WACS_INIT_DONE = 1
        WACS_FSM_WFDLE = 4
        WACS_FSM_REQ = 2
        WACS_FSM_WFVLDCLR = 6

        IO_PHYS = 0x10000000
        PMIF_SPI_BASE = IO_PHYS + 0x00026000
        PMIF_SPI_PMIF_SWINF_0_ACC = PMIF_SPI_BASE + 0xC00
        PMIF_SPI_PMIF_SWINF_0_WDATA_31_0 = PMIF_SPI_BASE + 0xC04
        PMIF_SPI_PMIF_SWINF_0_RDATA_31_0 = PMIF_SPI_BASE + 0xC14
        PMIF_SPI_PMIF_SWINF_0_VLD_CLR = PMIF_SPI_BASE + 0xC24
        PMIF_SPI_PMIF_SWINF_0_STA = PMIF_SPI_BASE + 0xC28

        if (swinf_no & (~(0x3) & 0xFFFFFFFF)) != 0:
            return E_PWR_INVALID_SWINF, 0
        if (cmd & (~(0x3) & 0xFFFFFFFF)) != 0:
            return E_PWR_INVALID_CMD, 0
        if (write & (~(0x1) & 0xFFFFFFFF)) != 0:
            return E_PWR_INVALID_RW, 0
        if (pmifid & (~(0x3) & 0xFFFFFFFF)) != 0:
            return E_PWR_INVALID_PMIFID, 0
        if (slvid & (~(0xf) & 0xFFFFFFFF)) != 0:
            return E_PWR_INVALID_SLVID, 0
        if (addr & (~(0xffff) & 0xFFFFFFFF)) != 0:
            return E_PWR_INVALID_ADDR, 0
        if (bytecnt & (~(0x1) & 0xFFFFFFFF)) != 0:
            return E_PWR_INVALID_BYTECNT, 0
        if (wdata & ((~(0xffff)) & 0xFFFFFFFF)) != 0:
            return E_PWR_INVALID_WDAT, 0

        reg_rdata = 0
        # Check whether INIT_DONE is set
        if pmifid == 0:
            reg_rdata = peek(PMIF_SPI_PMIF_SWINF_0_STA + 0x40 * swinf_no)
        return 0, reg_rdata

        def GET_SWINF_2_INIT_DONE(x):
            return ((x >> 15) & 0x00000001) & 0xFFFFFFFF

        def GET_SWINF_2_FSM(x):
            return ((x >> 1) & 0x00000007) & 0xFFFFFFFF

        def wait_for_fsm_vldclr(x):
            return GET_SWINF_2_FSM(x) != WACS_FSM_WFVLDCLR

        def wait_for_fsm_idle(x):
            return GET_SWINF_2_FSM(x) != WACS_FSM_IDLE

        def wait_for_state_idle(fp, timeout_us, wacs_register):
            while True:
                # if _pwrap_timeout_ns(start_time_ns, timeout_ns):
                #    pwrap_dump_ap_register()
                #    return E_PWR_WAIT_IDLE_TIMEOUT
                reg_rdata = peek(wacs_register)
                if GET_SWINF_2_INIT_DONE(reg_rdata) != WACS_INIT_DONE:
                    return E_PWR_NOT_INIT_DONE
                state = GET_SWINF_2_FSM(reg_rdata)
                if state == WACS_FSM_WFVLDCLR:
                    poke(wacs_register, 1)
                elif state == WACS_FSM_WFDLE:
                    pass
                elif state == WACS_FSM_REQ:
                    pass
                if not fp(reg_rdata):
                    break
            return 0

        def wait_for_state_ready(fp, timeout_us, wacs_register):
            # 	start_time_ns = _pwrap_get_current_time();
            # 	timeout_ns = _pwrap_time2ns(timeout_us);
            while True:
                """
                if (_pwrap_timeout_ns(start_time_ns, timeout_ns)) {
                    PWRAPERR("ready_init timeout\n");
                    pwrap_dump_ap_register();
                    return E_PWR_WAIT_IDLE_TIMEOUT;
                }
                """
                reg_rdata = peek(wacs_register)
                if not fp(reg_rdata):
                    break
            return reg_rdata

        if GET_SWINF_2_INIT_DONE(reg_rdata) != 1:
            return E_PWR_NOT_INIT_DONE

        # Wait for Software Interface FSM state to be IDLE
        return_value = wait_for_state_idle(wait_for_fsm_idle, TIMEOUT_WAIT_IDLE,
                                           (PMIF_SPI_PMIF_SWINF_0_STA + 0x40 * swinf_no) & 0xFFFFFFFF)
        if return_value != 0:
            return return_value

        # Set the write data
        if write == 1:
            if pmifid == 0:
                poke(PMIF_SPI_PMIF_SWINF_0_WDATA_31_0 + 0x40 * swinf_no, wdata)

        # Send the command
        if pmifid == 0:
            poke(PMIF_SPI_PMIF_SWINF_0_ACC + 0x40 * swinf_no,
                 (cmd << 30) | (write << 29) | (slvid << 24) | (bytecnt << 16) | addr)

        if write == 0:
            # Wait for Software Interface FSM to be WFVLDCLR, read the data and clear the valid flag
            return_value, reg_rdata = wait_for_state_ready(wait_for_fsm_vldclr, TIMEOUT_READ,
                                                           (PMIF_SPI_PMIF_SWINF_0_STA + 0x40 * swinf_no) & 0xFFFFFFFF,
                                                           1, pmifid)
            if return_value != 0:
                return_value += 1
                return return_value

        if pmifid == 0:
            rdata = peek(PMIF_SPI_PMIF_SWINF_0_RDATA_31_0 + 0x40 * swinf_no)

        if pmifid == 0:
            poke(PMIF_SPI_PMIF_SWINF_0_VLD_CLR + 0x40 * swinf_no, 0x1)

        return rdata

    def pwrap_read(self, adr):
        PMIF_SPI_AP_SWINF_NO = 2
        DEFAULT_CMD = 0
        PMIF_SPI_PMIFID = 0
        DEFAULT_SLVID = 0
        DEFAULT_BYTECNT = 0
        status, rdata = self.pwrap_swinf_acc(PMIF_SPI_AP_SWINF_NO, DEFAULT_CMD, 0, PMIF_SPI_PMIFID,
                                             DEFAULT_SLVID, adr, DEFAULT_BYTECNT, 0x0)
        return status, rdata

    def pwrap_write(self, adr, wdata):
        PMIF_SPI_AP_SWINF_NO = 2
        DEFAULT_CMD = 0
        PMIF_SPI_PMIFID = 0
        DEFAULT_SLVID = 0
        DEFAULT_BYTECNT = 0
        status, rdata = self.pwrap_swinf_acc(PMIF_SPI_AP_SWINF_NO, DEFAULT_CMD, 1, PMIF_SPI_PMIFID,
                                             DEFAULT_SLVID, adr, DEFAULT_BYTECNT, wdata)
        return status, rdata

    def pmic_config_interface(self, regnum, val, mask, shift):
        status, rdata = self.pwrap_read(regnum)
        if not status:
            wdata = (rdata & (~(mask << shift) & 0xFFFFFFFF)) | ((val << shift) & 0xFFFFFFFF)
            return self.pwrap_write(regnum, wdata)
        return status, 0

    def efuse_fsource_set(self):
        if self.mtk.config.hwcode == 0x6789:
            regs = [0x1E98, 0x1E98, 0x1C44]
        elif self.mtk.config.hwcode == 0x6885:
            regs = [0x200C, 0x200C, 0x1BD0]
        else:
            return -1
        ret = self.pmic_config_interface(regs[0], 0xC, 0xF, 8)
        ret2 = self.pmic_config_interface(regs[1], 0, 0xF, 0)
        ret3 = self.pmic_config_interface(regs[2], 1, 1, 0)
        time.sleep(0.1)
        return ret[0] | ret2[0] | ret3[0]

    def efuse_fsource_close(self):
        if self.mtk.config.hwcode == 0x6789:
            value = 0x1C44
        elif self.mtk.config.hwcode == 0x6885:
            value = 0x1BD0
        else:
            return -1
        ret = self.pmic_config_interface(value, 0, 1, 0)
        time.sleep(0.1)
        return ret[0]

    def pmic_read_interface(self, regnum, mask, shift):
        status, rdata = self.pwrap_read(regnum)
        if not status:
            return ((rdata & (mask << shift) & 0xFFFFFFFF) >> shift) & 0xFFFFFFFF
        return status

    def efuse_fsource_is_enabled(self):
        if self.mtk.config.hwcode == 0x6789:
            value = 0x1C44
        elif self.mtk.config.hwcode == 0x6885:
            value = 0x1BD0
        else:
            return -1
        ret = self.pmic_read_interface(value, 1, 0)
        time.sleep(0.1)
        return ret

    def efuse_wdt_restart(self):
        self.mtk.daloader.poke(0x10007008, 0x1971)

    def tzcc_clk(self, enable):
        if enable:
            self.mtk.daloader.poke(0x1000108C, 0x18000000)
        else:
            self.mtk.daloader.poke(0x10001088, 0x8000000)

    def efuse_reinit(self):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            self.mtk.daloader.poke(base, self.mtk.daloader.peek(base) | 4)
            if self.efuse_wait_for_mask(1, 1, 0x100000) == 0:
                return True
        return False

    def read_internal_fuse(self, idx):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            addr = efuseconfig.internal_fuses[idx][0]
            data = bytearray(self.mtk.daloader.peek(addr=addr, length=4, registers=True))
            return data
        return None

    def efuse_write_macro(self, addr, value):
        ret = self.efuse_wait_for_mask(2, 0, 0x1000)
        if not ret:
            self.mtk.daloader.poke(addr, value)
            return self.efuse_wait_for_mask(2, 0, 0x1000)
        return ret

    def efuse_runtime_blow_main_handler(self, idx, data):
        peek = self.mtk.daloader.peek
        poke = self.mtk.daloader.poke
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            fields = efuse_runtime_def(efuseconfig.internal_fuses[idx])

            poke(base + 0x230, peek(base + 0x230) & 0xFFFFFC00)
            poke(base + 0x250, peek(base + 0x250) & ((~1) & 0xFFFFFFFF))
            status = peek(base + 0x254)
            value = peek(fields.addr)
            r_blow = fields.mask & ((~value) & 0xFFFFFFFF) & data
            if not r_blow:
                print("Already blown: Bypass blowing")
                return 0
            if (fields.ecc_type - 2 > 1) or (value & fields.mask) == 0 and (fields.ecc_address & fields.ecc_mask) == 0:
                self.efuse_wdt_restart()
                if self.efuse_fsource_set():
                    return 0x20000
                ret = self.efuse_blow_protect(0)
                if ret:
                    print("Blow fail !")
                    if self.efuse_fsource_is_enabled():
                        self.efuse_fsource_close()
                    self.efuse_blow_protect(1)
                    return
                ret = self.efuse_write_macro(fields.addr, r_blow)
                if (ret):
                    return ret | 0x100000
                if (status & 1) == 0:
                    self.efuse_blow_protect(1)
                    if not self.efuse_fsource_close():
                        self.efuse_reinit()
                        return 0
                    return 0x20000
            if fields.ecc_type == 1:
                wd = fields.mask & ~peek(fields.addr) & data
                print("[Run-Time] data=%x, %x, %x\n" % (peek(fields.addr), data, wd))
                wecc = (wd << fields.ecc_dw) & fields.ecc_mask
                ret = self.efuse_write_macro(fields.ecc_address, wecc)
                print("[Run-Time] OECC: idx[0x%x], data[0x%x]\n" % (idx, wecc))
            elif fields.ecc_type == 2:
                print("[Run-Time] MECC_CHECK: idx[0x%x]\n", idx)
                if fields.field_type == 1:
                    addr2 = base + 0x400
                    value2 = fields.ecc_dw | 0xA6810000
                    print("[Run-Time] MECC_WRITE: idx[0x%x], data[0x%x]\n" % (idx, value2))
                    self.efuse_write_macro(addr2, value2)
                elif fields.field_type == 0:
                    addr2 = base + 0x408
                    value2 = fields.ecc_dw | 0x6810000
                    print("[Run-Time] MECC_WRITE: idx[0x%x], data[0x%x]\n" % (idx, value2))
                    ret = self.efuse_write_macro(addr2, value2)
            if ret:
                print("This field can only be blown once!")
            else:
                print("Blow fail !")
            if self.efuse_fsource_is_enabled():
                self.efuse_fsource_close()
            self.efuse_blow_protect(1)

    def zeroization(self):
        self.efuse_blow_protect(0)
        self.efuse_fsource_set()
        self.efuse_reinit()
        self.tzcc_clk(1)
        while not self.mtk.daloader.peek(0x10210ABC):
            pass
        lcs = self.mtk.daloader.peek(0x10210AD4) & 0xF
        _ = lcs
        self.tzcc_clk(0)
        cm = [self.read_internal_fuse(0x18), self.read_internal_fuse(0x19)]
        hrk = [self.read_internal_fuse(0x8), self.read_internal_fuse(0x9), self.read_internal_fuse(0xA),
               self.read_internal_fuse(0xB), self.read_internal_fuse(0xC), self.read_internal_fuse(0xD),
               self.read_internal_fuse(0xE), self.read_internal_fuse(0xF)]
        ac_key = [self.read_internal_fuse(0x10), self.read_internal_fuse(0x11),
                  self.read_internal_fuse(0x12), self.read_internal_fuse(0x13)]
        scp = [self.read_internal_fuse(0x1B), self.read_internal_fuse(0x1C),
               self.read_internal_fuse(0x1D), self.read_internal_fuse(0x1E)]
        custk = [self.read_internal_fuse(0x14), self.read_internal_fuse(0x15),
                 self.read_internal_fuse(0x16), self.read_internal_fuse(0x17),
                 self.read_internal_fuse(0x1A)]
        val = self.read_internal_fuse(0x18)
        _ = cm
        _ = hrk
        _ = ac_key
        _ = scp
        _ = custk
        _ = val
        """
        # Wipe keys
        efuse_runtime_internal_blow(0x18u, val | 0x80000000)
        efuse_runtime_internal_blow(8u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(9u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0xAu, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0xBu, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0xCu, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0xDu, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0xEu, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0xFu, 0xFFFFFFFF)
        efuse_runtime_internal_read(0x18u, val)
        efuse_runtime_internal_blow(0x18u, val[0] | 0xFF)
        efuse_runtime_internal_blow(0x10u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x11u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x12u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x13u, 0xFFFFFFFF)
        efuse_runtime_internal_read(0x19u, val)
        efuse_runtime_internal_blow(0x19u, val[0] | 0xFF000000)
        efuse_runtime_internal_blow(0x1Bu, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x1Cu, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x1Du, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x1Eu, 0xFFFFFFFF)
        efuse_runtime_internal_read(0x18u, val)
        efuse_runtime_internal_blow(0x18u, val[0] | 0x7F00)
        efuse_runtime_internal_blow(0x14u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x15u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x16u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x17u, 0xFFFFFFFF)
        efuse_runtime_internal_blow(0x1Au, 0xFFFFFFFF)
        """
        self.efuse_fsource_close()
        self.efuse_reinit()
        self.efuse_blow_protect(1)
        self.tzcc_clk(1)
        self.mtk.daloader.poke(0x10001088, 0x8000000)
        self.mtk.daloader.poke(0x1000108C, 0x8000000)
        self.tzcc_clk(0)
        self.tzcc_clk(1)
        while not self.mtk.daloader.peek(0x10210ABC):
            pass
        new_lcs = self.mtk.daloader.peek(0x10210AD4) & 0xF
        _ = new_lcs
        self.tzcc_clk(0)

    def get_current_slot(self):
        tmp = self.da_read_partition("misc")
        if tmp == b"":
            tmp = self.da_read_partition("para")
        if tmp != b"":
            slot = tmp[0x800:0x802].decode('utf-8')
            if slot == "\x00\x00":
                slot = ""
        else:
            slot = ""
        return slot

    def da_brom(self, filename: str):
        return self.mtk.daloader.dump_brom(filename)

    def da_peek(self, addr: int, length: int, filename: str, registers=False):
        bytestoread = length
        pos = 0
        pagesize = 0x20000
        if self.mtk.daloader.flashmode == DAmodes.XFLASH:
            pagesize = self.mtk.daloader.get_packet_length()
        pg = progress(total=length, prefix='Peek:')
        bytesread = 0
        wf = None
        if filename is not None:
            wf = open(filename, "wb")
        retval = bytearray()
        while bytestoread > 0:
            msize = min(bytestoread, pagesize)
            try:
                data = self.mtk.daloader.peek(addr=addr + pos, length=msize, registers=registers)
                if wf is not None:
                    wf.write(data)
                else:
                    retval.extend(data)
                pg.update(len(data))
                pos += len(data)
                bytesread += len(data)
                bytestoread -= len(data)
            except Exception as err:
                self.error(err)
                pass
        pg.done()
        if filename is not None:
            wf.close()
            self.info(f"Successfully wrote data from {hex(addr)}, length {hex(length)} to {filename}")
        else:
            self.info(
                f"Data read from {hex(addr)}, length: {hex(length)}:\n{hexlify(retval).decode('utf-8')}\n")

    def da_poke(self, addr: int, data: str, filename: str):
        if filename is not None:
            if os.path.exists(filename):
                data = open(filename, "rb").read()
        else:
            if "0x" in data:
                data = pack("<I", int(data, 16))
            else:
                data = bytes.fromhex(data)
        if self.mtk.daloader.poke(addr=addr, data=data):
            self.info(f"Successfully wrote data to {hex(addr)}, length {hex(len(data))}")

    def handle_da_cmds(self, mtk, cmd: str, args):
        if mtk is None or mtk.daloader is None:
            self.error("Error on running da, aborting :(")
            sys.exit(1)
        if mtk.daloader.config.generatekeys and mtk.daloader.is_patched():
            mtk.daloader.keys()
        if cmd == "gpt":
            directory = args.directory
            self.da_gpt(directory=directory)
        elif cmd == "printgpt":
            data, guid_gpt = mtk.daloader.get_gpt()
            if not guid_gpt:
                self.error('Error reading gpt, please read whole flash using "mtk rf flash.bin".')
            else:
                guid_gpt.print()
        elif cmd == "r":
            partitionname = args.partitionname
            parttype = args.parttype
            filename = args.filename
            offset = args.offset
            if offset is not None and isinstance(args.offset, str):
                offset = int(args.offset, 16)
            length = args.length
            if length is not None and isinstance(args.length, str):
                length = int(args.length, 16)
            self.mtk.config.hwparam_path = os.path.dirname(filename)
            self.da_read(partitionname=partitionname, parttype=parttype, filename=filename, offset=offset,
                         length=length)
        elif cmd == "rl":
            directory = args.directory
            self.mtk.config.hwparam_path = directory
            parttype = args.parttype
            if args.skip:
                skip = args.skip.split(",")
            else:
                skip = []
            self.da_rl(directory=directory, parttype=parttype, skip=skip)
        elif cmd == "rf":
            offset = args.offset
            length = args.length
            filename = args.filename
            if offset is not None and isinstance(args.offset, str):
                offset = int(args.offset, 16)
            if length is not None and isinstance(args.length, str):
                length = int(args.length, 16)
            self.mtk.config.hwparam_path = os.path.dirname(filename)
            parttype = args.parttype
            self.da_rf(filename=filename, parttype=parttype, offset=offset, length=length)
        elif cmd == "rs":
            start = getint(args.startsector)
            sectors = getint(args.sectors)
            filename = args.filename
            self.mtk.config.hwparam_path = os.path.dirname(filename)
            parttype = args.parttype
            if self.da_rs(start=start, sectors=sectors, filename=filename, parttype=parttype):
                print(f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}.")
            else:
                print(f"Failed to dump sector {str(start)} with sector count {str(sectors)} as {filename}.")
        elif cmd == "ro":
            start = getint(args.offset)
            length = getint(args.length)
            filename = args.filename
            self.mtk.config.hwparam_path = os.path.dirname(filename)
            parttype = args.parttype
            if self.da_ro(start=start, length=length, filename=filename, parttype=parttype):
                print(f"Dumped offset {hex(start)} with length {hex(length)} as {filename}.")
            else:
                print(f"Failed to dump offset {hex(start)} with length {hex(length)} as {filename}.")
        elif cmd == "fs":
            if FUSE is not None:
                print(f'Mounting FUSE fs at: {args.mountpoint}...')
                fs = FUSE(MtkDaFS(self, rw=args.rw), mountpoint=args.mountpoint, foreground=True, allow_other=True,
                          nothreads=True)
                _ = fs
        elif cmd == "footer":
            filename = args.filename
            self.da_footer(filename=filename)
        elif cmd == "w":
            partitionname = args.partitionname
            filename = args.filename
            parttype = args.parttype
            filenames = filename.split(",")
            partitions = partitionname.split(",")
            self.da_write(parttype=parttype, filenames=filenames, partitions=partitions)
        elif cmd == "wl":
            directory = args.directory
            parttype = args.parttype
            self.da_wl(directory=directory, parttype=parttype)
        elif cmd == "wo":
            start = getint(args.offset)
            length = getint(args.length)
            filename = args.filename
            parttype = args.parttype
            if filename is None:
                self.error("No filename given to write to flash")
                self.close()
                return
            if not os.path.exists(filename):
                self.error(f"Filename {filename} to write doesn't exist")
                self.close()
                return
            self.info(f"Writing offset {hex(start)} with length {hex(length)}")

            if self.da_wo(start=start, length=length, filename=filename, parttype=parttype):
                print(f"Wrote {filename} to offset {hex(start)} with " +
                      f"length {hex(length)}.")
            else:
                print(f"Failed to write {filename} to offset {hex(start)} with " +
                      f"length {hex(length)}.")
                self.close()
        elif cmd == "wf":
            filename = args.filename
            parttype = args.parttype
            filenames = filename.split(",")
            self.da_wf(filenames=filenames, parttype=parttype)
        elif cmd == "e":
            partitionname = args.partitionname
            parttype = args.parttype
            partitions = partitionname.split(",")
            self.da_erase(partitions=partitions, parttype=parttype)
        elif cmd == "es":
            partitionname = args.partitionname
            parttype = args.parttype
            sectors = getint(args.sectors)
            if args.sectors is None:
                self.error("Sector count is missing. Usage: es [partname] [sector count]")
                self.close()
            partitions = partitionname.split(",")
            self.da_es(partitions=partitions, parttype=parttype, sectors=sectors)
        elif cmd == "ess":
            sector = getint(args.startsector)
            parttype = args.parttype
            sectors = getint(args.sectors)
            if args.sectors is None:
                self.error("Sector count is missing. Usage: ess [sector] [sector count]")
                self.close()
            self.da_ess(sector=sector, parttype=parttype, sectors=sectors)
        elif cmd == "reset":
            if os.path.exists(os.path.join(self.mtk.config.hwparam_path, ".state")):
                os.remove(os.path.join(self.mtk.config.hwparam_path, ".state"))
            mtk.daloader.shutdown(bootmode=0)
            print("Reset command was sent. Disconnect usb cable to power off.")
        elif cmd == "da":
            subcmd = args.subcmd
            if subcmd is None:
                print(
                    "Available da cmds are: [peek, poke, generatekeys, seccfg, rpmb, meta, memdump, efuse, dumpbrom, vbmeta]")
                return
            if subcmd == "peek":
                addr = getint(args.address)
                length = getint(args.length)
                filename = args.filename
                self.da_peek(addr=addr, length=length, filename=filename)
            elif subcmd == "memdump":
                directory = args.directory
                if not os.path.exists(directory):
                    os.mkdir(directory)
                dramaddr = 0x40000000
                dramsize = 0x100000000 - 0x40000000  # 0xE0000000
                bromaddr = 0
                bromsize = 0x300000
                sramaddr = 0x300000
                sramsize = 0x11200000
                efuseaddr = 0x11C10000
                efusesize = 0x10000
                if self.mtk.config.dram is not None:
                    dramaddr = self.mtk.config.dram.base_address
                    dramsize = self.mtk.config.dram.size
                if self.mtk.config.sram is not None:
                    sramaddr = self.mtk.config.sram.base_address
                    sramsize = self.mtk.config.sram.size
                self.info("Dumping brom...")
                self.da_peek(addr=bromaddr, length=bromsize,
                             filename=os.path.join(directory, "dump_brom.bin"), registers=True)
                self.info(f"Dumping dram at {hex(dramaddr)}, size {hex(dramsize - dramaddr)}...")
                self.da_peek(addr=dramaddr, length=0x100000000 - dramaddr,
                             filename=os.path.join(directory, f"dump_dram_{hex(dramaddr)}.bin"), registers=False)
                self.info(f"Dumping efuse at {hex(efuseaddr)}, size at {hex(efusesize)}...")
                self.da_peek(addr=efuseaddr, length=efusesize,
                             filename=os.path.join(directory, "dump_efuse.bin"), registers=True)
                self.info(f"Dumping sram at {hex(sramaddr)}, size {hex(sramsize)}...")
                self.da_peek(addr=sramaddr, length=sramsize,
                             filename=os.path.join(directory, "dump_sram.bin"), registers=False)
            elif subcmd == "memdram":
                directory = args.directory
                if not os.path.exists(directory):
                    os.mkdir(directory)
                dramaddr = 0x40000000
                dramsize = 0x100000000 - 0x40000000  # 0xE0000000
                if self.mtk.config.dram is not None:
                    dramaddr = self.mtk.config.dram.base_address
                    dramsize = self.mtk.config.dram.size
                self.info(f"Dumping dram at {hex(dramaddr)}, size {hex(dramsize - dramaddr)}...")
                self.da_peek(addr=dramaddr, length=0x100000000 - dramaddr,
                             filename=os.path.join(directory, f"dump_dram_{hex(dramaddr)}.bin"), registers=False)
            elif subcmd == "poke":
                addr = getint(args.address)
                filename = args.filename
                data = args.data
                self.da_poke(addr=addr, data=data, filename=filename)
            elif subcmd == "generatekeys":
                self.mtk.config.hwparam_path = "."
                mtk.daloader.keys()
            elif subcmd == "keyserver":
                mtk.daloader.keyserver()
            elif subcmd == "dumpbrom":
                filename = f"brom_{hex(mtk.daloader.config.hwcode)[2:]}.bin"
                mtk.daloader.dump_brom(filename=filename)
            elif subcmd == "efuse":
                self.da_efuse()
            elif subcmd == "seccfg":
                v = mtk.daloader.seccfg(args.flag)
                if v[0]:
                    self.info(v[1])
                else:
                    self.error(v[1])
            elif subcmd == "nvitem":
                if args.encrypt:
                    encrypt = True
                else:
                    encrypt = False
                if isinstance(args.seed, bytes):
                    seed = args.seed
                elif isinstance(args.seed, str):
                    seed = bytes.fromhex(args.seed)
                result = mtk.daloader.nvitem(filename=args.filename,
                                             encrypt=encrypt,
                                             otp=mtk.config.get_otp(),
                                             seed=seed,
                                             aeskey=bytes.fromhex(args.aeskey))
            elif subcmd == "patchmodem":
                slot = self.get_current_slot()
                md1img = self.da_read_partition(partitionname="md1img" + slot)
                if md1img != b"":
                    new_md1img = patch_md1img(md1img)
                    if self.da_write_partition(partitionname="md1img" + slot, data=new_md1img):
                        print("Modem patch was successful.")
                    else:
                        print("Failed to patch modem.")
                    sys.stdout.flush()
            elif subcmd == "imei":
                if args.write:
                    write = True
                else:
                    write = False
                print()
                if not write:
                    nvdata = self.da_read_partition(partitionname="nvdata")
                    if nvdata != b"":
                        pos = find_binary(nvdata, b"\x4C\x44\x49\x00\x10\xEF\x0A\x00\x0A")
                        if pos != -1:
                            if isinstance(args.seed, bytes):
                                seed = args.seed
                            elif isinstance(args.seed, str):
                                seed = bytes.fromhex(args.seed)
                            nvitem_data = nvdata[pos:pos + 0x180]
                            result = mtk.daloader.nvitem(data=nvitem_data,
                                                         encrypt=False,
                                                         otp=mtk.config.get_otp(),
                                                         seed=seed,
                                                         aeskey=bytes.fromhex(args.aeskey),
                                                         display=False)
                            for i in range(len(result) // 0x20):
                                data = bytearray(result[i * 0x20:i * 0x20 + 0x20])
                                if data[:0xA] == b"\xFF" * 0xA:
                                    # IMEI empty
                                    continue
                                csum = calc_checksum(data, 0xA)
                                if csum == data[0xA:0xA + 8]:
                                    imei = decode_imei(data[:0xA])
                                    state = "valid" if is_luhn_valid(imei) else "invalid"
                                    print(f"{state} IMEI{i + 1}:\"{imei}\"")
                                    sys.stdout.flush()
                        cssd_pos = nvdata.find(b"devPubKeyModulus")
                        if cssd_pos != -1:
                            cssd_data = nvdata[cssd_pos - 0x40:cssd_pos - 0x40 + 0x1048]
                            content = decrypt_cssd(data=cssd_data).config
                            print("\nCSSD Device data:\n-------------")
                            for field in content:
                                value = content[field]
                                print(f"{field}:{value}")
                            sys.stdout.flush()
                            # open("config.json","w").write(json.dumps(content))
                elif write:
                    imei_arg = args.imeis
                    imeis = imei_arg.split(",")
                    for i in range(len(imeis)):
                        preimei = imeis[i][:14] + "0"
                        imeis[i] = preimei[:14] + str(make_luhn_checksum(preimei))
                    nvdata = self.da_read_partition(partitionname="nvdata")
                    if nvdata != b"":
                        pos = 0
                        while pos != -1:
                            pos = nvdata.find(b"\x4C\x44\x49\x00\x10\xEF\x0A\x00\x0A", pos + 1)
                            if pos != -1:
                                old_nvitem_data = nvdata[pos:pos + 0x180]
                                nvitem_data = bytearray()
                                x = 0
                                for imei in imeis:
                                    data = encode_imei(imei) + b"\x00\x00"
                                    csum = calc_checksum(data, 0xA)
                                    encoded_imei = data + csum + b"\x00" * 0xE
                                    nvitem_data.extend(encoded_imei)
                                    x += 1
                                for i in range(10 - x):
                                    data = b"\xFF" * 0xA
                                    csum = calc_checksum(data, 0xA)
                                    encoded_imei = data + csum + b"\x00" * 0xE
                                    nvitem_data.extend(encoded_imei)
                                # header=bytes.fromhex("4C44490010EF0A000A0000002A4000000020000000000000000000000000C2448D000000000000000000A08D0100000000000000000000000000000000000000")
                                header = old_nvitem_data[:0x40]
                                result = mtk.daloader.nvitem(data=header + nvitem_data,
                                                             encrypt=True,
                                                             otp=mtk.config.get_otp(),
                                                             seed=bytes.fromhex(args.seed),
                                                             aeskey=bytes.fromhex(args.aeskey),
                                                             display=False)
                                nvitem = header + result
                                nvdata[pos:pos + 0x180] = nvitem
                                print("Data to write: " + nvitem.hex())
                        cssd_pos = 0
                        while cssd_pos != -1:
                            cssd_pos = nvdata.find(b"devPubKeyModulus", cssd_pos + 1)
                            if cssd_pos != -1:
                                cssd_data = nvdata[cssd_pos - 0x40:cssd_pos - 0x40 + 0x1048]
                                content = decrypt_cssd(data=cssd_data).config
                                content["imei_1"] = imeis[0]
                                content["imei_2"] = imeis[1]
                                if os.path.exists("private_2048.pem") and os.path.exists("private_1024.pem"):
                                    new_cssd_data = create_cssd(content, product=args.product)
                                    nvdata[cssd_pos - 0x40:cssd_pos - 0x40 + 0x1048] = new_cssd_data

                        if self.da_write_partition(partitionname="nvdata", data=nvdata):
                            print("IMEIs were written successfully")
                        else:
                            print("Failed to write IMEIs.")
                        sys.stdout.flush()

            elif subcmd == "rpmb":
                rpmb_subcmd = args.rpmb_subcmd
                if rpmb_subcmd is None:
                    print('Available da xflash rpmb cmds are: [r w e a]')
                if rpmb_subcmd == "r":
                    mtk.daloader.read_rpmb(args.filename, args.sector, args.sectors)
                elif rpmb_subcmd == "w":
                    mtk.daloader.write_rpmb(args.filename, args.sector, args.sectors)
                elif rpmb_subcmd == "e":
                    mtk.daloader.erase_rpmb(args.sector, args.sectors)
                elif rpmb_subcmd == "a":
                    rpmbkey = args.rpmbkey
                    mtk.daloader.auth_rpmb(rpmbkey)

            elif subcmd == "meta":
                metamode = args.metamode
                if metamode is None:
                    print("metamode is needed [usb,uart,off]!")
                else:
                    mtk.daloader.setmetamode(metamode)
            elif subcmd == "vbmeta":
                vbmode = int(args.vbmode)
                self.da_vbmeta(vbmode=vbmode)

