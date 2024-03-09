import os
import time
import sys
import logging
from struct import pack, unpack
from binascii import hexlify
from mtkclient.Library.utils import LogBase, logsetup, getint
from mtkclient.config.payloads import pathconfig
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.utils import progress
from mtkclient.config.brom_config import efuse, damodes


class DA_handler(metaclass=LogBase):
    def __init__(self, mtk, loglevel=logging.INFO):
        self.__logger = self.__logger
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.config = mtk.config
        self.loader = mtk.config.loader
        self.vid = mtk.config.vid
        self.pid = mtk.config.pid
        self.interface = mtk.config.interface
        self.pathconfig = pathconfig()
        self.__logger = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.eh = ErrorHandler()
        self.mtk = mtk

    def close(self):
        sys.exit(0)

    def dump_preloader_ram(self):
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
                        if not os.path.exists(filename):
                            try:
                                with open(filename, "wb") as wf:
                                    wf.write(preloader)
                                    print(f"Successfully extracted preloader for this device to: {filename}")
                            except Exception:
                                pass
                return preloader
        except Exception as err:
            self.error(str(err))
            return None

    def configure_da(self, mtk, preloader):
        mtk.port.cdc.connected = mtk.port.cdc.connect()
        if mtk.port.cdc.connected is None or not mtk.port.cdc.connected or mtk.serialportname is not None:
            mtk.preloader.init()
        else:
            if mtk.serialportname is not None:
                mtk.preloader.init()
            if mtk.port.cdc.connected and os.path.exists(".state"):
                mtk.daloader.reinit()
                return mtk
        if mtk.config.target_config is None:
            self.info("Please disconnect, start mtkclient and reconnect.")
            return None
        if mtk.config.target_config["sbc"] and not mtk.config.is_brom and mtk.config.loader is None:
            mtk = mtk.bypass_security()
            self.mtk = mtk
            if self.mtk.daloader.patch :
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
                    if preloader is None:
                        preloader = self.dump_preloader_ram()
        else:
            if mtk.config.target_config["sbc"]:
                self.info("Device is protected.")
            else:
                self.info("Device is unprotected.")
            if mtk.config.is_brom and not mtk.config.iot:
                self.info("Device is in BROM-Mode. Bypassing security.")
                mtk.daloader.patch = False
                hassecurity = (self.mtk.config.target_config["sla"] or self.mtk.config.target_config["daa"]
                               or self.mtk.config.target_config["sbc"])
                if not hassecurity:
                    mtk.daloader.patch = True
                mtk = mtk.bypass_security()  # Needed for dumping preloader
                if mtk is not None:
                    self.mtk = mtk
                    if preloader is None:
                        if self.mtk.config.chipconfig.damode != 6 and self.mtk.config.is_brom:
                            self.warning(
                                "Device is in BROM mode. No preloader given, trying to dump preloader from ram.")
                            preloader = self.dump_preloader_ram()
                            if preloader is None:
                                self.error("Failed to dump preloader from ram, provide a valid one " +
                                           "via --preloader option")
                                mtk.daloader.patch = False
                            else:
                                mtk.daloader.patch = True
                        else:
                            self.error("Failed to dump preloader from ram, provide a valid one " +
                                       "via --preloader option")
            elif not mtk.config.is_brom:
                self.info("Device is in Preloader-Mode.")
                mtk.daloader.patch = False
            else:
                self.info("Device is in BROM-Mode - Iot Mode.")
                mtk.daloader.patch = False

        if preloader is not None and mtk.config.preloader is None:
            mtk.config.preloader = preloader

        if not mtk.daloader.upload_da(preloader=preloader):
            return None
        else:
            mtk.daloader.writestate()
            return mtk

    def da_gpt(self, directory: str):
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

            print(f"Dumped GPT from to {sfilename}")
            sfilename = os.path.join(directory, "gpt_backup.bin")
            with open(sfilename, "wb") as wf:
                wf.write(data[self.mtk.daloader.daconfig.pagesize:])
            print(f"Dumped Backup GPT to {sfilename}")

    def da_read(self, partitionname, parttype, filename):
        filenames = filename.split(",")
        partitions = partitionname.split(",")
        if len(partitions) != len(filenames):
            self.error("You need to gives as many filenames as given partitions.")
            self.close()
        if parttype == "user" or parttype is None:
            i = 0
            countDump = 0
            self.info("Requesting available partitions ....")
            gpttable = self.mtk.daloader.get_partition_data(parttype=parttype)
            for partition in partitions:
                partfilename = filenames[i]
                i += 1
                if partition == "gpt":
                    self.mtk.daloader.readflash(addr=0,
                                                length=0x16000,
                                                filename=partfilename, parttype=parttype)
                    countDump += 1
                    continue
                else:
                    rpartition = None
                    for gptentry in gpttable:
                        if gptentry.name.lower() == partition.lower():
                            rpartition = gptentry
                            break
                    if rpartition is not None:
                        self.info(f"Dumping partition \"{rpartition.name}\"")
                        if self.mtk.daloader.readflash(addr=rpartition.sector * self.config.pagesize,
                                                       length=rpartition.sectors * self.config.pagesize,
                                                       filename=partfilename, parttype=parttype):
                            self.info(f"Dumped sector {str(rpartition.sector)} with sector count " +
                                      f"{str(rpartition.sectors)} as {partfilename}.")
                            countDump += 1
                        else:
                            self.info(f"Failed to dump sector {str(rpartition.sector)} with sector count " +
                                      f"{str(rpartition.sectors)} as {partfilename}.")
                            countDump += 1
                    else:
                        self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                        for rpartition in gpttable:
                            self.info(rpartition.name)
            if countDump > 1 and countDump == len(filenames):
                self.info("All partitions were dumped")
            elif countDump > 1 and countDump != len(filenames):
                self.info("Failed to dump some partitions")
        else:
            i = 0
            for partfilename in filenames:
                pos = 0
                if self.mtk.daloader.readflash(addr=pos, length=0xFFFFFFFF, filename=partfilename,
                                               parttype=parttype):
                    print(f"Dumped partition {str(partitionname)} as {partfilename}.")
                else:
                    print(f"Failed to dump partition {str(partitionname)} as {partfilename}.")
                i += 1

    def da_rl(self, directory, parttype, skip):
        if not os.path.exists(directory):
            os.mkdir(directory)
        data, guid_gpt = self.mtk.daloader.get_gpt(parttype=parttype)
        if not data:
            self.error("Couldn't set gpt :(")
            return
        if guid_gpt is None:
            self.error("Error reading gpt")
        else:
            storedir = directory
            if not os.path.exists(storedir):
                os.mkdir(storedir)
            sfilename = os.path.join(storedir, "gpt.bin")
            with open(sfilename, "wb") as wf:
                wf.write(data)

            sfilename = os.path.join(storedir, "gpt_backup.bin")
            with open(sfilename, "wb") as wf:
                wf.write(data[self.config.pagesize * 2:])

            countGPT = 0
            for partition in guid_gpt.partentries:
                partitionname = partition.name
                if partition.name in skip:
                    continue
                filename = os.path.join(storedir, partitionname + ".bin")
                self.info(
                    f"Dumping partition {str(partition.name)} with sector count {str(partition.sectors)} " +
                    f"as {filename}.")

                if self.mtk.daloader.readflash(addr=partition.sector * self.config.pagesize,
                                               length=partition.sectors * self.config.pagesize,
                                               filename=filename,
                                               parttype=parttype):

                    countGPT += 1
                    self.info(f"Dumped partition {str(partition.name)} as {str(filename)}.")
                else:
                    countGPT -= 1
                    self.error(f"Failed to dump partition {str(partition.name)} as {str(filename)}.")

            partitionsForRead = len(guid_gpt.partentries) - len(skip)
            if countGPT == partitionsForRead:
                self.info("All Dumped partitions success.")
            else:
                self.error("Failed to dump all partitions")

    def da_rf(self, filename, parttype):
        if self.mtk.daloader.daconfig.flashtype == "ufs":
            if parttype == "lu0":
                length = self.mtk.daloader.daconfig.flashsize
            elif parttype == "lu1":
                length = self.mtk.daloader.daconfig.flashsize
            elif parttype == "lu2":
                length = self.mtk.daloader.daconfig.flashsize
            else:
                length = self.mtk.daloader.daconfig.flashsize
        else:
            length = self.mtk.daloader.daconfig.flashsize
        print(f"Dumping sector 0 with flash size {hex(length)} as {filename}.")
        sys.stdout.flush()
        if self.mtk.daloader.readflash(addr=0, length=length, filename=filename, parttype=parttype) == b"ACK":
            print(f"Dumped sector 0 with flash size {hex(length)} as {filename}.")
        else:
            print(f"Failed to dump sector 0 with flash size {hex(length)} as {filename}.")

    def da_rs(self, start: int, sectors: int, filename: str, parttype: str):
        return self.mtk.daloader.readflash(addr=start * self.config.pagesize,
                                           length=sectors * self.config.pagesize,
                                           filename=filename, parttype=parttype)

    def da_ro(self, start: int, length: int, filename: str, parttype: str):
        return self.mtk.daloader.readflash(addr=start,
                                           length=length,
                                           filename=filename, parttype=parttype)

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
        countFP = 0
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
                        countFP += 1
                    else:
                        print(
                            f"Failed to format sector {str(rpartition.sector)} with " +
                            f"sector count {str(rpartition.sectors)}.")
                        countFP -= 1
                else:
                    self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for rpartition in res[1]:
                        self.info(rpartition.name)
        if countFP == len(partitions) and countFP > 1:
            print("All partitions formatted.")
        elif countFP != len(partitions) and countFP > 1:
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
                                                filename=None,
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
                                                        filename=None,
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
            efuseconfig = efuse(base, hwcode)
            for idx in range(len(efuseconfig.efuses)):
                addr = efuseconfig.efuses[idx]
                if addr < 0x1000:
                    data = int.to_bytes(addr, 4, 'little')
                else:
                    data = bytearray(self.mtk.daloader.peek(addr=addr, length=4))
                self.info(f"EFuse Idx {hex(idx)}: {data.hex()}")

    def da_brom(self, filename: str):
        return self.mtk.daloader.dump_brom(filename)

    def da_peek(self, addr: int, length: int, filename: str):
        bytestoread = length
        pos = 0
        pagesize = 0x200
        if self.mtk.daloader.flashmode == damodes.XFLASH:
            pagesize = self.mtk.daloader.get_packet_length()
        pg = progress(pagesize)
        bytesread = 0
        wf = None
        if filename is not None:
            wf = open(filename, "wb")
        retval = bytearray()
        while bytestoread > 0:
            msize = min(bytestoread, pagesize)
            try:
                data = self.mtk.daloader.peek(addr=addr + pos, length=msize)
                if wf is not None:
                    wf.write(data)
                else:
                    retval.extend(data)
                pg.show_progress("Dump:", bytesread, length)
                pos += len(data)
                bytesread += len(data)
                bytestoread -= len(data)
            except Exception:
                pass
        pg.show_progress("Dump:", 100, 100)
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
                self.error("Error reading gpt, please read whole flash using \"mtk rf flash.bin\".")
            else:
                guid_gpt.print()
        elif cmd == "r":
            partitionname = args.partitionname
            parttype = args.parttype
            filename = args.filename
            self.da_read(partitionname=partitionname, parttype=parttype, filename=filename)
        elif cmd == "rl":
            directory = args.directory
            parttype = args.parttype
            if args.skip:
                skip = args.skip.split(",")
            else:
                skip = []
            self.da_rl(directory=directory, parttype=parttype, skip=skip)
        elif cmd == "rf":
            filename = args.filename
            parttype = args.parttype
            self.da_rf(filename=filename, parttype=parttype)
        elif cmd == "rs":
            start = getint(args.startsector)
            sectors = getint(args.sectors)
            filename = args.filename
            parttype = args.parttype
            if self.da_rs(start=start, sectors=sectors, filename=filename, parttype=parttype):
                print(f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}.")
            else:
                print(f"Failed to dump sector {str(start)} with sector count {str(sectors)} as {filename}.")
        elif cmd == "ro":
            start = getint(args.offset)
            length = getint(args.length)
            filename = args.filename
            parttype = args.parttype
            if self.da_ro(start=start, length=length, filename=filename, parttype=parttype):
                print(f"Dumped offset {hex(start)} with length {hex(length)} as {filename}.")
            else:
                print(f"Failed to dump offset {hex(start)} with length {hex(length)} as {filename}.")
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
            sector = args.startsector
            parttype = args.parttype
            sectors = getint(args.sectors)
            if args.sectors is None:
                self.error("Sector count is missing. Usage: ess [sector] [sector count]")
                self.close()
            self.da_ess(sector=sector, parttype=parttype, sectors=sectors)
        elif cmd == "reset":
            if os.path.exists(".state"):
                os.remove(".state")
                try:
                    os.remove(os.path.join("logs", "hwparam.json"))
                except FileNotFoundError:
                    pass
            mtk.daloader.shutdown(bootmode=0)
            print("Reset command was sent. Disconnect usb cable to power off.")
        elif cmd == "da":
            subcmd = args.subcmd
            if subcmd is None:
                print("Available da cmds are: [peek, poke, generatekeys, seccfg, rpmb, meta, memdump, efuse, dumpbrom]")
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
                bromsize = 0x200000
                sramaddr = 0x200000
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
                             filename=os.path.join(directory, "dump_brom.bin"))
                self.info(f"Dumping dram at {hex(dramaddr)}, size {hex(dramsize - dramaddr)}...")
                self.da_peek(addr=dramaddr, length=0x100000000 - dramaddr,
                             filename=os.path.join(directory, f"dump_dram_{hex(dramaddr)}.bin"))
                self.info(f"Dumping efuse at {hex(efuseaddr)}, size at {hex(efusesize)}...")
                self.da_peek(addr=efuseaddr, length=efusesize,
                             filename=os.path.join(directory, "dump_efuse.bin"))
                self.info(f"Dumping sram at {hex(sramaddr)}, size {hex(sramsize)}...")
                self.da_peek(addr=sramaddr, length=sramsize,
                             filename=os.path.join(directory, "dump_sram.bin"))
            elif subcmd == "poke":
                addr = getint(args.address)
                filename = args.filename
                data = args.data
                self.da_poke(addr=addr, data=data, filename=filename)
            elif subcmd == "generatekeys":
                mtk.daloader.keys()
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
            elif subcmd == "rpmb":
                rpmb_subcmd = args.rpmb_subcmd
                if rpmb_subcmd is None:
                    print('Available da xflash rpmb cmds are: [r w]')
                if rpmb_subcmd == "r":
                    mtk.daloader.read_rpmb(args.filename)
                elif rpmb_subcmd == "w":
                    mtk.daloader.write_rpmb(args.filename)
                elif rpmb_subcmd == "e":
                    mtk.daloader.erase_rpmb()
            elif subcmd == "meta":
                metamode = args.metamode
                if metamode is None:
                    print("metamode is needed [usb,uart,off]!")
                else:
                    mtk.daloader.setmetamode(metamode)
