#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2026.
# Licensed under GPLv3 License
import os
import sys
import logging
import time
from binascii import hexlify
from struct import unpack, pack
from mtkclient.Library.mtk_class import Mtk
from mtkclient.config.payloads import PathConfig
from mtkclient.Library.pltools import PLTools
from mtkclient.Library.meta import META
from mtkclient.Library.utils import getint
from mtkclient.Library.gui_utils import LogBase, logsetup, progress
from mtkclient.config.mtk_config import MtkConfig
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.DA.mtk_da_handler import DaHandler
from mtkclient.Library.Partitions.gpt import GptSettings

metamodes = "[FASTBOOT, FACTFACT, METAMETA, FACTORYM, ADVEMETA, AT+NBOOT]"


class ArgHandler(metaclass=LogBase):
    def __init__(self, args, config):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  config.loglevel, config.gui)
        try:
            config.gpt_file = None
            if args.gpt_file is not None:
                if os.path.exists(args.gpt_file):
                    config.gpt_file = args.gpt_file
        except AttributeError:
            pass
        try:
            if args.vid is not None:
                config.vid = getint(args.vid)
        except AttributeError:
            pass
        try:
            if args.pid is not None:
                config.pid = getint(args.pid)
        except AttributeError:
            pass
        config.stock = False
        try:
            if args.stock is not None:
                config.stock = args.stock
        except AttributeError:
            pass

        config.reconnect = True
        try:
            if args.noreconnect is not None:
                config.reconnect = not args.noreconnect
        except AttributeError:
            pass
        config.uartloglevel = 2
        try:
            if args.uartloglevel is not None:
                config.uartloglevel = args.uartloglevel
        except AttributeError:
            pass
        try:
            if args.payload is not None:
                config.payloadfile = args.payload
        except Exception:
            pass
        try:
            if args.appid is not None:
                config.appid = bytes.fromhex(args.appid)
        except Exception:
            pass
        try:
            if args.loader is not None:
                config.loader = args.loader
        except AttributeError:
            pass
        try:
            if args.da_address is not None:
                config.chipconfig.da_payload_addr = getint(args.da_address)
                self.info("O:DA offset:\t\t\t" + args.da_address)
        except AttributeError:
            pass
        try:
            if args.brom_address is not None:
                config.chipconfig.brom_payload_addr = getint(args.brom_address)
                self.info("O:Payload offset:\t\t" + args.brom_address)
        except AttributeError:
            pass
        try:
            if args.watchdog_address is not None:
                config.chipconfig.watchdog = getint(args.wdt)
                self.info("O:Watchdog addr:\t\t" + args.wdt)
        except AttributeError:
            pass
        try:
            if args.skipwdt is not None:
                config.skipwdt = args.skipwdt
        except AttributeError:
            pass
        try:
            if args.uart_address is not None:
                config.chipconfig.uart = getint(args.uart_address)
                self.info("O:Uart addr:\t\t" + args.uart_address)
        except AttributeError:
            pass
        try:
            if args.preloader is not None:
                config.chipconfig.var1 = getint(args.var1)
                self.info("O:Var1:\t\t" + hex(config.chipconfig.var1))
        except AttributeError:
            pass
        try:
            if args.preloader is not None:
                if os.path.exists(args.preloader):
                    config.preloader_filename = args.preloader
                    config.preloader = open(config.preloader_filename, "rb").read()
        except AttributeError:
            pass
        try:
            if args.write_preloader_to_file is not None:
                config.write_preloader_to_file = args.write_preloader_to_file
        except AttributeError:
            pass
        try:
            if args.generatekeys is not None:
                config.generatekeys = args.generatekeys
        except AttributeError:
            pass
        try:
            if args.ptype is not None:
                config.ptype = args.ptype
        except AttributeError:
            pass
        try:
            if args.socid is not None:
                config.readsocid = args.socid
        except AttributeError:
            pass
        try:
            if args.crash is not None:
                config.enforcecrash = args.crash
        except AttributeError:
            pass

        gpt_num_part_entries = 0
        try:
            if args.gpt_num_part_entries is not None:
                gpt_num_part_entries = args.gpt_num_part_entries
        except Exception:
            pass

        gpt_part_entry_size = 0
        try:
            if args.gpt_part_entry_size is not None:
                gpt_part_entry_size = args.gpt_part_entry_size
        except Exception:
            pass

        gpt_part_entry_start_lba = 0
        try:
            if args.gpt_part_entry_start_lba is not None:
                gpt_part_entry_start_lba = args.gpt_part_entry_start_lba
        except Exception:
            pass

        config.gpt_settings = GptSettings(gpt_num_part_entries, gpt_part_entry_size,
                                          gpt_part_entry_start_lba)


class Main(metaclass=LogBase):
    def __init__(self, args):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  args.loglevel, None)
        self.eh = None
        self.args = args
        if args.loglevel == logging.DEBUG:
            if not os.path.exists("logs"):
                os.mkdir("logs")

    @staticmethod
    def close():
        sys.exit(0)

    def cmd_stage(self, mtk, filename, stage2addr, stage2file, verifystage2):
        if filename is None:
            pc = PathConfig()
            stage1file = os.path.join(pc.get_payloads_path(), "generic_stage1_payload.bin")
        else:
            stage1file = filename
        if not os.path.exists(stage1file):
            self.error(f"Error: {stage1file} doesn't exist !")
            return False
        if stage2file is not None:
            if not os.path.exists(stage2file):
                self.error(f"Error: {stage2file} doesn't exist !")
                return False
        else:
            stage2file = os.path.join(mtk.pathconfig.get_payloads_path(), "stage2.bin")
        if mtk.preloader.init():
            mtk = mtk.crasher()
            if mtk.port.cdc.pid == 0x0003:
                plt = PLTools(mtk, self.__logger.level)
                self.info("Uploading stage 1")
                mtk.config.set_gui_status(mtk.config.tr("Uploading stage 1"))
                if plt.runpayload(filename=stage1file):
                    self.info("Successfully uploaded stage 1, sending stage 2")
                    mtk.config.set_gui_status(mtk.config.tr("Successfully uploaded stage 1, sending stage 2"))
                    with open(stage2file, "rb") as rr:
                        stage2data = rr.read()
                        while len(stage2data) % 0x200:
                            stage2data += b"\x00"
                    if stage2addr is None:
                        stage2addr = mtk.config.chipconfig.da_payload_addr
                        if stage2addr is None:
                            stage2addr = 0x201000

                    # ###### Send stage2
                    # magic
                    mtk.port.usbwrite(pack(">I", 0xf00dd00d))
                    # cmd write
                    mtk.port.usbwrite(pack(">I", 0x4000))
                    # address
                    mtk.port.usbwrite(pack(">I", stage2addr))
                    # length
                    mtk.port.usbwrite(pack(">I", len(stage2data)))
                    bytestowrite = len(stage2data)
                    pos = 0
                    while bytestowrite > 0:
                        size = min(bytestowrite, 1)
                        if mtk.port.usbwrite(stage2data[pos:pos + size]):
                            bytestowrite -= size
                            pos += size
                    # mtk.port.usbwrite(b"")
                    time.sleep(0.1)
                    flag = mtk.port.rdword()
                    if flag != 0xD0D0D0D0:
                        self.error(f"Error on sending stage2, size {hex(len(stage2data))}.")
                    self.info(f"Done sending stage2, size {hex(len(stage2data))}.")
                    mtk.config.set_gui_status(mtk.config.tr("Done sending stage 2"))
                    if verifystage2:
                        self.info("Verifying stage2 data")
                        rdata = b""
                        mtk.port.usbwrite(pack(">I", 0xf00dd00d))
                        mtk.port.usbwrite(pack(">I", 0x4002))
                        mtk.port.usbwrite(pack(">I", stage2addr))
                        mtk.port.usbwrite(pack(">I", len(stage2data)))
                        bytestoread = len(stage2data)
                        while bytestoread > 0:
                            size = min(bytestoread, 1)
                            rdata += mtk.port.usbread(size)
                            bytestoread -= size
                        flag = mtk.port.rdword()
                        if flag != 0xD0D0D0D0:
                            self.error("Error on reading stage2 data")
                        if rdata != stage2data:
                            self.error("Stage2 data doesn't match")
                            with open("rdata", "wb") as wf:
                                wf.write(rdata)
                        else:
                            self.info("Stage2 verification passed.")
                            mtk.config.set_gui_status(mtk.config.tr("Stage2 verification passed."))

                    # ####### Kick Watchdog
                    # magic
                    # mtk.port.usbwrite(pack("<I", 0xf00dd00d))
                    # cmd kick_watchdog
                    # mtk.port.usbwrite(pack("<I", 0x3001))

                    # ######### Jump stage1
                    # magic
                    mtk.port.usbwrite(pack(">I", 0xf00dd00d))
                    # cmd jump
                    mtk.port.usbwrite(pack(">I", 0x4001))
                    # address
                    mtk.port.usbwrite(pack(">I", stage2addr))
                    self.info("Done jumping stage2 at %08X" % stage2addr)
                    mtk.config.set_gui_status(mtk.config.tr("Done jumping stage2 at %08X" % stage2addr))
                    ack = unpack(">I", mtk.port.usbread(4))[0]
                    if ack == 0xB1B2B3B4:
                        self.info("Successfully loaded stage2")

    def cmd_peek(self, mtk, addr, length, preloader, filename):
        wwf = None
        if preloader is not None:
            if os.path.exists(preloader):
                daaddr, dadata = mtk.parse_preloader(preloader)
        if mtk.preloader.init():
            if mtk.config.target_config["daa"]:
                mtk = mtk.bypass_security()
        if mtk is not None:
            if preloader is not None:
                if os.path.exists(preloader):
                    daaddr, dadata = mtk.parse_preloader(preloader)
                    if mtk.preloader.send_da(daaddr, len(dadata), 0x100, dadata):
                        self.info(f"Sent preloader to {hex(daaddr)}, length {hex(len(dadata))}")
                        if mtk.preloader.jump_da(daaddr):
                            self.info(f"Jumped to pl {hex(daaddr)}.")
                            time.sleep(2)
                            config = MtkConfig(loglevel=self.__logger.level, gui=mtk.config.gui,
                                               guiprogress=mtk.config.guiprogress)
                            mtk = Mtk(loglevel=self.__logger.level, config=config,
                                      serialportname=mtk.port.serialportname)
                            res = mtk.preloader.init()
                            if not res:
                                self.error("Error on loading preloader")
                                return
                            else:
                                self.info("Successfully connected to pl.")
                                # mtk.preloader.get_hw_sw_ver()
                                # status=mtk.preloader.jump_to_partition(b"") # Do not remove !
                else:
                    self.error("Error on jumping to pl")
                    return
            self.info("Starting to read ...")
            dwords = length // 4
            if length % 4:
                dwords += 1
            if filename is not None:
                wwf = open(filename, "wb")
            sdata = b""
            pg = progress(total=addr + length, prefix='Progress:')
            length = dwords * 4
            pos = 0
            while dwords:
                size = min(512 // 4, dwords)
                if dwords == 1:
                    data = pack("<I", mtk.preloader.read32(addr + pos, size))
                else:
                    data = b"".join(int.to_bytes(val, 4, 'little') for val in mtk.preloader.read32(addr + pos, size))
                pg.update(len(data))
                sdata += data
                if filename is not None:
                    wwf.write(data)
                pos += len(data)
                dwords = (length - pos) // 4
            pg.done()
            if filename is None:
                print(hexlify(sdata).decode('utf-8'))
            else:
                wwf.close()
                self.info(f"Data from {hex(addr)} with size of {hex(length)} was written to " + filename)

    def run(self, parser):
        try:
            if self.args.debugmode:
                loglevel = logging.DEBUG
                self.__logger.setLevel(logging.DEBUG)
            else:
                loglevel = logging.INFO
                self.__logger.setLevel(logging.INFO)
        except Exception:
            loglevel = logging.INFO
            self.__logger.setLevel(logging.INFO)
            pass
        try:
            if self.args.loader is not None:
                if not os.path.exists(self.args.loader):
                    print(f"Couldn't find loader {self.args.loader} :(")
                    sys.exit(1)
        except Exception:
            pass
        config = MtkConfig(loglevel=loglevel, gui=None, guiprogress=None)
        ArgHandler(self.args, config)
        self.eh = ErrorHandler()
        serialport = None
        try:
            serialport = self.args.serialport
        except Exception:
            pass
        try:
            disable_internal_flash = self.args.disable_internal_flash
            config.internal_flash = not disable_internal_flash
        except Exception:
            pass
        try:
            auth = self.args.auth
            config.auth = auth
        except Exception:
            pass
        try:
            cert = self.args.cert
            config.cert = cert
        except Exception:
            pass
        mtk = Mtk(config=config, loglevel=loglevel, serialportname=serialport)
        config.set_peek(mtk.daloader.peek)
        if mtk.config.debugmode:
            logfilename = os.path.join("logs", "log.txt")
            if os.path.exists(logfilename):
                os.remove(logfilename)
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)

        self.debug(" ".join(sys.argv))
        # DA / Flash commands start here
        try:
            mtk.config.preloader_filename = self.args.preloader
        except Exception:
            mtk.config.preloader_filename = None
        try:
            directory = self.args.directory
        except Exception:
            directory = "."
        cmd = self.args.cmd
        if cmd == "devices":
            filter = self.args.filter
            print("\n")
            from mtkclient.config.devicedb import supported_devices
            for device in supported_devices:
                if filter is not None:
                    if not filter.lower() in device.lower():
                        continue
                info = f"{device}:\n" + "-" * len(device) + "\n"
                for infodev in supported_devices[device]:
                    sinfo = supported_devices[device][infodev]
                    info += f"\t{infodev}: {sinfo}\n"
                print(info)
            exit(0)
        elif cmd == "script":
            if not os.path.exists(self.args.script):
                self.error("Couldn't find script: " + self.args.script)
                self.close()
                return
            commands = open(self.args.script, "r").read().splitlines()
            da_handler = DaHandler(mtk, loglevel)
            mtk = da_handler.connect(mtk, directory)
            if mtk is None:
                return
            mtk = da_handler.configure_da(mtk)
            if mtk is not None:
                for rcmd in commands:
                    self.args = parser.parse_args(rcmd.split(" "))
                    ArgHandler(self.args, config)
                    cmd = self.args.cmd
                    da_handler.handle_da_cmds(mtk, cmd, self.args)
                    sys.stdout.flush()
                    sys.stderr.flush()
            else:
                self.close()
        elif cmd == "multi":
            # Split the commands in the multi argument
            commands = self.args.commands.split(';')
            da_handler = DaHandler(mtk, loglevel)
            mtk = da_handler.connect(mtk, directory)
            if mtk is None:
                self.close()
                return
            mtk = da_handler.configure_da(mtk)
            if mtk is not None:
                for rcmd in commands:
                    self.args = parser.parse_args(rcmd.split(" "))
                    ArgHandler(self.args, config)
                    cmd = self.args.cmd
                    da_handler.handle_da_cmds(mtk, cmd, self.args)
                    sys.stdout.flush()
                    sys.stderr.flush()
            else:
                self.close()
        elif cmd == "dumpbrom":
            if mtk.preloader.init():
                rmtk = mtk.crasher()
                if rmtk is None:
                    sys.exit(0)
                if rmtk.port.cdc.vid != 0xE8D and rmtk.port.cdc.pid != 0x0003:
                    self.warning("We couldn't enter preloader.")
                filename = self.args.filename
                if filename is None:
                    cpu = ""
                    if rmtk.config.cpu != "":
                        cpu = "_" + rmtk.config.cpu
                    filename = "brom" + cpu + "_" + hex(rmtk.config.hwcode)[2:] + ".bin"
                plt = PLTools(rmtk, self.__logger.level)
                plt.run_dump_brom(filename, self.args.ptype)
                rmtk.port.close()
            self.close()
        elif cmd == "dumppreloader":
            if mtk.preloader.init():
                rmtk = mtk.crasher()
                if rmtk is None:
                    sys.exit(0)
                if rmtk.port.cdc.vid != 0xE8D or rmtk.port.cdc.pid != 0x0003:
                    self.warning("We couldn't enter preloader.")
                plt = PLTools(rmtk, self.__logger.level)
                data, filename = plt.run_dump_preloader(self.args.ptype)
                if self.args.filename is not None:
                    filename = self.args.filename
                if filename is None:
                    filename = "preloader.bin"
                if data is not None:
                    if filename == "":
                        if self.args.filename is not None:
                            filename = self.args.filename
                        else:
                            filename = "preloader.bin"
                    with open(filename, 'wb') as wf:
                        wf.write(data)
                        self.info("Preloader dumped as: " + filename)
                rmtk.port.close()
            self.close()
        elif cmd == "dumpsram":
            if mtk.preloader.init():
                rmtk = mtk.crasher()
                if rmtk is None:
                    sys.exit(0)
                if rmtk.port.cdc.vid != 0xE8D and rmtk.port.cdc.pid != 0x0003:
                    self.warning("We couldn't enter preloader.")
                filename = self.args.filename
                if filename is None:
                    cpu = ""
                    if rmtk.config.cpu != "":
                        cpu = "_" + rmtk.config.cpu
                    filename = "sram" + cpu + "_" + hex(rmtk.config.hwcode)[2:] + ".bin"
                plt = PLTools(rmtk, self.__logger.level)
                plt.run_dump_brom(filename, self.args.ptype, loader="generic_sram_payload.bin")
                rmtk.port.close()
            self.close()
        elif cmd == "brute":
            self.info("Kamakiri / DA Bruteforce run")
            rmtk = Mtk(config=mtk.config, loglevel=self.__logger.level, serialportname=mtk.port.serialportname)
            plt = PLTools(rmtk, self.__logger.level)
            plt.runbrute(self.args)
            self.close()
        elif cmd == "crash":
            if mtk.preloader.init():
                mtk = mtk.crasher(mode=getint(self.args.mode))
            mtk.port.close()
            self.close()
        elif cmd == "plstage":
            if mtk.config.chipconfig.pl_payload_addr is not None:
                plstageaddr = mtk.config.chipconfig.pl_payload_addr
            else:
                plstageaddr = 0x40001000  # 0x40200000  # 0x40001000
            if self.args.pl is None:
                plstage = os.path.join(mtk.pathconfig.get_payloads_path(), "pl.bin")
            else:
                plstage = self.args.pl
            if os.path.exists(plstage):
                with open(plstage, "rb") as rf:
                    rf.seek(0)
                    if os.path.basename(plstage) != "pl.bin":
                        pldata = mtk.patch_preloader_security_da1(rf.read())
                    else:
                        pldata = rf.read()
            if mtk.preloader.init():
                if mtk.config.target_config["daa"]:
                    mtk = mtk.bypass_security()
                    if mtk is None:
                        self.error("Error on bypassing security, aborting")
                        return
                self.info("Connected to device, loading")
            else:
                self.error("Couldn't connect to device, aborting.")

            if mtk.config.is_brom and mtk.config.preloader is None and os.path.basename(plstage) == "pl.bin":
                self.warning("PL stage needs preloader, please use --preloader option. " +
                             "Trying to dump preloader from ram.")
                plt = PLTools(mtk=mtk, loglevel=self.__logger.level)
                dadata, filename = plt.run_dump_preloader(self.args.ptype)
                mtk.config.preloader = mtk.patch_preloader_security_da1(dadata)

            if mtk.config.preloader_filename is not None:
                self.info("Using custom preloader : " + mtk.config.preloader_filename)
                mtk.preloader.setreg_disablewatchdogtimer(mtk.config.hwcode, mtk.config.hwver)
                daaddr, dadata = mtk.parse_preloader(mtk.config.preloader_filename)
                dadata = mtk.config.preloader = mtk.patch_preloader_security_da1(dadata)
                if mtk.preloader.send_da(daaddr, len(dadata), 0x100, dadata):
                    self.info(f"Sent preloader to {hex(daaddr)}, length {hex(len(dadata))}")
                    if mtk.preloader.jump_da(daaddr):
                        self.info(f"PL Jumped to daaddr {hex(daaddr)}.")
                        mtk = Mtk(config=mtk.config, loglevel=self.__logger.level)
                        if self.args.metamode is not None:
                            time.sleep(1)
                            meta = META(mtk, loglevel)
                            if meta.init(metamode=self.args.metamode, display=False):
                                self.info(f"Successfully set meta mode : {self.args.metamode}")
                            mtk.port.close()
                            self.close()
                            return
                        if (self.args.startpartition is not None or self.args.offset is not None or
                                self.args.length is not None):
                            time.sleep(1)
                            res = mtk.preloader.init()
                            if not res:
                                self.error("Error on loading preloader")
                                return
                            else:
                                self.info("Successfully connected to pl")
                        else:
                            mtk.port.close()
                            time.sleep(3)
                            self.info("Keep pressed power button to boot.")
                            self.close()
                            return

                        if self.args.startpartition is not None:
                            partition = self.args.startpartition
                            self.info("Booting to : " + partition)
                            # mtk.preloader.send_partition_data(partition, mtk.patch_preloader_security(pldata))
                            status = mtk.preloader.jump_to_partition(partition)  # Do not remove !

                        if self.args.offset is not None and self.args.length is not None:
                            offset = getint(self.args.offset)
                            length = getint(self.args.length)
                            rlen = min(0x200, length)
                            status = 0
                            mtk.preloader.get_hw_sw_ver()
                            if self.args.filename is not None:
                                with open(self.args.filename, "wb") as wf:
                                    for pos in range(offset, offset + length, rlen):
                                        print("Reading pos %08X" % pos)
                                        res = mtk.preloader.read32(pos, rlen // 4)
                                        wf.write(b"".join([pack("<I", val) for val in res]))
                            else:
                                for pos in range(offset, offset + length, rlen):
                                    print("Reading pos %08X" % pos)
                                    res = mtk.preloader.read32(pos, rlen // 4)
                                    if not res:
                                        break
                                    print(hexlify(b"".join([pack("<I", val) for val in res])).decode('utf-8'))

                            # for val in res:
                            #    print(hex(val))
                            if status != 0x0:
                                self.error("Error on jumping to partition: " + self.eh.status(status))
                            else:
                                self.info("Jumping to partition ....")
                            return
                        mtk.port.close()
                        sys.exit(0)
            if mtk.preloader.send_da(plstageaddr, len(pldata), 0x100, pldata):
                self.info(f"Sent stage2 to {hex(plstageaddr)}, length {hex(len(pldata))}")
                mtk.preloader.get_hw_sw_ver()
                if mtk.preloader.jump_da(plstageaddr):
                    self.info(f"Jumped to stage2 at {hex(plstageaddr)}.")
                    if os.path.basename(plstage) == "pl.bin":
                        ack = unpack(">I", mtk.port.usbread(4))[0]
                        if ack == 0xB1B2B3B4:
                            self.info("Successfully loaded stage2")
                            return
                    else:
                        self.info("Successfully loaded stage2, dis- and reconnect usb cable")
                        time.sleep(2)
                        ack = unpack(">I", mtk.port.usbread(4))[0]
                        mtk.port.close()
                        return
                else:
                    self.error("Error on jumping to pl")
                    return
            else:
                self.error("Error on sending pl")
                return
            self.close()
        elif cmd == "peek":
            addr = getint(self.args.address)
            length = getint(self.args.length)
            preloader = self.args.preloader
            filename = self.args.filename
            self.cmd_peek(mtk=mtk, addr=addr, length=length, preloader=preloader, filename=filename)
            self.close()
        elif cmd == "stage":
            filename = self.args.filename
            stage2addr = self.args.stage2addr
            if self.args.stage2addr is not None:
                stage2addr = getint(self.args.stage2addr)
            stage2file = self.args.stage2
            verifystage2 = self.args.verifystage2

            self.cmd_stage(mtk=mtk, filename=filename, stage2addr=stage2addr, stage2file=stage2file,
                           verifystage2=verifystage2)
            self.close()
        elif cmd == "payload":
            payloadfile = self.args.payload
            self.cmd_payload(mtk=mtk, payloadfile=payloadfile)
            self.close()
        elif cmd == "gettargetconfig":
            if mtk.preloader.init():
                self.info("Getting target info...")
                mtk.preloader.get_target_config()
            mtk.port.close()
            self.close()
        elif cmd == "logs":
            if self.args.filename is None:
                filename = "log.txt"
            else:
                filename = self.args.filename
            self.cmd_log(mtk=mtk, filename=filename)
            mtk.port.close()
            self.close()
        elif cmd == "meta":
            meta = META(mtk, loglevel)
            if self.args.metamode is None:
                self.error("You need to give a metamode as argument ex: " + metamodes)
            else:
                if meta.init(metamode=self.args.metamode, display=True):
                    self.info(f"Successfully set meta mode : {self.args.metamode}")
            mtk.port.close()
            self.close()
        elif cmd == "meta2":
            meta = META(mtk, loglevel)
            if meta.init_wdg(display=True):
                self.info("Successfully set meta mode :)")
            mtk.port.close()
            self.close()
        else:
            # DA / FLash commands start here
            da_handler = DaHandler(mtk, loglevel)
            mtk.offset = 0
            try:
                if self.args.offset is not None:
                    mtk.offset = int(self.args.offset, 16)
            except Exception:
                pass
            mtk.length = 0x400000
            try:
                if self.args.length is not None:
                    mtk.length = int(self.args.length, 16)
            except Exception:
                pass
            mtk.step = 0x1000
            try:
                if self.args.step is not None:
                    mtk.step = int(self.args.step, 16)
            except Exception:
                pass
            mtk = da_handler.connect(mtk, directory)
            if mtk is not None:
                mtk = da_handler.configure_da(mtk)
                if mtk is not None:
                    self.info("Handling da commands ...")
                    da_handler.handle_da_cmds(mtk, cmd, self.args)
                    mtk.port.close()
            self.close()

    def cmd_log(self, mtk, filename):
        if mtk.preloader.init():
            self.info("Getting target logs...")
            try:
                logs = mtk.preloader.get_brom_log_new()
            except Exception:
                logs = mtk.preloader.get_brom_log()
            if logs != b"":
                with open(filename, "wb") as wf:
                    wf.write(logs)
                    self.info(f'Successfully wrote logs to "{filename}"')
            else:
                self.info("No logs found.")

    def cmd_payload(self, mtk, payloadfile):
        if mtk.preloader.init():
            mtk = mtk.crasher()
            plt = PLTools(mtk, self.__logger.level)
            if payloadfile is None:
                if mtk.config.chipconfig.loader is None:
                    payloadfile = os.path.join(mtk.pathconfig.get_payloads_path(), "generic_patcher_payload.bin")
                else:
                    payloadfile = os.path.join(mtk.pathconfig.get_payloads_path(), mtk.config.chipconfig.loader)
            plt.runpayload(filename=payloadfile)
            if self.args.metamode:
                mtk.port.run_handshake()
                mtk.preloader.jump_bl()
                mtk.port.close(reset=True)
                meta = META(mtk, self.__logger.level)
                if meta.init(metamode=self.args.metamode, display=True):
                    self.info(f"Successfully set meta mode : {self.args.metamode}")
        mtk.port.close(reset=True)
