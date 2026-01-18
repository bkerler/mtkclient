#!/usr/bin/env python3
# MTK Stage2 Client (c) B.Kerler 2018-2025.
# Licensed under GPLv3 License

import os
import sys
import logging
import time
import argparse
import hashlib
from binascii import hexlify
from struct import pack, unpack
from mtkclient.Library.Connection.usblib import UsbClass
from mtkclient.Library.gui_utils import LogBase
from mtkclient.Library.gui_utils import progress
from mtkclient.Library.Hardware.hwcrypto import CryptoSetup, HwCrypto
from mtkclient.Library.settings import HwParam
from mtkclient.config.mtk_config import MtkConfig
from mtkclient.config.usb_ids import default_ids


class Stage2(metaclass=LogBase):
    def __init__(self, args, loglevel=logging.INFO):
        self.hwcrypto = None
        self.config = None
        self.__logger = self.__logger
        self.args = args
        self.loglevel = loglevel
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.emmc_inited = False
        # Setup HW Crypto chip variables
        self.setup = CryptoSetup()

        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            if os.path.exists(logfilename):
                os.remove(logfilename)
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

        self.cdc = UsbClass(portconfig=default_ids, loglevel=loglevel, devclass=10)
        self.usbread = self.cdc.usbread
        self.usbwrite = self.cdc.usbwrite

    def preinit(self):
        try:
            hwcode = self.read32(0x8000000)
        except:
            print("Error reading hwcode...aborting.")
            return False
        self.config = MtkConfig(self.loglevel)
        self.config.init_hwcode(hwcode)
        self.setup.blacklist = self.config.chipconfig.blacklist
        self.setup.gcpu_base = self.config.chipconfig.gcpu_base
        self.setup.dxcc_base = self.config.chipconfig.dxcc_base
        self.setup.da_payload_addr = self.config.chipconfig.da_payload_addr
        self.setup.sej_base = self.config.chipconfig.sej_base
        self.setup.read32 = self.read32
        self.setup.write32 = self.write32
        self.setup.writemem = self.memwrite
        self.setup.meid_addr = self.config.chipconfig.meid_addr
        self.setup.socid_addr = self.config.chipconfig.socid_addr
        self.hwcrypto = HwCrypto(self.setup, self.loglevel, self.config.gui)
        return True

    def init_emmc(self):
        self.usbwrite(pack(">I", 0xf00dd00d))
        self.usbwrite(pack(">I", 0x6001))
        if unpack("<I", self.usbread(4))[0] != 0x1:
            self.usbwrite(pack(">I", 0xf00dd00d))
            self.usbwrite(pack(">I", 0x6000))
            time.sleep(2)
            if unpack("<I", self.usbread(4))[0] == 0xD1D1D1D1:
                return True
            self.emmc_inited = True
        return False

    def jump(self, addr):
        self.usbwrite(pack(">I", 0xf00dd00d))
        self.usbwrite(pack(">I", 0x4001))
        self.usbwrite(pack(">I", addr))
        time.sleep(5)
        if unpack("<I", self.usbread(4))[0] == 0xD0D0D0D0:
            return True
        return False

    def read32(self, addr, dwords=1):
        result = []
        for pos in range(dwords):
            self.usbwrite(pack(">I", 0xf00dd00d))
            self.usbwrite(pack(">I", 0x4002))
            self.usbwrite(pack(">I", addr + (pos * 4)))
            self.usbwrite(pack(">I", 4))
            result.append(unpack("<I", self.usbread(4))[0])
        if len(result) == 1:
            # print(f"R:{hex(addr)}={hex(result[0])}")
            # sys.stdout.flush()
            return result[0]
        return result

    def write32(self, addr, dwords) -> bool:
        if isinstance(dwords, int):
            dwords = [dwords]
        for pos in range(0, len(dwords)):
            self.usbwrite(pack(">I", 0xf00dd00d))
            self.usbwrite(pack(">I", 0x4000))
            self.usbwrite(pack(">I", addr + (pos * 4)))
            self.usbwrite(pack(">I", 4))
            self.usbwrite(pack("<I", dwords[pos]))
            # print(f"W:{hex(addr)}={hex(dwords[pos])}")
            # sys.stdout.flush()
            if self.usbread(4) == b"\xD0\xD0\xD0\xD0":
                continue
            else:
                return False
        return True

    def cmd_C8(self, val) -> bool:
        """Clear cache func"""
        self.usbwrite(pack(">I", 0xf00dd00d))
        self.usbwrite(pack(">I", 0x5000))
        if self.usbread(4) == b"\xD0\xD0\xD0\xD0":
            return True
        return False

    def connect(self):
        self.cdc.connected = self.cdc.connect()
        return self.cdc.connected

    def close(self):
        if self.cdc.connected:
            self.cdc.close()

    def readflash(self, type_: int, start, length, display=False, filename: str = None):
        if not self.emmc_inited:
            self.init_emmc()
        wf = None
        pg = progress(pagesize=0x200, total=length)
        buffer = bytearray()
        if filename is not None:
            wf = open(filename, "wb")
        sectors = (length // 0x200)
        sectors += (1 if length % 0x200 else 0)
        startsector = (start // 0x200)
        # emmc_switch(1)
        self.usbwrite(pack(">I", 0xf00dd00d))
        self.usbwrite(pack(">I", 0x1002))
        self.usbwrite(pack(">I", type_))

        # kick-wdt
        # self.usbwrite(pack(">I", 0xf00dd00d))
        # self.usbwrite(pack(">I", 0x3001))

        bytestoread = length
        bytesread = 0
        old = 0
        # emmc_read(0)
        self.usbwrite(pack(">I", 0xf00dd00d))
        self.usbwrite(pack(">I", 0x1000))
        self.usbwrite(pack(">I", startsector))
        self.usbwrite(pack(">I", sectors))

        for sector in range(sectors):
            tmp = self.usbread(0x200)
            if not tmp or len(tmp) != 0x200:
                self.error("Error on getting data")
                return
            if display:
                pg.update(len(tmp))
            bytesread += len(tmp)
            size = min(bytestoread, len(tmp))
            if wf is not None:
                wf.write(tmp[:size])
            else:
                buffer.extend(tmp)
            bytestoread -= size
        if display:
            pg.done()
        if wf is not None:
            wf.close()
        else:
            return buffer[start % 0x200:(start % 0x200) + length]

    def userdata(self, start=0, length=32 * 0x200, filename="data.bin"):
        sectors = 0
        if length != 0:
            sectors = (length // 0x200) + (1 if length % 0x200 else 0)
        self.info("Reading user data...")
        if self.cdc.connected:
            self.readflash(type_=0, start=start, length=length, display=True, filename=filename)

    def preloader(self, start, length, filename):
        sectors = 0
        if start != 0:
            start = (start // 0x200)
        if length != 0:
            sectors = (length // 0x200) + (1 if length % 0x200 else 0)
        self.info("Reading preloader...")
        if self.cdc.connected:
            if sectors == 0:
                buffer = self.readflash(type_=1, start=0, length=0x4000, display=False)
                if len(buffer) != 0x4000:
                    print("Error on reading boot1 area.")
                    return
                if buffer[:9] == b'EMMC_BOOT':
                    startbrlyt = unpack("<I", buffer[0x10:0x14])[0]
                    if buffer[startbrlyt:startbrlyt + 5] == b"BRLYT":
                        start = unpack("<I", buffer[startbrlyt + 0xC:startbrlyt + 0xC + 4])[0]
                        st = buffer[start:start + 4]
                        if st == b"MMM\x01":
                            length = unpack("<I", buffer[start + 0x20:start + 0x24])[0]
                            data = self.readflash(type_=1, start=0, length=start + length, display=True)
                            if len(data) != start + length:
                                print("Warning, please rerun command, length doesn't match.")
                            idx = data.find(b"MTK_BLOADER_INFO")
                            if idx != -1:
                                filename = data[idx + 0x1B:idx + 0x3D].rstrip(b"\x00").decode('utf-8')
                            with open(os.path.join("logs", filename), "wb") as wf:
                                wf.write(data[start:start + length])
                                print(f"Done writing to {os.path.join('logs', filename)}")
                            with open(os.path.join("logs", "hdr_" + filename), "wb") as wf:
                                wf.write(data[:start])
                                print(f"Done writing to {os.path.join('logs', 'hdr_' + filename)}")

                            return
                else:
                    length = 0x40000
                    self.readflash(type_=1, start=0, length=length, display=True, filename=filename)
                    print("Done")
                print("Error on getting preloader info, aborting.")
            else:
                self.readflash(type_=1, start=start, length=length, display=True, filename=filename)
            print("Done")

    def boot2(self, start, length, filename):
        sectors = 0
        if start != 0:
            start = (start // 0x200)
        if length != 0:
            sectors = (length // 0x200) + (1 if length % 0x200 else 0)
        self.info("Reading boot2...")
        if self.cdc.connected:
            if sectors == 0:
                self.readflash(type_=2, start=0, length=0x40000, display=True, filename=filename)
                print("Done")
            else:
                self.readflash(type_=1, start=start, length=length, display=True, filename=filename)
            print("Done")

    def memread(self, start, length, filename=None):
        bytestoread = length
        addr = start
        data = b""
        pos = 0
        wf = None
        if filename is not None:
            wf = open(filename, "wb")
        while bytestoread > 0:
            size = min(bytestoread, 0x100)
            self.usbwrite(pack(">I", 0xf00dd00d))
            self.usbwrite(pack(">I", 0x4002))
            self.usbwrite(pack(">I", addr + pos))
            self.usbwrite(pack(">I", size))
            if filename is None:
                data += self.usbread(size)
            else:
                wf.write(self.usbread(size))
            bytestoread -= size
            pos += size
        self.info(f"{hex(start)}: {hexlify(data).decode('utf-8')}")
        if filename is not None:
            wf.close()
        return data

    def memwrite(self, start, data, filename=None):
        rf = None
        if filename is not None:
            rf = open(filename, "rb")
            bytestowrite = os.stat(filename).st_size
        else:
            if isinstance(data, str):
                data = bytes.fromhex(data)
            elif isinstance(data, int):
                data = pack("<I", data)
            bytestowrite = len(data)
        addr = start
        pos = 0
        while bytestowrite > 0:
            size = min(bytestowrite, 0x100)
            self.usbwrite(pack(">I", 0xf00dd00d))
            self.usbwrite(pack(">I", 0x4000))
            self.usbwrite(pack(">I", addr + pos))
            self.usbwrite(pack(">I", size))
            if filename is None:
                wdata = data[pos:pos + size]
            else:
                wdata = rf.read(size)
            bytestowrite -= size
            pos += size
            while len(wdata) % 4 != 0:
                wdata += b"\x00"
            self.usbwrite(wdata)

        if filename is not None:
            rf.close()
        ack = self.usbread(4)
        return ack == b"\xD0\xD0\xD0\xD0"

    def rpmb(self, start, length, filename, reverse=False):
        pg = progress(pagesize=0x100,total=length)
        if not self.emmc_inited:
            self.init_emmc()
        if start == 0:
            start = 0
        else:
            start = (start // 0x100)
        if start > 0xFFFF:
            start = 0xFFFF
        if length == 0:
            sectors = 16 * 1024 * 1024 // 0x100
        else:
            sectors = (length // 0x100) + (1 if length % 0x100 else 0)
        self.info("Reading rpmb...")

        self.usbwrite(pack(">I", 0xf00dd00d))
        self.usbwrite(pack(">I", 0x1002))
        self.usbwrite(pack(">I", 0x1))

        # kick-wdt
        # self.usbwrite(pack(">I", 0xf00dd00d))
        # self.usbwrite(pack(">I", 0x3001))

        bytesread = 0
        old = 0
        bytestoread = sectors * 0x100
        count = sectors
        pg = progress(pagesize=0x200,total=bytestoread)
        if sectors > 0xFFFF:
            count = 0xFFFF
        with open(filename, "wb") as wf:
            self.usbwrite(pack(">I", 0xf00dd00d))
            self.usbwrite(pack(">I", 0x2000))
            self.usbwrite(pack(">H", start))
            self.usbwrite(pack(">H", count))
            for sector in range(count):
                tmp = self.usbread(0x100)
                if reverse:
                    tmp = tmp[::-1]
                if len(tmp) != 0x100:
                    self.error("Error on getting data")
                    return
                pg.update(len(tmp))
                bytesread += 0x100
                size = min(bytestoread, len(tmp))
                wf.write(tmp[:size])
                bytestoread -= size
            while bytestoread > 0:
                self.usbwrite(pack(">I", 0xf00dd00d))
                self.usbwrite(pack(">I", 0x2000))
                self.usbwrite(pack(">H", sector + 1))
                self.usbwrite(pack(">H", 1))
                tmp = self.usbread(0x100)
                size = min(bytestoread, len(tmp))
                wf.write(tmp[:size])
                bytestoread -= size
                sector += 1
            pg.done()
            print("Done")

    def keys(self, data=b"", otp=None, mode="dxcc"):
        # self.hwcrypto.disable_range_blacklist("cqdma",self.cmd_C8)
        keyinfo = ""
        retval = {}
        meid = self.config.get_meid()
        socid = self.config.get_socid()
        self.config.hwparam = HwParam(self.config, meid, self.config.hwparam_path)
        if meid is not None:
            self.info(f"MEID        : {hexlify(meid).decode('utf-8')}")
        else:
            try:
                if self.config.chipconfig.meid_addr is not None:
                    meid = self.memread(self.config.chipconfig.meid_addr, 16)
                    self.config.set_meid(meid)
                    self.info(f"MEID        : {hexlify(meid).decode('utf-8')}")
                    retval["meid"] = hexlify(meid).decode('utf-8')
            except Exception as err:
                pass
        if socid is not None:
            self.info(f"SOCID        : {hexlify(socid).decode('utf-8')}")
            retval["socid"] = socid
        else:
            try:
                if self.config.chipconfig.socid_addr is not None:
                    socid = self.memread(self.config.chipconfig.socid_addr, 32)
                    self.config.set_socid(socid)
                    self.info(f"SOCID        : {hexlify(socid).decode('utf-8')}")
                    retval["socid"] = hexlify(socid).decode('utf-8')
            except Exception as err:
                pass
        if self.setup.dxcc_base is not None and mode not in ["sej_aes_decrypt", "sej_aes_encrypt", "sej_sst_decrypt_4g",
                                                             "sej_sst_decrypt_5g", "sej_sst_encrypt_5g",
                                                             "sej_sst_encrypt_4g", "dxcc_sha256"]:
            rpmbkey = self.hwcrypto.aes_hwcrypt(btype="dxcc", mode="rpmb")
            rpmb2key = self.hwcrypto.aes_hwcrypt(btype="dxcc", mode="rpmb2")
            fdekey = self.hwcrypto.aes_hwcrypt(btype="dxcc", mode="fde")
            ikey = self.hwcrypto.aes_hwcrypt(btype="dxcc", mode="itrustee")
            platkey, provkey = self.hwcrypto.aes_hwcrypt(btype="dxcc", mode="prov")
            keyinfo += "\nKeys :\n-----------------------------------------\n"
            keyinfo += f"RPMB:         {hexlify(rpmbkey).decode('utf-8')}\n"
            keyinfo += f"RPMB2:        {hexlify(rpmb2key).decode('utf-8')}\n"
            keyinfo += f"FDE :         {hexlify(fdekey).decode('utf-8')}\n"
            keyinfo += f"iTrustee:     {hexlify(ikey).decode('utf-8')}\n"
            keyinfo += f"Platform:     {hexlify(platkey).decode('utf-8')}\n"
            keyinfo += f"Provisioning: {hexlify(provkey).decode('utf-8')}\n"
            keyinfo += "\n"
            if rpmbkey is not None:
                self.info(f"RPMB        : {hexlify(rpmbkey).decode('utf-8')}")
                self.config.hwparam.writesetting("rpmbkey", hexlify(rpmbkey).decode('utf-8'))
                retval["rpmbkey"] = hexlify(rpmbkey).decode('utf-8')
            if rpmb2key is not None:
                self.info(f"RPMB2       : {hexlify(rpmb2key).decode('utf-8')}")
                self.config.hwparam.writesetting("rpmb2key", hexlify(rpmb2key).decode('utf-8'))
                retval["rpmb2key"] = hexlify(rpmb2key).decode('utf-8')
            if fdekey is not None:
                self.info(f"FDE         : {hexlify(fdekey).decode('utf-8')}")
                self.config.hwparam.writesetting("fdekey", hexlify(fdekey).decode('utf-8'))
                retval["fdekey"] = hexlify(fdekey).decode('utf-8')
            if ikey is not None:
                self.info(f"iTrustee    : {hexlify(ikey).decode('utf-8')}")
                self.config.hwparam.writesetting("kmkey", hexlify(ikey).decode('utf-8'))
                retval["kmkey"] = hexlify(ikey).decode('utf-8')
            if self.config.chipconfig.prov_addr:
                provkey = self.memread(self.config.chipconfig.prov_addr, 16)
                self.info(f"PROV        : {hexlify(provkey).decode('utf-8')}")
                self.config.hwparam.writesetting("provkey", hexlify(provkey).decode('utf-8'))
                retval["provkey"] = hexlify(provkey).decode('utf-8')
            return retval, keyinfo
        elif self.setup.sej_base is not None and mode not in ["sej_aes_decrypt", "sej_aes_encrypt", "sej_sst_decrypt_4g",
                                                             "sej_sst_decrypt_5g", "sej_sst_encrypt_5g",
                                                             "sej_sst_encrypt_4g", "dxcc_sha256"]:
            retval = {}
            rpmbkey = self.hwcrypto.aes_hwcrypt(mode="rpmb", data=meid, otp=otp, btype="sej")
            if rpmbkey:
                self.info(f"RPMB        : {hexlify(rpmbkey).decode('utf-8')}")
                self.config.hwparam.writesetting("rpmbkey", hexlify(rpmbkey).decode('utf-8'))
                retval["rpmbkey"] = hexlify(rpmbkey).decode('utf-8')
            self.info("Generating sej mtee...")
            mtee = self.hwcrypto.aes_hwcrypt(mode="mtee", otp=otp, btype="sej")
            if mtee:
                self.info(f"MTEE        : {hexlify(mtee).decode('utf-8')}")
                self.config.hwparam.writesetting("mtee", hexlify(mtee).decode('utf-8'))
                retval["mtee"] = hexlify(mtee).decode('utf-8')
            mtee3 = self.hwcrypto.aes_hwcrypt(mode="mtee3", otp=otp, btype="sej")
            if mtee3:
                self.info(f"MTEE3       : {hexlify(mtee3).decode('utf-8')}")
                self.config.hwparam.writesetting("mtee3", hexlify(mtee3).decode('utf-8'))
                retval["mtee3"] = hexlify(mtee3).decode('utf-8')

            keyinfo += "\nKeys :\n-----------------------------------------\n"
            keyinfo += f"RPMB: {hexlify(rpmbkey).decode('utf-8')}\n"
            keyinfo += f"MTEE: {hexlify(mtee).decode('utf-8')}\n"
            retval["rpmbkey"] = hexlify(rpmbkey).decode('utf-8')
            return retval, keyinfo
        if mode == "sej_aes_decrypt":
            dec_data = self.hwcrypto.aes_hwcrypt(mode="cbc", data=data, btype="sej", encrypt=False, otp=otp)
            keyinfo += f"\nData: {hexlify(dec_data).decode('utf-8')}\n"
            return dec_data, keyinfo
        elif mode == "sej_aes_encrypt":
            enc_data = self.hwcrypto.aes_hwcrypt(mode="cbc", data=data, btype="sej", encrypt=True, otp=otp)
            keyinfo += f"\nData: {hexlify(enc_data).decode('utf-8')}\n"
            return enc_data, keyinfo
        elif mode == "sej_sst_decrypt_4g":
            dec_data = self.hwcrypto.aes_hwcrypt(mode="sst_4g", data=data, btype="sej", encrypt=False, otp=otp)
            keyinfo += f"\nData: {hexlify(dec_data).decode('utf-8')}\n"
            return dec_data, keyinfo
        elif mode == "sej_sst_encrypt_4g":
            enc_data = self.hwcrypto.aes_hwcrypt(mode="sst_4g", data=data, btype="sej", encrypt=True, otp=otp)
            keyinfo += f"\nData: {hexlify(enc_data).decode('utf-8')}\n"
            return enc_data, keyinfo
        elif mode == "sej_sst_decrypt_5g":
            dec_data = self.hwcrypto.aes_hwcrypt(mode="sst_5g", data=data, btype="sej", encrypt=False, otp=otp)
            keyinfo += f"\nData: {hexlify(dec_data).decode('utf-8')}\n"
            return dec_data, keyinfo
        elif mode == "sej_sst_encrypt_5g":
            enc_data = self.hwcrypto.aes_hwcrypt(mode="sst_5g", data=data, btype="sej", encrypt=True, otp=otp)
            keyinfo += f"\nData: {hexlify(enc_data).decode('utf-8')}\n"
            return enc_data, keyinfo
        elif mode == "dxcc_sha256":
            sha256val = self.hwcrypto.aes_hwcrypt(mode="sha256", data=data, btype="dxcc")
            keyinfo += f"\nSHA256: {hexlify(sha256val).decode('utf-8')}\n"
            return sha256val, keyinfo
        return None, ""

    def reboot(self):
        print("Rebooting..")
        self.usbwrite(pack(">I", 0xf00dd00d))
        self.usbwrite(pack(">I", 0x3000))


def getint(valuestr):
    if valuestr == '':
        return None
    try:
        return int(valuestr)
    except Exception as err:
        err = err
        try:
            return int(valuestr, 16)
        except Exception as err:
            err = err
            pass
    return 0


cmds = {
    "rpmb": 'Dump rpmb',
    "preloader": 'Dump preloader',
    "data": 'Dump mmc data',
    "boot2": 'Dump boot2',
    "reboot": 'Reboot phone',
    "memread": "Read memory [Example: memread 0 0x10]",
    "memwrite": "Write memory [Example: memwrite 0x200000 1122334455667788, memwrite 0x0 0x12345678, " +
                "memwrite 0x0 data.bin]",
    "keys": "Extract rpmb and fde key",
    "seccfg": "Generate unlock config"
}

info = "MTK Stage2 client (c) B.Kerler 2021"


def main():
    parser = argparse.ArgumentParser(description=info)
    subparsers = parser.add_subparsers(dest="cmd",
                                       help='Valid commands are: rpmb, preloader, data, boot2, memread, memwrite, keys')

    parser_rpmb = subparsers.add_parser("rpmb", help="Dump the rpmb")
    parser_rpmb.add_argument('--start', dest='start', type=str,
                             help='Start offset to dump')
    parser_rpmb.add_argument('--length', dest='length', type=str,
                             help='Max length to dump')
    parser_rpmb.add_argument('--reverse', dest='reverse', action="store_true",
                             help='Reverse byte order (example: rpmb command)')
    parser_rpmb.add_argument('--filename', dest='filename', type=str,
                             help='Read from / save to filename')

    parser_preloader = subparsers.add_parser("preloader", help="Dump the preloader")
    parser_preloader.add_argument('--start', dest='start', type=str,
                                  help='Start offset to dump')
    parser_preloader.add_argument('--length', dest='length', type=str,
                                  help='Max length to dump')
    parser_preloader.add_argument('--filename', dest='filename', type=str,
                                  help='Read from / save to filename')

    parser_data = subparsers.add_parser("data", help="Read the mmc")
    parser_data.add_argument('--start', dest='start', type=str,
                             help='Start offset to dump')
    parser_data.add_argument('--length', dest='length', type=str,
                             help='Max length to dump')
    parser_data.add_argument('--filename', dest='filename', type=str,
                             help='Read from / save to filename')

    parser_boot2 = subparsers.add_parser("boot2", help="Dump boot2")
    parser_boot2.add_argument('--start', dest='start', type=str,
                              help='Start offset to dump')
    parser_boot2.add_argument('--length', dest='length', type=str,
                              help='Max length to dump')
    parser_boot2.add_argument('--filename', dest='filename', type=str,
                              help='Read from / save to filename')

    parser_memread = subparsers.add_parser("memread", help="Read memory")
    parser_memread.add_argument(dest='start', type=str,
                                help='Start offset to dump')
    parser_memread.add_argument(dest='length', type=str,
                                help='Max length to dump')
    parser_memread.add_argument('--filename', dest='filename', type=str,
                                help='Save to filename')

    parser_memwrite = subparsers.add_parser("memwrite", help="Write memory")
    parser_memwrite.add_argument(dest='start', type=str,
                                 help='Start offset to dump')
    parser_memwrite.add_argument('data', type=str,
                                 help='Data to write [hexstring, dword or filename]')

    parser_reboot = subparsers.add_parser("reboot", help="Reboot device")

    parser_seccfg = subparsers.add_parser("seccfg", help="Generate seccfg")
    parser_seccfg.add_argument('flag', type=str,
                               help='Option for generating: unlock or lock')
    parser_seccfg.add_argument('--sw', dest='sw', action="store_true",
                               help='Option for generating: sw or hw')

    parser_keys = subparsers.add_parser("keys", help="Write memory")
    parser_keys.add_argument('--otp', dest='otp', type=str,
                             help='OTP for keys (dxcc,sej,gcpu)')
    parser_keys.add_argument('--mode', dest='mode', default=None, type=str,
                             help='keymode (dxcc,sej,gcpu,sej_aes_decrypt,sej_aes_decrypt,' +
                                  'sej_sst_decrypt_4g,sej_sst_decrypt_5g,sej_sst_encrypt_4g,sej_sst_encrypt_5g')
    parser_keys.add_argument('--data', dest='data', default=None, type=str,
                             help='data')
    args = parser.parse_args()
    cmd = args.cmd
    if cmd not in cmds:
        parser.print_help()
        exit(0)

    if not os.path.exists("logs"):
        os.mkdir("logs")
    st2 = Stage2(args)
    if st2.connect():
        if not st2.preinit():
            exit(1)

        if cmd == "rpmb":
            if args.filename is None:
                filename = os.path.join("logs", "rpmb")
            else:
                filename = args.filename
            start = getint(args.start)
            length = getint(args.length)
            st2.rpmb(start, length, filename, not args.reverse)
        elif cmd == "preloader":
            if args.filename is None:
                filename = os.path.join("logs", "preloader")
            else:
                filename = args.filename
            start = getint(args.start)
            length = getint(args.length)
            st2.preloader(start, length, filename=filename)
        elif cmd == "data":
            if args.filename is None:
                filename = os.path.join("logs", "data")
            else:
                filename = args.filename
            start = getint(args.start)
            length = getint(args.length)
            st2.userdata(start, length, filename=filename)
        elif cmd == "boot2":
            if args.filename is None:
                filename = os.path.join("logs", "boot2")
            else:
                filename = args.filename
            start = getint(args.start)
            length = getint(args.length)
            st2.boot2(start, length, filename=filename)
        elif cmd == "memread":
            if args.start is None:
                print("Option --start is needed")
                exit(0)
            if args.length is None:
                print("Option --length is needed")
                exit(0)
            start = getint(args.start)
            length = getint(args.length)
            st2.memread(start, length, args.filename)
        elif cmd == "memwrite":
            if args.start is None:
                print("Option --start is needed")
                exit(0)
            if args.data is None:
                print("Option --data is needed")
                exit(0)
            start = getint(args.start)
            if os.path.exists(args.data):
                filename = args.data
                data = None
            else:
                if "0x" in args.data:
                    data = getint(args.data)
                else:
                    data = args.data
                filename = None
            if st2.memwrite(start, data, filename):
                print(f"Successfully wrote data to {hex(start)}.")
            else:
                print(f"Failed to write data to {hex(start)}.")
        elif cmd == "keys":
            keyinfo = ""
            data = b""
            if args.mode in ["sej_aes_decrypt", "sej_aes_encrypt", "sej_sst_decrypt_5g","sej_sst_decrypt_4g",
                             "sej_sst_encrypt_4g","sej_sst_encrypt_5g"]:
                if not args.data:
                    print("Option --data is needed")
                    exit(0)
                data = bytes.fromhex(args.data)
            # otp_hisense=bytes.fromhex("486973656E736500000000000000000000000000000000000000000000000000")
            # st2.jump(0x223449)
            keys, keyinfo = st2.keys(data=data, mode=args.mode, otp=args.otp)
            print(keyinfo)
            print("Wrote keys to logs/hwparam.json")
        elif cmd == "reboot":
            st2.reboot()
        elif cmd == "seccfg":
            critical_lock_state = 0
            if args.flag not in ["unlock", "lock"]:
                print("Valid flags are: unlock, lock")
                """
                  LKS_DEFAULT = 0x01
                  LKS_MP_DEFAULT = 0x02
                  LKS_UNLOCK = 0x03
                  LKS_LOCK = 0x04
                  LKS_VERIFIED = 0x05
                  LKS_CUSTOM = 0x06
                  """
                """
                LKCS_UNLOCK = 0x01
                LKCS_LOCK = 0x02
                """
                """
                SBOOT_RUNTIME_OFF = 0
                SBOOT_RUNTIME_ON  = 1
                """
                sys.exit(1)

            if args.flag == "unlock":
                lock_state = 3
                critical_lock_state = 1
            elif args.flag == "lock":
                lock_state = 1
                critical_lock_state = 0
            with open("seccfg.bin", "wb") as wf:
                seccfg_ver = 4
                seccfg_size = 0x3C
                sboot_runtime = 0
                seccfg_data = pack("<IIIIIII", 0x4D4D4D4D, seccfg_ver, seccfg_size, lock_state,
                                   critical_lock_state, sboot_runtime, 0x45454545)
                dec_hash = hashlib.sha256(seccfg_data).digest()
                if args.sw:
                    enc_hash = st2.hwcrypto.sej.sej_sec_cfg_sw(dec_hash, True)
                else:
                    enc_hash = st2.hwcrypto.sej.sej_sec_cfg_hw(dec_hash, True)
                data = seccfg_data + enc_hash
                data += b"\x00" * (0x200 - len(data))
                wf.write(data)
                print("Successfully wrote seccfg to seccfg.bin. You need to write seccfg.bin to partition seccfg.")
    st2.close()


if __name__ == "__main__":
    main()
