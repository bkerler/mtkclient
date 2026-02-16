import os
import sys
from struct import unpack, pack

from mtkclient.config.payloads import PathConfig
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.Hardware.hwcrypto import CryptoSetup, HwCrypto
from mtkclient.Library.utils import find_binary, do_tcp_keyserver
from mtkclient.Library.gui_utils import LogBase, logsetup
from mtkclient.Library.Hardware.seccfg import SecCfgV4, SecCfgV3
from binascii import hexlify
from mtkclient.Library.utils import MTKTee
import hashlib
import json


class LCmd:
    CUSTOM_READ = b"\x29"
    CUSTOM_WRITE = b"\x2A"
    ACK = b"\x5A"
    NACK = b"\xA5"


class LegacyExt(metaclass=LogBase):
    def __init__(self, mtk, legacy, loglevel):
        self.patched_read = False
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
        self.legacy = legacy
        self.Cmd = LCmd()
        self.da2 = None
        self.da2address = None

    def patch_da2_readmem(self, da2patched):
        """
        70 B5                                   PUSH            {R4-R6,LR}
        4A F2 C8 64 C8 F2 04 04                 MOV             R4, #0x8004A6C8
        63 6A                                   LDR             R3, [R4,#(ReadDWORD - 0x8004A6C8)]
        98 47                                   BLX             R3
        05 46                                   MOV             R5, R0
        63 6A                                   LDR             R3, [R4,#(ReadDWORD - 0x8004A6C8)]
        98 47                                   BLX             R3
        06 46                                   MOV             R6, R0
        04 2E                                   CMP             R6, #4
        04 DD                                   BLE             loc_8000BC6C
        28 46                                   MOV             R0, R5
        31 46                                   MOV             R1, R6
        63 69                                   LDR             R3, [R4,#(SendData - 0x8004A6C8)]
        98 47                                   BLX             R3
        02 E0                                   B               loc_8000BC72
        A3 6A                                   LDR             R3, [R4,#(SendDWORD - 0x8004A6C8)]
        28 68                                   LDR             R0, [R5]
        98 47                                   BLX             R3
        23 69                                   LDR             R3, [R4,#(SendChar - 0x8004A6C8)]
        5A 20                                   MOVS            R0, #0x5A ; 'Z'
        BD E8 70 40                             POP.W           {R4-R6,LR}
        18 47                                   BX              R3
        """
        da2patched = bytearray(da2patched)
        idx = da2patched.find(b"\x70\xB5\x4A\xF2\xC8\x64\xC8\xF2\x04\x04\x63\x6a\x98\x47\x05\x68\xFF\xF7\xEC\xFA")
        if idx != -1:
            # patch = bytes.fromhex("F0B54AF2C864C8F20404636A98470546636A984706464FF00007A36AE859984707F10407B742F8DB00BF23695A20BDE8F0401847")
            patch = bytes.fromhex(
                "70B54AF2C864C8F20404636A98470546636A98470646042E04DD284631466369984702E0A36A2868984723695A20BDE870401847")
            da2patched[idx:idx + len(patch)] = patch
            self.patched_read = True
            self.info("Legacy Fast Read is patched.")
        else:
            self.warning("Legacy Read is normal.")
        return da2patched

    def patch_da2(self, da2):
        da2patched = bytearray(da2)
        # Patch security READ_REG16_CMD
        check_addr = find_binary(da2, b"\x08\xB5\x4F\xF4\x50\x42")
        if check_addr is not None:
            da2patched[check_addr:check_addr + 6] = b"\x08\xB5\x00\x20\x08\xBD"
            self.info("Legacy DA2 is patched.")
        else:
            self.warning("Legacy address check not patched.")
        check_addr2 = find_binary(da2, b"\x30\xB5\x85\xB0\x03\xAB")
        if check_addr2 is not None:
            """
            PUSH            {R4-R6,LR}
            MOV             R4, #0x8004A6C8
            LDR             R3, [R4,#0x24]
            BLX             R3
            LDR             R3, [R4,#0x24]
            MOV             R5, R0
            BLX             R3
            MOV             R6, R0
            LDR             R0, [R5]
            ADD.W           R5, R5, #4
            LDR             R3, [R4,#0x28]
            BLX             R3
            SUB.W           R6, R6, #1
            CMP             R6, #0
            BNE             0x8000C1B6
            MOVS            R0, #0x5A
            LDR             R3, [R4,#0x10]
            POP.W           {R4-R6,LR}
            BX              R3
            """
            cmd_f0 = bytes.fromhex(
                "70 B5 4A F2 C8 64 C8 F2 04 04 63 6A 98 47 63 6A 05 46 98 47 06 46 4F F0 00 01 28 68 05 F1 04 05 A3 " +
                "6A 98 47 A6 F1 01 06 00 2E F6 D1 5A 20 23 69 BD E8 70 40 18 47")
            da2patched[check_addr2:check_addr2 + len(cmd_f0)] = cmd_f0
            self.info("Legacy DA2 CMD F0 is patched.")
        else:
            self.warning("Legacy DA2 CMD F0 not patched.")
        da2patched = self.patch_da2_readmem(da2patched)
        return da2patched

    @staticmethod
    def fix_hash(da1, da2, da2sig_len, hashpos, hashmode):
        da1 = bytearray(da1)
        dahash = None
        if hashmode == 0:
            dahash = hashlib.md5(da2[:-da2sig_len]).digest()
        elif hashmode == 1:
            dahash = hashlib.sha1(da2[:-da2sig_len]).digest()
        elif hashmode == 2:
            dahash = hashlib.sha256(da2[:-da2sig_len]).digest()
        da1[hashpos:hashpos + len(dahash)] = dahash
        return da1

    def readmem(self, addr, dwords=1):
        res = self.custom_read(addr, dwords * 4, registers=True)
        if dwords == 1:
            return int.from_bytes(res, 'little')
        return res

    def custom_read_reg32(self, addr: int, dwords: int = 1):
        if self.usbwrite(b"\x7A"):  # 0x7A
            self.usbwrite(pack(">I", addr))
            self.usbwrite(pack(">I", dwords * 4))
            data = self.usbread(dwords * 4)
            if dwords == 1:
                data = int.from_bytes(data, byteorder='little')
            ack = self.usbread(1)
            if ack == b"\x5A":
                return data
        return None

    def custom_read(self, addr, length, registers=True):
        if self.patched_read and not registers:
            dwords = length // 4
            if length % 4 != 0:
                dwords += 1
            data = self.custom_read_reg32(addr, dwords)
            return data[:length]
        elif self.patched_read and registers:
            dwords = length // 4
            if length % 4 != 0:
                dwords += 1
            data = bytearray(b"".join(int.to_bytes(val, 4, 'little') for val in
                                      [self.custom_read_reg32(addr + pos * 4, 1) for pos in range(dwords)]))
            return data[:length]
        else:
            dwords = length // 4
            if length % 4 != 0:
                dwords += 1
            data = bytearray(b"".join(int.to_bytes(val, 4, 'little') for val in
                                      [self.legacy.read_reg32(addr + pos * 4) for pos in range(dwords)]))
            # res = self.legacy.custom_F0(addr, dwords)
            # data = bytearray(b"".join([int.to_bytes(val,4,'little') for val in res]))
            return data[:length]

    def writeregister(self, addr, dwords):
        if isinstance(dwords, int):
            dwords = [dwords]
        pos = 0
        if len(dwords) < 0x20:
            for val in dwords:
                if not self.legacy.write_reg32(addr + pos, val):
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

    def custom_write(self, addr, data):
        return self.writemem(addr, data)

    def setotp(self, hwc):
        otp = None
        if self.mtk.config.preloader is not None:
            idx = self.mtk.config.preloader.find(b"\x4D\x4D\x4D\x01\x30")
            if idx != -1:
                otp = self.mtk.config.preloader[idx + 0xC:idx + 0xC + 32]
        if otp is None:
            otp = 32 * b"\x00"
        hwc.sej.sej_set_otp(otp)

    def cryptosetup(self):
        setup = CryptoSetup()
        setup.blacklist = self.config.chipconfig.blacklist
        setup.gcpu_base = self.config.chipconfig.gcpu_base
        setup.dxcc_base = self.config.chipconfig.dxcc_base
        setup.hwcode = self.config.hwcode
        setup.da_payload_addr = self.config.chipconfig.da_payload_addr
        setup.sej_base = self.config.chipconfig.sej_base
        setup.read32 = self.readmem
        setup.write32 = self.writeregister
        setup.writemem = self.writemem
        return HwCrypto(setup, self.loglevel, self.config.gui)

    def seccfg(self, lockflag):
        if lockflag not in ["unlock", "lock"]:
            return False, "Valid flags are: unlock, lock"
        data, guid_gpt = self.legacy.partition.get_gpt(self.mtk.config.gpt_settings, "user")
        seccfg_data = None
        partition = None
        if guid_gpt is not None:
            for rpartition in guid_gpt.partentries:
                if rpartition.name == "seccfg":
                    partition = rpartition
                    seccfg_data = self.legacy.readflash(
                        addr=partition.sector * self.mtk.daloader.daconfig.pagesize,
                        length=partition.sectors * self.mtk.daloader.daconfig.pagesize,
                        filename="", parttype="user", display=False)
                    break
        if seccfg_data is None:
            return False, "Couldn't detect existing seccfg partition. Aborting unlock."
        hwc = self.cryptosetup()
        if seccfg_data[:0xC] == b"AND_SECCFG_v":
            self.info("Detected V3 Lockstate")
            sc_org = SecCfgV3(hwc, self.mtk)
            if not sc_org.parse(seccfg_data):
                return False, "Device has is either already unlocked or algo is unknown. Aborting."
        elif seccfg_data[:4] == b"\x4D\x4D\x4D\x4D":
            self.info("Detected V4 Lockstate")
            sc_org = SecCfgV4(hwc, self.mtk)
            if not sc_org.parse(seccfg_data):
                return False, "Device has is either already unlocked or algo is unknown. Aborting."
        else:
            res=input("Unknown lockstate or no lockstate. Shall I write a new one ?\n" +
                "Dangerous !! Type \"v3\" or \"v4\" for a new state. Press just enter to cancel.")
            if res == "v3":
                sc_org = SecCfgV3(hwc, self.mtk)
            elif res == "v4":
                sc_org = SecCfgV4(hwc, self.mtk)
            else:
                return False, "Unknown lockstate or no lockstate"
        ret, writedata = sc_org.create(lockflag=lockflag)
        if ret is False:
            return False, writedata
        if self.legacy.writeflash(addr=partition.sector * self.mtk.daloader.daconfig.pagesize,
                                  length=len(writedata),
                                  filename="", wdata=writedata, parttype="user", display=True):
            return True, "Successfully wrote seccfg."
        return False, "Error on writing seccfg config to flash."

    def decrypt_tee(self, filename="tee1.bin", aeskey1: bytes = None, aeskey2: bytes = None):
        hwc = self.cryptosetup()
        if os.path.exists(filename):
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

    def read_pubk(self):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            addr = base + 0x90
            data = bytearray(self.mtk.daloader.peek(addr=addr, length=0x30, registers=True))
            return data
        return None

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
        # data = b"".join([pack("<I", val) for val in self.readmem(0x111418EC, 0x20000 // 4)])
        # print(data.hex())
        sys.stdout.flush()
        if self.config.meid is None:
            try:
                data = self.readmem(base + 0x8EC, 0x10 // 4)
                self.config.meid = data
                self.config.set_meid(data)
            except Exception as err:
                self.error("Error retrieving meid: " + str(err))
                return
        if self.config.socid is None:
            try:
                data = self.readmem(base + 0x934, 0x20 // 4)
                self.config.socid = data
                self.config.set_socid(data)
            except Exception as err:
                self.error("Error retrieving socid: " + str(err))
                return
        hwc = self.cryptosetup()
        retval = {"hwcode": hex(self.config.hwcode)}
        meid = self.config.get_meid()
        socid = self.config.get_socid()
        hwcode = self.config.get_hwcode()
        pubk = self.read_pubk()
        if pubk is not None:
            retval["pubkey"] = pubk.hex()
            self.info(f"PUBK        : {pubk.hex()}")
            self.config.hwparam.writesetting("pubkey", pubk.hex())
        if meid is not None:
            self.info(f"MEID        : {hexlify(meid).decode('utf-8')}")
            retval["meid"] = hexlify(meid).decode('utf-8')
            self.config.hwparam.writesetting("meid", hexlify(meid).decode('utf-8'))
        if socid is not None:
            self.info(f"SOCID       : {hexlify(socid).decode('utf-8')}")
            retval["socid"] = hexlify(socid).decode('utf-8')
            self.config.hwparam.writesetting("socid", hexlify(socid).decode('utf-8'))
        if hwcode is not None:
            self.info(f"HWCODE      : {hex(hwcode)}")
            retval["hwcode"] = hex(hwcode)
            self.config.hwparam.writesetting("hwcode", hex(hwcode))
        if self.mtk.config.chipconfig.efuse_addr:
            hrid = self.mtk.daloader.peek(self.mtk.config.chipconfig.efuse_addr + 0x140, 8)
            if hrid is not None:
                self.info("HRID        : " + hexlify(hrid).decode('utf-8'))
                retval["hrid"] = hexlify(hrid).decode('utf-8')
                self.config.hwparam.writesetting("hrid", hexlify(hrid).decode('utf-8'))
                hrid_md5 = hashlib.md5(hrid + hrid).hexdigest()
                retval["hrid_md5"] = hrid_md5
                self.info("HRID MD5    : " + hrid_md5)
                self.config.hwparam.writesetting("hrid_md5", hrid_md5)
        if self.config.chipconfig.dxcc_base is not None:
            self.info("Generating dxcc rpmbkey...")
            rpmbkey = hwc.aes_hwcrypt(btype="dxcc", mode="rpmb")
            self.info("Generating dxcc fdekey...")
            fdekey = hwc.aes_hwcrypt(btype="dxcc", mode="fde")
            self.info("Generating dxcc rpmbkey2...")
            rpmb2key = hwc.aes_hwcrypt(btype="dxcc", mode="rpmb2")
            self.info("Generating dxcc km key...")
            ikey = hwc.aes_hwcrypt(btype="dxcc", mode="itrustee", data=self.config.hwparam.appid)
            # self.info("Generating dxcc platkey + provkey key...")
            # platkey, provkey = hwc.aes_hwcrypt(btype="dxcc", mode="prov")
            # self.info("Provkey     : " + hexlify(provkey).decode('utf-8'))
            # self.info("Platkey     : " + hexlify(platkey).decode('utf-8'))
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
                provkey = self.custom_read(self.config.chipconfig.prov_addr, 16)
                self.info(f"PROV        : {hexlify(provkey).decode('utf-8')}")
                self.config.hwparam.writesetting("provkey", hexlify(provkey).decode('utf-8'))
                retval["provkey"] = hexlify(provkey).decode('utf-8')
            if hwcode == 0x699 and self.config.chipconfig.sej_base:
                otp = self.config.get_otp()
                mtee3 = hwc.aes_hwcrypt(mode="mtee3", btype="sej", otp=otp)
                if mtee3:
                    self.info(f"MTEE3       : {hexlify(mtee3).decode('utf-8')}")
                    self.config.hwparam.writesetting("mtee3", hexlify(mtee3).decode('utf-8'))
                    retval["mtee3"] = hexlify(mtee3).decode('utf-8')
            return retval
        elif self.config.chipconfig.sej_base is not None:
            if os.path.exists("tee.json"):
                val = json.loads(open("tee.json", "r").read())
                self.decrypt_tee(val["filename"], bytes.fromhex(val["data"]), bytes.fromhex(val["data2"]))
            if meid == b"":
                if self.config.chipconfig.meid_addr is None:
                    meid_addr = 0x1008ec
                else:
                    meid_addr = self.config.chipconfig.meid_addr
                meid = self.readmem(meid_addr, 4)
            if meid != b"":
                otp = self.config.get_otp()
                self.info("Generating sej rpmbkey...")
                self.setotp(hwc)
                rpmbkey = hwc.aes_hwcrypt(mode="rpmb", data=meid, btype="sej", otp=otp)
                rpmbkey6580 = hwc.aes_hwcrypt(mode="rpmb6580", btype="sej", otp=otp)
                if rpmbkey:
                    self.info(f"RPMB        : {hexlify(rpmbkey).decode('utf-8')}")
                    self.config.hwparam.writesetting("rpmbkey", hexlify(rpmbkey).decode('utf-8'))
                    retval["rpmbkey"] = hexlify(rpmbkey).decode('utf-8')
                if rpmbkey6580:
                    self.info(f"RPMB_6580        : {hexlify(rpmbkey6580).decode('utf-8')}")
                    self.config.hwparam.writesetting("rpmbkey6580", hexlify(rpmbkey6580).decode('utf-8'))
                    retval["rpmbkey6580"] = hexlify(rpmbkey6580).decode('utf-8')
                self.info("Generating sej mtee...")
                mtee = hwc.aes_hwcrypt(mode="mtee", btype="sej", otp=otp)
                if mtee:
                    self.info(f"MTEE        : {hexlify(mtee).decode('utf-8')}")
                    self.config.hwparam.writesetting("mtee", hexlify(mtee).decode('utf-8'))
                    retval["mtee"] = hexlify(mtee).decode('utf-8')
                self.info("Generating sej mtee3...")
                mtee3 = hwc.aes_hwcrypt(mode="mtee3", btype="sej", otp=otp)
                if mtee3:
                    self.info(f"MTEE3       : {hexlify(mtee3).decode('utf-8')}")
                    self.config.hwparam.writesetting("mtee3", hexlify(mtee3).decode('utf-8'))
                    retval["mtee3"] = hexlify(mtee3).decode('utf-8')
            else:
                self.info("SEJ Mode: No meid found. Are you in brom mode ?")
        if self.config.chipconfig.gcpu_base is not None:
            if self.config.hwcode in [0x335, 0x8167, 0x8168, 0x8163, 0x8176]:
                self.info("Generating gcpu mtee2 key...")
                mtee2 = hwc.aes_hwcrypt(btype="gcpu", mode="mtee")
                if mtee2 is not None:
                    self.info(f"MTEE2       : {hexlify(mtee2).decode('utf-8')}")
                    self.config.hwparam.writesetting("mtee2", hexlify(mtee2).decode('utf-8'))
                    retval["mtee2"] = hexlify(mtee2).decode('utf-8')
        self.config.hwparam.writesetting("hwcode", retval["hwcode"])
        return retval

    def custom_read_reg(self, addr: int, length: int) -> bytes:
        return self.custom_read(addr, length)
