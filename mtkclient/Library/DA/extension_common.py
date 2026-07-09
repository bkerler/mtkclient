import hashlib
import json
import os
from struct import unpack, pack

from Cryptodome.Cipher import AES

from mtkclient.Library.Hardware.hwcrypto_sej import sej_cryptmode
from mtkclient.Library.mtk_crypto import verify_checksum, SST_Get_NVRAM_SW_Key, nvram_keys
from mtkclient.Library.utils import do_tcp_keyserver, MTKTee
from mtkclient.Library.Hardware.seccfg import SecCfgV3, SecCfgV4


class DaExtCommonMixin:
    """Logic identical across LegacyExt, XFlashExt and XmlFlashExt."""

    def setotp(self, hwc):
        otp = None
        if self.mtk.config.preloader is not None:
            idx = self.mtk.config.preloader.find(b"\x4D\x4D\x4D\x01\x30")
            if idx != -1:
                otp = self.mtk.config.preloader[idx + 0xC:idx + 0xC + 32]
        if otp is None:
            otp = 32 * b"\x00"
        hwc.sej.sej_set_otp(otp)

    def keyserver(self):
        hwc = self.cryptosetup()
        if self.config.chipconfig.dxcc_base is not None:
            self.info("Starting key server...")
            do_tcp_keyserver(hwc)
        return

    def writemem(self, addr, data):
        for i in range(0, len(data), 4):
            value = data[i:i + 4]
            while len(value) < 4:
                value += b"\x00"
            self.writeregister(addr + i, unpack("<I", value))
        return True


class XFlashXmlCommonMixin(DaExtCommonMixin):
    """Logic identical between XFlashExt and XmlFlashExt only."""

    def _finalize_seccfg(self, seccfg_data, lockflag, partition):
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

    def custom_read_reg(self, addr: int, length: int) -> bytes:
        tmp = self.custom_readregister(addr, length // 4)
        if isinstance(tmp, int):
            return int.to_bytes(tmp, 4, 'little')
        else:
            data = bytearray(b"".join([tmp[i].to_bytes(4, 'little') for i in range(len(tmp))]))
        return data

    def auth_rpmb(self, rpmbkey: bytes = None):
        if self.custom_rpmb_init(rpmbkey):
            return True
        return False

    def protect(self, data):
        return data
        hrid = self.mtk.daloader.peek(self.config.chipconfig.efuse_addr + 0x140, 8)
        hwcode = int.to_bytes(self.config.hwcode, 4, 'little')
        for i in range(len(data)):
            data[i] = data[i] ^ hrid[i % 8]
        for i in range(len(data)):
            data[i] = data[i] ^ hwcode[i % 4]
        return data

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

    def _write_hrid_hashes(self, retval):
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

    def _write_mtee3_dxcc(self, hwc, retval, hwcode):
        if hwcode == 0x699 and self.config.chipconfig.sej_base is not None:
            mtee3 = hwc.aes_hwcrypt(mode="mtee3", btype="sej")
            if mtee3:
                self.config.hwparam.writesetting("mtee3", mtee3.hex())
                self.info(f"MTEE3       : {mtee3.hex()}")
                retval["mtee3"] = mtee3.hex()

    def _decrypt_nvitem_entries(
            self, data, items, nvitemsize, attr, cryptmode, swcrypt, encrypt, otp, seed, aeskey, display, sw, hwc):
        outdata = bytearray()
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
            if attr & 0x20 and not encrypt:
                if not verify_checksum(ddata):
                    cryptmode = sej_cryptmode.HW_ENCRYPTED
                    status, ddata = self.custom_sej_hw(encrypt=encrypt,
                                                       data=data[0x40 + (x * nvitemsize):
                                                                 0x40 + (x * nvitemsize) + nvitemsize],
                                                       cryptmode=cryptmode, swcrypt=swcrypt, otp=otp, seed=seed,
                                                       aeskey=aeskey)
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

    def _populate_basic_keys(self, retval, pubk, meid, socid, hwcode, cid):
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

    def _generate_sej_gcpu_keys(self, hwc, meid, otp, retval, extra_after_rpmbkey=None):
        if self.config.chipconfig.sej_base is not None:
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
                if extra_after_rpmbkey is not None:
                    extra_after_rpmbkey(hwc, otp, retval)
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

    def _generate_dxcc_keys(self, hwc, retval):
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
