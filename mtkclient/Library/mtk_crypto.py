#!/usr/bin/env python3
import hmac
import json
import math
import os
import sys
from enum import Enum

from Cryptodome.Cipher import AES
import hashlib

from Cryptodome.PublicKey import RSA
from Cryptodome.Util.number import long_to_bytes, bytes_to_long

from mtkclient.Library.gui_utils import structhelper_io

NVRAM_CUSTOM_KEY = bytearray(b"12abcdef")
CODED_LOCK_PATTERN_SIZE = 12
CODED_LOCK_PATTERN_OFFSET = 22

nvram_keys = {
    "mtk": bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000"),
    "mtkv2": bytes.fromhex("425431988FD5AFE5EA6ACD443F382EFEFB6124B5814C376B759F21B484213B8F"),
    "samsung": bytes.fromhex("C1A2B1D9B1DDC1F621436F6E666964656E7469616C53414D53554E4700000000")
}


def aes_cbc(key, iv, data, decrypt=True):
    if decrypt:
        return AES.new(key, AES.MODE_CBC, IV=iv).decrypt(data)
    else:
        return AES.new(key, AES.MODE_CBC, IV=iv).encrypt(data)


def aes_ecb(key, iv, data, decrypt=True):
    if decrypt:
        return AES.new(key, AES.MODE_ECB).decrypt(data)
    else:
        return AES.new(key, AES.MODE_ECB).encrypt(data)


def sod(wert):
    a = math.floor(wert // 10)
    b = math.floor(wert - (10 * a))
    return a + b


def make_cd(IMEI_String):
    work = IMEI_String.upper()
    IMEI = bytearray(b"\x00" * 15)
    a = bytearray(b"\x00" * 7)
    IMEI[14] = 0

    for i in range(14):
        IMEI[i] = int(work[i])
    j = 0
    for i in range(1, 14, 2):
        a[j] = IMEI[i] * 2
        j += 1

    sum = 0
    for i in range(7):
        sum = sum + sod(a[i])
    for i in range(0, 13, 2):
        sum = sum + IMEI[i]

    if (math.floor(sum // 10) == (sum / 10)):
        IMEI[14] = 0
    else:
        IMEI[14] = ((math.floor(sum // 10) + 1) * 10) - sum
    return IMEI[14]


def luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]

    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    for i in range(len(even_digits)):
        digit = even_digits[i] * 2
        if digit > 9:
            digit = digit // 10 + digit % 10
        even_digits[i] = digit
    checksum = 0
    checksum += sum(odd_digits)
    checksum += sum(even_digits)
    v = checksum % 10
    return v


def make_luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]

    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = 0
    checksum += sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    if (math.floor(checksum // 10) == (checksum / 10)):
        return 0
    else:
        return ((math.floor(checksum // 10) + 1) * 10) - checksum


def is_luhn_valid(card_number):
    return luhn_checksum(card_number) == 0


def calc_checksum(data, itemsize):
    hash = bytearray(hashlib.md5(data[:itemsize]).digest())
    for i in range(8):
        hash[i] = hash[i] ^ hash[i + 8]
    return hash[:8]


def decode_imei(data):
    imei = ""
    data = bytearray(data)
    for x in range(8):
        imei += "%0x" % (data[x] & 0xF)
        val = (data[x] & 0xF0) >> 4
        if val == 0xf:
            break
        imei += "%0x" % val
    return imei[:15]


def encode_imei(data):
    imei = b""
    data = data[:15]
    data += "F"
    for x in range(0, 16, 2):
        v = int(data[x], 16) + (int(data[x + 1], 16) << 4)
        imei += int.to_bytes(v, 1, 'little')
    return imei

#  custom_nvram_decrypt(nvram_ptr->secret_key, lock_pattern, CODED_LOCK_PATTERN_SIZE, 0);


def custom_nvram_IV_generator(A, B, X, C):
    if (X > B):
        hashIndex = ((A * (X - B) + C) % 256)
    else:
        hashIndex = ((A * (B - X) + C) % 256)
    return hashIndex


def nvram_decrypt(secret_key, lock_pattern, length, scramble_index):
    if scramble_index == 0:
        init_vector = 0
    else:
        init_vector = scramble_index
    return nvram_rc4_cipher(secret_key, lock_pattern, length, init_vector)


def nvram_rc4_cipher(key, buffer, length, init_vector):
    endpos = length + init_vector
    keybuf = bytearray([key[i] for i in range(len(key))])
    buffer = bytearray(buffer)
    pos = 0
    tmp1 = 0
    tmppos = 0
    while pos != endpos:
        tmp1 = (tmp1 + 1) & 0xFF
        tmp2 = keybuf[tmp1]
        tmppos = (tmppos + tmp2) & 0xFF
        keybuf[tmp1] = keybuf[tmppos]
        keybuf[tmppos] = tmp2
        if pos >= init_vector:
            buffer[-init_vector + pos] ^= keybuf[(tmp2 + keybuf[tmp1]) & 0xFF]
        pos += 1
    return buffer


def nvram_get_key(key):
    tkey = bytearray(b"\x00" * 4)
    for x in range(4):
        tkey[x] = int(key[(x * 2):(x * 2) + 2], 16)
    outptr = bytearray([i for i in range(256)])
    pos = 0
    tmp = 0
    for t in range(256):
        result = outptr[t]
        tmp = (tkey[pos] + result + tmp) & 0xFF
        outptr[t] = outptr[tmp]
        outptr[tmp] = result
        pos = (pos + 1) & 3
    return outptr


def CustCHL_Get_Sym_Key(hrid):
    key = bytearray(b"MTK_HRIDDIRH_KTMMTK_HRIDDIRH_KTM")
    hriddata = bytearray()
    for i in range(0, 32, 4):
        if (i & 4) != 0:
            hriddata.extend(hrid[16:16 + 4])
        else:
            hriddata.extend(hrid[:4])
    return CustCHL_AES_Encrypt(key, hriddata)


def CustCHL_Gen_Root_Key(hrid):
    # HMAC Key for end of CSSSD file
    key = bytes.fromhex("A65A01A33EDCEA60CC259E0C219ABE1F84C2F4DD6C8C417AC34C2A15FD47D262")
    hrid = hrid + hrid
    return CustCHL_AES_Encrypt(key, hrid)


def CustCHL_AES_Encrypt(key, data):
    iv = bytes.fromhex("7F62238222C39A57075E1DE3234A5649DE654ABE661DED4CA56B581A967E7D95")
    ctx = che()
    ctx.set_iv(iv, 0x20)
    ctx.set_key_process(key, 0x20)
    key = ctx.aes_process(4, 2, 1, data, None, 0x32, 0, 0)
    return key


class SST_Get_NVRAM_Key:
    databasekey = None

    def __init__(self, data):
        pattern = b"\xA4\xB5\xA4\xE9\xA4\x73\xB9\xEB\xA9\xFA\xA4\xE9\xA5\x44\xAC\x79"
        if data[0x40:0x40 + 0x10] == pattern:
            self.databasekey = data[:0x40]
        else:
            self.databasekey = None
        """
        che_rc4_set_key((RC4_CNXT *)&cnxt, (kal_uint32)real_key_len, (kal_uint8 *)key);
        che_rc4((RC4_CNXT *)&cnxt, p_g_u1_ft_nvram_pdu_ptr , g_u2_ft_nvram_pdu_length, key, real_key_len, CHE_MODE_NULL, output_data);
        """


def SST_Scramble_NVRAM_Key_Source(iv, buffer):
    iv = bytearray(iv)
    buffer = bytearray(buffer)
    second_seed_cpy = bytes.fromhex("8F9C6151DC86B9163A37506D9DFF7753464BA73E5EDEF3625BA18D481235805B")
    for i in range(0, 0x20, 2):
        tmp = iv[i + 1]
        iv[i + 1] = iv[i]
        iv[i] = tmp
    for i in range(0, 0x20, 2):
        tmp = buffer[i + 1]
        buffer[i + 1] = buffer[i]
        buffer[i] = tmp
    for i in range(0x20):
        bv1 = iv[i] ^ second_seed_cpy[i]
        iv[i] = bv1
        buffer[i] = bv1 ^ buffer[i]
    return iv, buffer


class che:
    iv = bytearray(b"\x00" * 16)
    key = bytearray(b"\x00" * 16)

    def __init__(self):
        pass

    def set_iv(self, iv, ivlen):
        self.iv = iv[:ivlen]

    def set_key_process(self, key, keylen):
        self.key = key[:keylen]

    def aes_process(self, mode4=4, algo=2, mode=1, data=b"", outbuffer=None, datalen=0x100, flag0=0, flag1=0):
        if algo == 2 and mode == 1:
            outbuffer = AES.new(self.key, AES.MODE_CBC, iv=self.iv[:0x10]).encrypt(data)
        elif algo == 1:
            # outbuffer=aes_f8(self.iv,self.key,None,data)[:datalen]
            if mode == 1:
                outbuffer = AES.new(self.key, AES.MODE_ECB).encrypt(data)
            else:
                outbuffer = AES.new(self.key, AES.MODE_ECB).decrypt(data)
        elif algo == 3:
            if mode == 3:
                outbuffer = AES.new(self.key, AES.MODE_CTR, nonce=self.iv).decrypt(data)
            elif mode == 1:
                outbuffer = AES.new(self.key, AES.MODE_CTR, nonce=self.iv).encrypt(data)
        return outbuffer


def SST_Get_NVRAM_SW_Key(iv, keylength):
    nvsw_kgen = bytes.fromhex(
        "BE410C67394D98017256AA3C8F21BB42CE75601B8F7BC3078216362B151F7F0196E9EB0431739C7438E4920CB18F0961956BE82D9D68403207B07A3687351302C718AD6B10EB571DCB8CFD250BAA0D55987C19528445B2728BFC252189FEF97446765F5C803309566DB380251A7CE31EB4751A06DBB2B0037B2F391D72B7266D14004905ED85E35901D9E12FE275A9207C01A76183EF175BF894282212EB9266B462B44F3079BB2EC37A9C4749CE9C7DCDE1FB60CB2A177ED103B07F95FAA84CDB156F1B9C90AD25A0A4B6217392886D20D65F182CA1DC42FD908262674CBF74ACD4E5186A44030881C8A213604A001F45F7B30BFCF7DB30D301270C59F7FC10")
    key = bytes.fromhex("3523325342455424438668347856341278563412438668344245542435233253")
    iv, key = SST_Scramble_NVRAM_Key_Source(iv, key)
    ctx = che()
    ctx.set_iv(iv, 0x20)
    ctx.set_key_process(key, 0x20)
    key = ctx.aes_process(4, 2, 1, nvsw_kgen, None, 0x100, 0, 0)
    return key[:keylength]


def decrypt_nvitem(data, key=None):
    # mtk
    if key is None:
        nvram_custom_key_seed = bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")
    else:
        nvram_custom_key_seed = bytes.fromhex(key)
    # blu
    # nvram_custom_key_seed = bytes.fromhex("425431988FD5AFE5EA6ACD443F382EFEFB6124B5814C376B759F21B484213B8F")
    # samsung
    # nvram_custom_key_seed = bytes.fromhex("C1A2B1D9B1DDC1F621436F6E666964656E7469616C53414D53554E4700000000")
    nvramkey = SST_Get_NVRAM_SW_Key(nvram_custom_key_seed, 0x10)
    ctx = che()
    ctx.set_key_process(nvramkey, 0x10)
    dec = ctx.aes_process(4, 1, 2, data, data, len(data), 0x6F, 0x6F)
    return dec


def encrypt_nvitem(data, key=None):
    if key is None:
        nvram_custom_key_seed = bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")
    else:
        nvram_custom_key_seed = key
    nvramkey = SST_Get_NVRAM_SW_Key(nvram_custom_key_seed, 0x10)
    ctx = che()
    ctx.set_key_process(nvramkey, 0x10)
    dec = ctx.aes_process(4, 1, 1, data, data, len(data), 0x6F, 0x6F)
    return dec


def decrypt_nvitem_rc4(data, key=None):
    # mtk
    if key is None:
        nvram_custom_key_seed = bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")
    else:
        nvram_custom_key_seed = key
    # blu
    # nvram_custom_key_seed = bytes.fromhex("425431988FD5AFE5EA6ACD443F382EFEFB6124B5814C376B759F21B484213B8F")
    # samsung
    # nvram_custom_key_seed = bytes.fromhex("C1A2B1D9B1DDC1F621436F6E666964656E7469616C53414D53554E4700000000")
    nvramkey = SST_Get_NVRAM_SW_Key(nvram_custom_key_seed, 0x100)
    dec = nvram_decrypt(nvramkey, data, len(data), 0)
    return dec


def encrypt_nvitem_rc4(data, key=None):
    if key is None:
        nvram_custom_key_seed = bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")
    else:
        nvram_custom_key_seed = key
    nvramkey = SST_Get_NVRAM_SW_Key(nvram_custom_key_seed, 0x100)
    dec = nvram_decrypt(nvramkey, data, len(data), 0)
    return dec


def nvram_data_header_checksum(data):
    data = bytearray(data)
    chksum = int.from_bytes(data[:2], byteorder='little')
    for i in range(len(data)):
        chksum = chksum & 0xFF00 | ((chksum + data[i]) & 0xFF)
    return chksum


def checksum_8b(data, itemsize):
    hash = bytearray(hashlib.md5(data[:itemsize]).digest())
    for i in range(8):
        hash[i] = hash[i] ^ hash[i + 8]
    return hash[:8]


def checksum_2b(data):
    value = 0
    data = bytearray(data)
    for i in range(len(data)):
        if i % 2 == 0:
            value = (value + data[i]) & 0xFF
        else:
            value ^= data[i]
    return (0xAA << 8) + (value & 0xFF)


def intval32(value):
    value = value & 0xFFFFFFFF
    if value & 0x80000000:
        value = -((~value & 0xFFFFFFFF) + 1)
    return value


def checksum_nvram(data):
    data = bytearray(data)
    size = len(data)
    sum = 0
    tempNum = 0
    for i in range(0, size, 4):
        value = int.from_bytes(data[i:i + 4], 'little')
        if len(data[i:i + 4]) % 4 != 0:
            tempNum = value
            break
        sum = (sum ^ value if (i // 4) % 2 == 0 else sum + value) & 0xFFFFFFFF
    return intval32((sum + tempNum)) ^ size


def verify_checksum(data, length=0xA):
    checksum = bytearray(hashlib.md5(data[:length]).digest())
    for i in range(len(checksum) // 2):
        checksum[i] = checksum[i] ^ checksum[i + len(checksum) // 2]
    if data[length:length + 8] != checksum[:8]:
        return False
    return True


class nvram_ef_imei_imeisv_struct:
    def __init__(self, data):
        imei = data[:8]
        svn = data[9]
        pad = data[0xA]
        _ = imei, svn, pad


class RSA_D:
    def __init__(self, n, e, d):
        if isinstance(n, bytes):
            self.n = bytes_to_long(n)
        else:
            self.n = int(n)
        if isinstance(e, bytes):
            self.e = bytes_to_long(e)
        else:
            self.e = int(e)
        if isinstance(d, bytes):
            self.d = bytes_to_long(d)
        else:
            self.d = int(d)

    def encrypt(self, data):
        return long_to_bytes(pow(bytes_to_long(data), self.d, self.n), len(data))

    def decrypt(self, data):
        return long_to_bytes(pow(bytes_to_long(data), self.e, self.n), len(data))

    def sign(self, data):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        hashlen = hashlib.sha256().digest_size
        padsize = self.n.bit_length() // 8 - hashlen - 3
        pad = b'\x00\x01' + (b'\xff' * padsize) + b'\x00'
        hashval = hashlib.sha256(data).digest()
        signdata = pad + hashval
        return self.encrypt(signdata)


class nvram_attr(Enum):
    AVERAGE = 0x00000000
    MULTI_DEFAULT = 0x00000001
    WRITEPROTECT = 0x00000002
    MULTIPLE = 0x00000004
    CONFIDENTIAL = 0x00000008
    MULTIREC_READ = 0x00000010
    MSP = 0x00000020  # Protected by MTK Secure Platform
    OTA_RESET = 0x00000040
    GEN_DEFAULT = 0x00000080
    RING = 0x00000100
    PACKAGE = 0x00000200  # NVRAM Reserved.LID will package in file
    BACKUP_FAT = 0x00000400  # Put a copy into backup partition, and the format is FAT
    BACKUP_RAW = 0x00000800  # Put a copy into backup partition, and the format is Raw data
    RESERVE_BACKWARD = 0x00001000
    FAULT_ASSERT = 0x00002000
    COMMITTED = 0x00004000  # Add for SP, add FS_COMMITTED while opening file
    RAW_DATA = 0x00008000
    CHKSUM_INTEGRATE = 0x00010000
    CHKSUM_ENHNC_ALGRTHM = 0x00020000
    # Add Attribute only for MCF Used
    MCF_OTA_ADDITIONAL_NOT_CHECK_VERNO = 0x10000000  # MCF will not check LID version when OTA. User MUST!! make sure structure is backward compatible. MUST set at least one of OTA, OTA_FOR_QUERY, or OTA_BY_OP. */
    MCF_OTA_FOR_QUERY = 0x20000000  # Customer can modify your LID when "OTA". MCF will NOT write setting to NVRAM. User need to query setting at run time. Conflict with MCF_OTA. */
    MCF_OTA_BY_OP = 0x40000000  # Customer can modify your LID when "OTA by operator". MCF will NOT write setting to NVRAM. User need to query setting at run time. */
    MCF_OTA = 0x80000000  # Customer can modify your LID when "OTA". MCF will write setting to NVRAM. User does not aware.*/
    ALL = 0xFFFFFFFF


class nvram_category(Enum):
    # NVRAM internal or Not
    USER = 0x0000
    INTERNAL = 0x0001
    # storage information
    BACKUP_SDS = 0x0010
    OTP = 0x0020
    CUSTOM_DISK = 0x0040  # Used by custom, it means the data is put into another partition
    """
    Used by custom, NVRAM will put custom's sensitive data into another folder
    if multiple folder feature turn on. Attribute of the data item in this category
    must with CONFIDENTIAL | MULTIPLE
    """
    CUSTOM_SENSITIVE = 0x0080
    # default value information
    CUSTPACK = 0x0100
    SECUPACK = 0x0200
    FUNC_DEFAULT = 0x0400
    # factory tool/Smartphone Nvram related information
    CALIBRAT = 0x1000
    IMPORTANT = 0x2000
    IMPORTANT_L4 = 0x4000
    IMPORTANT_L1 = 0x8000
    ALL = 0xFFFF
    RESERVED = 0x80000000  # for __NVRAM_READ_RESERVED_FILE__ feature


class CriticalData:
    def __init__(self, critical_data):
        self.config = {}
        ff = structhelper_io(critical_data)
        hdr = ff.bytes(3)
        _ = hdr
        self.config["dev_type"] = ff.bytes(1)
        while True:
            field = ff.bytes(1)
            if field == b"":
                break
            len = ff.bytes(1)
            if field == 1:
                self.config["chip_id"] = ff.bytes(len).decode('utf-8')
            elif field == 2:
                self.config["imei_1"] = ff.bytes(len).decode('utf-8')
            elif field == 3:
                self.config["imei_2"] = ff.bytes(len).decode('utf-8')
            elif field == 4:
                self.config["meid"] = ff.bytes(len).decode('utf-8')
            elif field == 5:
                self.config["wifi_mac"] = ff.bytes(len).decode('utf-8')
            elif field == 6:
                self.config["bt_mac"] = ff.bytes(len).decode('utf-8')


def decrypt_cssd(data=None, filename=""):
    if filename != "":
        content = open("/home/bjk/Projects/mtk_nvram/imei_patch/tool/data/begonia/cssd.bin", "rb").read()
        content = content[content.find(b"dev"):]
        data = content[:content.find(b"\x00")].decode('utf-8')
    else:
        data = data[data.find(b"dev"):]
        data = data[:data.find(b"\x00")].decode('utf-8')
    items = {}
    for line in data.split("\\n"):
        tmp = line.split(":")
        try:
            items[tmp[0]] = bytes.fromhex(tmp[1])
        except Exception:
            items[tmp[0]] = int(tmp[1], 16)
    data = items["crticalDataSign"]
    critical_data = items["criticalData"]
    if os.path.exists("private_2048.pem"):
        priv2048 = RSA.import_key(open("private_2048.pem", "r").read(), "")
        priv1024 = RSA.import_key(open("private_1024.pem", "r").read(), "")
        rsafn2048 = RSA_D(priv2048.n, priv2048.e, priv2048.d)
        rsafn1024 = RSA_D(priv1024.n, priv1024.e, priv1024.d)
        hash = rsafn1024.decrypt(data)[-0x20:]
        if hash == hashlib.sha256(bytes(critical_data.hex(), 'utf-8')).digest():
            print("crticalDataSign does match !")
        devPubKeySign = items["devPubKeySign"]
        hash2 = rsafn2048.decrypt(devPubKeySign)[-0x20:]
        devicename = "begonia"
        devPubKeyToSign = "%5x" % int(priv1024.e) + long_to_bytes(priv1024.n, 1024 // 8).hex() + devicename
        if hash2 == hashlib.sha256(bytes(devPubKeyToSign, 'utf-8')).digest():
            print("devPubKeySign does match !")
    return CriticalData(critical_data)


def create_cssd(config, product: str = "thunder"):
    if product is None:
        config["product"] = "thunder"
    else:
        config["product"] = product
    if config is None:
        if not os.path.exists("config.json"):
            print("Can't find config.json")
            sys.exit(1)
        else:
            config = json.loads(open("config.json", "r").read())
    config["wifi_mac"] = config["wifi_mac"].upper().replace(":", "")
    config["bt_mac"] = config["bt_mac"].upper().replace(":", "")
    if (len(config['product']) == 0 or
            len(config['chip_id'][:0x22]) != 34 or
            len(config['imei_1']) != 15 or
            len(config['imei_2']) != 15 or
            # len($config['meid']) != 14 or
            len(config['wifi_mac']) != 12 or
            len(config['bt_mac']) != 12):
        sys.exit(1)
    if not os.path.exists("private_2048.pem"):
        print("Can't find private_2048.pem")
        sys.exit(1)
    elif not os.path.exists("private_1024.pem"):
        print("Can't find private_1024.pem")
        sys.exit(1)

    priv2048 = RSA.import_key(open("private_2048.pem", "r").read(), "")
    priv1024 = RSA.import_key(open("private_1024.pem", "r").read(), "")
    if priv1024.e != 0x10001:
        print("Wrong modulus for private_1024.pem")
        sys.exit(1)
    rsafn1024 = RSA_D(priv1024.n, priv1024.e, priv1024.d)
    rsafn2048 = RSA_D(priv2048.n, priv2048.e, priv2048.d)
    devPubKeyToSign = "%5x" % int(priv1024.e) + long_to_bytes(priv1024.n, 1024 // 8).hex() + config["product"]
    devPubKeySign = rsafn2048.sign(devPubKeyToSign)

    data = b"\x00\x01\x00" + int.to_bytes(config["dev_type"], 1, 'little')  # ends with 0x72 for chinese begonia
    data += b"\x01\x22" + bytes(config["chip_id"], 'utf-8')[:0x22]
    data += b"\x02\x0F" + bytes(config["imei_1"], 'utf-8')
    data += b"\x03\x0F" + bytes(config["imei_2"], 'utf-8')
    # data += b"\x04\x0E" + bytes(config["meid"],'utf-8')
    data += b"\x05\x0C" + bytes(config["wifi_mac"], 'utf-8')
    data += b"\x06\x0C" + bytes(config["bt_mac"], 'utf-8')
    data = data.hex()

    crticalDataSign = rsafn1024.sign(bytes(data, 'utf-8'))

    cssd = "devPubKeyModulus:" + long_to_bytes(priv1024.n, 1024 // 8).hex()
    cssd += "\\ndevPubKeyExponent:%5X" % int(priv1024.e)
    cssd += "\\ndevPubKeySign:" + devPubKeySign.hex().upper()
    cssd += "\\ncriticalData:" + data
    cssd += "\\ncrticalDataSign:" + crticalDataSign.hex()
    cssd = bytes(cssd, 'utf-8').ljust(0x1000, b"\x00")
    cssd += checksum_8b(cssd, len(cssd))

    # nvram_ldi_ota_header
    header = b"LDI\x00"
    header += int.to_bytes(0x08C1, 2, 'little')  # LID
    header += int.to_bytes(0x1, 2, 'little')  # total_records
    header += int.to_bytes(0x1000, 4, 'little')  # record_size
    header += int.to_bytes(0x4000, 4, 'little')  # ldi_attr
    header += int.to_bytes(0x2000, 4, 'little')  # ldi_category
    header += b"\x00" * 10  # defval_chkrst_h
    header += int.to_bytes(0x445F, 2, 'little')  # checksum

    # nvram_ldi_debug_header
    header += int.to_bytes(0x8D, 4, 'little')  # last_write_taskID
    header += b"\x00" * 6  # defval_chkrst_l
    header += int.to_bytes(0x8339, 2, 'little')  # last_write_time
    header += int.to_bytes(0x1, 4, 'little')  # write_times
    header += b"\x00" * 16  # struct_chkrst
    # open("CSSD_000", "wb").write(header + cssd)
    return header + cssd


def patch_md1img(md1img):
    priv2048 = RSA.import_key(open("private_2048.pem", "r").read(), "")
    modulus_new = long_to_bytes(priv2048.n, 2048 // 8)
    # xiaomi modulus
    modulus_old = bytearray(
        [0xC0, 0x76, 0x21, 0xF1, 0x95, 0x51, 0x14, 0x2D, 0x3D, 0x5D, 0x9D, 0xD5, 0x14, 0x05, 0xD5, 0xD8,
         0x34, 0x70, 0xD5, 0x41, 0x7E, 0x66, 0x1C, 0xB3, 0xF5, 0x47, 0x2D, 0x2E, 0x4A, 0x9A, 0xE5, 0x63,
         0x45, 0xBF, 0x41, 0x87, 0x16, 0xFE, 0x7F, 0xB5, 0xA5, 0xC0, 0x41, 0x0E, 0x0F, 0xB1, 0x06, 0x72,
         0x59, 0x23, 0x05, 0xAC, 0x46, 0xC1, 0xB8, 0x01, 0x24, 0x06, 0xDD, 0x02, 0x8B, 0xF6, 0x68, 0x7F,
         0x39, 0xDC, 0x5C, 0xAF, 0x45, 0x82, 0x9A, 0xE0, 0x6F, 0x17, 0x58, 0x94, 0xC2, 0x0A, 0xE3, 0x5A,
         0x33, 0x3B, 0x71, 0x9D, 0x96, 0xA5, 0xD7, 0x7F, 0x85, 0x20, 0x66, 0xA8, 0xFF, 0x17, 0xCA, 0xFC,
         0x22, 0x53, 0x89, 0xC0, 0x15, 0x14, 0x92, 0xE0, 0x7F, 0x67, 0xC8, 0x82, 0xB8, 0x9D, 0x13, 0x97,
         0xF9, 0xB5, 0x6A, 0xC2, 0xE5, 0x72, 0xCB, 0x07, 0xC1, 0xCC, 0xF5, 0xD2, 0xFC, 0x59, 0x07, 0x04,
         0x37, 0xDC, 0xBB, 0x35, 0x1C, 0xE0, 0xB6, 0x3D, 0x6C, 0x76, 0x2B, 0x42, 0x7E, 0xB6, 0x6C, 0x90,
         0xD9, 0x3F, 0x6F, 0x2C, 0xCB, 0x66, 0xD4, 0xEF, 0xF2, 0x63, 0xC0, 0xDA, 0x77, 0x35, 0x5B, 0x9E,
         0xE4, 0x02, 0x6F, 0x0C, 0x80, 0x56, 0x9A, 0x19, 0xB8, 0x39, 0xD3, 0x98, 0x8F, 0x4B, 0x55, 0xB0,
         0x42, 0xE7, 0xB9, 0x77, 0x30, 0x84, 0x8F, 0xA6, 0x2D, 0xCA, 0x42, 0x72, 0x02, 0x76, 0xC6, 0x1C,
         0xC3, 0xB6, 0x98, 0x16, 0x4E, 0xE7, 0x41, 0x9B, 0xD1, 0x38, 0xB8, 0x5C, 0xAE, 0x04, 0x21, 0x74,
         0xA7, 0x49, 0x38, 0x19, 0xC8, 0x33, 0x95, 0x3A, 0x4F, 0x93, 0x06, 0x8F, 0xF5, 0x65, 0x1F, 0x31,
         0x63, 0x3A, 0x2A, 0xDB, 0xD1, 0xFB, 0x5F, 0xD8, 0xD6, 0xDD, 0x0E, 0xBF, 0xB3, 0x56, 0x16, 0x6E,
         0xB3, 0x31, 0xBD, 0xE5, 0x8D, 0x1E, 0x22, 0x84, 0xA0, 0x47, 0xC4, 0x42, 0x06, 0x2C, 0x1E, 0xB5])
    md1img = bytearray(md1img)
    idx = md1img.find(modulus_old)
    if idx != -1:
        md1img[idx:idx + (2048 // 8)] = modulus_new
    else:
        # Realme patch
        idx = md1img.find(b"\xc5\x64\x02\x6a\x06\xd2\x00\x6a\x07\xd2\x04\x6a\x04\xd2\x08\xf0")
        if idx != -1:
            md1img[idx:idx + 3] = b"\x20\xe8\x01"
        else:
            # CPH1909
            idx = md1img.find(b"\x20\xe8\x01\x6a\xa0\xff\x30\x91\x20\xe8")
            if idx != -1:
                md1img[idx:idx + 10] = b"\x01"
    return md1img


def adb_get_prop(property):
    import subprocess
    result = subprocess.run(['adb', 'shell', f'su -c getprop {property}'], stdout=subprocess.PIPE)
    return result.stdout.decode('utf-8').rstrip("\n")


def adb_create_config():
    data = {}
    # chip_id is the same as hrid, but big endian each 4 bytes
    data["chip_id"] = adb_get_prop("ro.boot.cpuid")
    data["imei_1"] = adb_get_prop("ro.ril.oem.imei1")
    data["imei_2"] = adb_get_prop("ro.ril.oem.imei2")
    data["wifi_mac"] = adb_get_prop("ro.ril.oem.wifimac").upper()
    data["bt_mac"] = adb_get_prop("ro.ril.oem.btmac").upper()
    data["product"] = adb_get_prop("ro.miui.cust_device")
    open("config.json", "w").write(json.dumps(data))


def create_devinfo():
    data = {}
    data["chip_id"] = "0x7e08d45734aadbeda90a7c1d2273484c"
    data["imei_1"] = "867965041894730"
    data["imei_2"] = "867965041894748"
    data["wifi_mac"] = "04C8072A36C8"
    data["bt_mac"] = "04C8072A36C7"
    data["product"] = "begonia"
    open("config.json", "w").write(json.dumps(data))

    """
    $cssd = $header.$cssd;

    with open("nvram_org.bin","rb") as rf:
        toc_size = 0x20000
        content_size = unpack('V', nvram, 4)[1]
        cssd_offset = nvram.find(b'/mnt/vendor/nvdata/md/NVRAM/NVD_IMEI/CSSD_000')
        if cssd_offset == -1:
            print("Cannot find CSSD LID in NVRAM image.\n")
            sys.exit(1)
        cssd_offset = toc_size + unpack('V', nvram, cssd_offset - 8)[1]
        wifi_offset = nvram.find(b'/mnt/vendor/nvdata/APCFG/APRDEB/WIFI')
        if wifi_offset == -1:
            print("Cannot find WIFI file in NVRAM image.\n")
            sys.exit(1)
        wifi_size = unpack('V', $nvram, $wifi_offset - 4)[1]
        wifi_offset = toc_size + unpack('V', nvram, wifi_offset - 8)[1]
        bt_offset = nvram.find(b'/mnt/vendor/nvdata/APCFG/APRDEB/BT_Addr')
        if bt_offset == -1:
            print("Cannot find BT_Addr file in NVRAM image.\n")
            sys.exit(1)
        bt_size = unpack('V', nvram, bt_offset - 4)[1]
        bt_offset = toc_size + unpack('V', nvram, bt_offset - 8)[1]
        nvram = nvram.replace(b"/CALIBRAT/", b"/CALIBRUH/")
        os.path.mkdir('out')
        open('out/nvram.img','wb').write(nvram)

    with open('out/nvram.img', 'r+b') as wf:
        wf.seek(cssd_offset)
        wf.write(cssd)
        wf.seek(wifi_offset + 4)
        wf.write(bytes.fromhex(config['wifi_mac']))
        wf.seek(wifi_offset)
        wf.read(wifi_size - 2)
        wf.write(checksum_2b(wifi))
        wf.seek(bt_offset)
        wf.write(bytes.fromhex(config['bt_mac']))
        wf.seek(bt_offset)
        bt = wf.read(bt_size - 2)
        wf.write(checksum_2b(bt))
        wf.seek(toc_size)
        content = wf.read(content_size)
        wf.seek(0x0C)
        wf.write(checksum_nvram(content))
    """


if __name__ == '__main__':
    hrid = "ccac763cf12a925fd9adcfb332bc88fa"
    # hrid = "5bd156e2f485eb22dc10830940c6b797"
    kv = CustCHL_Gen_Root_Key(bytes.fromhex(hrid))
    data = bytes.fromhex(
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 FE 01 90 00 00 00 00 E2 00 00 01 00 00 00 61 85 5A ED A6 1A 6C E5 4F 2D 70 B4 6F AD 16 DB 97 B0 6D 3D 02 48 BE AA 5F 4B 2D 82 78 37 35 47")
    # kv = bytes.fromhex("AF8EC27A423AD1CF4FB6693D50A854655FE557E6EEEF8CEA18CD493BE542B903")
    res = hmac.new(key=kv, msg=data[:-0x20], digestmod=hashlib.sha256).digest()
    print(res.hex())
    exit(1)
    dt = nvram_get_key(NVRAM_CUSTOM_KEY)
    print(dt.hex())

    """
    val = "863160066836550"
    rr=make_luhn_checksum(val)

    nvram_data_header_checksum(
        bytes.fromhex("4C 44 49 00 C1 08 01 00 00 10 00 00 00 40 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00"))
    #create_devinfo()
    adb_create_config()
    decrypt_cssd()
    create_cssd()
    """

    # data = checksum_nvram(b"12abcdef00")
    # print(hex(data))
    # hrid = bytes.fromhex("5bd156e2f485eb22dc10830940c6b797")
    # value = CustCHL_Gen_Root_Key(hrid)

    # nvramkey = SST_Get_NVRAM_SW_Key(nvram_keys["samsung"], 0x10)
    # value=AES.new(nvramkey, AES.MODE_ECB).decrypt(bytes.fromhex("47A6B8B6B86FB7F681595770E6627E7767B85A00D10EE8CDC2E09181801E0B49"))

    # data=bytes.fromhex("68 72 48 60 61 64 64 F5 00 00 1C 58 69 1D F2 4849 75 00 00 00 00 00 00 00 00 00 00 00 00 00 0068 72 48 60 61 64 74 F3 00 00 05 93 53 75 C1 2FA8 96 00 00 00 00 00 00 00 00 00 00 00 00 00 00FF FF FF FF FF FF FF FF FF FF 21 36 4F 41 23 FC17 C1 00 00 00 00 00 00 00 00 00 00 00 00 00 00FF FF FF FF FF FF FF FF FF FF 21 36 4F 41 23 FC17 C1 00 00 00 00 00 00 00 00 00 00 00 00 00 00FF FF FF FF FF FF FF FF FF FF 21 36 4F 41 23 FC17 C1 00 00 00 00 00 00 00 00 00 00 00 00 00 00FF FF FF FF FF FF FF FF FF FF 21 36 4F 41 23 FC17 C1 00 00 00 00 00 00 00 00 00 00 00 00 00 00FF FF FF FF FF FF FF FF FF FF 21 36 4F 41 23 FC17 C1 00 00 00 00 00 00 00 00 00 00 00 00 00 00FF FF FF FF FF FF FF FF FF FF 21 36 4F 41 23 FC17 C1 00 00 00 00 00 00 00 00 00 00 00 00 00 00FF FF FF FF FF FF FF FF FF FF 21 36 4F 41 23 FC17 C1 00 00 00 00 00 00 00 00 00 00 00 00 00 00FF FF FF FF FF FF FF FF FF FF 21 36 4F 41 23 FC17 C1 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
    # ret=calc_checksum_regular(data)
    # print(value.hex())

    nvramkey = SST_Get_NVRAM_SW_Key(nvram_keys["samsung"], 0x256)
    # dt = bytearray(b'LDI\x00\x08\xf0\x02\x00 \x00\x00\x00\x81`\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00DD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00e\x05\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00(?\x11\x02<j\xd1\x05\x0f\x8a\xf5\xcc\xe2\xbb\x8c\xcb\xbf\xa1\x8b\x00\xe5Z\x87\xc9\xd6IW\xff\x9fB\nS\xe5\xdc=mm\xb0\xeb\xcf\x88\x93Y\x97B\xd2\xa3\x15?%<\x02!\xee\xe1\x98Oz\x1a\xef\xef\x0c\xa3\x02S\xd6\xcb+\x04\x8f\x80\xd9f\x90\xbe@r\x12\xf5\x16')
    # dt = bytes.fromhex("4C 44 49 00 06 F0 01 00 10 00 00 00 AE 60 00 0000 24 00 00 00 00 00 00 00 00 00 00 00 00 5E 4400 00 00 00 00 00 00 00 00 00 CD 03 01 00 00 0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00F6 25 25 AD 0C A4 3A AA CC EF 93 1F 2D C2 A3 EEA8 E0 4A 3D 41 BC 7B 0A 13 3F 50 B8 72 5D B1 16")
    # dt = bytes.fromhex("4C 44 49 00 08 F0 02 00 20 00 00 00 81 60 00 0000 24 00 00 00 00 00 00 00 00 00 00 00 00 44 4400 00 00 00 00 00 00 00 00 00 BA 05 01 00 00 0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00F2 97 D2 2C 29 05 26 6B 75 0D 2C DA AE 6B 95 A599 0B 8A 58 7F EC 01 1A 99 A5 1F 40 25 C3 24 9684 2D ED 71 BD 4D 7E CD D3 2A 6C DF B5 59 41 0464 9C 09 4A D6 65 03 89 14 C3 2F A7 18 87 41 1308 6F FE 63 F3 04 62 C8 3D 29 8B 08 85 99 17 07")
    dt = open("/mnt/Wordlists/sm_a346b/nvdata/md/NVRAM/NVD_IMEI/NV0S_000", "rb").read()
    # print(dt.hex())
    offset = 0x40
    inputd = dt[0x40 + offset:0x40 + offset + 0x20]
    print(inputd.hex())
    value = AES.new(nvramkey[:0x10], AES.MODE_ECB).decrypt(inputd)
    a = value[:0x10]
    b = value[0x10:]
    c = b"".join([int.to_bytes(a[x] ^ b[x], 1, 'little') for x in range(0x10)])
    print(f"{a.hex()}:{b.hex()}:{c.hex()}:{hex(0x40 + offset)}")
    """
    for i in range(0,len(nvramkey),0x10):
        value = AES.new(nvramkey[i:i+0x10], AES.MODE_ECB).decrypt(dt[0x40:0x40+0x20])
        print(value.hex())
    """
    # print(value.hex())
