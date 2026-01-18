#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License

import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from Cryptodome.Hash import CMAC
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
from binascii import hexlify
import hmac


class PKCS1BaseException(Exception):
    pass


class DecryptionError(PKCS1BaseException):
    pass


class MessageTooLong(PKCS1BaseException):
    pass


class WrongLength(PKCS1BaseException):
    pass


class MessageTooShort(PKCS1BaseException):
    pass


class InvalidSignature(PKCS1BaseException):
    pass


class RSAModulusTooShort(PKCS1BaseException):
    pass


class IntegerTooLarge(PKCS1BaseException):
    pass


class MessageRepresentativeOutOfRange(PKCS1BaseException):
    pass


class CiphertextRepresentativeOutOfRange(PKCS1BaseException):
    pass


class SignatureRepresentativeOutOfRange(PKCS1BaseException):
    pass


class EncodingError(PKCS1BaseException):
    pass


class InvalidInputException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


class InvalidTagException(Exception):
    def __str__(self):
        return 'The authentication tag is invalid.'


class CryptUtils:
    class Aes:
        # GF(2^128) defined by 1 + a + a^2 + a^7 + a^128
        # Please note the MSB is x0 and LSB is x127
        @staticmethod
        def gf_2_128_mul(x, y):
            assert x < (1 << 128)
            assert y < (1 << 128)
            res = 0
            for i in range(127, -1, -1):
                res ^= x * ((y >> i) & 1)  # branchless
                x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
            assert res < 1 << 128
            return res

        class AesGcm:
            # Galois/Counter Mode with AES-128 and 96-bit IV
            """
            Example:
            master_key = 0x0ADAABC70895E008147A48C27791F654 #54F69177C2487A1408E09508C7ABDA0A
            init_value = 0x2883B4173F9A838437C1CD86CCFAA5ED #EDA5FACC86CDC13784839A3F17B48328
            auth_tag = 46D1FA806ADA1A916E6D0D0B55A40C1F94D7820D110F3DFC984AA3EEC9D67521
            ciphertext = b"\x8A\x40\x9D\xF8\x76\x09\xCA\x10\x36\xB3\xFA\x86\x20\xC5\x85\xA3"+ \
                        b"\xE3\x8E\x17\x14\x40\xBD\x6B\xA7\x26\x1F\x0B\xFE\xC5\x0A\xB0\xF0"+\
                        b"\xCF\x69\x2E\x76\x18\x6D\x96\x9E\x83\x87\x63\xC7\x15\x7C\x1F\x28"+\
                        b"\xEE\xE8\xF1\xD6\x1F\x02\x2A\xF1\xA2\x43\x8A\xCF\x7C\xF2\x66\x37"+\
                        b"\x8B\x49\x1D\xC5\xDC\xE2\x54\x77\xED\x2F\x17\x5B\xA9\xFC\x8A\x81"+\
                        b"\x60\xF6\x5A\x22\x39\xCA\x79\x32\x9B\xDB\x49\x50\xCE\x74\x2C\x56"+\
                        b"\xDB\x97\xCA\x13\xDD\x25\xA3\x3C\x0F\x53\xDD\x38\xBF\x7B\x8B\xDA"+\
                        b"\xD6\x74\x38\x87\x96\xA8\x10\x5A\x96\x38\x39\x7F\xFD\xEC\xC7\x62"+\
                        b"\x06\x44\xF4\x0F\x78\xD6\x3D\x1A\xC5\x40\x4B\x3B\x8C\xBE\xE6\x76"+\
                        b"\x65\xFA\x40\xDA\xD3\xF0\xF2\x19\x35\xB7\xB2\x91\xFC\x18\x2C\x53"+\
                        b"\xA2\x3F\x1A\xA7\x4F\xFC\x42\xAE\xC1\x97\x89\xAB\x7E\x9B\xA1\x5C"+\
                        b"\x3A\x3B\x2F\x01\x60\xB1\xC5\x30\x7C\xB7\x2B\xD5\xAF\x27\xA0\x4C"+\
                        b"\xE9\x80\xC5\xB4\xEC\xFB\xD7\x59\xE8\x5D\xEE\xB5\x6F\x3B\xA7\xDE"+\
                        b"\xDA\xD8\x55\x09\x7A\x5A\xAD\x6C\x13\x2D\xD1\x23\x7C\x13\x5F\x84"+\
                        b"\x35\x29\x51\x55\xF4\x53\x12\x9C\x86\x7A\x77\x2B\xE2\x7B\x01\xA2"+\
                        b"\x6B\xC8\x5D\xD8\xCA\x92\xFB\x32\x0A\x09\xAE\xB3\x45\x8D\x0B\x60"+\
                        b"\x9D\xEB\xB7\x02\x07\xAB\x4A\x24\xF6\xA1\xE7\x59\xA0\xC4\xB1\xFB"+\
                        b"\x44\xAD\x32\xC7\xD4\x8F\xC6\x0C\x33\xD5\x88\x82\xF4\x9A\xA2\x7C"+\
                        b"\xDC\x56\x90\x96\x3C\xBC\xCF\x95\x17\x22\x55\x64\x67\x62\x52\x86"+\
                        b"\xFA\x3B\xFC\xAA\xC7\x1B\xDE\x7F\x01\xB3\x61\x8C\x28\xAE\x64\x7E"+\
                        b"\x43\xF0\x5A\x50\x60\x50\x85\xD4\xC4\xA6\x92\xC7\x8B\xE5\x04\x80"+\
                        b"\x74\x0F\xBA\xEB\x7C\x2C\x81\x07\x99\x22\x51\xD1\x9E\xE1\x59\xEE"+\
                        b"\x77\xC2\x13\x2C\x46\x16\x92\x9A\x69\xD9\x01\x75\x31\xA6\x20\xB9"+\
                        b"\x13\x46\x55\xF7\x8C\xC6\xB8\x7C\x8F\xAC\x00\x1A\x58\x68\xC7\xAD"+\
                        b"\x4E\x34\xB9\xEF\x5F\xCD\x87\x12\x0E\x8A\xEA\xD2\x4D\x66\x5E\x40"+\
                        b"\xBD\x1D\x30\x8A\x83\xB8\x4F\xC2\xAB\x28\x58\x6C\xEA\xDB\xF5\x87"+\
                        b"\xA0\x62\x9E\xF9\xF4\xE7\xE8\x65"
            my_gcm = AES_GCM(master_key)
            decrypted = my_gcm.decrypt(init_value, ciphertext, auth_tag)
            """

            def __init__(self, master_key):
                self.change_key(master_key)

            def change_key(self, master_key):
                if master_key >= (1 << 128):
                    raise InvalidInputException('Master key should be 128-bit')

                self.__master_key = long_to_bytes(master_key, 16)
                self.__aes_ecb = AES.new(self.__master_key, AES.MODE_ECB)
                self.__auth_key = bytes_to_long(self.__aes_ecb.encrypt(b'\x00' * 16))

                # precompute the table for multiplication in finite field
                table = []  # for 8-bit
                for i in range(16):
                    row = []
                    for j in range(256):
                        row.append(self.gf_2_128_mul(self.__auth_key, j << (8 * i)))
                    table.append(tuple(row))
                self.__pre_table = tuple(table)

                self.prev_init_value = None  # reset

            def __times_auth_key(self, val):
                res = 0
                for i in range(16):
                    res ^= self.__pre_table[i][val & 0xFF]
                    val >>= 8
                return res

            def __ghash(self, aad, txt):
                len_aad = len(aad)
                len_txt = len(txt)

                # padding
                if 0 == len_aad % 16:
                    data = aad
                else:
                    data = aad + b'\x00' * (16 - len_aad % 16)
                if 0 == len_txt % 16:
                    data += txt
                else:
                    data += txt + b'\x00' * (16 - len_txt % 16)

                tag = 0
                assert len(data) % 16 == 0
                for i in range(len(data) // 16):
                    tag ^= bytes_to_long(data[i * 16: (i + 1) * 16])
                    tag = self.__times_auth_key(tag)
                    # print 'X\t', hex(tag)
                tag ^= ((8 * len_aad) << 64) | (8 * len_txt)
                tag = self.__times_auth_key(tag)

                return tag

            def encrypt(self, init_value, plaintext, auth_data=b''):
                if init_value >= (1 << 96):
                    raise InvalidInputException('IV should be 96-bit')
                # a naive checking for IV reuse
                if init_value == self.prev_init_value:
                    raise InvalidInputException('IV must not be reused!')
                self.prev_init_value = init_value

                len_plaintext = len(plaintext)
                # len_auth_data = len(auth_data)

                if len_plaintext > 0:
                    counter = Counter.new(
                        nbits=32,
                        prefix=long_to_bytes(init_value, 12),
                        initial_value=2,  # notice this
                        allow_wraparound=False)
                    aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)

                    if 0 != len_plaintext % 16:
                        padded_plaintext = plaintext + b'\x00' * (16 - len_plaintext % 16)
                    else:
                        padded_plaintext = plaintext
                    ciphertext = aes_ctr.encrypt(padded_plaintext)[:len_plaintext]

                else:
                    ciphertext = b''

                auth_tag = self.__ghash(auth_data, ciphertext)
                # print 'GHASH\t', hex(auth_tag)
                auth_tag ^= bytes_to_long(self.__aes_ecb.encrypt(
                    long_to_bytes((init_value << 32) | 1, 16)))

                # assert len(ciphertext) == len(plaintext)
                assert auth_tag < (1 << 128)
                return ciphertext, auth_tag

            def decrypt(self, init_value, ciphertext, auth_tag, auth_data=b''):
                # if init_value >= (1 << 96):
                #    raise InvalidInputException('IV should be 96-bit')
                # if auth_tag >= (1 << 128):
                #    raise InvalidInputException('Tag should be 128-bit')

                if auth_tag != self.__ghash(auth_data, ciphertext) ^ \
                        bytes_to_long(self.__aes_ecb.encrypt(
                            long_to_bytes((init_value << 32) | 1, 16))):
                    raise InvalidTagException

                len_ciphertext = len(ciphertext)
                if len_ciphertext > 0:
                    counter = Counter.new(
                        nbits=32,
                        prefix=long_to_bytes(init_value, 12),
                        initial_value=2,
                        allow_wraparound=True)
                    aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)

                    if 0 != len_ciphertext % 16:
                        padded_ciphertext = ciphertext + b'\x00' * (16 - len_ciphertext % 16)
                    else:
                        padded_ciphertext = ciphertext
                    plaintext = aes_ctr.decrypt(padded_ciphertext)[:len_ciphertext]

                else:
                    plaintext = b''

                return plaintext

        @staticmethod
        def aes_gcm(indata, nounce, aes_key, hdr, tag_auth, decrypt=True):
            cipher = AES.new(aes_key, AES.MODE_GCM, nounce)
            if hdr is not None:
                cipher.update(hdr)
            if decrypt:
                if tag_auth is None:
                    plaintext = cipher.decrypt(indata)
                    return plaintext
                elif tag_auth is not None:
                    plaintext = cipher.decrypt(indata)
                    cipher.verify(tag_auth)
                    return plaintext
            elif not decrypt:
                if tag_auth is None:
                    ciphertext = cipher.encrypt(indata)
                    return ciphertext
                elif tag_auth is not None:
                    ciphertext, tag_auth = cipher.encrypt_and_digest(indata)
                    return ciphertext, tag_auth

        @staticmethod
        def aes_cbc(key, iv, data, decrypt=True):
            if decrypt:
                return AES.new(key, AES.MODE_CBC, IV=iv).decrypt(data)
            else:
                return AES.new(key, AES.MODE_CBC, IV=iv).encrypt(data)

        @staticmethod
        def aes_ecb(key, data, decrypt=True):
            if decrypt:
                return AES.new(key, AES.MODE_ECB).decrypt(data)
            else:
                return AES.new(key, AES.MODE_ECB).encrypt(data)

        @staticmethod
        def aes_ctr(key, counter, enc_data, decrypt=True):
            ctr = Counter.new(128, initial_value=counter)
            # Create the AES cipher object and decrypt the ciphertext, basically this here is just aes ctr 256 :)
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            data = cipher.decrypt(enc_data) if decrypt else cipher.encrypt(enc_data)
            return data

        @staticmethod
        def aes_ccm(key, nounce, tag_auth, data, decrypt=True):
            cipher = AES.new(key, AES.MODE_CCM, nounce)
            if decrypt:
                plaintext = cipher.decrypt(data)
                try:
                    cipher.verify(tag_auth)
                    return plaintext
                except ValueError:
                    return None
            else:
                ciphertext = cipher.encrypt(data)
                return ciphertext

        @staticmethod
        def aes_cmac_verify(key, plain, compare):
            ctx = CMAC.new(key, ciphermod=AES)
            ctx.update(plain)
            result = ctx.hexdigest()
            if result != compare:
                print("AES-CMAC failed !")
            else:
                print("AES-CMAC ok !")

    class Rsa:  # RFC8017
        def __init__(self, hashtype="SHA256"):
            if hashtype == "SHA1":
                self.hash = self.sha1
                self.digestLen = 0x14
            elif hashtype == "SHA256":
                self.hash = self.sha256
                self.digestLen = 0x20

        def pss_test(self):
            n = "a2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e577c2eeaffa20d883a76e65" + \
                "e394c69d4b3c05a1e8fadda27edb2a42bc000fe888b9b32c22d15add0cd76b3e7936e19955b220dd17d4ea9" + \
                "04b1ec102b2e4de7751222aa99151024c7cb41cc5ea21d00eeb41f7c800834d2c6e06bce3bce7ea9a5"
            e = "010001"
            d = "050e2c3e38d886110288dfc68a9533e7e12e27d2aa56d2cdb3fb6efa990bcff29e1d2987fb711962860e739" + \
                "1b1ce01ebadb9e812d2fbdfaf25df4ae26110a6d7a26f0b810f54875e17dd5c9fb6d641761245b81e79f8c8" + \
                "8f0e55a6dcd5f133abd35f8f4ec80adf1bf86277a582894cb6ebcd2162f1c7534f1f4947b129151b71"
            msg = "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e5" + \
                  "3a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6b" + \
                  "bfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc"
            salt = "e3b5d5d002c1bce50c2b65ef88a188d83bce7e61"

            n = int(n, 16)
            e = int(e, 16)
            d = int(d, 16)
            msg = bytes.fromhex(msg)
            salt = bytes.fromhex(salt)
            signature = self.pss_sign(d, n, self.hash(msg), salt, 1024)  # pkcs_1_pss_encode_sha256
            isvalid = self.pss_verify(e, n, self.hash(msg), signature, 1024)
            if isvalid:
                print("Test passed.")
            else:
                print("Test failed.")

        @staticmethod
        def i2osp(x, x_len):
            """Converts the integer x to its big-endian representation of length
               x_len.
            """
            if x > 256 ** x_len:
                raise "Integer Too Large"
            h = hex(x)[2:]
            if h[-1] == 'L':
                h = h[:-1]
            if len(h) & 1 == 1:
                h = '0%s' % h
            x = bytes.fromhex(h)
            return b'\x00' * int(x_len - len(x)) + x

        @staticmethod
        def os2ip(x):
            """Converts the byte string x representing an integer reprented using the
               big-endian convient to an integer.
            """
            return int(hexlify(x), 16)

        # def os2ip(self, X):
        #    return int.from_bytes(X, byteorder='big')

        def mgf1(self, indata, length):
            counter = 0
            output = b''
            while len(output) < length:
                c = self.i2osp(counter, 4)
                output += self.hash(indata + c)
                counter += 1
            return output[:length]

        @staticmethod
        def assert_int(var: int, name: str):
            if isinstance(var, int):
                return
            raise TypeError('%s should be an integer, not %s' % (name, var.__class__))

        def sign(self, tosign, d, n, em_bits=1024):
            self.assert_int(tosign, 'message')
            self.assert_int(d, 'D')
            self.assert_int(n, 'n')

            if tosign < 0:
                raise ValueError('Only non-negative numbers are supported')

            if tosign > n:
                raise OverflowError("The message %i is too long for n=%i" % (tosign, n))

            signature = pow(tosign, d, n)
            hexsign = self.i2osp(signature, em_bits // 8)
            return hexsign

        def pss_sign(self, d, n, msghash, salt, em_bits=1024):
            if isinstance(d, str):
                d = bytes.fromhex(d)
                d = self.os2ip(d)
            if isinstance(n, str):
                n = bytes.fromhex(n)
                n = self.os2ip(n)
            slen = len(salt)
            em_len = self.ceil_div(em_bits, 8)
            in_block = b"\x00" * 8 + msghash + salt
            _hash = self.hash(in_block)
            ps_len = em_len - self.digestLen - slen - 1 - 1
            db = (ps_len * b"\x00") + b"\x01" + salt
            rlen = em_len - len(_hash) - 1
            db_mask = self.mgf1(_hash, rlen)
            masked_db = bytearray()
            for i in range(0, len(db_mask)):
                masked_db.append(db_mask[i] ^ db[i])
            masked_db[0] = masked_db[0] & 0x7F
            em = masked_db + _hash + b"\xbc"
            tosign = self.os2ip(em)
            # EM=hexlify(EM).decode('utf-8')
            # tosign = int(EM,16)
            return self.sign(tosign, d, n, em_bits)
            # 6B1EAA2042A5C8DA8B1B4A8320111A70A0CBA65233D1C6E418EF8156E82A8F96BD843F047FF25AB9702A6582C8387298753E628F23448B4580E09CBD2A483C623B888F47C4BD2C5EFF09013C6DFF67DB59BAB3037F0BEE05D5660264D28CC6251631FE75CE106D931A04FA032FEA31259715CE0FAB1AE0E2F8130807AF4019A61B9C060ECE59104F22156FEE8108F17DC80D7C2F8397AFB9780994F7C5A0652F93D1B48010B0B248AB9711235787D797FBA4D10A29BCF09628585D405640A866B15EE9D7526A2703E72A19811EF447F6E5C43F915B3808EBC79EA4BCF78903DBDE32E47E239CFB5F2B5986D0CBBFBE6BACDC29B2ADE006D23D0B90775B1AE4DD

        @staticmethod
        def ceil_div(a, b):
            (q, r) = divmod(a, b)
            if r:
                return q + 1
            else:
                return q

        def pss_verify(self, e, n, msghash, signature, em_bits=1024, salt=None):
            if salt is None:
                slen = self.digestLen
            else:
                slen = len(salt)
            sig = self.os2ip(signature)

            em = pow(sig, e, n)
            # EM = bytes.fromhex(hex(EM)[2:])
            em = self.i2osp(em, em_bits // 8)

            em_len = len(signature)

            val_bc = em[-1]
            if val_bc != 0xbc:
                print("[rsa_pss] : 0xbc check failed, value: 0x%02X" % val_bc)
                return False
            _hash = em[em_len - self.digestLen - 1:-1]
            masked_db = em[:em_len - self.digestLen - 1]

            lmask = ~(0xFF >> (8 * em_len + 1 - em_bits))
            if em[0] & lmask:
                print("[rsa_pss] : lmask check failed")
                return False

            db_mask = self.mgf1(_hash, em_len - self.digestLen - 1)

            db = bytearray()
            for i in range(0, len(db_mask)):
                db.append(db_mask[i] ^ masked_db[i])

            ts = bytearray()
            ts.append(db[0] & ~lmask)
            ts.extend(db[1:])

            ps = (b"\x00" * (em_len - self.digestLen - slen - 2)) + b"\x01"
            if ts[:len(ps)] != ps:
                print(ts[:len(ps)])
                print(ps)
                print("[rsa_pss] : 0x01 check failed")
                return False

            if salt is not None:
                in_block = b"\x00" * 8 + msghash + salt
                mhash = self.hash(in_block)
                return mhash == _hash
            else:
                salt = ts[-self.digestLen:]
                in_block = b"\x00" * 8 + msghash + salt
                mhash = self.hash(in_block)
                return mhash == _hash

        @staticmethod
        def sha1(msg):
            return hashlib.sha1(msg).digest()

        @staticmethod
        def sha256(msg):
            return hashlib.sha256(msg).digest()


def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def aes_gcm(ciphertext, nounce, aes_key, hdr, tag_auth, decrypt=True):
    cipher = AES.new(aes_key, AES.MODE_GCM, nounce)
    if hdr is not None:
        cipher.update(hdr)
    if decrypt:
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag_auth)
            return plaintext
        except ValueError:
            return None
