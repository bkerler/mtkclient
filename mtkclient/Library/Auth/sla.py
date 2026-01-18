#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License

from Cryptodome.Hash import SHA256
from Cryptodome.Util.number import bytes_to_long, ceil_div, size, long_to_bytes
from Cryptodome.Cipher import PKCS1_OAEP


def customized_sign(n, e, msg):
    mod_bits = size(n)
    k = ceil_div(mod_bits, 8)

    ps = b'\xFF' * (k - len(msg) - 3)
    em = b'\x00\x01' + ps + b'\x00' + msg

    em_int = bytes_to_long(em)
    m_int = pow(em_int, e, n)
    signature = long_to_bytes(m_int, k)

    return signature


def generate_brom_sla_challenge(data, d, e):
    for i in range(0, len(data), 2):
        data[i], data[i + 1] = data[i + 1], data[i]
    msg = bytearray(customized_sign(d, e, data))
    for i in range(0, len(msg), 2):
        msg[i], msg[i + 1] = msg[i + 1], msg[i]
    return msg


def generate_da_sla_signature(data, key):
    cipher = PKCS1_OAEP.new(key, SHA256, mgfunc=lambda x, y: PKCS1_OAEP.MGF1(x, y, SHA256))
    ciphertext = cipher.encrypt(data)
    return ciphertext
