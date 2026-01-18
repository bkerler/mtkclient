#!/usr/bin/env python3
import os
from struct import unpack
import sys


def extract_emi(data):
    idx = data.find(b"\x4D\x4D\x4D\x01\x38\x00\x00\x00")
    siglen = 0
    if idx != -1:
        data = data[idx:]
        mlen = unpack("<I", data[0x20:0x20 + 4])[0]
        siglen = unpack("<I", data[0x2C:0x2C + 4])[0]
        data = data[:mlen - siglen]
        dramsize = unpack("<I", data[-4:])[0]
        data = data[-dramsize - 4:-4]
    bldrstring = b"MTK_BLOADER_INFO_v"
    len_bldrstring = len(bldrstring)
    idx = data.find(bldrstring)
    if idx == -1:
        return None
    else:
        if data.find(b"MTK_BIN") != -1:
            emi = data[data.find(b"MTK_BIN") + 0xC:]
            ver = int(data[idx + len_bldrstring:idx + len_bldrstring + 2].rstrip(b"\x00"))
            if ver == 0x0D:
                emi = data[data.find(b"MTK_BIN") + 0x16:]
            return ver, emi


for root, dirs, files in os.walk(sys.argv[1], topdown=False):
    for file in files:
        fname = os.path.join(root, file)
        with open(fname, "rb") as rf:
            data = rf.read()
            ver, data = extract_emi(data)
            if data is not None:
                with open(fname + ".dram", "wb") as wf:
                    wf.write(data)
            else:
                print(f"Error on extracting {fname}")
