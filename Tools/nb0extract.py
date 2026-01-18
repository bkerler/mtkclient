#!/usr/bin/env python3
import sys
import os
from struct import unpack


def main():
    if not os.path.exists("out"):
        os.makedirs("out")

    with open(sys.argv[1], "rb") as rf:
        count = unpack("<I", rf.read(4))[0]
        for pos in range(count):
            rf.seek(4 + pos * 0x40)
            start = unpack("<I", rf.read(4))[0] + (count * 0x40) + 4
            length = unpack("<I", rf.read(4))[0]
            # flag1 =
            unpack("<I", rf.read(4))[0]
            # flag2 =
            unpack("<I", rf.read(4))[0]
            filename = rf.read(0x30).rstrip(b"\x00").decode('utf-8')
            print(f"Start: {hex(start)} Length: {hex(length)} Filename: {filename}")
            with open(os.path.join("out", filename), "wb") as wf:
                rf.seek(start)
                while length > 0:
                    size = min(length, 0x200000)
                    data = rf.read(size)
                    wf.write(data)
                    length -= size


if __name__ == "__main__":
    main()
