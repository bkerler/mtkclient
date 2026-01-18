#!/usr/bin/env python3
import os
from struct import unpack, pack


def main():
    loaders = []
    for root, dirs, files in os.walk("", topdown=False):
        for file in files:
            loaders.append(os.path.join(root, file))

    for loader in loaders:
        data = open(loader, "rb").read()
        idx = data.find(pack("<II", 0x8000004, 0x8000008))
        if idx != -1:
            print(loader)
            v = unpack("<I", data[idx - 4:idx])[0]
            if v == 0x1003C0:
                v = unpack("<I", data[idx + 3 * 4:idx + 3 * 4 + 4])[0]
                print("2:" + hex(v))
            if v == 0x800000c:
                v = unpack("<I", data[idx + 3 * 4:idx + 3 * 4 + 4])[0]
                print("3:" + hex(v))
            if v == 0x8825252:
                v = unpack("<I", data[idx - 8:idx - 4])[0]
                if v == 0x1003C0:
                    v = unpack("<I", data[idx + 3 * 4:idx + 3 * 4 + 4])[0]
                    print("5:" + hex(v))
                else:
                    print("4:" + hex(v))

            print(hex(v))


if __name__ == "__main__":
    main()
