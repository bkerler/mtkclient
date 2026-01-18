#!/usr/bin/env python3
from struct import unpack


def dword(data, addr, count=1):
    vals = unpack("<" + str(count) + "I", data[addr:addr + 4 * count])
    if count == 1:
        return vals[0]
    return vals


def main():
    # data=open("memdump_8695.bin","rb").read()
    # checklist_generic = [0x10290, 0xA]

    data = open("memdump.bin", "rb").read()
    # preloader_whitelist = [dword(data, 0x105914), dword(data, 0x105994)]
    # read_whitelist = [dword(data, 0x102BCC), dword(data, 0x102B28)]
    checklist_generic = [dword(data, 0x102824), dword(data, 0x102828)]

    # whitelist = dword(data, checklist_generic[0], checklist_generic[1] * 3)
    whitelist = dword(data, checklist_generic[0], checklist_generic[1] * 3)
    for i in range(checklist_generic[1]):
        flag = whitelist[(i * 3)]
        ptr = whitelist[1 + (i * 3)]
        count = whitelist[2 + (i * 3)]
        info = ""
        if flag & 0x2:
            info += "R"
        if flag & 0x20:
            info += "R"
        if flag & 0x200:
            info += "R"
        elif flag & 0x4:
            info += "W"
        elif flag & 0x40:
            info += "W"
        if flag & 0x400:
            info += "W"
        if flag & 0x1:
            info += "X"
        if flag & 0x10:
            info += "X"
        if flag & 0x100:
            info += "X"
        if (flag & 0x16F) != 0:
            info += "B"
        print(
            f"Offset {hex(checklist_generic[0] + (i * 3))} -> Flag {hex(flag)}+" +
            f"[{info}] Ptr {hex(ptr)} Count {hex(count)}")
        print("----------------------------------------------------------------------------------------------")
        for field in range(count):
            start, end = dword(data, ptr + (field * 8), 2)
            print(f"Start {hex(start)}, End {hex(end)}")
        print()


if __name__ == "__main__":
    main()
