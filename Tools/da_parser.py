#!/usr/bin/env python3
# (c) B.Kerler 2021 MIT License
import os
import sys
from struct import unpack
import inspect
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir =os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from mtkclient.config.payloads import PathConfig
from mtkclient.Library.utils import read_object
from mtkclient.Library.utils import find_binary


entry_region = [
    ('m_buf', 'I'),
    ('m_len', 'I'),
    ('m_start_addr', 'I'),
    ('m_start_offset', 'I'),
    ('m_sig_len', 'I')]

DA = [
    ('magic', 'H'),
    ('hw_code', 'H'),
    ('hw_sub_code', 'H'),
    ('hw_version', 'H'),
    ('sw_version', 'H'),
    ('reserved1', 'H'),
    ('pagesize', 'H'),
    ('reserved3', 'H'),
    ('entry_region_index', 'H'),
    ('entry_region_count', 'H')
    # vector<entry_region> LoadRegion
]

efusedb = {}


def main():
    da_setup = []
    loaders = []
    pc = PathConfig()
    if len(sys.argv) > 1:
        loaders.append(sys.argv[1])
    else:
        for root, dirs, files in os.walk(pc.get_loader_path(), topdown=False):
            for file in files:
                if "MTK_DA_V5.bin" in file:
                    loaders.append(os.path.join(root, file))
    if not os.path.exists("loaders"):
        os.mkdir("loaders")
    dadb = {}
    for loader in loaders:
        with open(loader, 'rb') as bootldr:
            bootldr.seek(0x68)
            count_da = unpack("<I", bootldr.read(4))[0]
            for i in range(0, count_da):
                bootldr.seek(0x6C + (i * 0xDC))
                datmp = read_object(bootldr.read(0x14), DA)  # hdr
                da = [datmp]
                # bootldr.seek(0x6C + (i * 0xDC) + 0x14) #sections
                for m in range(0, datmp["entry_region_count"]):
                    entry_tmp = read_object(bootldr.read(20), entry_region)
                    da.append(entry_tmp)
                da_setup.append(da)
                print(f"Loader: {os.path.basename(loader)}")
                dadb[da[0]["hw_code"]] = [("da_payload_addr", da[2]["m_start_addr"]),
                                          ("pl_payload_addr", da[3]["m_start_addr"])]
                print("hwcode: 0x%04X" % da[0]["hw_code"])
                print("hw_sub_code: 0x%04X" % da[0]["hw_sub_code"])
                print("hw_version: 0x%04X" % da[0]["hw_version"])
                print("sw_version: 0x%04X" % da[0]["sw_version"])
                print("Reserved1: 0x%04X" % da[0]["reserved1"])
                print("Reserved3: 0x%04X" % da[0]["reserved3"])
                for x in range(da[0]["entry_region_count"]):
                    entry = da[x + 1]
                    print(f"\t{x}: {hex(entry['m_start_addr'])}")
                mbuf = da[3]["m_buf"]
                m_len = da[3]["m_len"]
                startaddr = da[3]["m_start_addr"]
                with open(loader, "rb") as rf:
                    rf.seek(mbuf)
                    da2data = rf.read(m_len)
                    fname = os.path.join("loaders",
                                         hex(da[0]["hw_code"])[2:] + "_" + hex(startaddr)[2:] + os.path.basename(
                                             loader))
                    open(fname, "wb").write(da2data)
                mbuf = da[2]["m_buf"]
                m_len = da[2]["m_len"]
                startaddr = da[2]["m_start_addr"]
                sys.stdout.flush()
                with open(loader, "rb") as rf:
                    rf.seek(mbuf)
                    data = rf.read(m_len)
                    test = data.find(b"\x01\x01\x54\xE3\x01\x14\xA0\xE3")
                    if test != -1:
                        print("V6 Device is patched against carbonara :(")
                    test=data.find(b"\x08\x00\xa8\x52\xff\x02\x08\xeb")
                    if test != -1:
                        print("V6 Device is patched against carbonara :(")
                    test=data.find(b"\x01\x01\x50\xE3\x01\x14\xA0\xE3")
                    if test != -1:
                        print("V6 Device is patched against carbonara :(")
                    test=data.find(b"2nd DA address is invalid")
                    if test != -1:
                        print("V6 Device is patched against carbonara :(")
                    test2=data.find(b"\x06\x9B\x4F\xF0\x80\x40\x02\xA9")
                    if test2 != -1:
                        print("V5 Device is patched against carbonara :(")
                    hashidx = data.find(int.to_bytes(0xC0070004, 4, 'little'))
                    if hashidx != -1:
                        print("Hash check found.")
                    else:
                        hashidx = data.find(b"\xCC\xF2\x07\x09")  # => b"\x4F\xF0\x00\x09""
                        if hashidx != -1:
                            print("Hash check 2 found.")
                        else:
                            hashidx = find_binary(data, b"\x14\x2C\xF6.\xFE\xE7")  # => b"\x14\x2C\xF6\xD1\x00\x00"
                            if hashidx is not None:
                                print("Hash check 3 found.")
                            else:
                                hashidx = find_binary(data, b"\x04\x50\x00\xE3\x07\x50\x4C\xE3")
                                if hashidx is not None:
                                    print("Hash check 4 (V6) found.")
                                else:
                                    hashidx = find_binary(data,b"\x01\x10\x81\xE2\x00\x00\x51\xE1")
                                    if hashidx is not None:
                                        print("Hash check 5 (V6) found.")
                                    else:
                                        print("HASH ERROR !!!!")

                    fname = os.path.join("loaders",
                                         hex(da[0]["hw_code"])[2:] + "_" + hex(startaddr)[2:] + os.path.basename(
                                             loader))
                    open(fname, "wb").write(data)
                print(f"Offset: {hex(mbuf)}")
                print(f"Length: {hex(m_len)}")
                print(f"Addr: {hex(startaddr)}")
                bootldr.seek(da[2]["m_buf"])
                tt = bootldr.read(da[2]["m_len"])
                idx = tt.find(bytes.fromhex("70BB442D27D244A7"))
                # idx = tt.find(bytes.fromhex("01279360D36013615361"))
                if idx != -1:
                    print("V3 Enabled")
                bootldr.seek(da[3]["m_buf"])
                tt = bootldr.read(da[3]["m_len"])
                idx2 = tt.find(bytes.fromhex("03 29 0D D9 07 4B 1B 68 03 60"))
                if idx2 != -1:
                    efusedb[da[0]["hw_code"]] = hex(int.from_bytes(tt[idx2 + 0x24:idx2 + 0x28], 'little') & 0xFFFFF000)
                else:
                    if not da[0]["hw_code"] in efusedb:
                        efusedb[da[0]["hw_code"]] = "None"
                print()

    sorted_dict = dict(sorted(efusedb.items()))
    for hwcode in sorted_dict:
        print(f"[{hex(hwcode)}] efuse_addr = {efusedb[hwcode]}")

    sorted_dict = dict(sorted(dadb.items()))
    for dat in sorted_dict:
        for ldr in dadb[dat]:
            print(f"{hex(dat)}:{ldr[0]}={hex(ldr[1])}")

    """
    chipinfo="/home/bjk/Projects/mtk_bypass/SP_Flash_Tool_v5.2052_Linux/libflashtool.v1.so"
    with open(chipinfo, 'rb') as ci:
        ci.seek(0x3C63C0) #830000004D543635
        data=bytearray(ci.read())
        for i in range(0,len(data),0x48):
            idx=unpack("<I",data[i:i+4])[0]
            name=data[i+4:i+4+0x20].rstrip(b"\x00").decode('utf-8')
            fields=unpack("<HHHIHIIIIII",data[i+4+0x20:i+4+0x20+6+4+2+(6*4)])
            print(str(idx)+" "+name+": "+hex(fields[2]))
    """


if __name__ == "__main__":
    main()
