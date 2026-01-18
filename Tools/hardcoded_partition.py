#!/usr/bin/env python3
import os.path
import sys
from io import BytesIO


def main():
    if len(sys.argv)<3:
        print("Usage: ./hardcoded_partition.py preloader.bin flash.bin")
        sys.exit(1)
    if not os.path.exists(sys.argv[1]):
        print("Invalid preloader given")
    if not os.path.exists(sys.argv[2]):
        print("Invalid flash given")
    preloader=open(sys.argv[1], "rb").read()
    idx = preloader.find(b"PRELOADER")
    partitions=[]
    if idx!=-1:
        offs=idx+0x200D00
        idx2 = preloader.find(int.to_bytes(offs,4,'little'))
        if idx2!=-1:
            class partition_t:
                def __init__(self,fh):
                    name_ptr=int.from_bytes(fh.read(4),'little')-0x200D00
                    self.start=int.from_bytes(fh.read(4),'little')
                    self.length=int.from_bytes(fh.read(4),'little')
                    unk1=int.from_bytes(fh.read(4),'little')
                    unk2=int.from_bytes(fh.read(4),'little')
                    unk3=int.from_bytes(fh.read(4),'little')
                    pos=fh.tell()
                    fh.seek(name_ptr)
                    self.name = fh.read(255).split(b"\x00")[0].decode('utf-8')
                    fh.seek(pos)
            fh = BytesIO(preloader)
            fh.seek(idx2)
            partitions=[]
            totlength = os.stat(sys.argv[2]).st_size
            pos=0
            while True:
                part=partition_t(fh)
                if part.name=="PRELOADER":
                    continue
                if pos==0:
                    pos = 0xB80000

                if part.start == 0:
                    part.start = pos
                if part.length == 0 and part.name=="USER":
                    part.length = 0x100000000
                elif part.length == 0 and part.name=="FAT":
                    part.length = totlength - 0x800 - 0x100000000
                pos += part.length
                if part.length!=0:
                    partitions.append(part)
                    if part.name == "FAT":
                        break
                else:
                    break
    if not os.path.exists("out"):
        os.mkdir("out")
    with open(sys.argv[2], "rb") as rf:
        pos = 0xB80000
        for partition in partitions:
            if partition.name=="PRELOADER":
                continue
            rf.seek(pos)
            bytestoread=partition.length
            filename=os.path.join("out",partition.name+".bin")
            fat=False
            print(f"Extracting {partition.name} to {filename}...")
            with open(filename, "wb") as wf:
                while bytestoread>0:
                    sz=min(0x200000,bytestoread)
                    data=rf.read(sz)
                    if data==b"":
                        break
                    wf.write(data)
                    bytestoread-=len(data)
            pos+=partition.length
if __name__ == '__main__':
    main()