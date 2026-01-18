from io import BytesIO
from mtkclient.Library.utils import StructhelperIo


class CHS:
    def __init__(self, rf):
        c = rf.bytes(1)
        self.cylinder = 0 if c == 0 else c | 0x300
        self.head = rf.bytes(1)
        self.sector = rf.bytes(1) & 0x2F

    def __repr__(self):
        return f"({hex(self.cylinder)},{hex(self.head)},{hex(self.sector)})"


class MbrEntry:
    def __init__(self, rf: StructhelperIo):
        self.active = rf.bytes(1)
        self.start_chs = CHS(rf)
        self.id = rf.bytes(1)
        self.end_chs = CHS(rf)
        self.start_sector = rf.dword()
        self.sectors = rf.dword()

    def __repr__(self):
        if self.active:
            active = f"active:{hex(self.active)} "
        else:
            active = ""
        return f"ID:{hex(self.id)} {active}start_chs:{self.start_chs} end_chs:{self.end_chs} start_sector: {hex(self.start_sector)} sectors:{hex(self.sectors)}"


class Ebr:
    def __init__(self, data):
        self.rf = StructhelperIo(BytesIO(bytearray(data)))

    def parse(self) -> list:
        self.rf.seek(0x200 - 2)
        mbr_entries = []
        if self.rf.short() == 0xAA55:
            for i in range(0x1FE, 0, -0x10):
                self.rf.seek(i - 0x10)
                entry = MbrEntry(self.rf)
                if entry.id == 0:
                    break
                mbr_entries.insert(0, entry)
        return mbr_entries


def main():
    data = open("EBR1.bin", "rb").read()
    mbr_entries = Ebr(data).parse()
    for entry in mbr_entries:
        print(entry)


if __name__ == '__main__':
    main()
