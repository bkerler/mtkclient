#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2023
# GPLv3 License
import logging
import os
from enum import Enum
from io import BytesIO
from struct import pack

from mtkclient.Library.gui_utils import structhelper_io
from mtkclient.Library.Partitions import generic

AB_FLAG_OFFSET = 6
AB_PARTITION_ATTR_SLOT_ACTIVE = (0x1 << 2)
AB_PARTITION_ATTR_BOOT_SUCCESSFUL = (0x1 << 6)
AB_PARTITION_ATTR_UNBOOTABLE = (0x1 << 7)
AB_SLOT_ACTIVE_VAL = 0x3F
AB_SLOT_INACTIVE_VAL = 0x0
AB_SLOT_ACTIVE = 1
AB_SLOT_INACTIVE = 0


class GptSettings:
    gpt_num_part_entries = 0
    gpt_part_entry_size = 0
    gpt_part_entry_start_lba = 0

    def __init__(self, gpt_num_part_entries: str, gpt_part_entry_size: str, gpt_part_entry_start_lba: str):
        self.gpt_num_part_entries = int(gpt_num_part_entries)
        self.gpt_part_entry_size = int(gpt_part_entry_size)
        self.gpt_part_entry_start_lba = int(gpt_part_entry_start_lba)


class gpt(generic):
    def __init__(self, rf, filesize: int, num_part_entries=0, part_entry_size=0, part_entry_start_lba=0,
                 loglevel=logging.INFO, *args, **kwargs):

        super().__init__(rf, filesize, num_part_entries, part_entry_size, part_entry_start_lba, loglevel, *args,
                         **kwargs)

    class gpt_header:
        def __init__(self, data):
            sh = structhelper_io(data)
            self.signature = sh.bytes(8)
            self.revision = sh.dword()
            self.header_size = sh.dword()
            self.crc32 = sh.dword()
            self.reserved = sh.dword()
            self.current_lba = sh.qword()
            self.backup_lba = sh.qword()
            self.first_usable_lba = sh.qword()
            self.last_usable_lba = sh.qword()
            self.disk_guid = sh.bytes(16)
            self.part_entry_start_lba = sh.qword()
            self.num_part_entries = sh.dword()
            self.part_entry_size = sh.dword()

    class gpt_partition:
        def __init__(self, data):
            sh = structhelper_io(data)
            self.type = sh.bytes(16)
            self.unique = sh.bytes(16)
            self.first_lba = sh.qword()
            self.last_lba = sh.qword()
            self.flags = sh.qword()
            self.name = sh.ustring(72)

        def create(self):
            val = pack("16s16sQQQ72s", self.type, self.unique, self.first_lba, self.last_lba, self.flags, self.name)
            return val

    class efi_type(Enum):
        EFI_UNUSED = 0x00000000
        EFI_MBR = 0x024DEE41
        EFI_SYSTEM = 0xC12A7328
        EFI_BIOS_BOOT = 0x21686148
        EFI_IFFS = 0xD3BFE2DE
        EFI_SONY_BOOT = 0xF4019732
        EFI_LENOVO_BOOT = 0xBFBFAFE7
        EFI_MSR = 0xE3C9E316
        EFI_BASIC_DATA = 0xEBD0A0A2
        EFI_LDM_META = 0x5808C8AA
        EFI_LDM = 0xAF9B60A0
        EFI_RECOVERY = 0xDE94BBA4
        EFI_GPFS = 0x37AFFC90
        EFI_STORAGE_SPACES = 0xE75CAF8F
        EFI_HPUX_DATA = 0x75894C1E
        EFI_HPUX_SERVICE = 0xE2A1E728
        EFI_LINUX_DAYA = 0x0FC63DAF
        EFI_LINUX_RAID = 0xA19D880F
        EFI_LINUX_ROOT32 = 0x44479540
        EFI_LINUX_ROOT64 = 0x4F68BCE3
        EFI_LINUX_ROOT_ARM32 = 0x69DAD710
        EFI_LINUX_ROOT_ARM64 = 0xB921B045
        EFI_LINUX_SWAP = 0x0657FD6D
        EFI_LINUX_LVM = 0xE6D6D379
        EFI_LINUX_HOME = 0x933AC7E1
        EFI_LINUX_SRV = 0x3B8F8425
        EFI_LINUX_DM_CRYPT = 0x7FFEC5C9
        EFI_LINUX_LUKS = 0xCA7D7CCB
        EFI_LINUX_RESERVED = 0x8DA63339
        EFI_FREEBSD_BOOT = 0x83BD6B9D
        EFI_FREEBSD_DATA = 0x516E7CB4
        EFI_FREEBSD_SWAP = 0x516E7CB5
        EFI_FREEBSD_UFS = 0x516E7CB6
        EFI_FREEBSD_VINUM = 0x516E7CB8
        EFI_FREEBSD_ZFS = 0x516E7CBA
        EFI_OSX_HFS = 0x48465300
        EFI_OSX_UFS = 0x55465300
        EFI_OSX_ZFS = 0x6A898CC3
        EFI_OSX_RAID = 0x52414944
        EFI_OSX_RAID_OFFLINE = 0x52414944
        EFI_OSX_RECOVERY = 0x426F6F74
        EFI_OSX_LABEL = 0x4C616265
        EFI_OSX_TV_RECOVERY = 0x5265636F
        EFI_OSX_CORE_STORAGE = 0x53746F72
        EFI_SOLARIS_BOOT = 0x6A82CB45
        EFI_SOLARIS_ROOT = 0x6A85CF4D
        EFI_SOLARIS_SWAP = 0x6A87C46F
        EFI_SOLARIS_BACKUP = 0x6A8B642B
        EFI_SOLARIS_USR = 0x6A898CC3
        EFI_SOLARIS_VAR = 0x6A8EF2E9
        EFI_SOLARIS_HOME = 0x6A90BA39
        EFI_SOLARIS_ALTERNATE = 0x6A9283A5
        EFI_SOLARIS_RESERVED1 = 0x6A945A3B
        EFI_SOLARIS_RESERVED2 = 0x6A9630D1
        EFI_SOLARIS_RESERVED3 = 0x6A980767
        EFI_SOLARIS_RESERVED4 = 0x6A96237F
        EFI_SOLARIS_RESERVED5 = 0x6A8D2AC7
        EFI_NETBSD_SWAP = 0x49F48D32
        EFI_NETBSD_FFS = 0x49F48D5A
        EFI_NETBSD_LFS = 0x49F48D82
        EFI_NETBSD_RAID = 0x49F48DAA
        EFI_NETBSD_CONCAT = 0x2DB519C4
        EFI_NETBSD_ENCRYPT = 0x2DB519EC
        EFI_CHROMEOS_KERNEL = 0xFE3A2A5D
        EFI_CHROMEOS_ROOTFS = 0x3CB8E202
        EFI_CHROMEOS_FUTURE = 0x2E0A753D
        EFI_HAIKU = 0x42465331
        EFI_MIDNIGHTBSD_BOOT = 0x85D5E45E
        EFI_MIDNIGHTBSD_DATA = 0x85D5E45A
        EFI_MIDNIGHTBSD_SWAP = 0x85D5E45B
        EFI_MIDNIGHTBSD_UFS = 0x0394EF8B
        EFI_MIDNIGHTBSD_VINUM = 0x85D5E45C
        EFI_MIDNIGHTBSD_ZFS = 0x85D5E45D
        EFI_CEPH_JOURNAL = 0x45B0969E
        EFI_CEPH_ENCRYPT = 0x45B0969E
        EFI_CEPH_OSD = 0x4FBD7E29
        EFI_CEPH_ENCRYPT_OSD = 0x4FBD7E29
        EFI_CEPH_CREATE = 0x89C57F98
        EFI_CEPH_ENCRYPT_CREATE = 0x89C57F98
        EFI_OPENBSD = 0x824CC7A0
        EFI_QNX = 0xCEF5A9AD
        EFI_PLAN9 = 0xC91818F9
        EFI_VMWARE_VMKCORE = 0x9D275380
        EFI_VMWARE_VMFS = 0xAA31E02A
        EFI_VMWARE_RESERVED = 0x9198EFFC

    def parseheader(self):
        self.rf.seek(self.sectorsize)
        return self.gpt_header(self.rf.bytes(0x5C))

    def parse_gpt(self):
        if self.header.revision != 0x10000:
            self.error("Unknown GPT revision.")
            return False
        if self.part_entry_start_lba != 0:
            start = self.part_entry_start_lba
        else:
            start = self.header.part_entry_start_lba * self.sectorsize

        entrysize = self.header.part_entry_size
        self.partentries = []

        class partf:
            unique = b""
            first_lba = 0
            last_lba = 0
            flags = 0
            sector = 0
            sectors = 0
            type = b""
            name = ""
            entryoffset = 0

        num_part_entries = self.header.num_part_entries

        for idx in range(0, num_part_entries):
            self.rf.seek(start + (idx * entrysize))
            data = self.rf.bytes(entrysize)
            if int(data[16:32].hex(), 16) == 0:
                break
            partentry = self.gpt_partition(data)
            pa = partf()
            guid1 = int.from_bytes(partentry.unique[0:0x4], 'little')
            guid2 = int.from_bytes(partentry.unique[0x4:0x6], 'little')
            guid3 = int.from_bytes(partentry.unique[0x6:0x8], 'little')
            guid4 = int.from_bytes(partentry.unique[0x8:0xA], 'little')
            guid5 = partentry.unique[0xA:0x10].hex()
            pa.unique = "{:08x}-{:04x}-{:04x}-{:04x}-{}".format(guid1, guid2, guid3, guid4, guid5)
            pa.sector = partentry.first_lba
            pa.sectors = partentry.last_lba - partentry.first_lba + 1
            pa.flags = partentry.flags
            pa.entryoffset = start + (idx * entrysize)
            ptype = int.from_bytes(partentry.type[0:0x4], 'little')
            try:
                pa.type = self.efi_type(ptype).name
            except Exception:
                pa.type = hex(ptype)
            pa.name = partentry.name
            if pa.type == "EFI_UNUSED":
                continue
            self.partentries.append(pa)
        self.totalsectors = self.header.last_usable_lba + 34
        return True

    def parse(self) -> bool:
        for sectorsize in [0x200, 0x1000]:
            self.sectorsize = sectorsize
            self.rf.seek(self.sectorsize)
            self.header = self.gpt_header(self.rf.bytes(0x5C))
            if self.header.signature == b"EFI PART":
                return self.parse_gpt()
        return False

    def generate_rawprogram(self, lun, sectorsize, directory):
        fname = "rawprogram" + str(lun) + ".xml"
        with open(os.path.join(directory, fname), "wb") as wf:
            mstr = "<?xml version=\"1.0\" ?>\n<data>\n"
            partofsingleimage = "false"
            readbackverify = "false"
            sparse = "false"
            for partition in self.partentries:
                filename = partition.name + ".bin"
                mstr += f"\t<program SECTOR_SIZE_IN_BYTES=\"{sectorsize}\" " + \
                        f"file_sector_offset=\"0\" " \
                        f"filename=\"{filename}\" " + \
                        f"label=\"{partition.name}\" " \
                        f"num_partition_sectors=\"{partition.sectors}\" " + \
                        f"partofsingleimage=\"{partofsingleimage}\" " \
                        f"physical_partition_number=\"{str(lun)}\" " + \
                        f"readbackverify=\"{readbackverify}\" " \
                        f"size_in_KB=\"{(partition.sectors * sectorsize / 1024):.1f}\" " \
                        f"sparse=\"{sparse}\" " + \
                        f"start_byte_hex=\"{hex(partition.sector * sectorsize)}\" " \
                        f"start_sector=\"{partition.sector}\"/>\n"
            partofsingleimage = "true"
            sectors = self.header.first_usable_lba
            mstr += f"\t<program SECTOR_SIZE_IN_BYTES=\"{sectorsize}\" " + \
                    "file_sector_offset=\"0\" " + \
                    f"filename=\"gpt_{str(lun)}.bin\" " + \
                    "label=\"PrimaryGPT\" " + \
                    f"num_partition_sectors=\"{sectors}\" " + \
                    f"partofsingleimage=\"{partofsingleimage}\" " + \
                    f"physical_partition_number=\"{str(lun)}\" " + \
                    f"readbackverify=\"{readbackverify}\" " + \
                    f"size_in_KB=\"{(sectors * sectorsize / 1024):.1f}\" " + \
                    f"sparse=\"{sparse}\" " + \
                    "start_byte_hex=\"0x0\" " + \
                    "start_sector=\"0\"/>\n"
            sectors = self.header.first_usable_lba - 1
            mstr += f"\t<program SECTOR_SIZE_IN_BYTES=\"{sectorsize}\" " + \
                    "file_sector_offset=\"0\" " + \
                    f"filename=\"gpt_backup{str(lun)}.bin\" " + \
                    "label=\"BackupGPT\" " + \
                    f"num_partition_sectors=\"{sectors}\" " + \
                    f"partofsingleimage=\"{partofsingleimage}\" " + \
                    f"physical_partition_number=\"{str(lun)}\" " + \
                    f"readbackverify=\"{readbackverify}\" " + \
                    f"size_in_KB=\"{(sectors * sectorsize / 1024):.1f}\" " + \
                    f"sparse=\"{sparse}\" " + \
                    f"start_byte_hex=\"({sectorsize}*NUM_DISK_SECTORS)-{sectorsize * sectors}.\" " + \
                    f"start_sector=\"NUM_DISK_SECTORS-{sectors}.\"/>\n"
            mstr += "</data>"
            wf.write(bytes(mstr, "utf-8"))
            print(f"Wrote partition xml as {fname}")

    def test(self):
        res = self.printfile(os.path.join("TestFiles", "gpt_sm8180x.bin"))
        assert res, "GPT Partition wasn't decoded properly"

    def patch(self, data: bytes, partitionname="boot", active: bool = True):
        try:
            rf = BytesIO(data)
            for sectorsize in [512, 4096]:
                self.sectorsize = sectorsize
                result = self.parse()
                if result:
                    for partition in self.partentries:
                        if partitionname.lower() == partition.name.lower():
                            rf.seek(partition.entryoffset)
                            sdata = rf.read(self.header.part_entry_size)
                            partentry = self.gpt_partition(sdata)
                            flags = partentry.flags
                            if active:
                                flags |= AB_PARTITION_ATTR_SLOT_ACTIVE << (AB_FLAG_OFFSET * 8)
                            else:
                                flags |= AB_PARTITION_ATTR_UNBOOTABLE << (AB_FLAG_OFFSET * 8)
                            partentry.flags = flags
                            data = partentry.create()
                            return data, partition.entryoffset
                    break
            return None, None
        except Exception as e:
            self.error(str(e))
        return None, None

    def get_flag(self, imagename):
        if "." in imagename:
            imagename = imagename[:imagename.find(".")]
        try:
            self.rf.seek(0)
            return self.get_flag_data(imagename)
        except Exception:
            return None, None

    def get_flag_data(self, imagename: str):
        pos = self.rf.getpos()
        for sectorsize in [512, 4096]:
            self.rf.seek(pos)
            self.sectorsize = sectorsize
            try:
                result = self.parse()
            except Exception:
                return None, None
            if result:
                for partition in self.partentries:
                    if imagename in partition.name.lower():
                        return partition.sector, sectorsize
        return None, None
