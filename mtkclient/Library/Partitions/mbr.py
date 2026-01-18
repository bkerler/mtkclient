import logging
from enum import Enum
from mtkclient.Library.gui_utils import structhelper_io
from mtkclient.Library.Partitions import generic, partf


class MasterBootRecord:
    def __init__(self, rf: structhelper_io):
        self.BootCode = rf.bytes(446)
        self.PartitionEntry = [PartitionEntry(rf) for _ in range(4)]
        self.EndOfSectorMarker = rf.short()


class ExtendedBootPartition:
    def __init__(self, rf: structhelper_io):
        self.Empty = rf.bytes(446)
        self.PartitionEntry = [PartitionEntry(rf) for _ in range(4)]
        self.EndOfSectorMarker = rf.short()


class BootIndicator(Enum):
    NOBOOT = 0
    SYSTEM_PARTITION = 0x80


class PartitionSystemID(Enum):
    PARTITION_SYSTEMID_EMPTY = 0
    PARTITION_SYSTEMID_FAT_12 = 1
    PARTITION_SYSTEMID_XENIX_ROOT = 2
    PARTITION_SYSTEMID_XENIX_USR = 3
    PARTITION_SYSTEMID_FAT_16_INF32MB = 4
    PARTITION_SYSTEMID_EXTENDED = 5
    PARTITION_SYSTEMID_FAT_16 = 6
    PARTITION_SYSTEMID_NTFS_HPFS_EXFAT = 7
    PARTITION_SYSTEMID_AIX = 8
    PARTITION_SYSTEMID_AIX_BOOT = 9
    PARTITION_SYSTEMID_OS2_BOOT_MGR = 10
    PARTITION_SYSTEMID_PRI_FAT32_INT13 = 11
    PARTITION_SYSTEMID_EXT_FAT32_INT13 = 12
    PARTITION_SYSTEMID_SILICON_SAFE = 13
    PARTITION_SYSTEMID_EXT_FAT16_INT13 = 14
    PARTITION_SYSTEMID_WIN95_EXT_PARTITION = 15
    PARTITION_SYSTEMID_OPUS = 16
    PARTITION_SYSTEMID_FAT_12_HIDDEN = 17
    PARTITION_SYSTEMID_COMPAQ_DIAG = 18
    PARTITION_SYSTEMID_FAT_16_HIDDEN_INF32MB = 20
    PARTITION_SYSTEMID_FAT_16_HIDDEN = 22
    PARTITION_SYSTEMID_NTFS_HPFS_HIDDEN = 23
    PARTITION_SYSTEMID_AST_SMARTSLEEP_PARTITION = 24
    PARTITION_SYSTEMID_OSR2_FAT32 = 27
    PARTITION_SYSTEMID_OSR2_FAT32_LBA = 28
    PARTITION_SYSTEMID_HIDDEN_FAT16_LBA = 30
    PARTITION_SYSTEMID_NEC_DOS = 36
    PARTITION_SYSTEMID_PQSERVICE_ROUTERBOOT = 39
    PARTITION_SYSTEMID_ATHEOS_FILE_SYSTEM = 42
    PARTITION_SYSTEMID_NOS = 50
    PARTITION_SYSTEMID_JFS_ON_OS2_OR_ECS = 53
    PARTITION_SYSTEMID_THEOS_2GB = 56
    PARTITION_SYSTEMID_PLAN_9_THEOS_SPANNED = 57
    PARTITION_SYSTEMID_THEOS_4GB = 58
    PARTITION_SYSTEMID_THEOS_EXTENDED = 59
    PARTITION_SYSTEMID_PARTITIONMAGIC_RECOVERY = 60
    PARTITION_SYSTEMID_HIDDEN_NETWARE = 61
    PARTITION_SYSTEMID_VENIX = 64
    PARTITION_SYSTEMID_LINUX_PPC_PREP = 65
    PARTITION_SYSTEMID_LINUX_SWAP = 66
    PARTITION_SYSTEMID_LINUX_NATIVE = 67
    PARTITION_SYSTEMID_GOBACK = 68
    PARTITION_SYSTEMID_BOOT_US_EUEL_ELAN = 69,
    PARTITION_SYSTEMID_EUMEL_ELAN_1 = 70
    PARTITION_SYSTEMID_EUMEL_ELAN_2 = 71
    PARTITION_SYSTEMID_EUMEL_ELAN_3 = 72
    PARTITION_SYSTEMID_OBERON = 76
    PARTITION_SYSTEMID_QNX4_X = 77
    PARTITION_SYSTEMID_QNX4_X_2ND_PART = 78
    PARTITION_SYSTEMID_QNX4_X_3RD_PART_OBERON = 79
    PARTITION_SYSTEMID_ONTRACK_LYNX_OBERON = 80
    PARTITION_SYSTEMID_ONTRACK_NOVELL = 81
    PARTITION_SYSTEMID_CP_M_MICROPORT_SYSV_AT = 82
    PARTITION_SYSTEMID_DISK_MANAGER_AUX3 = 83
    PARTITION_SYSTEMID_DISK_MANAGER_DDO = 84
    PARTITION_SYSTEMID_EZ_DRIVE = 85
    PARTITION_SYSTEMID_GOLDEN_BOW_EZ_BIOS = 86
    PARTITION_SYSTEMID_DRIVEPRO_VNDI = 87
    PARTITION_SYSTEMID_PRIAM_EDISK = 92
    PARTITION_SYSTEMID_SPEEDSTOR = 97
    PARTITION_SYSTEMID_GNU_HURD = 99
    PARTITION_SYSTEMID_NOVELL = 100
    PARTITION_SYSTEMID_NETWARE_386 = 101
    PARTITION_SYSTEMID_NETWARE_SMS_PARTITION = 102
    PARTITION_SYSTEMID_NOVELL_1 = 103
    PARTITION_SYSTEMID_NOVELL_2 = 104
    PARTITION_SYSTEMID_NETWARE_NSS = 105
    PARTITION_SYSTEMID_DISKSECURE_MULTI_BOOT = 112
    PARTITION_SYSTEMID_V7_X86 = 114
    PARTITION_SYSTEMID_PC_IX = 117
    PARTITION_SYSTEMID_M2FS_M2CS_VNDI = 119
    PARTITION_SYSTEMID_XOSL_FS = 120
    PARTITION_SYSTEMID_MINUX_OLD = 128
    PARTITION_SYSTEMID_MINUX_LINUX = 129
    PARTITION_SYSTEMID_LINUX_SWAP_2 = 130
    PARTITION_SYSTEMID_LINUX_NATIVE_2 = 131
    PARTITION_SYSTEMID_OS2_HIDDEN_HIBERNATION = 132
    PARTITION_SYSTEMID_LINUX_EXTENDED = 133
    PARTITION_SYSTEMID_OLD_LINUX_RAID_FAT16 = 134
    PARTITION_SYSTEMID_NTFS_VOLUME_SET = 135
    PARTITION_SYSTEMID_LINUX_PLAINTEXT_TABLE = 136
    PARTITION_SYSTEMID_LINUX_KERNEL_AIR_BOOT = 138
    PARTITION_SYSTEMID_FAULT_TOLERANT_FAT32 = 139
    PARTITION_SYSTEMID_FAULT_TOLERANT_FAT32_INT13H = 140
    PARTITION_SYSTEMID_FREE_FDISK_FAT12 = 141,
    PARTITION_SYSTEMID_LINUX_LOGICAL_VOLUME_MANAGER = 142
    PARTITION_SYSTEMID_FREE_FDISK_PRIMARY_FAT16 = 144
    PARTITION_SYSTEMID_FREE_FDISK_EXTENDED = 145
    PARTITION_SYSTEMID_FREE_FDISK_LARGE_FAT16 = 146
    PARTITION_SYSTEMID_AMOEBA = 147
    PARTITION_SYSTEMID_AMOEBA_BBT = 148
    PARTITION_SYSTEMID_MIT_EXOPC = 149
    PARTITION_SYSTEMID_CHRP_ISO_9660 = 150
    PARTITION_SYSTEMID_FREE_FDISK_FAT32 = 151
    PARTITION_SYSTEMID_FREE_FDISK_FAT32_LBA = 152
    PARTITION_SYSTEMID_DCE376 = 153
    PARTITION_SYSTEMID_FREE_FDISK_FAT16_LBA = 154
    PARTITION_SYSTEMID_FREE_FDISK_EXTENDED_LBA = 155
    PARTITION_SYSTEMID_FORTHOS = 158
    PARTITION_SYSTEMID_BSD_OS = 159
    PARTITION_SYSTEMID_LAPTOP_HIBERNATION = 160
    PARTITION_SYSTEMID_LAPTOP_HIBERNATION_HP = 161
    PARTITION_SYSTEMID_HP_EXPANSION_SPEEDSTOR_1 = 163
    PARTITION_SYSTEMID_HP_EXPANSION_SPEEDSTOR_2 = 164
    PARTITION_SYSTEMID_BSD_386 = 165
    PARTITION_SYSTEMID_OPENBSD_SPEEDSTOR = 166
    PARTITION_SYSTEMID_NEXTSTEP = 167
    PARTITION_SYSTEMID_MAC_OS_X = 168
    PARTITION_SYSTEMID_NETBSD = 169
    PARTITION_SYSTEMID_OLIVETTI = 170
    PARTITION_SYSTEMID_MAC_OS_X_BOOT_GO = 171
    PARTITION_SYSTEMID_RISC_OS_ADFS = 173
    PARTITION_SYSTEMID_SHAGOS = 174
    PARTITION_SYSTEMID_SHAGOS_SWAP_MACOS_X_HFS = 175
    PARTITION_SYSTEMID_BOOTSTAR_DUMMY = 176
    PARTITION_SYSTEMID_HP_EXPANSION_QNX = 177
    PARTITION_SYSTEMID_QNX_POWER_SAFE = 178
    PARTITION_SYSTEMID_HP_EXPANSION_QNX_2 = 179
    PARTITION_SYSTEMID_HP_EXPANSION_SPEEDSTOR_3 = 180
    PARTITION_SYSTEMID_HP_EXPANSION_FAT16 = 182
    PARTITION_SYSTEMID_BSDI_FS = 183
    PARTITION_SYSTEMID_BSDI_SWAP = 184
    PARTITION_SYSTEMID_BOOT_WIZARD_HIDDEN = 187
    PARTITION_SYSTEMID_ACRONIS_BACKUP = 188
    PARTITION_SYSTEMID_BONNYDOS_286 = 189
    PARTITION_SYSTEMID_SOLARIS_8_BOOT = 190
    PARTITION_SYSTEMID_NEW_SOLARIS = 191
    PARTITION_SYSTEMID_CTOS_REAL_32_DR_DOS = 192
    PARTITION_SYSTEMID_DRDOS_SECURED = 193
    PARTITION_SYSTEMID_HIDDEN_LINUX_SWAP = 195
    PARTITION_SYSTEMID_DRDOS_SECURED_FAT16 = 196
    PARTITION_SYSTEMID_DRDOS_SECURED_EXTENDED = 197
    PARTITION_SYSTEMID_DRDOS_SECURED_FAT16_STRIPE = 198
    PARTITION_SYSTEMID_SYRINX = 199
    PARTITION_SYSTEMID_DR_DOS_8_1 = 200
    PARTITION_SYSTEMID_DR_DOS_8_2 = 201
    PARTITION_SYSTEMID_DR_DOS_8_3 = 202
    PARTITION_SYSTEMID_DR_DOS_7_SECURED_FAT32_CHS = 203
    PARTITION_SYSTEMID_DR_DOS_7_SECURED_FAT32_LBA = 204
    PARTITION_SYSTEMID_CTOS_MEMDUMP = 205
    PARTITION_SYSTEMID_DR_DOS_7_FAT16X = 206
    PARTITION_SYSTEMID_DR_DOS_7_SECURED_EXT_DOS = 207
    PARTITION_SYSTEMID_REAL_32_SECURE = 208
    PARTITION_SYSTEMID_OLD_MULTIUSER_FAT12 = 209
    PARTITION_SYSTEMID_OLD_MULTIUSER_FAT16 = 212
    PARTITION_SYSTEMID_OLD_MULTIUSER_EXTENDED = 213
    PARTITION_SYSTEMID_OLD_MULTIUSER_FAT16_2 = 214
    PARTITION_SYSTEMID_CP_M_86 = 216
    PARTITION_SYSTEMID_NON_FS_DATA_POWERCOPY_BACKUP = 218
    PARTITION_SYSTEMID_CP_M = 219
    PARTITION_SYSTEMID_HIDDEN_CTOS_MEMDUMP = 221
    PARTITION_SYSTEMID_DELL_POWEREDGE_UTIL = 222
    PARTITION_SYSTEMID_DG_UX_DISK_MANAGER_BOOTIT = 223
    PARTITION_SYSTEMID_ACCESS_DOS = 225
    PARTITION_SYSTEMID_DOS_R_O = 227
    PARTITION_SYSTEMID_SPEEDSTOR_FAT16_EXTENDED = 228
    PARTITION_SYSTEMID_STORAGE_DIMENSIONS_SPEEDSTOR = 230
    PARTITION_SYSTEMID_LUKS = 232
    PARTITION_SYSTEMID_RUFUS_EXTRA_FREEDESKTOP = 234
    PARTITION_SYSTEMID_BEOS_BFS = 235
    PARTITION_SYSTEMID_SKYOS_SKYFS = 236
    PARTITION_SYSTEMID_LEGACY_MBR_EFI_HEADER = 238
    PARTITION_SYSTEMID_EFI_FS = 239
    PARTITION_SYSTEMID_LINUX_PA_RISC_BOOT = 240
    PARTITION_SYSTEMID_STORAGE_DIMENSIONS_SPEEDSTOR_2 = 241
    PARTITION_SYSTEMID_DOS_SECONDARY = 242
    PARTITION_SYSTEMID_SPEEDSTOR_LARGE_PROLOGUE = 244
    PARTITION_SYSTEMID_PROLOGUE_MULTI_VOLUME = 245
    PARTITION_SYSTEMID_STORAGE_DIMENSIONS_SPEEDSTOR_3 = 246
    PARTITION_SYSTEMID_DDRDRIVE_SOLID_STATE_FS = 247
    PARTITION_SYSTEMID_PCACHE = 249
    PARTITION_SYSTEMID_BOCHS = 250
    PARTITION_SYSTEMID_VMWARE_FILE_SYSTEM = 251
    PARTITION_SYSTEMID_VMWARE_SWAP = 252
    PARTITION_SYSTEMID_LINUX_RAID = 253
    PARTITION_SYSTEMID_SPEEDSTOR_LANSTEP_LINUX = 254
    PARTITION_SYSTEMID_BBT = 255


class PartitionEntry:
    def __init__(self, rf: structhelper_io):
        self.bootindicator = BootIndicator(rf.bytes(1))
        self.startinghead = rf.bytes(1)
        self.starting_sect_cylinder = rf.short()
        self.system_id = PartitionSystemID(rf.bytes(1))
        self.ending_head = rf.bytes(1)
        self.ending_sect_cylinder = rf.short()
        self.relative_sector = rf.dword()
        self.total_sectors = rf.dword()


class PartEntry:
    def __init__(self, start, length, ptype, name):
        self.start = start
        self.length = length
        self.ptype = ptype
        self.name = name

    def __repr__(self):
        info = f"Offset: {hex(self.start)} "
        info += f"Size: {hex(self.length)} "
        if self.name:
            info += f"Name:{self.name} "
        if self.ptype:
            info += f"PType:{self.ptype} "
        return info


class MBR_Structure:
    def __init__(self, rf: structhelper_io):
        self.partitions = []
        self.rf = rf
        mbr = MasterBootRecord(self.rf)
        self.parse(mbr.PartitionEntry)

    def parse(self, partitions: list) -> bool:
        entries = []
        for partition in partitions:
            if partition.system_id == PartitionSystemID.PARTITION_SYSTEMID_EXTENDED:
                offs = partition.relative_sector * 512
                self.rf.seek(offs + 0x1FE)
                marker = self.rf.short()
                self.rf.seek(offs)
                if marker == 0xAA55:
                    ebp = ExtendedBootPartition(self.rf)
                    for part in ebp.PartitionEntry:
                        part.relative_sector += offs // 512
                        partitions.append(part)
            elif partition.total_sectors != 0:
                entries.append(partition)

        for partition in entries:
            pos = self.rf.getpos()
            partoffs = partition.relative_sector * 512
            self.rf.seek(partoffs + 0x438)
            hdr = self.rf.short()
            if hdr == 0xEF53:
                ptype = "EXT"
                self.rf.seek(partoffs + 0x488)
                name = self.rf.string(255).replace("/", "")
                self.partitions.append(
                    PartEntry(start=partition.relative_sector, length=partition.total_sectors, ptype=ptype,
                              name=name))
            else:
                self.partitions.append(
                    PartEntry(start=partition.relative_sector, length=partition.total_sectors, ptype="",
                              name=""))
            self.rf.seek(pos)
        if not entries:
            return False
        return True


class mbr(generic):

    def __init__(self, rf, filesize: int = 0, num_part_entries=0, part_entry_size=0, part_entry_start_lba=0,
                 loglevel=logging.INFO, *args, **kwargs):

        super().__init__(rf, filesize, num_part_entries, part_entry_size, part_entry_start_lba, loglevel, *args,
                         **kwargs)
        self.parttype = "MBR"
        self.sectorsize = 512
        self.totalsectors = filesize // self.sectorsize
        if filesize == 0:
            self.calcsectors = True
        else:
            self.calcsectors = False

    def parse(self, offset:int=0) -> bool:
        dt = self.rf
        dt.seek(offset+0x1FE)
        marker = dt.short()
        dt.seek(offset)
        if marker == 0xAA55:
            ms = MBR_Structure(dt)
            partitions = sorted(ms.partitions, key=lambda x: x.start)
            self.partentries = []
            i = 0
            for partition in partitions:
                pf = partf()
                pf.name = partition.name if len(partition.name) else str(i)
                pf.sector = partition.start + (offset//512)
                pf.sectors = partition.length
                pf.type = partition.ptype
                if self.calcsectors:
                    if pf.sector + pf.sectors > self.totalsectors:
                        self.totalsectors = pf.sector + pf.sectors
                else:
                    if pf.sector + pf.sectors > self.totalsectors:
                        pf.sectors = self.totalsectors - pf.sector
                self.partentries.append(pf)
                i += 1
            return True
        return False
