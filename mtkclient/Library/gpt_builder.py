#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
Build a GUID Partition Table (protective MBR + primary + backup) from a
partition layout. mtkclient's gpt.py only *parses* a GPT; to repartition a
device from a scatter file (SP Flash Tool "Firmware Upgrade") we need to
*emit* one, which is what this module does.

The layout is given as a list of GptPartitionEntry (name, first/last LBA, type
and unique GUID bytes, flags). Addresses come straight from the scatter's
linear_start_addr / partition_size, so the produced table matches the layout
SP Flash Tool would write. Existing type/unique GUIDs are preserved by the
caller (see da_ws) so a re-flash keeps the device's own identifiers.
"""
import os
from binascii import crc32
from struct import pack, unpack
from uuid import UUID

GPT_HEADER_SIZE = 92
GPT_SIGNATURE = b"EFI PART"
GPT_REVISION = 0x00010000
DEFAULT_NUM_ENTRIES = 128
DEFAULT_ENTRY_SIZE = 128

# Microsoft "Basic data" partition type GUID -- what MTK uses for data
# partitions that don't have a more specific type.
BASIC_DATA_TYPE_GUID = UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")


def guid_to_bytes(value) -> bytes:
    """Accept a uuid.UUID, a GUID string, or raw 16 bytes; return 16 mixed-endian bytes."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value)
        if len(value) != 16:
            raise ValueError("GUID bytes must be 16 long")
        return value
    if isinstance(value, str):
        value = UUID(value)
    if isinstance(value, UUID):
        return value.bytes_le
    raise TypeError(f"Unsupported GUID type: {type(value)}")


class GptPartitionEntry:
    def __init__(self, name: str, first_lba: int, last_lba: int,
                 type_guid=BASIC_DATA_TYPE_GUID, unique_guid=None, flags: int = 0):
        self.name = name
        self.first_lba = first_lba
        self.last_lba = last_lba
        self.type_guid = guid_to_bytes(type_guid)
        if unique_guid is None:
            unique_guid = os.urandom(16)
        self.unique_guid = guid_to_bytes(unique_guid)
        self.flags = flags

    def pack(self) -> bytes:
        # 72 bytes = 36 UTF-16 code units; truncate by code unit (not byte, which
        # could split a surrogate pair) and leave a NUL terminator.
        name_utf16 = self.name[:35].encode("utf-16-le")
        name_utf16 = name_utf16.ljust(72, b"\x00")
        return pack("<16s16sQQQ72s", self.type_guid, self.unique_guid,
                    self.first_lba, self.last_lba, self.flags, name_utf16)


class GPTBuilder:
    def __init__(self, sectorsize: int = 512, num_part_entries: int = DEFAULT_NUM_ENTRIES,
                 part_entry_size: int = DEFAULT_ENTRY_SIZE, disk_guid=None):
        self.sectorsize = sectorsize
        self.num_part_entries = num_part_entries
        self.part_entry_size = part_entry_size
        self.disk_guid = guid_to_bytes(disk_guid) if disk_guid is not None else os.urandom(16)

    @property
    def entry_array_bytes(self) -> int:
        return self.num_part_entries * self.part_entry_size

    @property
    def entry_array_sectors(self) -> int:
        return (self.entry_array_bytes + self.sectorsize - 1) // self.sectorsize

    def first_usable_lba(self) -> int:
        # MBR(1) + header(1) + entry array
        return 2 + self.entry_array_sectors

    def last_usable_lba(self, total_sectors: int) -> int:
        # last sector holds the backup header; entry array sits just before it
        return total_sectors - 2 - self.entry_array_sectors

    def _pack_entries(self, entries) -> bytes:
        if len(entries) > self.num_part_entries:
            raise ValueError(f"{len(entries)} partitions exceed table capacity "
                             f"of {self.num_part_entries} entries")
        buf = bytearray()
        for e in entries:
            buf += e.pack()
        # zero-fill the remaining unused entry slots
        buf += b"\x00" * (self.entry_array_bytes - len(buf))
        return bytes(buf)

    def _pack_header(self, current_lba: int, backup_lba: int, first_usable: int,
                     last_usable: int, entry_start_lba: int, entries_crc: int) -> bytes:
        header = bytearray(pack(
            "<8sIIIIQQQQ16sQIII",
            GPT_SIGNATURE, GPT_REVISION, GPT_HEADER_SIZE,
            0,                      # header crc32 (filled in after)
            0,                      # reserved
            current_lba, backup_lba, first_usable, last_usable,
            self.disk_guid, entry_start_lba,
            self.num_part_entries, self.part_entry_size, entries_crc))
        assert len(header) == GPT_HEADER_SIZE
        header_crc = crc32(bytes(header)) & 0xFFFFFFFF
        header[16:20] = pack("<I", header_crc)
        return bytes(header)

    def build_protective_mbr(self, total_sectors: int) -> bytes:
        mbr = bytearray(self.sectorsize)
        size_in_lba = min(total_sectors - 1, 0xFFFFFFFF)
        entry = pack("<B3sB3sII",
                     0x00,                 # boot indicator
                     b"\x00\x02\x00",      # starting CHS
                     0xEE,                 # OS type: GPT protective
                     b"\xFF\xFF\xFF",      # ending CHS
                     1,                    # starting LBA
                     size_in_lba)
        mbr[446:446 + 16] = entry
        mbr[510] = 0x55
        mbr[511] = 0xAA
        return bytes(mbr)

    def build(self, entries, total_sectors: int, with_mbr: bool = True):
        """
        Return (primary_bytes, backup_bytes, backup_start_lba).

        primary_bytes: protective MBR (optional) + primary header + entry array,
                       meant to be written at LBA 0.
        backup_bytes:  backup entry array + backup header, meant to be written at
                       backup_start_lba.
        """
        first_usable = self.first_usable_lba()
        last_usable = self.last_usable_lba(total_sectors)

        for e in entries:
            if e.first_lba < first_usable:
                raise ValueError(f"Partition {e.name} starts at LBA {e.first_lba} "
                                 f"before first usable LBA {first_usable}")
            if e.last_lba > last_usable:
                raise ValueError(f"Partition {e.name} ends at LBA {e.last_lba} "
                                 f"past last usable LBA {last_usable} "
                                 f"(disk has {total_sectors} sectors)")
            if e.last_lba < e.first_lba:
                raise ValueError(f"Partition {e.name} has last_lba < first_lba")

        # Reject overlapping partitions -- a malformed scatter or a resize
        # miscalculation would otherwise produce a valid-CRC but corrupt table.
        for a, b in zip(sorted(entries, key=lambda e: e.first_lba),
                        sorted(entries, key=lambda e: e.first_lba)[1:]):
            if b.first_lba <= a.last_lba:
                raise ValueError(f"Partitions {a.name} (LBA {a.first_lba}-{a.last_lba}) "
                                 f"and {b.name} (LBA {b.first_lba}-{b.last_lba}) overlap")

        entry_array = self._pack_entries(entries)
        entries_crc = crc32(entry_array) & 0xFFFFFFFF

        primary_entry_lba = 2
        backup_entry_lba = total_sectors - 1 - self.entry_array_sectors
        primary_header_lba = 1
        backup_header_lba = total_sectors - 1

        primary_header = self._pack_header(
            current_lba=primary_header_lba, backup_lba=backup_header_lba,
            first_usable=first_usable, last_usable=last_usable,
            entry_start_lba=primary_entry_lba, entries_crc=entries_crc)
        backup_header = self._pack_header(
            current_lba=backup_header_lba, backup_lba=primary_header_lba,
            first_usable=first_usable, last_usable=last_usable,
            entry_start_lba=backup_entry_lba, entries_crc=entries_crc)

        # primary blob: [MBR][header (padded to sector)][entry array]
        primary = bytearray()
        if with_mbr:
            primary += self.build_protective_mbr(total_sectors)
        primary += primary_header.ljust(self.sectorsize, b"\x00")
        primary += entry_array
        # pad entry array up to a sector boundary
        if len(entry_array) % self.sectorsize:
            primary += b"\x00" * (self.sectorsize - (len(entry_array) % self.sectorsize))

        # backup blob: [entry array][backup header (padded)]
        backup = bytearray()
        backup += entry_array
        if len(entry_array) % self.sectorsize:
            backup += b"\x00" * (self.sectorsize - (len(entry_array) % self.sectorsize))
        backup += backup_header.ljust(self.sectorsize, b"\x00")

        return bytes(primary), bytes(backup), backup_entry_lba


def parse_existing_entries(data: bytes, sectorsize: int = 512):
    """
    Walk a raw primary-GPT image and return {name: (type16, unique16, flags)}.
    Used to preserve a device's existing type/unique GUIDs when repartitioning.
    Returns ({}, None) if no valid GPT header is found.
    """
    if len(data) < sectorsize * 2:
        return {}, None
    hdr = data[sectorsize:sectorsize + GPT_HEADER_SIZE]
    if hdr[0:8] != GPT_SIGNATURE:
        return {}, None
    (_, _, _, _, _, _cur, _bak, _fu, _lu, disk_guid, entry_start_lba,
     num_entries, entry_size, _ecrc) = unpack("<8sIIIIQQQQ16sQIII", hdr)
    start = entry_start_lba * sectorsize
    result = {}
    for idx in range(num_entries):
        off = start + idx * entry_size
        entry = data[off:off + entry_size]
        if len(entry) < 56:
            break
        type_guid = entry[0:16]
        if int.from_bytes(type_guid, "little") == 0:
            continue
        unique_guid = entry[16:32]
        # entry layout: type[0:16] unique[16:32] first_lba[32:40] last_lba[40:48]
        # flags[48:56] name[56:128]. Flags are at 48, NOT 40 (that's last_lba).
        flags = unpack("<Q", entry[48:56])[0]
        name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
        if name:
            result[name.lower()] = (type_guid, unique_guid, flags)
    return result, disk_guid


def parse_existing_layout(data: bytes, sectorsize: int = 512):
    """
    Walk a raw primary-GPT image and return {name.lower(): (first_lba, last_lba)}.
    Used to detect whether a rebuilt table would move/resize existing partitions
    (which would corrupt device-unique data). Returns {} if no valid GPT.
    """
    if len(data) < sectorsize * 2:
        return {}
    hdr = data[sectorsize:sectorsize + GPT_HEADER_SIZE]
    if hdr[0:8] != GPT_SIGNATURE:
        return {}
    (_, _, _, _, _, _cur, _bak, _fu, _lu, _guid, entry_start_lba,
     num_entries, entry_size, _ecrc) = unpack("<8sIIIIQQQQ16sQIII", hdr)
    start = entry_start_lba * sectorsize
    result = {}
    for idx in range(num_entries):
        off = start + idx * entry_size
        entry = data[off:off + entry_size]
        if len(entry) < 56:
            break
        if int.from_bytes(entry[0:16], "little") == 0:
            continue
        first_lba, last_lba = unpack("<QQ", entry[32:48])
        name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
        if name:
            result[name.lower()] = (first_lba, last_lba)
    return result
