#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""Tests for the GPT builder (mtkclient.Library.gpt_builder).

The strongest check is a round-trip: build a table, then parse it back with
mtkclient's own gpt parser and confirm the partitions come out identical.
"""
import logging
import unittest
from binascii import crc32
from io import BytesIO
from struct import unpack
from uuid import UUID

from mtkclient.Library.gpt_builder import (
    GPTBuilder, GptPartitionEntry, parse_existing_entries, guid_to_bytes,
    BASIC_DATA_TYPE_GUID, GPT_SIGNATURE,
)
from mtkclient.Library.Partitions.gpt import gpt

SECTOR = 512
TOTAL_SECTORS = 0x200000  # 1 GiB disk in 512-byte sectors


def sample_entries():
    # first usable LBA for 128*128 entries at 512B/sector is 34
    return [
        GptPartitionEntry("boot_a", first_lba=64, last_lba=64 + 0x20000 - 1,
                          unique_guid=UUID("11111111-1111-1111-1111-111111111111")),
        GptPartitionEntry("system_a", first_lba=64 + 0x20000, last_lba=64 + 0x40000 - 1,
                          unique_guid=UUID("22222222-2222-2222-2222-222222222222")),
        GptPartitionEntry("userdata", first_lba=64 + 0x40000, last_lba=TOTAL_SECTORS - 34,
                          unique_guid=UUID("33333333-3333-3333-3333-333333333333")),
    ]


class GuidHelperTest(unittest.TestCase):
    def test_bytes_passthrough(self):
        b = bytes(range(16))
        self.assertEqual(guid_to_bytes(b), b)

    def test_string_and_uuid_equal(self):
        s = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
        self.assertEqual(guid_to_bytes(s), guid_to_bytes(UUID(s)))

    def test_mixed_endian(self):
        # bytes_le puts the first field little-endian: A2 A0 D0 EB ...
        self.assertEqual(guid_to_bytes(BASIC_DATA_TYPE_GUID)[:4], bytes.fromhex("a2a0d0eb"))

    def test_bad_length_raises(self):
        with self.assertRaises(ValueError):
            guid_to_bytes(b"\x00" * 15)

    def test_bytearray_and_memoryview_accepted(self):
        # readflash returns a bytearray, so parse_existing_entries hands GUID
        # slices back as bytearray/memoryview -- these must be accepted.
        raw = bytes(range(16))
        self.assertEqual(guid_to_bytes(bytearray(raw)), raw)
        self.assertEqual(guid_to_bytes(memoryview(raw)), raw)

    def test_entry_accepts_bytearray_guids(self):
        e = GptPartitionEntry("x", 64, 128,
                              type_guid=bytearray(range(16)),
                              unique_guid=bytearray(range(16, 32)))
        self.assertIsInstance(e.type_guid, bytes)
        self.assertIsInstance(e.unique_guid, bytes)


class GPTBuildTest(unittest.TestCase):
    def setUp(self):
        self.builder = GPTBuilder(sectorsize=SECTOR,
                                  disk_guid=UUID("deadbeef-0000-0000-0000-000000000000"))
        self.entries = sample_entries()
        self.primary, self.backup, self.backup_lba = self.builder.build(
            self.entries, TOTAL_SECTORS)

    # ---- protective MBR ----
    def test_protective_mbr(self):
        mbr = self.primary[:SECTOR]
        self.assertEqual(mbr[510], 0x55)
        self.assertEqual(mbr[511], 0xAA)
        self.assertEqual(mbr[446 + 4], 0xEE)  # OS type = GPT protective
        start_lba, size_lba = unpack("<II", mbr[446 + 8:446 + 16])
        self.assertEqual(start_lba, 1)
        self.assertEqual(size_lba, TOTAL_SECTORS - 1)

    # ---- primary header ----
    def test_primary_header_signature_and_crc(self):
        hdr = self.primary[SECTOR:SECTOR + 92]
        self.assertEqual(hdr[0:8], GPT_SIGNATURE)
        stored = unpack("<I", hdr[16:20])[0]
        recomputed = crc32(hdr[0:16] + b"\x00\x00\x00\x00" + hdr[20:92]) & 0xFFFFFFFF
        self.assertEqual(stored, recomputed)

    def test_entry_array_crc_matches_header(self):
        hdr = self.primary[SECTOR:SECTOR + 92]
        entries_crc = unpack("<I", hdr[88:92])[0]
        entry_array = self.primary[2 * SECTOR:2 * SECTOR + 128 * 128]
        self.assertEqual(entries_crc, crc32(entry_array) & 0xFFFFFFFF)

    def test_header_lbas(self):
        hdr = self.primary[SECTOR:SECTOR + 92]
        (_, _, _, _, _, cur, bak, fu, lu, _guid, entry_start,
         num, esize, _e) = unpack("<8sIIIIQQQQ16sQIII", hdr)
        self.assertEqual(cur, 1)
        self.assertEqual(bak, TOTAL_SECTORS - 1)
        self.assertEqual(entry_start, 2)
        self.assertEqual(num, 128)
        self.assertEqual(esize, 128)
        self.assertEqual(fu, 34)
        self.assertEqual(lu, TOTAL_SECTORS - 34)

    # ---- backup ----
    def test_backup_header_mirrors_primary(self):
        backup_header = self.backup[-SECTOR:][:92]
        self.assertEqual(backup_header[0:8], GPT_SIGNATURE)
        (_, _, _, _, _, cur, bak, _fu, _lu, _guid, entry_start,
         _num, _esize, _e) = unpack("<8sIIIIQQQQ16sQIII", backup_header)
        self.assertEqual(cur, TOTAL_SECTORS - 1)
        self.assertEqual(bak, 1)
        self.assertEqual(self.backup_lba, TOTAL_SECTORS - 1 - 32)
        self.assertEqual(entry_start, self.backup_lba)

    def test_primary_and_backup_entry_arrays_identical(self):
        primary_entries = self.primary[2 * SECTOR:2 * SECTOR + 128 * 128]
        backup_entries = self.backup[:128 * 128]
        self.assertEqual(primary_entries, backup_entries)

    # ---- round trip through mtkclient's own parser ----
    def test_roundtrip_parse(self):
        g = gpt(rf=BytesIO(self.primary), filesize=len(self.primary),
                loglevel=logging.ERROR)
        self.assertTrue(g.parse())
        parsed = {p.name: p for p in g.partentries}
        self.assertEqual(set(parsed), {"boot_a", "system_a", "userdata"})
        for e in self.entries:
            p = parsed[e.name]
            self.assertEqual(p.sector, e.first_lba)
            self.assertEqual(p.sectors, e.last_lba - e.first_lba + 1)

    def test_roundtrip_unique_guid_preserved(self):
        g = gpt(rf=BytesIO(self.primary), filesize=len(self.primary),
                loglevel=logging.ERROR)
        g.parse()
        parsed = {p.name: p for p in g.partentries}
        self.assertEqual(parsed["boot_a"].unique, "11111111-1111-1111-1111-111111111111")

    # ---- validation ----
    def test_too_many_partitions_raises(self):
        builder = GPTBuilder(sectorsize=SECTOR, num_part_entries=4)
        entries = [GptPartitionEntry(f"p{i}", 34 + i, 34 + i) for i in range(5)]
        with self.assertRaises(ValueError):
            builder.build(entries, TOTAL_SECTORS)

    def test_partition_past_disk_raises(self):
        entries = [GptPartitionEntry("toobig", 64, TOTAL_SECTORS + 100)]
        with self.assertRaises(ValueError):
            self.builder.build(entries, TOTAL_SECTORS)

    def test_partition_before_first_usable_raises(self):
        entries = [GptPartitionEntry("early", 5, 100)]
        with self.assertRaises(ValueError):
            self.builder.build(entries, TOTAL_SECTORS)

    def test_last_before_first_raises(self):
        entries = [GptPartitionEntry("rev", 100, 50)]
        with self.assertRaises(ValueError):
            self.builder.build(entries, TOTAL_SECTORS)


class ParseExistingEntriesTest(unittest.TestCase):
    def test_roundtrip_preserves_type_and_unique(self):
        builder = GPTBuilder(sectorsize=SECTOR)
        entries = sample_entries()
        primary, _backup, _lba = builder.build(entries, TOTAL_SECTORS)
        found, disk_guid = parse_existing_entries(primary, SECTOR)
        self.assertEqual(set(found), {"boot_a", "system_a", "userdata"})
        type_guid, unique_guid, flags = found["boot_a"]
        self.assertEqual(type_guid, guid_to_bytes(BASIC_DATA_TYPE_GUID))
        self.assertEqual(unique_guid, guid_to_bytes(
            UUID("11111111-1111-1111-1111-111111111111")))
        self.assertEqual(disk_guid, builder.disk_guid)

    def test_no_gpt_returns_empty(self):
        found, disk_guid = parse_existing_entries(b"\x00" * (SECTOR * 4), SECTOR)
        self.assertEqual(found, {})
        self.assertIsNone(disk_guid)

    def test_short_buffer_returns_empty(self):
        found, disk_guid = parse_existing_entries(b"\x00" * 10, SECTOR)
        self.assertEqual(found, {})


if __name__ == "__main__":
    unittest.main()
