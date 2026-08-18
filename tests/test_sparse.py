#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""Tests for the Android sparse-image expander (Library.sparse)."""
import os
import tempfile
import unittest
from struct import pack

from mtkclient.Library.sparse import (
    SparseImage, is_sparse, is_sparse_file, SPARSE_MAGIC,
    CHUNK_RAW, CHUNK_FILL, CHUNK_DONT_CARE, CHUNK_CRC32,
)

BLK = 4  # tiny block size for the test


def sparse_header(total_blks, total_chunks, blk=BLK):
    return pack("<IHHHHIIII", SPARSE_MAGIC, 1, 0, 28, 12, blk,
                total_blks, total_chunks, 0)


def chunk(ctype, chunk_blks, body=b""):
    return pack("<HHII", ctype, 0, chunk_blks, 12 + len(body)) + body


def write_sparse(chunks, total_blks):
    data = sparse_header(total_blks, len(chunks))
    for c in chunks:
        data += c
    fd, path = tempfile.mkstemp(suffix=".img")
    with os.fdopen(fd, "wb") as wf:
        wf.write(data)
    return path


class SparseDetectTest(unittest.TestCase):
    def test_is_sparse(self):
        self.assertTrue(is_sparse(pack("<I", SPARSE_MAGIC) + b"rest"))
        self.assertFalse(is_sparse(b"ANDR..."))
        self.assertFalse(is_sparse(b"\x00"))


class SparseExpandTest(unittest.TestCase):
    def setUp(self):
        # RAW "AAAA", FILL 'B', DONT_CARE, RAW "ZZZZ"  -> 4 blocks of 4 bytes
        self.path = write_sparse([
            chunk(CHUNK_RAW, 1, b"AAAA"),
            chunk(CHUNK_FILL, 1, b"BBBB"),        # fill value 0x42424242
            chunk(CHUNK_DONT_CARE, 1),
            chunk(CHUNK_RAW, 1, b"ZZZZ"),
        ], total_blks=4)
        self.addCleanup(os.remove, self.path)

    def test_detect_file(self):
        self.assertTrue(is_sparse_file(self.path))

    def test_expanded_size(self):
        with SparseImage(self.path) as img:
            self.assertEqual(img.expanded_size, 4 * BLK)

    def test_regions_skip_dont_care(self):
        with SparseImage(self.path) as img:
            regions = list(img.regions())
        # DONT_CARE (offset 8) is a hole -> not yielded
        self.assertEqual(regions, [(0, b"AAAA"), (4, b"BBBB"), (12, b"ZZZZ")])

    def test_reconstruct_full_image(self):
        # rebuild the raw image from regions; holes stay zero
        with SparseImage(self.path) as img:
            out = bytearray(img.expanded_size)
            for off, data in img.regions():
                out[off:off + len(data)] = data
        self.assertEqual(bytes(out), b"AAAA" + b"BBBB" + b"\x00\x00\x00\x00" + b"ZZZZ")


class SparseFillZeroIsHoleTest(unittest.TestCase):
    def test_zero_fill_skipped(self):
        path = write_sparse([
            chunk(CHUNK_RAW, 1, b"DATA"),
            chunk(CHUNK_FILL, 1, b"\x00\x00\x00\x00"),  # zero fill == hole
        ], total_blks=2)
        self.addCleanup(os.remove, path)
        with SparseImage(path) as img:
            self.assertEqual(list(img.regions()), [(0, b"DATA")])


class SparseCrcChunkTest(unittest.TestCase):
    def test_crc_chunk_consumed(self):
        path = write_sparse([
            chunk(CHUNK_RAW, 1, b"DATA"),
            chunk(CHUNK_CRC32, 0, b"\x01\x02\x03\x04"),
        ], total_blks=1)
        self.addCleanup(os.remove, path)
        with SparseImage(path) as img:
            self.assertEqual(list(img.regions()), [(0, b"DATA")])


class RealFirmwareSparseTest(unittest.TestCase):
    """Confirms the real super/userdata images are sparse (the bug's premise)."""
    FW = os.path.expanduser("~/Documents/P30/Firmware")

    def test_super_and_userdata_are_sparse(self):
        for name in ("super.img", "userdata.img"):
            p = os.path.join(self.FW, name)
            if not os.path.exists(p):
                self.skipTest("firmware not present")
            self.assertTrue(is_sparse_file(p), f"{name} should be sparse")
            with SparseImage(p) as img:
                self.assertGreater(img.expanded_size, os.path.getsize(p))


if __name__ == "__main__":
    unittest.main()
