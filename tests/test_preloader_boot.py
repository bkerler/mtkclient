#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""Tests for the EMMC_BOOT/BRLYT preloader wrapper (Library.preloader_boot)."""
import os
import unittest
from struct import unpack

from mtkclient.Library.preloader_boot import (
    wrap_preloader, build_boot_header, is_wrapped, HEADER_SIZE,
    DEFAULT_REGION_SIZE,
)


class BuildHeaderTest(unittest.TestCase):
    def setUp(self):
        self.hdr = build_boot_header()

    def test_size_and_magics(self):
        self.assertEqual(len(self.hdr), HEADER_SIZE)
        self.assertEqual(self.hdr[0:9], b"EMMC_BOOT")
        self.assertEqual(self.hdr[0x200:0x205], b"BRLYT")

    def test_fields(self):
        self.assertEqual(unpack("<I", self.hdr[0x0C:0x10])[0], 1)       # bl_exist
        self.assertEqual(unpack("<I", self.hdr[0x10:0x14])[0], 0x200)   # dev_rw_unit
        self.assertEqual(unpack("<I", self.hdr[0x208:0x20C])[0], 1)     # info_ver
        self.assertEqual(unpack("<I", self.hdr[0x20C:0x210])[0], 0x800)      # begin
        self.assertEqual(unpack("<I", self.hdr[0x210:0x214])[0], 0x40800)    # boundary
        self.assertEqual(self.hdr[0x214:0x218], b"BBBB")

    def test_padding_layout(self):
        # identifier region pads with 0xFF; the BRLYT block is mostly 0x00 with
        # an erased 0xFF island at 0x2b4..0x400 (matches the device's own layout)
        self.assertEqual(self.hdr[0x20:0x200], b"\xFF" * (0x200 - 0x20))
        self.assertEqual(self.hdr[0x228:0x2B4], b"\x00" * (0x2B4 - 0x228))
        self.assertEqual(self.hdr[0x2B4:0x400], b"\xFF" * (0x400 - 0x2B4))
        self.assertEqual(self.hdr[0x400:HEADER_SIZE], b"\x00" * (HEADER_SIZE - 0x400))


class WrapTest(unittest.TestCase):
    def test_wraps_bare_preloader(self):
        pre = b"MMM\x01" + b"\xAA" * 0x1000
        out = wrap_preloader(pre)
        self.assertTrue(is_wrapped(out))
        self.assertEqual(out[:HEADER_SIZE], build_boot_header())
        self.assertEqual(out[HEADER_SIZE:], pre)

    def test_already_wrapped_passthrough(self):
        pre = b"EMMC_BOOT\x00\x00\x00" + b"\x00" * 0x1000
        self.assertEqual(wrap_preloader(pre), pre)

    def test_oversized_raises(self):
        with self.assertRaises(ValueError):
            wrap_preloader(b"\x00" * (DEFAULT_REGION_SIZE + 1))

    def test_unverified_storage_refused(self):
        # UFS/NAND must not get a made-up header that could brick the device
        for storage in ("ufs", "nand", "nor"):
            with self.assertRaises(ValueError):
                wrap_preloader(b"MMM\x01" + b"\x00" * 0x100, storage=storage)

    def test_is_wrapped_recognises_other_magics(self):
        from mtkclient.Library.preloader_boot import is_wrapped
        self.assertTrue(is_wrapped(b"EMMC_BOOT\x00\x00\x00rest"))
        self.assertTrue(is_wrapped(b"UFS_BOOT\x00rest"))
        self.assertTrue(is_wrapped(b"COMBO_BOOT\x00rest"))
        self.assertFalse(is_wrapped(b"MMM\x01 not a boot header"))

    def test_descriptor_type_decode(self):
        # 0x00010005 = device_type EMMC(0x05) | reserved(0) | gfh_type ARM_BL(1)<<16
        hdr = build_boot_header("emmc")
        self.assertEqual(unpack("<I", hdr[0x218:0x21C])[0], 0x00010005)


class RealDumpTest(unittest.TestCase):
    """If a real boot1 dump is available, our header must match it exactly."""
    DUMP = os.path.expanduser("~/mtkclient/preloader.bin")

    def test_header_matches_real_boot1(self):
        if not os.path.exists(self.DUMP):
            self.skipTest("no real boot1 dump present")
        with open(self.DUMP, "rb") as rf:
            head = rf.read(HEADER_SIZE)
        if head[:9] != b"EMMC_BOOT":
            self.skipTest("dump is not an EMMC_BOOT image")
        # our synthesized header must be byte-identical to the device's own
        self.assertEqual(build_boot_header(), head)


if __name__ == "__main__":
    unittest.main()
