#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""Tests for the SP Flash Tool scatter parser (mtkclient.Library.scatter)."""
import os
import tempfile
import unittest

from mtkclient.Library.scatter import Scatter, ScatterPartition, REGION_TO_PARTTYPE

SCATTER_TEXT = """\
- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.2
      platform: MT6765
      project: k62v1_64_bsp
      storage: EMMC
      boot_channel: MSDC_0
      block_size: 0x20000

- partition_index: SYS0
  partition_name: preloader
  file_name: preloader_k62v1_64_bsp.bin
  is_download: true
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x40000
  region: EMMC_BOOT1_BOOT2
  storage: HW_STORAGE_EMMC
  operation_type: BOOTLOADERS

- partition_index: SYS1
  partition_name: pgpt
  file_name: NONE
  is_download: false
  type: NORMAL_ROM
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x8000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
  operation_type: INVISIBLE

- partition_index: SYS2
  partition_name: boot_a
  file_name: boot.img
  is_download: true
  type: NORMAL_ROM
  linear_start_addr: 0x8000
  physical_start_addr: 0x8000
  partition_size: 0x4000000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
  operation_type: UPDATE

- partition_index: SYS3
  partition_name: userdata
  file_name: userdata.img
  is_download: false
  type: NORMAL_ROM
  linear_start_addr: 0x4008000
  physical_start_addr: 0x4008000
  partition_size: 0xc0000000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
  operation_type: UPDATE
"""


class ScatterParserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.path = tempfile.mkstemp(suffix="_scatter.txt")
        with os.fdopen(fd, "w") as wf:
            wf.write(SCATTER_TEXT)
        cls.scatter = Scatter(cls.path)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.path)

    def test_general_header(self):
        self.assertEqual(self.scatter.platform, "MT6765")
        self.assertEqual(self.scatter.storage, "EMMC")
        self.assertEqual(self.scatter.project, "k62v1_64_bsp")
        self.assertEqual(self.scatter.block_size, 0x20000)

    def test_partition_count(self):
        # 4 partition records; the general header must not be counted
        self.assertEqual(len(self.scatter.partitions), 4)
        names = [p.name for p in self.scatter.partitions]
        self.assertEqual(names, ["preloader", "pgpt", "boot_a", "userdata"])

    def test_none_file_becomes_none(self):
        pgpt = self.scatter.get("pgpt")
        self.assertIsNone(pgpt.file_name)

    def test_real_file_kept(self):
        boot = self.scatter.get("boot_a")
        self.assertEqual(boot.file_name, "boot.img")

    def test_numeric_conversion(self):
        boot = self.scatter.get("boot_a")
        self.assertEqual(boot.linear_start_addr, 0x8000)
        self.assertEqual(boot.partition_size, 0x4000000)
        self.assertIsInstance(boot.linear_start_addr, int)

    def test_is_download_bool(self):
        self.assertTrue(self.scatter.get("boot_a").is_download)
        self.assertFalse(self.scatter.get("pgpt").is_download)
        self.assertIsInstance(self.scatter.get("boot_a").is_download, bool)

    def test_region_to_parttype(self):
        self.assertEqual(self.scatter.get("preloader").parttype, "boot1")
        self.assertEqual(self.scatter.get("boot_a").parttype, "user")
        self.assertTrue(self.scatter.get("preloader").is_boot_region)
        self.assertTrue(self.scatter.get("boot_a").is_user_region)

    def test_is_preloader(self):
        # the SV5_BL_BIN bootloader must be recognised so da_ws wraps it
        self.assertTrue(self.scatter.get("preloader").is_preloader)
        self.assertFalse(self.scatter.get("boot_a").is_preloader)

    def test_download_partitions_filter(self):
        # is_download AND has a real file. pgpt (no file) and userdata
        # (is_download false) must be excluded.
        dl = self.scatter.download_partitions()
        names = [p.name for p in dl]
        self.assertEqual(names, ["preloader", "boot_a"])

    def test_user_partitions_filter(self):
        # everything in EMMC_USER, regardless of download flag
        names = [p.name for p in self.scatter.user_partitions()]
        self.assertEqual(names, ["pgpt", "boot_a", "userdata"])

    def test_lba_helpers(self):
        boot = self.scatter.get("boot_a")
        self.assertEqual(boot.start_lba(512), 0x8000 // 512)
        self.assertEqual(boot.size_lba(512), 0x4000000 // 512)

    def test_size_lba_rounds_up(self):
        p = ScatterPartition({"partition_name": "x", "partition_size": 0x201,
                              "region": "EMMC_USER"})
        self.assertEqual(p.size_lba(512), 2)  # 0x201 bytes -> 2 sectors

    def test_region_map_completeness(self):
        # both boot regions and the user region must resolve
        for region in ("EMMC_BOOT1_BOOT2", "EMMC_USER", "EMMC_BOOT_2"):
            self.assertIn(region, REGION_TO_PARTTYPE)

    def test_region_names_match_spft_exactly(self):
        # exact strings SP Flash Tool serialises (verified vs FlashtoollibEx.dll):
        # underscore GP, RPMP typo, UFS preloader region.
        def pt(region):
            return ScatterPartition({"partition_name": "x", "region": region}).parttype
        self.assertEqual(pt("EMMC_GP_1"), "gp1")
        self.assertEqual(pt("EMMC_GP_4"), "gp4")
        self.assertEqual(pt("EMMC_RPMP"), "rpmb")
        self.assertEqual(pt("UFS_LU0_LU1"), "boot1")
        self.assertEqual(pt("UFS_LU0"), "user")
        # the wrong spellings must NOT be mapped (they'd fall back to user)
        self.assertNotIn("EMMC_GP1", REGION_TO_PARTTYPE)
        self.assertNotIn("EMMC_RPMB", REGION_TO_PARTTYPE)

    def test_comments_and_blank_lines_ignored(self):
        text = "# a comment\n\n" + SCATTER_TEXT
        fd, path = tempfile.mkstemp(suffix="_scatter.txt")
        with os.fdopen(fd, "w") as wf:
            wf.write(text)
        try:
            s = Scatter(path)
            self.assertEqual(len(s.partitions), 4)
        finally:
            os.remove(path)


class PseudoPartitionTest(unittest.TestCase):
    """Sentinel-addressed pseudo partitions must be excluded, but real
    high-address partitions on >4 GiB storage must not be."""

    def _part(self, name, addr, size=0x800000):
        return ScatterPartition({"partition_name": name, "linear_start_addr": addr,
                                 "partition_size": size, "region": "EMMC_USER"})

    def test_sentinel_is_pseudo(self):
        self.assertTrue(self._part("otp", 0xFFFF01D8).is_pseudo)
        self.assertTrue(self._part("flashinfo", 0xFFFF0080).is_pseudo)
        self.assertTrue(self._part("sgpt", 0xFFFF0000).is_pseudo)

    def test_high_address_not_pseudo(self):
        # userdata past the 4 GiB mark must remain a real partition
        self.assertFalse(self._part("userdata", 0x1BB400000, 0xC0000000).is_pseudo)
        self.assertFalse(self._part("vbmeta_b", 0x1B9C00000).is_pseudo)

    def test_boundary(self):
        self.assertTrue(self._part("x", 0xFFFFFFFF).is_pseudo)      # top of band
        self.assertFalse(self._part("x", 0x100000000).is_pseudo)    # just above band (4 GiB)
        self.assertFalse(self._part("x", 0xFFFEFFFF).is_pseudo)     # just below band

    def test_gpt_area_names_pseudo(self):
        self.assertTrue(self._part("pgpt", 0x0).is_pseudo)
        self.assertTrue(self._part("PGPT", 0x0).is_pseudo)  # case-insensitive


class OperationTypeTest(unittest.TestCase):
    def _part(self, name, op, addr=0x1000, size=0x1000):
        return ScatterPartition({"partition_name": name, "operation_type": op,
                                 "region": "EMMC_USER", "linear_start_addr": addr,
                                 "partition_size": size})

    def test_protected(self):
        self.assertTrue(self._part("nvcfg", "PROTECTED").is_protected)
        self.assertTrue(self._part("nvram", "BINREGION").is_protected)
        self.assertFalse(self._part("boot_a", "UPDATE").is_protected)

    def test_needs_resize(self):
        self.assertTrue(self._part("userdata", "NEEDRESIZE").needs_resize)
        self.assertFalse(self._part("boot_a", "UPDATE").needs_resize)

    def test_reserved(self):
        self.assertTrue(self._part("otp", "RESERVED").is_reserved)
        self.assertFalse(self._part("boot_a", "UPDATE").is_reserved)

    def test_is_reserved_flag(self):
        p = ScatterPartition({"partition_name": "x", "operation_type": "UPDATE",
                              "region": "EMMC_USER", "is_reserved": True})
        self.assertTrue(p.is_reserved)


class ProtectedAndResizeScatterTest(unittest.TestCase):
    """Uses the real P30 scatter if present to check attribute-driven filtering."""
    REAL = os.path.expanduser("~/Documents/P30/Firmware/MT6765_Android_scatter.txt")

    def setUp(self):
        if not os.path.exists(self.REAL):
            self.skipTest("real scatter not present")
        self.s = Scatter(self.REAL)

    def test_reserved_excluded_from_gpt(self):
        gpt_names = [p.name for p in self.s.gpt_partitions()]
        for reserved in ("otp", "flashinfo", "sgpt"):
            self.assertNotIn(reserved, gpt_names)

    def test_protected_partitions_detected(self):
        prot = {p.name for p in self.s.protected_partitions()}
        # nvcfg/protect1/protect2/proinfo are PROTECTED, nvram is BINREGION
        self.assertTrue({"nvcfg", "protect1", "protect2", "proinfo", "nvram"} <= prot)

    def test_userdata_needs_resize(self):
        self.assertTrue(self.s.get("userdata").needs_resize)

    def test_dynamic_partitions_are_otp_flashinfo(self):
        # otp/flashinfo are dynamically-addressed real entries; pgpt/sgpt are
        # GPT tables and must not appear as dynamic partitions.
        dyn = {p.name for p in self.s.dynamic_partitions()}
        self.assertEqual(dyn, {"otp", "flashinfo"})
        self.assertTrue(self.s.get("otp").is_dynamic)
        self.assertTrue(self.s.get("sgpt").is_gpt_area)
        self.assertFalse(self.s.get("sgpt").is_dynamic)


class ScatterValidationTest(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix="_scatter.txt")
        with os.fdopen(fd, "w") as wf:
            wf.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_empty_scatter_rejected(self):
        with self.assertRaises(ValueError):
            Scatter(self._write("# nothing here\n"))

    def test_v2_version_accepted(self):
        # SP Flash Tool emits V1.x and V2.0 YAML scatters; both must parse.
        text = SCATTER_TEXT.replace("config_version: V1.1.2", "config_version: V2.0")
        s = Scatter(self._write(text))
        self.assertEqual(len(s.partitions), 4)

    def test_v1_accepted(self):
        s = Scatter(self._write(SCATTER_TEXT))
        self.assertEqual(len(s.partitions), 4)

    def test_nand_storage_rejected(self):
        text = SCATTER_TEXT.replace("storage: EMMC", "storage: NAND")
        with self.assertRaises(ValueError):
            Scatter(self._write(text))


class RealScatterTest(unittest.TestCase):
    """Runs only if the P30 scatter is present; skipped otherwise."""
    REAL = os.path.expanduser("~/Documents/P30/Firmware/MT6765_Android_scatter.txt")

    def setUp(self):
        if not os.path.exists(self.REAL):
            self.skipTest("real scatter not present")

    def test_real_scatter(self):
        s = Scatter(self.REAL)
        self.assertEqual(s.platform, "MT6765")
        self.assertGreater(len(s.partitions), 40)
        # preloader must be the only boot-region download entry
        boot_dls = [p for p in s.download_partitions() if p.is_boot_region]
        self.assertEqual([p.name for p in boot_dls], ["preloader"])
        # every download entry with a user region must have a positive size
        for p in s.download_partitions():
            self.assertGreater(p.partition_size, 0, p.name)


if __name__ == "__main__":
    unittest.main()
