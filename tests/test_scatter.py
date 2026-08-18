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
        # preloader's EMMC_BOOT1_BOOT2 region must map to "boot" (DA parttype 10,
        # which wraps it in a BRLYT boot header), NOT a raw "boot1" write.
        self.assertEqual(self.scatter.get("preloader").parttype, "boot")
        self.assertEqual(self.scatter.get("boot_a").parttype, "user")
        self.assertTrue(self.scatter.get("preloader").is_boot_region)
        self.assertTrue(self.scatter.get("boot_a").is_user_region)

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
