#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for the GenAutoFormatRange port (mtkclient/Library/Scatter/autofmt.py).
# Ranges are verified against hand-computed values from the real MT6785 begonia
# scatter (preloader 0x0+0x80000 boot region, pgpt 0x0+0x8000, userdata end
# 0x4D2800000, sgpt/flashinfo RESERVED) and synthetic NAND/NOR layouts.
import os
import unittest

from mtkclient.Library.Scatter.scatter import parse_scatter
from mtkclient.Library.Scatter.autofmt import (AutoFormatArg, AutoFormatFlag,
                                               AutoFormatArgFactory, EMMCFormatArg,
                                               UFSFormatArg, NANDFormatArg, NORFormatArg,
                                               SDMMCAutoFormatArg, DEFAULT_BMT_BLOCKS)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
BEGONIA_SCATTER = os.path.join(FIXTURES, "MT6785_begonia_scatter.txt")

# hand-computed from the begonia scatter:
#   preloader: 0x0..0x80000 region EMMC_BOOT1_BOOT2 / UFS_LU0_LU1 (bootloader)
#   userdata:  0x1D2800000..0x4D2800000 (largest non-bootloader end)
BEGONIA_USER_END = 0x4D2800000
# Full device capacity as SPFT queries it from the eMMC (32GiB).  It MUST sit
# above the 19.3GiB user-area end: a smaller flashsize (e.g. 16GiB) clamps the
# except-bootloader range and eats the tail of userdata.
FLASHSIZE_32GB = 0x800000000


class TestQueryPartLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scatter = parse_scatter(BEGONIA_SCATTER)
        cls.arg = AutoFormatArg.from_scatter(cls.scatter, "EMMC")

    def test_known_partition(self):
        addr, size = self.arg.QueryPartLayout("recovery")
        self.assertEqual(addr, 0x8000)
        self.assertEqual(size, 0x4000000)

    def test_case_insensitive(self):
        addr, size = self.arg.QueryPartLayout("USERDATA")
        self.assertEqual(addr, 0x1D2800000)
        self.assertEqual(size, 0x300000000)

    def test_unknown_partition_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self.arg.QueryPartLayout("does_not_exist")
        self.assertIn("not found", str(ctx.exception))


class TestGenAutoFormatRangeEMMC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scatter = parse_scatter(BEGONIA_SCATTER)
        cls.arg = EMMCFormatArg.from_scatter(cls.scatter, "EMMC",
                                             flashsize=FLASHSIZE_32GB)

    def test_whole_flash(self):
        start, length = self.arg.GenAutoFormatRange(AutoFormatFlag.WHOLE_FLASH)
        self.assertEqual(start, 0)
        self.assertEqual(length, FLASHSIZE_32GB)  # clamped to flashsize

    def test_whole_flash_except_bootloader(self):
        # bootloader (preloader) is in EMMC_BOOT1_BOOT2, outside the linear user
        # map, so the user area starts at pgpt 0x0 and ends at userdata end
        start, length = self.arg.GenAutoFormatRange(
            AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER)
        self.assertEqual(start, 0)
        self.assertEqual(length, BEGONIA_USER_END)

    def test_auto_format_flag(self):
        start, length = self.arg.GenAutoFormatRange(AutoFormatFlag.AUTO_FORMAT)
        self.assertEqual((start, length), (0, BEGONIA_USER_END))

    def test_single_partition_flag(self):
        start, length = self.arg.GenAutoFormatRange(AutoFormatFlag.PARTITION,
                                                    partitionname="boot")
        self.assertEqual(start, 0x2E980000)
        self.assertEqual(length, 0x4000000)

    def test_partitionname_wins_over_flag(self):
        start, length = self.arg.GenAutoFormatRange(AutoFormatFlag.WHOLE_FLASH,
                                                    partitionname="misc")
        self.assertEqual(start, 0x4008000)
        self.assertEqual(length, 0x400000)

    def test_block_size_from_scatter(self):
        self.assertEqual(self.arg.block_size, 0x20000)


class TestGenAutoFormatRangeUFS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scatter = parse_scatter(BEGONIA_SCATTER)
        cls.arg = UFSFormatArg.from_scatter(cls.scatter, "UFS",
                                            flashsize=FLASHSIZE_32GB)

    def test_ufs_bootloader_in_lu0_lu1(self):
        # preloader region is UFS_LU0_LU1 -> excluded from the user map
        start, length = self.arg.GenAutoFormatRange(
            AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER)
        self.assertEqual(start, 0)
        self.assertEqual(length, BEGONIA_USER_END)

    def test_ufs_block_size(self):
        self.assertEqual(self.arg.block_size, 0x80000)
        self.assertEqual(self.arg.storage_type, "UFS")


class TestNandNor(unittest.TestCase):
    def _nand_layout(self):
        class P:
            def __init__(self, name, addr, size, op=None):
                self.partition_name = name
                self.linear_start_addr = addr
                self.partition_size = size
                self.operation_type = op or (
                    "BOOTLOADERS" if name == "preloader" else "UPDATE")
                self.region = "NAND"
        return [P("preloader", 0x0, 0x80000),
                P("recovery", 0x80000, 0x4000000),
                P("userdata", 0x4080000, 0x1000000)]

    def test_nand_bmt_protection(self):
        # flashsize 0x2000000, bmt 80 * block 0x20000 = 0xA00000 protected
        arg = NANDFormatArg(partitions=self._nand_layout(), flashsize=0x2000000,
                            block_size=0x20000, bmt_blocks=80)
        start, length = arg.GenAutoFormatRange(AutoFormatFlag.WHOLE_FLASH)
        self.assertEqual(start, 0)
        self.assertEqual(length, 0x2000000 - 80 * 0x20000)

    def test_nand_except_bootloader_starts_after_preloader(self):
        arg = NANDFormatArg(partitions=self._nand_layout(), flashsize=0x2000000,
                            block_size=0x20000, bmt_blocks=80)
        start, length = arg.GenAutoFormatRange(
            AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER)
        self.assertEqual(start, 0x80000)  # end of preloader
        self.assertEqual(length, 0x2000000 - 80 * 0x20000 - 0x80000)

    def test_nand_default_bmt_from_platform_xml(self):
        arg = NANDFormatArg()
        self.assertEqual(arg.bmt_blocks, DEFAULT_BMT_BLOCKS)
        self.assertEqual(DEFAULT_BMT_BLOCKS, 80)

    def test_nor_except_bootloader(self):
        class P:
            def __init__(self, name, addr, size):
                self.partition_name = name
                self.linear_start_addr = addr
                self.partition_size = size
                # only the bootloader image is a bootloader - the OS partitions
                # are regular UPDATE entries
                self.operation_type = ("BOOTLOADERS" if name == "bootloader"
                                       else "UPDATE")
        layout = [P("bootloader", 0x0, 0x20000), P("linux", 0x20000, 0x100000)]
        arg = NORFormatArg(partitions=layout, flashsize=0x400000, block_size=0x1000)
        start, length = arg.GenAutoFormatRange(
            AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER)
        # layout covers 0x0..0x120000; bootloader 0x0..0x20000 is skipped
        self.assertEqual(start, 0x20000)
        self.assertEqual(length, 0x120000 - 0x20000)

    def test_nor_whole_flash(self):
        arg = NORFormatArg(flashsize=0x400000)
        start, length = arg.GenAutoFormatRange(AutoFormatFlag.WHOLE_FLASH)
        self.assertEqual((start, length), (0, 0x400000))


class TestFactory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scatter = parse_scatter(BEGONIA_SCATTER)

    def test_create_all_types(self):
        for flashtype, klass in (("EMMC", EMMCFormatArg), ("emmc", EMMCFormatArg),
                                 ("SDMMC", SDMMCAutoFormatArg), ("UFS", UFSFormatArg),
                                 ("NAND", NANDFormatArg), ("NOR", NORFormatArg)):
            arg = AutoFormatArgFactory.create(flashtype, flashsize=0x1000)
            self.assertIsInstance(arg, klass)

    def test_factory_unknown_type(self):
        with self.assertRaises(ValueError):
            AutoFormatArgFactory.create("OPTANE")

    def test_factory_from_scatter_emmc(self):
        arg = AutoFormatArgFactory.create("EMMC")
        arg.partitions = self.scatter.get_storage("EMMC").partitions
        arg.block_size = self.scatter.get_storage("EMMC").block_size
        start, length = arg.GenAutoFormatRange(
            AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER)
        self.assertEqual((start, length), (0, BEGONIA_USER_END))


class TestFormatflashIntegration(unittest.TestCase):
    def test_to_formatflash_args_partition(self):
        scatter = parse_scatter(BEGONIA_SCATTER)
        arg = AutoFormatArg.from_scatter(scatter, "EMMC", flashsize=FLASHSIZE_32GB)
        addr, length, partitionname, parttype = arg.to_formatflash_args(
            AutoFormatFlag.PARTITION, partitionname="seccfg")
        self.assertEqual(addr, 0x13800000)
        self.assertEqual(length, 0x800000)
        self.assertEqual(partitionname, "seccfg")
        self.assertEqual(parttype, "user")

    def test_to_formatflash_args_whole(self):
        scatter = parse_scatter(BEGONIA_SCATTER)
        arg = AutoFormatArg.from_scatter(scatter, "EMMC", flashsize=FLASHSIZE_32GB)
        addr, length, partitionname, parttype = arg.to_formatflash_args(
            AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER)
        self.assertEqual(addr, 0)
        self.assertEqual(length, BEGONIA_USER_END)
        self.assertEqual(partitionname, "")
        self.assertEqual(parttype, "user")

    def test_daloader_formatflash_signature_unchanged(self):
        # the range must feed the existing formatflash(addr, length, partitionname, parttype)
        import inspect
        from mtkclient.Library.DA.mtk_daloader import DAloader
        params = list(inspect.signature(DAloader.formatflash).parameters)
        self.assertEqual(params, ["self", "addr", "length", "partitionname", "parttype",
                                  "display"])


if __name__ == "__main__":
    unittest.main()
