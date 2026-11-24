#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for the imageChecker port (Library/imagecheck.py): validation of
# the load images against the scatter layout before flashing. Verified against
# the real MT6785 begonia scatter fixture (boot: 0x2E980000, 0x4000000 bytes).
# No device is touched.
import os
import tempfile
import unittest

from mtkclient.Library.Scatter.scatter import parse_scatter
from mtkclient.Library.chksum import chksum_crc32, ChksumRule
from mtkclient.Library.imagecheck import (ImageChecker, ImageCheckStatus,
                                          images_checker_verify)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
BEGONIA_SCATTER = os.path.join(FIXTURES, "MT6785_begonia_scatter.txt")
BOOT_SIZE = 0x4000000  # begonia boot partition


class TestImageChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scatter = parse_scatter(BEGONIA_SCATTER)
        cls.partitions = cls.scatter.get_storage("EMMC").partitions
        cls.tmpdir = tempfile.mkdtemp(prefix="mtk_imgchk_")

    @classmethod
    def tearDownClass(cls):
        for name in os.listdir(cls.tmpdir):
            os.unlink(os.path.join(cls.tmpdir, name))
        os.rmdir(cls.tmpdir)

    def _image(self, name, size, fill=b"A"):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as f:
            f.write(fill * size)
        return path

    def _checker(self, images, rule=None, partitions=None):
        return ImageChecker(partitions or self.partitions, images,
                            chksum_rule=rule)

    def test_image_fits_partition_passes(self):
        img = self._image("boot.img", 1024)
        items = self._checker({"boot": img}).verify_images()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].status, ImageCheckStatus.PASS)
        self.assertEqual(items[0].partition, "boot")

    def test_image_bigger_than_partition_fails(self):
        img = self._image("boot_big.img", BOOT_SIZE + 1)
        items = self._checker({"boot": img}).verify_images()
        self.assertEqual(items[0].status, ImageCheckStatus.FAIL)
        self.assertIn("fit", items[0].detail)

    def test_unknown_partition_fails_with_pmt_message(self):
        # SPFT CDefaultRom::CheckPmtLayout: "PMT no <%s>!"
        img = self._image("x.img", 16)
        items = self._checker({"no_such_partition": img}).verify_images()
        self.assertEqual(items[0].status, ImageCheckStatus.FAIL)
        self.assertIn("no_such_partition", items[0].detail)

    def test_missing_image_file_fails(self):
        items = self._checker({"boot": os.path.join(self.tmpdir, "gone.img")}).verify_images()
        self.assertEqual(items[0].status, ImageCheckStatus.FAIL)
        self.assertIn("gone.img", items[0].detail)

    def test_empty_image_file_fails(self):
        img = self._image("empty.img", 0)
        items = self._checker({"boot": img}).verify_images()
        self.assertEqual(items[0].status, ImageCheckStatus.FAIL)
        self.assertIn("empty", items[0].detail)

    def test_plain_dict_partitions_are_supported(self):
        # GPT-style duck-typed entries: name + size instead of scatter fields
        partitions = [{"name": "boot", "size": 0x1000},
                      {"name": "system", "size": 0x2000}]
        img = self._image("boot_d.img", 0x800)
        items = self._checker({"boot": img}, partitions=partitions).verify_images()
        self.assertEqual(items[0].status, ImageCheckStatus.PASS)

    def test_every_requested_image_is_checked(self):
        boot = self._image("b.img", 512)
        system = self._image("s.img", 512)
        misc = self._image("m.img", 512)
        items = self._checker({"boot": boot, "system": system,
                               "misc": misc}).verify_images()
        self.assertEqual({i.partition for i in items}, {"boot", "system", "misc"})
        by_partition = {i.partition: i.status for i in items}
        # the real begonia scatter marks misc as is_download: FALSE
        self.assertEqual(by_partition["boot"], ImageCheckStatus.PASS)
        self.assertEqual(by_partition["system"], ImageCheckStatus.PASS)
        self.assertEqual(by_partition["misc"], ImageCheckStatus.SKIP)


class TestImageCheckerChksum(unittest.TestCase):
    """Optional checksum layer (SPFT imageChksumVerify over ChksumRule)."""
    @classmethod
    def setUpClass(cls):
        cls.scatter = parse_scatter(BEGONIA_SCATTER)
        cls.partitions = cls.scatter.get_storage("EMMC").partitions
        cls.tmpdir = tempfile.mkdtemp(prefix="mtk_imgchk2_")

    @classmethod
    def tearDownClass(cls):
        for name in os.listdir(cls.tmpdir):
            os.unlink(os.path.join(cls.tmpdir, name))
        os.rmdir(cls.tmpdir)

    def _image(self, name, size, fill=b"A"):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as f:
            f.write(fill * size)
        return path

    def test_rule_match_passes(self):
        img = self._image("boot_ok.img", 512)
        rule = ChksumRule()
        rule.chksum_map["boot_ok.img"] = chksum_crc32.calc(b"A" * 512)
        items = ImageChecker(self.partitions, {"boot": img},
                             chksum_rule=rule).verify_images()
        self.assertEqual(items[0].status, ImageCheckStatus.PASS)
        self.assertIn("checksum", items[0].detail.lower())

    def test_rule_mismatch_fails(self):
        img = self._image("boot_bad.img", 512)
        rule = ChksumRule()
        rule.chksum_map["boot_bad.img"] = 0x00000001
        items = ImageChecker(self.partitions, {"boot": img},
                             chksum_rule=rule).verify_images()
        self.assertEqual(items[0].status, ImageCheckStatus.FAIL)
        self.assertIn("mismatch", items[0].detail.lower())

    def test_image_without_rule_entry_is_skipped(self):
        # SPFT: "skip chksum for rom(%s)." - no rule entry, no verification
        img = self._image("unmapped.img", 512)
        rule = ChksumRule()
        rule.chksum_map["other.img"] = 0x1
        items = ImageChecker(self.partitions, {"boot": img},
                             chksum_rule=rule).verify_images()
        self.assertEqual(items[0].status, ImageCheckStatus.SKIP)
        self.assertIn("skip", items[0].detail.lower())


class TestVerifyEntryPoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scatter = parse_scatter(BEGONIA_SCATTER)
        cls.partitions = cls.scatter.get_storage("EMMC").partitions
        cls.tmpdir = tempfile.mkdtemp(prefix="mtk_imgchk3_")

    @classmethod
    def tearDownClass(cls):
        for name in os.listdir(cls.tmpdir):
            os.unlink(os.path.join(cls.tmpdir, name))
        os.rmdir(cls.tmpdir)

    def test_images_checker_verify_true_on_pass(self):
        path = os.path.join(self.tmpdir, "ok.img")
        with open(path, "wb") as f:
            f.write(b"A" * 512)
        self.assertTrue(images_checker_verify(self.partitions, {"boot": path}))

    def test_images_checker_verify_false_on_fail(self):
        path = os.path.join(self.tmpdir, "bad.img")
        with open(path, "wb") as f:
            f.write(b"A" * (BOOT_SIZE + 1))
        self.assertFalse(images_checker_verify(self.partitions, {"boot": path}))

    def test_empty_image_set_is_a_pass(self):
        self.assertTrue(images_checker_verify(self.partitions, {}))


if __name__ == "__main__":
    unittest.main()
