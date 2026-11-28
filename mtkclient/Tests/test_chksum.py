#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for the VerifyImageChksum / ChksumRule port (Library/chksum.py)
# and the DAXML write-path checksum hook (SPFT V6 imageChksumVerify).
# No device is touched: checksums are verified against independent known
# vectors, the hook against stub DAXML objects.
import os
import tempfile
import unittest

from mtkclient.Library.DA.xmlflash.xml_cmd import XMLCmd
from mtkclient.Library.chksum import (chksum_add, chksum_crc32, chksum_factory,
                                      ChksumRule, VerifyImageChksum)

CRC32_CHECK_VALUE = 0xCBF43926  # standard CRC-32 check value of b"123456789"


class TestChksumAlgorithms(unittest.TestCase):
    def test_crc32_known_vector(self):
        self.assertEqual(chksum_crc32.calc(b"123456789"), CRC32_CHECK_VALUE)

    def test_crc32_is_unsigned_32bit(self):
        self.assertEqual(chksum_crc32.calc(b"\xff" * 4096),
                         chksum_crc32.calc(b"\xff" * 4096) & 0xFFFFFFFF)

    def test_add_hand_computed_words(self):
        # words (little-endian 16-bit): 0x0201 + 0x0403 = 0x0604
        self.assertEqual(chksum_add.calc(b"\x01\x02\x03\x04"), 0x0604)

    def test_add_odd_length_is_zero_padded(self):
        self.assertEqual(chksum_add.calc(b"\x01"), 0x0001)
        self.assertEqual(chksum_add.calc(b"\x01\x02\x03"), 0x0201 + 0x0003)

    def test_add_wraps_at_32bit(self):
        # 65538 words of 0xffff: 65535*65538 = 0x1_0000FFFE -> truncated to 0xFFFE
        self.assertEqual(chksum_add.calc(b"\xff" * (2 * 65538)), 0xFFFE)

    def test_add_empty(self):
        self.assertEqual(chksum_add.calc(b""), 0)

    def test_factory(self):
        self.assertIsInstance(chksum_factory("CRC32"), chksum_crc32)
        self.assertIsInstance(chksum_factory("crc32"), chksum_crc32)
        self.assertIsInstance(chksum_factory("ADD"), chksum_add)
        self.assertIsInstance(chksum_factory("add"), chksum_add)
        with self.assertRaises(ValueError):
            chksum_factory("MD5")


def _write_checksum_ini(text):
    fd, path = tempfile.mkstemp(suffix=".ini")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


class TestChksumRule(unittest.TestCase):
    INI = """
# Checksum.ini produced by the firmware build (SPFT ChksumRule::IniChksumMap)
[images]
boot.img = 0x12345678
; another comment
system.img = 305419896
vendor.img=0xdeadbeef
"""

    def test_ini_chksum_map_parses_sections_and_comments(self):
        path = _write_checksum_ini(self.INI)
        try:
            rule = ChksumRule()
            count = rule.IniChksumMap(path)
            self.assertEqual(count, 3)
        finally:
            os.unlink(path)

    def test_query_by_image_name_is_case_insensitive(self):
        path = _write_checksum_ini(self.INI)
        try:
            rule = ChksumRule()
            rule.IniChksumMap(path)
            self.assertEqual(rule.QueryChksumByImageName("BOOT.IMG"), 0x12345678)
            self.assertEqual(rule.QueryChksumByImageName("boot.img"), 0x12345678)
            self.assertEqual(rule.QueryChksumByImageName("vendor.img"), 0xDEADBEEF)
        finally:
            os.unlink(path)

    def test_query_unknown_image_returns_none(self):
        path = _write_checksum_ini(self.INI)
        try:
            rule = ChksumRule()
            rule.IniChksumMap(path)
            self.assertIsNone(rule.QueryChksumByImageName("does_not_exist.img"))
        finally:
            os.unlink(path)

    def test_missing_checksum_file_is_not_fatal(self):
        rule = ChksumRule()
        self.assertEqual(rule.IniChksumMap("/nonexistent/Checksum.ini"), 0)
        self.assertIsNone(rule.QueryChksumByImageName("boot.img"))

    def test_default_chksum_type(self):
        self.assertEqual(ChksumRule().chksum_type, "CRC32")
        self.assertEqual(ChksumRule(chksum_type="ADD").chksum_type, "ADD")


class TestVerifyImageChksum(unittest.TestCase):
    DATA = b"123456789"

    def test_crc32_match(self):
        self.assertTrue(VerifyImageChksum("boot.img", self.DATA, CRC32_CHECK_VALUE))

    def test_crc32_mismatch(self):
        self.assertFalse(VerifyImageChksum("boot.img", self.DATA, 0x00000001))

    def test_add_type(self):
        expected = chksum_add.calc(self.DATA)
        self.assertTrue(VerifyImageChksum("boot.img", self.DATA, expected,
                                          chksum_type="ADD"))

    def test_empty_data_matches_zero_only_for_add(self):
        self.assertTrue(VerifyImageChksum("x.img", b"", chksum_add.calc(b""),
                                          chksum_type="ADD"))


class TestDaxmlWriteflashHook(unittest.TestCase):
    """
    The XML write path must consult the checksum rule before uploading
    (SPFT V6: "Begin verify load images checksum" / imageChksumVerify).
    """
    IMAGE_DATA = b"A" * 100

    def _make_daxml(self):
        from mtkclient.Library.DA.xmlflash.xml_lib import DAXML, FileSysOp, DwnFile

        daxml = DAXML.__new__(DAXML)  # skip __init__ (usb/hw deps)
        daxml.info = lambda *args, **kwargs: None
        daxml.debug = lambda *args, **kwargs: None
        daxml.warning = lambda *args, **kwargs: None
        daxml.error = lambda *args, **kwargs: None
        daxml.cmd = XMLCmd(None)
        daxml.chksum_rule = None

        class Storage:
            def get_storage(self, parttype, length):
                return "EMMC-USER", "user", length

        class Daconfig:
            storage = Storage()

        daxml.daconfig = Daconfig()

        sent = []
        acked = []
        uploads = []
        results = [(None, FileSysOp("FILE-SIZE", "unused")),
                   (None, DwnFile("CHK_NO", "WriteMemory", "unused", 0))]

        daxml.send_command = lambda xmldata, noack=False: sent.append(xmldata)
        daxml.get_command_result = lambda: results.pop(0)
        daxml.ack_value = lambda length: acked.append(length)
        daxml.upload = lambda result, data, display=True, raw=False: \
            (uploads.append(data), True)[1]
        return daxml, sent, uploads

    def _rule_with(self, value):
        rule = ChksumRule()
        rule.chksum_map["image.bin"] = value
        return rule

    def _image_file(self, data):
        """Write the load image under its rule name (hook keys on basename)."""
        tmpdir = tempfile.mkdtemp(prefix="mtk_chksum_")
        path = os.path.join(tmpdir, "image.bin")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_hook_inactive_without_rule(self):
        daxml, _, _ = self._make_daxml()
        self.assertTrue(daxml.verify_image_chksum("image.bin", self.IMAGE_DATA))

    def test_hook_skips_empty_filename(self):
        daxml, _, _ = self._make_daxml()
        daxml.chksum_rule = self._rule_with(0)
        self.assertTrue(daxml.verify_image_chksum("", self.IMAGE_DATA))

    def test_hook_skips_image_without_rule_entry(self):
        daxml, _, _ = self._make_daxml()
        daxml.chksum_rule = self._rule_with(0)
        # SPFT: "skip chksum for rom(%s)." - unknown images are not verified
        self.assertTrue(daxml.verify_image_chksum("other.img", self.IMAGE_DATA))

    def test_hook_detects_mismatch(self):
        daxml, _, _ = self._make_daxml()
        daxml.chksum_rule = self._rule_with(0x00000001)
        self.assertFalse(daxml.verify_image_chksum("image.bin", self.IMAGE_DATA))

    def test_writeflash_aborts_on_chksum_fail(self):
        daxml, sent, uploads = self._make_daxml()
        daxml.chksum_rule = self._rule_with(0x00000001)  # wrong on purpose
        path = self._image_file(self.IMAGE_DATA)
        try:
            result = daxml.writeflash(addr=0x1000, length=0x1000, filename=path,
                                      parttype="user")
        finally:
            os.unlink(path)
            os.rmdir(os.path.dirname(path))
        self.assertFalse(result)
        self.assertEqual(len(sent), 1)   # CMD:WRITE-FLASH was issued...
        self.assertEqual(uploads, [])    # ...but nothing was uploaded

    def test_writeflash_uploads_on_chksum_pass(self):
        daxml, sent, uploads = self._make_daxml()
        daxml.chksum_rule = self._rule_with(
            chksum_crc32.calc(self.IMAGE_DATA))
        path = self._image_file(self.IMAGE_DATA)
        try:
            result = daxml.writeflash(addr=0x1000, length=0x1000, filename=path,
                                      parttype="user")
        finally:
            os.unlink(path)
            os.rmdir(os.path.dirname(path))
        self.assertTrue(result)
        self.assertEqual(len(uploads), 1)
        # the upload payload is the raw image padded to the transport block
        self.assertTrue(uploads[0].startswith(self.IMAGE_DATA))
        self.assertEqual(len(uploads[0]) % 512, 0)


if __name__ == "__main__":
    unittest.main()
