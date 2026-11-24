#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for the SPFT scatter parser port (mtkclient/Library/Scatter/scatter.py).
# Reference fixtures: real MT6785 (begonia) text scatter + xml scatter samples built
# from the field names confirmed in SPFT FlashtoollibEx/FlashToolLib.v1 strings.
import os
import unittest

from mtkclient.Library.Scatter.scatter import (ScatterError, ScatterChipMismatch,
                                               parse_scatter, parse_scatter_text,
                                               parse_scatter_xml, parse_scatter_checksum)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
BEGONIA_SCATTER = os.path.join(FIXTURES, "MT6785_begonia_scatter.txt")

XML_V8 = """<?xml version="1.0" encoding="utf-8"?>
<rom_info version="V8">
 <general>
  <config_version name="V8">
    <platform>MT6785</platform><project>begonia</project>
    <check_bootloaders_consistency>TRUE</check_bootloaders_consistency>
    <skip_pmt_operate>FALSE</skip_pmt_operate>
    <modem_check>TRUE</modem_check><modem>MD1</modem><resize_check>FALSE</resize_check>
  </config_version>
  <storage name="EMMC"><boot_channel>MSDC_0</boot_channel><block_size>0x20000</block_size></storage>
 </general>
 <partition>
  <partition_index>SYS0</partition_index><partition_name>preloader</partition_name>
  <file_name>preloader_begonia.bin</file_name><is_download>true</is_download>
  <type>SV5_BL_BIN</type><linear_start_addr>0x0</linear_start_addr>
  <physical_start_addr>0x0</physical_start_addr><partition_size>0x80000</partition_size>
  <region>EMMC_BOOT1_BOOT2</region><storage>HW_STORAGE_EMMC</storage>
  <boundary_check>true</boundary_check><is_reserved>false</is_reserved>
  <operation_type>BOOTLOADERS</operation_type><is_upgradable>true</is_upgradable>
  <empty_boot_needed>false</empty_boot_needed><reserve>0x00</reserve>
 </partition>
 <partition>
  <partition_index>SYS1</partition_index><partition_name>recovery</partition_name>
  <file_name>recovery.img</file_name><is_download>true</is_download>
  <type>NORMAL_ROM</type><linear_start_addr>0x8000</linear_start_addr>
  <physical_start_addr>0x8000</physical_start_addr><partition_size>0x4000000</partition_size>
  <region>EMMC_USER</region><storage>HW_STORAGE_EMMC</storage>
  <boundary_check>true</boundary_check><is_reserved>false</is_reserved>
  <operation_type>UPDATE</operation_type><is_upgradable>true</is_upgradable>
  <empty_boot_needed>false</empty_boot_needed><reserve>0x00</reserve>
 </partition>
</rom_info>
"""

XML_V4 = """<?xml version="1.0" encoding="utf-8"?>
<rom_info version="V4">
 <general>
  <config_version name="V4">
    <platform>MT6785</platform><project>begonia</project>
  </config_version>
  <storage name="EMMC"><boot_channel>MSDC_0</boot_channel><block_size>0x20000</block_size></storage>
 </general>
 <partition>
  <partition_index>SYS0</partition_index><partition_name>preloader</partition_name>
  <file_name>preloader_begonia.bin</file_name><is_download>true</is_download>
  <type>SV5_BL_BIN</type><linear_start_addr>0x0</linear_start_addr>
  <physical_start_addr>0x0</physical_start_addr><partition_size>0x80000</partition_size>
  <region>EMMC_BOOT1_BOOT2</region><storage>HW_STORAGE_EMMC</storage>
  <boundary_check>true</boundary_check><is_reserved>false</is_reserved>
  <operation_type>BOOTLOADERS</operation_type><is_upgradable>true</is_upgradable>
  <empty_boot_needed>false</empty_boot_needed><reserve>0x00</reserve>
 </partition>
</rom_info>
"""

XML_V11 = XML_V8.replace('version="V8"', 'version="V11"').replace('name="V8"', 'name="V11"') \
    .replace("<modem>MD1</modem>", "<modem>MD1</modem><chip_version>S00</chip_version>")

SCATTER_CHECKSUM = """<?xml version="1.0" encoding="utf-8"?>
<scatter version="1.0">
  <images_sha256>
    <file name="preloader_begonia.bin" checksum="AABBCCDD00112233"/>
    <file name="recovery.img" checksum="deadbeefcafebabe"/>
  </images_sha256>
</scatter>
"""


class TestTextScatter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.info = parse_scatter(BEGONIA_SCATTER)

    def test_general_settings(self):
        self.assertEqual(self.info.platform, "MT6785")
        self.assertEqual(self.info.project, "begonia")

    def test_storage_sections(self):
        # the begonia scatter carries both layouts: EMMC + UFS
        self.assertEqual(len(self.info.storages), 2)
        emmc = self.info.get_storage("EMMC")
        ufs = self.info.get_storage("UFS")
        self.assertIsNotNone(emmc)
        self.assertIsNotNone(ufs)
        self.assertEqual(emmc.boot_channel, "MSDC_0")
        self.assertEqual(emmc.block_size, 0x20000)
        self.assertEqual(ufs.boot_channel, "UFSHCI_0")
        self.assertEqual(ufs.block_size, 0x80000)
        self.assertEqual(len(emmc.partitions), 50)
        self.assertEqual(len(ufs.partitions), 50)
        self.assertEqual(len(self.info.partitions), 100)

    def test_partition_fields(self):
        rec = self.info.by_name("recovery")[0]
        self.assertEqual(rec.partition_index, "SYS2")
        self.assertEqual(rec.file_name, "recovery.img")
        self.assertTrue(rec.is_download)
        self.assertEqual(rec.type, "NORMAL_ROM")
        self.assertEqual(rec.linear_start_addr, 0x8000)
        self.assertEqual(rec.partition_size, 0x4000000)
        self.assertEqual(rec.region, "EMMC_USER")
        self.assertEqual(rec.operation_type, "UPDATE")
        self.assertEqual(rec.end_addr, 0x8000 + 0x4000000)

    def test_preloader_both_storages(self):
        pres = self.info.by_name("preloader")
        self.assertEqual(len(pres), 2)
        regions = {p.region for p in pres}
        self.assertEqual(regions, {"EMMC_BOOT1_BOOT2", "UFS_LU0_LU1"})
        for p in pres:
            self.assertTrue(p.is_bootloader())
            self.assertEqual(p.linear_start_addr, 0x0)
            self.assertEqual(p.partition_size, 0x80000)

    def test_download_partitions(self):
        dl = self.info.get_download_partitions()
        self.assertEqual(len(dl), 64)
        names = {p.partition_name for p in dl}
        self.assertIn("boot", names)
        self.assertIn("system", names)
        self.assertNotIn("pgpt", names)  # is_download: false

    def test_bootloader_detection(self):
        emmc = self.info.get_storage("EMMC")
        bootloaders = [p for p in emmc.partitions if p.is_bootloader()]
        self.assertEqual([p.partition_name for p in bootloaders], ["preloader"])

    def test_chip_validation_ok(self):
        self.assertTrue(self.info.validate_chip(0x6785))

    def test_chip_validation_mismatch(self):
        # SPFT: "Chip mismatch! scatter: platform[%s] ... hw_code[0x%x] ..."
        with self.assertRaises(ScatterChipMismatch) as ctx:
            self.info.validate_chip(0x1234)
        self.assertIn("Chip mismatch!", str(ctx.exception))
        self.assertIn("MT6785", str(ctx.exception))
        self.assertIn("hw_code[0x1234]", str(ctx.exception))

    def test_missing_file(self):
        with self.assertRaises(ScatterError) as ctx:
            parse_scatter("/nonexistent/scatter.txt")
        self.assertIn("STATUS_SCATTER_FILE_NOT_FOUND", str(ctx.exception))

    def test_garbage_rejected(self):
        with self.assertRaises(ScatterError):
            parse_scatter_text("this is not a scatter file\n")

    def test_duplicate_partition_in_one_section(self):
        dup = """- general: MTK_PLATFORM_CFG
  info:
    - config_version: V2.1.0
      platform: MT6785
      project: x
- storage_type: EMMC
  description:
  - general: MTK_STORAGE_CFG
    info:
      - storage: EMMC
        boot_channel: MSDC_0
        block_size: 0x20000
  - partition_index: SYS0
    partition_name: boot
    file_name: boot.img
    is_download: true
    type: NORMAL_ROM
    linear_start_addr: 0x0
    physical_start_addr: 0x0
    partition_size: 0x1000
    region: EMMC_USER
    storage: HW_STORAGE_EMMC
    boundary_check: true
    is_reserved: false
    operation_type: UPDATE
    is_upgradable: false
    empty_boot_needed: false
    reserve: 0x00
  - partition_index: SYS1
    partition_name: boot
    file_name: boot2.img
    is_download: true
    type: NORMAL_ROM
    linear_start_addr: 0x1000
    physical_start_addr: 0x1000
    partition_size: 0x1000
    region: EMMC_USER
    storage: HW_STORAGE_EMMC
    boundary_check: true
    is_reserved: false
    operation_type: UPDATE
    is_upgradable: false
    empty_boot_needed: false
    reserve: 0x00
"""
        # SPFT yaml_reader: "Error: partition name(%s) duplicated."
        with self.assertRaises(ScatterError) as ctx:
            parse_scatter_text(dup)
        self.assertIn("duplicated", str(ctx.exception))


class TestXmlScatter(unittest.TestCase):
    def test_v8_full(self):
        info = parse_scatter_xml(XML_V8)
        self.assertEqual(info.scatter_version, "V8")
        self.assertEqual(info.platform, "MT6785")
        self.assertEqual(info.project, "begonia")
        # V7+ fields
        self.assertTrue(info.check_bootloaders_consistency)
        self.assertFalse(info.skip_pmt_operate)
        # V8+ fields
        self.assertTrue(info.modem_check)
        self.assertEqual(info.modem_type, "MD1")
        self.assertFalse(info.resize_check)
        self.assertEqual(len(info.partitions), 2)
        pre = info.partitions[0]
        self.assertEqual(pre.partition_name, "preloader")
        self.assertEqual(pre.linear_start_addr, 0x0)
        self.assertEqual(pre.partition_size, 0x80000)
        self.assertEqual(pre.region, "EMMC_BOOT1_BOOT2")
        self.assertEqual(info.get_storage("EMMC").block_size, 0x20000)
        self.assertTrue(info.validate_chip(0x6785))

    def test_v4_minimal(self):
        info = parse_scatter_xml(XML_V4)
        self.assertEqual(info.scatter_version, "V4")
        self.assertIsNone(info.check_bootloaders_consistency)  # not parsed before V7
        self.assertIsNone(info.modem_check)                    # not parsed before V8
        self.assertEqual(len(info.partitions), 1)
        self.assertEqual(info.partitions[0].partition_name, "preloader")

    def test_v11_chip_version(self):
        info = parse_scatter_xml(XML_V11)
        self.assertEqual(info.scatter_version, "V11")
        self.assertEqual(info.chip_version, "S00")

    def test_all_decorator_versions_parse(self):
        for version in ("V4", "V5", "V7", "V8", "V10", "V11"):
            xml = XML_V8.replace('version="V8"', f'version="{version}"') \
                        .replace('name="V8"', f'name="{version}"')
            info = parse_scatter_xml(xml)
            self.assertEqual(info.scatter_version, version)
            self.assertEqual(info.platform, "MT6785")
            self.assertEqual(len(info.partitions), 2)

    def test_no_partitions_rejected(self):
        with self.assertRaises(ScatterError):
            parse_scatter_xml('<?xml version="1.0"?><rom_info><general/></rom_info>')

    def test_invalid_xml_rejected(self):
        with self.assertRaises(ScatterError):
            parse_scatter_xml("<rom_info><unclosed>")


class TestScatterChecksum(unittest.TestCase):
    def test_parse(self):
        version, images = parse_scatter_checksum(SCATTER_CHECKSUM)
        self.assertEqual(version, "1.0")
        self.assertEqual(images["preloader_begonia.bin"], "aabbccdd00112233")
        self.assertEqual(images["recovery.img"], "deadbeefcafebabe")

    def test_invalid_version(self):
        # flash.dll: "scatter_checksum.xml version is invalid."
        with self.assertRaises(ScatterError) as ctx:
            parse_scatter_checksum('<scatter><images_sha256/></scatter>')
        self.assertIn("version is invalid", str(ctx.exception))

    def test_wrong_root(self):
        # flash.dll: "Open scatter checksum file failed: ..."
        with self.assertRaises(ScatterError) as ctx:
            parse_scatter_checksum('<other version="1.0"/>')
        self.assertIn("Open scatter checksum file failed", str(ctx.exception))

    def test_from_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tf:
            tf.write(SCATTER_CHECKSUM)
            path = tf.name
        try:
            version, images = parse_scatter_checksum(path)
            self.assertEqual(version, "1.0")
            self.assertEqual(len(images), 2)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
