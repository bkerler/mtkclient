#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for the SPFT V6 flash.xml loader (Library/DAXML/loader.py),
# parsed per the official console_mode.xsd (SP_Flash_Tool_V6.2404_Win) and
# mapped 1:1 onto the existing XMLCmd methods. No device is touched.
import unittest

from mtkclient.Library.DA.xmlflash.xml_cmd import XMLCmd
from mtkclient.Library.DAXML.loader import (parse_flash_xml, map_commands,
                                            FlashXmlError)

FULL_FLASH_XML = """<?xml version="1.0" encoding="UTF-8"?>
<cflashtool-config version="2.0">
  <general>
    <connect-args com_port_name="COM3" version="2.0" baud_rate="115200"
                  timeout_ms="3000" com_port_type="UART" conn_stage="brom"
                  da_port_name="COM4">
      <flash-xml>MT6785_Android_scatter.xml</flash-xml>
      <auth-file>auth_sv5.auth</auth-file>
      <cert-file>cert.bin</cert-file>
      <da-file>MTK_DA_V6.bin</da-file>
    </connect-args>
    <runtime-parameter version="2.0" da_log_level="INFO" system_os="WINDOWS"
                       battery_status="1" log_channel="USB" checksum_level="6"
                       initialize_dram="NO" usb_speed="0"/>
    <log-info version="2.0" log_path="C:\\logs" clean_hours="72"/>
  </general>
  <commands>
    <ERASE-FLASH version="2.0" partition="userdata" length="0x1000" offset="0x0"/>
    <READ-FLASH version="2.0" partition="boot" length="0x4000000" offset="0x2E980000">
      <target-file version="2.0" file_type="LOCAL_FILE" file_name="boot_readout.img"/>
    </READ-FLASH>
    <WRITE-FLASH version="2.0" partition="boot" offset="0x2E980000">
      <source-file version="2.0" file_type="LOCAL_FILE" file_name="boot.img"/>
    </WRITE-FLASH>
    <SET-RSC version="2.0" key="k6885v1_64[op01]">
      <source-file version="2.0" file_type="LOCAL_FILE" file_name="RSC.bin"/>
    </SET-RSC>
    <WRITE-PRIVATE-CERT version="2.0">
      <source-file version="2.0" file_type="LOCAL_FILE" file_name="my_cert.bin"/>
    </WRITE-PRIVATE-CERT>
    <RUN-PROGRAM version="2.0" at_address="0x40000000" jmp_address="0x40000100"
                 signature_offset="0x0" signature_length="0x100">
      <source-file version="2.0" file_type="LOCAL_FILE" file_name="loader.bin"/>
    </RUN-PROGRAM>
    <REBOOT version="2.0" action="WARM-RESET"/>
    <READ-EFUSE version="2.0">
      <target-file version="2.0" file_type="LOCAL_FILE" file_name="efuse.bin"/>
    </READ-EFUSE>
  </commands>
</cflashtool-config>
"""

FLASH_ALL_XML = """<?xml version="1.0" encoding="UTF-8"?>
<cflashtool-config version="2.0">
  <general>
    <connect-args com_port_name="" version="2.0" baud_rate="115200"
                  timeout_ms="3000" com_port_type="USB-PCIE" conn_stage="2nd DA">
      <flash-xml>scatter.xml</flash-xml>
      <auth-file></auth-file>
      <cert-file></cert-file>
    </connect-args>
    <runtime-parameter version="2.0" da_log_level="DEBUG" system_os="LINUX"
                       battery_status="0" log_channel="UART" checksum_level="2"/>
    <log-info version="2.0" log_path="/tmp/logs" clean_hours="24"/>
  </general>
  <commands>
    <LIFE-CYCLE-STATUS version="2.0">
      <target-file version="2.0" file_type="MEMORY_FILE" file_name="mem"/>
    </LIFE-CYCLE-STATUS>
    <FLASH-ALL version="2.0" path_separator="/">
      <source-file version="2.0" file_type="LOCAL_FILE" file_name="target.bin"/>
      <flash_list>
        <pt name="preloader">preloader.bin</pt>
        <pt name="boot">boot.img</pt>
      </flash_list>
    </FLASH-ALL>
    <FLASH-UPDATE version="2.0" path_separator="/">
      <source-file version="2.0" file_type="LOCAL_FILE" file_name="target.bin"/>
      <backup_folder>D:/backup</backup_folder>
      <flash_list><pt name="system">system.img</pt></flash_list>
    </FLASH-UPDATE>
    <WRITE-PARTITIONS version="2.0">
      <source-file version="2.0" file_type="LOCAL_FILE" file_name="target.bin"/>
      <flash_list><pt name="vendor">vendor.img</pt></flash_list>
    </WRITE-PARTITIONS>
    <GET-DOWNLOADED-IMAGE-FEEDBACK version="2.0">
      <target-file version="2.0" file_type="MEMORY_FILE" file_name="mem"/>
    </GET-DOWNLOADED-IMAGE-FEEDBACK>
    <WRITE-EFUSE version="2.0">
      <source-file version="2.0" file_type="LOCAL_FILE" file_name="efuse.xml"/>
    </WRITE-EFUSE>
  </commands>
</cflashtool-config>
"""


def _config(xml):
    return parse_flash_xml(xml)


def _names(config):
    return [type(cmd).__name__ for cmd in config.commands]


class TestParseFlashXml(unittest.TestCase):
    def test_full_config_fields(self):
        config = _config(FULL_FLASH_XML)
        self.assertEqual(config.version, "2.0")
        # connect-args
        ca = config.connect_args
        self.assertEqual(ca.flash_xml, "MT6785_Android_scatter.xml")
        self.assertEqual(ca.auth_file, "auth_sv5.auth")
        self.assertEqual(ca.cert_file, "cert.bin")
        self.assertEqual(ca.da_file, "MTK_DA_V6.bin")
        self.assertEqual(ca.com_port_name, "COM3")
        self.assertEqual(ca.baud_rate, "115200")
        self.assertEqual(ca.timeout_ms, "3000")
        self.assertEqual(ca.com_port_type, "UART")
        self.assertEqual(ca.conn_stage, "brom")
        self.assertEqual(ca.da_port_name, "COM4")
        # runtime-parameter
        rp = config.runtime_parameters
        self.assertEqual(rp.da_log_level, "INFO")
        self.assertEqual(rp.system_os, "WINDOWS")
        self.assertEqual(rp.battery_status, "1")
        self.assertEqual(rp.log_channel, "USB")
        self.assertEqual(rp.checksum_level, "6")
        self.assertEqual(rp.initialize_dram, "NO")
        self.assertEqual(rp.usb_speed, "0")
        # log-info
        self.assertEqual(config.log_info.log_path, "C:\\logs")
        self.assertEqual(config.log_info.clean_hours, "72")
        # commands
        self.assertEqual(_names(config), ["EraseFlash", "ReadFlash", "WriteFlash",
                                          "SetRsc", "WritePrivateCert",
                                          "RunProgram", "Reboot", "ReadEfuse"])

    def test_da_file_is_optional(self):
        xml = FULL_FLASH_XML.replace("\n      <da-file>MTK_DA_V6.bin</da-file>", "")
        config = _config(xml)
        self.assertIsNone(config.connect_args.da_file)

    def test_flash_all_family(self):
        config = _config(FLASH_ALL_XML)
        self.assertEqual(_names(config), ["LifeCycleStatus", "FlashAll",
                                          "FlashUpdate", "WritePartitions",
                                          "GetDownloadedImageFeedback",
                                          "WriteEfuse"])
        flash_all = config.commands[1]
        self.assertEqual(flash_all.path_separator, "/")
        self.assertEqual(flash_all.source_file.file_name, "target.bin")
        self.assertEqual(flash_all.partitions, [("preloader", "preloader.bin"),
                                                ("boot", "boot.img")])
        flash_update = config.commands[2]
        self.assertEqual(flash_update.backup_folder, "D:/backup")
        write_partitions = config.commands[3]
        self.assertEqual(write_partitions.partitions, [("vendor", "vendor.img")])

    def test_file_assistant_fields(self):
        config = _config(FULL_FLASH_XML)
        write_flash = config.commands[2]
        self.assertEqual(write_flash.source_file.file_type, "LOCAL_FILE")
        self.assertEqual(write_flash.source_file.version, "2.0")


class TestFlashXmlValidation(unittest.TestCase):
    """console_mode.xsd constraints: enums, hex formats, required attrs, order."""

    def _invalid(self, xml, fragment):
        with self.assertRaises(FlashXmlError) as ctx:
            parse_flash_xml(xml)
        self.assertIn(fragment, str(ctx.exception))

    def test_bad_enum_com_port_type(self):
        self._invalid(FULL_FLASH_XML.replace('com_port_type="UART"',
                                             'com_port_type="FOO"'),
                      "com_port_type")

    def test_bad_enum_da_log_level(self):
        self._invalid(FLASH_ALL_XML.replace('da_log_level="DEBUG"',
                                            'da_log_level="TRACE"'),
                      "da_log_level")

    def test_bad_enum_battery_status(self):
        self._invalid(FULL_FLASH_XML.replace('battery_status="1"',
                                             'battery_status="9"'),
                      "battery_status")

    def test_bad_checksum_level_not_in_1_2_4_6(self):
        self._invalid(FULL_FLASH_XML.replace('checksum_level="6"',
                                             'checksum_level="3"'),
                      "checksum_level")

    def test_bad_action(self):
        self._invalid(FULL_FLASH_XML.replace('action="WARM-RESET"',
                                             'action="MAYBE"'),
                      "action")

    def test_bad_file_type(self):
        self._invalid(FULL_FLASH_XML.replace('file_type="LOCAL_FILE"',
                                             'file_type="HTTP_FILE"'),
                      "file_type")

    def test_bad_conn_stage(self):
        self._invalid(FULL_FLASH_XML.replace('conn_stage="brom"',
                                             'conn_stage="4th DA"'),
                      "conn_stage")

    def test_offset_must_be_hex(self):
        self._invalid(FULL_FLASH_XML.replace('offset="0x2E980000"',
                                             'offset="12345"'),
                      "offset")

    def test_erase_length_all_is_valid(self):
        xml = FULL_FLASH_XML.replace('length="0x1000"', 'length="ALL"')
        config = _config(xml)
        self.assertEqual(config.commands[0].length, "ALL")

    def test_read_flash_length_rejects_all(self):
        # READ-FLASH uses length_number_type: hex only (console_mode.xsd)
        self._invalid(FULL_FLASH_XML.replace('length="0x4000000"', 'length="ALL"'),
                      "length")

    def test_missing_required_attribute(self):
        self._invalid(FULL_FLASH_XML.replace(' partition="userdata"', ""),
                      "partition")

    def test_missing_root_version(self):
        self._invalid(FULL_FLASH_XML.replace('<cflashtool-config version="2.0">',
                                             "<cflashtool-config>"),
                      "version")

    def test_unknown_command_rejected(self):
        self._invalid(FULL_FLASH_XML.replace(
            "<REBOOT version=\"2.0\" action=\"WARM-RESET\"/>",
            "<FORMAT-C-DRIVE version=\"2.0\"/>"),
            "FORMAT-C-DRIVE")

    def test_unknown_general_child_rejected(self):
        # log-info is self-closing, so renaming the tag keeps the XML well-formed
        # and the unknown-element check (not the XML parser) must reject it
        self._invalid(FULL_FLASH_XML.replace("<log-info ", "<surprise-log "),
                      "surprise-log")

    def test_command_order_must_follow_the_xsd_sequence(self):
        # ERASE-FLASH after WRITE-FLASH violates the schema sequence
        xml = FULL_FLASH_XML.replace(
            "    <ERASE-FLASH version=\"2.0\" partition=\"userdata\" length=\"0x1000\" offset=\"0x0\"/>\n",
            "")
        xml = xml.replace("</commands>",
                          "    <ERASE-FLASH version=\"2.0\" partition=\"userdata\" "
                          "length=\"0x1000\" offset=\"0x0\"/>\n  </commands>")
        self._invalid(xml, "ERASE-FLASH")

    def test_single_occurrence_command_repeated(self):
        xml = FULL_FLASH_XML.replace(
            "    <ERASE-FLASH version=\"2.0\" partition=\"userdata\" length=\"0x1000\" offset=\"0x0\"/>\n",
            "    <ERASE-FLASH version=\"2.0\" partition=\"userdata\" length=\"0x1000\" offset=\"0x0\"/>\n"
            "    <ERASE-FLASH version=\"2.0\" partition=\"cache\" length=\"0x1000\" offset=\"0x0\"/>\n")
        self._invalid(xml, "ERASE-FLASH")

    def test_not_xml_at_all(self):
        self._invalid("this is not xml", "parse")


class TestMapCommands(unittest.TestCase):
    """1:1 mapping of flash.xml commands onto the existing XMLCmd methods."""

    def setUp(self):
        self.xmlcmd = XMLCmd(None)

    def test_erase_flash(self):
        config = _config(FULL_FLASH_XML)
        name, data = map_commands(config, self.xmlcmd)[0]
        self.assertEqual(name, "ERASE-FLASH")
        self.assertIn("<command>CMD:ERASE-FLASH</command>", data)
        self.assertIn("<partition>userdata</partition>", data)
        self.assertIn("<offset>0x0</offset>", data)
        self.assertIn("<length>0x1000</length>", data)

    def test_read_flash(self):
        config = _config(FULL_FLASH_XML)
        name, data = map_commands(config, self.xmlcmd)[1]
        self.assertEqual(name, "READ-FLASH")
        self.assertIn("<command>CMD:READ-FLASH</command>", data)
        self.assertIn("<partition>boot</partition>", data)
        self.assertIn("<offset>0x2e980000</offset>", data)
        self.assertIn("<length>0x4000000</length>", data)

    def test_write_flash(self):
        config = _config(FULL_FLASH_XML)
        name, data = map_commands(config, self.xmlcmd)[2]
        self.assertEqual(name, "WRITE-FLASH")
        self.assertIn("<command>CMD:WRITE-FLASH</command>", data)
        self.assertIn("<partition>boot</partition>", data)
        self.assertIn("<offset>0x2e980000</offset>", data)

    def test_set_rsc(self):
        config = _config(FULL_FLASH_XML)
        name, data = map_commands(config, self.xmlcmd)[3]
        self.assertEqual(name, "SET-RSC")
        self.assertIn("<command>CMD:SET-RSC</command>", data)
        self.assertIn("<key>k6885v1_64[op01]</key>", data)

    def test_write_private_cert(self):
        config = _config(FULL_FLASH_XML)
        name, data = map_commands(config, self.xmlcmd)[4]
        self.assertEqual(name, "WRITE-PRIVATE-CERT")
        self.assertIn("<command>CMD:WRITE-PRIVATE-CERT</command>", data)
        self.assertIn("ms-appdata:///local/my_cert.bin", data)

    def test_run_program(self):
        config = _config(FULL_FLASH_XML)
        name, data = map_commands(config, self.xmlcmd)[5]
        self.assertEqual(name, "RUN-PROGRAM")
        self.assertIn("<command>CMD:BOOT-TO</command>", data)
        self.assertIn("<at_address>0x40000000</at_address>", data)
        # signature fields are kept on the parsed command for the caller
        run_program = config.commands[5]
        self.assertEqual(run_program.signature_offset, "0x0")
        self.assertEqual(run_program.signature_length, "0x100")

    def test_reboot(self):
        config = _config(FULL_FLASH_XML)
        name, data = map_commands(config, self.xmlcmd)[6]
        self.assertEqual(name, "REBOOT")
        self.assertIn("<command>CMD:REBOOT</command>", data)
        self.assertIn("<action>IMMEDIATE</action>", data)

    def test_reboot_disconnect(self):
        xml = FULL_FLASH_XML.replace('action="WARM-RESET"', 'action="DISCONNECT"')
        config = _config(xml)
        name, data = map_commands(config, self.xmlcmd)[6]
        self.assertIn("<action>DISCONNECT</action>", data)

    def test_read_efuse(self):
        config = _config(FULL_FLASH_XML)
        name, data = map_commands(config, self.xmlcmd)[7]
        self.assertEqual(name, "READ-EFUSE")
        self.assertIn("<command>CMD:READ-EFUSE</command>", data)

    def test_flash_all_family_mapping(self):
        config = _config(FLASH_ALL_XML)
        mapped = map_commands(config, self.xmlcmd)
        self.assertEqual([name for name, _ in mapped],
                         ["FLASH-ALL", "FLASH-UPDATE", "WRITE-PARTITIONS",
                          "GET-DOWNLOADED-IMAGE-FEEDBACK", "WRITE-EFUSE"])
        self.assertIn("<command>CMD:FLASH-ALL</command>", mapped[0][1])
        self.assertIn("<command>CMD:FLASH-UPDATE</command>", mapped[1][1])
        self.assertIn("<pt name=vendor", mapped[2][1])
        self.assertIn("<command>CMD:GET-DOWNLOADED-IMAGE-FEEDBACK</command>",
                      mapped[3][1])
        self.assertIn("<command>CMD:WRITE-EFUSE</command>", mapped[4][1])

    def test_life_cycle_status_is_parsed_but_not_mapped(self):
        # console_mode.xsd defines LIFE-CYCLE-STATUS, but there is no xml_cmd
        # equivalent - the loader keeps it in config.commands only
        config = _config(FLASH_ALL_XML)
        self.assertEqual(type(config.commands[0]).__name__, "LifeCycleStatus")
        mapped = map_commands(config, self.xmlcmd)
        self.assertNotIn("LIFE-CYCLE-STATUS", [name for name, _ in mapped])

    def test_erase_flash_all_length_cannot_be_mapped(self):
        xml = FULL_FLASH_XML.replace('length="0x1000"', 'length="ALL"')
        config = _config(xml)
        with self.assertRaises(FlashXmlError) as ctx:
            map_commands(config, self.xmlcmd)
        self.assertIn("ALL", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
