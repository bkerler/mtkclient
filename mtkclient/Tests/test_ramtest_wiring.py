#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for the cmd_ram_test / cmd_dram_repair CLI + API wiring
# (SPFT V6 CMD:RAM-TEST / CMD:DEBUG:DRAM-REPAIR, flash.dll strings).
# No device is touched: protocol strings and dispatch are verified with stubs.
import os
import sys
import unittest

from mtkclient.Library.DA.xmlflash.xml_cmd import XMLCmd


class TestRamTestProtocol(unittest.TestCase):
    def setUp(self):
        self.cmd = XMLCmd(None)

    def test_flip_wire_format(self):
        # SPFT V6: <function>FLIP</function> + start/length/repeat
        data = self.cmd.cmd_ram_test(function="FLIP", start_address=0x4000000,
                                     length=0x100000, repeat=0xA)
        self.assertIn("<command>CMD:RAM-TEST</command>", data)
        self.assertIn("<function>FLIP</function>", data)
        self.assertIn("<start_address>0x4000000</start_address>", data)
        self.assertIn("<length>0x100000</length>", data)
        self.assertIn("<repeat>0xa</repeat>", data)
        self.assertTrue(data.endswith("</da>"))

    def test_calibration_wire_format(self):
        # CalibrationRAMTestCmdXML (SPFT v6.2228): CALIBRATION addresses a host
        # memory range (MEM://0x8000000:0x100000 in the C++ sample), not a
        # DA-local ms-appdata file
        data = self.cmd.cmd_ram_test(function="CALIBRATION")
        self.assertIn("<command>CMD:RAM-TEST</command>", data)
        self.assertIn("<function>CALIBRATION</function>", data)
        self.assertIn("<target_file>MEM://0x8000000:0x100000</target_file>", data)
        self.assertNotIn("ms-appdata", data)
        self.assertNotIn("start_address", data)

    def test_calibration_custom_mem_range(self):
        data = self.cmd.cmd_ram_test(function="CALIBRATION", host_mem_offset=0x7fe800000000,
                                     host_mem_length=0x200000)
        self.assertIn("<target_file>MEM://0x7fe800000000:0x200000</target_file>", data)
        self.assertNotIn("start_address", data)

    def test_dram_repair_wire_format(self):
        # SPFT flash.dll sends the debug-prefixed command: CMD:DEBUG:DRAM-REPAIR
        data = self.cmd.cmd_dram_repair(mem_offset=0x10000, mem_length=0x1000,
                                        param_file="D:/dram.info")
        self.assertIn("<command>CMD:DEBUG:DRAM-REPAIR</command>", data)
        self.assertNotIn("<command>CMD:DRAM-REPAIR<", data)
        self.assertIn("<param_file>D:/dram.info</param_file>", data)
        self.assertIn("<target_file>MEM://0x10000:0x1000</target_file>", data)

    def test_dram_repair_default_param_file_unchanged(self):
        data = self.cmd.cmd_dram_repair()
        self.assertIn("<param_file>D:/dram.info</param_file>", data)


class TestXmlFlashExtWiring(unittest.TestCase):
    def _make_ext(self, script=None, send_result=True):
        """Build an XmlFlashExt against stub mtk/xmlflash objects. `script` is
        the scripted DA answer sequence for get_command_result() as
        (cmd, result) tuples; transfer calls are recorded in `calls`."""
        from mtkclient.Library.DA.xmlflash.extension.v6 import XmlFlashExt

        sent = []
        calls = {"noack": None, "download": [], "upload": [], "ack": 0}
        script = list(script or [])

        class Port:
            @staticmethod
            def usbwrite(data):
                return True

            @staticmethod
            def usbread(data=None, length=0, w_max_packet_size=0):
                return b""

            @staticmethod
            def echo(data):
                return True

            @staticmethod
            def rbyte(length):
                return b""

            @staticmethod
            def rdword(length=32):
                return 0

            @staticmethod
            def rword(length=16):
                return 0

        class Config:
            gui = None

        class Mtk:
            config = Config()
            port = Port()

        class XmlFlash:
            cmd = XMLCmd(None)

            @staticmethod
            def send_command(xmldata, noack=False):
                sent.append(xmldata)
                calls["noack"] = noack
                return send_result

            @staticmethod
            def get_command_result():
                return script.pop(0)

            @staticmethod
            def download(result):
                calls["download"].append(result)
                return b"SUCCEEDED"

            @staticmethod
            def upload(result, data, display=True, raw=False, drain_end=True):
                calls["upload"].append((result, bytes(data), drain_end))
                return True

            @staticmethod
            def ack():
                calls["ack"] += 1
                return True

            @staticmethod
            def xsend(data, datatype=None, is64bit=False):
                sent.append(data)
                return True

            @staticmethod
            def xread():
                return -1, 0

        xmlflash = XmlFlash()
        ext = XmlFlashExt(Mtk(), xmlflash, 4)
        return ext, sent, calls

    def test_ram_test_sends_protocol_command(self):
        # Transfer-free transaction: the DA closes with the END/START drain
        script = [("CMD:END", "OK"), ("CMD:START", "START")]
        ext, sent, calls = self._make_ext(script=script)
        result = ext.ram_test(function="FLIP", start_address=0x4000000,
                              length=0x100000, repeat=0xA)
        self.assertEqual(result, "OK")
        self.assertEqual(len(sent), 1)
        self.assertIn("<command>CMD:RAM-TEST</command>", sent[0])
        self.assertTrue(calls["noack"])
        self.assertEqual(calls["upload"], [])

    def test_ram_test_serves_upload_file_verdict(self):
        # flash.dll: the DA reports the FLIP verdict via CMD:UPLOAD-FILE
        # (the host pulls the payload), then closes with CMD:END/CMD:START
        from mtkclient.Library.DA.xmlflash.xml_lib import UpFile

        upfile = UpFile("CHK_NO", "RAM test.", "MEM://0x8000000:0x100000", "0x1000")
        script = [("CMD:UPLOAD-FILE", upfile), ("CMD:END", "OK"), ("CMD:START", "START")]
        ext, sent, calls = self._make_ext(script=script)
        result = ext.ram_test(function="FLIP", start_address=0x4000000,
                              length=0x100000, repeat=0xA)
        self.assertEqual(result, "SUCCEEDED")
        self.assertEqual(calls["download"], [upfile])
        self.assertEqual(calls["ack"], 1)

    def test_ram_test_download_file_request_without_data_fails(self):
        from mtkclient.Library.DA.xmlflash.xml_lib import DwnFile

        script = [("CMD:DOWNLOAD-FILE",
                   DwnFile("CHK_NO", "dram.info", "ms-appdata:///local/dram.info", 0x1000))]
        ext, sent, calls = self._make_ext(script=script)
        self.assertEqual(ext.ram_test(function="FLIP"), "FAILED")
        self.assertEqual(calls["upload"], [])

    def test_ram_test_rejected_command_fails(self):
        ext, sent, calls = self._make_ext(send_result=False, script=[])
        self.assertEqual(ext.ram_test(function="FLIP"), "FAILED")
        self.assertEqual(len(sent), 1)

    def test_dram_repair_serves_download_file_and_verdict(self):
        # C++ DebugDRAMRepairCmdXML: the DA fetches dram.info via
        # CMD:DOWNLOAD-FILE, then reports SUCCEEDED/NO-NEED/FAILED (the
        # target_file result string) via CMD:UPLOAD-FILE
        from mtkclient.Library.DA.xmlflash.xml_lib import DwnFile, UpFile

        script = [
            ("CMD:DOWNLOAD-FILE",
             DwnFile("CHK_NO", "dram.info", "ms-appdata:///local/dram.info", 0x1000)),
            ("CMD:UPLOAD-FILE",
             UpFile("CHK_NO", "dram-repair", "MEM://0x10000:0x1000", "0x1000")),
            ("CMD:END", "OK"),
            ("CMD:START", "START"),
        ]
        ext, sent, calls = self._make_ext(script=script)
        paramfile = os.path.join(os.path.dirname(__file__), "fixtures", "dram.info")
        result = ext.dram_repair(param_file=paramfile, mem_offset=0x10000, mem_length=0x1000)
        self.assertEqual(result, "SUCCEEDED")
        self.assertEqual(len(sent), 1)
        self.assertIn("<command>CMD:DEBUG:DRAM-REPAIR</command>", sent[0])
        self.assertIn(f"<param_file>{paramfile}</param_file>", sent[0])
        self.assertEqual(len(calls["upload"]), 1)
        with open(paramfile, "rb") as fhandle:
            self.assertEqual(calls["upload"][0][1], fhandle.read())
        self.assertFalse(calls["upload"][0][2])  # the loop owns the END/START drain

    def test_dram_repair_verdict_in_cmd_end(self):
        # A DA may also report the verdict in the CMD:END result field
        from mtkclient.Library.DA.xmlflash.xml_lib import DwnFile

        script = [
            ("CMD:DOWNLOAD-FILE",
             DwnFile("CHK_NO", "dram.info", "ms-appdata:///local/dram.info", 0x1000)),
            ("CMD:END", "NO-NEED"),
            ("CMD:START", "START"),
        ]
        ext, sent, calls = self._make_ext(script=script)
        paramfile = os.path.join(os.path.dirname(__file__), "fixtures", "dram.info")
        result = ext.dram_repair(param_file=paramfile, mem_offset=0x10000, mem_length=0x1000)
        self.assertEqual(result, "NO-NEED")
        self.assertEqual(calls["ack"], 1)

    def test_dram_repair_missing_file_fails_early(self):
        ext, sent, calls = self._make_ext()
        result = ext.dram_repair(param_file="/nonexistent/dram.info")
        self.assertEqual(result, "FAILED")
        self.assertEqual(len(sent), 0)


class TestCliWiring(unittest.TestCase):
    """
    The real mtk.py CLI is verified via subprocess --help (importing mtk.py in-process
    rewraps sys.stdout via Library/utils.py, breaking the unittest runner).
    """
    MTK_PY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mtk.py"))

    def _help(self, *argv):
        import subprocess
        proc = subprocess.run([sys.executable, self.MTK_PY, *argv, "--help"],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0,
                         f"help failed for {argv}: {proc.stderr[-400:]}")
        return proc.stdout

    def test_mtk_da_ramtest_help(self):
        out = self._help("da", "ramtest")
        self.assertIn("ramtest", out)
        self.assertIn("--addr", out)
        self.assertIn("--length", out)
        self.assertIn("--repeat", out)
        self.assertIn("FLIP", out)

    def test_mtk_da_dram_repair_help(self):
        out = self._help("da", "dram-repair")
        self.assertIn("dram-repair", out)
        self.assertIn("--file", out)
        self.assertIn("--offset", out)
        self.assertIn("--length", out)


class TestDaLoaderDispatch(unittest.TestCase):
    def test_daloader_routes_to_xmlft(self):
        """DAloader.ram_test/dram_repair route to xmlft in XML mode."""
        from mtkclient.Library.DA.mtk_daloader import DAloader
        from mtkclient.config.brom_config import DAmodes

        calls = {}

        class Xmlft:
            def ram_test(self, function, start_address, length, repeat):
                calls["ram_test"] = (function, start_address, length, repeat)
                return "SUCCEEDED"

            def dram_repair(self, param_file, mem_offset, mem_length):
                calls["dram_repair"] = (param_file, mem_offset, mem_length)
                return "NO-NEED"

        class Mtk:
            class config:
                gui = None
                loader = None
                preloader = None

            class port:
                @staticmethod
                def usbwrite(data):
                    return True

                @staticmethod
                def usbread(*args, **kwargs):
                    return b""

                echo = staticmethod(lambda data: True)
                rbyte = staticmethod(lambda length: b"")
                rdword = staticmethod(lambda length=32: 0)
                rword = staticmethod(lambda length=16: 0)

        loader = DAloader.__new__(DAloader)  # skip __init__ (usb/hw deps)
        loader.mtk = Mtk()
        loader.config = Mtk.config
        loader.error = lambda *args, **kwargs: None
        loader.info = lambda *args, **kwargs: None
        loader.flashmode = DAmodes.XML
        loader.xmlft = Xmlft()
        self.assertEqual(loader.ram_test("FLIP", 0x4000000, 0x100000, 0xA), "SUCCEEDED")
        self.assertEqual(calls["ram_test"], ("FLIP", 0x4000000, 0x100000, 0xA))
        self.assertEqual(loader.dram_repair("/tmp/dram.info", 0x10000, 0x1000), "NO-NEED")
        self.assertEqual(calls["dram_repair"], ("/tmp/dram.info", 0x10000, 0x1000))

    def test_daloader_rejects_non_xml_mode(self):
        from mtkclient.Library.DA.mtk_daloader import DAloader
        from mtkclient.config.brom_config import DAmodes

        class Mtk:
            class config:
                gui = None

        loader = DAloader.__new__(DAloader)
        loader.mtk = Mtk()
        loader.config = Mtk.config
        loader.error = lambda *args, **kwargs: None
        loader.flashmode = DAmodes.XFLASH
        loader.xmlft = None
        self.assertFalse(loader.ram_test())
        self.assertFalse(loader.dram_repair())


if __name__ == "__main__":
    unittest.main()
