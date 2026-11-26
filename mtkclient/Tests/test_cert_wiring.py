#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for the private-cert wiring (SPFT V6 CMD:WRITE-PRIVATE-CERT /
# console_mode.xsd WRITE-PRIVATE-CERT, V5 FlashTool_DownloadCert heritage):
# XMLCmd protocol, XmlFlashExt flow, DAloader routing and the mtk CLI
# "da cert download <file>" command. No device is touched.
import os
import tempfile
import unittest

from mtkclient.Library.DA.xmlflash.xml_cmd import XMLCmd


class TestWritePrivateCertProtocol(unittest.TestCase):
    def setUp(self):
        self.cmd = XMLCmd(None)

    def test_default_source_file_unchanged(self):
        data = self.cmd.cmd_write_private_cert()
        self.assertIn("<command>CMD:WRITE-PRIVATE-CERT</command>", data)
        self.assertIn("<source_file>ms-appdata:///local/cert.bin</source_file>", data)
        self.assertTrue(data.endswith("</da>"))

    def test_custom_cert_file_is_used(self):
        data = self.cmd.cmd_write_private_cert(cert_file="my_cert.bin")
        self.assertIn("<command>CMD:WRITE-PRIVATE-CERT</command>", data)
        self.assertIn("<source_file>ms-appdata:///local/my_cert.bin</source_file>", data)
        self.assertNotIn("ms-appdata:///local/cert.bin<", data)

    def test_nested_path_is_flattened_to_da_local_name(self):
        data = self.cmd.cmd_write_private_cert(cert_file="/tmp/certs/slb1.bin")
        self.assertIn("<source_file>ms-appdata:///local/slb1.bin</source_file>", data)


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

    def test_write_private_cert_serves_download_file(self):
        # The DA fetches the cert from its ms-appdata local storage via
        # CMD:DOWNLOAD-FILE; the host hands over the real file bytes, then
        # the transaction closes with CMD:END/CMD:START
        from mtkclient.Library.DA.xmlflash.xml_lib import DwnFile

        cert_bytes = b"\x01CERT-PAYLOAD\x02" * 24
        fd, certfile = tempfile.mkstemp(suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as fhandle:
                fhandle.write(cert_bytes)
            script = [
                ("CMD:DOWNLOAD-FILE",
                 DwnFile("CHK_NO", "cert", f"ms-appdata:///local/{os.path.basename(certfile)}",
                         0x1000)),
                ("CMD:END", "OK"),
                ("CMD:START", "START"),
            ]
            ext, sent, calls = self._make_ext(script=script)
            result = ext.write_private_cert(cert_file=certfile)
        finally:
            os.unlink(certfile)
        self.assertEqual(result, "OK")
        self.assertEqual(len(sent), 1)
        self.assertTrue(calls["noack"])
        self.assertIn("<command>CMD:WRITE-PRIVATE-CERT</command>", sent[0])
        self.assertIn(f"ms-appdata:///local/{os.path.basename(certfile)}", sent[0])
        self.assertEqual(len(calls["upload"]), 1)
        self.assertEqual(calls["upload"][0][1], cert_bytes)
        self.assertFalse(calls["upload"][0][2])  # the loop owns the END/START drain

    def test_write_private_cert_plain_success(self):
        # Transfer-free transaction: the DA closes with the END/START drain
        script = [("CMD:END", "OK"), ("CMD:START", "START")]
        ext, sent, calls = self._make_ext(script=script)
        fd, certfile = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        try:
            result = ext.write_private_cert(cert_file=certfile)
        finally:
            os.unlink(certfile)
        self.assertEqual(result, "OK")
        self.assertEqual(len(sent), 1)
        self.assertIn("<command>CMD:WRITE-PRIVATE-CERT</command>", sent[0])
        self.assertIn(f"ms-appdata:///local/{os.path.basename(certfile)}", sent[0])
        self.assertEqual(calls["upload"], [])

    def test_write_private_cert_missing_file_fails_early(self):
        ext, sent, calls = self._make_ext()
        result = ext.write_private_cert(cert_file="/nonexistent/cert.bin")
        self.assertEqual(result, "FAILED")
        self.assertEqual(len(sent), 0)


class TestDaLoaderDispatch(unittest.TestCase):
    def test_daloader_routes_to_xmlft(self):
        from mtkclient.Library.DA.mtk_daloader import DAloader
        from mtkclient.config.brom_config import DAmodes

        calls = {}

        class Xmlft:
            def write_private_cert(self, cert_file):
                calls["cert"] = cert_file
                return "OK"

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
        self.assertEqual(loader.write_private_cert("/tmp/my_cert.bin"), "OK")
        self.assertEqual(calls["cert"], "/tmp/my_cert.bin")

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
        self.assertFalse(loader.write_private_cert("/tmp/my_cert.bin"))


class TestCliWiring(unittest.TestCase):
    """
    The real mtk.py CLI is verified via subprocess --help (importing mtk.py
    in-process rewraps sys.stdout via Library/utils.py, breaking the runner).
    """
    MTK_PY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mtk.py"))

    def _help(self, *argv):
        import subprocess
        import sys
        proc = subprocess.run([sys.executable, self.MTK_PY, *argv, "--help"],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0,
                         f"help failed for {argv}: {proc.stderr[-400:]}")
        return proc.stdout

    def test_mtk_da_cert_help_lists_download(self):
        out = self._help("da", "cert")
        self.assertIn("download", out)

    def test_mtk_da_cert_download_help(self):
        out = self._help("da", "cert", "download")
        self.assertIn("filename", out)
        self.assertIn("cert", out.lower())


if __name__ == "__main__":
    unittest.main()
