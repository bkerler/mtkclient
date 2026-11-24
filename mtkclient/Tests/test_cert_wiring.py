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
    def _make_ext(self, send_result="OK"):
        from mtkclient.Library.DA.xmlflash.extension.v6 import XmlFlashExt

        sent = []

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
                return send_result

            @staticmethod
            def xsend(data, datatype=None, is64bit=False):
                sent.append(data)
                return True

            @staticmethod
            def xread():
                return -1, 0

        xmlflash = XmlFlash()
        ext = XmlFlashExt(Mtk(), xmlflash, 4)
        return ext, sent

    def test_write_private_cert_sends_protocol_command(self):
        ext, sent = self._make_ext()
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

    def test_write_private_cert_missing_file_fails_early(self):
        ext, sent = self._make_ext()
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
