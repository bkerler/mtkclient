#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for DAXML.upload() serving semantics used by the
# ramtest/dram-repair/cert file-transfer loop: the MEM://addr:len URI carries
# the transfer length, ms-appdata/plain names use the data length, and
# drain_end=False hands the CMD:END/CMD:START drain to the caller.
# No device is touched: the transport is scripted.
import unittest


class TestUploadServing(unittest.TestCase):
    def _make_daxml(self, responses):
        """DAXML.upload() against a scripted transport. Returns (daxml, wire)
        where wire is the live response list both get_response() and
        get_command_result() pop from, and sent collects the host's answers."""
        from mtkclient.Library.DA.xmlflash.xml_lib import DAXML

        daxml = DAXML.__new__(DAXML)  # skip __init__ (usb/hw deps)
        wire = list(responses)
        sent = []

        class Config:
            guiprogress = None

        class Mtk:
            config = Config()

        daxml.mtk = Mtk()
        daxml.xsend = lambda data, datatype=None, is64bit=False: (sent.append(data), True)[1]
        daxml.get_response = lambda: wire.pop(0)
        daxml.get_response_data = lambda: b""
        daxml.ack_value = lambda length: sent.append(f"OK@{hex(length)}")
        daxml.ack = lambda: sent.append("OK")
        daxml.get_command_result = lambda: wire.pop(0)
        daxml.error = lambda *args, **kwargs: None
        return daxml, wire, sent

    def test_mem_uri_length_parse_unchanged(self):
        # MEM://0x10000:0x1000 announces the length in the URI (0x1000), the
        # data is sent in packet_length chunks, and the default drain reads
        # CMD:END + CMD:START like the boot_to/sla flows
        from mtkclient.Library.DA.xmlflash.xml_lib import DwnFile

        data = b"\xa5" * 0x1000
        daxml, wire, sent = self._make_daxml(
            ["OK", "OK", "OK", ("CMD:END", "OK"), ("CMD:START", "START")])
        result = daxml.upload(DwnFile("CHK_NO", "info", "MEM://0x10000:0x1000", 0x1000), data,
                              display=False)
        self.assertTrue(result)
        self.assertEqual(wire, [])
        self.assertIn("OK@0x1000", sent)
        self.assertIn(data, sent)

    def test_ms_appdata_uses_data_length(self):
        # ms-appdata:///local/... carries no length: the data itself defines it
        # (the old ":"-split crashed with IndexError on these URIs)
        from mtkclient.Library.DA.xmlflash.xml_lib import DwnFile

        data = b"\x5a" * 5000  # 2 chunks at packet_length 0x1000
        daxml, wire, sent = self._make_daxml(
            ["OK", "OK", "OK", "OK", "OK", ("CMD:END", "OK"), ("CMD:START", "START")])
        result = daxml.upload(DwnFile("CHK_NO", "cert", "ms-appdata:///local/cert.bin", 0x1000),
                              data, display=False)
        self.assertTrue(result)
        self.assertEqual(wire, [])
        self.assertIn("OK@0x1388", sent)
        self.assertIn(data[:0x1000], sent)
        self.assertIn(data[0x1000:], sent)

    def test_drain_end_false_leaves_end_start_to_caller(self):
        # drain_end=False: the data transfer returns without consuming the
        # scripted CMD:END/CMD:START (the serving loop owns them)
        from mtkclient.Library.DA.xmlflash.xml_lib import DwnFile

        end_start = [("CMD:END", "OK"), ("CMD:START", "START")]
        daxml, wire, sent = self._make_daxml(["OK", "OK", "OK"] + end_start)
        result = daxml.upload(DwnFile("CHK_NO", "cert", "ms-appdata:///local/cert.bin", 0x1000),
                              b"\x01" * 16, display=False, drain_end=False)
        self.assertTrue(result)
        self.assertEqual(wire, end_start)  # untouched for the caller


if __name__ == "__main__":
    unittest.main()
