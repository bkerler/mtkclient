#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
Unit tests for the DA DOWNLOAD command construction (xflash cmd_download).

These validate the wire-level parameter block without hardware: DOWNLOAD must
use opcode 0x010001 and the same param layout as WRITE_DATA, with bin_type
carrying the image type (0 = normal, sparse selects the DA unsparse engine).
"""
import unittest
from struct import unpack
from types import SimpleNamespace

from mtkclient.Library.DA.xflash.xflash_lib import DAXFlash
from mtkclient.Library.DA.xflash.xflash_param import Cmd
from mtkclient.Library.DA.storage import DaStorage, EmmcPartitionType


def make_daxflash():
    x = DAXFlash.__new__(DAXFlash)
    x.cmd = Cmd()
    x.sent = []           # opcodes passed to xsend
    x.params = []         # param blocks passed to send_param
    x.xsend = lambda op: (x.sent.append(op), True)[1]
    x.status = lambda: 0
    x.send_param = lambda p: (x.params.append(p), True)[1]
    x.error = lambda *a, **k: None
    return x


class CmdDownloadTest(unittest.TestCase):
    def setUp(self):
        self.x = make_daxflash()

    def test_uses_download_opcode(self):
        self.x.cmd_download(0x1000, 0x2000)
        self.assertEqual(self.x.sent, [Cmd.DOWNLOAD])
        self.assertEqual(Cmd.DOWNLOAD, 0x010001)
        self.assertNotEqual(Cmd.DOWNLOAD, Cmd.WRITE_DATA)

    def test_param_layout(self):
        self.x.cmd_download(addr=0x8000, size=0x40000,
                            storage=DaStorage.MTK_DA_STORAGE_EMMC,
                            parttype=EmmcPartitionType.MTK_DA_EMMC_PART_USER,
                            bintype=0)
        param = self.x.params[0]
        storage, parttype, addr, size = unpack("<IIQQ", param[:24])
        self.assertEqual(storage, DaStorage.MTK_DA_STORAGE_EMMC)
        self.assertEqual(parttype, EmmcPartitionType.MTK_DA_EMMC_PART_USER)
        self.assertEqual(addr, 0x8000)
        self.assertEqual(size, 0x40000)
        # NandExtension block: bin_type is the 3rd u32
        ext = unpack("<IIIIIIII", param[24:24 + 32])
        self.assertEqual(ext[2], 0)  # bin_type = normal

    def test_bintype_sparse(self):
        self.x.cmd_download(0, 0x1000, bintype=0x1)
        ext = unpack("<IIIIIIII", self.x.params[0][24:24 + 32])
        self.assertEqual(ext[2], 0x1)

    def test_refused_status_returns_false(self):
        self.x.status = lambda: 0xC0010007  # a DA error status
        self.x.eh = SimpleNamespace(status=lambda s: "refused")
        self.assertFalse(self.x.cmd_download(0, 0x1000))
        self.assertEqual(self.x.params, [])  # no data sent when the cmd is refused


class DaWsWriteImageRoutingTest(unittest.TestCase):
    """da_ws_write_image must route to the DA download() when da_download=True."""

    def _handler(self, has_download=True):
        import os
        from mtkclient.Library.DA.mtk_da_handler import DaHandler
        calls = []
        da = SimpleNamespace()
        if has_download:
            da.download = lambda **kw: (calls.append(kw), True)[1]
        daloader = SimpleNamespace(
            da=da,
            writeflash=lambda **kw: (calls.append(("writeflash", kw)), True)[1])
        h = DaHandler.__new__(DaHandler)
        h.mtk = SimpleNamespace(daloader=daloader)
        for m in ("info", "debug", "warning", "error"):
            setattr(h, m, lambda *a, **k: None)
        return h, calls

    def _img(self, sparse=False):
        import tempfile, os
        from struct import pack
        fd, path = tempfile.mkstemp(suffix=".img")
        with os.fdopen(fd, "wb") as wf:
            if sparse:
                wf.write(pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 4096, 1, 1, 0))
                wf.write(pack("<HHII", 0xCAC1, 0, 1, 12 + 4096) + b"\x00" * 4096)
            else:
                wf.write(b"\x11" * 4096)
        self.addCleanup(os.remove, path)
        return path

    def test_routes_to_da_download(self):
        h, calls = self._handler(has_download=True)
        path = self._img(sparse=True)
        ok = h.da_ws_write_image("super", path, 0x8000, None, da_download=True)
        self.assertTrue(ok)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["addr"], 0x8000)
        self.assertTrue(calls[0]["sparse"])

    def test_falls_back_when_no_download(self):
        h, calls = self._handler(has_download=False)
        path = self._img(sparse=False)
        ok = h.da_ws_write_image("boot", path, 0x8000, None, da_download=True)
        self.assertTrue(ok)
        # no da.download -> host-side writeflash used
        self.assertTrue(any(c[0] == "writeflash" for c in calls if isinstance(c, tuple)))


if __name__ == "__main__":
    unittest.main()
