#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
NAND/NOR/COMBO scatters must be flashed via the DA (PMT/BMT/boot header are
DA-managed): da_ws forces the DA download path, skips host-side repartition,
and routes the preloader through the DA (which builds the NAND boot header).
"""
import os
import tempfile
import unittest
from types import SimpleNamespace

from mtkclient.Library.DA.mtk_da_handler import DaHandler

PAGE = 2048

SCATTER = """\
- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.2
      platform: MT6261
      storage: NAND
      block_size: 0x20000

- partition_index: SYS0
  partition_name: preloader
  file_name: preloader.bin
  is_download: true
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  partition_size: 0x40000
  region: NAND_BOOT1

- partition_index: SYS1
  partition_name: android
  file_name: android.img
  is_download: true
  type: UBI_IMG
  linear_start_addr: 0x80000
  partition_size: 0x100000
  region: NAND_GP1
"""


class FakeNandDaLoader:
    def __init__(self):
        self.downloads = []
        self.writeflashes = []
        self.da = SimpleNamespace(
            download=lambda **kw: (self.downloads.append(kw), True)[1])
        self.daconfig = SimpleNamespace(
            storage=SimpleNamespace(flashsize=0x8000000, flashtype="nand"))

    def readflash(self, addr, length, filename, parttype=None, display=True):
        return b""  # no GPT -> layout gate allows

    def detect_partition(self, name, parttype=None):
        return [True, SimpleNamespace(sector=0x80000 // PAGE, sectors=0x100000 // PAGE)]

    def writeflash(self, **kw):
        self.writeflashes.append(kw)
        return True


class NandDispatchTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "MT6261_Android_scatter.txt"), "w") as f:
            f.write(SCATTER)
        self.scatter = os.path.join(self.dir, "MT6261_Android_scatter.txt")
        for n in ("preloader.bin", "android.img"):
            with open(os.path.join(self.dir, n), "wb") as f:
                f.write(b"\x11" * 0x1000)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _handler(self, dl):
        h = DaHandler.__new__(DaHandler)
        h.mtk = SimpleNamespace(daloader=dl)
        h.config = SimpleNamespace(pagesize=PAGE)
        for m in ("info", "debug", "warning", "error"):
            setattr(h, m, lambda *a, **k: None)
        h.close = lambda *a, **k: None
        return h

    def test_nand_routes_through_da(self):
        dl = FakeNandDaLoader()
        h = self._handler(dl)
        # even with repartition requested, NAND must NOT build a host GPT
        ok = h.da_ws(self.scatter, repartition=True)
        self.assertTrue(ok)
        # both preloader and the data partition went through the DA download
        parttypes = [d["parttype"] for d in dl.downloads]
        self.assertIn("boot1", parttypes)   # preloader via DA
        self.assertIn("user", parttypes)    # data partition via DA
        # no host-side GPT/raw writeflash happened
        self.assertEqual(dl.writeflashes, [])


if __name__ == "__main__":
    unittest.main()
