#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
End-to-end UFS scatter flash (mocked 4096-byte UFS device): the preloader must
be wrapped in a UFS_BOOT header and written to the boot LU, and data partitions
(UFS_LU2) written to the user LU, with the 4096-byte sector threaded through.
"""
import os
import tempfile
import unittest
from types import SimpleNamespace

from mtkclient.Library.DA.mtk_da_handler import DaHandler

UFS_SECTOR = 4096

SCATTER = """\
- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.2
      platform: MT6835
      storage: UFS
      block_size: 0x20000

- partition_index: SYS0
  partition_name: preloader
  file_name: preloader.bin
  is_download: true
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  partition_size: 0x40000
  region: UFS_LU0_LU1

- partition_index: SYS1
  partition_name: boot_a
  file_name: boot.img
  is_download: true
  type: NORMAL_ROM
  linear_start_addr: 0x8000
  partition_size: 0x2000
  region: UFS_LU2
"""


class FakeUfsPartition:
    def __init__(self, sector, sectors):
        self.sector = sector
        self.sectors = sectors


class FakeUfsDaLoader:
    def __init__(self):
        self.writes = []
        self.daconfig = SimpleNamespace(
            storage=SimpleNamespace(flashsize=0x40000000, flashtype="ufs"))
        self.da = SimpleNamespace()  # no flash_all -> not the v6 path

    def readflash(self, addr, length, filename, parttype=None, display=True):
        return b""  # no existing GPT -> download-only layout gate allows

    def detect_partition(self, name, parttype=None):
        return [True, FakeUfsPartition(sector=0x8000 // UFS_SECTOR, sectors=0x2000 // UFS_SECTOR)]

    def writeflash(self, addr, length, filename="", offset=0, parttype=None,
                   wdata=None, display=True):
        self.writes.append(SimpleNamespace(addr=addr, parttype=parttype,
                                           wdata=bytes(wdata) if wdata else None,
                                           filename=filename))
        return True


class UfsFlashTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "MT6835_Android_scatter.txt"), "w") as f:
            f.write(SCATTER)
        self.scatter = os.path.join(self.dir, "MT6835_Android_scatter.txt")
        with open(os.path.join(self.dir, "preloader.bin"), "wb") as f:
            f.write(b"MMM\x01" + b"\x00" * 0x2000)   # bare GFH preloader
        with open(os.path.join(self.dir, "boot.img"), "wb") as f:
            f.write(b"\xAA" * 0x2000)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _handler(self, dl):
        h = DaHandler.__new__(DaHandler)
        h.mtk = SimpleNamespace(daloader=dl)
        h.config = SimpleNamespace(pagesize=UFS_SECTOR)
        for m in ("info", "debug", "warning", "error"):
            setattr(h, m, lambda *a, **k: None)
        h.close = lambda *a, **k: None
        return h

    def test_ufs_download_only(self):
        dl = FakeUfsDaLoader()
        h = self._handler(dl)
        ok = h.da_ws(self.scatter, repartition=False)
        self.assertTrue(ok)

        by = {}
        for w in dl.writes:
            by.setdefault(w.parttype, []).append(w)

        # preloader -> boot1 LU, wrapped in a UFS_BOOT header
        self.assertIn("boot1", by)
        pre = by["boot1"][0]
        self.assertEqual(pre.addr, 0)
        self.assertTrue(pre.wdata.startswith(b"UFS_BOOT"))

        # boot_a (UFS_LU2) -> user LU at the device sector (0x8000/4096 = 8)
        self.assertIn("user", by)
        self.assertEqual(by["user"][0].addr, 0x8000)


if __name__ == "__main__":
    unittest.main()
