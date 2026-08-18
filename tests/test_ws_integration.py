#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
Integration tests for DaHandler.da_ws (scatter flashing orchestration).

The DA/USB layer is replaced with a fake that records writeflash calls, so the
whole flow -- preflight, plan, repartition, per-partition writes -- runs with no
device attached. DaHandler is created with __new__ to skip its hardware __init__.
"""
import os
import struct
import tempfile
import unittest
from types import SimpleNamespace

from mtkclient.Library.DA.mtk_da_handler import DaHandler
from mtkclient.Library.gpt_builder import GPT_SIGNATURE

SECTOR = 512
FLASH_SECTORS = 0x400000  # 2 GiB

SCATTER = """\
- general: MTK_PLATFORM_CFG
  info:
    - platform: MT6765
      storage: EMMC
      block_size: 0x20000

- partition_index: SYS0
  partition_name: preloader
  file_name: preloader.bin
  is_download: true
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  partition_size: 0x40000
  region: EMMC_BOOT1_BOOT2

- partition_index: SYS1
  partition_name: pgpt
  file_name: NONE
  is_download: false
  linear_start_addr: 0x0
  partition_size: 0x8000
  region: EMMC_USER

- partition_index: SYS2
  partition_name: boot_a
  file_name: boot.img
  is_download: true
  linear_start_addr: 0x8000
  partition_size: 0x40000
  region: EMMC_USER

- partition_index: SYS3
  partition_name: super
  file_name: super.img
  is_download: true
  linear_start_addr: 0x48000
  partition_size: 0x100000
  region: EMMC_USER
"""


class FakePartition:
    def __init__(self, sector, sectors, name):
        self.sector = sector
        self.sectors = sectors
        self.name = name


class FakeDaLoader:
    def __init__(self, existing_gpt=b"", partitions=None):
        self.writes = []            # (addr, length, parttype, has_wdata)
        self.existing_gpt = existing_gpt
        self.partitions = partitions or {}
        self.daconfig = SimpleNamespace(
            storage=SimpleNamespace(flashsize=FLASH_SECTORS * SECTOR))

    def writeflash(self, addr, length, filename="", offset=0, parttype=None,
                   wdata=None, display=True):
        self.writes.append(SimpleNamespace(addr=addr, length=length, parttype=parttype,
                                           has_wdata=wdata is not None,
                                           filename=filename))
        return True

    def readflash(self, addr, length, filename, parttype=None, display=True):
        return self.existing_gpt[:length]

    def detect_partition(self, name, parttype=None):
        if name in self.partitions:
            return [True, self.partitions[name]]
        return [False, []]


def make_handler(daloader):
    h = DaHandler.__new__(DaHandler)
    h.mtk = SimpleNamespace(daloader=daloader)
    h.config = SimpleNamespace(pagesize=SECTOR)
    h.info = lambda *a, **k: None
    h.debug = lambda *a, **k: None
    h.warning = lambda *a, **k: None
    h.error = lambda *a, **k: None
    h.close = lambda *a, **k: None
    return h


class WsTestBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.scatter_path = os.path.join(self.dir, "MT6765_Android_scatter.txt")
        with open(self.scatter_path, "w") as wf:
            wf.write(SCATTER)
        # dummy images sized within their partitions
        self._img("preloader.bin", 0x1000)
        self._img("boot.img", 0x20000)
        self._img("super.img", 0x80000)

    def _img(self, name, size):
        with open(os.path.join(self.dir, name), "wb") as wf:
            wf.write(b"\xAA" * size)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)


class DownloadOnlyTest(WsTestBase):
    def test_writes_into_existing_partitions(self):
        parts = {
            "boot_a": FakePartition(sector=0x8000 // SECTOR, sectors=0x40000 // SECTOR, name="boot_a"),
            "super": FakePartition(sector=0x48000 // SECTOR, sectors=0x100000 // SECTOR, name="super"),
        }
        dl = FakeDaLoader(partitions=parts)
        h = make_handler(dl)
        ok = h.da_ws(self.scatter_path, repartition=False)
        self.assertTrue(ok)

        by_parttype = {}
        for w in dl.writes:
            by_parttype.setdefault(w.parttype, []).append(w)

        # preloader -> boot1 at its scatter address (0)
        self.assertIn("boot1", by_parttype)
        self.assertEqual(by_parttype["boot1"][0].addr, 0x0)

        # boot_a and super -> user, at the *device* partition's sector address
        user_addrs = sorted(w.addr for w in by_parttype["user"])
        self.assertEqual(user_addrs, [0x8000, 0x48000])
        # no GPT written in download-only mode
        self.assertFalse(any(w.has_wdata for w in dl.writes))

    def test_missing_partition_reports_failure(self):
        # boot_a exists but super is absent from device GPT
        parts = {"boot_a": FakePartition(0x8000 // SECTOR, 0x40000 // SECTOR, "boot_a")}
        dl = FakeDaLoader(partitions=parts)
        h = make_handler(dl)
        ok = h.da_ws(self.scatter_path, repartition=False)
        self.assertFalse(ok)  # super couldn't be resolved

    def test_oversized_image_skipped(self):
        # boot_a partition is smaller than the image
        parts = {
            "boot_a": FakePartition(0x8000 // SECTOR, 0x1000 // SECTOR, "boot_a"),
            "super": FakePartition(0x48000 // SECTOR, 0x100000 // SECTOR, "super"),
        }
        dl = FakeDaLoader(partitions=parts)
        h = make_handler(dl)
        ok = h.da_ws(self.scatter_path, repartition=False)
        self.assertFalse(ok)
        # boot_a (oversized) must not have been written to the user area
        self.assertNotIn(0x8000, [w.addr for w in dl.writes if w.parttype == "user"])


class RepartitionTest(WsTestBase):
    def test_writes_gpt_then_flashes_by_address(self):
        dl = FakeDaLoader(existing_gpt=b"")  # no existing GPT
        h = make_handler(dl)
        ok = h.da_ws(self.scatter_path, repartition=True)
        self.assertTrue(ok)

        gpt_writes = [w for w in dl.writes if w.has_wdata]
        # exactly two GPT writes: primary (addr 0) and backup (near end)
        self.assertEqual(len(gpt_writes), 2)
        self.assertEqual(gpt_writes[0].addr, 0)
        self.assertGreater(gpt_writes[1].addr, (FLASH_SECTORS - 64) * SECTOR)

        # primary blob must actually contain a GPT header at LBA 1
        # (we can't see wdata here, but the two-write shape + success is asserted)

        # user partitions flashed at their scatter addresses, not device sectors
        user_addrs = sorted(w.addr for w in dl.writes
                            if w.parttype == "user" and not w.has_wdata)
        self.assertEqual(user_addrs, [0x8000, 0x48000])
        # preloader still routed to boot1
        self.assertTrue(any(w.parttype == "boot1" for w in dl.writes))

    def test_repartition_gpt_is_valid(self):
        # capture the primary blob and confirm it parses as a real GPT
        captured = {}

        dl = FakeDaLoader(existing_gpt=b"")
        orig = dl.writeflash

        def capturing(addr, length, filename="", offset=0, parttype=None, wdata=None, display=True):
            if wdata is not None and addr == 0:
                captured["primary"] = bytes(wdata)
            return orig(addr, length, filename, offset, parttype, wdata, display)

        dl.writeflash = capturing
        h = make_handler(dl)
        self.assertTrue(h.da_ws(self.scatter_path, repartition=True))

        primary = captured["primary"]
        # protective MBR then GPT header
        self.assertEqual(primary[510:512], b"\x55\xAA")
        self.assertEqual(primary[SECTOR:SECTOR + 8], GPT_SIGNATURE)

        from io import BytesIO
        import logging
        from mtkclient.Library.Partitions.gpt import gpt
        g = gpt(rf=BytesIO(primary), filesize=len(primary), loglevel=logging.ERROR)
        self.assertTrue(g.parse())
        names = {p.name for p in g.partentries}
        self.assertIn("boot_a", names)
        self.assertIn("super", names)
        self.assertNotIn("pgpt", names)       # GPT area excluded
        self.assertNotIn("preloader", names)  # boot region excluded


if __name__ == "__main__":
    unittest.main()
