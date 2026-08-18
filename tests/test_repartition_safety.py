#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
Safety tests for da_ws_repartition: NEEDRESIZE handling, dynamic partition
placement from the device's real GPT, and the PROTECTED-partition guard.
"""
import io
import logging
import os
import tempfile
import unittest
from types import SimpleNamespace

from mtkclient.Library.DA.mtk_da_handler import DaHandler
from mtkclient.Library.gpt_builder import GPTBuilder, GptPartitionEntry
from mtkclient.Library.Partitions.gpt import gpt

SECTOR = 512
TOTAL_SECTORS = 0x100000  # 512 MiB

# device layout (in sectors): a protected partition, userdata, then trailing
# dynamic partitions otp/flashinfo near the end.
DEV = {
    "nvram":     (64, 127),
    "userdata":  (128, 0x40000),          # small on device; will be resized
    "otp":       (TOTAL_SECTORS - 200, TOTAL_SECTORS - 101),
    "flashinfo": (TOTAL_SECTORS - 100, TOTAL_SECTORS - 40),
}


def device_gpt():
    entries = [GptPartitionEntry(name, a, b) for name, (a, b) in DEV.items()]
    primary, _backup, _lba = GPTBuilder(sectorsize=SECTOR).build(entries, TOTAL_SECTORS)
    return primary


SCATTER = """\
- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.2
      platform: MT6765
      storage: EMMC
      block_size: 0x20000

- partition_index: SYS0
  partition_name: nvram
  file_name: NONE
  is_download: false
  linear_start_addr: {nvram_addr}
  partition_size: 0x8000
  region: EMMC_USER
  operation_type: BINREGION

- partition_index: SYS1
  partition_name: userdata
  file_name: NONE
  is_download: false
  linear_start_addr: 0x10000
  partition_size: 0x40000
  region: EMMC_USER
  operation_type: NEEDRESIZE

- partition_index: SYS2
  partition_name: otp
  file_name: NONE
  is_download: false
  linear_start_addr: 0xFFFF01d8
  partition_size: 0xc800
  region: EMMC_USER
  operation_type: RESERVED

- partition_index: SYS3
  partition_name: flashinfo
  file_name: NONE
  is_download: false
  linear_start_addr: 0xFFFF0080
  partition_size: 0x7800
  region: EMMC_USER
  operation_type: RESERVED
"""


class FakeDaLoader:
    def __init__(self, gpt_bytes):
        self.gpt_bytes = gpt_bytes
        self.writes = []
        self.daconfig = SimpleNamespace(
            storage=SimpleNamespace(flashsize=TOTAL_SECTORS * SECTOR, flashtype="emmc"))

    def readflash(self, addr, length, filename, parttype=None, display=True):
        data = self.gpt_bytes[:length].ljust(length, b"\x00") if addr == 0 \
            else b"\xBB" * length  # stand-in device content for backups
        if filename:
            with open(filename, "wb") as wf:
                wf.write(data)
            return True
        return data

    def writeflash(self, addr, length, filename="", offset=0, parttype=None,
                   wdata=None, display=True):
        self.writes.append(SimpleNamespace(addr=addr, parttype=parttype,
                                           wdata=bytes(wdata) if wdata else None))
        return True

    def formatflash(self, addr, length, partitionname, parttype, display=True):
        if not hasattr(self, "formats"):
            self.formats = []
        self.formats.append(SimpleNamespace(addr=addr, length=length, name=partitionname))
        return True


def make_handler(daloader):
    h = DaHandler.__new__(DaHandler)
    h.mtk = SimpleNamespace(daloader=daloader)
    h.config = SimpleNamespace(pagesize=SECTOR)
    for m in ("info", "debug", "warning", "error"):
        setattr(h, m, lambda *a, **k: None)
    h.close = lambda *a, **k: None
    return h


def write_scatter(nvram_addr):
    fd, path = tempfile.mkstemp(suffix="_scatter.txt")
    with os.fdopen(fd, "w") as wf:
        wf.write(SCATTER.format(nvram_addr=nvram_addr))
    return path


class RepartitionSafetyTest(unittest.TestCase):
    def setUp(self):
        from mtkclient.Library.scatter import Scatter
        self.Scatter = Scatter

    def _run(self, nvram_addr, allow_data_loss=False):
        import shutil
        path = write_scatter(nvram_addr)
        self.addCleanup(os.remove, path)
        backup_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, backup_dir, True)
        scatter = self.Scatter(path)
        dl = FakeDaLoader(device_gpt())
        h = make_handler(dl)
        ok = h.da_ws_repartition(scatter, SECTOR, allow_data_loss=allow_data_loss,
                                 backup_dir=backup_dir)
        return ok, dl, backup_dir

    def _parse_written_primary(self, dl):
        primary = next(w.wdata for w in dl.writes if w.addr == 0 and w.parttype == "user")
        g = gpt(rf=io.BytesIO(primary), filesize=len(primary), loglevel=logging.ERROR)
        self.assertTrue(g.parse())
        return {p.name: p for p in g.partentries}

    def test_dynamic_partitions_placed_from_device(self):
        # nvram unchanged -> no conflict; otp/flashinfo taken from device GPT
        ok, dl, _bk = self._run(nvram_addr=64 * SECTOR)
        self.assertTrue(ok)
        parts = self._parse_written_primary(dl)
        self.assertIn("otp", parts)
        self.assertIn("flashinfo", parts)
        self.assertEqual(parts["otp"].sector, DEV["otp"][0])
        self.assertEqual(parts["flashinfo"].sector, DEV["flashinfo"][0])

    def test_userdata_resized_before_dynamic(self):
        ok, dl, _bk = self._run(nvram_addr=64 * SECTOR)
        self.assertTrue(ok)
        parts = self._parse_written_primary(dl)
        ud = parts["userdata"]
        earliest_dynamic = min(DEV["otp"][0], DEV["flashinfo"][0])
        end = ud.sector + ud.sectors
        # userdata must not run into the first dynamic partition ...
        self.assertLessEqual(end, earliest_dynamic)
        # ... its end is rounded down to the erase block (0x20000 / 512 = 256) ...
        self.assertEqual(end % 256, 0)
        self.assertGreater(end, earliest_dynamic - 256)  # but only by the alignment slack
        # ... and it's far bigger than the scatter's placeholder 0x40000
        self.assertGreater(ud.sectors, 0x40000)

    def test_protected_move_aborts(self):
        # move nvram -> must refuse without allow_data_loss
        ok, dl, _bk = self._run(nvram_addr=0x9000)  # different from device (64 sectors)
        self.assertFalse(ok)
        self.assertEqual(dl.writes, [])  # nothing written

    def test_protected_move_allowed_with_flag(self):
        # move nvram to sector 56 (differs from device's 64) without overlapping
        # userdata (starts at sector 128); with the flag it must proceed.
        ok, dl, _bk = self._run(nvram_addr=0x7000, allow_data_loss=True)
        self.assertTrue(ok)
        self.assertTrue(any(w.addr == 0 for w in dl.writes))

    def test_protected_backed_up_and_restored_to_new_pos(self):
        # nvram moved to sector 56: it must be backed up to a file AND restored
        # by a write to the NEW sector (56) so the device-unique data survives.
        ok, dl, backup_dir = self._run(nvram_addr=0x7000, allow_data_loss=True)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(os.path.join(backup_dir, "nvram.img")))
        restore = [w for w in dl.writes if w.parttype == "user" and w.addr == 56 * SECTOR]
        self.assertEqual(len(restore), 1, "nvram must be restored to its new sector")

    def test_no_move_still_backs_up(self):
        # even with no move, protected data is backed up before touching the table
        ok, dl, backup_dir = self._run(nvram_addr=64 * SECTOR)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(os.path.join(backup_dir, "nvram.img")))

    def test_resized_userdata_is_formatted(self):
        # the grown userdata must be formatted to its new full size
        ok, dl, _bk = self._run(nvram_addr=64 * SECTOR)
        self.assertTrue(ok)
        fmts = [f for f in getattr(dl, "formats", []) if f.name == "userdata"]
        self.assertEqual(len(fmts), 1)
        parts = self._parse_written_primary(dl)
        ud = parts["userdata"]
        self.assertEqual(fmts[0].addr, ud.sector * SECTOR)
        self.assertEqual(fmts[0].length, ud.sectors * SECTOR)


if __name__ == "__main__":
    unittest.main()
