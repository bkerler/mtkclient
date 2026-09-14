#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""Tests for the v6 FLASH-ALL file resolver and orchestrator dispatch."""
import os
import tempfile
import unittest

from mtkclient.Library.DA.mtk_da_handler import ws_file_resolver


class ResolverTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.scatter = os.path.join(self.dir, "MT6765_Android_scatter.txt")
        open(self.scatter, "w").close()
        with open(self.scatter, "w") as f: f.write("scatter")
        for img in ("boot.img", "super.img"):
            with open(os.path.join(self.dir, img), "wb") as f: f.write(b"x")
        self.r = ws_file_resolver(self.scatter, self.dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_scatter_request_maps_to_scatter(self):
        self.assertEqual(self.r("D:/scatter.xml"), self.scatter)
        self.assertEqual(self.r("scatter.xml"), self.scatter)
        self.assertEqual(self.r("D:/MT6765_Android_scatter.txt"), self.scatter)

    def test_image_request_maps_by_basename(self):
        self.assertEqual(self.r("D:/boot.img"), os.path.join(self.dir, "boot.img"))
        self.assertEqual(self.r("C:\\path\\super.img"), os.path.join(self.dir, "super.img"))

    def test_unknown_returns_none(self):
        self.assertIsNone(self.r("D:/nonexistent.img"))


class DispatchTest(unittest.TestCase):
    """da_ws must delegate to DA.flash_all when the DA exposes it (v6/XML)."""

    def test_v6_dispatch(self):
        from types import SimpleNamespace
        from mtkclient.Library.DA.mtk_da_handler import DaHandler
        calls = []
        da = SimpleNamespace(flash_all=lambda resolver, update=False: (
            calls.append(("flash_all", update, resolver("D:/scatter.xml"))), True)[1])
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        scatterfile = os.path.join(d, "MT6765_Android_scatter.txt")
        # minimal valid eMMC v1 scatter
        with open(scatterfile, "w") as _f: _f.write(
            "- general: MTK_PLATFORM_CFG\n  info:\n    - config_version: V1.1.2\n"
            "      storage: EMMC\n      block_size: 0x20000\n\n"
            "- partition_index: SYS0\n  partition_name: boot\n  file_name: NONE\n"
            "  is_download: false\n  linear_start_addr: 0x8000\n  partition_size: 0x1000\n"
            "  region: EMMC_USER\n  operation_type: UPDATE\n")
        h = DaHandler.__new__(DaHandler)
        h.mtk = SimpleNamespace(daloader=SimpleNamespace(da=da))
        h.config = SimpleNamespace(pagesize=512)
        for m in ("info", "debug", "warning", "error"):
            setattr(h, m, lambda *a, **k: None)
        h.close = lambda *a, **k: None
        ok = h.da_ws(scatterfile, repartition=True)
        self.assertTrue(ok)
        self.assertEqual(calls[0][0], "flash_all")
        self.assertTrue(calls[0][1])  # update=True passed through from repartition
        self.assertEqual(calls[0][2], scatterfile)  # resolver maps scatter request


if __name__ == "__main__":
    unittest.main()
