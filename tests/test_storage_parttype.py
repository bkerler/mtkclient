#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
Regression test for the preloader partition-type mapping.

The bug this guards against: the scatter's preloader region (EMMC_BOOT1_BOOT2)
must resolve to DA partition type MTK_DA_EMMC_BOOT1_BOOT2 (10), which makes the
DA build the EMMC_BOOT/BRLYT boot-region wrapper. Mapping it to a raw "boot1"
(type 1) write instead flashes the bare preloader and the device drops to BROM.
"""
import unittest
from types import SimpleNamespace

from mtkclient.Library.DA.storage import Storage, EmmcPartitionType, DaStorage
from mtkclient.config.brom_config import DAmodes


def make_storage():
    # Build via __new__ to skip the LogBase logger setup; the mapping only needs
    # damode, flashtype and the emmc sizes.
    si = Storage.__new__(Storage)
    si.mtk = SimpleNamespace(config=SimpleNamespace(
        chipconfig=SimpleNamespace(damode=DAmodes.XFLASH)))
    si.error = lambda *a, **k: None
    si.flashtype = "emmc"
    si.emmc = SimpleNamespace(
        boot1_size=0x400000, boot2_size=0x400000, rpmb_size=0x400000,
        gp1_size=0, gp2_size=0, gp3_size=0, gp4_size=0, user_size=0x747c00000)
    return si


class PreloaderParttypeTest(unittest.TestCase):
    def setUp(self):
        self.si = make_storage()

    def test_boot_maps_to_boot1_boot2(self):
        for name in ("boot", "boot1_boot2", "preloader"):
            storage, parttype, length = self.si.get_storage(name, 0x40000)
            self.assertEqual(parttype, EmmcPartitionType.MTK_DA_EMMC_BOOT1_BOOT2,
                             f"{name} must map to type 10, not {parttype}")
            self.assertEqual(parttype, 10)

    def test_boot_differs_from_raw_boot1(self):
        _, boot, _ = self.si.get_storage("boot", 0x40000)
        _, boot1, _ = self.si.get_storage("boot1", 0x40000)
        self.assertNotEqual(boot, boot1)
        self.assertEqual(boot1, EmmcPartitionType.MTK_DA_EMMC_PART_BOOT1)

    def test_boot_length_capped_to_boot1_size(self):
        _, _, length = self.si.get_storage("boot", 0x99999999)
        self.assertEqual(length, 0x400000)


if __name__ == "__main__":
    unittest.main()
