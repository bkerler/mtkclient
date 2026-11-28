#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) Daniel Kamyshan 2026, ported from SP Flash Tool (FlashtoollibEx / flash_tool)
# Licensed under GPLv3 License
#
# Image checksum pipeline for mtkclient.
#
# Ported from SP Flash Tool V5/V6 (see begonia-kernel-research/
# spft-decompile-2026-11-24.md, section "Чексуммы"):
#  - FlashtoollibEx checksum classes chksum_crc32 / chksum_add with the shared
#    chksum_factory (.?AVchksum_crc32@@ / .?AVchksum_add@@ / chksum_factory)
#  - flash_tool Rules\ChksumRule.cpp: ChksumRule::IniChksumMap,
#    ChksumRule::QueryChksumByImageName - per-image checksum values loaded from
#    "Checksum.ini" next to the firmware images
#    ("Checksum File(%s) is not found!", "Checksum Value for (%s) is not found
#    in the map.", "chksum name(%s), chksum value(0x%x)")
#  - AppCore::VerifyImageChksum / "skip chksum for rom(%s)"
#  - V6 write-path hook ConsoleMode::ConsoleModeRunner::imageChksumVerify /
#    AsyncFlashXMLLoader::imageChksumVerify ("Begin verify load images
#    checksum", "verify load images checksum done!", "image checksum mismatch")
#
# The chksum_level (NONE/USB/STORAGE/USB-STORAGE) is the DA-side runtime
# parameter and already exists in xml_cmd.cmd_set_runtime_parameter; this
# module supplies the missing host-side half: compute the load-image checksum
# and verify it on the write path.
#
# chksum_add is the classic MTK additive checksum (Brom_Checksum16Cmd
# heritage): a 32-bit sum over little-endian 16-bit words, zero-padding an
# odd trailing byte. chksum_crc32 is the standard CRC-32 (zlib polynomial).
import logging
import os
import zlib

from mtkclient.Library.gui_utils import LogBase, logsetup


class chksum_crc32:
    """Standard CRC-32 image checksum (FlashtoollibEx chksum_crc32)."""
    name = "CRC32"

    @staticmethod
    def calc(data: bytes) -> int:
        return zlib.crc32(data) & 0xFFFFFFFF


class chksum_add:
    """
    Additive image checksum (FlashtoollibEx chksum_add): 32-bit sum of
    little-endian 16-bit words; an odd trailing byte counts as one zero-padded
    word.
    """
    name = "ADD"

    @staticmethod
    def calc(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for i in range(0, len(data), 2):
            total = (total + int.from_bytes(data[i:i + 2], "little")) & 0xFFFFFFFF
        return total


_CHKSUM_TYPES = {
    "CRC32": chksum_crc32,
    "ADD": chksum_add,
}


def chksum_factory(chksum_type: str = "CRC32"):
    """FlashtoollibEx chksum_factory: checksum type name -> checksummer."""
    key = str(chksum_type or "").upper()
    if key not in _CHKSUM_TYPES:
        raise ValueError(f"Unsupported checksum type: {chksum_type} "
                         f"(known: {', '.join(sorted(_CHKSUM_TYPES))})")
    return _CHKSUM_TYPES[key]()


def VerifyImageChksum(image_name: str, data: bytes, expected: int,
                      chksum_type: str = "CRC32") -> bool:
    """
    AppCore::VerifyImageChksum: compute the checksum of a load image and
    compare it against the expected value (from Checksum.ini). Returns True on
    match, False on mismatch ("image checksum mismatch").
    """
    chk = chksum_factory(chksum_type)
    value = chk.calc(data)
    if value != expected:
        return False
    return True


class ChksumRule(metaclass=LogBase):
    """
    Per-image checksum map (flash_tool Rules\\ChksumRule.cpp).

    IniChksumMap() loads "Checksum.ini" - an INI whose keys are image file
    names (case-insensitive) and whose values are 32-bit checksums (hex or
    decimal); sections and comments are ignored. QueryChksumByImageName()
    looks an image up; unknown images return None, which callers treat as
    "skip chksum for rom(%s)" (SPFT does not verify images without a rule).
    """

    def __init__(self, chksum_type: str = "CRC32", loglevel=logging.INFO):
        self.chksum_type = str(chksum_type).upper()
        self.chksum_map = {}
        self.__logger, self.info, self.debug, self.warning, self.error = \
            logsetup(self, self.__logger, loglevel)

    def IniChksumMap(self, checksum_ini: str) -> int:
        """
        Load the per-image checksum map from a Checksum.ini file. Returns the
        number of entries; a missing file is logged and returns 0 (SPFT:
        "Checksum File(%s) is not found!") instead of raising.
        """
        self.chksum_map = {}
        if not os.path.exists(checksum_ini):
            self.error(f"Checksum File({checksum_ini}) is not found!")
            return 0
        with open(checksum_ini, "r", encoding="utf-8", errors="replace") as rf:
            for line in rf:
                line = line.strip()
                if (not line or line.startswith("#") or line.startswith(";")
                        or line.startswith("[")):
                    continue
                if "=" not in line:
                    continue
                name, _, value = line.partition("=")
                name = name.strip().lower()
                value = value.strip()
                try:
                    self.chksum_map[name] = int(value, 0)
                except ValueError:
                    self.error(f"Invalid checksum value for {name}: {value}")
                    continue
        return len(self.chksum_map)

    def QueryChksumByImageName(self, image_name: str):
        """
        Return the expected checksum of an image, or None when the map has no
        entry for it (SPFT: "Checksum Value for (%s) is not found in the
        map.").
        """
        key = str(image_name or "").strip().lower()
        if key not in self.chksum_map:
            return None
        return self.chksum_map[key]

    def verify_image(self, image_name: str, data: bytes) -> bool:
        """
        Verify a load image against its rule entry. Unknown images are skipped
        (True, SPFT: "skip chksum for rom(%s)."); known images are checked with
        the rule's checksum type.
        """
        expected = self.QueryChksumByImageName(image_name)
        if expected is None:
            return True
        if not VerifyImageChksum(image_name, data, expected,
                                 chksum_type=self.chksum_type):
            self.error(f"image checksum mismatch: {image_name} "
                       f"(expected 0x{expected:08x}, "
                       f"{self.chksum_type} over {len(data)} bytes)")
            return False
        return True
