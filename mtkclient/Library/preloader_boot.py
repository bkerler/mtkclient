#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
Build the MTK eMMC boot-region wrapper (EMMC_BOOT + BRLYT) around a preloader.

On MediaTek eMMC the boot1 partition does not hold the bare preloader. The BROM
reads a fixed layout at offset 0:

    0x000  "EMMC_BOOT\\0\\0\\0"            (12 bytes identifier)
    0x00C  u32 bl_exist   = 1
    0x010  u32 dev_rw_unit = 0x200        (eMMC sector size)
    0x014  0xFF padding .. 0x200
    0x200  "BRLYT\\0\\0\\0"                (8 bytes)
    0x208  u32 info_ver   = 1
    0x20C  u32 boot_region_addr = 0x800   (where the preloader begins)
    0x210  u32 main_region_addr = 0x40800 (region boundary)
    0x214  u32 magic       = 0x42424242   ("BBBB")
    0x218  u32 type        = 0x00010005
    0x21C  u32 begin_dev_addr    = 0x800
    0x220  u32 boundary_dev_addr = 0x40800
    0x224  u32 attr        = 1
    0x228  0x00 padding .. 0x800
    0x800  preloader payload (GFH "MMM\\x01 FILE_INFO ...")

SP Flash Tool builds this header in software and writes header+preloader to
boot1; the download agent writes it raw. Writing the bare preloader at offset 0
(as a plain boot1 write does) leaves no valid BRLYT, so the BROM finds no
bootloader and the device drops to BROM/download mode.

The header is constant for a given platform (it only points at the preloader
region), so we reproduce it byte-for-byte. Values verified against a real
k62v1_64_bsp (MT6765) boot1 dump.
"""
from struct import pack

EMMC_BOOT_MAGIC = b"EMMC_BOOT\x00\x00\x00"
BRLYT_MAGIC = b"BRLYT\x00\x00\x00"
BRLYT_BBBB = 0x42424242

HEADER_SIZE = 0x800            # preloader starts here
PRELOADER_REGION_BEGIN = 0x800
DEFAULT_REGION_SIZE = 0x40000  # 256 KiB main region (boundary = begin + size)
DEFAULT_DEV_RW_UNIT = 0x200    # eMMC sector


def is_wrapped(data: bytes) -> bool:
    """True if data already begins with an EMMC_BOOT boot-region header."""
    return data[:9] == b"EMMC_BOOT"


def build_boot_header(dev_rw_unit: int = DEFAULT_DEV_RW_UNIT,
                      region_size: int = DEFAULT_REGION_SIZE) -> bytes:
    begin = PRELOADER_REGION_BEGIN
    boundary = begin + region_size
    hdr = bytearray(b"\xFF" * HEADER_SIZE)

    # EMMC_BOOT header @ 0x000
    hdr[0x000:0x00C] = EMMC_BOOT_MAGIC
    hdr[0x00C:0x010] = pack("<I", 1)            # bl_exist
    hdr[0x010:0x014] = pack("<I", dev_rw_unit)  # dev_rw_unit
    # 0x014..0x1FF stays 0xFF

    # BRLYT @ 0x200. The block is 0x00-padded except for an erased 0xFF island
    # at 0x2b4..0x400 (relative 0xb4..0x200) -- reproduced to match the device's
    # own boot1 layout byte-for-byte.
    brlyt = bytearray(HEADER_SIZE - 0x200)
    brlyt[0xB4:0x200] = b"\xFF" * (0x200 - 0xB4)
    brlyt[0x00:0x08] = BRLYT_MAGIC
    brlyt[0x08:0x0C] = pack("<I", 1)          # info_ver
    brlyt[0x0C:0x10] = pack("<I", begin)      # boot_region_addr
    brlyt[0x10:0x14] = pack("<I", boundary)   # main_region_addr
    brlyt[0x14:0x18] = pack("<I", BRLYT_BBBB)
    brlyt[0x18:0x1C] = pack("<I", 0x00010005)  # type
    brlyt[0x1C:0x20] = pack("<I", begin)      # descriptor begin_dev_addr
    brlyt[0x20:0x24] = pack("<I", boundary)   # descriptor boundary_dev_addr
    brlyt[0x24:0x28] = pack("<I", 1)          # descriptor attr
    hdr[0x200:HEADER_SIZE] = brlyt
    return bytes(hdr)


def wrap_preloader(preloader: bytes, dev_rw_unit: int = DEFAULT_DEV_RW_UNIT,
                   region_size: int = DEFAULT_REGION_SIZE) -> bytes:
    """Return EMMC_BOOT header + preloader, ready to write raw to boot1.

    If the input is already wrapped it is returned unchanged. Raises ValueError
    if the preloader is too big for the boot region.
    """
    if is_wrapped(preloader):
        return preloader
    if len(preloader) > region_size:
        raise ValueError(f"preloader ({len(preloader)} bytes) exceeds boot region "
                         f"({region_size} bytes)")
    return build_boot_header(dev_rw_unit, region_size) + preloader
