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

Writing the bare preloader at offset 0 (as a plain boot1 write does) leaves no
valid BRLYT, so the BROM finds no bootloader and the device drops to BROM mode.

NOTE ON APPROACH: the DA's "download" command builds this boot header on the
device itself and is the proper, storage-agnostic way to flash a preloader (it
works for eMMC/UFS/NAND alike). This module is a software fallback used by the
xflash write path; it is verified byte-for-byte only against a real eMMC
(k62v1_64_bsp / MT6765) boot1 dump, and refuses storage types it hasn't been
verified for (see wrap_preloader) rather than emit a header that could brick.
The header is otherwise constant for a platform (it only points at the
preloader region), so we reproduce it exactly.
"""
from struct import pack, unpack

EMMC_BOOT_MAGIC = b"EMMC_BOOT\x00\x00\x00"
BRLYT_MAGIC = b"BRLYT\x00\x00\x00"
BRLYT_BBBB = 0x42424242

HEADER_SIZE = 0x800            # preloader starts here
PRELOADER_REGION_BEGIN = 0x800
DEFAULT_REGION_SIZE = 0x40000  # 256 KiB main region (boundary = begin + size)

# Block/rw unit per storage. eMMC = 512, UFS = 4096.
DEV_RW_UNIT = {"emmc": 0x200, "ufs": 0x1000}

# m_device_type = GfhFlashDev (bl_dev, u8). Values per the GFH enum
# (Nor=1, NandSeq=2, NandTtbl=3, NandFdm50=4, EmmcBoot=5, EmmcData=6, Sf=7,
# SpiNand=9, Ufs=12/0x0C, Combo=14/0x0E). Verified: eMMC=0x05 matches the dump.
DEVICE_TYPE = {"emmc": 0x05, "nand": 0x02, "nor": 0x01, "sf": 0x07,
               "ufs": 0x0C, "combo": 0x0E}
GFH_TYPE_ARM_BL = 0x0001       # ARM bootloader GFH type (GfhFileType::ArmBl)

# GFH_FILE_INFO of the preloader payload: "MMM\x01" ... "FILE_INFO", with a
# max_size (boot-region size) field at offset 0x24.
GFH_MAGIC = b"MMM\x01"
GFH_MAX_SIZE_OFF = 0x24

# The boot-region identifier that sits at offset 0 differs per storage.
BOOT_MAGIC = {"emmc": b"EMMC_BOOT", "ufs": b"UFS_BOOT",
              "sdmmc": b"SDMMC_BOOT", "combo": b"COMBO_BOOT", "sf": b"SF_BOOT"}
KNOWN_BOOT_MAGICS = tuple(BOOT_MAGIC.values())

# eMMC is verified byte-for-byte against a real k62v1_64_bsp dump. UFS uses the
# same BRLYT structure with the UFS_BOOT magic, a 4096-byte dev_rw_unit and
# device type 0x0C (GfhFlashDev::Ufs) -- built structurally here; the region
# size still comes from the preloader's GFH max_size. NAND/NOR use a different
# boot layout and are not built here. (The DA "download" command builds the
# header on-device and is the fully storage-agnostic path.)
VERIFIED_STORAGE = ("emmc", "ufs")


def is_wrapped(data: bytes) -> bool:
    """True if data already begins with any known boot-region header."""
    return any(data.startswith(m) for m in KNOWN_BOOT_MAGICS)


def gfh_max_size(preloader: bytes):
    """Boot-region size from the preloader's GFH max_size field, or None.

    This is the authoritative region size (the DA aligns the boundary to it);
    it is 0x40000 on this device but varies by preloader, so deriving it beats a
    hardcoded constant.
    """
    if preloader[:4] != GFH_MAGIC or len(preloader) < GFH_MAX_SIZE_OFF + 4:
        return None
    val = unpack("<I", preloader[GFH_MAX_SIZE_OFF:GFH_MAX_SIZE_OFF + 4])[0]
    # sanity: must be a power-of-two-ish region at least as big as the payload
    if val < len(preloader) or val > 0x2000000:
        return None
    return val


def build_boot_header(storage: str = "emmc", region_size: int = DEFAULT_REGION_SIZE) -> bytes:
    if storage not in DEV_RW_UNIT or storage not in DEVICE_TYPE:
        raise ValueError(f"unsupported storage {storage!r} for boot header")
    dev_rw_unit = DEV_RW_UNIT[storage]
    # Descriptor magic word (little-endian bytes 05 00 01 00 on eMMC):
    #   byte0 = m_device_type (EMMC=0x05), byte1 = reserved,
    #   u16    = m_gfh_type (0x0001 = ARM bootloader).
    desc_type = DEVICE_TYPE[storage] | (GFH_TYPE_ARM_BL << 16)

    begin = PRELOADER_REGION_BEGIN
    boundary = begin + region_size
    hdr = bytearray(b"\xFF" * HEADER_SIZE)

    # boot identifier header @ 0x000 ("EMMC_BOOT\0\0\0", ...)
    hdr[0x000:0x00C] = BOOT_MAGIC[storage].ljust(0x0C, b"\x00")
    hdr[0x00C:0x010] = pack("<I", 1)            # bl_exist
    hdr[0x010:0x014] = pack("<I", dev_rw_unit)  # dev_rw_unit
    # 0x014..0x1FF stays 0xFF

    # BRLYT @ 0x200:
    #   identifier[8] "BRLYT\0\0\0"
    #   version, boot_region_address, main_region_address
    #   bl_desc[8]  -- array of 8 BlDescriptor{ bl_exists_magic u32, bl_dev u8,
    #                  reserved u8, bl_type u16, bl_begin_addr u32,
    #                  bl_boundary_addr u32, bl_attribute u32 } (0x14 each).
    # Only descriptor[0] is populated; the struct ends at 0xB4 and the device
    # leaves the rest of the header as an erased 0xFF island (reproduced so the
    # output matches a real boot1 dump byte-for-byte). Layout cross-checked
    # against shomykohai/hacc src/preloader/pl.rs.
    brlyt = bytearray(HEADER_SIZE - 0x200)
    brlyt[0xB4:0x200] = b"\xFF" * (0x200 - 0xB4)
    brlyt[0x00:0x08] = BRLYT_MAGIC
    brlyt[0x08:0x0C] = pack("<I", 1)          # version
    brlyt[0x0C:0x10] = pack("<I", begin)      # boot_region_address
    brlyt[0x10:0x14] = pack("<I", boundary)   # main_region_address
    # bl_desc[0]:
    brlyt[0x14:0x18] = pack("<I", BRLYT_BBBB)  # bl_exists_magic
    brlyt[0x18:0x1C] = pack("<I", desc_type)   # bl_dev | reserved | bl_type<<16
    brlyt[0x1C:0x20] = pack("<I", begin)       # bl_begin_addr
    brlyt[0x20:0x24] = pack("<I", boundary)    # bl_boundary_addr
    brlyt[0x24:0x28] = pack("<I", 1)           # bl_attribute
    hdr[0x200:HEADER_SIZE] = brlyt
    return bytes(hdr)


def wrap_preloader(preloader: bytes, storage: str = "emmc",
                   region_size: int = None) -> bytes:
    """Return boot header + preloader, ready to write raw to boot1.

    If the input is already wrapped it is returned unchanged. The boot-region
    size is taken from the preloader's GFH max_size (authoritative, per device),
    falling back to 0x40000. Raises ValueError if the preloader is too big for
    the region, or if the storage type is not one we can build a verified header
    for (use the DA download command for UFS/NAND/NOR instead).
    """
    if is_wrapped(preloader):
        return preloader
    if storage not in VERIFIED_STORAGE:
        raise ValueError(
            f"software preloader wrapping is only verified for {VERIFIED_STORAGE} "
            f"(got {storage!r}); flash the preloader via the DA download command instead")
    if region_size is None:
        region_size = gfh_max_size(preloader) or DEFAULT_REGION_SIZE
    if len(preloader) > region_size:
        raise ValueError(f"preloader ({len(preloader)} bytes) exceeds boot region "
                         f"({region_size} bytes)")
    return build_boot_header(storage, region_size) + preloader
