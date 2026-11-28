#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) Daniel Kamyshan 2026, ported from SP Flash Tool V5
# Licensed under GPLv3 License
#
# Auto-format range computation for mtkclient (GenAutoFormatRange port).
#
# Ported from SP Flash Tool V5 (flash_tool.exe, Arg/*.cpp):
#  - APCore::AutoFormatArg::GenAutoFormatRange / AutoFormatArg::QueryPartLayout
#  - APCore::EMMCFormatArg::GenAutoFormatRange
#  - APCore::SDMMCAutoFormatArg::GenAutoFormatRange
#  - APCore::UFSFormatArg::GenAutoFormatRange
#  - APCore::NANDFormatArg::GenAutoFormatRange
#  - APCore::NORFormatArg::GenAutoFormatRange
# Scenes (flash_tool strings): "Format whole flash", "Format whole flash except
# Bootloader", "Auto Format Flash". BMT protection size comes from platform.xml
# (default_bmt_blocks, e.g. 80 for MT6785).
#
# The computed range feeds the existing mtkclient DAloader.formatflash(addr,
# length, partitionname, parttype) call.


class AutoFormatFlag:
    """Format scenes (SPFT UI radio buttons / download_scene.ini)."""
    WHOLE_FLASH = "WHOLE_FLASH"                        # "Format whole flash"
    WHOLE_FLASH_EXCEPT_BOOTLOADER = "EXCEPT_BOOTLOADER"  # "Format whole flash except Bootloader"
    AUTO_FORMAT = "AUTO_FORMAT"                        # "Auto Format Flash" (layout-derived)
    PARTITION = "PARTITION"                            # single partition (QueryPartLayout)


# Regions that hold bootloader images (scatter 'region' field values)
BOOT_REGIONS = ("EMMC_BOOT1_BOOT2", "UFS_LU0_LU1")
# operation_type values excluded from the auto-format layout query
RESERVED_TYPES = ("RESERVED", "INVISIBLE")

DEFAULT_BMT_BLOCKS = 80  # platform.xml default_bmt_blocks (e.g. MT6785)


def _attr(obj, name, default=None):
    """Duck-typed attribute access: ScatterPartition, gpt.partf or plain dicts."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _is_bootloader(part):
    region = str(_attr(part, "region", "") or "").upper()
    op_type = str(_attr(part, "operation_type", "") or "").upper()
    name = str(_attr(part, "partition_name", _attr(part, "name", "")) or "").lower()
    return (op_type == "BOOTLOADERS" or region in BOOT_REGIONS or
            name in ("preloader", "preloader.bin"))


def _part_addr(part):
    return int(_attr(part, "linear_start_addr", _attr(part, "start", 0)) or 0)


def _part_size(part):
    return int(_attr(part, "partition_size", _attr(part, "size", 0)) or 0)


def _part_name(part):
    return str(_attr(part, "partition_name", _attr(part, "name", "")) or "")


class AutoFormatArg:
    """
    Base auto-format engine (port of AutoFormatArg): computes the format range
    from a partition layout (scatter partitions or GPT entries).
    """

    def __init__(self, partitions=None, flashsize: int = 0, block_size: int = 0x20000,
                 storage_type: str = "EMMC", bmt_blocks: int = 0):
        self.partitions = list(partitions or [])
        self.flashsize = flashsize
        self.block_size = block_size
        self.storage_type = storage_type
        self.bmt_blocks = bmt_blocks

    # ---- layout query (AutoFormatArg::QueryPartLayout) ----------------------

    def QueryPartLayout(self, partitionname: str) -> "tuple[int, int]":
        """Return (start_addr, size) of a partition from the layout."""
        for part in self.partitions:
            if _part_name(part).lower() == str(partitionname).lower():
                return _part_addr(part), _part_size(part)
        raise ValueError(f"QueryPartLayout: partition {partitionname} not found in layout")

    # ---- range computation (GenAutoFormatRange) ------------------------------

    def GenAutoFormatRange(self, flag: str = AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER,
                           partitionname: str = None) -> "tuple[int, int]":
        """
        Compute the (start, length) range for the requested format scene.
        """
        if flag == AutoFormatFlag.PARTITION or partitionname is not None:
            return self.QueryPartLayout(partitionname)
        if flag == AutoFormatFlag.WHOLE_FLASH:
            return self._whole_flash_range()
        if flag in (AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER,
                    AutoFormatFlag.AUTO_FORMAT):
            return self._except_bootloader_range()
        raise ValueError(f"Unknown auto-format flag: {flag}")

    def _layout_end(self) -> int:
        """End of the area covered by the partition layout."""
        return max((_part_addr(p) + _part_size(p)) for p in self.partitions) \
            if self.partitions else 0

    def _format_end(self) -> int:
        """End of the formattable area: explicit flashsize if given, else layout end."""
        if self.flashsize:
            return self.flashsize
        return self._layout_end()

    def _whole_flash_range(self) -> "tuple[int, int]":
        return 0, self._format_end()

    def _except_bootloader_range(self) -> "tuple[int, int]":
        # the scatter describes what exists: cover it fully, minus the bootloader.
        # Clamp against the formattable end (_format_end) so storage-specific
        # reservations survive: NAND subtracts the BMT area (bmt_blocks *
        # block_size) here, just like in the whole-flash scene.
        end = min(self._layout_end(), self._format_end())
        # Bootloaders in a dedicated hardware region (EMMC_BOOT1_BOOT2 / UFS_LU0_LU1)
        # are outside the linear user map - the user area still starts at pgpt 0x0.
        # Only NAND/NOR carry the bootloader inside the same linear map: start after it.
        boot_end = 0
        for part in self.partitions:
            if _is_bootloader(part):
                region = str(_attr(part, "region", "") or "").upper()
                if region in BOOT_REGIONS:
                    continue
                boot_end = max(boot_end, _part_addr(part) + _part_size(part))
        return boot_end, max(end - boot_end, 0)

    def to_formatflash_args(self, flag: str = AutoFormatFlag.WHOLE_FLASH_EXCEPT_BOOTLOADER,
                            partitionname: str = None, parttype: str = None):
        """
        Map the computed range onto mtkclient's existing
        DAloader.formatflash(addr, length, partitionname, parttype) call.
        """
        addr, length = self.GenAutoFormatRange(flag, partitionname)
        if partitionname is None:
            partitionname = ""
        if parttype is None:
            parttype = "user"
        return addr, length, partitionname, parttype

    # ---- layout sources ------------------------------------------------------

    @classmethod
    def from_scatter(cls, scatter, storage_type: str = None, flashsize: int = 0,
                     bmt_blocks: int = DEFAULT_BMT_BLOCKS) -> "AutoFormatArg":
        """
        Build the engine from a parsed ScatterInfo (mtkclient.Library.Scatter):
        uses the storage section matching storage_type (first section if None).
        """
        storage = None
        if storage_type is not None:
            storage = scatter.get_storage(storage_type)
        if storage is None:
            storage = scatter.storages[0]
        # subclasses set their own storage_type; pass only the shared kwargs
        arg = cls(partitions=storage.partitions, flashsize=flashsize,
                  block_size=storage.block_size, bmt_blocks=bmt_blocks)
        return arg


class EMMCFormatArg(AutoFormatArg):
    """
    EMMC: bootloader lives in the separate EMMC_BOOT1_BOOT2 region (addressed via
    parttype boot1/boot2), the user area starts with pgpt at 0x0.
    """
    def __init__(self, partitions=None, flashsize: int = 0, block_size: int = 0x20000,
                 bmt_blocks: int = 0):
        super().__init__(partitions=partitions, flashsize=flashsize,
                         block_size=block_size, storage_type="EMMC",
                         bmt_blocks=bmt_blocks)


class SDMMCAutoFormatArg(EMMCFormatArg):
    """SDMMC (APCore::SDMMCAutoFormatArg) - same layout rules as EMMC."""
    def __init__(self, partitions=None, flashsize: int = 0, block_size: int = 0x20000,
                 bmt_blocks: int = 0):
        super().__init__(partitions=partitions, flashsize=flashsize,
                         block_size=block_size, bmt_blocks=bmt_blocks)
        self.storage_type = "SDMMC"


class UFSFormatArg(AutoFormatArg):
    """
    UFS: boot LU0/LU1 hold the bootloader, LU2 is the user area.
    """
    def __init__(self, partitions=None, flashsize: int = 0, block_size: int = 0x80000,
                 bmt_blocks: int = 0):
        super().__init__(partitions=partitions, flashsize=flashsize,
                         block_size=block_size, storage_type="UFS",
                         bmt_blocks=bmt_blocks)


class NANDFormatArg(AutoFormatArg):
    """
    NAND: the Bad-Block-Management area (bmt_blocks * block_size, platform.xml
    default_bmt_blocks) at the end of the flash must never be formatted.
    """
    def __init__(self, partitions=None, flashsize: int = 0, block_size: int = 0x20000,
                 bmt_blocks: int = DEFAULT_BMT_BLOCKS):
        super().__init__(partitions=partitions, flashsize=flashsize,
                         block_size=block_size, storage_type="NAND",
                         bmt_blocks=bmt_blocks)

    def _bmt_size(self):
        return (self.bmt_blocks or 0) * self.block_size

    def _format_end(self):
        end = super()._format_end()
        # clamp away the BMT area at the end of the flash
        return max(end - self._bmt_size(), 0) if end else 0


class NORFormatArg(AutoFormatArg):
    """NOR: single linear chip, bootloader at offset 0."""
    def __init__(self, partitions=None, flashsize: int = 0, block_size: int = 0x1000,
                 bmt_blocks: int = 0):
        super().__init__(partitions=partitions, flashsize=flashsize,
                         block_size=block_size, storage_type="NOR",
                         bmt_blocks=bmt_blocks)


class AutoFormatArgFactory:
    """flashtype -> engine (SPFT factory: EMMC/UFS/NAND/NOR/SDMMC)."""
    MAP = {
        "EMMC": EMMCFormatArg,
        "SDMMC": SDMMCAutoFormatArg,
        "UFS": UFSFormatArg,
        "NAND": NANDFormatArg,
        "NOR": NORFormatArg,
    }

    @classmethod
    def create(cls, flashtype: str, partitions=None, flashsize: int = 0,
               block_size: int = None, bmt_blocks: int = None) -> AutoFormatArg:
        key = str(flashtype).upper()
        if key not in cls.MAP:
            raise ValueError(f"Unsupported storage type: {flashtype} "
                             f"(known: {', '.join(sorted(cls.MAP))})")
        klass = cls.MAP[key]
        kwargs = {"partitions": partitions, "flashsize": flashsize}
        if block_size is not None:
            kwargs["block_size"] = block_size
        if bmt_blocks is not None:
            kwargs["bmt_blocks"] = bmt_blocks
        return klass(**kwargs)
