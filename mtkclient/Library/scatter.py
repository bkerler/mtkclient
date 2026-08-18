#!/usr/bin/env python3
# !/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
"""
Parser for SP Flash Tool "scatter" files (MTK_PLATFORM_CFG YAML layout).

The scatter file describes the on-flash partition layout of a MediaTek device:
one record per partition with its name, image file, download flag, on-flash
address and size, and the storage region it lives in. This module turns that
text into plain Python objects so mtkclient can flash a full firmware from a
scatter directory (like SP Flash Tool's "Download Only" / "Firmware Upgrade").

The format is a small, very regular subset of YAML. To avoid adding a PyYAML
dependency we parse it with a purpose-built line scanner that understands the
two record kinds actually emitted by SP Flash Tool:

  - general: MTK_PLATFORM_CFG        (platform / storage / block_size header)
  - partition_index: SYSn            (one per partition)
"""


def _convert(value: str):
    """Convert a scatter scalar to int (hex/dec) or bool, else return str."""
    v = value.strip()
    if v == "":
        return None
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        if low.startswith("0x"):
            return int(v, 16)
        return int(v, 10)
    except ValueError:
        return v


# SP Flash Tool marks pseudo/virtual partitions (otp, flashinfo, sgpt, ...)
# with a sentinel linear_start_addr in the narrow band 0xFFFF0000..0xFFFFFFFF
# (0xFFFF0000 + index). These are NOT real linearly-addressed regions and must
# be kept out of the GPT. Note the band is bounded at 0xFFFFFFFF: real
# partitions on a >4 GiB eMMC legitimately have addresses far ABOVE it
# (e.g. userdata at 0x1bb400000), so a bare ">=" would wrongly catch them.
PSEUDO_ADDR_MIN = 0xFFFF0000
PSEUDO_ADDR_MAX = 0xFFFFFFFF

# Names that describe the GPT tables themselves rather than a real partition.
GPT_AREA_NAMES = {"pgpt", "sgpt", "pmt", "spmt"}

# region -> mtkclient parttype (see storage.partitiontype_and_size)
REGION_TO_PARTTYPE = {
    "EMMC_BOOT_1": "boot1",
    "EMMC_BOOT1": "boot1",
    "EMMC_BOOT_2": "boot2",
    "EMMC_BOOT2": "boot2",
    # Preloader (SV5_BL_BIN) lives in boot1. NOTE: it must NOT be written as the
    # bare preloader -- da_ws wraps it in an EMMC_BOOT/BRLYT boot header first
    # (see preloader_boot.wrap_preloader), otherwise the BROM can't boot boot1.
    "EMMC_BOOT1_BOOT2": "boot1",
    "EMMC_RPMB": "rpmb",
    "EMMC_GP1": "gp1",
    "EMMC_GP2": "gp2",
    "EMMC_GP3": "gp3",
    "EMMC_GP4": "gp4",
    "EMMC_USER": "user",
    # UFS scatters reuse the same field with UFS_ prefixes
    "UFS_LU0": "user",
    "UFS_LU1": "boot1",
    "UFS_LU2": "boot2",
    "UFS_LU3": "rpmb",
}


class ScatterPartition:
    def __init__(self, fields: dict):
        self.raw = fields
        self.partition_index = fields.get("partition_index")
        self.name = fields.get("partition_name")
        file_name = fields.get("file_name")
        # SP Flash Tool uses the literal string NONE for "no image".
        if isinstance(file_name, str) and file_name.strip().upper() == "NONE":
            file_name = None
        self.file_name = file_name
        self.is_download = bool(fields.get("is_download", False))
        self.type = fields.get("type")
        self.linear_start_addr = fields.get("linear_start_addr", 0) or 0
        self.physical_start_addr = fields.get("physical_start_addr", 0) or 0
        self.partition_size = fields.get("partition_size", 0) or 0
        self.region = fields.get("region", "EMMC_USER")
        self.storage = fields.get("storage")
        self.operation_type = fields.get("operation_type")
        self.is_reserved = bool(fields.get("is_reserved", False))

    @property
    def parttype(self) -> str:
        return REGION_TO_PARTTYPE.get(str(self.region).upper(), "user")

    @property
    def is_user_region(self) -> bool:
        return self.parttype == "user"

    @property
    def is_pseudo(self) -> bool:
        """True for virtual/sentinel entries (otp, flashinfo, pgpt, sgpt, ...)."""
        return (PSEUDO_ADDR_MIN <= self.linear_start_addr <= PSEUDO_ADDR_MAX or
                (self.name or "").lower() in GPT_AREA_NAMES)

    @property
    def is_boot_region(self) -> bool:
        return self.parttype in ("boot1", "boot2")

    @property
    def is_preloader(self) -> bool:
        """The bootloader that goes in boot1 wrapped in an EMMC_BOOT header."""
        return self.type == "SV5_BL_BIN" or (self.name or "").lower() == "preloader"

    def start_lba(self, sectorsize: int) -> int:
        return self.linear_start_addr // sectorsize

    def size_lba(self, sectorsize: int) -> int:
        return (self.partition_size + sectorsize - 1) // sectorsize

    def __repr__(self):
        return (f"ScatterPartition(name={self.name!r}, region={self.region}, "
                f"addr={hex(self.linear_start_addr)}, size={hex(self.partition_size)}, "
                f"download={self.is_download}, file={self.file_name!r})")


class Scatter:
    def __init__(self, filename: str):
        self.filename = filename
        self.general = {}
        self.partitions = []
        self.platform = None
        self.storage = None
        self.block_size = 0x20000
        self.project = None
        self._parse(filename)

    def _parse(self, filename: str):
        with open(filename, "r", encoding="utf-8", errors="replace") as rf:
            lines = rf.readlines()

        records = []          # list of (kind, fields-dict)
        current = None        # fields dict of the record we're filling

        for raw in lines:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # A record starts at a top-level list item ("- key: value" at
            # column 0). Nested list items (the "info:" sub-list) are indented,
            # so they fall through to the key/value branch and merge into the
            # record they belong to -- which is all we need for block_size etc.
            is_toplevel_item = line.startswith("- ")
            body = stripped[2:] if stripped.startswith("- ") else stripped

            if ":" not in body:
                continue
            key, _, value = body.partition(":")
            key = key.strip()
            val = _convert(value)

            if is_toplevel_item and key in ("general", "partition_index"):
                current = {key: val}
                records.append((key, current))
                continue

            if current is not None:
                current[key] = val

        for kind, fields in records:
            if kind == "general":
                self.general = fields
                self.platform = fields.get("platform")
                self.storage = fields.get("storage")
                self.project = fields.get("project")
                if fields.get("block_size"):
                    self.block_size = fields.get("block_size")
            elif kind == "partition_index":
                if fields.get("partition_name"):
                    self.partitions.append(ScatterPartition(fields))

    def download_partitions(self):
        """Partitions flagged is_download that actually have an image."""
        return [p for p in self.partitions if p.is_download and p.file_name]

    def user_partitions(self):
        """All EMMC_USER partitions (including pseudo ones)."""
        return [p for p in self.partitions if p.is_user_region]

    def gpt_partitions(self):
        """Real, linearly-addressed user partitions to place in a rebuilt GPT.

        Excludes the GPT tables themselves (pgpt/sgpt) and the sentinel-addressed
        pseudo partitions (otp/flashinfo/...) that must not appear in the table.
        """
        return [p for p in self.partitions
                if p.is_user_region and not p.is_pseudo and p.partition_size > 0]

    def get(self, name: str):
        for p in self.partitions:
            if p.name == name:
                return p
        return None
