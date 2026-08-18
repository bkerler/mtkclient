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

# region -> mtkclient parttype (see storage.partitiontype_and_size).
# Keys are the EXACT strings SP Flash Tool serialises (verified against the
# region enum table in FlashtoollibEx.dll): note EMMC_GP_1 (underscore),
# EMMC_RPMP (MediaTek's spelling), and UFS_LU0_LU1 (the UFS preloader region).
REGION_TO_PARTTYPE = {
    "EMMC_BOOT_1": "boot1",
    "EMMC_BOOT1": "boot1",
    "EMMC_BOOT_2": "boot2",
    "EMMC_BOOT2": "boot2",
    # Preloader (SV5_BL_BIN) lives in boot1. NOTE: it must NOT be written as the
    # bare preloader -- da_ws wraps it in an EMMC_BOOT/BRLYT boot header first
    # (see preloader_boot.wrap_preloader), otherwise the BROM can't boot boot1.
    "EMMC_BOOT1_BOOT2": "boot1",
    "EMMC_RPMP": "rpmb",
    "EMMC_GP_1": "gp1",
    "EMMC_GP_2": "gp2",
    "EMMC_GP_3": "gp3",
    "EMMC_GP_4": "gp4",
    "EMMC_USER": "user",
    # UFS regions. LU mapping follows the MTK convention (LU0=user, LU1/LU2=boot,
    # LU0_LU1=preloader region) -- UNVERIFIED against a real UFS scatter; UFS
    # preloader wrapping is refused anyway (see preloader_boot.VERIFIED_STORAGE).
    "UFS_LU0": "user",
    "UFS_LU1": "boot1",
    "UFS_LU2": "boot2",
    "UFS_LU0_LU1": "boot1",
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
        self._is_reserved_flag = bool(fields.get("is_reserved", False))

    @property
    def parttype(self) -> str:
        return REGION_TO_PARTTYPE.get(str(self.region).upper(), "user")

    @property
    def is_user_region(self) -> bool:
        return self.parttype == "user"

    @property
    def has_sentinel_addr(self) -> bool:
        """linear_start_addr is a 0xFFFF00xx sentinel (address set dynamically)."""
        return PSEUDO_ADDR_MIN <= self.linear_start_addr <= PSEUDO_ADDR_MAX

    @property
    def is_gpt_area(self) -> bool:
        """The GPT tables themselves (pgpt/sgpt) -- never a partition entry."""
        return (self.name or "").lower() in GPT_AREA_NAMES

    @property
    def is_dynamic(self) -> bool:
        """Real partition whose address SP Flash Tool computes at flash time.

        These (e.g. otp, flashinfo) sit after the resized userdata, so the
        scatter gives them a sentinel address instead of a fixed one. They ARE
        real GPT entries -- their true position must be taken from the device's
        current table, not invented.
        """
        return self.has_sentinel_addr and not self.is_gpt_area

    @property
    def is_pseudo(self) -> bool:
        """Not a fixed-address partition entry (GPT-table or dynamic)."""
        return self.has_sentinel_addr or self.is_gpt_area

    @property
    def is_boot_region(self) -> bool:
        return self.parttype in ("boot1", "boot2")

    @property
    def is_preloader(self) -> bool:
        """The bootloader that goes in boot1 wrapped in an EMMC_BOOT header."""
        return self.type == "SV5_BL_BIN" or (self.name or "").lower() == "preloader"

    # --- operation_type semantics (drive safe GPT rebuilds) ---------------
    # BOOTLOADERS  preloader
    # INVISIBLE    normal partition, hidden in the UI, still real in the GPT
    # UPDATE       normal updatable partition
    # PROTECTED    device-unique data that MUST be preserved (nvcfg, proinfo, ...)
    # BINREGION    device-unique binary region that MUST be preserved (nvram)
    # NEEDRESIZE   grown to fill the remaining space (userdata)
    # RESERVED     not a real linear partition (otp/flashinfo/sgpt)
    @property
    def op(self) -> str:
        return str(self.operation_type or "").upper()

    @property
    def is_protected(self) -> bool:
        """Holds device-unique data that must survive a repartition."""
        return self.op in ("PROTECTED", "BINREGION")

    @property
    def needs_resize(self) -> bool:
        """Grown to fill the rest of the disk (userdata)."""
        return self.op == "NEEDRESIZE"

    @property
    def is_reserved(self) -> bool:
        """Not a real placeable partition (RESERVED op, or the is_reserved flag)."""
        return self.op == "RESERVED" or self._is_reserved_flag

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
        self.config_version = None
        # SP Flash Tool control flags (general section):
        #   skip_pt_operate=true -> DA does NOT write PGPT/SGPT (skip repartition)
        #   resize_check=false   -> do NOT resize NEEDRESIZE partitions
        self.skip_pt_operate = False
        self.skip_resize = False
        self._parse(filename)
        self._validate()

    def _validate(self):
        """Reject formats this parser can't handle instead of mis-flashing.

        This parses the SP Flash Tool YAML text scatter. An XML scatter (newer
        DAs) yields no partitions and is rejected below. We do NOT hard-reject
        on config_version major: SP Flash Tool emits V1.x and V2.0 text scatters
        and the schema is compatible; only warn on unknown majors.
        """
        if not self.partitions:
            raise ValueError(f"{self.filename}: no partitions parsed; not a "
                             f"recognised SP Flash Tool (YAML) scatter file "
                             f"(XML scatters are not supported)")
        storage = str(self.storage or "").upper()
        if storage and storage != "EMMC":
            # The ws host-side flow is verified only for eMMC. UFS LU->role
            # mapping is unverified (and mtkclient's own storage.py is
            # inconsistent: v5 maps "user"->LU0, v6 maps "user"->LU2), and
            # NAND/NOR/COMBO need page addressing + PMT/BMT. Refuse rather than
            # risk a destructive mis-flash; these belong on the DA download /
            # FLASH-ALL path (see da_ws "Known limitations").
            raise ValueError(f"{self.filename}: storage {self.storage!r} is not supported by "
                             f"the ws scatter flow yet (eMMC only); UFS/NAND/NOR/COMBO need the "
                             f"DA-driven download/FLASH-ALL path.")
        ver = str(self.config_version or "")
        if ver and not (ver.upper().startswith("V1") or ver.upper().startswith("V2")):
            self.log_unknown_version(ver)

    def log_unknown_version(self, ver):
        # best-effort: keep going, but make the unknown schema visible
        import sys
        print(f"warning: {self.filename}: unrecognised scatter config_version {ver!r}; "
              f"parsing anyway", file=sys.stderr)

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

            # A record starts at a list item ("- key: value"). Nested list items
            # (the "info:" sub-list) merge into the record they belong to. A new
            # record is only started for the "general"/"partition_index" keys, so
            # indentation of the top-level item doesn't matter (robust to tools
            # that indent list items).
            is_list_item = stripped.startswith("- ")
            body = stripped[2:] if is_list_item else stripped

            if ":" not in body:
                continue
            key, _, value = body.partition(":")
            key = key.strip()
            val = _convert(value)

            if is_list_item and key in ("general", "partition_index"):
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
                self.config_version = fields.get("config_version")
                if fields.get("block_size"):
                    self.block_size = fields.get("block_size")
                self.skip_pt_operate = bool(fields.get("skip_pt_operate", False))
                if fields.get("resize_check") is False:
                    self.skip_resize = True
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
        """Fixed-address user partitions to place in a rebuilt GPT.

        Excludes the GPT tables (pgpt/sgpt) and the dynamically-addressed
        partitions (otp/flashinfo), which are handled separately because their
        real position depends on the resized userdata / device flash size.
        """
        return [p for p in self.partitions
                if p.is_user_region and not p.is_pseudo and not p.is_reserved
                and p.partition_size > 0]

    def dynamic_partitions(self):
        """Real user partitions whose address SP Flash Tool sets at flash time.

        These (otp, flashinfo, ...) ARE GPT entries but sit after the resized
        userdata, so the scatter gives them a sentinel address. Their true
        position must be read from the device's existing table.
        """
        return [p for p in self.partitions
                if p.is_user_region and p.is_dynamic and p.partition_size > 0]

    def protected_partitions(self):
        """Partitions holding device-unique data that a repartition must preserve."""
        return [p for p in self.partitions if p.is_protected]

    def get(self, name: str):
        for p in self.partitions:
            if p.name == name:
                return p
        return None
