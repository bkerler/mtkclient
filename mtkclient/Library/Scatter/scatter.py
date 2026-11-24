#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) Daniel Kamyshan 2026, ported from SP Flash Tool (FlashtoollibEx / FlashToolLib.v1)
# Licensed under GPLv3 License
#
# MTK scatter file parser for mtkclient.
#
# Ported from SP Flash Tool V5/V6 (official packages, see begonia-kernel-research/
# spft-decompile-2026-11-24.md, section 4.1):
#  - text scatter: yaml_reader.cpp / ScatterFileParser@FlashToolLib.v1
#    (DL_LoadScatter / DL_GetScatterInfo / DL_GetScatterVersion / DL_AutoLoadByScatRegionName)
#  - xml scatter: SPFlashTool::XMLScatterFileGeneralSettingParserDecorator{V4,V5,V7,V8,V10,V11}
#    + XMLScatterFileStorageGeneralSettingParserBase
#  - scatter_checksum.xml: flash.dll ("scatter_checksum.xml", "images_sha256",
#    "<xmlattr>.name", "<xmlattr>.checksum")
#
# A scatter file provides the partition map (name, offsets, sizes, regions) WITHOUT
# reading the GPT/PMT from the device - the main deficit of mtkclient prior to this port.
import os
import re
from typing import Optional
import xml.etree.ElementTree as ET


class ScatterError(Exception):
    """Base class for scatter parsing errors (STATUS_SCATTER_FILE_INVALID)."""


class ScatterChipMismatch(ScatterError):
    """
    Raised when the scatter platform doesn't match the connected device.
    SPFT message: "Chip mismatch! scatter: platform[%s] type[%s]; device:
    hw_code[0x%x], hw_subcode[0x%x], hw_ver[0x%x], sw_ver[0x%x], chip_evolution[%d]"
    (STATUS_SCATTER_HW_CHIP_ID_MISMATCH).
    """


# Field sets confirmed via FlashtoollibEx strings (yaml_reader::partition_parser):
# partition_index, partition_name, file_name, is_download, type, linear_start_addr,
# physical_start_addr, partition_size, region, storage, boundary_check, is_reserved,
# operation_type, is_upgradable, empty_boot_needed, reserve, slc_percentage, d_type,
# combo_partsize_check. "file_size" is validated separately by DL_GetScatterInfo.
_INT_FIELDS = ("linear_start_addr", "physical_start_addr", "partition_size",
               "file_size", "reserve", "slc_percentage")
_BOOL_FIELDS = ("is_download", "boundary_check", "is_reserved", "is_upgradable",
                "empty_boot_needed")
_KNOWN_FIELDS = ("partition_index", "partition_name", "file_name", "is_download", "type",
                 "linear_start_addr", "physical_start_addr", "partition_size", "region",
                 "storage", "boundary_check", "is_reserved", "operation_type",
                 "is_upgradable", "empty_boot_needed", "reserve", "file_size",
                 "slc_percentage", "d_type", "combo_partsize_check")


def _to_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def _to_int(value):
    v = str(value).strip()
    if v.upper() in ("", "NONE"):
        return 0
    return int(v, 16) if v.lower().startswith("0x") else int(v, 10)


class ScatterPartition:
    """One partition entry of a scatter file (image_info_t in SPFT terms)."""

    def __init__(self, **kwargs):
        self.partition_index = kwargs.get("partition_index", "")
        self.partition_name = kwargs.get("partition_name", "")
        self.file_name = kwargs.get("file_name", "NONE")
        self.is_download = _to_bool(kwargs.get("is_download", "false"))
        self.type = kwargs.get("type", "NORMAL_ROM")
        self.linear_start_addr = _to_int(kwargs.get("linear_start_addr", 0))
        self.physical_start_addr = _to_int(kwargs.get("physical_start_addr", 0))
        self.partition_size = _to_int(kwargs.get("partition_size", 0))
        self.file_size = _to_int(kwargs.get("file_size", 0))
        self.region = kwargs.get("region", "")
        self.storage = kwargs.get("storage", "")
        self.boundary_check = _to_bool(kwargs.get("boundary_check", "true"))
        self.is_reserved = _to_bool(kwargs.get("is_reserved", "false"))
        self.operation_type = kwargs.get("operation_type", "UPDATE")
        self.is_upgradable = _to_bool(kwargs.get("is_upgradable", "false"))
        self.empty_boot_needed = _to_bool(kwargs.get("empty_boot_needed", "false"))
        self.reserve = _to_int(kwargs.get("reserve", 0))
        self.slc_percentage = _to_int(kwargs.get("slc_percentage", 0))
        self.d_type = kwargs.get("d_type", "")
        self.extra = {}
        for key, value in kwargs.items():
            if key not in _KNOWN_FIELDS:
                self.extra[key] = value

    def __repr__(self):
        return (f"<ScatterPartition {self.partition_name} "
                f"addr={hex(self.linear_start_addr)} size={hex(self.partition_size)} "
                f"region={self.region} dl={self.is_download}>")

    @property
    def end_addr(self):
        return self.linear_start_addr + self.partition_size

    def is_bootloader(self):
        """
        Bootloader image for auto-format purposes: region EMMC_BOOT1_BOOT2 / UFS_LU0_LU1
        or operation_type BOOTLOADERS (SPFT "Format whole flash except Bootloader" scene).
        """
        return (self.operation_type.upper() == "BOOTLOADERS" or
                self.region.upper() in ("EMMC_BOOT1_BOOT2", "UFS_LU0_LU1"))


class ScatterStorage:
    """One storage section of a scatter file (EMMC or UFS block)."""

    def __init__(self, storage_type="EMMC", boot_channel="", block_size=0x20000):
        self.storage_type = storage_type
        self.boot_channel = boot_channel
        self.block_size = block_size
        self.partitions = []

    def __repr__(self):
        return (f"<ScatterStorage {self.storage_type} channel={self.boot_channel} "
                f"block_size={hex(self.block_size)} parts={len(self.partitions)}>")


class ScatterInfo:
    """Parsed scatter file: general settings + storage sections + partitions."""

    check_bootloaders_consistency: Optional[bool]
    skip_pmt_operate: Optional[bool]
    modem_check: Optional[bool]
    resize_check: Optional[bool]

    def __init__(self):
        self.config_version = ""
        self.platform = ""
        self.project = ""
        self.check_bootloaders_consistency = None  # Optional[bool], V7+
        self.skip_pmt_operate = None               # Optional[bool], V7+
        self.modem_check = None                    # Optional[bool], V8+
        self.modem_type = ""
        self.resize_check = None                   # Optional[bool], V8+
        self.chip_version = ""
        self.scatter_version = ""       # "V4".."V11" for xml scatters, "V1.x/V2.x" for text
        self.storages = []              # list of ScatterStorage
        self.partitions = []            # flat list over all storage sections

    def __repr__(self):
        return (f"<ScatterInfo platform={self.platform} project={self.project} "
                f"version={self.scatter_version} partitions={len(self.partitions)}>")

    def by_name(self, name):
        """
        Return partition(s) with the given name. Scatters may carry multiple storage
        sections (EMMC + UFS), so duplicate names are legal - SPFT errors out with
        "Error: partition name(%s) duplicated." when they appear in one section.
        """
        return [p for p in self.partitions if p.partition_name.lower() == str(name).lower()]

    def get_download_partitions(self):
        return [p for p in self.partitions if p.is_download]

    def by_region(self, region):
        return [p for p in self.partitions if p.region.upper() == str(region).upper()]

    def get_storage(self, storage_type):
        for storage in self.storages:
            if storage.storage_type.upper() == str(storage_type).upper():
                return storage
        return None

    def validate_chip(self, hw_code, hw_subcode=0, hw_ver=0, sw_ver=0, chip_evolution=0):
        """
        Validate the scatter platform against the connected device, mirroring SPFT's
        "Chip mismatch!" check (STATUS_SCATTER_HW_CHIP_ID_MISMATCH). MT6785 -> 0x6785.
        """
        m = re.search(r"MT(\d{4})", self.platform.upper())
        if m is None:
            raise ScatterChipMismatch(f"Scatter platform has no MT chip id: {self.platform}")
        scatter_hw_code = int(m.group(1), 16)
        if scatter_hw_code != hw_code:
            raise ScatterChipMismatch(
                "Chip mismatch! scatter: platform[%s]; device: "
                "hw_code[0x%x], hw_subcode[0x%x], hw_ver[0x%x], sw_ver[0x%x], "
                "chip_evolution[%d]" % (self.platform, hw_code, hw_subcode, hw_ver,
                                        sw_ver, chip_evolution))
        return True

    def to_dict(self):
        return {
            "config_version": self.config_version,
            "platform": self.platform,
            "project": self.project,
            "scatter_version": self.scatter_version,
            "storages": [{"storage_type": s.storage_type,
                          "boot_channel": s.boot_channel,
                          "block_size": s.block_size} for s in self.storages],
            "partitions": [{"partition_index": p.partition_index,
                            "partition_name": p.partition_name,
                            "file_name": p.file_name,
                            "is_download": p.is_download,
                            "type": p.type,
                            "linear_start_addr": p.linear_start_addr,
                            "physical_start_addr": p.physical_start_addr,
                            "partition_size": p.partition_size,
                            "region": p.region,
                            "operation_type": p.operation_type} for p in self.partitions],
        }


def _check_duplicate_names(info):
    """
    SPFT yaml_reader: "Error: partition name(%s) duplicated." - enforced per storage
    section, since one scatter file may legally carry several storage layouts
    (e.g. EMMC + UFS blocks with the same partition names).
    """
    for storage in info.storages:
        seen = set()
        for part in storage.partitions:
            key = part.partition_name.lower()
            if key in seen:
                raise ScatterError(f"Error: partition name({part.partition_name}) duplicated.")
            seen.add(key)
    seen = set()
    for part in info.partitions:
        key = (part.partition_name.lower(), part.region.upper())
        if key in seen:
            raise ScatterError(f"Error: partition name({part.partition_name}) duplicated "
                               f"in region {part.region}.")
        seen.add(key)


def parse_scatter_text(text):
    """
    Parse a text scatter file (MTK_PLATFORM_CFG yaml layout, config_version V1.x/V2.x).
    Handles files containing multiple storage sections (e.g. EMMC + UFS layouts in one
    file, as produced by modern SPFT).
    """
    info = ScatterInfo()
    section = None              # None | "general" | "storage" | "partition"
    storage = None
    current = None              # dict for the item being collected
    general_done = False

    re_item = re.compile(r"^(\s*)-\s*([A-Za-z_0-9]+)\s*:\s*(.*)$")
    re_kv = re.compile(r"^(\s+)([A-Za-z_0-9]+)\s*:\s*(.*)$")

    def flush():
        nonlocal current, storage
        if current is None:
            return
        if section == "general":
            _apply_general(info, current)
        elif section == "storage":
            if storage is not None:
                _apply_storage_item(storage, current)
        elif section == "partition":
            if storage is None:
                storage = ScatterStorage()
                info.storages.append(storage)
            part = ScatterPartition(**current)
            storage.partitions.append(part)
            info.partitions.append(part)
        current = None

    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        m_item = re_item.match(line)
        m_kv = re_kv.match(line)
        if m_item:
            key = m_item.group(2)
            value = m_item.group(3).strip().strip('"')
            if key == "general" and value == "MTK_PLATFORM_CFG":
                flush()
                section = "general"
                general_done = True
                current = {}
                continue
            if key == "storage_type":
                flush()
                section = "storage"
                storage = ScatterStorage(storage_type=value)
                info.storages.append(storage)
                current = None
                continue
            if key == "general" and value == "MTK_STORAGE_CFG":
                # "  - general: MTK_STORAGE_CFG" opens the storage info item
                flush()
                section = "storage"
                current = {}
                continue
            if key == "partition_index" and section in ("storage", "partition", None):
                # "- partition_index: SYS0" opens a partition entry; flush first so the
                # pending storage info item isn't mis-filed as a partition. Only
                # partition_index opens a block - other known fields (storage, region,
                # file_name, ...) appear as nested keys of the storage/partition item.
                flush()
                if section != "partition":
                    if storage is None:
                        storage = ScatterStorage()
                        info.storages.append(storage)
                    section = "partition"
                current = {key: value}
                continue
            # nested list item inside an open block ("- config_version: V2.1.0")
            if current is None:
                current = {}
            current[key] = value
            continue
        if m_kv:
            key = m_kv.group(2)
            value = m_kv.group(3).strip().strip('"')
            if key in ("info", "description"):
                continue
            if section is None and key in ("config_version", "platform", "project"):
                section = "general"
                general_done = True
            if current is None:
                current = {}
            current[key] = value
    flush()
    if not general_done and not info.partitions:
        raise ScatterError("STATUS_SCATTER_FILE_INVALID: no general/partition blocks found")
    _check_duplicate_names(info)
    if info.config_version == "":
        info.config_version = info.scatter_version
    return info


def _apply_general(info, current):
    for key, value in current.items():
        if key == "__config_version":
            info.config_version = value
        elif key == "platform":
            info.platform = value
        elif key == "project":
            info.project = value
        elif key == "check_bootloaders_consistency":
            info.check_bootloaders_consistency = _to_bool(value)
        elif key == "skip_pmt_operate":
            info.skip_pmt_operate = _to_bool(value)
        elif key == "modem_check":
            info.modem_check = _to_bool(value)
        elif key == "modem":
            info.modem_type = value
        elif key == "resize_check":
            info.resize_check = _to_bool(value)
        elif key == "chip_version":
            info.chip_version = value


def _apply_storage_item(storage, current):
    for key, value in current.items():
        if key == "storage":
            if value:
                storage.storage_type = value
        elif key == "boot_channel":
            storage.boot_channel = value
        elif key == "block_size":
            storage.block_size = _to_int(value)


def _xml_findtext(node, tag, default=""):
    if node is None:
        return default
    child = node.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def parse_scatter_xml(text):
    """
    Parse an xml scatter file (scatter.xml), port of the SPFT decorator chain
    XMLScatterFileGeneralSettingParserDecorator{V4,V5,V7,V8,V10,V11}:
      - base (XMLScatterFileStorageGeneralSettingParserBase): storage settings
        (boot_channel, block_size)
      - V4/V5: platform, project, storage type
      - V7: + check_bootloaders_consistency, skip_pmt_operate
      - V8: + modem_check, modem, resize_check
      - V10/V11: + chip_version
    Partition entries share the text-scatter field names (confirmed via FlashtoollibEx
    strings: root.general.config_version.platform, general.storage.block_size, ...).
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ScatterError(f"STATUS_SCATTER_FILE_INVALID: xml parse error: {e}") from e

    info = ScatterInfo()
    general = root.find(".//general")
    if general is None:
        general = root

    # Decorator version detection: root/@version, general/@version or
    # config_version/@name|<name> (root.general.config_version.<xmlattr>.name)
    version = (root.get("version") or general.get("version") or
               _xml_findtext(general, "version"))
    cfg = general.find("config_version")
    if not version and cfg is not None:
        version = cfg.get("name") or _xml_findtext(cfg, "name")
    info.scatter_version = version or "V11"

    info.platform = _xml_findtext(cfg, "platform")
    info.project = _xml_findtext(cfg, "project")
    info.config_version = _xml_findtext(cfg, "type") or info.scatter_version
    vnum = int(re.sub(r"[^0-9]", "", info.scatter_version) or 11)
    if vnum >= 7:
        cbc = _xml_findtext(cfg, "check_bootloaders_consistency")
        if cbc:
            info.check_bootloaders_consistency = _to_bool(cbc)
        spo = _xml_findtext(cfg, "skip_pmt_operate")
        if spo:
            info.skip_pmt_operate = _to_bool(spo)
    if vnum >= 8:
        mc = _xml_findtext(cfg, "modem_check")
        if mc:
            info.modem_check = _to_bool(mc)
        info.modem_type = _xml_findtext(cfg, "modem")
        rc = _xml_findtext(cfg, "resize_check")
        if rc:
            info.resize_check = _to_bool(rc)
    if vnum >= 10:
        info.chip_version = _xml_findtext(cfg, "chip_version")

    # Storage settings (base parser): general/storage with boot_channel/block_size
    storage = None
    storage_node = general.find("storage")
    if storage_node is not None:
        storage = ScatterStorage(
            storage_type=storage_node.get("name") or _xml_findtext(general, "storage_type",
                                                                   "EMMC"),
            boot_channel=_xml_findtext(storage_node, "boot_channel"),
            block_size=_to_int(_xml_findtext(storage_node, "block_size", "0x20000")))
        info.storages.append(storage)

    # Partition entries: any element carrying partition_name
    for pnode in root.iter():
        if pnode.find("partition_name") is None:
            continue
        values = {}
        for child in pnode:
            if child.tag in _KNOWN_FIELDS and child.text is not None:
                values[child.tag] = child.text.strip()
        if storage is None:
            storage = ScatterStorage()
            info.storages.append(storage)
        part = ScatterPartition(**values)
        if part.storage == "" and storage.storage_type:
            part.storage = f"HW_STORAGE_{storage.storage_type}"
        storage.partitions.append(part)
        info.partitions.append(part)

    if not info.partitions:
        raise ScatterError("STATUS_SCATTER_FILE_INVALID: no partition entries in xml scatter")
    _check_duplicate_names(info)
    return info


def parse_scatter(path):
    """Load a scatter file from disk, auto-detecting text vs xml format."""
    if not os.path.exists(path):
        # STATUS_SCATTER_FILE_NOT_FOUND
        raise ScatterError(f"STATUS_SCATTER_FILE_NOT_FOUND: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as rf:
        text = rf.read()
    if text.lstrip().startswith("<?xml") or text.lstrip().startswith("<rom"):
        return parse_scatter_xml(text)
    return parse_scatter_text(text)


def parse_scatter_checksum(path_or_text):
    """
    Parse scatter_checksum.xml (SPFT V6, flash.dll):
        <scatter version=".."><images_sha256>
            <file name="boot.img" checksum="aabb.."/>
        </images_sha256></scatter>
    Returns (version, {file_name: sha256hex}).
    """
    text = path_or_text
    if "\n" not in text and os.path.exists(path_or_text):
        with open(path_or_text, "r", encoding="utf-8", errors="replace") as rf:
            text = rf.read()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ScatterError(f"Open scatter checksum file failed: {e}") from e
    if root.tag != "scatter":
        raise ScatterError("Open scatter checksum file failed: wrong root element")
    version = root.get("version", "")
    if version == "":
        # flash.dll: "scatter_checksum.xml version is invalid."
        raise ScatterError("scatter_checksum.xml version is invalid.")
    images = {}
    node = root.find("images_sha256")
    if node is not None:
        for file in node.findall("file"):
            name = file.get("name")
            checksum = file.get("checksum")
            if name and checksum:
                images[name] = checksum.lower()
    return version, images
