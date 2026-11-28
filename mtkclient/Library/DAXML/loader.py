#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) Daniel Kamyshan 2026, ported from SP Flash Tool V6
# Licensed under GPLv3 License
#
# SPFT V6 flash.xml package loader for mtkclient (DAXML).
#
# Ported from SP Flash Tool V6 (see begonia-kernel-research/
# spft-decompile-2026-11-24.md, section 5.5): V6 drives downloads through a
# flash.xml descriptor validated by console_mode.xsd (-f flash.xml -c <op>).
# The descriptor carries the connection setup (<connect-args>: flash-xml /
# auth-file / cert-file / da-file), the DA runtime parameters (checksum_level
# among them, 1|2|4|6 -> cmd_set_runtime_parameter levels) and an ordered
# command sequence (ERASE-FLASH, FLASH-ALL, FLASH-UPDATE, WRITE-PARTITIONS,
# READ-FLASH, READ-PARTITION, WRITE-FLASH, GET-DOWNLOADED-IMAGE-FEEDBACK,
# SET-RSC, WRITE-PRIVATE-CERT, RUN-PROGRAM, REBOOT, WRITE-EFUSE, READ-EFUSE).
#
# parse_flash_xml() validates an SPFT flash.xml against the schema rules
# (enums, hex formats, required attributes, command order/occurrence) and
# map_commands() maps the parsed commands 1:1 onto the existing XMLCmd
# methods - so original SPFT V6 firmware-advance scenarios run unchanged on
# mtkclient. LIFE-CYCLE-STATUS has no xml_cmd equivalent and stays a parsed
# command only.
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


class FlashXmlError(ValueError):
    """flash.xml violates console_mode.xsd (or cannot be parsed at all)."""


# ---- console_mode.xsd restriction tables ------------------------------------

_ENUMS = {
    "com_port_type": ("USB-PCIE", "UART", "unknown"),
    "conn_stage": ("brom", "1st DA", "2nd DA", "unknown"),
    "da_log_level": ("DEBUG", "INFO", "WARN", "ERROR"),
    "system_os": ("WINDOWS", "LINUX"),
    "battery_status": ("0", "1", "2"),
    "log_channel": ("USB", "UART"),
    "checksum_level": ("1", "2", "4", "6"),
    "usb_speed": ("0", "1"),
    "action": ("DISCONNECT", "IMMEDIATE", "WARM-RESET", "COLD-RESET"),
    "file_type": ("MEMORY_FILE", "LOCAL_FILE", "REMOTE_FILE"),
    "connect_type": ("USB", "UART", "WIFI"),     # SET-BOOT-MODE/@connect_type
    "adb": ("ON", "OFF"),                        # SET-BOOT-MODE/@adb, @mobile_log
    "mobile_log": ("ON", "OFF"),
    "mode": ("META", "FASTBOOT"),                # SET-BOOT-MODE/@mode (optional)
}

_HEX16 = re.compile(r"^0x[0-9a-fA-F]{1,16}$")


def _is_hex(value: str) -> bool:
    return bool(_HEX16.match(value))


# ---- descriptor model --------------------------------------------------------

@dataclass
class FileAssistant:
    """file-assistant-type: version / file_type / file_name."""
    version: str
    file_type: str
    file_name: str


@dataclass
class ConnectArgs:
    flash_xml: str
    auth_file: str
    cert_file: str
    com_port_name: str
    baud_rate: str
    timeout_ms: str
    com_port_type: str
    conn_stage: str
    version: str
    da_file: Optional[str] = None
    da_port_name: Optional[str] = None


@dataclass
class RuntimeParameters:
    da_log_level: str
    system_os: str
    battery_status: str
    log_channel: str
    checksum_level: str
    version: str
    initialize_dram: Optional[str] = None   # YES|NO
    usb_speed: Optional[str] = None         # 0|1


@dataclass
class LogInfo:
    version: str
    log_path: str
    clean_hours: str


@dataclass
class LifeCycleStatus:
    TAG = "LIFE-CYCLE-STATUS"

    version: str
    target_file: FileAssistant


@dataclass
class GetRpmbKeyStatus:
    """console_mode.xsd target_verion_type: version + <target-file>."""
    TAG = "GET-RPMB-KEY-STATUS"

    version: str
    target_file: FileAssistant


@dataclass
class SetBootMode:
    TAG = "SET-BOOT-MODE"

    version: str
    connect_type: str          # USB | UART | WIFI (connect_type_type)
    adb: str                   # ON | OFF (on_off_type)
    mobile_log: str            # ON | OFF (on_off_type)
    mode: Optional[str] = None  # META | FASTBOOT (mode_type, optional)


@dataclass
class EraseFlash:
    TAG = "ERASE-FLASH"

    version: str
    partition: str
    length: str          # 0x.. | ALL | MAX (length_type)
    offset: str          # 0x.. | ALL (offset_type)


@dataclass
class FlashAll:
    TAG = "FLASH-ALL"

    version: str
    path_separator: str
    source_file: FileAssistant
    partitions: List[Tuple[str, str]] = field(default_factory=list)


@dataclass
class FlashUpdate:
    TAG = "FLASH-UPDATE"

    version: str
    path_separator: str
    source_file: FileAssistant
    backup_folder: str
    partitions: List[Tuple[str, str]] = field(default_factory=list)


@dataclass
class WritePartitions:
    TAG = "WRITE-PARTITIONS"

    version: str
    source_file: FileAssistant
    partitions: List[Tuple[str, str]] = field(default_factory=list)


@dataclass
class ReadFlash:
    TAG = "READ-FLASH"

    version: str
    partition: str
    length: str
    offset: str
    target_file: FileAssistant


@dataclass
class ReadPartition:
    TAG = "READ-PARTITION"

    version: str
    partition: str
    target_file: FileAssistant


@dataclass
class WriteFlash:
    TAG = "WRITE-FLASH"

    version: str
    partition: str
    offset: str
    source_file: FileAssistant


@dataclass
class GetDownloadedImageFeedback:
    TAG = "GET-DOWNLOADED-IMAGE-FEEDBACK"

    version: str
    target_file: FileAssistant


@dataclass
class SetRsc:
    TAG = "SET-RSC"

    version: str
    key: str
    source_file: FileAssistant


@dataclass
class WritePrivateCert:
    TAG = "WRITE-PRIVATE-CERT"

    version: str
    source_file: FileAssistant


@dataclass
class RunProgram:
    TAG = "RUN-PROGRAM"

    version: str
    at_address: str
    jmp_address: str
    signature_offset: str
    signature_length: str
    source_file: FileAssistant


@dataclass
class Reboot:
    TAG = "REBOOT"

    version: str
    action: str


@dataclass
class WriteEfuse:
    TAG = "WRITE-EFUSE"

    version: str
    source_file: FileAssistant


@dataclass
class ReadEfuse:
    TAG = "READ-EFUSE"

    version: str
    target_file: FileAssistant


@dataclass
class FlashXmlConfig:
    version: str
    connect_args: ConnectArgs
    runtime_parameters: RuntimeParameters
    log_info: LogInfo
    commands: list = field(default_factory=list)


# ---- validation helpers ------------------------------------------------------

def _req(el, attr: str, ctx: str) -> str:
    value = el.get(attr)
    if value is None:
        raise FlashXmlError(f"{ctx}: missing required attribute '{attr}' "
                            "(console_mode.xsd use=required)")
    return value


def _enum(el, attr: str, ctx: str) -> str:
    value = _req(el, attr, ctx)
    if value not in _ENUMS[attr]:
        raise FlashXmlError(f"{ctx}: attribute '{attr}' has invalid value "
                            f"'{value}' (allowed: {'|'.join(_ENUMS[attr])})")
    return value


def _hex(el, attr: str, ctx: str, allow_all: bool = False,
         allow_max: bool = False) -> str:
    value = _req(el, attr, ctx)
    if _is_hex(value):
        return value
    if allow_all and value == "ALL":
        return value
    if allow_max and value == "MAX":
        return value
    allowed = "0x<hex>" + (" | ALL" if allow_all else "") + \
        (" | MAX" if allow_max else "")
    raise FlashXmlError(f"{ctx}: attribute '{attr}' has invalid value "
                        f"'{value}' (expected {allowed})")


def _file_assistant(el, tag: str, ctx: str) -> FileAssistant:
    child = el.find(tag)
    if child is None:
        raise FlashXmlError(f"{ctx}: missing required element <{tag}>")
    fctx = f"{ctx}/{tag}"
    file_type = _enum(child, "file_type", fctx)
    version = _req(child, "version", fctx)
    file_name = _req(child, "file_name", fctx)
    return FileAssistant(version=version, file_type=file_type, file_name=file_name)


def _pt_list(el) -> List[Tuple[str, str]]:
    flash_list = el.find("flash_list")
    partitions = []
    if flash_list is not None:
        for pt in flash_list.findall("pt"):
            name = pt.get("name")
            if name is None:
                raise FlashXmlError("flash_list/pt: missing required attribute "
                                    "'name' (console_mode.xsd use=required)")
            partitions.append((name, (pt.text or "").strip()))
    return partitions


# ---- command parsers (tag -> (class, parser)) --------------------------------

def _p_lifecycle(el, ctx):
    return LifeCycleStatus(version=_req(el, "version", ctx),
                           target_file=_file_assistant(el, "target-file", ctx))


def _p_get_rpmb_key_status(el, ctx):
    return GetRpmbKeyStatus(version=_req(el, "version", ctx),
                            target_file=_file_assistant(el, "target-file", ctx))


def _p_set_boot_mode(el, ctx):
    kwargs = dict(version=_req(el, "version", ctx),
                  connect_type=_enum(el, "connect_type", ctx),
                  adb=_enum(el, "adb", ctx),
                  mobile_log=_enum(el, "mobile_log", ctx))
    if el.get("mode") is not None:
        kwargs["mode"] = _enum(el, "mode", ctx)
    return SetBootMode(**kwargs)


def _p_erase_flash(el, ctx):
    return EraseFlash(version=_req(el, "version", ctx),
                      partition=_req(el, "partition", ctx),
                      length=_hex(el, "length", ctx, allow_all=True, allow_max=True),
                      offset=_hex(el, "offset", ctx, allow_all=True))


def _p_flash_all(el, ctx):
    return FlashAll(version=_req(el, "version", ctx),
                    path_separator=_req(el, "path_separator", ctx),
                    source_file=_file_assistant(el, "source-file", ctx),
                    partitions=_pt_list(el))


def _p_flash_update(el, ctx):
    backup = el.find("backup_folder")
    if backup is None:
        raise FlashXmlError(f"{ctx}: missing required element <backup_folder>")
    return FlashUpdate(version=_req(el, "version", ctx),
                       path_separator=_req(el, "path_separator", ctx),
                       source_file=_file_assistant(el, "source-file", ctx),
                       backup_folder=backup.text or "",
                       partitions=_pt_list(el))


def _p_write_partitions(el, ctx):
    return WritePartitions(version=_req(el, "version", ctx),
                           source_file=_file_assistant(el, "source-file", ctx),
                           partitions=_pt_list(el))


def _p_read_flash(el, ctx):
    return ReadFlash(version=_req(el, "version", ctx),
                     partition=_req(el, "partition", ctx),
                     length=_hex(el, "length", ctx),
                     offset=_hex(el, "offset", ctx),
                     target_file=_file_assistant(el, "target-file", ctx))


def _p_read_partition(el, ctx):
    return ReadPartition(version=_req(el, "version", ctx),
                         partition=_req(el, "partition", ctx),
                         target_file=_file_assistant(el, "target-file", ctx))


def _p_write_flash(el, ctx):
    return WriteFlash(version=_req(el, "version", ctx),
                      partition=_req(el, "partition", ctx),
                      offset=_hex(el, "offset", ctx),
                      source_file=_file_assistant(el, "source-file", ctx))


def _p_feedback(el, ctx):
    return GetDownloadedImageFeedback(version=_req(el, "version", ctx),
                                      target_file=_file_assistant(el, "target-file", ctx))


def _p_set_rsc(el, ctx):
    return SetRsc(version=_req(el, "version", ctx),
                  key=_req(el, "key", ctx),
                  source_file=_file_assistant(el, "source-file", ctx))


def _p_write_private_cert(el, ctx):
    return WritePrivateCert(version=_req(el, "version", ctx),
                            source_file=_file_assistant(el, "source-file", ctx))


def _p_run_program(el, ctx):
    return RunProgram(version=_req(el, "version", ctx),
                      at_address=_hex(el, "at_address", ctx),
                      jmp_address=_hex(el, "jmp_address", ctx),
                      signature_offset=_hex(el, "signature_offset", ctx),
                      signature_length=_hex(el, "signature_length", ctx),
                      source_file=_file_assistant(el, "source-file", ctx))


def _p_reboot(el, ctx):
    return Reboot(version=_req(el, "version", ctx),
                  action=_enum(el, "action", ctx))


def _p_write_efuse(el, ctx):
    return WriteEfuse(version=_req(el, "version", ctx),
                      source_file=_file_assistant(el, "source-file", ctx))


def _p_read_efuse(el, ctx):
    return ReadEfuse(version=_req(el, "version", ctx),
                     target_file=_file_assistant(el, "target-file", ctx))


# canonical <commands> sequence from console_mode.xsd; True = maxOccurs
# unbounded (READ-FLASH / READ-PARTITION / WRITE-FLASH). GET-RPMB-KEY-STATUS and
# SET-BOOT-MODE are schema members the original table missed; RUN-PROGRAM is
# kept parseable although the published console_mode.xsd does not list it under
# <commands> (it exists in the SPFT binaries as a BROM-stage command).
_COMMAND_SCHEMA = [
    ("LIFE-CYCLE-STATUS", _p_lifecycle, False),
    ("GET-RPMB-KEY-STATUS", _p_get_rpmb_key_status, False),
    ("ERASE-FLASH", _p_erase_flash, False),
    ("FLASH-ALL", _p_flash_all, False),
    ("FLASH-UPDATE", _p_flash_update, False),
    ("WRITE-PARTITIONS", _p_write_partitions, False),
    ("READ-FLASH", _p_read_flash, True),
    ("READ-PARTITION", _p_read_partition, True),
    ("WRITE-FLASH", _p_write_flash, True),
    ("GET-DOWNLOADED-IMAGE-FEEDBACK", _p_feedback, False),
    ("SET-BOOT-MODE", _p_set_boot_mode, False),
    ("SET-RSC", _p_set_rsc, False),
    ("WRITE-PRIVATE-CERT", _p_write_private_cert, False),
    ("RUN-PROGRAM", _p_run_program, False),
    ("REBOOT", _p_reboot, False),
    ("WRITE-EFUSE", _p_write_efuse, False),
    ("READ-EFUSE", _p_read_efuse, False),
]

_TAG_INDEX = {tag: i for i, (tag, _, _) in enumerate(_COMMAND_SCHEMA)}


# ---- top-level parsers -------------------------------------------------------

def _parse_connect_args(el, ctx) -> ConnectArgs:
    def child_text(tag) -> str:
        # required element, text may be empty (XSD allows "")
        child = el.find(tag)
        if child is None:
            raise FlashXmlError(f"{ctx}: missing required element <{tag}>")
        return child.text or ""

    def child_text_opt(tag) -> Optional[str]:
        child = el.find(tag)
        if child is None:
            return None
        return child.text or ""

    return ConnectArgs(
        version=_req(el, "version", ctx),
        com_port_name=_req(el, "com_port_name", ctx),
        baud_rate=_req(el, "baud_rate", ctx),
        timeout_ms=_req(el, "timeout_ms", ctx),
        com_port_type=_enum(el, "com_port_type", ctx),
        conn_stage=_enum(el, "conn_stage", ctx),
        da_port_name=el.get("da_port_name"),
        flash_xml=child_text("flash-xml"),
        auth_file=child_text("auth-file"),
        cert_file=child_text("cert-file"),
        da_file=child_text_opt("da-file"),
    )


def _parse_runtime_parameter(el, ctx) -> RuntimeParameters:
    return RuntimeParameters(
        version=_req(el, "version", ctx),
        da_log_level=_enum(el, "da_log_level", ctx),
        system_os=_enum(el, "system_os", ctx),
        battery_status=_enum(el, "battery_status", ctx),
        log_channel=_enum(el, "log_channel", ctx),
        checksum_level=_enum(el, "checksum_level", ctx),
        initialize_dram=el.get("initialize_dram"),
        usb_speed=el.get("usb_speed"),
    )


def _parse_log_info(el, ctx) -> LogInfo:
    return LogInfo(version=_req(el, "version", ctx),
                   log_path=_req(el, "log_path", ctx),
                   clean_hours=_req(el, "clean_hours", ctx))


def parse_flash_xml(data: str) -> FlashXmlConfig:
    """
    Parse an SPFT V6 flash.xml descriptor (console_mode.xsd) into a
    FlashXmlConfig. Raises FlashXmlError on any schema violation.
    """
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise FlashXmlError(f"flash.xml parse error: {e}") from e
    if root.tag != "cflashtool-config":
        raise FlashXmlError(f"flash.xml: unexpected root element <{root.tag}> "
                            "(expected <cflashtool-config>)")
    version = _req(root, "version", "cflashtool-config")

    general = root.find("general")
    if general is None:
        raise FlashXmlError("flash.xml: missing required element <general>")
    general_tags = [child.tag for child in general]
    # unknown children first: the more specific diagnostic wins
    for tag in general_tags:
        if tag not in ("connect-args", "runtime-parameter", "log-info"):
            raise FlashXmlError(f"flash.xml/general: unknown element <{tag}>")
    for tag in ("connect-args", "runtime-parameter", "log-info"):
        if tag not in general_tags:
            raise FlashXmlError(f"flash.xml/general: missing required element <{tag}>")
    connect_args = _parse_connect_args(general.find("connect-args"),
                                       "flash.xml/general/connect-args")
    runtime_parameters = _parse_runtime_parameter(
        general.find("runtime-parameter"), "flash.xml/general/runtime-parameter")
    log_info = _parse_log_info(general.find("log-info"), "flash.xml/general/log-info")

    commands_el = root.find("commands")
    if commands_el is None:
        raise FlashXmlError("flash.xml: missing required element <commands>")
    commands = []
    last_index = -1
    seen = set()
    for child in commands_el:
        tag = child.tag
        if tag not in _TAG_INDEX:
            raise FlashXmlError(f"flash.xml/commands: unknown command element "
                                f"<{tag}> (not part of console_mode.xsd)")
        index = _TAG_INDEX[tag]
        if index < last_index:
            raise FlashXmlError(f"flash.xml/commands: <{tag}> appears out of "
                                "the console_mode.xsd sequence order")
        last_index = index
        unbounded = _COMMAND_SCHEMA[index][2]
        if not unbounded:
            if tag in seen:
                raise FlashXmlError(f"flash.xml/commands: <{tag}> may appear at "
                                    "most once (console_mode.xsd maxOccurs=1)")
            seen.add(tag)
        parser = _COMMAND_SCHEMA[index][1]
        commands.append(parser(child, f"flash.xml/commands/{tag}"))

    return FlashXmlConfig(version=version, connect_args=connect_args,
                          runtime_parameters=runtime_parameters,
                          log_info=log_info, commands=commands)


# ---- 1:1 mapping onto XMLCmd -------------------------------------------------

def _to_int(value: str, what: str) -> int:
    try:
        return int(value, 16)
    except ValueError:
        raise FlashXmlError(f"{what}: value '{value}' cannot be mapped onto the "
                            "xml_cmd API (concrete 0x<hex> required)") from None


def map_commands(config: FlashXmlConfig, xmlcmd) -> List[Tuple[str, str]]:
    """
    Map every parsed flash.xml command onto the existing XMLCmd methods, in
    order. Returns a list of (logical_command, xmldata) tuples ready for
    xmlflash.send_command(). LIFE-CYCLE-STATUS is parsed but not mapped
    (no xml_cmd equivalent).
    """
    mapped = []
    for cmd in config.commands:
        if isinstance(cmd, (LifeCycleStatus, GetRpmbKeyStatus, SetBootMode)):
            # parsed-only: no xml_cmd equivalent (see module docstring)
            continue
        if isinstance(cmd, EraseFlash):
            if cmd.length in ("ALL", "MAX") or cmd.offset == "ALL":
                raise FlashXmlError(
                    f"ERASE-FLASH length/offset '{cmd.length}/{cmd.offset}' "
                    "cannot be mapped onto cmd_erase_flash: mtkclient needs a "
                    "concrete 0x<hex> range (resolve it from the partition "
                    "layout first)")
            data = xmlcmd.cmd_erase_flash(partition=cmd.partition,
                                          offset=_to_int(cmd.offset, "ERASE-FLASH offset"),
                                          length=_to_int(cmd.length, "ERASE-FLASH length"))
        elif isinstance(cmd, FlashAll):
            data = xmlcmd.cmd_flash_all()
        elif isinstance(cmd, FlashUpdate):
            data = xmlcmd.cmd_flash_update()
        elif isinstance(cmd, WritePartitions):
            data = xmlcmd.cmd_write_partitions([name for name, _ in cmd.partitions])
        elif isinstance(cmd, ReadFlash):
            data = xmlcmd.cmd_read_flash(partition=cmd.partition,
                                         offset=_to_int(cmd.offset, "READ-FLASH offset"),
                                         length=_to_int(cmd.length, "READ-FLASH length"))
        elif isinstance(cmd, ReadPartition):
            data = xmlcmd.cmd_read_partition(partition=cmd.partition)
        elif isinstance(cmd, WriteFlash):
            data = xmlcmd.cmd_write_flash(partition=cmd.partition,
                                          offset=_to_int(cmd.offset, "WRITE-FLASH offset"))
        elif isinstance(cmd, GetDownloadedImageFeedback):
            data = xmlcmd.cmd_get_downloaded_image_feedback()
        elif isinstance(cmd, SetRsc):
            data = xmlcmd.cmd_set_rsc(key=cmd.key)
        elif isinstance(cmd, WritePrivateCert):
            data = xmlcmd.cmd_write_private_cert(cert_file=cmd.source_file.file_name)
        elif isinstance(cmd, RunProgram):
            # SPFT's RUN-PROGRAM is CMD:RUN-PROGRAM targeted at BROM
            # (RunProgramCmdXML, BROM_NODE_NAME) - NOT the DA-stage CMD:BOOT-TO.
            # Silently substituting another command on the wire would be unsafe;
            # refuse until a proper xml_cmd.cmd_run_program exists.
            raise FlashXmlError(
                "RUN-PROGRAM has no xml_cmd equivalent (SPFT sends CMD:RUN-PROGRAM "
                "to BROM, not CMD:BOOT-TO to the DA) - refusing to substitute")
        elif isinstance(cmd, Reboot):
            data = xmlcmd.cmd_reboot(disconnect=(cmd.action == "DISCONNECT"))
        elif isinstance(cmd, WriteEfuse):
            data = xmlcmd.cmd_write_efuse()
        elif isinstance(cmd, ReadEfuse):
            data = xmlcmd.cmd_read_efuse()
        else:  # pragma: no cover - every parsed command is handled above
            raise FlashXmlError(f"Unhandled flash.xml command: {cmd!r}")
        mapped.append((cmd.TAG, data))
    return mapped
