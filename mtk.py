#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2025 (refactored & cleaned 2025/2026)
# Licensed under GPLv3 License

import argparse
import logging
import os
import sys

from mtkclient.Library.mtk_main import Main, metamodes

INFO = "MTK Flash/Exploit Client V2.1.4 (c) B.Kerler 2018-2026"

CMDS_HELP = {
    "printgpt": "Print GPT Table information",
    "gpt": "Save gpt table to given directory",
    "r": "Read flash to filename",
    "rl": "Read all partitions from flash to a directory",
    "rf": "Read whole flash to file",
    "rs": "Read sectors starting at start_sector to filename",
    "ro": "Read flash starting at offset to filename",
    "fs": "Mount the device as a FUSE filesystem",
    "w": "Write partition from filename",
    "wf": "Write flash from filename",
    "wl": "Write partitions from directory path to flash",
    "wo": "Write flash starting at offset from filename",
    "e": "Erase partition",
    "es": "Erase partition with sector count",
    "ess": "Erase sector with sector count",
    "footer": "Read crypto footer from flash",
    "reset": "Send mtk reset command",
    "meta": "Switch to meta mode",
    "meta2": "Switch to meta mode (wdt)",
    "dumpbrom": "Try to dump the bootrom",
    "dumpsram": "Try to dump the sram",
    "dumppreloader": "Try to dump the preloader",
    "payload": "Run a specific kamakiri / da payload",
    "crash": "Try to crash the preloader",
    "brute": "Bruteforce the kamakiri var1",
    "gettargetconfig": "Get target config (sbc, daa, etc.)",
    "logs": "Get target logs",
    "peek": "Read memory in patched preloader mode",
    "stage": "Run stage2 payload via boot rom mode (kamakiri)",
    "plstage": "Run stage2 payload via preloader mode (send_da)",
    "da": "Run da xflash/legacy special commands",
    "script": "Run multiple commands using text script",
    "multi": "Run multiple commands using semicolon-separated list",
    "devices": "List supported devices"
}


# ================== Argument Groups ==================

# NOTE: these "shared" options are attached both to the top-level parser and
# to every subcommand parser (via parents=[base]). argparse dispatches a
# subcommand by parsing its remaining args into a *fresh* namespace and then
# copying every attribute from that namespace onto the parent one - which
# means a subparser's own default silently overwrites a value already set
# by an option given *before* the subcommand (e.g. `mtk.py --stock r ...`).
# default=argparse.SUPPRESS stops a subparser from ever re-asserting its
# default for these dests; the real defaults are applied exactly once, by
# seeding the initial namespace passed to parser.parse_args() in main().
SHARED_DEFAULTS = {}


def _shared_arg(g, *flags, default=None, **kwargs):
    dest = kwargs.get('dest')
    if dest is None:
        dest = flags[-1].lstrip('-').replace('-', '_')
    SHARED_DEFAULTS[dest] = default
    g.add_argument(*flags, default=argparse.SUPPRESS, **kwargs)


def add_connection_group(parser):
    g = parser.add_argument_group("Connection & Interface")
    _shared_arg(g, '--vid', type=str)
    _shared_arg(g, '--pid', type=str)
    _shared_arg(g, '--serialport', nargs='?', const='DETECT',
                help='Use serial port (can be DETECT)')
    _shared_arg(g, '--noreconnect', action='store_true', default=False)
    _shared_arg(g, '--stock', action='store_true', default=False, help='use stock da')
    _shared_arg(g, '--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    _shared_arg(g, '--logchannel', help='Set log channel ("UART","USB", "BOTH")', default="UART")
    _shared_arg(g, '--loglevel', help='Set log level (0=Trace, 2=Normal)')
    _shared_arg(g, '--write_preloader_to_file', action='store_true', default=False,
                help='Dump preloader to file')
    _shared_arg(g, '--generatekeys', action='store_true', default=False, help='Derive HW keys')
    _shared_arg(g, '--iot', help='Use special mode for iot MT6261/2301', action="store_true",
                default=False)
    _shared_arg(g, '--socid', action='store_true', default=False, help='Read Soc ID')

def add_auth_group(parser):
    g = parser.add_argument_group("Authentication")
    _shared_arg(g, '--auth', type=str, help="Use auth file (auth_sv5.auth)")
    _shared_arg(g, '--cert', type=str, help="Use cert file")


def add_debug_group(parser):
    g = parser.add_argument_group("Debug & Sector")
    _shared_arg(g, '--debugmode', action='store_true', default=False, help='Enable verbose mode')

def add_exploit_group(parser):
    g = parser.add_argument_group("Bootrom / Preloader Exploit")
    _shared_arg(g, '--loader', type=str, help='Use specific DA loader, disable autodetection')
    _shared_arg(g, '--preloader', help='Set the preloader filename for dram config')
    _shared_arg(g, '--ptype', help='Payload type: amonet, kamakiri, kamakiri2, carbonara')
    _shared_arg(g, '--var1', help='Set kamakiri specific var1 value')
    _shared_arg(g, '--uart_addr', help='Set payload uart_addr value')
    _shared_arg(g, '--da_addr', help='Set a specific da payload addr')
    _shared_arg(g, '--brom_addr', help='Set a specific brom payload addr')
    _shared_arg(g, '--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    _shared_arg(g, '--wdt', help='Set a specific watchdog addr')
    _shared_arg(g, '--skipwdt', action='store_true', default=False, help='Skip wdt init')
    _shared_arg(g, '--crash', action='store_true', default=False,
                help='Enforce crash if device is in pl mode')
    _shared_arg(g, '--appid', help='Use app id (hexstring)')

def add_gpt_group(parser):
    g = parser.add_argument_group("GPT & Partition")
    _shared_arg(g, "--sectorsize", default='0x200', help='Set default sector size')
    _shared_arg(g, '--gpt-num-part-entries', default='0', help='Set GPT entry count')
    _shared_arg(g, '--gpt-part-entry-size', default='0', help='Set GPT entry size')
    _shared_arg(g, '--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    _shared_arg(g, '--parttype', help='Partition type (user/boot1/rpmb/lu0 etc.)')
    _shared_arg(g, '--skip', help='Skip partitions (comma separated names)')


# ================== Base Parser ==================

def create_base_parser():
    parser = argparse.ArgumentParser(
        description=INFO,
        add_help=False
    )
    add_connection_group(parser)
    add_auth_group(parser)
    add_debug_group(parser)
    add_exploit_group(parser)
    add_gpt_group(parser)
    return parser


# ================== Helper for common flash commands ==================

def add_common_flash_cmd(subparsers, name, title, parent_parser):
    return subparsers.add_parser(
        name,
        help=title,
        parents=[parent_parser]
    )


def main():
    base = create_base_parser()

    parser = argparse.ArgumentParser(
        description=INFO,
        parents=[base],
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='cmd', required=True, metavar='command')

    # ─── Commands using most common options ──────────────────────────────

    common_cmds = [
        "printgpt", "gpt", "r", "rl", "rf", "rs", "ro",
        "w", "wf", "wl", "wo", "e", "es", "ess", "footer"
    ]

    cmd_parsers = {}
    for cmd in common_cmds:
        cmd_parsers[cmd] = add_common_flash_cmd(
            subparsers, cmd, CMDS_HELP.get(cmd, cmd), base
        )

    # Specific positional/required arguments
    # Read partition(s)
    cmd_parsers["r"].add_argument("partitionname", help="Partitions (comma sep)")
    cmd_parsers["r"].add_argument("filename", help="Output files (comma sep)")
    cmd_parsers["r"].add_argument("--offset", help="Offset to read from")
    cmd_parsers["r"].add_argument("--length", help="Length to read")

    # Write partition(s)
    cmd_parsers["w"].add_argument("partitionname", help="Partitions (comma sep)")
    cmd_parsers["w"].add_argument("filename", help="Input files (comma sep)")
    cmd_parsers["w"].add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')

    # Directory based
    for cmd in ["rl", "gpt", "wl"]:
        cmd_parsers[cmd].add_argument("directory", help="Directory path")

    # Full flash image
    for cmd in ["rf", "wf"]:
        cmd_parsers[cmd].add_argument("filename", help="Flash image file")
        cmd_parsers[cmd].add_argument("--offset", help="Byte offset")
        cmd_parsers[cmd].add_argument("--length", help="Length")
        cmd_parsers[cmd].add_argument('--disable_internal_flash',
                                      help='Disable internal flash read for iot MT6261/2301',
                                      action="store_true",
                                      default=False)

    # Sector based
    for cmd in ["rs", "ess"]:
        cmd_parsers[cmd].add_argument("startsector", help="Start sector")
        cmd_parsers[cmd].add_argument("sectors", help="Sector count")

    # Offset based
    for cmd in ["ro", "wo"]:
        cmd_parsers[cmd].add_argument("offset", help="Byte offset")
        cmd_parsers[cmd].add_argument("length", help="Length")
        cmd_parsers[cmd].add_argument("filename", help="File")


    # Erase
    cmd_parsers["e"].add_argument("partitionname", help="Partition to erase")
    cmd_parsers["es"].add_argument("partitionname", help="Partition to erase")
    cmd_parsers["es"].add_argument("sectors", help="Sectors count")

    # Footer
    cmd_parsers["footer"].add_argument("filename", help="Filename to store footer")

    # ─── Other commands ──────────────────────────────────────────────────

    cmd_fs = subparsers.add_parser("fs", help="Mount as FUSE filesystem")
    cmd_fs.add_argument("mountpoint")
    cmd_fs.add_argument("--rw", action="store_true")

    subparsers.add_parser("reset", help="Send reset command", parents=[base])
    subparsers.add_parser("meta", help="Enter meta mode", parents=[base]) \
        .add_argument("metamode", nargs="?", default=None, help=f"[{metamodes}]")
    subparsers.add_parser("meta2", help="Enter meta mode (wdt)", parents=[base])

    subparsers.add_parser("dumpbrom", help=CMDS_HELP["dumpbrom"], parents=[base]
                          ).add_argument('--filename', help='Optional filename')
    subparsers.add_parser("dumpsram", help=CMDS_HELP["dumpsram"], parents=[base]
                          ).add_argument('--filename', help='Optional filename')
    subparsers.add_parser("dumppreloader", help=CMDS_HELP["dumppreloader"], parents=[base]
                          ).add_argument('--filename', help='Optional filename')

    parser_payload = subparsers.add_parser("payload", help=CMDS_HELP["payload"], parents=[base])
    parser_payload.add_argument("--payload", type=str, help="Payload file (optional)")
    parser_payload.add_argument("--metamode", type=str, default=None, help=f"metamode to use [{metamodes}]")

    subparsers.add_parser("crash", help=CMDS_HELP["crash"], parents=[base])
    subparsers.add_parser("brute", help=CMDS_HELP["brute"], parents=[base])
    subparsers.add_parser("gettargetconfig", help=CMDS_HELP["gettargetconfig"], parents=[base])
    subparsers.add_parser("logs", help=CMDS_HELP["logs"], parents=[base])

    cmd_peek=subparsers.add_parser("peek", help=CMDS_HELP["peek"], parents=[base])
    cmd_peek.add_argument('address', help='Address to read from memory')
    cmd_peek.add_argument('length', help='Bytes to read from memory')
    cmd_peek.add_argument("--filename", help="Save to file (optional)")

    stage=subparsers.add_parser("stage", help=CMDS_HELP["stage"], parents=[base])
    stage.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    stage.add_argument('--stage2', help='Set stage2 filename')
    stage.add_argument('--stage2addr', help='Set stage2 loading address')
    stage.add_argument('--filename', help='Set stage1 loader filename')

    plstage=subparsers.add_parser("plstage", help=CMDS_HELP["plstage"], parents=[base])
    plstage.add_argument('--startpartition', help='Option for plstage - Boot to (lk, tee1)')
    plstage.add_argument('--offset', help='Address to read from memory')
    plstage.add_argument('--length', help='Bytes to read from memory')
    plstage.add_argument('--pl', help='pl stage filename (optional)')
    plstage.add_argument("--metamode", type=str, help="metamode to use [off,usb,uart]")


    # DA subcommands
    p_da = subparsers.add_parser("da", help=CMDS_HELP["da"], parents=[base])
    da_subs = p_da.add_subparsers(dest="subcmd", required=True)

    da_peek = da_subs.add_parser("peek", parents=[base])
    da_peek.add_argument('address', type=str, help="Address to read from (hex value)")
    da_peek.add_argument('length', type=str, help="Length to read")
    da_peek.add_argument('--filename', type=str, help="Save to file (optional)")

    da_subs.add_parser("efuse", parents=[base], help="Read efuses")
    da_subs.add_parser("generatekeys", parents=[base], help="Generate keys")
    da_subs.add_parser("keyserver", parents=[base], help="Enable key server")
    da_meta = da_subs.add_parser("meta", parents=[base], help="MetaMode Tools")
    da_meta.add_argument("metamode", type=str, help="metamode to use [off,usb,uart]")
    da_vbmeta = da_subs.add_parser("vbmeta", parents=[base], help="Patch vbmeta partition")
    da_vbmeta.add_argument("vbmode", type=str,
                           help="vbmeta mode (0=locked, 1=disable_verity, 2=disable_verification, 3=disable verity+verification)")

    da_nvitem = da_subs.add_parser("nvitem", parents=[base], help="nvitem decryption/encryption")
    da_nvitem.add_argument('filename',type=str, help="LD0B_001.bin")
    da_nvitem.add_argument('--encrypt', action="store_true", default=False, help='Encrypt')
    da_nvitem.add_argument('--seed', type=str, default="3132616263646566", help='seed')
    da_nvitem.add_argument('--aeskey', type=str, default="0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000", help='aeskey')

    da_patchmodem = da_subs.add_parser("patchmodem", parents=[base], help="patch modem for imei")

    da_imei = da_subs.add_parser("imei", parents=[base], help="imei decryption/encryption")
    da_imei.add_argument('imeis', type=str, help="imeis, separated by ,",nargs="?", default="")
    da_imei.add_argument('--product', type=str, default="thunder", help='productname')
    da_imei.add_argument('--write', action="store_true", default=False, help='Write')
    da_imei.add_argument('--seed', type=str, default="3132616263646566", help='seed')
    da_imei.add_argument('--aeskey', type=str,
                           default="0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000", help='aeskey')

    da_rpmb = da_subs.add_parser("rpmb", parents=[base], help="RPMB Tools")
    da_rpmb_cmds = da_rpmb.add_subparsers(dest='rpmb_subcmd', help='Commands: r w')
    da_rpmb_r = da_rpmb_cmds.add_parser("r", help="Read rpmb")
    da_rpmb_r.add_argument('filename', type=str, help="Filename to write data into", default="rpmb.bin", nargs="?")
    da_rpmb_r.add_argument('--sector', help='Start sector (offset/0x100 bytes)')
    da_rpmb_r.add_argument('--sectors', help='Sector count')

    da_rpmb_w = da_rpmb_cmds.add_parser("w", help="Write rpmb")
    da_rpmb_w.add_argument('filename', type=str, help="Filename to write from", default="rpmb.bin", nargs="?")
    da_rpmb_w.add_argument('--sector', help='Start sector (offset/0x100 bytes)')
    da_rpmb_w.add_argument('--sectors', help='Sector count')

    da_rpmb_e = da_rpmb_cmds.add_parser("e", help="Erase rpmb")
    da_rpmb_e.add_argument('--sector', help='Start sector (offset/0x100 bytes)')
    da_rpmb_e.add_argument('--sectors', help='Sector count')

    da_rpmb_a = da_rpmb_cmds.add_parser("a", help="Auth rpmbkey")
    da_rpmb_a.add_argument('--rpmbkey', help='rpmb key (hexstring, 32 bytes)')

    da_dump = da_subs.add_parser("memdump", parents=[base], help="Dump whole memory areas")
    da_dump.add_argument('directory', type=str, help="Directory to dump ram dump files")
    da_dump.add_argument('--startpartition', help='Option for plstage - Boot to (lk, tee1)')

    da_dramdump = da_subs.add_parser("memdram", parents=[base], help="Dump dram memory")
    da_dramdump.add_argument('directory', type=str, help="Directory to dump ram dump files")
    da_dramdump.add_argument('--startpartition', help='Option for plstage - Boot to (lk, tee1)')

    da_dumpbrom = da_subs.add_parser("dumpbrom", parents=[base], help="Dump whole memory areas")

    da_poke = da_subs.add_parser("poke", parents=[base], help="Write memory")
    da_poke.add_argument('address', type=str, help="Address to read from (hex value)")
    da_poke.add_argument('data', type=str, help="Data to write")

    da_unlock = da_subs.add_parser("seccfg", parents=[base], help="Unlock device / Configure seccfg")
    da_unlock.add_argument('flag', type=str, help="Needed flag (unlock,lock)")

    # Minimal commands
    subparsers.add_parser("devices", help=CMDS_HELP["devices"])\
        .add_argument("--filter", help="Optional Filter string")

    subparsers.add_parser("script", help=CMDS_HELP["script"])\
        .add_argument("script")

    subparsers.add_parser("multi", help=CMDS_HELP["multi"])\
        .add_argument("commands")

    # ─── Parse & Run ─────────────────────────────────────────────────────

    # Seed the real defaults for every option shared with subparsers (see
    # SHARED_DEFAULTS / _shared_arg above) via a pre-populated namespace,
    # rather than parser.set_defaults(): set_defaults() also overwrites
    # action.default in place, and since these actions are the exact same
    # objects shared across the top-level parser and every subparser (via
    # parents=[base]), that would silently undo the SUPPRESS default
    # everywhere and reintroduce the bug this is working around. Passing a
    # pre-filled namespace instead only sets attributes argparse doesn't
    # already see, so an option's default only "wins" if the option truly
    # never appeared anywhere on the command line.
    args = parser.parse_args(namespace=argparse.Namespace(**SHARED_DEFAULTS))

    if not args.cmd:
        parser.print_help()
        sys.exit(0)

    logging.basicConfig(
        level=logging.DEBUG if args.debugmode else logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    if args.debugmode:
        if not os.path.exists("logs"):
            os.makedirs("logs")

    mtk = Main(args)
    return mtk.run(parser)


if __name__ == '__main__':
    sys.exit(main() or 0)
