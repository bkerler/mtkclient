#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2024.
# Licensed under GPLv3 License
import argparse
from mtkclient.Library.mtk_main import Main, metamodes

info = "MTK Flash/Exploit Client Public V2.0.1 (c) B.Kerler 2018-2024"

cmds = {
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
    "dumpbrom": "Try to dump the bootrom",
    "dumpsram": "Try to dump the sram",
    "dumppreloader": "Try to dump the preloader",
    "payload": "Run a specific kamakiri / da payload, if no filename is given, generic patcher is used",
    "crash": "Try to crash the preloader",
    "brute": "Bruteforce the kamakiri var1",
    "gettargetconfig": "Get target config (sbc, daa, etc.)",
    "logs": "Get target logs",
    "meta": "Set meta mode",
    "peek": "Read memory in patched preloader mode",
    "stage": "Run stage2 payload via boot rom mode (kamakiri)",
    "plstage": "Run stage2 payload via preloader mode (send_da)",
    "da": "Run da xflash/legacy special commands",
    "script": "Run multiple commands using text script"
}

if __name__ == '__main__':
    print(info)
    print("")
    parser = argparse.ArgumentParser(description=info)
    subparsers = parser.add_subparsers(dest="cmd",
                                       help='Valid commands are: \n' +
                                            'printgpt, gpt, r, rl, rf, fs, rs, w, wf, wl, e, es, footer, reset, \n' +
                                            'dumpbrom, dumpsram, dumppreloader, payload, crash, brute, \n' +
                                            'gettargetconfig, peek, stage, plstage, da, script\n')

    parser_script = subparsers.add_parser("script", help="Run text script")
    parser_printgpt = subparsers.add_parser("printgpt", help="Print GPT Table information")
    parser_gpt = subparsers.add_parser("gpt", help="Save gpt table to given directory")
    parser_r = subparsers.add_parser("r", help="Read flash to filename")
    parser_rl = subparsers.add_parser("rl", help="Read all partitions from flash to a directory")
    parser_rf = subparsers.add_parser("rf", help="Read whole flash to file")
    parser_rs = subparsers.add_parser("rs", help="Read sectors starting at start_sector to filename")
    parser_ro = subparsers.add_parser("ro", help="Read flash starting at offset to filename")
    parser_fs = subparsers.add_parser("fs", help="Mount the device as a FUSE filesystem")
    parser_w = subparsers.add_parser("w", help="Write partition from filename")
    parser_wf = subparsers.add_parser("wf", help="Write flash from filename")
    parser_wl = subparsers.add_parser("wl", help="Write partitions from directory path to flash")
    parser_wo = subparsers.add_parser("wo", help="Write flash starting at offset from filename")
    parser_e = subparsers.add_parser("e", help="Erase partition")
    parser_es = subparsers.add_parser("es", help="Erase partition with sector count")
    parser_ess = subparsers.add_parser("ess", help="Erase sector with sector count")
    parser_footer = subparsers.add_parser("footer", help="Read crypto footer from flash")
    parser_reset = subparsers.add_parser("reset", help="Send mtk reset command")

    parser_dumpbrom = subparsers.add_parser("dumpbrom", help="Try to dump the bootrom")
    parser_dumpsram = subparsers.add_parser("dumpsram", help="Try to dump the sram")
    parser_dumppreloader = subparsers.add_parser("dumppreloader", help="Try to dump the preloader")
    parser_payload = subparsers.add_parser("payload",
                                           help="Run a specific kamakiri / da payload, " +
                                                "if no filename is given, generic patcher is used")
    parser_crash = subparsers.add_parser("crash", help="Try to crash the preloader")
    parser_brute = subparsers.add_parser("brute", help="Bruteforce the kamakiri var1")
    parser_gettargetconfig = subparsers.add_parser("gettargetconfig", help="Get target config (sbc, daa, etc.)")
    parser_peek = subparsers.add_parser("peek", help="Read memory in patched preloader mode")
    parser_stage = subparsers.add_parser("stage", help="Run stage2 payload via boot rom mode (kamakiri)")
    parser_plstage = subparsers.add_parser("plstage", help="Run stage2 payload via preloader mode (send_da)")
    parser_logs = subparsers.add_parser("logs", help="Read logs")
    parser_meta = subparsers.add_parser("meta", help="Enter meta mode")

    parser_da = subparsers.add_parser("da", help="Run da special commands")
    da_cmds = parser_da.add_subparsers(dest='subcmd', help='Commands: peek poke keys unlock memdump seccfg rpmb efuse')

    da_efuse = da_cmds.add_parser("efuse", help="Read efuses")
    da_efuse.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_efuse.add_argument('--loader', type=str, help='Use specific loader, disable autodetection')

    da_keys = da_cmds.add_parser("generatekeys", help="Generate keys")
    da_keys.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_keys.add_argument('--loader', type=str, help='Use specific loader, disable autodetection')

    da_meta = da_cmds.add_parser("meta", help="MetaMode Tools")
    da_meta.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_meta.add_argument("metamode", type=str, help="metamode to use [off,usb,uart]")

    da_rpmb = da_cmds.add_parser("rpmb", help="RPMB Tools")

    da_rpmb_cmds = da_rpmb.add_subparsers(dest='rpmb_subcmd', help='Commands: r w')
    da_rpmb_r = da_rpmb_cmds.add_parser("r", help="Read rpmb")
    da_rpmb_r.add_argument('--filename', type=str, help="Filename to write data into")
    da_rpmb_r.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_rpmb_r.add_argument('--loader', type=str, help='Use specific loader, disable autodetection')
    da_rpmb_r.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    da_rpmb_r.add_argument('--cert', type=str, help="Use cert file")

    da_rpmb_w = da_rpmb_cmds.add_parser("w", help="Write rpmb")
    da_rpmb_w.add_argument('filename', type=str, help="Filename to write from")
    da_rpmb_w.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_rpmb_w.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    da_rpmb_w.add_argument('--cert', type=str, help="Use cert file")
    da_rpmb_w.add_argument('--loader', type=str, help='Use specific loader, disable autodetection')

    da_rpmb_e = da_rpmb_cmds.add_parser("e", help="Erase rpmb")
    da_rpmb_e.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_rpmb_e.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    da_rpmb_e.add_argument('--cert', type=str, help="Use cert file")
    da_rpmb_e.add_argument('--loader', type=str, help='Use specific loader, disable autodetection')

    da_peek = da_cmds.add_parser("peek", help="Read memory")
    da_peek.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_peek.add_argument('address', type=str, help="Address to read from (hex value)")
    da_peek.add_argument('length', type=str, help="Length to read")
    da_peek.add_argument('--loader', type=str, help='Use specific loader, disable autodetection')
    da_peek.add_argument('--filename', type=str, help="Filename to write data into")
    da_peek.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    da_peek.add_argument('--cert', type=str, help="Use cert file")

    da_dump = da_cmds.add_parser("memdump", help="Dump whole memory areas")
    da_dump.add_argument('directory', type=str, help="Directory to dump ram dump files")
    da_dump.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_dump.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    da_dump.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    da_dump.add_argument('--cert', type=str, help="Use cert file")

    da_dumpbrom = da_cmds.add_parser("dumpbrom", help="Dump whole memory areas")
    da_dumpbrom.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_dumpbrom.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    da_dumpbrom.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    da_dumpbrom.add_argument('--cert', type=str, help="Use cert file")

    da_poke = da_cmds.add_parser("poke", help="Write memory")
    da_poke.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_poke.add_argument('address', type=str, help="Address to read from (hex value)")
    da_poke.add_argument('data', type=str, help="Data to write")
    da_poke.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    da_poke.add_argument('--filename', type=str, help="Filename to read data from")
    da_poke.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    da_poke.add_argument('--cert', type=str, help="Use cert file")

    da_unlock = da_cmds.add_parser("seccfg", help="Unlock device / Configure seccfg")
    da_unlock.add_argument('--preloader', help='Set the preloader filename for dram config')
    da_unlock.add_argument('flag', type=str, help="Needed flag (unlock,lock)")
    da_unlock.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    da_unlock.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    da_unlock.add_argument('--cert', type=str, help="Use cert file")

    parser_script.add_argument('script', help='Text script to run')
    parser_script.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_script.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_script.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_script.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_script.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_script.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_script.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_script.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_script.add_argument('--skipwdt', help='Skip wdt init')
    parser_script.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_script.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_script.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_script.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_script.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_script.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_script.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_script.add_argument('--ptype', help='Set the payload type ("amonet","kamakiri","kamakiri2",'
                                               '"carbonara" kamakiri2/da used by default)')
    parser_script.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_script.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_script.add_argument('--socid', help='Read Soc ID')
    parser_script.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_script.add_argument('--cert', type=str, help="Use cert file")

    parser_printgpt.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_printgpt.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_printgpt.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_printgpt.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_printgpt.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_printgpt.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_printgpt.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_printgpt.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_printgpt.add_argument('--skipwdt', help='Skip wdt init')
    parser_printgpt.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_printgpt.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_printgpt.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_printgpt.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_printgpt.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_printgpt.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_printgpt.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_printgpt.add_argument('--ptype',
                                 help='Set the payload type ("amonet","kamakiri","kamakiri2","carbonara" '
                                      'kamakiri2/da used by default)')
    parser_printgpt.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_printgpt.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_printgpt.add_argument('--socid', help='Read Soc ID')
    parser_printgpt.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_printgpt.add_argument('--cert', type=str, help="Use cert file")

    parser_gpt.add_argument('directory', help='Filename to store gpt files')
    parser_gpt.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_gpt.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_gpt.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_gpt.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_gpt.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_gpt.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_gpt.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_gpt.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_gpt.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_gpt.add_argument('--skipwdt', help='Skip wdt init')
    parser_gpt.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_gpt.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_gpt.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_gpt.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_gpt.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_gpt.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_gpt.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_gpt.add_argument('--ptype',
                            help='Set the payload type ("amonet","kamakiri","kamakiri2","carbonara", kamakiri2/da ' +
                                 'used by default)')
    parser_gpt.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_gpt.add_argument('--parttype', help='Partition type\n' +
                                               '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                               '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_gpt.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_gpt.add_argument('--socid', help='Read Soc ID')
    parser_gpt.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_gpt.add_argument('--cert', type=str, help="Use cert file")

    parser_r.add_argument('partitionname', help='Partitions to read (separate by comma for multiple partitions)')
    parser_r.add_argument('filename', help='Filename to store files (separate by comma for multiple filenames)')
    parser_r.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_r.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_r.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_r.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_r.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_r.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_r.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_r.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_r.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_r.add_argument('--skipwdt', help='Skip wdt init')
    parser_r.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_r.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_r.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_r.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_r.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_r.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_r.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_r.add_argument('--ptype',
                          help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                               'used by default)')
    parser_r.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_r.add_argument('--parttype', help='Partition type\n' +
                                             '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                             '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_r.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_r.add_argument('--socid', help='Read Soc ID')
    parser_r.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_r.add_argument('--cert', type=str, help="Use cert file")

    parser_rl.add_argument('directory', help='Directory to write dumped partitions into')
    parser_rl.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_rl.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_rl.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_rl.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_rl.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_rl.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_rl.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_rl.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_rl.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_rl.add_argument('--skipwdt', help='Skip wdt init')
    parser_rl.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_rl.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_rl.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_rl.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_rl.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_rl.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_rl.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_rl.add_argument('--ptype',
                           help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                                'used by default)')
    parser_rl.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_rl.add_argument('--parttype', help='Partition type\n' +
                                              '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                              '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_rl.add_argument('--filename', help='Optional filename')
    parser_rl.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_rl.add_argument('--socid', help='Read Soc ID')
    parser_rl.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_rl.add_argument('--cert', type=str, help="Use cert file")

    parser_rf.add_argument('filename', help='Filename to store flash file')
    parser_rf.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_rf.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_rf.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_rf.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_rf.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_rf.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_rf.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_rf.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_rf.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_rf.add_argument('--skipwdt', help='Skip wdt init')
    parser_rf.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_rf.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_rf.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_rf.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_rf.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_rf.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_rf.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_rf.add_argument('--ptype',
                           help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                                'used by default)')
    parser_rf.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_rf.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_rf.add_argument('--parttype', help='Partition type\n' +
                                              '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                              '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')

    parser_rf.add_argument('--filename', help='Optional filename')
    parser_rf.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_rf.add_argument('--socid', help='Read Soc ID')
    parser_rf.add_argument('--iot', help='Use special mode for iot MT6261/2301', action="store_true",
                           default=False)
    parser_rf.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_rf.add_argument('--cert', type=str, help="Use cert file")

    parser_rs.add_argument('startsector', help='Sector to start reading (int or hex)')
    parser_rs.add_argument('sectors', help='Sector count')
    parser_rs.add_argument('filename', help='Filename to store sectors')
    parser_rs.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_rs.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_rs.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_rs.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_rs.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_rs.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_rs.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_rs.add_argument('--gpt-part-entry-start-lba', default='0',
                           help='Set GPT entry start lba sector')
    parser_rs.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_rs.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_rs.add_argument('--skipwdt', help='Skip wdt init')
    parser_rs.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_rs.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_rs.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_rs.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_rs.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_rs.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_rs.add_argument('--ptype',
                           help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                                'used by default)')
    parser_rs.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_rs.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_rs.add_argument('--parttype', help='Partition type\n' +
                                              '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                              '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')

    parser_rs.add_argument('--filename', help='Optional filename')
    parser_rs.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_rs.add_argument('--socid', help='Read Soc ID')
    parser_rs.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_rs.add_argument('--cert', type=str, help="Use cert file")

    parser_ro.add_argument('offset', help='Offset to start reading (int or hex)')
    parser_ro.add_argument('length', help='Length to read (int or hex)')
    parser_ro.add_argument('filename', help='Filename to store sectors')
    parser_ro.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_ro.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_ro.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_ro.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_ro.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_ro.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_ro.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_ro.add_argument('--gpt-part-entry-start-lba', default='0',
                           help='Set GPT entry start lba sector')
    parser_ro.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_ro.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_ro.add_argument('--skipwdt', help='Skip wdt init')
    parser_ro.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_ro.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_ro.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_ro.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_ro.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_ro.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_ro.add_argument('--ptype',
                           help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                                'used by default)')
    parser_ro.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_ro.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_ro.add_argument('--parttype', help='Partition type\n' +
                                              '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                              '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_ro.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_ro.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_ro.add_argument('--cert', type=str, help="Use cert file")

    parser_fs.add_argument('mountpoint', help='Directory to mount the FUSE filesystem in')
    parser_fs.add_argument('--rw', help='Mount the filesystem as writeable', default=False,
                           action='store_true')

    parser_w.add_argument('partitionname',
                          help='Partition to write (separate by comma for multiple partitions)')
    parser_w.add_argument('filename',
                          help='Filename for writing (separate by comma for multiple filenames)')
    parser_w.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_w.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_w.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_w.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_w.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_w.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_w.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_w.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_w.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_w.add_argument('--skipwdt', help='Skip wdt init')
    parser_w.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_w.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_w.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_w.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_w.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_w.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_w.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_w.add_argument('--ptype',
                          help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                               'used by default)')
    parser_w.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_w.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_w.add_argument('--parttype', help='Partition type\n' +
                                             '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                             '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')

    parser_w.add_argument('--filename', help='Optional filename')
    parser_w.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_w.add_argument('--socid', help='Read Soc ID')
    parser_w.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_w.add_argument('--cert', type=str, help="Use cert file")

    parser_wf.add_argument('filename', help='Filename to write to flash')
    parser_wf.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_wf.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_wf.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_wf.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_wf.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_wf.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_wf.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_wf.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_wf.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_wf.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_wf.add_argument('--skipwdt', help='Skip wdt init')
    parser_wf.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_wf.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_wf.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_wf.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_wf.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_wf.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_wf.add_argument('--ptype',
                           help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                                'used by default)')
    parser_wf.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_wf.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_wf.add_argument('--parttype', help='Partition type\n' +
                                              '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                              '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_wf.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_wf.add_argument('--socid', help='Read Soc ID')
    parser_wf.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_wf.add_argument('--cert', type=str, help="Use cert file")

    parser_wl.add_argument('directory', help='Directory with partition filenames to write to flash')
    parser_wl.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_wl.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_wl.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_wl.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_wl.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_wl.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_wl.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_wl.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_wl.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_wl.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_wl.add_argument('--skipwdt', help='Skip wdt init')
    parser_wl.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_wl.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_wl.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_wl.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_wl.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_wl.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_wl.add_argument('--ptype',
                           help='Set the payload type ("amonet","kamakiri","kamakiri2",' +
                                '"carbonara" kamakiri2/da used by default)')
    parser_wl.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_wl.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_wl.add_argument('--parttype', help='Partition type\n' +
                                              '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                              '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_wl.add_argument('--filename', help='Optional filename')
    parser_wl.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_wl.add_argument('--socid', help='Read Soc ID')
    parser_wl.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_wl.add_argument('--cert', type=str, help="Use cert file")

    parser_wo.add_argument('offset', help='Offset to start writing (int or hex)')
    parser_wo.add_argument('length', help='Length to write (int or hex)')
    parser_wo.add_argument('filename', help='Filename to write to flash')
    parser_wo.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_wo.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_wo.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_wo.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_wo.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_wo.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_wo.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_wo.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_wo.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_wo.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_wo.add_argument('--skipwdt', help='Skip wdt init')
    parser_wo.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_wo.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_wo.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_wo.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_wo.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_wo.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_wo.add_argument('--ptype',
                           help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" ' +
                                'kamakiri2/da used by default)')
    parser_wo.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_wo.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_wo.add_argument('--parttype', help='Partition type\n' +
                                              '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                              '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_wo.add_argument('--filename', help='Optional filename')
    parser_wo.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_wo.add_argument('--socid', help='Read Soc ID')
    parser_wo.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_wo.add_argument('--cert', type=str, help="Use cert file")

    parser_e.add_argument('partitionname', help='Partitionname to erase from flash')
    parser_e.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_e.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_e.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_e.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_e.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_e.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_e.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_e.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_e.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_e.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_e.add_argument('--skipwdt', help='Skip wdt init')
    parser_e.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_e.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_e.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_e.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_e.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_e.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_e.add_argument('--ptype',
                          help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" ' +
                               'kamakiri2/da used by default)')
    parser_e.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_e.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_e.add_argument('--parttype', help='Partition type\n' +
                                             '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                             '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_e.add_argument('--filename', help='Optional filename')
    parser_e.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_e.add_argument('--socid', help='Read Soc ID')
    parser_e.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_e.add_argument('--cert', type=str, help="Use cert file")

    parser_es.add_argument('partitionname', help='Partitionname to erase from flash')
    parser_es.add_argument('sectors', help='Sectors to erase')
    parser_es.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_es.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_es.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_es.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_es.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_es.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_es.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_es.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_es.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_es.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_es.add_argument('--skipwdt', help='Skip wdt init')
    parser_es.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_es.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_es.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_es.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_es.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_es.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_es.add_argument('--ptype',
                           help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                                'used by default)')
    parser_es.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_es.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_es.add_argument('--parttype', help='Partition type\n' +
                                              '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                              '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_es.add_argument('--filename', help='Optional filename')
    parser_es.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_es.add_argument('--socid', help='Read Soc ID')
    parser_es.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_es.add_argument('--cert', type=str, help="Use cert file")

    parser_ess.add_argument('startsector', help='Startsector to erase')
    parser_ess.add_argument('sectors', help='Sectors to erase')
    parser_ess.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_ess.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_ess.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_ess.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_ess.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_ess.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_ess.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_ess.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_ess.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_ess.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_ess.add_argument('--skipwdt', help='Skip wdt init')
    parser_ess.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_ess.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_ess.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_ess.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_ess.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_ess.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_ess.add_argument('--ptype',
                            help='Set the payload type ( "amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da ' +
                                 'used by default)')
    parser_ess.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_ess.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_ess.add_argument('--parttype', help='Partition type\n' +
                                               '\t\tEMMC: [user, boot1, boot2, gp1, gp2, gp3, gp4, rpmb]' +
                                               '\t\tUFS: [lu0, lu1, lu2, lu0_lu1]')
    parser_ess.add_argument('--filename', help='Optional filename')
    parser_ess.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_ess.add_argument('--socid', help='Read Soc ID')
    parser_ess.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_ess.add_argument('--cert', type=str, help="Use cert file")

    parser_footer.add_argument('filename', help='Filename to store footer')
    parser_footer.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_footer.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_footer.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_footer.add_argument('--sectorsize', default='0x200', help='Set default sector size')
    parser_footer.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_footer.add_argument('--gpt-num-part-entries', default='0', help='Set GPT entry count')
    parser_footer.add_argument('--gpt-part-entry-size', default='0', help='Set GPT entry size')
    parser_footer.add_argument('--gpt-part-entry-start-lba', default='0', help='Set GPT entry start lba sector')
    parser_footer.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_footer.add_argument('--gpt_file', help='Use a gpt file instead of trying to read gpt from flash')
    parser_footer.add_argument('--skipwdt', help='Skip wdt init')
    parser_footer.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_footer.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_footer.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_footer.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_footer.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_footer.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_footer.add_argument('--ptype',
                               help='Set the payload type ' +
                                    '("amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da used by default)')
    parser_footer.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_footer.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_footer.add_argument('--filename', help='Optional filename')
    parser_footer.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_footer.add_argument('--socid', help='Read Soc ID')
    parser_footer.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_footer.add_argument('--cert', type=str, help="Use cert file")

    parser_dumpbrom.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_dumpbrom.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_dumpbrom.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_dumpbrom.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_dumpbrom.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_dumpbrom.add_argument('--skipwdt', help='Skip wdt init')
    parser_dumpbrom.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_dumpbrom.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_dumpbrom.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_dumpbrom.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_dumpbrom.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_dumpbrom.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_dumpbrom.add_argument('--ptype',
                                 help='Set the payload type ' +
                                      '("amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da used by default)')
    parser_dumpbrom.add_argument('--filename', help='Optional filename')
    parser_dumpbrom.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_dumpbrom.add_argument('--socid', help='Read Soc ID')
    parser_dumpbrom.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_dumpbrom.add_argument('--cert', type=str, help="Use cert file")

    parser_dumpsram.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_dumpsram.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_dumpsram.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_dumpsram.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_dumpsram.add_argument('--skip', help='Skip reading partition with names "partname1,partname2,etc."')
    parser_dumpsram.add_argument('--skipwdt', help='Skip wdt init')
    parser_dumpsram.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_dumpsram.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_dumpsram.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_dumpsram.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_dumpsram.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_dumpsram.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_dumpsram.add_argument('--ptype',
                                 help='Set the payload type ' +
                                      '("amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da used by default)')
    parser_dumpsram.add_argument('--filename', help='Optional filename')
    parser_dumpsram.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_dumpsram.add_argument('--socid', help='Read Soc ID')
    parser_dumpsram.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_dumpsram.add_argument('--cert', type=str, help="Use cert file")

    parser_dumppreloader.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_dumppreloader.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_dumppreloader.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_dumppreloader.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_dumppreloader.add_argument('--skipwdt', help='Skip wdt init')
    parser_dumppreloader.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_dumppreloader.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_dumppreloader.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_dumppreloader.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_dumppreloader.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_dumppreloader.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_dumppreloader.add_argument('--ptype',
                                      help='Set the payload type ' +
                                           '("amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da used by default)')
    parser_dumppreloader.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_dumppreloader.add_argument('--filename', help='Optional filename')
    parser_dumppreloader.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_dumppreloader.add_argument('--socid', help='Read Soc ID')
    parser_dumppreloader.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_dumppreloader.add_argument('--cert', type=str, help="Use cert file")

    parser_payload.add_argument('--payload', type=str, help='Payload filename (optional)')
    parser_payload.add_argument('--metamode', type=str, default=None, help='metamode to use ' + metamodes)
    parser_payload.add_argument('--loader', type=str, help='Use specific loader, disable autodetection')
    parser_payload.add_argument('--filename', help='Optional payload to load')
    parser_payload.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_payload.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_payload.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_payload.add_argument('--skipwdt', help='Skip wdt init')
    parser_payload.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_payload.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_payload.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_payload.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_payload.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_payload.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_payload.add_argument('--ptype',
                                help='Set the payload type ' +
                                     '("amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da used by default)')
    parser_payload.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_payload.add_argument('--socid', help='Read Soc ID')
    parser_payload.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_payload.add_argument('--cert', type=str, help="Use cert file")

    parser_crash.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_crash.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_crash.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_crash.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_crash.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_crash.add_argument('--cert', type=str, help="Use cert file")

    parser_brute.add_argument('--loader', type=str, help='Use specific loader, disable autodetection')
    parser_brute.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_brute.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_brute.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_brute.add_argument('--skipwdt', help='Skip wdt init')
    parser_brute.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_brute.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_brute.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_brute.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_brute.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_brute.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_brute.add_argument('--ptype',
                              help='Set the payload type ' +
                                   '("amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da used by default)')
    parser_brute.add_argument('--filename', help='Optional filename')
    parser_brute.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_brute.add_argument('--socid', help='Read Soc ID')
    parser_brute.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_brute.add_argument('--cert', type=str, help="Use cert file")

    parser_logs.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_logs.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_logs.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_logs.add_argument('--filename', help='Optional filename to write dumped data')
    parser_logs.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_logs.add_argument('--cert', type=str, help="Use cert file")

    parser_meta.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_meta.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_meta.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_meta.add_argument('metamode', type=str, default=None, help='metamode to use ' + metamodes)
    parser_meta.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_meta.add_argument('--cert', type=str, help="Use cert file")

    parser_gettargetconfig.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_gettargetconfig.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_gettargetconfig.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_gettargetconfig.add_argument('--socid', help='Read Soc ID')
    parser_gettargetconfig.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_gettargetconfig.add_argument('--cert', type=str, help="Use cert file")

    parser_peek.add_argument('address', help='Address to read from memory')
    parser_peek.add_argument('length', help='Bytes to read from memory')
    parser_peek.add_argument('--filename', help='Optional filename to write dumped data')
    parser_peek.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_peek.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_peek.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_peek.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_peek.add_argument('--skipwdt', help='Skip wdt init')
    parser_peek.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_peek.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_peek.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_peek.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_peek.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_peek.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_peek.add_argument('--ptype',
                             help='Set the payload type ' +
                                  '("amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da used by default)')
    parser_peek.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_peek.add_argument('--socid', help='Read Soc ID')
    parser_peek.add_argument('--preloader', help='Set the preloader filename for dram config')
    parser_peek.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_peek.add_argument('--cert', type=str, help="Use cert file")

    parser_stage.add_argument('--payload', type=str, help='Payload filename (optional)')
    parser_stage.add_argument('--stage2', help='Set stage2 filename')
    parser_stage.add_argument('--stage2addr', help='Set stage2 loading address')
    parser_stage.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_stage.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_stage.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_stage.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_stage.add_argument('--skipwdt', help='Skip wdt init')
    parser_stage.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_stage.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_stage.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_stage.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_stage.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_stage.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_stage.add_argument('--ptype',
                              help='Set the payload type ' +
                                   '("amonet","kamakiri","kamakiri2","carbonara" kamakiri2/da used by default)')
    parser_stage.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_stage.add_argument('--filename', help='Optional filename')
    parser_stage.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_stage.add_argument('--socid', help='Read Soc ID')
    parser_stage.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_stage.add_argument('--cert', type=str, help="Use cert file")

    parser_plstage.add_argument('--payload', type=str, help='Payload filename (optional)')
    parser_plstage.add_argument('--pl', help='pl stage filename (optional)')
    parser_plstage.add_argument('--loader', type=str, help='Use specific DA loader, disable autodetection')
    parser_plstage.add_argument('--vid', type=str, help='Set usb vendor id used for MTK Preloader')
    parser_plstage.add_argument('--pid', type=str, help='Set usb product id used for MTK Preloader')
    parser_plstage.add_argument('--debugmode', action='store_true', default=False, help='Enable verbose mode')
    parser_plstage.add_argument('--skipwdt', help='Skip wdt init')
    parser_plstage.add_argument('--offset', help='Peek ram offset using patched preloader')
    parser_plstage.add_argument('--length', help='Peek ram length using patched preloader')
    parser_plstage.add_argument('--filename', help='Filename for peek ram using patched preloader')
    parser_plstage.add_argument('--wdt', help='Set a specific watchdog addr')
    parser_plstage.add_argument('--mode', help='Set a crash mode (0=dasend1,1=dasend2,2=daread)')
    parser_plstage.add_argument('--var1', help='Set kamakiri specific var1 value')
    parser_plstage.add_argument('--uart_addr', help='Set payload uart_addr value')
    parser_plstage.add_argument('--da_addr', help='Set a specific da payload addr')
    parser_plstage.add_argument('--brom_addr', help='Set a specific brom payload addr')
    parser_plstage.add_argument("--metamode", type=str, help="metamode to use [FASTBOOT,METAMETA,etc.]")
    parser_plstage.add_argument('--ptype',
                                help='Set the payload type ' +
                                     '("amonet","kamakiri","kamakiri2", kamakiri2/da used by default)')
    parser_plstage.add_argument('--preloader', help='Set the preloader filename for loading')
    parser_plstage.add_argument('--verifystage2', help='Verify if stage2 data has been written correctly')
    parser_plstage.add_argument('--crash', help='Enforce crash if device is in pl mode to enter brom mode')
    parser_plstage.add_argument('--socid', help='Read Soc ID')
    parser_plstage.add_argument('--startpartition', help='Option for plstage - Boot to (lk, tee1)')
    parser_plstage.add_argument('--auth', type=str, help="Use auth file (auth_sv5.auth)")
    parser_plstage.add_argument('--cert', type=str, help="Use cert file")

    parser_printgpt.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_footer.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_e.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_es.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_wl.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_wf.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_w.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_rs.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_rf.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_rl.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_gpt.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')
    parser_r.add_argument('--generatekeys', action="store_true", help='Option for deriving hw keys')

    parser_printgpt.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                                 action='store', type=str, nargs='?')
    parser_footer.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                               action='store', type=str, nargs='?')
    parser_e.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                          action='store', type=str, nargs='?')
    parser_es.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                           action='store', type=str, nargs='?')
    parser_wl.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                           action='store', type=str, nargs='?')
    parser_wf.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                           action='store', type=str, nargs='?')
    parser_w.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                          action='store', type=str, nargs='?')
    parser_rs.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                           action='store', type=str, nargs='?')
    parser_rf.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                           action='store', type=str, nargs='?')
    parser_rl.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                           action='store', type=str, nargs='?')
    parser_gpt.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                            action='store', type=str, nargs='?')
    parser_r.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                          action='store', type=str, nargs='?')
    parser_reset.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                              action='store', type=str, nargs='?')
    parser_payload.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                                action='store', type=str, nargs='?')
    parser_script.add_argument('--serialport', help='Use serial port', default=None, const='DETECT',
                               action='store', type=str, nargs='?')

    parser_script.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_printgpt.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_footer.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_e.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_es.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_wl.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_wf.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_w.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_rs.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_rf.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_rl.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_gpt.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    parser_r.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    da_keys.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    da_unlock.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    da_peek.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    da_poke.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    da_dump.add_argument('--noreconnect', action="store_true", help='Disable reconnect')
    da_rpmb.add_argument('--noreconnect', action="store_true", help='Disable reconnect')

    parser_script.add_argument('--stock', action="store_true", help='use stock da')
    parser_printgpt.add_argument('--stock', action="store_true", help='use stock da')
    parser_footer.add_argument('--stock', action="store_true", help='use stock da')
    parser_e.add_argument('--stock', action="store_true", help='use stock da')
    parser_es.add_argument('--stock', action="store_true", help='use stock da')
    parser_wl.add_argument('--stock', action="store_true", help='use stock da')
    parser_wf.add_argument('--stock', action="store_true", help='use stock da')
    parser_w.add_argument('--stock', action="store_true", help='use stock da')
    parser_rs.add_argument('--stock', action="store_true", help='use stock da')
    parser_rf.add_argument('--stock', action="store_true", help='use stock da')
    parser_rl.add_argument('--stock', action="store_true", help='use stock da')
    parser_gpt.add_argument('--stock', action="store_true", help='use stock da')
    parser_r.add_argument('--stock', action="store_true", help='use stock da')
    da_keys.add_argument('--stock', action="store_true", help='use stock da')
    da_unlock.add_argument('--stock', action="store_true", help='use stock da')
    da_peek.add_argument('--stock', action="store_true", help='use stock da')
    da_poke.add_argument('--stock', action="store_true", help='use stock da')
    da_dump.add_argument('--stock', action="store_true", help='use stock da')
    da_rpmb.add_argument('--stock', action="store_true", help='use stock da')

    parser_script.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_printgpt.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_footer.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_e.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_es.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_wl.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_wf.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_w.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_rs.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_rf.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_rl.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_gpt.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    parser_r.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    da_keys.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    da_unlock.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    da_peek.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    da_poke.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    da_dump.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')
    da_rpmb.add_argument('--uartloglevel', help='Set uart log level (0=Trace, 2=Normal)')

    parser_script.add_argument('--appid', help='Use app id (hexstring)')
    parser_printgpt.add_argument('--appid', help='Use app id (hexstring)')
    parser_rs.add_argument('--appid', help='Use app id (hexstring)')
    parser_rf.add_argument('--appid', help='Use app id (hexstring)')
    parser_rl.add_argument('--appid', help='Use app id (hexstring)')
    parser_gpt.add_argument('--appid', help='Use app id (hexstring)')
    parser_r.add_argument('--appid', help='Use app id (hexstring)')
    da_keys.add_argument('--appid', help='Use app id (hexstring)')

    args = parser.parse_args()
    cmd = args.cmd
    if cmd not in cmds:
        parser.print_help()
        exit(0)

    mtk = Main(args).run(parser)
