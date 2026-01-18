#!/usr/bin/env python3
# (c) B.Kerler 2021 MIT License
import sys
from binascii import unhexlify
from struct import unpack


def find_binary(data, strf, pos=0):
    if isinstance(strf, str):
        strf = unhexlify(strf)
    t = strf.split(b".")
    pre = 0
    offsets = []
    while pre != -1:
        pre = data[pos:].find(t[0], pre)
        if pre == -1:
            break
        offsets.append(pre)
        pre += 1

    for offset in offsets:
        error = 0
        rt = pos + offset + len(t[0])
        for i in range(1, len(t)):
            if t[i] == b'':
                rt += 1
                continue
            rt += 1
            rdat = data[rt:]
            prep = rdat.find(t[i])
            if prep != 0:
                error = 1
                break
            rt += len(t[i])
        if error == 0:
            return pos + offset

    return None


def ldr_lit(curpc, instr):
    # LDR (literal), LDR R1, =SEC_REG
    imm8 = instr & 0xFF
    rt = (instr >> 8) & 7
    pc = curpc // 4 * 4
    return (pc + (imm8 * 4) + 4), rt


def ldr_imm(instr):
    simm5 = (instr >> 6) & 0x1F
    s_rt = instr & 0x7
    s_rn = (instr >> 3) & 0x7
    return simm5, s_rt, s_rn


def main():
    if len(sys.argv) < 2:
        print("Usage: ./brom_to_offs brom.bin")
        sys.exit(0)
    with open(sys.argv[1], "rb") as rf:
        print()
        print(f"Using : {sys.argv[1]}")
        data = rf.read()
        base = 0
        mpos = find_binary(data, b"\xA0\x0A\x50\x05.\x00\x00\x00", 0)
        usbdl_get_dword = None
        usbdl_put_dword = None
        if mpos is not None:
            usbdl_put_data = unpack("<I", data[mpos - 0xC:mpos - 0xC + 4])[0]
            base = (((usbdl_put_data >> 16) & 0xFFFFF) << 16)
            usbdl_get_data = unpack("<I", data[mpos - 0x10:mpos - 0x10 + 4])[0]
            usbdl_put_dword = unpack("<I", data[mpos - 0x14:mpos - 0x14 + 4])[0]
            usbdl_get_dword = unpack("<I", data[mpos - 0x18:mpos - 0x18 + 4])[0]
            usbdl_put_word = unpack("<I", data[mpos - 0x1C:mpos - 0x1C + 4])[0]
        else:
            usbdl_get_data = find_binary(data, "2DE9F04780460F46")
            usbdl_put_data = find_binary(data, "10B5064AD4689368")
            usbdl_put_word = find_binary(data, b"\x2D\xE9\xF8\x4F\x80\x46\x8a\x46.\x48")

        usbdl_ptr = None
        if usbdl_put_word:
            mpos = (usbdl_put_word & 0xFFFFF) + 7
            offset, rn = ldr_lit(mpos,
                                 unpack("<H", data[mpos:mpos + 2])[0])
            usbdl_ptr = (base | offset)

        pos = find_binary(data, b"\x30\xB5\x00\x23.\x4C\x08\x28\x0F\xD0", 0)
        if pos is None:
            pos = find_binary(data, b"\x30\xB5..\x00\x25.\x33", 0)
            if pos is None:
                pos = find_binary(data, "10B500244FF08953032806D0", 0)
                if pos is None:
                    pos = find_binary(data, b"\x00\x24\x03\x28\x06\xD0\x02\x28", 0)
                    if pos is not None:
                        pos -= 0x4
        send_usb_response = None
        if pos is not None:
            pos += 1
            send_usb_response = base | pos
        pos = find_binary(data, b"\x10\xB5.\xF0...\x46", 0)
        if pos is None:
            pos = find_binary(data, b"\xB5.\xF0...\x49", 0)
            if pos is not None:
                pos -= 1
        else:
            pos2 = find_binary(data, "46FFF7", pos + 8)
            if pos2 is not None:
                if pos2 - pos < 0x20:
                    pos = pos
                else:
                    pos = pos2 - 1
        posr = -1
        startpos = 0
        while posr is not None:
            posr = find_binary(data, "2DE9F047", startpos)
            if posr is None:
                break
            if data[posr + 7] == 0x46 and data[posr + 8] == 0x92:
                break
            startpos = posr + 2

        pattern = b"\xB5.\xF0"
        sla = None
        if pos is not None:
            print("sbc:\t\t\t\t\t\t0x%08X" % (base | pos))
            pos = find_binary(data, pattern, pos + 8)
            if pos is not None:
                pos -= 1
                print("sla:\t\t\t\t\t\t0x%08X" % (base | pos))
                sla = pos
                if pos is not None:
                    pos = find_binary(data, pattern, ((base | pos) + 2))
                    if pos is not None:
                        pos -= 1
                        print("daa:\t\t\t\t\t\t0x%08X" % (base | pos))
        sec_mode = None
        sec_sbc = None
        sec_sla = None
        if sla is not None:
            if data[sla + 9] & 0xF0 == 0x60:
                offset, rn = ldr_lit(sla + 6,
                                     unpack("<H", data[sla + 6:sla + 6 + 2])[0])
                sec_sbc = unpack("<I", data[offset:offset + 4])[0]
                if data[sla + 8] == 0x51:
                    sec_sbc += 4
                sec_mode = 0
            else:
                mpos = find_binary(data, "48C16809B1", 0)
                if mpos is not None:
                    mpos -= 1
                    sec_mode = 1
                    offset, rn = ldr_lit(mpos,
                                         unpack("<H", data[mpos:mpos + 2])[0])
                    _ = rn
                    rbase = unpack("<I", data[offset:offset + 4])[0]
                    simm5, s_rt, s_rn = ldr_imm(unpack("<H", data[mpos + 2:mpos + 4])[0])
                    _ = s_rt
                    _ = s_rn
                    sec_sbc = (rbase + (simm5 * 4))
                    instr = unpack("<H", data[sla + 0x12:sla + 0x12 + 2])[0]
                    offset, rn = ldr_lit(sla + 0x12, instr)
                    rbase = unpack("<I", data[offset:offset + 4])[0]
                    simm5, s_rt, s_rn = ldr_imm(unpack("<H", data[sla + 0x12 + 2:sla + 0x12 + 4])[0])
                    sec_sla = (rbase + (simm5 * 4))

        func_wdt = None
        func_acm = None
        pos = find_binary(data, "70B50646A648", 0)
        if pos is not None:
            pos += 1
            func_acm = base | pos
        pos = find_binary(data, "0F4941F6", 0)
        if pos is None:
            pos = find_binary(data, "124941F6", 0)
        if pos is not None:
            pos += 1
            func_wdt = base | pos

        pos = find_binary(data, "F8B50024", 0)
        if pos is None:
            pos = find_binary(data, "2DE9F8430024", 0)  # mt6572 special
        usb_buffer = 0
        if pos is not None:
            pos += 1
            func_usb_buffer = pos - 1
            for i in range(0, 0x100, 2):
                if data[func_usb_buffer + i + 1] == 0x48:
                    offset, rn = ldr_lit(func_usb_buffer + i,
                                         unpack("<H", data[func_usb_buffer + i:func_usb_buffer + i + 2])[0])
                    usb_buffer = unpack("<I", data[offset:offset + 4])[0]
                    break

        vulnaddr = None
        var1 = None
        pos = find_binary(data, b"\xA1..\xD0\x21", 0)
        if pos is not None:
            for i in range(0, 0x100, 2):
                if data[pos - i - 3] == 0xB5 and data[pos - i - 1] == 0x4A:
                    pos = pos - i - 4
                    break
                if data[pos - i - 3] == 0xB4 and data[pos - i - 1] == 0x4B:
                    pos = pos - i - 4
                    break
                if data[pos - i - 3] == 0xB5 and data[pos - i - 1] == 0x4D:
                    pos = pos - i - 4
                    break
            vuln_ctrl_handler = pos
            try:
                for i in range(0, 0x100, 2):
                    if data[vuln_ctrl_handler + i + 1] == 0x49 or data[vuln_ctrl_handler + i + 1] == 0x4C:
                        offset, rn = ldr_lit(vuln_ctrl_handler + i,
                                             unpack("<H", data[vuln_ctrl_handler + i:vuln_ctrl_handler + i + 2])[0])
                        vulnaddr = unpack("<I", data[offset:offset + 4])[0]
                    if data[vuln_ctrl_handler + i + 1] == 0x6A and usb_buffer != 0:
                        simm5, s_rt, s_rn = ldr_imm(
                            unpack("<H", data[vuln_ctrl_handler + i:vuln_ctrl_handler + i + 2])[0])
                        vulnoff = (simm5 * 4)
                        var1 = (usb_buffer - vulnaddr - vulnoff) / 0x34
                        if int(var1) != var1:
                            var1 = int(var1)
                            var1 += 1
                        break
            except:
                pass

        cmd_handler = None
        pos = find_binary(data, b"\xFF\xF7.\xFF\xFF\xF7..\x04", 0)
        if pos is None:
            pos = find_binary(data, b"\x10\xB5..\xF4.\x00\x21", 0)
        if pos is not None:
            pos += 1
            cmd_handler = base | pos

        uart_info = None
        pos = find_binary(data, "10B5114A")
        if pos is not None:
            uart_info = pos

        uart_addr = None
        pos = find_binary(data, "315F454E930F0E00")
        if pos is None:
            pos = find_binary(data, "0070315F454E00")
            if pos is not None:
                pos += 6
                uart_addr = unpack("<I", data[pos:pos + 4])[0]
        else:
            pos += 8
            uart_addr = unpack("<I", data[pos:pos + 4])[0]

        wd = None
        pos = find_binary(data, "33332F4005000022")
        if pos is not None:
            pos -= 4
            wd = unpack("<I", data[pos:pos + 4])[0]
        else:
            pos = find_binary(data, "4941F67110")  # mt6572 special
            if pos is not None:
                pos -= 1
                instr = unpack("<H", data[pos:pos + 2])[0]
                offset, rn = ldr_lit(pos, instr)
                wd = unpack("<I", data[offset:offset + 4])[0]

        blacklist = None
        pos = find_binary(data, b"\x48\x00\x21\x02\x1B.\x48")
        if pos is None:
            pos = find_binary(data, b"\xFC\xB5\x06\x46\x0F\x46\x14\x46")
            if pos is None:
                pos = find_binary(data, "78B50D1C041C161C1A48")
                if pos is not None:
                    pos += 8
                    instr = unpack("<H", data[pos:pos + 2])[0]
                    offset, rn = ldr_lit(pos, instr)
                    blacklist_ptr = unpack("<I", data[offset:offset + 4])[0] & 0xFFFFF
                    blacklist = unpack("<I", data[blacklist_ptr - 4:blacklist_ptr - 4 + 4])[0]
            else:
                pos += 10
        else:
            pos += 11

        if pos is not None and blacklist is None:
            instr = unpack("<H", data[pos:pos + 2])[0]
            offset, rn = ldr_lit(pos, instr)
            blacklist = unpack("<I", data[offset:offset + 4])[0]

        blacklistcount = None
        pos = find_binary(data, b"\x02\x4A\x02\x60")
        if pos is not None:
            pos += 4
            blacklistcount = unpack("<H", data[pos:pos + 2])[0] & 0xF

        blacklist2 = None
        pos = find_binary(data, b"\x10\xB5..\xD2\xF8\x90\x30\x10\x32")
        if pos is not None:
            pos += 2
            instr = unpack("<H", data[pos:pos + 2])[0]
            offset, rn = ldr_lit(pos, instr)
            bl2 = unpack("<I", data[offset:offset + 4])[0]
            blacklist2 = bl2 + 0x90

        pos = 0
        memread = 0
        while pos is not None:
            pos = find_binary(data, b"\x10\xB5", pos)
            if pos is not None:
                if data[pos + 3] == 0x20 and data[pos + 0x9] == 0x49:
                    pos += 8
                    instr = unpack("<H", data[pos:pos + 2])[0]
                    offset, rn = ldr_lit(pos, instr)
                    memread = unpack("<I", data[offset:offset + 4])[0]
                    break
                pos += 1

        payload_addr = 0
        while pos is not None:
            pos = find_binary(data, "C40811A9", pos)
            if pos is not None:
                pos -= (2 * 4)
                payload_addr = unpack("<I", data[pos:pos + 4])[0]
                break

        coffs = (usbdl_put_data & 0xFFFFF) + 1
        try:
            offset, rn = ldr_lit(coffs,
                                 unpack("<H", data[coffs:coffs + 2])[0])
        except:
            print("Err:" + sys.argv[1])
        send_ptr = unpack("<I", data[offset:offset + 4])[0] + 8
        send_ptr_offset = base | offset
        ctrl_addr = None
        pos = find_binary(data, "41434D2043")
        if pos is not None:
            pos -= 0x10
            ctrl_addr = unpack("<I", data[pos:pos + 4])[0]

        socid_addr = None
        pos = find_binary(data, "10B501212020FF")
        if pos is not None:
            pos += 0xA
            instr = unpack("<H", data[pos:pos + 2])[0]
            offset, rn = ldr_lit(pos, instr)
            socid_addr = unpack("<I", data[offset:offset + 4])[0]

        meid_addr = None
        pos = find_binary(data, "10B501211020FF")
        if pos is not None:
            pos += 0xA
            instr = unpack("<H", data[pos:pos + 2])[0]
            offset, rn = ldr_lit(pos, instr)
            meid_addr = unpack("<I", data[offset:offset + 4])[0]

        brom_register_access = None
        brom_register_access_ptr = None
        brom_register_access_ptr_offset = None
        pos2 = find_binary(data, "2DE9F04100244FF001")
        if pos2 is not None:
            brom_register_access = base | pos2
            pos = find_binary(data, b"\xA9\x07.\x48", pos2)
            if pos is not None:
                pos += 2
                instr = unpack("<H", data[pos:pos + 2])[0]
                offset, rn = ldr_lit(pos, instr)
                brom_register_access_ptr = base | pos2
                brom_register_access_ptr_offset = base | offset
            else:
                pos = find_binary(data, "194D1B49", pos2)
                if pos is not None:
                    instr = unpack("<H", data[pos:pos + 2])[0]
                    offset, rn = ldr_lit(pos, instr)
                    # da_range = offset

        print("Base: \t\t\t\t\t\t0x%08X" % base)
        print("usbdl_put_data:\t\t\t\t0x%08X" % usbdl_put_data)
        print("usbdl_get_data:\t\t\t\t0x%08X" % usbdl_get_data)
        if usbdl_put_dword:
            print("usbdl_put_dword:\t\t\t0x%08X" % usbdl_put_dword)
        if usbdl_get_dword:
            print("usbdl_get_dword:\t\t\t0x%08X" % usbdl_get_dword)
        if usbdl_put_word:
            print("usbdl_put_word:\t\t\t\t0x%08X" % usbdl_put_word)
        if send_usb_response:
            print("*send_usb_response:\t\t\t0x%08X" % send_usb_response)
        if sec_mode:
            print("*sec_mode:\t\t\t\t\t0x%08X" % sec_mode)
        if sec_sbc:
            print("*sec_sbc:\t\t\t\t\t0x%08X" % sec_sbc)
        if sec_mode == 1 and sec_sla:
            print("*sec_sla:\t\t\t\t\t0x%08X" % sec_sla)
        print("*func_usb_buffer:\t\t\t0x%08X" % (func_usb_buffer + 1 | base))
        print("usb_buffer:\t\t\t\t\t0x%08X" % usb_buffer)
        if func_wdt:
            print("*func_wdt:\t\t\t\t\t0x%08X" % func_wdt)
        if func_acm:
            print("*func_acm:\t\t\t\t\t0x%08X" % func_acm)
        print("vuln_ctrl_handler:\t\t\t0x%08X" % (vuln_ctrl_handler + 1))
        if vulnaddr:
            print("Vuln_addr:\t\t\t\t\t0x%08X" % vulnaddr)
        print("Vuln_offset:\t\t\t\t0x%08X" % vulnoff)
        if usbdl_ptr:
            print("usbdl_ptr:\t\t\t\t\t\t0x%08X" % usbdl_ptr)
        else:
            print("Uhoh: " + sys.argv[1])
        if memread:
            print("memread:\t\t\t\t\t0x%08X" % memread)
        if payload_addr:
            print("brom_payload_addr:\t\t\t0x%08X" % payload_addr)
        if brom_register_access:
            print("brom_register_access:\t\t\t\t\t\t0x%08X" % brom_register_access)
        if uart_info:
            print("uart_info:\t\t\t\t\tAround offset 0x%08X" % (base | uart_info))

        if var1:
            print("Var1:\t\t\t\t\t\t0x%08X" % int(var1))
        if wd:
            print("watchdog:\t\t\t\t\t0x%08X" % wd)
        if uart_addr:
            print("uart_addr0:\t\t\t\t\t0x%08X" % (uart_addr + 0x14))
            print("uart_addr1:\t\t\t\t\t0x%08X" % uart_addr)
        if blacklist:
            print("blacklist:\t\t\t\t\t0x%08X" % blacklist)
        if blacklist2:
            print("blacklist2:\t\t\t\t\t0x%08X" % blacklist2)
        if blacklistcount:
            print("blacklist-count:\t\t\t0x%08X" % blacklistcount)
        print(f"send_ptr:\t\t\t\t\t{hex(send_ptr)},{hex(send_ptr_offset)}")
        print("ctrl_handler:\t\t\t\t0x%08X" % ctrl_addr)
        if cmd_handler:
            print("*cmd_handler:\t\t\t\t0x%08X" % cmd_handler)
        if brom_register_access_ptr:
            print(
                f"brom_register_access_ptr:\t\t\t\t\t({hex(brom_register_access_ptr)}," +
                f"{hex(brom_register_access_ptr_offset)}),")
        if meid_addr:
            print(f"meid_addr:\t\t\t\t\t{hex(meid_addr)}")
        if socid_addr:
            print(f"socid_addr:\t\t\t\t\t{hex(socid_addr)}")
        print("da_range:\t\t\t\t\t0x%08X" % offset)

    if sec_mode == 1:
        sec_offset = 0x28
    else:
        sec_offset = 0x40
        sec_sla = 0

    if blacklist2 is None:
        blacklist2 = 0
    import os
    socname = os.path.basename(sys.argv[1]).replace(".bin", "")[:6]
    try:
        if usbdl_ptr:
            header = f"""
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "{socname}";
    
void (*send_usb_response)(int, int, int) = (void*){hex(send_usb_response)};
int (*(*usbdl_ptr))() = (void*){hex(usbdl_ptr)};

const int mode={sec_mode};
volatile uint32_t **SEC_REG=(volatile uint32_t **){hex(sec_sbc)};
volatile uint32_t **SEC_REG2=(volatile uint32_t **){hex(sec_sla)};
volatile uint32_t SEC_OFFSET={hex(sec_offset)};
volatile uint32_t *bladdr=(volatile uint32_t *){hex(blacklist)};
volatile uint32_t *bladdr2=(volatile uint32_t *){hex(blacklist2)};
volatile uint32_t *uart_reg0 = (volatile uint32_t*){hex(uart_addr + 0x14)};
volatile uint32_t *uart_reg1 = (volatile uint32_t*){hex(uart_addr)};

int (*cmd_handler)() = (void*){hex(cmd_handler)};
            """
            print()
            print(header)
            if not os.path.exists("headers"):
                os.mkdir("headers")
            with open(os.path.join("headers", socname + ".h"), "w", encoding='utf-8') as wf:
                wf.write(header)
    except Exception as e:
        print(str(e))
        print(sys.argv[1])


if __name__ == "__main__":
    main()
