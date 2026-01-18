#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025
import codecs
import io
import json
import os
import shutil
import stat
import struct
import sys
from struct import unpack, pack

from mtkclient.Library.gui_utils import structhelper_io

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    pass
try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, KsError
except ImportError:
    pass

sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')


class MTKTee:
    magic = None
    hdrlen = None
    flag1 = None
    flag2 = None
    flag3 = None
    flag4 = None
    flag5 = None
    datalen = None
    datalen2 = None
    keyseed = None
    ivseed = None
    data = None

    def parse(self, data) -> None:
        sh = structhelper_io(data)
        self.magic = sh.qword()
        self.hdrlen = sh.dword()
        self.flag1 = sh.bytes()
        self.flag2 = sh.bytes()
        self.flag3 = sh.bytes()
        self.flag4 = sh.bytes()
        self.flag5 = sh.dword()
        self.datalen = sh.dword()
        self.datalen2 = sh.dword()
        self.keyseed = bytearray(sh.bytes(16))
        self.ivseed = bytearray(sh.bytes(16))
        sh.seek(self.hdrlen)
        self.data = bytearray(sh.bytes(self.datalen))


def find_binary(data, strf, pos=0):
    t = strf.split(b".")
    pre = 0
    offsets = []
    while pre != -1:
        pre = data[pos:].find(t[0], pre)
        if pre == -1:
            if len(offsets) > 0:
                for offset in offsets:
                    error = 0
                    rt = offset + len(t[0])
                    for i in range(1, len(t)):
                        if t[i] == b'':
                            rt += 1
                            continue
                        rt += 1
                        prep = data[pos + rt:].find(t[i])
                        if prep != 0:
                            error = 1
                            break
                        rt += len(t[i])
                    if error == 0:
                        return offset + pos
            else:
                return None
        else:
            offsets.append(pre)
            pre += 1
    return None


def do_tcp_server(client, arguments, handler):
    def tcpprint(arg):
        if isinstance(arg, bytes) or isinstance(arg, bytearray):
            return connection.sendall(arg)
        else:
            return connection.sendall(bytes(str(arg), 'utf-8'))

    client.printer = tcpprint
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = int(arguments.tcpport)
    server_address = ('localhost', port)
    print(f'starting up on {server_address[0]} port {port}')
    sock.bind(server_address)
    sock.listen(1)
    response = None
    while True:
        print('waiting for a connection')
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address)
            while True:
                data = connection.recv(4096).decode('utf-8')
                if data == '':
                    break
                print(f'received {data}')
                if data:
                    print('handling request')
                    lines = data.split("\n")
                    for line in lines:
                        if ":" in line:
                            cmd = line.split(":")[0]
                            try:
                                opts = parse_args(cmd, line.split(":")[1], arguments)
                            except Exception:
                                response = "Wrong arguments\n<NAK>\n"
                                opts = None
                            if opts is not None:
                                response = "<ACK>\n" if handler(cmd, opts) else "<NAK>\n"
                            connection.sendall(bytes(response, 'utf-8'))
        finally:
            connection.close()


def do_tcp_keyserver(handler):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = int(1234)
    server_address = ('localhost', port)
    print('starting up on %s port %s' % server_address)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)
    while True:
        print('waiting for a connection')
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address)
            while True:
                data = connection.recv(4096)
                if data == b'':
                    break
                try:
                    data = data.decode('utf-8')
                except Exception:
                    continue
                print('received %s' % data)
                if data:
                    print('handling key request')
                    if "\"req\"" in data:
                        field = json.loads(data)["req"]
                        data = bytes.fromhex(field)
                        derived_key = handler.aes_hwcrypt(btype="dxcc", mode="aescmac", key_sz=32, data=data)
                        response = ""
                        if derived_key is not None:
                            if "custom" in derived_key:
                                response = {"Req": field, "Key": derived_key["custom"]}
                        connection.sendall(bytes(json.dumps(response), 'utf-8'))
        finally:
            connection.close()


def parse_args(cmd, args, mainargs):
    options = {}
    opts = args.split(",") if "," in args else [args]
    for arg in mainargs:
        if "--" in arg:
            options[arg] = mainargs[arg]
    if cmd == "gpt":
        options["<directory>"] = opts[0]
    elif cmd == "r":
        options["<partitionname>"] = opts[0]
        options["<filename>"] = opts[1]
    elif cmd == "rl":
        options["<directory>"] = opts[0]
    elif cmd == "rf":
        options["<filename>"] = opts[0]
    elif cmd == "rs":
        options["<start_sector>"] = opts[0]
        options["<sectors>"] = opts[1]
        options["<filename>"] = opts[2]
    elif cmd == "w":
        options["<partitionname>"] = opts[0]
        options["<filename>"] = opts[0]
    elif cmd == "wl":
        options["<directory>"] = opts[0]
    elif cmd == "wf":
        options["<filename>"] = opts[0]
    elif cmd == "ws":
        options["<start_sector>"] = opts[0]
        options["<filename>"] = opts[1]
    elif cmd == "e":
        options["<partitionname>"] = opts[0]
    elif cmd == "es":
        options["<start_sector>"] = opts[0]
        options["<sectors>"] = opts[1]
    elif cmd == "footer":
        options["<filename>"] = opts[0]
    elif cmd == "peek":
        options["<offset>"] = opts[0]
        options["<length>"] = opts[1]
        options["<filename>"] = opts[2]
    elif cmd == "peekhex":
        options["<offset>"] = opts[0]
        options["<length>"] = opts[1]
    elif cmd == "peekdword":
        options["<offset>"] = opts[0]
    elif cmd == "peekqword":
        options["<offset>"] = opts[0]
    elif cmd == "memtbl":
        options["<filename>"] = opts[0]
    elif cmd == "poke":
        options["<offset>"] = opts[0]
        options["<filename>"] = opts[1]
    elif cmd == "pokehex":
        options["<offset>"] = opts[0]
        options["<data>"] = opts[1]
    elif cmd == "pokedword":
        options["<offset>"] = opts[0]
        options["<data>"] = opts[1]
    elif cmd == "pokeqword":
        options["<offset>"] = opts[0]
        options["<data>"] = opts[1]
    elif cmd == "memcpy":
        options["<offset>"] = opts[0]
        options["<size>"] = opts[1]
    elif cmd == "pbl":
        options["<filename>"] = opts[0]
    elif cmd == "qfp":
        options["<filename>"] = opts[0]
    elif cmd == "setbootablestoragedrive":
        options["<lun>"] = opts[0]
    elif cmd == "send":
        options["<command>"] = opts[0]
    elif cmd == "xml":
        options["<xmlfile>"] = opts[0]
    elif cmd == "rawxml":
        options["<xmlstring>"] = opts[0]
    return options


def getint(valuestr):
    try:
        return int(valuestr)
    except Exception:
        try:
            return int(valuestr, 16)
        except Exception:
            return 0


def revdword(value):
    return unpack(">I", pack("<I", value))[0]


def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


def rmrf(path):
    if os.path.exists(path):
        if os.path.isfile(path):
            del_rw("", path, "")
        else:
            shutil.rmtree(path, onerror=del_rw)


class ELF:
    class MemorySegment:
        phy_addr = 0
        virt_start_addr = 0
        virt_end_addr = 0
        file_start_addr = 0
        file_end_addr = 0

    def __init__(self, indata, filename):
        self.data = indata
        self.filename = filename
        self.header, self.pentry = self.parse()
        self.memorylayout = []
        for entry in self.pentry:
            ms = self.MemorySegment()
            ms.phy_addr = entry.phy_addr
            ms.virt_start_addr = entry.virt_addr
            ms.virt_end_addr = entry.virt_addr + entry.seg_mem_len
            ms.file_start_addr = entry.from_file
            ms.file_end_addr = entry.from_file + entry.seg_file_len
            self.memorylayout.append(ms)

    def getfileoffset(self, offset):
        for memsegment in self.memorylayout:
            if memsegment.virt_end_addr >= offset >= memsegment.virt_start_addr:
                return offset - memsegment.virt_start_addr + memsegment.file_start_addr
        return None

    def getvirtaddr(self, fileoffset):
        for memsegment in self.memorylayout:
            if memsegment.file_end_addr >= fileoffset >= memsegment.file_start_addr:
                return memsegment.virt_start_addr + fileoffset - memsegment.file_start_addr
        return None

    def getbaseaddr(self, offset):
        for memsegment in self.memorylayout:
            if memsegment.virt_end_addr >= offset >= memsegment.virt_start_addr:
                return memsegment.virt_start_addr
        return None

    class ProgramEntry:
        p_type = 0
        from_file = 0
        virt_addr = 0
        phy_addr = 0
        seg_file_len = 0
        seg_mem_len = 0
        p_flags = 0
        p_align = 0

    def parse_programentry(self, dat):
        pe = self.ProgramEntry()
        if self.elfclass == 1:
            (pe.p_type, pe.from_file, pe.virt_addr, pe.phy_addr, pe.seg_file_len, pe.seg_mem_len, pe.p_flags,
             pe.p_align) = struct.unpack("<IIIIIIII", dat)
        elif self.elfclass == 2:
            (pe.p_type, pe.p_flags, pe.from_file, pe.virt_addr, pe.phy_addr, pe.seg_file_len, pe.seg_mem_len,
             pe.p_align) = struct.unpack("<IIQQQQQQ", dat)
        return pe

    def parse(self) -> list:
        self.elfclass = self.data[4]
        if self.elfclass == 1:  # 32Bit
            start = 0x28
        elif self.elfclass == 2:  # 64Bit
            start = 0x34
        else:
            print(f"Error on parsing {self.filename}")
            return ['', '']
        elfheadersize, programheaderentrysize, programheaderentrycount = struct.unpack("<HHH",
                                                                                       self.data[start:start + 3 * 2])
        programheadersize = programheaderentrysize * programheaderentrycount
        header = self.data[0:elfheadersize + programheadersize]
        pentry = []
        for i in range(0, programheaderentrycount):
            start = elfheadersize + (i * programheaderentrysize)
            end = start + programheaderentrysize
            pentry.append(self.parse_programentry(self.data[start:end]))

        return [header, pentry]


class Patchtools:
    cstyle = False
    bDebug = False

    def __init__(self, bdebug=False):
        self.bDebug = bdebug

    @staticmethod
    def has_bad_uart_chars(data):
        badchars = [b'\x00', b'\n', b'\r', b'\x08', b'\x7f', b'\x20', b'\x09']
        for idx, c in enumerate(data):
            c = bytes([c])
            if c in badchars:
                return True
        return False

    def generate_offset(self, offset):
        div = 0
        found = False
        while not found and div < 0x606:
            data = struct.pack("<I", offset + div)
            data2 = struct.pack("<H", div)
            badchars = self.has_bad_uart_chars(data)
            if not badchars:
                badchars = self.has_bad_uart_chars(data2)
                if not badchars:
                    return div
            div += 4

        # if div is not found within positive offset, try negative offset
        div = 0
        while not found and div < 0x606:
            data = struct.pack("<I", offset - div)
            data2 = struct.pack("<H", div)
            badchars = self.has_bad_uart_chars(data)
            if not badchars:
                badchars = self.has_bad_uart_chars(data2)
                if not badchars:
                    return -div
            div += 4
        return 0

    # Usage: offset, "X24"
    def generate_offset_asm(self, offset, reg):
        div = self.generate_offset(offset)
        abase = ((offset + div) & 0xFFFF0000) >> 16
        a = ((offset + div) & 0xFFFF)
        strasm = ""
        strasm += f"# {hex(offset)}\n"
        strasm += f"mov {reg}, #{hex(a)};\n"
        strasm += f"movk {reg}, #{hex(abase)}, LSL#16;\n"
        if div > 0:
            strasm += f"sub  {reg}, {reg}, #{hex(div)};\n"
        else:
            strasm += f"add  {reg}, {reg}, #{hex(-div)};\n"
        return strasm

    @staticmethod
    def uart_valid_sc(sc):
        badchars = [b'\x00', b'\n', b'\r', b'\x08', b'\x7f', b'\x20', b'\x09']
        for idx, c in enumerate(sc):
            c = bytes([c])
            if c in badchars:
                print("bad char 0x%s in SC at offset %d, opcode # %d!\n" % (codecs.encode(c, 'hex'), idx, idx / 4))
                print(codecs.encode(sc, 'hex'))
                return False
        return True

    @staticmethod
    def disasm(code, size):
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        instr = [f"{i.mnemonic}\t{i.op_str}" for i in cs.disasm(code, size)]
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        return instr

    def assembler(self, code):
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        if self.bDebug:
            try:
                encoding, count = ks.asm(code)
            except KsError as e:
                print(e)
                print(e.stat_count)
                print(code[e.stat_count:e.stat_count + 10])
                """
                if self.bDebug:
                    # walk every line to find the (first) error
                    for idx, line in enumerate(code.splitlines()):
                        print("%02d: %s" % (idx, line))
                        if len(line) and line[0] != '.':
                            try:
                                encoding, count = ks.asm(line)
                            except Exception as e:
                                print("bummer: " + str(e))
                else:
                    exit(0)
                """
                exit(0)
        else:
            encoding, count = ks.asm(code)

        sc = ""
        count = 0
        out = ""
        for i in encoding:
            if self.cstyle:
                out += ("\\x%02x" % i)
            else:
                out += ("%02x" % i)
            sc += "%02x" % i

            count += 1
            # if bDebug and count % 4 == 0:
            #    out += ("\n")

        return out

    @staticmethod
    def find_binary(data, strf, pos=0):
        t = strf.split(b".")
        pre = 0
        offsets = []
        while pre != -1:
            pre = data[pos:].find(t[0], pre)
            if pre == -1:
                if len(offsets) > 0:
                    for offset in offsets:
                        error = 0
                        rt = offset + len(t[0])
                        for i in range(1, len(t)):
                            if t[i] == b'':
                                rt += 1
                                continue
                            rt += 1
                            prep = data[rt:].find(t[i])
                            if prep != 0:
                                error = 1
                                break
                            rt += len(t[i])
                        if error == 0:
                            return offset
                else:
                    return None
            else:
                offsets.append(pre)
                pre += 1
        return None


def read_object(data: object, definition) -> dict:
    """
    Unpacks a structure using the given data and definition.
    """
    obj = {}
    object_size = 0
    pos = 0
    for (name, stype) in definition:
        object_size += struct.calcsize(stype)
        obj[name] = struct.unpack(stype, data[pos:pos + struct.calcsize(stype)])[0]
        pos += struct.calcsize(stype)
    obj['object_size'] = object_size
    obj['raw_data'] = data
    return obj


def write_object(definition, *args):
    """
    Unpacks a structure using the given data and definition.
    """
    obj = {}
    object_size = 0
    data = b""
    i = 0
    for (name, stype) in definition:
        object_size += struct.calcsize(stype)
        arg = args[i]
        try:
            data += struct.pack(stype, arg)
        except Exception as e:
            print("Error:" + str(e))
            break
        i += 1
    obj['object_size'] = len(data)
    obj['raw_data'] = data
    return obj
