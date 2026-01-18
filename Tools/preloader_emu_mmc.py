#!/usr/bin/env python3
# (c) B.Kerler 2021

import os
import logging
from binascii import hexlify
from struct import pack, unpack
from mtkclient.Library.Connection.usblib import UsbClass
from mtkclient.Library.utils import LogBase
from mtkclient.Library.utils import print_progress
from unicorn import (Uc, UC_MEM_WRITE, UC_MEM_READ, UC_MEM_FETCH, UC_MEM_READ_UNMAPPED,
                     UC_HOOK_CODE, UC_MEM_WRITE_UNMAPPED, UC_MEM_FETCH_UNMAPPED, UC_MEM_WRITE_PROT,
                     UC_MEM_FETCH_PROT, UC_MEM_READ_AFTER, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_WRITE, UC_ARCH_ARM, UC_MODE_ARM)
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R4)

logger = logging.getLogger(__name__)
# debuglevel=logging.DEBUG
debuglevel = logging.INFO
logging.basicConfig(format='%(funcName)20s:%(message)s', level=debuglevel)

debug = False


class Stage2(metaclass=LogBase):
    def __init__(self, args, loglevel=logging.INFO):
        self.__logger = self.__logger
        self.args = args
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            if os.path.exists(logfilename):
                os.remove(logfilename)
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)
        portconfig = [[0x0E8D, 0x0003, -1], [0x0E8D, 0x2000, -1]]
        self.cdc = UsbClass(portconfig=portconfig, loglevel=loglevel, devclass=10)

    def connect(self):
        self.cdc.connected = self.cdc.connect()
        return self.cdc.connected

    def close(self):
        if self.cdc.connected:
            self.cdc.close()

    def readflash(self, type: int, start, length, display=False, filename: str = None):
        wf = None
        buffer = bytearray()
        if filename is not None:
            wf = open(filename, "wb")
        sectors = (length // 0x200) + (1 if length % 0x200 else 0)
        startsector = (start // 0x200)
        # emmc_switch(1)
        self.cdc.usbwrite(pack(">I", 0xf00dd00d))
        self.cdc.usbwrite(pack(">I", 0x1002))
        self.cdc.usbwrite(pack(">I", type))

        if display:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)

        # kick-wdt
        # self.cdc.usbwrite(pack(">I", 0xf00dd00d))
        # self.cdc.usbwrite(pack(">I", 0x3001))

        bytestoread = sectors * 0x200
        bytesread = 0
        old = 0
        # emmc_read(0)
        for sector in range(startsector, sectors):
            self.cdc.usbwrite(pack(">I", 0xf00dd00d))
            self.cdc.usbwrite(pack(">I", 0x1000))
            self.cdc.usbwrite(pack(">I", sector))
            tmp = self.cdc.usbread(0x200)
            if len(tmp) != 0x200:
                self.error("Error on getting data")
                return
            if display:
                prog = sector / sectors * 100
                if round(prog, 1) > old:
                    print_progress(prog, 100, prefix='Progress:',
                                   suffix='Complete, Sector:' + hex((sectors * 0x200) - bytestoread),
                                   bar_length=50)
                    old = round(prog, 1)
            bytesread += len(tmp)
            size = min(bytestoread, len(tmp))
            if wf is not None:
                wf.write(tmp[:size])
            else:
                buffer.extend(tmp)
            bytestoread -= size
        if display:
            print_progress(100, 100, prefix='Complete: ', suffix=filename, bar_length=50)
        if wf is not None:
            wf.close()
        else:
            return buffer[start % 0x200:(start % 0x200) + length]

    def preloader(self, start, length, filename):
        sectors = 0
        if start != 0:
            start = (start // 0x200)
        if length != 0:
            sectors = (length // 0x200) + (1 if length % 0x200 else 0)
        self.info("Reading preloader...")
        if self.cdc.connected:
            if sectors == 0:
                buffer = self.readflash(type=1, start=0, length=0x1000, display=False)
                if len(buffer) != 0x1000:
                    print("Error on reading boot1 area.")
                    return
                if buffer[:9] == b'EMMC_BOOT':
                    startbrlyt = unpack("<I", buffer[0x10:0x14])[0]
                    if buffer[startbrlyt:startbrlyt + 5] == b"BRLYT":
                        start = unpack("<I", buffer[startbrlyt + 0xC:startbrlyt + 0xC + 4])[0]
                        if buffer[start:start + 4] == b"MMM\x01":
                            length = unpack("<I", buffer[start + 0x20:start + 0x24])[0]
                            self.readflash(type=1, start=start, length=length, display=True, filename=filename)
                            print("Done")
                            return
                print("Error on getting preloader info, aborting.")
            else:
                self.readflash(type=1, start=start, length=length, display=True, filename=filename)
            print("Done")

    def memread(self, start, length):
        bytestoread = length
        addr = start
        data = b""
        pos = 0
        while bytestoread > 0:
            size = min(bytestoread, 0x200)
            self.cdc.usbwrite(pack(">I", 0xf00dd00d))
            self.cdc.usbwrite(pack(">I", 0x4000))
            self.cdc.usbwrite(pack(">I", addr + pos))
            self.cdc.usbwrite(pack(">I", size))
            data += self.cdc.usbread(size)
            bytestoread -= size
            pos += size
        return data

    def memwrite(self, start, data):
        if isinstance(data, str):
            data = bytes.fromhex(data)
        elif isinstance(data, int):
            data = pack("<I", data)
        bytestowrite = len(data)
        addr = start
        pos = 0
        while bytestowrite > 0:
            size = min(bytestowrite, 0x200)
            self.cdc.usbwrite(pack(">I", 0xf00dd00d))
            self.cdc.usbwrite(pack(">I", 0x4002))
            self.cdc.usbwrite(pack(">I", addr + pos))
            self.cdc.usbwrite(pack(">I", size))
            self.cdc.usbwrite(data[pos:pos + 4])
            bytestowrite -= size
            pos += size
        ack = self.cdc.usbread(4)
        return ack == b"\xD0\xD0\xD0\xD0"

    def rpmb(self, start, length, filename):
        if start == 0:
            start = 0
        else:
            start = (start // 0x100)
        if length == 0:
            sectors = 4 * 1024 * 1024 // 0x100
        else:
            sectors = (length // 0x100) + (1 if length % 0x100 else 0)
        self.info("Reading rpmb...")

        self.cdc.usbwrite(pack(">I", 0xf00dd00d))
        self.cdc.usbwrite(pack(">I", 0x1002))
        self.cdc.usbwrite(pack(">I", 0x1))

        # kick-wdt
        self.cdc.usbwrite(pack(">I", 0xf00dd00d))
        self.cdc.usbwrite(pack(">I", 0x3001))

        print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        bytesread = 0
        old = 0
        bytestoread = sectors * 0x100
        with open(filename, "wb") as wf:
            for sector in range(start, sectors):
                self.cdc.usbwrite(pack(">I", 0xf00dd00d))
                self.cdc.usbwrite(pack(">I", 0x2000))
                self.cdc.usbwrite(pack(">H", sector))
                tmp = self.cdc.usbread(0x100)[::-1]
                if len(tmp) != 0x100:
                    self.error("Error on getting data")
                    return
                prog = sector / sectors * 100
                if round(prog, 1) > old:
                    print_progress(prog, 100, prefix='Progress:',
                                   suffix='Complete, Sector:' + hex((sectors * 0x200) - bytestoread),
                                   bar_length=50)
                    old = round(prog, 1)
                bytesread += 0x100
                size = min(bytestoread, len(tmp))
                wf.write(tmp[:size])
                bytestoread -= size
            print_progress(100, 100, prefix='Complete: ', suffix=filename, bar_length=50)
        print("Done")


st2 = Stage2(None)


def getint(valuestr):
    if valuestr == '':
        return None
    try:
        return int(valuestr)
    except Exception:
        try:
            return int(valuestr, 16)
        except Exception:
            pass
    return 0


class ARMRegisters(dict):
    def __init__(self, mu):
        super().__init__()
        self.mu = mu

    def __setitem__(self, key, value):
        if isinstance(key, str):
            key = key.casefold()
            self.mu.reg_write(eval("UC_ARM_REG_" + key.upper()), value)
        super().__setitem__(key, value)

    def __getitem__(self, key):
        if isinstance(key, str):
            key = key.casefold()
            value = self.mu.reg_read(eval("UC_ARM_REG_" + key.upper()))
            super().__setitem__(key, value)
        return super().__getitem__(key)


buffer = bytearray()
data = ""

timer = 0


def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if 0x10009000 > address > 0x10000000 and not (0x11050000 <= address <= 0x11060000):
        value = st2.memread(address, size)
        v = unpack("<I", value)[0]
        # print("READ of 0x%x at 0x%X, data size = %u, value: 0x%x" % (address, pc, size, v))
        uc.mem_write(address, value)
        return True
    elif 0x11300000 > address > 0x11200000:
        value = st2.memread(address, size)
        v = unpack("<I", value)[0]
        print("READ of 0x%x at 0x%X, data size = %u, value: 0x%x" % (address, pc, size, v))
        uc.mem_write(address, value)
        return True
    elif address > 0x10009000 and not (0x11050000 <= address <= 0x11060000):
        value = st2.memread(address, size)
        v = unpack("<I", value)[0]
        # print("READ of 0x%x at 0x%X, data size = %u, value: 0x%x" % (address, pc, size, v))
        uc.mem_write(address, value)
        return True
    elif address == 0x11002014:
        # print("UART0: %08X" % pc)
        uc.mem_write(0x11002014, pack("<I", 0x20))
        return True
    elif address == 0x11020014:
        # print("UART0: %08X" % pc)
        uc.mem_write(0x11020014, pack("<I", 0x20))
        return True
    elif address == 0x11002000:
        uc.mem_write(0x11002014, pack("<I", 0))
        print("UART1 R")
        return True
    elif address == 0x11003014:
        # print("UART0: %08X" % pc)
        uc.mem_write(0x11003014, pack("<I", 0x20))
        return True
    elif address == 0x11003000:
        uc.mem_write(0x11003014, pack("<I", 0))
        print("UART1 R")
        return True
    elif address == 0x11005014:
        # print("UART0: %08X" % pc)
        uc.mem_write(0x11005014, pack("<I", 0x20))
        return True
    elif address == 0x11005000:
        uc.mem_write(0x11005014, pack("<I", 0))
        print("UART1 R")
        return True
    elif address == 0x11050014:
        # print("UART0: %08X" % pc)
        uc.mem_write(0x11050014, pack("<I", 0x20))
        return True
    elif address == 0x11050000:
        uc.mem_write(0x11050014, pack("<I", 0))
        print("UART1 R")
        return True


def hook_mem_write(uc, access, address, size, value, user_data):
    global buffer
    global data
    pc = uc.reg_read(UC_ARM_REG_PC)
    if 0x11300000 > address > 0x11200000:
        print("WRITE of 0x%x at 0x%X, data size = %u, value: 0x%x" % (address, pc, size, value))
        st2.memwrite(address, value)
        uc.mem_write(address, pack("<I", value))
        return True
    elif address > 0x10000000 and not (0x11050000 <= address <= 0x11060000):
        # print("WRITE of 0x%x at 0x%X, data size = %u, value: 0x%x" % (address, pc, size, value))
        st2.memwrite(address, value)
        uc.mem_write(address, pack("<I", value))
        return True
    elif address == 0x11020000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xa:
            print(f"UART: {buffer.decode('utf-8')}")
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    elif address == 0x11050000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xd:
            print(f"UART: {buffer.decode('utf-8')}")
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    elif address == 0x11002000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xa:
            print(f"UART: {buffer.decode('utf-8')}")
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    elif address == 0x11003000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xa:
            print(f"UART: {buffer.decode('utf-8')}")
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    elif address == 0x11005000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xa:
            print(f"UART: {buffer.decode('utf-8')}")
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    # else:
    #    print("Write : %08X - %08X" % (address, value))
    return True


def hook_code(uc, access, address, size):
    pc = uc.reg_read(UC_ARM_REG_PC)
    # print("PC: + " + hex(pc))
    if pc == 0x70095364:
        keyslot0 = uc.mem_read(0x701953CC, 0x20)
        keyslot1 = uc.mem_read(0x701953EC, 0x20)
        keyslot2 = uc.mem_read(0x7019540C, 0x20)
        print(f"Keyslot0: {hexlify(keyslot0).decode('utf-8')}")
        print(f"Keyslot1: {hexlify(keyslot1).decode('utf-8')}")
        print(f"Keyslot2: {hexlify(keyslot2).decode('utf-8')}")
    elif pc == 0x70094A5C:  # sha256_write
        lr = uc.reg_read(UC_ARM_REG_LR)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        s1 = uc.mem_read(r1, r2)
        print("sha256_write")
        print(f"lr: {hex(lr)}")
        print(f"r1: {hex(r1)} {hexlify(s1).decode('utf-8')}")
        print(f"r2: {hex(r2)}\n")
    elif pc == 0x70094E3C:  # kdflib_get_huk
        lr = uc.reg_read(UC_ARM_REG_LR)
        r0 = uc.reg_read(UC_ARM_REG_R0)
        print("kdflib_get_huk")
        print(f"klr: {hex(lr)}")
        print(f"kr0: {hex(r0)}")
    elif pc == 0x70095240:
        lr = uc.reg_read(UC_ARM_REG_LR)
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r4 = uc.reg_read(UC_ARM_REG_R4)
        print("hmac_sha256")
        print(f"hlr: {hex(lr)}")
        print(f"hr0: {hex(r0)}")
        print(f"hr4: {hex(r4)}")
    elif pc == 0x70087430:  # memcpy
        lr = uc.reg_read(UC_ARM_REG_LR)
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R0)
        r2 = uc.reg_read(UC_ARM_REG_R0)
        print("memcpy")
        print(f"lr: {hex(lr)}")
        print(f"r0: {hex(r0)}")
        print(f"r1: {hex(r1)}")
        print(f"r2: {hex(r2)}")
    elif pc == 0x70095084:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print("hmac_init")
        print(f"lr: {hex(lr)}")
    elif pc == 0x70094CF8:
        lr = uc.reg_read(UC_ARM_REG_LR)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        debug = r1
        print("sha_finish")
        print(f"lr: {hex(lr)}")
        print(f"r1: {hex(r1)}")
    elif pc == 0x70094DB8:
        lr = uc.reg_read(UC_ARM_REG_LR)
        r1 = debug
        s1 = uc.mem_read(r1, 0x20)
        print("sha_finish2")
        print(f"lr: {hex(lr)}")
        print(f"r1: {hex(r1)}")
        print(f"s1: {hexlify(s1).decode('utf-8')}")

    # print("PC %08X" % pc)
    return True


def hook_mem_invalid(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if access == UC_MEM_WRITE:
        info = ("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, pc, size, value))
    if access == UC_MEM_READ:
        info = ("invalid READ of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH:
        info = ("UC_MEM_FETCH of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_READ_UNMAPPED:
        info = ("UC_MEM_READ_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_WRITE_UNMAPPED:
        info = ("UC_MEM_WRITE_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_UNMAPPED:
        info = ("UC_MEM_FETCH_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_WRITE_PROT:
        info = ("UC_MEM_WRITE_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_PROT:
        info = ("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_PROT:
        info = ("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_READ_AFTER:
        info = ("UC_MEM_READ_AFTER of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    print(info)
    return False


def do_generic_emu_setup(mu, reg):
    def replace_function(address, callback):
        def hook_code(uc, address, size, user_data):
            logger.debug(">>> Installed hook at 0x%x, instruction size = 0x%x" % (address, size))
            ret = user_data(reg)
            uc.reg_write(UC_ARM_REG_R0, ret)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        mu.hook_add(UC_HOOK_CODE, hook_code, user_data=callback, begin=address, end=address)

    def monitor_function(address, callback):
        def hook_code(uc, address, size, user_data):
            logger.debug(">>> Installed monitor at 0x%x, instruction size = 0x%x" % (address, size))
            user_data(reg)

        mu.hook_add(UC_HOOK_CODE, hook_code, user_data=callback, begin=address, end=address)

    def copy_from_user(regs):
        pc = reg["LR"]
        r0 = reg["R0"]
        r1 = reg["R1"]
        r2 = reg["R2"]
        print("copy_from_user %08X" % pc)
        print("r0: %08X" % r0)
        print("r1: %08X" % r1)
        print("r2: %08X" % r2)
        mu.mem_write(r0, mu.mem_read(r1, r2))
        return 0

    def uthread_get_current(regs):
        pc = reg["LR"]
        print("uthread_get_current %08X" % pc)
        mu.mem_write(0x7000005C + 0x64, pack("<I", 0x70000200))
        mu.mem_write(0x70000200 + 0x10, pack("<I", 0x70000400))
        return 0x7000005C

    def printf(regs):
        # pc = reg["LR"]
        r0 = reg["R0"]
        r1 = reg["R1"]
        strdat = mu.mem_read(r0)
        print(strdat + str(r1))
        return 0

    # mu.hook_add(UC_HOOK_BLOCK, hook_block)
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=0, end=-1)
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    replace_function(0x70082318, uthread_get_current)
    replace_function(0x70087E4C, copy_from_user)
    replace_function(0x224CD9, printf)
    # replace_function(brom_base+br[field][2]-1,usbdl_get_data)


def main():
    pfilename = "preloader_k71v1_64_bsp.bin"

    with open(pfilename, "rb") as rf:
        rf.seek(0x1C)
        addr = unpack("<I", rf.read(4))[0]
        length = unpack("<I", rf.read(4))[0]
        rf.seek(0)
        payload = rf.read()

    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    reg = ARMRegisters(mu)
    reg["SP"] = addr - 0x10  # Stack from start
    reg["R0"] = 0
    emustart = addr // 4096 * 4096
    emulen = (length // 4096) * 4096 + (4 * 4096)
    mu.mem_map(0x100000, 0x100000)
    mu.mem_map(0x11050000, 0x1000)
    mu.mem_map(0x11F30000, 0x1000)
    mu.mem_map(0x11230000, 0x1000)
    mu.mem_map(0x10000000, 0x20000)
    mu.mem_map(emustart, emulen)  # Map generic memory for payload
    mu.mem_write(addr, payload)

    if st2.connect():
        do_generic_emu_setup(mu, reg)
    try:
        mu.emu_start(0x21E224 + 1, 0x21E26A, 0, 0)
    except Exception:
        pass
    logger.info("Emulation done.")


if __name__ == "__main__":
    main()
