#!/usr/bin/env python3
# (c) B.Kerler 2021

import logging
from emu_config.payload_config import br
from unicorn import (Uc, UC_MEM_WRITE, UC_MEM_READ, UC_MEM_FETCH, UC_MEM_READ_UNMAPPED,
                     UC_HOOK_CODE, UC_MEM_WRITE_UNMAPPED, UC_MEM_FETCH_UNMAPPED, UC_MEM_WRITE_PROT,
                     UC_MEM_FETCH_PROT, UC_MEM_READ_AFTER, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_WRITE, UC_ARCH_ARM, UC_MODE_THUMB)
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_R0)
import os
from struct import pack
from binascii import hexlify

logger = logging.getLogger(__name__)
# debuglevel=logging.DEBUG
debuglevel = logging.INFO
logging.basicConfig(format='%(funcName)20s:%(message)s', level=debuglevel)
debug = False


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


def hook_mem_read(uc, access, address, size, value, user_data):
    global data
    # pc = uc.reg_read(UC_ARM_REG_PC)
    # if address<0xF000000:
    #    #print("READ of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    #    #return True
    if address == 0x10007000:
        print("WD 0x10007000")
        data += "WD 0x10007000"
        return True
    if address == 0x10211000:
        print("WD 0x10211000")
        data += "WD 0x10211000"
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
    elif 0x102000 > address >= 0x100FF0:
        # val = unpack("<I", uc.mem_read(address, 4))[0]
        # print("RHeap: %08X A:%08X V:%08X" % (pc,address,val))
        return True


def hook_mem_write(uc, access, address, size, value, user_data):
    global buffer
    global data
    # pc = uc.reg_read(UC_ARM_REG_PC)
    if 0x100A00 + 0x20000 > address >= 0x100A00 + 0x10000:  # hide stack
        return True
    if address == 0x10007000:
        data += "WD: 0x10007000"
        print("WD: 0x10007000")
        return True
    elif address == 0x10211000:
        data += "WD: 0x10211000"
        print("WD: 0x10211000")
        return True
    elif address == 0x10212000:
        data += "WD: 0x10212000"
        print("WD: 0x10212000")
        return True
    elif address == 0x11020000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xa:
            print("UART: " + buffer.decode('utf-8'))
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    elif address == 0x11002000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xa:
            print("UART: " + buffer.decode('utf-8'))
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    elif address == 0x11003000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xa:
            print("UART: " + buffer.decode('utf-8'))
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    elif address == 0x11005000:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        if r0 == 0xa:
            print("UART: " + buffer.decode('utf-8'))
            data += buffer.decode('utf-8')
            buffer = bytearray()
        else:
            buffer.append(r0)
        return True
    else:
        print("Write : %08X - %08X" % (address, value))
    if address >= 0x100FF0:
        # val = unpack("<I", uc.mem_read(address, 4))[0]
        # print("WHeap: %08X A:%08X V:%08X" % (pc,address,val))
        return True
    elif address == 0x1027DC:
        print("SEC_REG pass")
        return True


def hook_code(uc, access, address, size):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if debug:
        if pc < 0x10110A:
            print("PC %08X" % pc)
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


def do_generic_emu_setup(mu, reg, brom_base, field):
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

    def send_usb_response(regs):
        pc = reg["LR"]
        print("send_usb_response %08X" % pc)
        return 0

    def usbdl_put_data(regs):
        pc = reg["LR"]
        print("usbdl_put_data %08X" % pc)
        return 0

    def usbdl_get_data(regs):
        pc = reg["LR"]
        print("usbdl_get_data %08X" % pc)
        reg["LR"] = -1
        mu.emu_stop()
        return 0

        # mu.hook_add(UC_HOOK_BLOCK, hook_block)

    mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=0, end=-1)
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    replace_function(brom_base + br[field][0] - 1, send_usb_response)
    replace_function(brom_base + br[field][1] - 1, usbdl_put_data)
    replace_function(brom_base + br[field][2] - 1, usbdl_get_data)


def main():
    pfilename = os.path.join("..", "..", "payloads", "generic_patcher_payload.bin")
    payload = open(pfilename, "rb").read()

    testsfailed = {}

    for field in br:
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        reg = ARMRegisters(mu)
        reg["SP"] = 0x100A00 + 0x20000  # Stack from start
        brom_base = br[field][7]
        mu.mem_map(0, 0x400000)  # Map generic memory for payload
        try:
            mu.mem_map(0x10000000, 0x1000000)  # Map WD
            mu.mem_map(0x11000000, 0x1000000)  # Map Uart+SEC_REG
        except Exception:
            pass
        try:
            mu.mem_map(brom_base, brom_base + 0x400000)
        except Exception:
            pass

        mu.mem_write(0x100A00, payload)
        bootrom = open(os.path.join("..", "..", "bootrom", field), "rb").read()
        mu.mem_write(brom_base, bootrom)
        do_generic_emu_setup(mu, reg, brom_base, field)

        # Main EDL emulation
        logger.info("Emulating EDL")
        try:
            mu.emu_start(0x100A00, -1, 0, 0)  # handle_xml
        except Exception:
            pass
        cpu = field.replace(".bin", "")
        val1 = hexlify(pack("<I", brom_base + br[field][0])).decode('utf-8').upper()
        if val1 not in data:
            print("send_usb_response failed")
            testsfailed[cpu] = 1
        val2 = hexlify(pack("<I", brom_base + br[field][1])).decode('utf-8').upper()
        if val2 not in data:
            print("usbdl_get_data failed")
            testsfailed[cpu] = 1
        val3 = hexlify(pack("<I", brom_base + br[field][2])).decode('utf-8').upper()
        if val3 not in data:
            print("usbdl_put_data failed")
            testsfailed[cpu] = 1
        val4 = hexlify(pack("<I", br[field][3])).decode('utf-8').upper()
        if val4 not in data:
            print("sec_roffset failed")
            testsfailed[cpu] = 1
        val4 = hexlify(pack("<I", br[field][4])).decode('utf-8').upper()
        if val4 not in data:
            print("sec_roffset2 failed")
            testsfailed[cpu] = 1
        val4 = hexlify(pack("<I", br[field][5])).decode('utf-8').upper()
        if val4 not in data:
            print("wdt failed")
            testsfailed[cpu] = 1
    if len(testsfailed) > 0:
        logger.error("Some tests failed:")
        for cpu in testsfailed:
            logger.error(cpu)
    else:
        logger.info("All tests passed.")
    logger.info("Emulation done.")


if __name__ == "__main__":
    main()
