#!/usr/bin/env python3
# (c) B.Kerler 2021

import os
import logging
from struct import pack
from binascii import hexlify
from unicorn import (Uc, UC_MEM_WRITE, UC_MEM_READ, UC_MEM_FETCH, UC_MEM_READ_UNMAPPED,
                     UC_HOOK_CODE, UC_MEM_WRITE_UNMAPPED, UC_MEM_FETCH_UNMAPPED, UC_MEM_WRITE_PROT,
                     UC_MEM_FETCH_PROT, UC_MEM_READ_AFTER, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_WRITE, UC_ARCH_ARM, UC_MODE_THUMB)
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                               UC_ARM_REG_R7, UC_ARM_REG_R9,
                               UC_ARM_REG_R11, UC_ARM_REG_R12)


# from emu_config.payload_config import br
logger = logging.getLogger(__name__)
# DEBUG_LEVEL = logging.DEBUG
DEBUG_LEVEL = logging.INFO
logging.basicConfig(format='%(funcName)20s:%(message)s', level=DEBUG_LEVEL)

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
DATA = ""


def hook_mem_read(uc, access, address, size, value, user_data):
    _ = access
    _ = size
    _ = user_data
    global DATA
    # pc = uc.reg_read(UC_ARM_REG_PC)
    # if address<0xF000000:
    #    #print("READ of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    #    #return True
    if address == 0x10007000:
        print("WD 0x10007000")
        DATA += "WD 0x10007000"
        return True
    if address == 0x10210A00:
        print("Crypto_Wait 0x10210A00")
        uc.mem_write(0x10210A00, pack("<I", 0xFFFFFFFF))
        return True
    if address == 0x10210AA0:
        print("Read key length")
        uc.mem_write(0x10210AA0, pack("<I", 0x6))
        return True
    if address == 0x10210BA0:
        print("Crypto_Wait 0x10210BA0")
        value = 1
        uc.mem_write(address, pack("<I", value))
        return True
    if address == 0x10210E9C:
        print("AddDescSequence 0x10210E9C")
        # mpc=pc+8
        # uc.reg_write(UC_ARM_REG_PC,mpc)
        uc.mem_write(address, pack("<I", 0xFFFFFFFF))
        return True
    if 0x10220000 > address >= 0x10210000:
        print("CBR %08X:%08X" % (address, value))
        return True
    return False


def hook_mem_write(uc, access, address, size, value, user_data):
    global DATA
    _ = uc
    _ = access
    _ = size
    _ = user_data
    # pc = uc.reg_read(UC_ARM_REG_PC)
    if address == 0x10007000:
        DATA += "WD: 0x10007000"
        print("WD: 0x10007000")
        return True
    if address == 0x1000108C:
        print(f"TZCC_CLK 0x1000108C {hex(value)}")
        return True
    if address == 0x10001088:
        print(f"TZCC_CLK 0x10001088 {hex(value)}")
        return True
    if 0x10220000 > address >= 0x10210000:
        print(f"CBW {hex(address)},{hex(value)}")
        return True
    # else:
    #    data=hex(value)
    #    print("MW %08X:%d:%s" %(address,size,data))
    return False

def hook_code(uc, access, address, size):
    _ = access
    _ = address
    _ = size
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    if pc == 0x23158C:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        print("sasi_paldmamap PC(%08X) R0:%08X,R1:%08X,R2:%08X" % (lr, r0, r1, r2))
        print("SRC:" + hexlify(uc.mem_read(r0, 16)).decode('utf-8'))
        print("DST:" + hex(r2))
    elif pc == 0x230DF8:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        r3 = uc.reg_read(UC_ARM_REG_R3)
        r4 = uc.reg_read(UC_ARM_REG_R4)
        r7 = uc.reg_read(UC_ARM_REG_R7)
        r9 = uc.reg_read(UC_ARM_REG_R9)
        r11 = uc.reg_read(UC_ARM_REG_R11)
        print("SBROM_AesCmac PC(%08X) R0:%08X,R1:%08X,R2:%08X,R3:%08X,R4:%08X,R7:%08X,R9:%08X,R11:%08X" % (
            lr, r0, r1, r2, r3, r4, r7, r9, r11))
        print("Buffer:" + hexlify(uc.mem_read(r9, r7)).decode('utf-8'))
    elif pc == 0x230CB6:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        r3 = uc.reg_read(UC_ARM_REG_R3)
        r4 = uc.reg_read(UC_ARM_REG_R4)
        r5 = uc.reg_read(UC_ARM_REG_R5)
        r6 = uc.reg_read(UC_ARM_REG_R6)
        print("SBROM_AesCmacDriver PC(%08X) R0:%08X,R1:%08X,R2:%08X,R3:%08X,R4:%08X,R5:%08X,R6:%08X" % (
            lr, r0, r1, r2, r3, r4, r5, r6))
    elif pc == 0x22750C:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        print("memcpy PC(%08X) R0:%08X,R1:%08X,R2:%08X" % (lr, r0, r1, r2))
        print("SRC:" + hexlify(uc.mem_read(r1, r2)).decode('utf-8'))
        print("DST:" + hex(r0))
    elif pc == 0x2316F8:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        print("UTIL_memcpy PC(%08X) R0:%08X,R1:%08X,R2:%08X" % (lr, r0, r1, r2))
        print("SRC:" + hexlify(uc.mem_read(r1, r2)).decode('utf-8'))
        print("DST:" + hex(r0))
    elif pc == 0x230BB8:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        r3 = uc.reg_read(UC_ARM_REG_R3)
        r4 = uc.reg_read(UC_ARM_REG_R4)
        r5 = uc.reg_read(UC_ARM_REG_R5)
        r6 = uc.reg_read(UC_ARM_REG_R6)
        r7 = uc.reg_read(UC_ARM_REG_R7)
        r12 = uc.reg_read(UC_ARM_REG_R12)
        print("SBROM_KeyDerivation PC(%08X)" % lr)
        print("R0:%08X,R1:%08X,R2:%08X,R3:%08X,R4:%08X,R5:%08X,R6:%08X,R7:%08X,R12:%08X" % (
            r0, r1, r2, r3, r4, r5, r6, r7, r12))
        print("R2:" + hexlify(uc.mem_read(r2, r3)).decode('utf-8'))
        print("R5:" + hexlify(uc.mem_read(r5, r6)).decode('utf-8'))
    # print("PC %08X" % pc)
    return True


def hook_mem_invalid(uc, access, address, size, value, user_data):
    info = ""
    _ = user_data
    pc = uc.reg_read(UC_ARM_REG_PC)
    if access == UC_MEM_WRITE:
        info = (f"invalid WRITE of {hex(address)} at {hex(pc)}, " +
                f"data size = {hex(size)}, data value = {hex(value)}")
    if access == UC_MEM_READ:
        info = f"invalid READ of {hex(address)} at {hex(pc)}, data size = {hex(size)}"
    if access == UC_MEM_FETCH:
        info = ("UC_MEM_FETCH of 0x%x at 0x%X, data size = %u" %
                (address, pc, size))
    if access == UC_MEM_READ_UNMAPPED:
        info = ("UC_MEM_READ_UNMAPPED of 0x%x at 0x%X, data size = %u" %
                (address, pc, size))
    if access == UC_MEM_WRITE_UNMAPPED:
        info = ("UC_MEM_WRITE_UNMAPPED of 0x%x at 0x%X, data size = %u" %
                (address, pc, size))
    if access == UC_MEM_FETCH_UNMAPPED:
        info = ("UC_MEM_FETCH_UNMAPPED of 0x%x at 0x%X, data size = %u" %
                (address, pc, size))
    if access == UC_MEM_WRITE_PROT:
        info = ("UC_MEM_WRITE_PROT of 0x%x at 0x%X, data size = %u" %
                (address, pc, size))
    if access == UC_MEM_FETCH_PROT:
        info = ("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" %
                (address, pc, size))
    if access == UC_MEM_FETCH_PROT:
        info = ("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" %
                (address, pc, size))
    if access == UC_MEM_READ_AFTER:
        info = ("UC_MEM_READ_AFTER of 0x%x at 0x%X, data size = %u" %
                (address, pc, size))
    print(info)
    return False


def do_generic_emu_setup(mu, reg):
    _ = reg
    _ = """
    def replace_function(address, callback):
        def hook_code(uc, address, size, user_data):
            logger.debug(">>> Installed hook at 0x%x, instruction size = 0x%x" %
                         (address, size))
            ret = user_data(reg)
            uc.reg_write(UC_ARM_REG_R0, ret)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        mu.hook_add(UC_HOOK_CODE, hook_code, user_data=callback, begin=address, end=address)

    def monitor_function(address, callback):
        def hook_code(uc, address, size, user_data):
            logger.debug(">>> Installed monitor at 0x%x, instruction size = 0x%x" % (address, size))
            user_data(reg)

        mu.hook_add(UC_HOOK_CODE, hook_code, user_data=callback, begin=address, end=address)
    """
    """
    
    def send_usb_response(regs):
        pc = reg["LR"]
        print("send_usb_response %08X" % pc)
        return 0
    """

    # mu.hook_add(UC_HOOK_BLOCK, hook_block)
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=0, end=-1)
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    # replace_function(brom_base+br[field][0]-1,send_usb_response)


def main():
    pfilename = os.path.join("../mtkclient", "Loader", "Preloader", "preloader_k71v1_64_bsp.bin")
    with open(pfilename, "rb") as rf:
        payload = rf.read()
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    reg = ARMRegisters(mu)
    reg["SP"] = 0x2001D4  # Stack from start
    preloader_base = 0x200E20
    mu.mem_map(0x100000, 0x400000)  # Map generic memory for payload
    try:
        mu.mem_map(0x10000000, 0x1000000)  # Map WD, TZCC
        mu.mem_map(0x11000000, 0x1000000)  # Map Uart+SEC_REG
    except Exception:
        pass
    reg["R0"] = 1
    reg["R1"] = 0x100000
    reg["R2"] = 16
    mu.mem_write(preloader_base, payload)
    do_generic_emu_setup(mu, reg)

    # Main EDL emulation
    logger.info("Emulating Preloader")
    try:
        mu.emu_start(0x230B1D, -1, 0, 0)  # generate_fde_key
    except Exception:
        pass
    logger.info("Emulation done.")


if __name__ == "__main__":
    main()
