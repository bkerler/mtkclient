#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) Daniel Kamyshan 2026, ported from SP Flash Tool V5
# Licensed under GPLv3 License
#
# Legacy DA memory test flow (MEMORY_TEST_CMD = 0xFE) for mtkclient.
#
# Port of SP Flash Tool V5:
#  - APCore::MemoryTestCommand::{RAMPatternTest, DRAMFlipTest, DRAMInterfaceDiagnoseTest,
#    EnableDRAM, exec} (flash_tool.exe, MemoryTestCommand.cpp)
#  - BromMemtestArg (BromMemtestArg.cpp): cb_memtest_init ("memory test inited..."),
#    cb_memtest_progress ("(0x%08X),", "[A%d]", "[D%d]"),
#    cb_memtest_nand_bad_block_report ("Bad Block addr: 0x%016I64X")
#  - libflashtool callbacks: memtest_operation_progress / memtest_stage_message /
#    memtest_notify_stop; stop flag ("memtest stop flag,(0x%08X)")
#  - DA-side result strings (H/W errors): incremental/decremental/dedicated pattern,
#    bus error, two pins short, pin always high / always low, "DRAM Flip test fail"
#
# The command byte matches mtkclient's own dalegacy_param.Cmd.MEMORY_TEST_CMD (0xFE),
# which existed without any flow around it - this module supplies the missing flow.
#
# NOTE on the arg layout: SPFT's Windows FlashToolLib binary carries the struct
# definition only in machine code; the packing below is a reconstruction from the
# BromMemtestArg semantics (test item mask, range, pattern, flip count, stop flag)
# using the same big-endian dword convention as the rest of the legacy DA protocol.
# All wire encoding lives in MemTestArg.pack()/parse_progress() so it can be adjusted
# against a live DA log without touching the flow logic.
import logging
from struct import pack, unpack

from mtkclient.Library.DA.legacy.dalegacy_param import Cmd, Rsp


class MemTestItems:
    """Test item bitmask (APCore::MemoryTestCommand test selection)."""
    RAM_PATTERN_TEST = 0x01          # Inc/Dec Pattern Test
    RAM_DEDICATED_PATTERN = 0x02     # Dedicated Pattern Test (0x5A)
    DRAM_FLIP_TEST = 0x04            # DRAM Flip Test
    DRAM_INTERFACE_DIAGNOSE = 0x08   # DRAM Interface Diagnose
    ENABLE_DRAM = 0x10               # Enable DRAM


class MemTestPattern:
    """Dedicated pattern values (SPFT: 'Pattern Test (0x5A)', '(0x5A5A)')."""
    DEDICATED_BYTE = 0x5A
    DEDICATED_HALFWORD = 0x5A5A


class MemTestResult:
    """DA memory test result codes and the SPFT H/W error messages."""
    OK = 0x00
    BUS_ERROR = 0x01
    PIN_TWO_SHORT = 0x02
    PIN_ALWAYS_HIGH = 0x03
    PIN_ALWAYS_LOW = 0x04
    ERROR_INCREMENTAL = 0x05
    ERROR_DECREMENTAL = 0x06
    ERROR_DEDICATED = 0x07
    FLIP_FAIL = 0x08

    MESSAGES = {
        OK: "Memory Test Ok",
        BUS_ERROR: "[H/W] DA detects bus error on the phone while memory test!",
        PIN_TWO_SHORT: "[H/W] DA detects that two pin is short on the phone while memory test!",
        PIN_ALWAYS_HIGH: "[H/W] DA detects that a pin is always high on the phone while memory test!",
        PIN_ALWAYS_LOW: "[H/W] DA detects that a pin is always low on the phone while memory test!",
        ERROR_INCREMENTAL: ("[H/W] DA detects error on the phone while memory test with "
                            "incremental pattern! Please ask for help."),
        ERROR_DECREMENTAL: ("[H/W] DA detects error on the phone while memory test with "
                            "decremental pattern! Please ask for help."),
        ERROR_DEDICATED: ("[H/W] DA detects error on the phone while memory test with "
                          "dedicated pattern! Please ask for help."),
        FLIP_FAIL: "[H/W] DA detect DRAM Flip test fail",
    }

    @classmethod
    def message(cls, code):
        return cls.MESSAGES.get(code, f"Unknown memory test result: 0x{code:08X}")


class MemTestArg:
    """
    Argument structure sent after MEMORY_TEST_CMD (reconstruction of BromMemtestArg):
    test item mask, range, dedicated pattern, flip count and stop flag, big-endian.
    """

    FORMAT = ">IIIIII"
    SIZE = 24

    def __init__(self, test_items: int = MemTestItems.RAM_PATTERN_TEST,
                 start_address: int = 0x40000000, length: int = 0x100000,
                 pattern: int = MemTestPattern.DEDICATED_BYTE,
                 flip_count: int = 1, stop_flag: int = 0):
        self.test_items = test_items
        self.start_address = start_address
        self.length = length
        self.pattern = pattern
        self.flip_count = flip_count
        self.stop_flag = stop_flag

    def pack(self) -> bytes:
        return pack(self.FORMAT, self.test_items, self.start_address, self.length,
                    self.pattern, self.flip_count, self.stop_flag)

    @classmethod
    def unpack(cls, data: bytes) -> "MemTestArg":
        if len(data) != cls.SIZE:
            raise ValueError(f"MemTestArg expects {cls.SIZE} bytes, got {len(data)}")
        items, start, length, pattern, flips, stop = unpack(cls.FORMAT, data)
        return cls(test_items=items, start_address=start, length=length,
                   pattern=pattern, flip_count=flips, stop_flag=stop)

    def stop(self):
        """Host requests termination (memtest_notify_stop / stop flag)."""
        self.stop_flag = 0xFFFFFFFF
        return self

    def __repr__(self):
        return (f"<MemTestArg items={hex(self.test_items)} "
                f"addr={hex(self.start_address)} len={hex(self.length)} "
                f"pattern={hex(self.pattern)} flips={self.flip_count} "
                f"stop={hex(self.stop_flag)}>")


class MemTestStage:
    """Stage ids reported by the DA during the test (memtest_stage_message)."""
    INIT = 0
    RAM_PATTERN = 1
    RAM_DEDICATED = 2
    DRAM_FLIP = 3
    DRAM_INTERFACE_DIAGNOSE = 4
    ENABLE_DRAM = 5
    DONE = 0xFF

    MESSAGES = {
        INIT: "memory test inited...",
        RAM_PATTERN: "RAM Pattern Test",
        RAM_DEDICATED: "Dedicated Pattern Test",
        DRAM_FLIP: "DRAM Flip Test",
        DRAM_INTERFACE_DIAGNOSE: "DRAM Interface Diagnose",
        ENABLE_DRAM: "Enable DRAM",
        DONE: "Memory test done",
    }


# Progress word framing: bit31 marks control words; plain words are relative
# offsets inside the test range (a test range never spans 2 GB), so they can
# never collide with control words. Absolute addresses are reconstructed
# host-side (base + offset). Control bands (disjoint high bytes):
#   0x800000xx  stage event (stage id in low byte)
#   0x8Bxxxxxx  nand bad-block report (block index, "BB")
#   0x900000xx  final verdict (MemTestResult code in low byte)
STAGE_FLAG = 0x80000000
BADBLOCK_FLAG = 0x8B000000
VERDICT_FLAG = 0x90000000
RESULT_OK = VERDICT_FLAG | MemTestResult.OK           # 0x90000000
RESULT_FAIL = VERDICT_FLAG | MemTestResult.FLIP_FAIL  # 0x90000008


def parse_progress(word: int):
    """
    Decode a progress word from the DA:
      - 0x800000xx -> ("stage", stage_id)
      - 0x8Bxxxxxx -> ("badblock", block index)
      - 0x900000xx -> ("result", MemTestResult code)
      - otherwise  -> ("progress", relative offset)
    """
    if word & STAGE_FLAG:
        if word & 0xFFFFFF00 == STAGE_FLAG:
            return "stage", word & 0xFF
        if word & 0xFF000000 == BADBLOCK_FLAG:
            return "badblock", word & 0x00FFFFFF
        if word & 0xFF000000 == VERDICT_FLAG:
            return "result", word & 0xFF
    return "progress", word


class MemoryTestCommand:
    """
    V5 legacy memory test flow: MEMORY_TEST_CMD (0xFE) + MemTestArg, with progress
    callbacks ported from libflashtool (memtest_operation_progress, memtest_stage_message,
    memtest_notify_stop) and SPFT's BromMemtestArg callbacks.
    """

    def __init__(self, mtk, loglevel=logging.INFO):
        self.mtk = mtk
        self.loglevel = loglevel
        self.usbwrite = mtk.port.usbwrite
        self.usbread = mtk.port.usbread
        self.stop_requested = False

    # ---- callbacks (override / pass in) -------------------------------------

    def on_init(self):
        """BromMemtestArg::cb_memtest_init - 'memory test inited...'"""

    def on_progress(self, address: int):
        """BromMemtestArg::cb_memtest_progress - '(0x%08X),'"""

    def on_stage_message(self, stage: int, message: str):
        """libflashtool memtest_stage_message."""

    def on_bad_block(self, address: int):
        """BromMemtestArg::cb_memtest_nand_bad_block_report."""

    def notify_stop(self):
        """libflashtool memtest_notify_stop - host side stop request."""

    # ---- protocol ------------------------------------------------------------

    def _send_stop_flag(self):
        """Send the stop flag word ('memtest stop flag,(0x%08X)')."""
        return self.usbwrite(pack(">I", 0xFFFFFFFF))

    def exec(self, arg: MemTestArg, display: bool = True) -> (bool, str):
        """
        Run the memory test. Returns (success, message).
        """
        self.stop_requested = False
        # 1) command byte
        if not self.usbwrite(Cmd.MEMORY_TEST_CMD):
            return False, "Failed to send MEMORY_TEST_CMD (0xFE)"
        status = self.usbread(1)
        if status == Rsp.UNKNOWN_CMD:
            return False, "DA doesn't support MEMORY_TEST_CMD (0xFE)"
        if status != Rsp.SOC_OK:
            return False, f"MEMORY_TEST_CMD rejected: {status.hex() if status else 'no answer'}"
        # 2) argument structure
        if not self.usbwrite(arg.pack()):
            return False, "Failed to send MemTestArg"
        # 3) progress loop: stage events / progress addresses / bad block reports
        while True:
            data = self.usbread(4)
            if data is None or len(data) < 4:
                return False, "Memory test aborted: DA stopped responding"
            word = unpack(">I", data[:4])[0]
            kind, value = parse_progress(word)
            if kind == "stage":
                if value == MemTestStage.INIT:
                    self.on_init()
                    if display:
                        print(MemTestStage.MESSAGES[MemTestStage.INIT])
                else:
                    message = MemTestStage.MESSAGES.get(value, f"Stage {value}")
                    self.on_stage_message(value, message)
                    if display:
                        print(message)
                # ack stage event
                self.usbwrite(Rsp.ACK)
                continue
            if kind == "badblock":
                self.on_bad_block(value)
                continue
            if kind == "progress":
                # relative offset inside the test range -> absolute address
                self.on_progress(arg.start_address + value)
                if self.stop_requested:
                    self._send_stop_flag()
                    self.stop_requested = False
                continue
            # 4) final verdict word (0x900000xx)
            return value == MemTestResult.OK, MemTestResult.message(value)

    def stop(self):
        """Request the DA to abort the running test (memtest_notify_stop port)."""
        self.stop_requested = True
        self.notify_stop()
        return self._send_stop_flag()


def run_memory_test(mtk, test_items: int = MemTestItems.RAM_PATTERN_TEST,
                    start_address: int = 0x40000000, length: int = 0x100000,
                    pattern: int = MemTestPattern.DEDICATED_BYTE, flip_count: int = 1,
                    display: bool = True, callbacks=None) -> (bool, str):
    """
    Convenience wrapper: build a MemTestArg and run the V5 0xFE flow.
    callbacks: optional object with on_init/on_progress/on_stage_message/on_bad_block.
    """
    command = MemoryTestCommand(mtk)
    if callbacks is not None:
        for name in ("on_init", "on_progress", "on_stage_message", "on_bad_block",
                     "notify_stop"):
            if hasattr(callbacks, name):
                setattr(command, name, getattr(callbacks, name))
    arg = MemTestArg(test_items=test_items, start_address=start_address, length=length,
                     pattern=pattern, flip_count=flip_count)
    return command.exec(arg, display=display)
