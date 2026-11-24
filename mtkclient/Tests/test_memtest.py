#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Unit tests for the V5 legacy memory test flow (MEMORY_TEST_CMD 0xFE) port.
# The DA side is a scripted fake port - no device is touched.
import unittest
from struct import pack, unpack

from mtkclient.Library.DA.legacy.memtest import (MemTestArg, MemTestItems, MemTestPattern,
                                                 MemTestResult, MemTestStage,
                                                 MemoryTestCommand, parse_progress,
                                                 run_memory_test, STAGE_FLAG,
                                                 RESULT_OK, RESULT_FAIL)
from mtkclient.Library.DA.legacy.dalegacy_param import Cmd, Rsp


class FakePort:
    """Scripted legacy-DA port: answers 0xFE with SOC_OK, records writes,
    streams a canned list of progress words."""

    def __init__(self, status=Rsp.SOC_OK, words=()):
        self.writes = []
        self.status = status
        self.words = list(words)

    def usbwrite(self, data):
        self.writes.append(bytes(data))
        return True

    def usbread(self, length=0, *args, **kwargs):
        if length == 1:
            return self.status
        if length == 4:
            if not self.words:
                return b""
            return pack(">I", self.words.pop(0))
        return b""


class FakeMtk:
    def __init__(self, port):
        self.port = port


class Recorder:
    def __init__(self):
        self.events = []

    def on_init(self):
        self.events.append(("init",))

    def on_progress(self, address):
        self.events.append(("progress", address))

    def on_stage_message(self, stage, message):
        self.events.append(("stage", stage, message))

    def on_bad_block(self, address):
        self.events.append(("badblock", address))


class TestMemTestArg(unittest.TestCase):
    def test_pack_layout(self):
        arg = MemTestArg(test_items=MemTestItems.DRAM_FLIP_TEST,
                         start_address=0x40000000, length=0x20000000,
                         pattern=MemTestPattern.DEDICATED_BYTE, flip_count=3)
        data = arg.pack()
        self.assertEqual(len(data), MemTestArg.SIZE)
        items, start, length, pattern, flips, stop = unpack(">IIIIII", data)
        self.assertEqual(items, 0x04)
        self.assertEqual(start, 0x40000000)
        self.assertEqual(length, 0x20000000)
        self.assertEqual(pattern, 0x5A)
        self.assertEqual(flips, 3)
        self.assertEqual(stop, 0)

    def test_pack_unpack_roundtrip(self):
        arg = MemTestArg(test_items=0x1F, start_address=0x40001000, length=0x1000,
                         pattern=0x5A5A, flip_count=7, stop_flag=0xFFFFFFFF)
        restored = MemTestArg.unpack(arg.pack())
        self.assertEqual(restored.test_items, arg.test_items)
        self.assertEqual(restored.start_address, arg.start_address)
        self.assertEqual(restored.length, arg.length)
        self.assertEqual(restored.pattern, arg.pattern)
        self.assertEqual(restored.flip_count, arg.flip_count)
        self.assertEqual(restored.stop_flag, arg.stop_flag)

    def test_unpack_wrong_size(self):
        with self.assertRaises(ValueError):
            MemTestArg.unpack(b"\x00" * 8)

    def test_stop_flag(self):
        arg = MemTestArg()
        self.assertEqual(arg.stop_flag, 0)
        arg.stop()
        self.assertEqual(arg.stop_flag, 0xFFFFFFFF)

    def test_command_byte_is_0xFE(self):
        # same byte mtkclient's dalegacy_param.Cmd.MEMORY_TEST_CMD uses
        self.assertEqual(Cmd.MEMORY_TEST_CMD, b"\xFE")
        self.assertEqual(Rsp.SOC_OK, b"\xC1")


class TestParseProgress(unittest.TestCase):
    def test_stage_words(self):
        self.assertEqual(parse_progress(STAGE_FLAG | 0), ("stage", 0))
        self.assertEqual(parse_progress(STAGE_FLAG | 3), ("stage", 3))
        self.assertEqual(parse_progress(STAGE_FLAG | 0xFF), ("stage", 0xFF))

    def test_progress_words(self):
        # plain words are relative offsets inside the test range
        self.assertEqual(parse_progress(0x00001000), ("progress", 0x1000))
        self.assertEqual(parse_progress(0x00000100), ("progress", 0x100))
        self.assertEqual(parse_progress(0x7FFFFFFF), ("progress", 0x7FFFFFFF))

    def test_badblock_words(self):
        self.assertEqual(parse_progress(0x8B001234), ("badblock", 0x1234))
        self.assertEqual(parse_progress(0x8B020000), ("badblock", 0x020000))

    def test_result_words(self):
        self.assertEqual(parse_progress(RESULT_OK), ("result", MemTestResult.OK))
        self.assertEqual(parse_progress(RESULT_FAIL), ("result", MemTestResult.FLIP_FAIL))
        self.assertEqual(parse_progress(0x90000005),
                         ("result", MemTestResult.ERROR_INCREMENTAL))

    def test_framing_bands_disjoint(self):
        # stage / badblock / verdict bands must never overlap, and no band
        # collides with plain progress words (bit31 clear)
        for word in (STAGE_FLAG | 1, 0x8B001234, RESULT_OK, RESULT_FAIL, 0x1000):
            self.assertEqual((word >> 24) & 0xFF in (0x80, 0x8B, 0x90),
                             bool(word & STAGE_FLAG))


class TestMemoryTestFlow(unittest.TestCase):
    def _words(self, *items):
        return [pack(">I", w) if isinstance(w, int) else w for w in items]

    def test_happy_path(self):
        rec = Recorder()
        port = FakePort(words=[STAGE_FLAG | MemTestStage.INIT,
                               0x1000,
                               STAGE_FLAG | MemTestStage.DRAM_FLIP,
                               RESULT_OK])
        mtk = FakeMtk(port)
        cmd = MemoryTestCommand(mtk)
        cmd.on_init = rec.on_init
        cmd.on_progress = rec.on_progress
        cmd.on_stage_message = rec.on_stage_message
        ok, message = cmd.exec(MemTestArg(), display=False)
        self.assertTrue(ok)
        self.assertEqual(message, "Memory Test Ok")
        # first write = 0xFE command, second = arg struct
        self.assertEqual(port.writes[0], b"\xFE")
        self.assertEqual(len(port.writes[1]), MemTestArg.SIZE)
        # stage events got acked
        acks = [w for w in port.writes if w == Rsp.ACK]
        self.assertEqual(len(acks), 2)
        self.assertIn(("init",), rec.events)
        # relative offset 0x1000 -> absolute addr with default base 0x40000000
        self.assertIn(("progress", 0x40001000), rec.events)
        self.assertIn(("stage", MemTestStage.DRAM_FLIP, "DRAM Flip Test"), rec.events)

    def test_pattern_error_mapping(self):
        from mtkclient.Library.DA.legacy.memtest import VERDICT_FLAG
        port = FakePort(words=[STAGE_FLAG | MemTestStage.INIT,
                               VERDICT_FLAG | MemTestResult.ERROR_INCREMENTAL])
        ok, message = MemoryTestCommand(FakeMtk(port)).exec(MemTestArg(), display=False)
        self.assertFalse(ok)
        self.assertIn("incremental pattern", message)

    def test_flip_fail_via_soc_fail_echo(self):
        port = FakePort(words=[RESULT_FAIL])
        ok, message = MemoryTestCommand(FakeMtk(port)).exec(MemTestArg(), display=False)
        self.assertFalse(ok)
        self.assertIn("Flip test fail", message)

    def test_da_rejects_command(self):
        port = FakePort(status=Rsp.UNKNOWN_CMD)
        ok, message = MemoryTestCommand(FakeMtk(port)).exec(MemTestArg(), display=False)
        self.assertFalse(ok)
        self.assertIn("doesn't support", message)
        # no args were sent
        self.assertEqual(len(port.writes), 1)

    def test_da_fail_status(self):
        port = FakePort(status=Rsp.SOC_FAIL)
        ok, message = MemoryTestCommand(FakeMtk(port)).exec(MemTestArg(), display=False)
        self.assertFalse(ok)
        self.assertIn("rejected", message)

    def test_bad_block_report(self):
        rec = Recorder()
        port = FakePort(words=[0x8B002000, RESULT_OK])
        cmd = MemoryTestCommand(FakeMtk(port))
        cmd.on_bad_block = rec.on_bad_block
        ok, _ = cmd.exec(MemTestArg(), display=False)
        self.assertTrue(ok)
        self.assertIn(("badblock", 0x002000), rec.events)

    def test_stop_request(self):
        port = FakePort(words=[0x40001000, RESULT_OK])
        cmd = MemoryTestCommand(FakeMtk(port))
        cmd.notify_stop = lambda: None
        # stop after first progress word
        orig_exec = cmd.exec

        def stop_after_first_progress():
            # simulate: after sending args, request stop
            pass
        ok, message = cmd.exec(MemTestArg(), display=False)
        # direct stop() call sends the stop flag word
        cmd.stop()
        stops = [w for w in port.writes if w == pack(">I", 0xFFFFFFFF)]
        self.assertEqual(len(stops), 1)
        self.assertTrue(ok)

    def test_da_silence(self):
        port = FakePort(words=[])
        ok, message = MemoryTestCommand(FakeMtk(port)).exec(MemTestArg(), display=False)
        self.assertFalse(ok)
        self.assertIn("stopped responding", message)


class TestConvenienceWrapper(unittest.TestCase):
    def test_run_memory_test(self):
        port = FakePort(words=[STAGE_FLAG | MemTestStage.INIT, RESULT_OK])
        rec = Recorder()
        ok, message = run_memory_test(FakeMtk(port),
                                      test_items=MemTestItems.RAM_PATTERN_TEST,
                                      start_address=0x40000000, length=0x100000,
                                      display=False, callbacks=rec)
        self.assertTrue(ok)
        self.assertIn(("init",), rec.events)
        # arg struct carried our range
        arg = MemTestArg.unpack(port.writes[1])
        self.assertEqual(arg.start_address, 0x40000000)
        self.assertEqual(arg.length, 0x100000)
        self.assertEqual(arg.test_items, MemTestItems.RAM_PATTERN_TEST)

    def test_result_messages_complete(self):
        # every SPFT H/W error string is mapped
        for code in (MemTestResult.BUS_ERROR, MemTestResult.PIN_TWO_SHORT,
                     MemTestResult.PIN_ALWAYS_HIGH, MemTestResult.PIN_ALWAYS_LOW,
                     MemTestResult.ERROR_INCREMENTAL, MemTestResult.ERROR_DECREMENTAL,
                     MemTestResult.ERROR_DEDICATED, MemTestResult.FLIP_FAIL):
            message = MemTestResult.message(code)
            self.assertNotIn("Unknown", message)
            self.assertTrue(message.startswith("[H/W]") or message == "Memory Test Ok")


if __name__ == "__main__":
    unittest.main()
