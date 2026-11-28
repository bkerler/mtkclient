# Unit tests for the EACCES-swallowing bug in Kamakiri2.exploit() (kamakiri2.py).
#
# Bug (mtk-macos-eacces-2026-11-24.md, key_bugs_found #2): exploit() caught
# usb.core.USBError, printed "USB CORE ERROR" and RETURNED TRUE anyway, so the
# caller (Exploitation.da_payload) logged "Done sending payload..." and the
# failure only surfaced later as an empty payload ack.
#
# Expected behavior after the fix:
#   - EACCES (errno 13) -> UsbResetMidTransferError (distinct class, chained
#     from the USBError) so the upper retry loop can treat a mid-transfer USB
#     reset (expected during kamakiri) differently from a permissions problem.
#   - Any other USBError propagates unchanged.
#   - Success still returns True.
#
# All USB interaction is mocked; no phone is required or touched.
import unittest
from types import SimpleNamespace

import usb.core

from mtkclient.Library.Connection.usblib import UsbResetMidTransferError
from mtkclient.Library.Exploit.kamakiri2 import Kamakiri2

EACCES_STRERROR = "Access denied (insufficient permissions)"


def make_usb_error(errno_, strerror):
    return usb.core.USBError(errno=errno_, strerror=strerror)


def make_kamakiri2(da_read_write):
    """Build a Kamakiri2 with the minimum state exploit() touches.

    The real __init__ drags in the full mtk config stack (logsetup,
    HwCrypto, PathConfig); the seam under test is exploit()'s error
    handling, so the instance is created directly and only the used
    attributes are stubbed."""
    inst = Kamakiri2.__new__(Kamakiri2)
    chipconfig = SimpleNamespace(brom_payload_addr=0x00200A00, send_ptr=[[0, 0x1100]])
    config = SimpleNamespace(chipconfig=chipconfig)
    # setattr form: logsetup normally creates these instance attributes at
    # runtime; the static checker does not know the __new__-built instance.
    setattr(inst, "mtk", SimpleNamespace(config=config))
    setattr(inst, "chipconfig", chipconfig)
    setattr(inst, "config", config)
    # pre-set linecode: exploit() then skips the initial ctrl_transfer
    setattr(inst, "linecode", bytearray(8))
    errors = []
    setattr(inst, "error", lambda msg: errors.append(str(msg)))
    setattr(inst, "info", lambda msg: None)
    setattr(inst, "da_read_write", da_read_write)
    setattr(inst, "_captured_errors", errors)
    return inst


class Kamakiri2ExploitEaccesTest(unittest.TestCase):
    PAYLOAD = b"\x00" * 0x10

    def test_exploit_eacces_raises_instead_of_returning_true(self):
        def raise_eacces(address, length, data=None, check_result=True):
            raise make_usb_error(13, EACCES_STRERROR)

        inst = make_kamakiri2(raise_eacces)

        with self.assertRaises(UsbResetMidTransferError) as ctx:
            inst.exploit(self.PAYLOAD)

        err = ctx.exception
        self.assertEqual(err.errno, 13)
        self.assertIn("kamakiri2 exploit", err.operation)
        self.assertIsInstance(err.__cause__, usb.core.USBError)

    def test_exploit_other_usberror_propagates(self):
        def raise_ioerror(address, length, data=None, check_result=True):
            raise make_usb_error(5, "Input/Output Error")

        inst = make_kamakiri2(raise_ioerror)

        with self.assertRaises(usb.core.USBError) as ctx:
            inst.exploit(self.PAYLOAD)
        self.assertNotIsInstance(ctx.exception, UsbResetMidTransferError)

    def test_exploit_success_still_returns_true(self):
        calls = []

        def fake_da_read_write(address, length, data=None, check_result=True):
            calls.append((address, length))
            return b"\x11\x22\x33\x44" if data is None else None

        inst = make_kamakiri2(fake_da_read_write)
        self.assertTrue(inst.exploit(self.PAYLOAD))
        self.assertEqual(len(calls), 3)  # da_read(send_ptr) + 2x da_write


if __name__ == "__main__":
    unittest.main()
