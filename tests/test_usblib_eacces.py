# Unit tests for the EACCES-swallowing bug in UsbClass.connect() (usblib.py).
#
# Bug (mtk-macos-eacces-2026-11-24.md, key_bugs_found #1): claim_interface(0)
# was wrapped in "except Exception: pass", so a libusb EACCES (errno 13) was
# swallowed and connect() returned True with an unclaimed interface.
#
# Expected behavior after the fix:
#   - EACCES on claim -> UsbResetMidTransferError with the mandated message
#     "USB reset mid-transfer (kamakiri crash) - retry expected" (chained from
#     the original USBError), so the upper retry loop can tell a mid-transfer
#     reset apart from a permissions problem.
#   - Non-EACCES claim errors keep the historical tolerate-and-continue path.
#
# All libusb interaction is mocked; no phone is required or touched.
import sys
import unittest

import usb.core
import usb.util

import mtkclient.Library.Connection.usblib as usblib
from mtkclient.Library.Connection.usblib import UsbClass
from mtkclient.Library.Connection.usblib import UsbResetMidTransferError

EACCES_STRERROR = "Access denied (insufficient permissions)"


class FakeEndpoint:
    bEndpointAddress = 0x81
    wMaxPacketSize = 64


class FakeInterface:
    bInterfaceNumber = 0
    bInterfaceClass = 0xFF


class FakeConfiguration:
    bNumInterfaces = 1


class FakeDevice:
    idVendor = 0x0E8D
    idProduct = 0x0003

    def get_active_configuration(self):
        return FakeConfiguration()

    def set_configuration(self):
        pass

    def is_kernel_driver_active(self, interface):
        # darwin backend raises NotImplementedError here; the current code
        # tolerates it, so the mock exercises the same path.
        raise NotImplementedError("Not supported by backend")


def make_usb_error(errno_, strerror):
    return usb.core.USBError(errno=errno_, strerror=strerror)


class UsbClaimEaccesTest(unittest.TestCase):
    def setUp(self):
        # UsbClass.__init__ needs no device: on backends without libusb it
        # simply keeps self.backend=None, which the mocked find() ignores.
        # Pin the platform to a non-darwin value so the darwin capture branch
        # is unreachable here regardless of the host OS or attached devices;
        # the darwin path is covered explicitly by DarwinCaptureTest.
        self._saved = {}
        self.patch(sys, "platform", "linux")
        self.patch(usblib.glob, "glob", lambda pattern: [])
        self.usb = UsbClass(loglevel=100)  # 100 > CRITICAL: silence logging
        self.usb.portconfig = {0x0E8D: {0x0003: 0}}

    def tearDown(self):
        for attr, value in self._saved.items():
            setattr(attr[0], attr[1], value)

    def patch(self, module, name, value):
        self._saved[(module, name)] = getattr(module, name)
        setattr(module, name, value)

    def _mock_enumeration(self, device):
        self.patch(usb.core, "find", lambda *args, **kwargs: [device])
        self.patch(usb.util, "find_descriptor", lambda *args, **kwargs: FakeInterface())

    def test_claim_eacces_raises_reset_mid_transfer_error(self):
        device = FakeDevice()
        self._mock_enumeration(device)

        def failing_claim(dev, interface):
            raise make_usb_error(13, EACCES_STRERROR)

        self.patch(usb.util, "claim_interface", failing_claim)

        with self.assertRaises(UsbResetMidTransferError) as ctx:
            self.usb.connect()

        err = ctx.exception
        self.assertTrue(
            str(err).startswith("USB reset mid-transfer (kamakiri crash) - retry expected"),
            f"unexpected message: {err}",
        )
        self.assertEqual(err.errno, 13)
        self.assertIn("claim_interface(0)", err.operation)
        self.assertIsInstance(err.usb_error, usb.core.USBError)
        # chained from the original libusb error
        self.assertIsInstance(err.__cause__, usb.core.USBError)

    def test_claim_eacces_must_not_report_connected(self):
        # The regression this test pins: connect() used to return True with an
        # unclaimed interface after swallowing EACCES.
        device = FakeDevice()
        self._mock_enumeration(device)
        self.patch(usb.util, "claim_interface",
                   lambda dev, interface: (_ for _ in ()).throw(make_usb_error(13, EACCES_STRERROR)))

        with self.assertRaises(UsbResetMidTransferError):
            self.usb.connect()
        self.assertFalse(self.usb.connected)

    def test_claim_non_eacces_error_still_tolerated(self):
        # Only EACCES became fatal; every other claim failure keeps the old
        # behavior (log and continue), e.g. backends without claim support.
        device = FakeDevice()
        self._mock_enumeration(device)
        self.patch(usb.util, "find_descriptor", lambda *args, **kwargs: FakeEndpoint())
        self.patch(usb.util, "claim_interface",
                   lambda dev, interface: (_ for _ in ()).throw(make_usb_error(19, "No such device")))

        self.assertTrue(self.usb.connect())
        self.assertTrue(self.usb.connected)

    def test_claim_non_usberror_exception_still_tolerated(self):
        # Non-USBError claim failures (e.g. unexpected backend wrapper bugs)
        # keep the historical tolerate-and-continue path; a regression back to
        # a bare "except: pass" would also pass, but a raise would not.
        device = FakeDevice()
        self._mock_enumeration(device)
        self.patch(usb.util, "find_descriptor", lambda *args, **kwargs: FakeEndpoint())
        self.patch(usb.util, "claim_interface",
                   lambda dev, interface: (_ for _ in ()).throw(ValueError("backend wrapper bug")))

        self.assertTrue(self.usb.connect())
        self.assertTrue(self.usb.connected)


class UpperRetryLoopTest(unittest.TestCase):
    def test_wait_for_device_survives_reset_error_and_retries(self):
        # End-to-end pin of the retry seam: Port.wait_for_device already
        # catches Exception and retries; with the new error class the loop
        # now SEES the EACCES cause (warning log) instead of a silent
        # connected=True with an unclaimed interface.
        from types import SimpleNamespace

        from mtkclient.Library.Port import Port

        mtk = SimpleNamespace(config=SimpleNamespace(gui=False))
        port = Port(mtk, portconfig=None, loglevel=100)
        attempts = {"n": 0}

        def fake_connect():
            attempts["n"] += 1
            raise UsbResetMidTransferError(make_usb_error(13, EACCES_STRERROR), "claim_interface(0)")

        setattr(port.cdc, "connect", fake_connect)

        self.assertFalse(port.wait_for_device(max_attempts=3, interval=0))
        self.assertEqual(attempts["n"], 3)


class DetachableFakeDevice(FakeDevice):
    def __init__(self):
        self.detach_calls = 0

    def detach_kernel_driver(self, interface):
        self.detach_calls += 1


class DarwinCaptureTest(unittest.TestCase):
    """The riskiest new path: darwin capture -> re-find -> rebuild -> claim.

    Pinned explicitly so the effective coverage does not depend on the host
    OS or on whatever /dev/cu.usbmodem* devices happen to be attached."""

    def setUp(self):
        self._saved = {}
        self.patch(sys, "platform", "darwin")
        self.patch(usblib.glob, "glob", lambda pattern: ["/dev/cu.usbmodem1101"])
        self.patch(usblib.time, "sleep", lambda seconds: None)
        self.usb = UsbClass(loglevel=100)
        self.usb.portconfig = {0x0E8D: {0x0003: 0}}

    def tearDown(self):
        for attr, value in self._saved.items():
            setattr(attr[0], attr[1], value)

    def patch(self, module, name, value):
        self._saved[(module, name)] = getattr(module, name)
        setattr(module, name, value)

    def _mock(self, device, refind_device):
        def fake_find(*args, **kwargs):
            if kwargs.get("find_all"):
                return [device]
            return refind_device

        self.patch(usb.core, "find", fake_find)
        self.patch(usb.util, "find_descriptor", lambda *a, **k: FakeInterface())
        self.patch(usb.util, "claim_interface", lambda dev, interface: None)
        # connect() on an already-connected instance calls close() first, and
        # close() runs the real dispose_resources on the mock — neutralize it.
        self.patch(usb.util, "dispose_resources", lambda dev: None)

    def test_capture_refinds_device_and_rebuilds_state(self):
        device = DetachableFakeDevice()
        dev2 = DetachableFakeDevice()
        self._mock(device, dev2)

        self.assertTrue(self.usb.connect())

        self.assertEqual(device.detach_calls, 1)
        self.assertIs(self.usb.device, dev2)
        self.assertTrue(self.usb._darwin_captured)

    def test_capture_happens_once_per_instance(self):
        device = DetachableFakeDevice()
        dev2 = DetachableFakeDevice()
        self._mock(device, dev2)

        self.assertTrue(self.usb.connect())
        self.assertTrue(self.usb.connect())

        # Second connect must not re-capture (churn guard): the gate is the
        # _darwin_captured flag, so the else-branch (is_kernel_driver_active)
        # runs instead — the FakeDevice base raises NotImplementedError there,
        # and neither device object is detached a second time.
        self.assertEqual(device.detach_calls, 1)
        self.assertEqual(dev2.detach_calls, 0)

    def test_device_vanishing_after_capture_returns_false(self):
        device = DetachableFakeDevice()
        self._mock(device, None)  # re-find never sees the device again

        self.assertFalse(self.usb.connect())
        self.assertEqual(device.detach_calls, 1)

    def test_capture_denied_surfaces_eacces_from_claim(self):
        # Without root the capture itself raises EACCES; the claim that
        # follows must still surface UsbResetMidTransferError (part-1
        # contract), and the log must name the permissions cause.
        device = DetachableFakeDevice()

        def denied_detach(interface):
            raise make_usb_error(13, EACCES_STRERROR)

        device.detach_kernel_driver = denied_detach
        self._mock(device, None)
        # real world: capture denied AND claim denied by the same ACM driver
        self.patch(usb.util, "claim_interface",
                   lambda dev, interface: (_ for _ in ()).throw(make_usb_error(13, EACCES_STRERROR)))

        with self.assertRaises(UsbResetMidTransferError):
            self.usb.connect()


class UsbResetMidTransferErrorContractTest(unittest.TestCase):
    def test_not_a_usberror_subclass(self):
        # Must not be caught by "except usb.core.USBError" handlers that treat
        # it as an ordinary transfer failure; it is a distinct condition.
        self.assertFalse(issubclass(UsbResetMidTransferError, usb.core.USBError))
        self.assertTrue(issubclass(UsbResetMidTransferError, Exception))

    def test_message_carries_operation_and_original_error(self):
        original = make_usb_error(13, EACCES_STRERROR)
        err = UsbResetMidTransferError(original, "claim_interface(0) on 0xe8d:0x3")
        self.assertEqual(err.errno, 13)
        self.assertIs(err.usb_error, original)
        self.assertIn("claim_interface(0) on 0xe8d:0x3", str(err))
        self.assertIn(EACCES_STRERROR, str(err))


if __name__ == "__main__":
    unittest.main()
