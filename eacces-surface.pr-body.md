## Summary

Two-part fix for the macOS BROM rescue path, built top-down from a live failure:

```text
connect() on darwin
  claim_interface(0)            ← AppleUSBACM (IOProbeScore 10001) holds CDC-Control
  ├─ EACCES was swallowed       → part 1: surface it (UsbResetMidTransferError)
  ├─ is_kernel_driver_active()  → NOT_SUPPORTED on darwin: detach branch is dead code
  └─ capture the whole device   → part 2: libusb >= 1.0.25 detach_kernel_driver() on
     (detach_kernel_driver)        darwin = USBDeviceReEnumerate + capture mask (PR libusb#911)
     re-find re-enumerated device
     retry claim → handshake → kamakiri → DA
```

Part 1 (previous commit): EACCES (errno 13) is no longer swallowed in
`UsbClass.connect()` (`except: pass` → `connected = True` on an unclaimed
interface) nor in `Kamakiri2.exploit()` (`USBError` → `return True`, a false
success). A dedicated `UsbResetMidTransferError` (deliberately not a
`usb.core.USBError` subclass) is raised with the original error chained, plus
`.errno`/`.operation` context. Non-EACCES claim errors keep the historical
tolerate-and-retry behavior.

Part 2 (this commit): when the claim still fails on darwin, the driver is
removed by force: `detach_kernel_driver(0)` on darwin maps to a whole-device
capture (`USBDeviceReEnumerate` + `kUSBReEnumerateCaptureDeviceMask`,
libusb PR #911). The device re-enumerates, so the code re-finds it and retries
the claim. A second capture is attempted only while a live `/dev/cu.usbmodem*`
node for the device exists. Scoped to darwin; Linux/Windows paths untouched
(on Linux the udev rules make the kernel driver situation moot, which is why
root is never needed there).

### Why root on macOS

On Linux the documented answer is udev rules, and running as root is never
needed. macOS has no udev equivalent; the IOKit driver ownership cannot be
released from userspace without the libusb capture mechanism, and that
mechanism requires root (libusb issue #1014 — Apple grants an entitlement
alternative only to VM-applications). The patch does not require root on
Linux and does not change Linux behavior.

## Evidence

- **Before:** `claim_interface(0)` → `[Errno 13] Access denied (insufficient
  permissions)`, swallowed → false `connected = True`; kamakiri printed
  `USB CORE ERROR` and returned `True` while the payload was never delivered.
  Every printgpt/read/write on macOS failed.
- **After (real device, Redmi Note 8 Pro / MT6785, BROM `0e8d:0003`, macOS
  27.2.1 Apple Silicon, libusb 1.0.30):**
  - `darwin: kernel driver detached (USB device captured)` → handshake OK →
    kamakiri payload executed (`Jumping to 0x200000: ok`)
  - `printgpt` completes in 6.4 s; partition reads at 20–30 MB/s; writes
    verified by read-back sha256 (restored `lk`/`vbmeta`/`recovery` on a
    PL-fatal-bricked device, which then booted normally)
- Tests: `python -m unittest discover -s tests -p "test_*.py"` → **16 tests,
  OK** (9 new EACCES/capture-contract tests, 7 pre-existing). Requires
  Python ≥ 3.10 (PEP 604 annotations in upstream `heapbait.py`).

## Merge Danger

**Door:** two-way. The capture path is darwin-scoped and gated: if capture
fails (no root, libusb < 1.0.25), behavior falls back to the surfaced-error
path of part 1; Linux and Windows code paths are unchanged.

**Blast radius:** darwin users connecting MTK BROM/preloader CDC-ACM devices.
The error surface for non-root macOS users changes from a silent false-success
to a visible EACCES with actionable context (run with sudo) — intended.
