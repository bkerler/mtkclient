# OPLUS/realme MT6789 (Helio G99) — RMX3630 unlock notes

Device: realme 10 4G (RMX3630), MT6789/MT8781V, hwcode `0x1208`, Android 14.
Firmware build on this unit: UNKNOWN (do not assume 2025-12 or any specific
EX01 build - the phone screen is dead and the build was never read from the
device). Screen is dead; phone boots to system. All work done
on Linux Mint 22.3 (kernel 7.0.0), mtkclient from `main` (2026-10).

## What blocks this device

1. **BROM is patched** — V6 generation. Carbonara and HeapBait detection
   strings are present in BROM (`Library/Exploit/carbonara.py` detects them).
   Classic BROM entry does not work.
2. **Preloader VCOM** (`22d9:0006`, "OPLUS Preloader", CDC-ACM) is reachable
   by holding 3 buttons during boot. It enumerates as `/dev/ttyACM0` and
   mtkclient can talk to it via USB bulk (NOT via the serial port — the
   kernel `cdc_acm` driver claims the interfaces and blocks libusb).
3. **OPLUS preloader drops off the bus ~150–250 ms after enumeration** unless
   the host engages quickly. This makes catching the window unreliable with
   slow polling.
4. Generic `MTK_DA_V6.bin` and even the **stock vendor DA** extracted from the
   official 14.0.0.200EX01 firmware are rejected by the preloader:
   `DAA_SIG_VERIFY_FAILED (0x7024)` — the DAA fuse keys were rotated with
   firmware updates, so the DA must match the phone's firmware generation.
5. **`DA_BR.bin`** (bootrom download agent, `IMAGES/download_agent/DA_BR.bin`
   inside the export zip) *is accepted* — DAA passes. It boots stage 2 and
   heapbait exploitation succeeds against the OPLUS DA2.
6. The OPLUS DA2 carries **its own auth layer** on top of MTK's SLA
   (`Server is not authenticated. Locked.`). It is *not* the standard MTK
   SLA (no `rnd` challenge — `CMD:SECURITY-GET-DEV-FW-INFO` returns an empty
   `dev_info`). It verifies a server-signed *security policy*
   (`cust_security_verify_sec_policy` / `oplus_security_verify_sec_policy`,
   `CMD:SECURITY-SET-FLASH-POLICY`). The policy signature can only come from
   OPLUS's auth server — this is the commercial "remote auth".

## Environment fixes that were required (Linux host)

* `snd_usb_audio` auto-claims the phone's normal-mode MIDI gadget and the
  preloader's CDC-ACM port. udev rule that unbinds drivers on appearance:

  ```
  # /etc/udev/rules.d/99-mtk-noaudio.rules
  SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTR{idVendor}=="22d9", ATTR{idProduct}=="2046", \
    RUN+="/bin/sh -c 'echo %p > /sys/bus/usb/drivers/snd-usb-audio/unbind'"
  SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTR{idVendor}=="22d9", ATTR{idProduct}=="0006", \
    RUN+="/bin/sh -c 'echo %p > /sys/bus/usb/drivers/cdc_acm/unbind'"
  ```
* `ModemManager` must be disabled (it AT-probes ttyACM).
* `0x22d9:0x2046` (RMX3630 normal-mode gadget) added to
  `mtkclient/config/usb_ids.py` so the tool doesn't crash parsing.

## Firmware

Official full OTA packages are still served from `rms01.realme.net` with
predictable names, e.g.

```
https://rms01.realme.net/sw/RMX3630export_11_14.0.0.200EX01_2024090223460108.zip
https://rms01.realme.net/sw/RMX3630export_11_14.0.0.420EX01_2025030414560165.zip
```

Contents of the export zip (IMAGES/): `preloader_k6789v1_64.bin`,
`preloader.img` (UFS), `preloader_emmc.img` (EMMC, `EMMC_BOOT` header),
`MTK_AllInOne_DA.bin` (MTK_DA_v6_2024-09-02, contains a `0x1208` section),
`download_agent/DA_BR.bin`, `libflash.1.0.0.so`, partition images.

DA sections in `MTK_AllInOne_DA.bin` for hwcode 0x1208:
DA1 @ file offset 0xBC, size 0x689FC, sig 256 B; DA2 @ 0x68AB8,
size 0x56FC8, sig 256 B; DA1 entry 0x200000, DA2 entry 0x40000000.
DA2 is 32-bit ARM (Thumb/ARM interwork), entry word `0xEA000007`.

## OPLUS DA2 auth layer (static analysis of da2_oplus.bin)

Interesting strings (file offsets in the extracted DA2):

```
0x4143a ***setup_security_env.***
0x4167f CMD:SECURITY-SET-ALLINONE-SIGNATURE
0x416b8 DA.SLA / ENABLED
0x416c7 CMD:SECURITY-GET-DEV-FW-INFO
0x416e4 CMD:SECURITY-SET-FLASH-POLICY
0x41702 CMD:OPLUS-WRITE-HASH256-ID
0x4171d CMD:OPLUS-GET-CPUID
0x43270 cust_security_get_dev_fw_info      (chip: MT6789, oplus_version MT6789_V1.1)
0x432bb cust_security_verify_sec_policy
0x44fd8 [OPLUS] hash256 64 from ofp: %s
0x45102 oplus_security_get_dev_fw_info
0x45236 [OPLUS]%s start, g_oplus_auth_status=%d buf_sz=%x
0x45268 oplus_security_verify_sec_policy
0x452ae [OPLUS] verify signature of device info.
0x45351 [OPLUS]write_old_hash256() : digest_id_offset=... 
0x4560b [OPLUS] Download authorization Ok in oplus
0x45637 [OPLUS] Download authorization Ok after sale
0x45664 [OPLUS] Download authorization error in oplus and after sale
0x42f33 Server is not authenticated. Locked.
```

`DA hash validation` / `DA hash validation OK` live in **DA1** (`cmd_boot_to`):
DA1 computes a hash over the received DA2 image and compares it before jumping
(**confirmed on device**: every attempt with a modified DA2 binary ends with
`DA Hash mismatch. Check these: 1. EMI setting cause DRAM is not stable. ...`
followed by a reset/USB disconnect). Therefore:

* the DA2 binary must be uploaded **unpatched** (hash must stay valid);
* any change to DA1 itself would break the DA1 signature accepted by the
  preloader (DAA);
* all vendor patches must be applied to the **running** DA2 in RAM after the
  heapbait exploit grants `CMD:EXP-PATCH-MEM` (see `apply_oplus_runtime_patches()`
  in `xml_lib.py`).

## Code changes (this branch)

1. `mtkclient/config/usb_ids.py` — add `0x22d9:0x2046`.
2. `xmlflash/xml_lib.py`:
   * In the heapbait path the DA2 is uploaded **unpatched** (DA1 hash check),
     and after a successful exploit `apply_oplus_runtime_patches()` patches the
     running DA2 in RAM via `CMD:EXP-PATCH-MEM`:
     - `cust_security_verify_sec_policy` → `MOV R0,#0; BX LR`
     - `oplus_security_verify_sec_policy` → self-contained stub:
       `MOV R0,#1; LDR R1,[PC,#8]; STR R0,[R1]; MOV R0,#0; BX LR` with a literal
       pointing to `g_oplus_auth_status` (= 1, "Ok in oplus")
     - `DA.SLA\0ENABLED` → `DA.SLA\0DISABLE` (in RAM; note heapbait's own
       `patch_da()` writes this patch to the FILE offset instead of the runtime
       VA - a no-op on device - so we do it with the correct VA)
   * Log the raw `get_dev_info()` payload when it lacks `rnd`
     (`unexpected payload (...)`) instead of crashing with `KeyError`.
   * In `handle_sla()`, log the device response after a failed SLA upload.
3. `xmlflash/extension/v6.py` `patch_da2()` — the same patches for the static
   binary (used by the non-exploit paths where the DA2 hash is not validated,
   e.g. carbonara boot). Offline test against the extracted DA2: 91 bytes
   patched, all functions located. **Not verified on device.**

Static analysis results (da2 from the 200EX01 AllInOne, identical code in the
DA_BR.bin DA2 except the trailing 254-byte signature trailer):

* `oplus_security_verify_sec_policy` @ VA 0x400103dc returns:
  - 0 = success (paths "Download authorization Ok in oplus/after sale",
    sets `g_oplus_auth_status` = 1/2 at global `0x4005455c`)
  - 0xE000000X = failure ("Server is not authenticated. Locked.",
    sets status = 3 at the same global)
* the CMD:SECURITY-SET-FLASH-POLICY handler wraps it via
  `cust_security_verify_sec_policy` @ 0x40007abc: `oplus_result != 0 → -1`.
  So a stub returning 0 is the correct "authorized" outcome.
* `g_oplus_auth_status` (`0x4005455c`) readers: value 4 → "authorization
  expired", 3 → "not authorized", 1/2 → authorized paths; another reader
  registers an XML command handler keyed on the status.

## What worked end-to-end (verified on the physical RMX3630)

* preloader VCOM → mtkclient USB handshake → `HW code 0x1208`,
  target config `0x5` (SBC on, **SLA off**, DAA on, mem read/write auth off,
  cmd 0xC8 not blocked) — repeated reliably once the udev unbind rules were
  installed. Entry method used on this dead-screen unit: hold the 3-button
  combo while plugging USB (empirically tuned; NOTE: on healthy-screen RMX3630
  units the community reports VolUp+VolDown goes to Recovery, and preloader is
  reached via `autoedl.exe` (ADB reboot) or Recovery → 7 taps on "Version 1.2"
  → Download Mode - see shomykohai/penumbra#151. With a dead screen and no ADB
  those alternatives are unavailable.)
* `DA_BR.bin` stage 1 upload **accepted** (no DAA error).
* Stage 2 upload + **heapbait exploit succeeded** in the earlier session
  (flaky, roughly every second attempt - USB errors during the stage-2/3
  shellcode writes; just retry. The per-attempt logs of that session were
  overwritten by later runs, so the exact rate is an estimate).
* Blocked only at the OPLUS DA2 auth gate ("Server is not authenticated.
  Locked." after a dummy SLA upload) - the runtime patches target exactly
  that gate and have NOT yet been verified on the device.

## Next steps

* Run the runtime-patch flow (unpatched DA2 → heapbait →
  `apply_oplus_runtime_patches()` → check_sla). If the DA2 still enforces auth
  from another code path, use the heapbait-enabled memory access to trace the
  branch that leads to `Server is not authenticated. Locked.` (the wrapper at
  0x40006ddc and the readers of `g_oplus_auth_status` are the first stops).
* DAA-key-generation question is open: the 200EX01 `MTK_AllInOne_DA.bin` DA1 is
  rejected with 0x7024 while the same zip's `DA_BR.bin` DA1 is accepted. Why
  the BR-class DA passes while AllInOne does not is NOT understood; "key
  rotation with firmware updates" is a hypothesis, not a verified fact.
* Firmware build of our unit is unknown; community data points:
  DekuzenOkahiro reached Carbonara→DA2 on a C.25-build unit, alexander-dev2313123
  is testing a 2710EX01 DA_BR (sha256 2e15a832b58e500505b785c1bb2817c77614b1c7475b2c84511015fa9e65d245).
  Our DA_BR.bin (200EX01) sha256:
  abee43e8abc67de86c5f4e20eb58f8665cb560fa38ce1b135aa7c0f97ca8007c.
  If DAA rejects it, pull DA_BR.bin from the export zip matching the unit's
  actual build.
* The newer firmware (14.0.0.420EX01, downloading) may ship a DA whose key
  version matches the phone's fuses — worth testing `--loader` with its
  AllInOne DA as an alternative to the heapbait path.
