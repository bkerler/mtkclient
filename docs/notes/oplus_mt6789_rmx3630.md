# OPLUS/realme MT6789 (Helio G99) — RMX3630 unlock notes

Device: realme 10 4G (RMX3630), MT6789/MT8781V, hwcode `0x1208`, Android 14,
security patch 2025-12. Screen is dead; phone boots to system. All work done
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

`DA hash validation` lives in **DA1** (`cmd_boot_to`): DA1 verifies the DA2
image hash before jumping. Patching the DA2 binary is therefore fine (observed
booting successfully), but any change to DA1 itself would break the DA1
signature accepted by the preloader.

## Code changes (this branch)

1. `mtkclient/config/usb_ids.py` — add `0x22d9:0x2046`.
2. `xmlflash/xml_lib.py`:
   * In the heapbait path, **pre-patch the DA2 binary with
     `xmlft.patch_da2()` before `boot_to()`** (the upstream code only patches
     through carbonara, which is blocked on this chip).
   * Log the raw `get_dev_info()` payload when it lacks `rnd`
     (`unexpected payload (...)`) instead of crashing with `KeyError`.
   * In `handle_sla()`, log the device response after a failed SLA upload.
3. `xmlflash/extension/v6.py` `patch_da2()` — new patches for the OPLUS DA2:
   * `oplus_security_verify_sec_policy` → `RET` (found via the string
     `[OPLUS] verify signature of device info`) — this is the function that
     prints `Server is not authenticated. Locked.`
   * the `g_oplus_auth_status` setter → `MOV R0, #1` (mark authorized).
   Offline test against the extracted DA2: 77 bytes patched, all functions
   located. Not yet verified on the device at the time of this commit.

## What worked end-to-end

* preloader VCOM (3-button) → mtkclient USB handshake → `HW code 0x1208`,
  target config `0x5` (SBC on, **SLA off**, DAA on, mem read/write auth off,
  cmd 0xC8 not blocked) — repeated reliably once the udev unbind rules were
  installed.
* `DA_BR.bin` stage 1 upload **accepted** (no DAA error).
* Stage 2 upload + **heapbait exploit succeeded** (flaky, ~50% of attempts —
  USB errors during the stage-2/3 shellcode writes; just retry).
* Blocked only at the OPLUS DA2 auth gate (see above) — the new patches in
  this branch target exactly that gate.

## Next steps

* Run the patched flow (`patch_da2` with the new OPLUS patches → heapbait →
  check_sla). If the DA2 still enforces auth from another code path, dump the
  `dpc`/auth decision structures via the heapbait-enabled memory access and
  locate the branch that leads to `Server is not authenticated. Locked.`
* If the policy check is done inside TEE (not the DA), fall back to glitching
  or to obtaining a remote-auth-signed policy from a paid tool and replaying
  it (the policy is per-device? — verify by comparing policies of two units).
* The newer firmware (14.0.0.420EX01) may ship a DA whose key version matches
  the phone's fuses — worth testing `--loader` with its AllInOne DA as an
  alternative to the heapbait path.
