# RMX3630 OPLUS DA2 — reversing blob

`da2_oplus.bin` — stage-2 download agent extracted from the realme 10 4G
(RMX3630, MT6789/Helio G99) firmware bundle. This is the binary all the
runtime-patch addresses in `docs/notes/rmx3630_session_2026-10-23.md`
refer to.

- md5:  `74d2b9f26b57ec3bc0ec04bf2b5c2d37`
- sha256: `fd3a5038518441299e6a60e94a6db43613950c028508cb522f3e3343f9947a60`
- size: 356296 bytes
- provenance: `/home/musin/firmware/extracted/IMAGES/da2_oplus.bin`
  (extracted 2026-10-23; identical copy also shipped as
  `download_agent/DA_BR.bin` stage 2 — DA1 validates the DA2 hash, so
  NEVER patch this file offline; all patches are runtime via heapbait
  `patch_mem`).

## Loading / disassembly hints

- Load base: **0x40000000** (file offset 0 == VA 0x40000000).
- Architecture: ARM32 (ARM state, prologues are `STMFD`/`PUSH`;
  some Thumb code regions exist).
- Strings are plain UTF-8-ish C strings, e.g. `sec_get_seccfg`,
  `SEC_CFG`, `[SEC] set lock state as LOCKED`, `SECCFG Anti-Clone
  Enabled`, `Security deny for [%s]`, `DA.SLA ENABLED/DISABLE`.

## Known addresses (verified in this campaign)

| VA | What |
|---|---|
| 0x40007abc | `cust_security_verify_sec_policy` (RET0 patch OK) |
| 0x400103dc | `oplus_security_verify_sec_policy` (RET0 + status global via patch_mem) |
| 0x400021a0 | WRITE-PARTITION policy deny byte-check (LDRB +3) |
| 0x4000392c | WRITE-FLASH policy deny byte-check (LDRB +3) |
| 0x400031a4 / 0x400031b0 | WRITE-FLASH handler deny BEQs |
| 0x40002e60 | WRITE-FLASH handler start |
| 0x40002034 | WRITE-PARTITION handler start |
| 0x40002598 | WRITE-PARTITIONS deny keyed on global 0x40054314 (untouched) |
| 0x4002f804 | oplus image hash-list check (RET0) |
| 0x4002fcf4 | entity-compare deny gate (BEQ->B) |
| 0x4002c800 | SEC service function containing "set lock state as LOCKED" print; print site 0x4002ceac; table-dispatched, no direct BL callers |
| 0x40034d6c | `sec_get_seccfg` — state cached in global 0x4006E9F0 |
| 0x40034ffc / 0x40035014 | SEC state writers: MOV r1,#1 / MOV r1,#2; STR @0x40035020 |
| 0x4006E9F0 | SEC lock-state global (writers store 1/2 here) |
| 0x4005455c | `g_oplus_auth_status` (patch_mem to 1 = FULL) |
| 0x40039d00 | `get_hw_sbc` (patch optional, OPLUS_SBC_PATCH=1) |
| 0x400416bf | "DA.SLA ENABLED" -> DISABLE string reference site |
| 0x400084a4 | generic "Security deny for [%s]" printer (~130 callers — do NOT patch) |

## Open reversing questions

1. Where does the post-write hang/EIO come from — SEC service pass after
   WRITE-PARTITION commit (suspect around `sec_get_seccfg` 0x40034d6c)?
2. Where does the WRITE-FLASH anti-tamper scrubber live (any exchange
   touching seccfg zeroes the area, even before data transfer)?
3. Does the SEC service restore seccfg from the oplusreserve2 copy
   (UFS offset 0x4800000) — i.e. is reserve2 the "master" it
   regenerates from?
4. Which code dispatches to the table-driven SEC service at 0x4002c800?
