# SP Flash Tool parity — scatter flashing (`ws`)

How our `ws` implementation maps onto stock SP Flash Tool v5 and v6, established
by reverse-engineering `FlashtoollibEx.dll`/`DA_PL.bin` (v5) and
`flash.dll`/`MTK_DA_V6.bin` (v6).

## Architecture

SP Flash Tool is thin; the **download agent (DA) does the flashing work**.
- **v5 (xflash DA)** — host issues the `DOWNLOAD` command (opcode `0x010001`);
  the DA builds the boot header, writes PGPT/SGPT (`[GPT_DA]`), resizes
  (`SET_DYNAMIC_PARTITION_SPACE`), unsparses (`[UNSPARSE]`), backs up/restores
  PROTECTED regions, and verifies the storage checksum.
- **v6 (XML DA)** — host sends the scatter as XML and issues `FLASH-ALL` /
  `FLASH-UPDATE`; the DA pulls each file (`CMD:DOWNLOAD-FILE`) and does
  everything above itself.

We therefore support two modes:
1. **Host-side** (default on v5/xflash): we build the GPT, wrap the preloader,
   expand sparse, back up/restore PROTECTED, and write with `WRITE_DATA`. Correct
   and validated for **eMMC + patched DA** (mtkclient's normal operating point).
2. **DA-delegated**: `--da_download` routes writes through the DA `DOWNLOAD`
   command (v5); a v6/XML DA auto-dispatches to `FLASH-ALL`/`FLASH-UPDATE`.

## Feature matrix

| Feature | Stock SPFT | Ours | Status |
|---|---|---|---|
| Scatter parse (regions, operation_type, flags) | yes | yes | ✅ tested (exact enum strings) |
| GPT build (PMBR/PGPT/SGPT, CRCs) | DA `[GPT_DA]` | host `gpt_builder` | ✅ tested (round-trips through the parser) |
| Preloader boot header (EMMC_BOOT/BRLYT) | DA | host `preloader_boot` | ✅ eMMC byte-exact vs real dump; UFS/NAND via DA only |
| Sparse images | DA `[UNSPARSE]` | host expand **or** DA (`--da_download`) | ✅ host tested; DA path needs device |
| NEEDRESIZE (grow userdata) + auto-format | DA | host (erase-block aligned) + `formatflash` | ✅ tested |
| PROTECTED/BINREGION backup + restore | DA `backup_folder`/`__NODL_` | host read→backup→restore | ✅ tested |
| Dynamic partitions (otp/flashinfo) | DA | placed from device GPT | ✅ tested |
| Per-image checksum verify | DA storage checksum | via DA `DOWNLOAD` (`--da_download`) | ⚠ needs device |
| `skip_pt_operate` / `resize_check` flags | yes | yes | ✅ tested |
| Download-Only layout-change gate | refuse if GPT changed | `da_ws_layout_matches` | ✅ tested |
| `DOWNLOAD` command (secured DAs) | yes | `cmd_download` / `--da_download` | ⚠ implemented; needs device |
| v6 `FLASH-ALL` / `FLASH-UPDATE` | yes | `xml_lib.flash_all` + resolver | ⚠ implemented; needs a v6 device |
| UFS | yes | refused (mapping unverified) | ❌ needs a real UFS scatter/device |
| NAND / NOR / COMBO (PMT, BMT, page addr) | yes | refused | ❌ out of scope (separate subsystem) |
| Secured (SBC/DAA/SLA) devices | yes (signed DA + SLA) | via mtkclient patched DA + `--da_download` | ⚠ needs device |

Legend: ✅ implemented & unit-tested · ⚠ implemented, needs on-hardware
validation · ❌ intentionally refused (safe) pending device access.

## Validation status

Everything marked ⚠/❌ requires a device class not available during
development (a v6/XML-DA phone, a UFS phone, or a secured/locked phone). The
host-side eMMC path is validated on an MT6765 (this repo's target) and by 95
unit tests. The DA-delegated commands are implemented with unit-tested wire
construction and must be validated on the corresponding hardware before being
relied on for a real flash — untested DA writes can brick.
