# CMP 50HX UEFI compute unlock (efi-unlock)

A pre-OS UEFI application that unlocks the CMP 50HX (TU102, `10de:1e09`)
compute path — SS0/SS1 full speed — before Linux boots, with no patched
kernel module required for the unlock itself. It is a port of the
[CMP40HX-Unlock](https://github.com/PZH1gdmu/CMP40HX-Unlock) v3.0.0
`unlock40x_v70.c` (MIT) to the 50HX; their MIT license text is kept in
`LICENSE-40HX-UNLOCK`.

Status: **WORKING — the exploit fires end-to-end on live hardware**
(.224 host, 2026-09-10). One BootNext cycle unlocks SS0/SS1 pre-OS, the
FWSEC/WPR2 state survives the no-POST chainload into Linux, and the kernel
module boots on top with zero Xid. See "Result" below for the live evidence
and the final root cause of the debugging trail.

## Result: UNLOCKED (live, 2026-09-10)

The exploit fires end-to-end on the .224 host. ESP log ends with
`*** UNLOCKED (SS0=0x88888888 SS1=0x8) ***`, the SEC2 sanitize is clean, and
Linux boots through the no-POST chainload with zero Xid. The kernel module's
own boot log then confirms the EFI state survived into the OS:
`POST_FWSEC_PRE_GSP_ENTRY WPR=027fee00:027fe000 FECS=ffffff8f` — the driver
finds WPR2 already latched by the EFI's FWSEC and a stock-restored PLM.

The final root cause of the earlier BL halt was a build bug, not silicon:
`objcopy` derives binary symbol names from the filename **as given**, so
passing `blobs/<file>` produced `_binary_blobs_..._start` symbols while the
redefines targeted `_binary_..._start` — a no-op. Every C extern
(`v67_payload_bin`, `booter_ucode_prod`, `fwsec_50hx_prod_bin`, …) stayed
undefined, resolved to address 0 in the PE, and all payloads were copied
from zero. Every falcon ran zero-filled code (hence the instant BL halt and
the all-zero interface reads). `build.sh` now runs objcopy from `blobs/`
with a bare filename and asserts each target symbol is defined.

Debugging trail that led there (all fixes retained): `.reloc` omission,
SysV/MS-ABI wrapper+EFIAPI issues, 57 unwrapped protocol calls, the 0-byte
log writer, `TRANSCFG=0x15` (MEM_TYPE_PHYSICAL), driver-faithful BL
tag/BOOTVEC semantics, and live diagnostics (desc readback, register dumps).

## Mechanism

Same exploit family as the authenticated stockflow package used by the
kernel-module path (the V67 "canary", Jon Pry, *A Canary in the Crypto
Mine*, DOI 10.5281/zenodo.20916112):

1. Find the card (fast probe + bus 0–16 sweep + raw CF8 0–255 fallback;
   accepts only `10de:1e09`).
2. Enable BAR0; dump VBIOS to `\50hx_vbios.bin` (build flag `VBIOS_DUMP`).
3. Wait for GFW, seed PTIMER, allocate all payloads **above 4 GB**.
4. Build a fake GSP firmware image: dummy FW + radix-3 page table +
   `GspFwWprMeta` (fbSize 10 GB), V67 payload as the oversized signature.
5. Snapshot WPR2, kill GFW (Falcon engine reset), check SEC2 is unlocked.
6. **FWSEC fallback only**: if WPR2 is down after the kill, HS-boot the
   native TU102 FWSEC on the GSP (blob extracted from our board ROM). On
   the 50HX the VBIOS POST normally leaves WPR2 already up — live dmesg
   proof: `FWSEC_COMPLETE_GSP_UNTOUCHED / WPR=027fee00:027fe000` — and the
   manual boot is skipped.
7. Direct SEC2 Booter load (the TU102 image, `SIG_PROD` patched at
   `0x8700`, `FALCON_RM = 0x162000A1` = TU102 BOOT_0). The signature check
   trips the canary; the ROP chain opens the FECS PLM (`0x409650`).
8. Host writes `SS0 = 0x88888888` (`0x409664`), `SS1 = 0x8`
   (`0x40966c`), sanitizes SEC2 back to cold state.
9. **Chainloads the OS with no POST in between**: Ubuntu
   `shimx64.efi` -> `grubx64.efi` -> systemd-boot -> generic
   `\EFI\BOOT\bootx64.efi` (never itself), last resort returns to firmware
   so BDS continues BootOrder.

The unlock is boot-time state, not a flash: it is re-applied every boot
and disappears if the GPU is reset. Scope is compute only; ReBAR, PCIe
Gen2, and the RT-count override remain kernel-module patches.

## Differences from the 40HX v70 baseline

| Item | 40HX (TU106) | 50HX (this port) |
|---|---|---|
| Device ID | `10de:1f0b` / `10de:220d` | `10de:1e09` only |
| chipId0 (`FALCON_RM`) | `0x166000A1` | `0x162000A1` (NV162) |
| WPR meta fbSize | 8 GB (`0x200000000`) | 10 GB (`0x280000000`) |
| FWSEC blob | from 40HX board ROM | from `CMP50HX.90.02.60.00.1A.live.rom` |
| FRTS offset | `0x1FFE00000` | `0x27FE00000` (10 GB − 2 MB) |
| FWSEC step | always after GFW kill | only if WPR2 is down after the kill |
| Chainload | `bootmgfw.efi` (Windows) | Linux ladder (see above) |

The Booter image, V67 payload, GSP bootloader, and SEC2 BL ucode are
byte-identical to the 40HX project's blobs (the TU102 Booter hash
`e0f0fc93…` matches the image documented in the main repo research).

## Blobs (`blobs/`)

| File | Size | SHA-256 (first 16) | Source |
|---|---:|---|---|
| `v67_payload.bin` | 64000 | `de7288bcfb80c2d4` | CMP40HX-Unlock (MIT) |
| `booter_ucode_prod.bin` | 59136 | `e0f0fc93da097b5b` | = TU102 driver bindata prod image |
| `booter_ucode_dbg.bin` | 59136 | `5c92cdaf8be232f5` | CMP40HX-Unlock (MIT) |
| `gsp_rm_boot_dbg.bin` | 131072 | `fa43239bcee7b97c` | CMP40HX-Unlock (MIT) |
| `bl_gsp_tu102.bin` | 768 | `f21f1cfbb8fffa80` | = `ksec2GetBinArchiveBlUcode_TU102` |
| `fwsec_50hx_prod.bin` | 40432 | `d8981d40f66339b7` | extracted here (below) |
| `fwsec_50hx_dbg.bin` | 40432 | `82e7d56d0b589544` | extracted here |
| `fwsec_ga102.bin` + `_sig` | — | — | 90HX leftovers, kept for the fallback path |
| `sec2_ucode_vbios_49/89.bin` | 16384 | `4fe7b59af6de3b6` | dev experiments, inert |

Full hashes: `sha256sum blobs/*.bin`.

### FWSEC extraction

`extract_fwsec.py CMP50HX.90.02.60.00.1A.live.rom blobs/` walks the VBIOS
like the driver's parser (`kernel_gsp_fwsec.c`): PCI image chain -> BIT
header -> FALCON_DATA token (0x70) -> falcon ucode table -> appId `0x85`
(FWSEC_PROD) -> V2 descriptor -> code+data blob. The pointer base for this
ROM layout is `0x11000` (validated against every entry's descriptor magic).
Result: V2 geometry identical to the 40HX blob (imem `0x9a00`, SEC
`0x400..0x9a00`, dmem `0x3f0`, interface `0xe0`), only FRTS/WPR2 constants
differ for 10 GB. `fwsec_50hx_desc.json` records the full descriptor.

**20 GB cards**: the fallback FWSEC boot would need FRTS `0x4FFE00000` and
matching WPR2 constants. The primary path (WPR2 already up from POST) is
size-independent. Not tested; see the main repo 20 GB guide for the memory
geometry background.

## Build (Linux host)

```bash
sudo apt install build-essential gnu-efi
cd efi-unlock && ./build.sh        # -> 50HXUNLK.EFI
```

## Install

```bash
sudo mkdir -p /boot/efi/EFI/50HX
sudo cp 50HXUNLK.EFI /boot/efi/EFI/50HX/
sudo efibootmgr -c -d /dev/<esp-disk> -p <esp-part> \
    -L "50HX Unlock" -l '\EFI\50HX\50HXUNLK.EFI'
# then move it first in BootOrder (efibootmgr -o ...)
```

Firmware prerequisites (same class as the 40HX tool):

- **Above 4G Decoding: on** — the payload lives above 4 GB; silent failure
  without it (the AB350M F54 + ReBarDxe host already has it on).
- **Secure Boot: off** — unsigned EFI (`mokutil --sb-state`).
- **CSM: off**, **Fast Boot: off**.

Rollback: `efibootmgr -B -b <XXXX>` for the entry, remove
`/boot/efi/EFI/50HX`, plus `\50hx_log.txt` and `\50hx_vbios.bin` from the
ESP root if present.

## Verification after boot

- ESP root `\50hx_log.txt` must end with
  `*** UNLOCKED (SS0=0x88888888 SS1=0x8) ***`.
- In Linux: `nvidia-smi` healthy, no new Xid/AER; the issue-rate probe
  reports full speed; CUDA/OpenCL smoke passes.
- The application chainloads the OS directly; watch for the unlock banner
  for ~1–2 s before the loader.

## Risks and cautions

- This is the same protected-path exploit as stockflow: a failed run can
  leave the GPU wedged until a cold power cycle (WoL cycle available on
  the test host).
- The chainload-no-POST handover is proved on the 40HX project's hardware;
  our AB350M behavior (especially the return-to-BDS fallback) is untested.
  If the ladder fails and BDS re-runs POST, the unlock is simply lost —
  reboot and try again.
- First live test target: the `.224` host with the patched module
  installed (known-good). A stock-module test is a separate, later
  experiment (the CMP-only GSP RPC timeout that patch 01 masks may or may
  not appear when the state arrives pre-unlocked).
- Multi-card hosts: v1 unlocks the **first** found `10de:1e09` only. The
  `.224` host has two cards — check `50hx_log.txt` for which BDF was
  unlocked.

## Repository layout

- `unlock50x_v1.c` — the application (header documents every change from
  `unlock40x_v70.c`)
- `blobs/` — embedded firmware images (see table)
- `extract_fwsec.py` — FWSEC extractor (driver-parser-faithful)
- `build.sh` — Linux build
- `tools/check_braces.py` — balance sanity check
- `LICENSE-40HX-UNLOCK` — upstream MIT license
