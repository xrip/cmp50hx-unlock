# CMP 50HX UEFI compute unlock (efi-unlock)

A pre-OS UEFI application that unlocks the CMP 50HX (TU102, `10de:1e09`)
compute path — SS0/SS1 full speed — before the operating system boots.
**No kernel patches, no driver modifications, no flashing**: the unlock runs
entirely from the ESP once per boot. It is a port of the
[CMP40HX-Unlock](https://github.com/PZH1gdmu/CMP40HX-Unlock) v3.0.0
`unlock40x_v70.c` (MIT; license kept in `LICENSE-40HX-UNLOCK`) to the 50HX.

Status: **WORKING — proven live on real hardware and proven against the
stock driver** (2026-09-10). See "Proof" below.

## Proof (2026-09-10, host .224)

**One BootNext cycle unlocks the card pre-OS.** The ESP log ends with
`*** UNLOCKED (SS0=0x88888888 SS1=0x8) ***`, the SEC2 sanitize is clean,
and Linux boots through the no-POST chainload with zero Xid. The kernel
module's boot log then confirms the EFI state survived into the OS
(`POST_FWSEC_PRE_GSP_ENTRY WPR=027fee00:027fe000 FECS=ffffff8f`).

**The stock, completely unpatched driver runs at full speed on it.** The
A/B matrix (one run per cell, fresh boot each, ProjectPhysX
OpenCL-Benchmark; full record in
[`runs/20260910-ab-stock-vs-efi.md`](runs/20260910-ab-stock-vs-efi.md)):

| Cell | Driver | EFI | FP32 | INT8 DP4A | PCIe |
|---|---|---|---:|---:|---|
| A | patched | no | 14.874 | 48.169 | Gen2 x4 |
| B | patched | yes | 14.866 | 48.056 | Gen2 x4 |
| C | stock | no | 0.427 | 1.689 | Gen1 |
| D | stock | **yes** | **13.512** | **47.984** | Gen1 |

Cell D is the headline: pristine 610.43.03 with zero patches + our EFI
unlock = **FP32 31.7x and DP4A 28.4x over the locked baseline**, no Xid,
and the stock driver's GSP boot accepts the pre-OS state cleanly (the
CMP-only RPC timeout that patch 01 masks never occurs when the state
arrives pre-unlocked). The approach is therefore portable to any host that
meets the firmware prerequisites — including Windows, like the 40HX tool.

Side findings: the EFI path is performance-neutral on top of the patched
module (A vs B); the 50HX lock clamps only FP32-FMA and DP4A (FP16 half2,
INT32, and memory bandwidth are not clamped).

## What it does and does not unlock

| Feature | EFI unlock | Kernel patches |
|---|---|---|
| SM/Tensor compute (SS0/SS1) | **yes** | also yes (redundant) |
| RT-core count report (56) | no | patch 02 |
| 16 GiB BAR1 ReBAR | no | patch 03 |
| PCIe Gen2 x4 | no (stays Gen1) | patch 04 |
| Idle-power governor | no | separate tools |

The unlock is boot-time state, not a flash: it is re-applied every time the
application runs and disappears if the GPU is reset. Both paths compose
cleanly — the EFI unlock plus the patched module is the same speed as the
patched module alone.

## Mechanism

Same exploit family as the authenticated stockflow package used by the
kernel-module path (the V67 "canary", Jon Pry, *A Canary in the Crypto
Mine*, DOI 10.5281/zenodo.20916112):

1. Find the card (fast probe + bus 0–16 sweep + raw CF8 0–255 fallback;
   accepts only `10de:1e09`; X79 boards need the CF8 path).
2. Enable BAR0; optional 1 MB VBIOS dump to `\50hx_vbios.bin`.
3. Wait for GFW, seed PTIMER, allocate all payloads **above 4 GB**.
4. Build a fake GSP firmware image: dummy FW + radix-3 page table +
   `GspFwWprMeta` (fbSize 10 GB), V67 payload as the oversized signature.
5. Snapshot WPR2, kill GFW (Falcon engine reset), check SEC2 is unlocked.
6. **FWSEC fallback**: if WPR2 is down after the kill (the normal case on
   hosts whose POST runs no GPU firmware), boot the native TU102 FWSEC on
   the GSP through the generic WITH_LOADER bootloader and issue the FRTS
   command; WPR2 latches (live: `027fee00:027fe000` in ~0 ms).
7. Direct SEC2 Booter load (the TU102 image, `SIG_PROD` patched at
   `0x8700`, `FALCON_RM = 0x162000A1` = TU102 BOOT_0). The oversized
   signature trips the canary; the ROP chain opens the FECS PLM.
8. Host writes `SS0 = 0x88888888` (`0x409664`), `SS1 = 0x8`
   (`0x40966c`), sanitizes SEC2 back to cold state.
9. **Chainloads the OS with no POST in between** (Ubuntu shim first, then
   grub, systemd-boot, generic `\EFI\BOOT\bootx64.efi`; never itself) so
   the unlocked state survives into the OS. Last resort: return to
   firmware and let BDS continue BootOrder.

Differences from the 40HX v70 baseline: device `10de:1e09` only; chipId0
`0x162000A1` (NV162, confirmed live via BOOT0); WPR meta fbSize 10 GB;
native TU102 FWSEC (see extraction below; FRTS `0x27FE00000`, WPR2
`0x027fe000/0x027fee00`); FWSEC runs only when WPR2 is down; Linux
chainload ladder instead of `bootmgfw.efi`.

The Booter image, V67 payload, GSP bootloader, and SEC2 BL ucode are
byte-identical to the 40HX project's blobs (the TU102 Booter hash
`e0f0fc93…` matches the image documented in the main repo research).

## Installation

Tested end-to-end on Ubuntu 24.04 (kernel 6.8.0-139) on the .224 host.

### 0. Firmware prerequisites (all required)

- **Above 4G Decoding: on** — all exploit buffers live above 4 GB; without
  it the unlock silently fails after the BAR step.
- **Secure Boot: off** — the application is unsigned
  (`mokutil --sb-state`).
- **CSM: off** and **Fast Boot: off**.
- UEFI+GPT boot (an ESP must exist — `/boot/efi` mounted).

### 1. Build (on the target host)

```bash
sudo apt install build-essential gnu-efi
cd cmp50hx-unlock/efi-unlock
./build.sh                     # -> 50HXUNLK.EFI (~1.6 MB)
sha256sum 50HXUNLK.EFI         # record the hash you deploy
```

The script asserts every embedded blob symbol resolves (an earlier build
bug let all blobs link as address zero — see "Debugging notes").

Optional pre-flight, no GPU needed: the QEMU/OVMF rig used during the port
(hello.efi + grubx64.efi controls) still exists in `~/efitest` on .224.

### 2. Deploy to the ESP

```bash
ESP=$(findmnt -n -o SOURCE /boot/efi)      # e.g. /dev/nvme0n1p1
sudo mkdir -p /boot/efi/EFI/50HX
sudo cp 50HXUNLK.EFI /boot/efi/EFI/50HX/
sudo efibootmgr -c -d ${ESP%p*} -p ${ESP##*p} \
    -L "50HX Unlock" -l '\EFI\50HX\50HXUNLK.EFI'
```

### 3. First run — one-shot BootNext (recommended)

Test with `BootNext` so a hang or failure falls back to the normal boot
automatically (BootNext is consumed once; BootOrder is untouched):

```bash
sudo rm -f /boot/efi/50hx_log.txt
sudo efibootmgr -n XXXX        # XXXX = the 50HX Unlock entry number
sudo reboot
```

During boot a banner appears for ~1–2 s before the OS loader. After login:

```bash
sudo cat /boot/efi/50hx_log.txt | tail    # must show:
# [50HX] *** UNLOCKED (SS0=0x88888888 SS1=0x8) ***
nvidia-smi                                 # healthy, no new Xid
```

### 4. Every-boot deployment

After a successful BootNext test, promote the entry to first in BootOrder:

```bash
sudo efibootmgr -o XXXX,0000,0003,0001,0002   # your entry first,
                                              # then the previous order
```

Every boot then runs the unlock before the OS. Nothing is flashed; removing
the boot entry (below) restores the stock behavior completely.

### Rollback

```bash
sudo efibootmgr -B -b XXXX          # remove the boot entry
sudo rm -rf /boot/efi/EFI/50HX /boot/efi/50hx_log.txt /boot/efi/50hx_vbios.bin
```

A cold power cycle after removal is the cleanest final state (the unlock
itself never survives a GPU reset anyway).

## Verification checklist

- `\50hx_log.txt` ends with `*** UNLOCKED (SS0=0x88888888 SS1=0x8) ***`.
- `grep -c "NVRM: Xid" <(sudo dmesg)` is unchanged across the boot.
- Benchmark of choice. Reference points on a 10 GB card at stock clocks:
  FP32 ~13.5 TFLOP/s, DP4A ~48 TIOP/s, coalesced read ~504 GB/s (locked:
  0.43 / 1.7 / 504 — FP32 and DP4A are the clamped paths).
- With the patched module installed, its boot lines double-check the hand
  off: `POST_FWSEC_PRE_GSP_ENTRY WPR=027fee00:027fe000 FECS=ffffff8f`.

## Risks and cautions

- Same protected-path exploit class as stockflow: a failed run can leave
  the GPU wedged until a cold power cycle (never observed here — every
  failed debug run chainloaded cleanly and Linux came up with zero Xid).
- The first test on any new board should use BootNext (auto-fallback), and
  the machine should be reachable for a cold cycle.
- 10 GB cards only in this build: 20 GB cards need FRTS `0x4FFE00000` and
  matching WPR2 constants (two `#define`s; untested).
- One card per run: the application unlocks the first `10de:1e09` it
  finds; multi-GPU hosts need an iteration loop (not yet ported).
- Windows: untested on this card. The 40HX project's Windows recipe
  additionally requires `EnableGpuFirmware=1` in the driver registry.

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
| `fwsec_ga102.bin` + `_sig` | — | — | 90HX leftovers, inert |
| `sec2_ucode_vbios_49/89.bin` | 16384 | `4fe7b59af6de3b6` | dev experiments, inert |

Full hashes: `sha256sum blobs/*.bin`.

### FWSEC extraction

`extract_fwsec.py CMP50HX.90.02.60.00.1A.live.rom blobs/` walks the VBIOS
like the driver's parser (`kernel_gsp_fwsec.c`): PCI image chain -> BIT
header -> FALCON_DATA token (0x70) -> falcon ucode table -> appId `0x85`
(FWSEC_PROD) -> V2 descriptor -> code+data blob. The pointer base for this
ROM layout is `0x11000` (validated against every entry's descriptor
magic). Result: V2 geometry identical to the 40HX blob (imem `0x9a00`, SEC
`0x400..0x9a00`, dmem `0x3f0`, interface `0xe0`), only FRTS/WPR2 constants
differ for 10 GB. `fwsec_50hx_desc.json` records the full descriptor.

## Debugging notes (what it took to get here)

Retained for the next porter; all fixes are in the code with comments:

- Debian gnu-efi is ELF, not PE: link with `crt0-efi-x86_64.o` +
  `elf_x86_64_efi.lds` + `-lgnuefi -lefi`, `-fpic`, ELF blob objects.
- `objcopy` **must include `-j .reloc`** — without it the PE gets
  `RELOCS_STRIPPED` and every firmware (including OVMF) refuses to load it.
- Do **not** define `GNU_EFI_USE_MS_ABI` (the distro crt0 is SysV); drop
  the upstream `uefi_call_wrapper` direct-call override and the `EFIAPI`
  on the custom logger; wrap all ~57 direct protocol calls
  (`tools/wrap_protocol_calls.py`).
- **objcopy names binary symbols after the filename as given**: run it
  from `blobs/` with bare names, else the redefines are no-ops, every
  payload links as address zero, and every falcon runs zero-filled code.
  This was the final blocker; `build.sh` now asserts each symbol resolves.
- The log writer must open-append-close per line (a persistent handle
  produced a 0-byte log on AMI 2.3.1).
- BL/desc/aperture details verified byte-for-byte against
  `open-gpu-kernel-modules` (`s_setupLoader`, `RM_FLCN_BL_DMEM_DESC`,
  `s_vbiosPatchInterfaceData`); `TRANSCFG(4)=0x15` (COHERENT_SYSMEM |
  MEM_TYPE_PHYSICAL).

## Repository layout

- `unlock50x_v1.c` — the application (header documents every change from
  `unlock40x_v70.c`)
- `blobs/` — embedded firmware images (see table)
- `extract_fwsec.py` — FWSEC extractor (driver-parser-faithful)
- `build.sh` — Linux build with symbol assertions
- `runs/` — live experiment records (A/B matrix)
- `tools/` — porting helpers (protocol-call wrapper, brace check)
- `LICENSE-40HX-UNLOCK` — upstream MIT license
