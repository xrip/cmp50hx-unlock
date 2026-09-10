Русская версия: [README.RU.md](README.RU.md) · [20 GB guide](docs/20GB.md) · [20 GB guide (RU)](docs/20GB_RU.md)

# CMP 50HX / CMP 90HX 610.43.03 unlock guide

This repo builds and installs patched NVIDIA `610.43.03` open kernel modules
for the CMP 50HX (TU102) and the CMP 90HX (GA102). The 50HX patches are
developed and proven here; the 90HX path is a port of the rejoin16 work by
[jdowning100/cmpunlocker](https://github.com/jdowning100/cmpunlocker) (GPL-2.0),
built on the [pearlfortune/cmpunlocker](https://github.com/pearlfortune/cmpunlocker)
v0.1.28 90hx-stockflow bundle.

## One-click install

Grab the latest from [GitHub Releases](../../releases/latest) — one file
per OS, one command to unlock:

| OS | Download | Install (one command) |
|---|---|---|
| **Linux** | `cmp50hx-unlock-linux.run` | `chmod +x cmp50hx-unlock-linux.run && sudo ./cmp50hx-unlock-linux.run` |
| **Windows** | `cmp50hx-unlock-windows.zip` | unzip, right-click `50HXInstaller.exe` → *Run as administrator* → *Install* |

Both bundles ship the same UEFI compute unlock (proven live, FP32 31.7×
and DP4A 28.4× over the locked stock driver — see [A/B matrix](efi-unlock/runs/20260910-ab-stock-vs-efi.md))
plus a Gen2 PCIe unlock. **No kernel patches required.** On Windows the
installer also enables `EnableGpuFirmware=1` so the EFI state survives
into the OS driver. On Linux the one-click `.run` builds and installs the
patched kernel module automatically; it is the equivalent path but
required only if you want the patched kernel module too (the UEFI unlock
itself works with the stock module).

To build the bundles yourself: `make release` (Linux + Windows
toolchain needed — see `Makefile`). CI ships them automatically: GitHub
Actions on every `v*` tag (`.github/workflows/release.yml`), and
`.gitlab-ci.yml` does the same on GitLab — including the Release with
downloadable artifacts. The GitLab pipeline needs only ordinary Linux
docker runners (the Windows Go tools are cross-compiled with
`GOOS=windows`).



## UEFI compute unlock (working, no kernel patches needed)

[`efi-unlock/`](efi-unlock/README.md) is a port of the
[CMP40HX-Unlock](https://github.com/PZH1gdmu/CMP40HX-Unlock) v3.0.0 UEFI
application (MIT) to the 50HX. It unlocks SS0/SS1 **pre-OS** via the same
V67 canary Booter exploit as stockflow, then chainloads the Linux boot
manager with no POST in between — so the compute unlock needs **no patched
kernel module at all**.

Proven live on 2026-09-10 (host .224): the exploit fires
(`*** UNLOCKED (SS0=0x88888888 SS1=0x8) ***`), the state survives into
Linux with zero Xid, and an A/B test against the **stock, unpatched**
610.43.03 driver measured FP32 0.427 → **13.512 TFLOP/s (31.7x)** and
DP4A 1.689 → **47.984 TIOP/s (28.4x)** versus the locked baseline — the
stock driver's GSP boot accepts the pre-OS state cleanly. Full matrix in
[`efi-unlock/runs/20260910-ab-stock-vs-efi.md`](efi-unlock/runs/20260910-ab-stock-vs-efi.md).

ReBAR, Gen2, and the RT-count override remain kernel patches (see the
feature table in the directory README). Install guide, prerequisites,
verification, and rollback: [`efi-unlock/README.md`](efi-unlock/README.md).

The rest of this file is the working record for the five CMP50HX patches in
`patches/cmp50hx/`. It explains the code path, the reason for each change, the
checks that support it, and the limits of the proof. The series is for the
official NVIDIA `610.43.03` open-module source and for the tested CMP50HX PCI
identity:

| Field | Packed RM value | Linux PCI value |
| --- | ---: | ---: |
| device | `0x1E0910DE` | vendor `10de`, device `1e09` |
| NVIDIA board | `0x155410DE` | `10de:1554` |
| MSI board | `0x371F1462` | `1462:371f` |

The packed values are used by RM/GSP code. The Linux module uses the split
vendor, device, and subsystem fields. The two forms must not be mixed when a
new patch is made.

## CMP 50HX 20 GB support

Patch `01-cmp50-stockflow.patch` supports both the original 10 GB layout and
the 20 GB layout. The old patch used fixed 10 GB WPR2 addresses and could fail
with NVIDIA Booter error `0x8d` on a 20 GB card. The updated patch reads the
stock FWSEC WPR2 range for each GPU, accepts only the known `0xe00` span, and
keeps the low/high values in per-BDF state for later boot checks.

The 20 GB path was validated with four `10de:1e09` / `10de:1554` cards, each
reporting `20480 MiB`, on NVIDIA Open `610.43.03`. See the [20 GB guide](docs/20GB.md)
for the install order, checks, and host limits. The Russian guide is
[available here](docs/20GB_RU.md).

10 GB and 20 GB CMP 50HX cards may be installed together. WPR2 state is keyed
by each card's PCI bus/device address, so one card's memory geometry is never
used for another card. This mixed-size arrangement is supported by the design;
verify every card after the first cold boot.

The split is mechanical, not a new code path: patch 01 is 5 files/24 hunks,
patch 02 is 1 file/1 hunk, patch 03 is 1 file/4 hunks, and patch 04 is 1
file/3 hunks. The old monolithic patch and this ordered series produce the
same eight changed source files.

Patch 05 (`05-cmp50-auto-pstate.patch`) is **deliberately not built**. A
cold-boot A/B on 2026-08-26 proved it does not enable native idle/load
selection: it pins the card at P8 645/405 even at 100% load (about 22x less
memory bandwidth, 2.9x less compute) and breaks the idle governor, because
with it the P16 release no longer restores clocks. The file is kept on disk
for research only. Native automatic P-State selection was investigated to
completion and is not host-reachable — the enable sits behind a readiness
barrier inside signed GSP-RM — so the optional idle governor below is the
idle-power solution.

## Quick install (Ubuntu/Debian)

On a fresh Ubuntu or Debian system with a CMP 50HX (`10de:1e09`) installed:

```bash
curl -fsSL https://xrip.github.io/cmp50hx-unlock/install.sh | sudo bash
```

The installer adds the build tools, installs the NVIDIA `610.43.03` userland
from the official `.run` package, builds the patched modules for the running
kernel, installs them with a backup, blacklists `nouveau`, rebuilds and verifies
the initramfs, and runs `depmod`. It never reboots or unloads a loaded driver.
It ends with a best-effort live check of the card.

The installer also enables the `cmp50hx-gen2` boot service: the card unlocks
its PCIe speed registers by itself a few minutes after each boot, and the
service fires one Retrain Link on the upstream port then, which trains the
link to Gen2 x4. The driver's own retrain at first device open runs before
that unlock and cannot succeed. Watch it with `journalctl -u cmp50hx-gen2 -b`;
a `PASS` line means the link is at 5.0 GT/s.

When the installer prints `PASS_CMP_INITRAMFS`, reboot to load the patched
module at boot:

```bash
sudo reboot
```

Rollback: `sudo /opt/cmp50hx-unlock/install-initramfs.sh --rollback` restores
the previous initramfs; module backups are under
`/opt/cmp50hx-unlock/backups/`.

On a CMP 90HX (`10de:220d`) the card is forced explicitly (the installer
also auto-detects it when it is the only CMP card):

```bash
curl -fsSL https://xrip.github.io/cmp50hx-unlock/install.sh | sudo bash -s -- --card cmp90hx
```

The 90HX build additionally downloads the pinned pearlfortune
`v0.1.28` 90hx-stockflow bundle (SHA-256 checked) and installs the
`cmp90hx-gen2` boot service. After the reboot, wait for the service to finish
(see below), then verify:

```bash
sudo /opt/cmp50hx-unlock/cmp90hx/verify.sh    # PASS_CMP90HX_ALL_LIVE
```

Notes:

- Secure Boot must be disabled, or the unsigned module will not load (the
  installer warns).
- Tested subsystem boards are `10de:1554` and `1462:371f`; other `10de:1e09`
  boards only get a warning.
- Ubuntu, Debian, and their derivatives work; Linux Mint is tested.
- The build downloads the NVIDIA source archive and the `.run` package into
  `/opt/cmp50hx-unlock/cache`; re-runs reuse them.
- Real RT execution stays impossible; this unlocks full SM/Tensor speed, the
  16 GiB BAR1, and PCIe Gen2 (see [`docs/CMP50HX.md`](docs/CMP50HX.md)). The
  five-library user-space audit and the negative forced-compiler comparison are
  in
  [`docs/CMP50HX-SHARED-OBJECT-AUDIT.md`](docs/CMP50HX-SHARED-OBJECT-AUDIT.md).

## Optional userspace pipeline-bind patch

[`userspace-patch/`](userspace-patch/README.md) makes a private copy of the
NVIDIA 610.43.03 `libnvidia-eglcore.so` and removes the validated CMP50HX
Vulkan pipeline-bind delay. It scans and patches exactly two byte-pattern
matches, never overwrites `/usr/lib`, and includes a native ELF launcher that
uses the system loader's `--library-path` without setting `LD_LIBRARY_PATH`.
This is based on the research in [Cyridd/cmpunlocker](https://github.com/Cyridd/cmpunlocker)
and is separate from the kernel-module unlock. It does not prove an RT-core or
general shader unlock.

The separate eglcore RT-capability study is summarized in
[`docs/CMP50HX.md`](docs/CMP50HX.md#eglcore-class-and-rt-exposure-map). It maps
the exact extension records, the `RT_CORE_COUNT && profile 0x0e3595` gate,
compiler consumers, validation-only environment/profile control, RT task
priority defaults, and the read-only live enumeration. These userspace paths
are already open on the tested card except for extensions with additional
class/state conditions; none makes the SM accept the faulting ray instruction.

## Idle power: optional governor

The card idles at **62–64 W** doing nothing, and it never lowers its own
P-state request: even an explicit `min,max` range lock is resolved to the
maximum. The private NVAPI P-state control can force the card to P8 at about
**1.8 W**.

[`idle-governor/`](idle-governor/README.md) supplies that P-state request
automatically — force P8 when idle, release to P16 when work appears:

The active service is a single C ELF, `cmp-governor`. It calls NVML and the
private NVAPI entry point directly; Bash, Python, and `nvidia-smi` are not in
the runtime path.

| | Idle | Under load |
|---|---|---|
| without | 62–64 W | full clocks |
| with | **1.8 W (P8)** | full clocks, restored within one poll |

About **−61 W per idle card**. It is optional, independent of the unlock, and
keeps runtime state only (stopping it releases the forced state). Enable during
install with `--idle-governor`, or later:

```bash
sudo systemctl enable --now cmp-idle-governor
```

Trade-off: a job starting while the card is in P8 runs at the idle clock for
up to one poll interval (5 s by default, tunable). Details, measurements, and
tuning: [`idle-governor/README.md`](idle-governor/README.md).

## Tuning: optional profiles

[`tuning/`](tuning/README.md) adds `cmp-tune`, a profile-driven utility for
power limit, core/memory VF offsets and the locked core-clock range. It uses
NVML directly (via `ctypes`, no build step) because `nvidia-smi` cannot set VF
offsets.

```bash
cmp-tune list                    # profiles
cmp-tune status                  # live state + the ranges your card reports
cmp-tune show efficient          # dry run
sudo cmp-tune apply efficient
sudo cmp-tune reset
```

Profiles live in `/etc/cmp-tune.conf`; every key is optional:

```ini
[efficient]
power_w = 170
core_offset = 225
mem_offset = 1000
clock_max = 2100
```

Key behaviours:

- **Bounds come from the card.** Omit `clock_min` and the card's own minimum
  supported clock is used (omit `clock_max` and its maximum is), so a lock
  always stays inside the card's real range. Every value is validated against
  what the card reports and an out-of-range profile is refused with the exact
  limits.
- **Only CMP cards are touched** — CMP 50HX (`10de:1e09`) and CMP 90HX
  (`10de:220d`), matched by PCI ID. Any other GPU is listed and skipped.
- **Multi-GPU:** applies to every CMP card by default, `-i N` for one.
- **Composes with the idle governor:** applying a profile writes the C
  governor's clock, core offset, memory offset, and power settings to its
  systemd drop-in. The clock lock and core offset are cleared while P8 is
  forced and restored when work appears.

Settings are runtime state and clear on reboot, by design.

## CMP 90HX support

The 90HX path is architecturally different from the 50HX one and is a port of
the rejoin16 line from
[jdowning100/cmpunlocker](https://github.com/jdowning100/cmpunlocker)
(GPL-2.0), cold-boot validated there on 2026-08-16 (35-cycle apply, 5 GT/s,
compute full). It has **not** been re-validated end-to-end by this repo on
90HX hardware yet.

What it unlocks on a CMP 90HX (`10de:220d`):

| Feature | Mechanism |
|---|---|
| Full SM compute throughput (~26x FP32) | stockflow patches `0014`+`0015` from the pinned pearlfortune bundle |
| PCIe Gen2 x4 (5.0 GT/s) | rejoin16: PLM opens + kernel-context speed path + bridge retrain |
| Full gfx issue-rate bin (19x fill rate) | `GFX_SPEED_SELECT` `0x823830 = 0x4` once its PLM (`0x823b04`) is open |

JTAG (Host2Jtag) is **not** solved on GA102 (the GA100 PJTAG PLM addresses do
not apply and the GA102 PJTAG block is not publicly documented); the word
"jtag" in the patch filename refers to the PLM-open table, not a working JTAG
path.

Measured on the source project's card (`10de:220d`, subsystem `10de:1555`):
FP32 0.72 → 18.78 TFLOP/s, TF32 41.13, FP16→FP32 80.47 TFLOP/s; PCIe host
transfers 1.0 → 1.7 GB/s at Gen2 x4.

Layout and flow:

- `patches/cmp90hx/0016-…-rejoin16-pcie-jtag-plm.patch` — the kernel patch:
  a crafted-Booter single-write slot per module load plus the in-kernel Gen2
  speed-path config, gated on subsystem `10de:1555` and on all PCIe privilege
  masks being open (`0x823800 == 0xffffffff`).
- `cmp90hx/build-candidate.sh` — the vendored candidate builder; applies
  bundle `0014`+`0015` then our `0016`.
- `cmp90hx/rejoin16-apply-all.sh` (with `rejoin16-cycle.sh`,
  `retry-gen2-train.sh`, `bar0poke`) — the per-boot apply: ~35 module reload
  cycles, one privilege-mask open each, then the bridge retrain. A warm reboot
  skips the cycles when the masks are still open.
- `cmp90hx/cmp90hx-gen2.service` — systemd unit running the apply once per
  boot after `multi-user.target`. The installer enables it but never starts
  it in the install session.
- `cmp90hx/verify.sh` — read-only post-boot check ending in
  `PASS_CMP90HX_ALL_LIVE` (module resolution, PLM set, link speed on both
  ends, and the `cmpunlocker-rs` compute verify).

Build inputs are pinned and SHA-256 checked by `build.sh --card cmp90hx`: the
NVIDIA `NVIDIA-kernel-module-source-610.43.03.tar.xz` and the pearlfortune
`cmpunlocker-v0.1.28-linux-x64-90hx-stockflow.tar.gz`.

Limits and cautions:

- One build serves one card type; the installer refuses a host that has both
  a 50HX and a 90HX unless `--card` forces the choice.
- The kernel Gen2 path only runs on subsystem `10de:1555`; other `10de:220d`
  boards get a warning and keep the stock path.
- The PLM opens re-latch on every cold boot, so the service must run each
  boot (~7–8 min on a cold boot).
- If the GPU shares a PCIe switch with the boot disk or the NIC, a wedged
  PCIe endpoint can hang the whole host; keep console/power access for the
  first boots.
- Rollback: `systemctl disable --now cmp90hx-gen2`, remove
  `/etc/systemd/system/cmp90hx-gen2.service`, then restore the module
  backups as for the 50HX.

## Fresh performance results

| Path | Result |
|---|---:|
| RM issue-rate and core-count gate | `PASS_CMP50HX_ISSUE_RATE_AND_COUNTS` |
| DP4A | `2782.422981` G thread-instructions/s |
| DP2A pair | `4435.776603` G thread-instructions/s |
| FFMA | `2584.518335` G thread-instructions/s |
| FMUL + FADD | `4404.996610` G thread-instructions/s |
| FP16 Tensor WMMA | `106.819293 TFLOPS`, correct |
| OpenCL FP64 | `0.419 TFLOPS` |
| OpenCL FP32 | `13.501 TFLOPS` |
| OpenCL FP16 | `26.872 TFLOPS` |
| OpenCL INT64 | `3.479 TIOPS` |
| OpenCL INT32 | `13.055 TIOPS` |
| OpenCL INT16 | `11.398 TIOPS` |
| OpenCL INT8 | `48.272 TIOPS` |
| OpenCL coalesced read/write | `504.98 / 474.54 GB/s` |
| OpenCL misaligned read/write | `419.44 / 124.30 GB/s` |
| OpenCL PCIe send/receive | `1.70 / 1.70 GB/s` |
| OpenCL PCIe bidirectional | `1.69 GB/s` |
| Pinned CUDA PCIe H2D/D2H | `1.701960 / 1.708828 GB/s`, correct |


## Evidence rules

The guide uses these labels:

- **S — source:** directly visible in the patch and its control flow;
- **I — IDA:** a checked function, instruction, xref, or data path in the open
  TU102 GSP IDB;
- **L — live:** a result from the installed CMP50HX package or the read-only
  performance matrix;
- **A — apply/build:** the split series applies to a clean official source tree
  and produces the same changed source files as the old monolithic patch.

The IDA database is
[`gsp_tu10x_610.43.03.elf.i64`](decompil/gsp_tu10x_610.43.03.elf.i64),
binary SHA-256
`c10c2866e360154e822087957bc4269168e44f8d45922110e67fd751355806f9`.
It is the GSP firmware, not the Linux host driver. Therefore it can prove the
stock firmware control surface, but it cannot prove a C change in
`kernel-open/nvidia/*.c`. No debugger was used. IDA work used xrefs, operand
values, scoped disassembly, and decompilation; names and comments are notes,
not primary proof.

**A:** the series was dry-run and applied to the clean official archive whose
SHA-256 is
`9df87d753cd9c05aa0eedc462af9b35debb549a657136e863282f94c96ee2640`. The
builder repeats the source hash check and applies the four files in the order
shown in [`build.sh`](build.sh).

## 1. `01-cmp50-stockflow.patch`

### Purpose

This is the firmware/RM patch. It keeps the NVIDIA stock Booter and GSP-RM
flow, but adds a CMP50-only, bounded transaction around the signed Booter
image. Its useful result is the normal full SM issue-rate state. It is not an
RT-fuse unlock and it is not a host PCIe link retrain by itself.

### Files and roles

| File | Role |
| --- | --- |
| `generated/g_kernel_gsp_nvoc.h` | Stores a private copy of the stock signature and its size. |
| `kernel/gpu/gsp/kernel_gsp.c` | CMP50 gate, signature allocation/replacement, stock-signature restore, and boot-state logs. |
| `arch/turing/kernel_gsp_booter_tu102.c` | Falcon/SEC2 checks, native Booter launch, WPR/FECS readback, and cleanup. |
| `arch/turing/kernel_gsp_falcon_tu102.c` | Per-BDF exploit-mode state and a Booter-only bounded halt wait. |
| `arch/turing/kernel_gsp_tu102.c` | Retry state, fresh WPR metadata, GSP-ready checks, and the TU102 PCIe policy gate. |

### Step-by-step behavior

1. **Gate the card.** Every special path checks the packed device and one of
   the two packed subsystem IDs above. Other GPUs take the stock path.

2. **Keep a recovery copy.** During signature-memdesc creation the patch saves
   the original firmware signature in `KernelGsp::pStockSignatureData` and
   records `stockSignatureSize`. The normal allocation is changed to a fixed
   `0xFA00` backing size only for the CMP50 target.

3. **Prepare the synthetic signature.** The new buffer is first filled with
   `0x00000CBD`. Selected dwords then form the bounded Booter transaction. The
   important values are:

   | Signature offset/value | Meaning used by the patch |
   | --- | --- |
   | `0x0000 = 0x00020001`, `0x0880 = 0x344`, `0x0884 = 1` | stock-looking header and LS metadata |
   | `0xF974 = 0x00409650` | FECS feature-override protection register |
   | `0xF988 = 0x88888888`, `0xBB20 = 8` | full-speed SM selector values |
   | `0xF9A4 = 0x00409664`, `0xBB38 = 0x0040966C` | FECS SM selector addresses |
   | `0xBB4C = 0xFFFFFF8F` | final FECS protection mask |
   | `0xBB98 = 0x8E1B0`, `0xBBC8 = 0x8E110`, `0xBBF8 = 0x8E12C`, `0xBC28 = 0x8E11C` | TU102 XP3G policy writes |
   | `0xBC58/0xBCB8 = 0x1FA828/0x1FA824` | WPR2 high/low state |
   | `0xBC88/0xBCE8 = 0x8403C4` | SEC2 reset-protection register |

   The patch calls these values guards, pivots, writers, PLM, WPR2, or cleanup
   tails. Those names explain intent; they do not by themselves prove that an
   arbitrary firmware payload is safe.

4. **Use fresh WPR metadata.** `_kgspCmp50ExecuteBooterFreshMeta` allocates a
   new 4 KiB metadata page, copies the canonical WPR metadata into it, launches
   the stock `kgspExecuteBooterLoad_HAL`, copies Booter's mutations back, and
   frees the temporary page. This prevents SEC2 from reusing a stale metadata
   DMA page on the second launch.

5. **Run Booter only in exploit mode.** `kernel_gsp_falcon_tu102.c` stores the
   mode by stable bus/device index. `kgspExecuteHsFalcon_TU102` uses the longer
   `250000`-unit halt wait only when the exact CMP50 board is in exploit mode
   and the ucode is the Booter-load image. All other Falcon launches keep the
   default timeout.

6. **Check the handoff, then clean SEC2.** The Booter path requires the exact
   state before it returns success: FECS PLM `0xFFFFFF8F`, FECS selectors
   `0x88888888` and `0x00000008`, WPR2 down (`HI=0`, `LO=0x1FFFFE00`), SEC2
   reset PLM `0xFF`, and a clear mailbox. The patch can accept mailbox1 values
   `0`, `1`, or `4` only after all other checks pass. The SEC2 cleanup path waits
   for halt, checks the reset PLM, resets SEC2 once, checks both mailboxes, and
   zeroes SEC2 DMEM over `[0, 0x10000)`.

7. **Restore the stock signature when the transaction is done.**
   `kgspCmp50RebuildStockSignature` maps the original signature memdesc, clears
   it, copies back the saved stock bytes, updates WPR metadata, flushes CPU
   caches, and logs the physical address and advertised size. The saved buffer
   is freed on the normal cleanup path.

8. **Apply the GSP-side Gen2 policy at two gates.**
   `s_cmp50ApplyGen2Policy` runs after the Booter transaction and again at
   `gsp-ready`. It first requires the XP3G PLM readout to be `0xFFFFFFFF`, then
   saves the old values, writes the TU102 policy, reads every value back, and
   rolls back on a mismatch. Its checked policy includes:

   - `0x8841C` private misc Gen2 enable/value bits;
   - `0x88610` VSEC hierarchy;
   - `0x8C2C0` CYA bit 2 clear;
   - `0x8C040` link policy field `2`;
   - `0x8C1C0` link-rate field `0x40000`;
   - `0x8872C` LTSSM value `6`.

   This is only the GSP policy half. The endpoint/bridge PCI config write and
   retrain are in patch 04.

### IDA proof for the stock control surfaces

The firmware IDB gives strong evidence for the two stock surfaces that this
patch reuses:

- `pcie_apply_link_speed_policy` at `0x4CB25B8` is the stock
  `RMPcieLinkSpeed` policy routine. Scoped RISC-V disassembly shows writes to
  the mirrors `0x880A8`, `0x8841C`, `0x8C040`, `0x8C1C0`, and `0x8C2C0`.
  At `0x4CB276C` the target-speed field at `0x880A8` is set to `2`; alternate
  branches at `0x4CB28A4` and `0x4CB2D08` set `4` and `3`. The routine reads
  `0x8C040` beside the current-speed mirror `0x88088` at `0x4CB2978`.
- The TU102 SM override callback at `0x528F508` has two checked indirect
  writes. The first constructs register ID `0x9664` (`lui 9` + `addi 0x664`);
  the second loads `0x966C`. Both use the object at `Graphics+0x1200` and its
  virtual slot `+0x40`. Data xrefs at `0x5B8DE04` and `0x5B8DE0C` install this
  callback.
- `kgraphicsApplyInitOverrides_inferred` at `0x52A5840` loads the
  `Graphics+0xB08` callback slot and calls it at `0x52A5A4C` with
  `RMOverrideSmSpeedSelect`, then at `0x52A5A8C` with
  `RMOverrideSmSpeedSelect1`. The callback return is ignored on this path.
- A bounded structured instruction scan found the two expected constructions
  (`0x9664` and `0x966C`) and no `0x9670` or `0x9674` construction in this
  selected path. This is why the current patch keeps the TU102 reg-map path
  and does not port the alternate OBJFUSE writer.
- The same scoped scan found no direct stock-GSP construction of `0x8E1B0`.
  Therefore the XP3G PLM write is a CMP50 patch addition, not a claim that the
  unmodified 610.43.03 firmware already performs that write.

IDA proves the stock policy and callback wiring. It does **not** prove that the
hard-coded synthetic signature is safe or that a host build will accept it.
Those claims require the source checks, the exact runtime readback, and a
failure/rollback test.

### Live result and limits

**L:** The installed package reports full issue-rate fields and survives a cold
boot. The performance matrix records
`PASS_CMP50HX_ISSUE_RATE_AND_COUNTS`, P0 at 1905 MHz, no new NVRM/Xid/AER/PCIe
errors, and useful CUDA/Tensor throughput. See
[`artifacts/cmp50-performance-matrix-20260817/VERIFY.md`](../../../artifacts/cmp50-performance-matrix-20260817/VERIFY.md).

The result proves the tested card reached the intended compute state. It does
not prove that every word in the synthetic signature is needed on every TU102
board. The BDF gate, exact readbacks, stock-signature restore, and fail-closed
branches are therefore part of the patch, not optional cleanup.

## 2. `02-cmp50-rt-core-count.patch`

### Purpose and code path

This is a small host/RM reporting patch. In
`kgraphicsLoadStaticInfo_KERNEL`, after the normal graphics static-info copy,
it checks the exact packed CMP50 device and subsystem IDs and sets
`NV2080_CTRL_GR_INFO_INDEX_RT_CORE_COUNT` to `56`.

The change affects the value returned by RM and the host API gate. It does not
change SM decode, the RT fuse, dispatch, clocks, power, or the firmware GR
init path. In particular, “RM reports 56” must not be written as “56 physical
RT cores are executable.”

### Evidence

- **S:** one hunk, one field, one exact BDF gate; no other graphics state is
  changed.
- **I:** the open GSP IDB cannot prove this host Linux C hunk. It is the wrong
  binary for that claim, so the correct IDA result is **not applicable**, not a
  guessed firmware match.
- **L:** the verifier reports `3584` CUDA, `448` Tensor, and `56` RT cores, while
  the project’s RT tests still fail at SM decode because of the physical RT
  fuse. This is a report/API result only.

## 3. `03-cmp50-rebar.patch`

### Purpose

This patch changes the TU102 XVE ReBAR configuration early enough in the Linux
PCI probe that Linux can build a large BAR1 resource window. It does not alter
the GSP image and does not make a board with a too-small host bridge capable of
using a large aperture.

### Step-by-step behavior

1. A read-only module parameter selects the size: `0` disables the path and
   `1..8` select `128 MiB..16 GiB`; the default is `8`.
2. The exact CMP50 BDF is checked. BAR0 must be memory-mapped and at least
   `0x89000` bytes long.
3. The function maps the 4 KiB XVE page at BAR0 offset `0x88000` and reads:

   | XVE offset | Role |
   | ---: | --- |
   | `0x724` | CYA unlock register; write `0x30` |
   | `0xBBC` | ReBAR capability readback |
   | `0xDCC` | ReBAR configuration; bit 31 enables, low nibble is the selector |

4. It preserves all other configuration bits, clears the old low-nibble size,
   sets enable plus the selected size, writes CYA then CFG, and reads both back.
5. It checks `pci_rebar_get_possible_sizes()` using `BIT(selector + 6)`. If the
   XVE readback or the PCI capability mask does not support the choice, it
   restores the old CFG and CYA values and fails probe.
6. On success it enables the existing NVIDIA ReBAR resize path and logs the
   selector, capability mask, old/new values, and final BAR1 size.

The code only compares the enable and size bits for CFG readback. The CYA
read is recorded and logged, but is not independently asserted; this is a real
review point for a future hardening patch.

### Evidence and limits

- **S:** the write/verify/rollback sequence is visible in
  `kernel-open/nvidia/nv-pci.c`; this is host PCI MMIO code.
- **I:** the GSP IDB is not a proof source for this Linux PCI probe function.
  Do not cite the firmware IDA address `0x880A8` as proof of the ReBAR offsets:
  the ReBAR addresses are BAR0 `0x88000 + {0x724,0xBBC,0xDCC}`.
- **L:** the live package and host notes show `cmp50_rebar_size=8`, a 16 GiB
  BAR1, and a clean cold boot. The host firmware and bridge still have to
  provide a compatible aperture.

## 4. `04-cmp50-pcie-gen2.patch`

### Purpose

Patch 01 prepares and checks the GSP-side TU102 policy. This patch completes the
host side: it programs the PCIe endpoint and its upstream bridge, asks the
bridge to retrain, and waits for an active 5.0 GT/s link.

### Step-by-step behavior

1. `nv_cmp50hx_is_supported()` applies the exact split Linux BDF gate.
2. `nv_cmp50hx_retrain_gen2()` finds the upstream bridge and maps the first
   `0x90000` bytes of GPU BAR0.
3. Before touching PCI config space it requires the GSP policy mirror to show:

   - CYA `0x8C2C0`, bit 2 clear;
   - link config `0x8C040`, bits `[19:18] == 2`;
   - PL link rate `0x8C1C0`, speed field `0x00040000`.

   If the GSP half did not pass, the host half skips the retrain.
4. After GSP/RM starts, it records the BAR0/XVE mirrors and the endpoint and
   upstream PCIe capabilities before and after each important phase under
   `CMP50_PCIE_DIAG_V1`.
5. It writes LTSSM `6` at BAR0 `0x8872C`, reads it back, and waits 50 ms.
6. It sets `PCI_EXP_LNKCTL2_TLS_5_0GT` on both the GPU and the bridge, sets
   `PCI_EXP_LNKCTL_RL` on the bridge, and polls the GPU link status up to 20
   times at 100 ms intervals.
7. Success requires the active link status class to be at least
   `PCI_EXP_LNKSTA_CLS_5_0GB`; the driver logs `RETRAIN_PASS mode=normal`.

The tested CMP50HX path does not use a Link Disable cycle. See
`docs/CMP50HX-PCIE-LINK-DISABLE-AUDIT.md` for the live negative result.

### IDA proof and live result

**I:** `pcie_apply_link_speed_policy` at `0x4CB25B8` is the stock reason these
mirrors are plausible. Its disassembly directly writes `0x880A8`, `0x8841C`,
`0x8C040`, `0x8C1C0`, and `0x8C2C0`, and its `RMPcieLinkSpeed` xrefs drive the
same policy branches listed in the patch. The IDB shows the stock policy
surface; the Linux writes and retrain still require host-source and live proof.

**L:** the tested package reaches an active `5.0 GT/s x4` link on both endpoint
and upstream bridge, with PCIe transfer rates around `1.70--1.71 GB/s` and no
new PCIe/AER errors. See the performance matrix linked above.

The patch deliberately does not add GA100-only OPT or unrelated XP3G register
writes. The extra XP3G policy in patch 01 is guarded by exact CMP50/TU102
readback; it must not be copied to another architecture without a new IDA and
runtime proof.

## How to reuse this work

For a future CMP50HX patch, keep this order:

1. Prove the exact BDF gate in the target source and in the live host.
2. Classify the change as firmware/RM, host PCI, host reporting, or a mix.
3. In IDA, start from xrefs and operand/immediate construction. Confirm the
   call path, register owner, read/write direction, and nearby rollback or
   reset behavior. Do not use a string match as the only proof.
4. Write the smallest source change. Keep readback and rollback beside each
   write. Keep an unsupported board on the stock path.
5. Apply the patch to a clean, hash-checked source tree with `patch --dry-run`
   first. Then build and check module strings, ABI, and source markers.
6. On hardware, record the before/after register or API value, active link or
   core state, dmesg delta, and cold-boot result. A success log without a
   readback is not enough.
7. Record negative evidence too: a missing IDA writer, a read-only register, a
   physical fuse failure, or an unsupported capability is useful project data.

The package builder applies this exact order:

1. stockflow and GSP policy;
2. RM RT-count report;
3. host ReBAR setup;
4. host PCIe endpoint/bridge retrain.

See [`build.sh`](build.sh) and [`docs/CMP50HX.md`](docs/CMP50HX.md) for the
operational and runtime limits.
