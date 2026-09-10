# CMP 50HX Windows EFI unlock (efi-unlock-windows)

Windows installer for the same pre-OS compute unlock that lives in
[`../efi-unlock/`](../efi-unlock/README.md) for Linux. **One EFI binary +
one installer + one Gen2 BYOVD runtime** — no kernel patches needed
beyond the vendor driver.

Ported from [PZH1gdmu/CMP40HX-Unlock](https://github.com/PZH1gdmu/CMP40HX-Unlock)
v3.0.0 (MIT). The Go sources and the BYOVD Gen2 runtime are taken directly
from that project and renamed 40HX → 50HX; the embedded `50HXUNLK.EFI`
is the v1 build from `../efi-unlock/` (TU102, hash `68372b03…`,
proven live on .224).

## What it does

1. **EFI unlock** (pre-OS, on every boot): writes the EFI to
   `\EFI\50HX\50HXUNLK.EFI` (BCD path) and `\EFI\Boot\bootx64.efi`
   (firmware fallback path), backs up any existing bootx64.efi to
   `bootx64.efi.50hx.bak`, creates the `50HX Unlock` UEFI boot entry,
   and — on every login — chains it first in BootOrder.
2. **Gen2 PCIe** (BYOVD at logon, with a scheduled task for resilience):
   loads two pre-signed drivers (`WinRing0x64.sys` for PCI config,
   `ThrottleStop.sys` for arbitrary physical memory), writes the
   protected PCIe policy registers on the 50HX, sets TLS=5 GT/s on GPU
   and root port, and retrains. Drivers uninstall when done by
   default (cleanest for games / anti-cheat); a resident-guardian mode
   re-checks every minute.
3. **Uninstall** removes everything (boot entry, EFI binary,
   backup, registry, drivers, scheduled tasks, ProgramData cache).

The installer runs entirely from the host, requires no internet, takes
~1 minute for the default install path, and the first-time success
prints a clean "GSP enabled" / "Unlock EFI deployed" / "PCIe Gen2 trained"
sequence.

## Prerequisite firmware settings

All required, like the 40HX tool:

| Setting | Value | Why |
|---|---|---|
| Above 4G Decoding | Enabled | payload buffers live >4 GB |
| Secure Boot | Disabled | the EFI is unsigned |
| CSM | Disabled (pure UEFI) | so the firmware sees the boot entry |
| Fast Boot | Disabled | otherwise the UEFI step is skipped |
| Resizable BAR | Auto/Enabled | complements Above 4G |

## Build (on Windows, MSYS2/Ubuntu, or any Go-capable shell)

The Go toolchain cross-compiles trivially; the binary is a static Windows
PE that needs no runtime. From `tools/winres_gen/` first (one-shot:

```bat
go run . -o tools/inst50hx/rsrc_windows_amd64.syso
```

Then build all three tools:

```bat
cd tools\inst50hx    && go build -a -trimpath -ldflags="-H=windowsgui -s -w" -o 50HXInstaller.exe   . && cd ..\..
cd tools\uninstall50x && go build -a -trimpath -ldflags="-H=windowsgui -s -w" -o 50HXUninstaller.exe . && cd ..\..
cd tools\check50x     && go build -a -trimpath -ldflags="-H=windowsgui -s -w" -o 50HXCheck.exe       . && cd ..\..
```

PowerShell one-shot:

```powershell
.\build.ps1
```

## Install

Run `50HXInstaller.exe` as Administrator (or right-click → "Run as
administrator"). The GUI shows three sections and pre-selects everything
that is not already in place; just click "Install selected components".
For a fully silent / scripted install:

```bat
50HXInstaller.exe -y
50HXInstaller.exe -silent
50HXInstaller.exe -gen2          # one-shot Gen2 retrain (called by the logon task)
50HXInstaller.exe -status        # print current state, exit
50HXInstaller.exe -uninstall     # clean removal
50HXInstaller.exe -task          # register the Gen2 logon task only
```

A reboot after first install is required (the EFI is only effective on
the next POST); subsequent boots use the `BootOrder` we set and run
unlock + chainload every time.

## Verification

After the next reboot, run `50HXCheck.exe` as Administrator. The window
shows the unlock state (Compute line: `✓ Full unlock (SS0=0x88888888)`)
and the PCIe state (line: `PCIe: Gen2 x4` = trained, `Gen1` = failed). For
an end-to-end check run `OpenCL.exe` (same as the 40HX tool's reference
benchmark) and compare to the locked baseline in
[`../efi-unlock/runs/20260910-ab-stock-vs-efi.md`](../efi-unlock/runs/20260910-ab-stock-vs-efi.md):
a fully unlocked 50HX should show ~13.5 TFLOP/s FP32, ~48 TIOP/s INT8 DP4A.

## Rollback

Either click "Uninstall" in the GUI, or:

```bat
50HXUninstaller.exe
```

That removes: the boot entry, both EFI copies and the backup, the
registry key, the logon task, the BYOVD driver service + files, and the
ProgramData cache. Reboot afterwards for the cleanest final state.

If the system becomes unbootable for any reason (extremely rare; the
installer's BootOrder writes are also written to the firmware fallback
path): boot any Windows install media, run

```bat
bcdedit /delete {<guid of 50HX Unlock>}
del \EFI\50HX /s
```

or — if even that fails — the firmware's built-in `Boot0000* Windows
Boot Manager` is untouched and always bootable.

## Repository layout

- `tools/inst50hx/` — `50HXInstaller.exe` source (installer + GUI,
  embedded `50HXUNLK.EFI` in `embed/`)
- `tools/uninstall50x/` — `50HXUninstaller.exe`
- `tools/check50x/` — `50HXCheck.exe` (read-mostly diagnostics)
- `tools/50hxcore/` — shared Go core (PCI + BAR0 access, registry,
  services, ESP mount, Defender; mirrors the 40HX `40hxcore`)
- `tools/winres_gen/` — generates `rsrc_windows_amd64.syso` for the
  Windows manifest (one-shot)
- `gen2/` — BYOVD runtime: `install_autostart.bat` (registers the
  logon task), `run_gen2.bat` (one-shot Gen2), `uninstall.bat`,
  `drivers/` (the two pre-signed `.sys` files)
- `build.ps1` — one-shot build of all four binaries

## Known caveats

- First test should be the BootNext-style "one-shot run": install with
  the GUI, observe a clean post-reboot, then promote the entry to
  first in BootOrder (the installer does the latter automatically on
  successful install).
- The Windows OpenCL benchmark numbers lag slightly behind the Linux
  EFI-only result (cell D of the matrix) — same card, ~10% lower FP32,
  mostly from clock boost + the missing Gen2 in cells C/D. With Gen2
  enabled here, expect numbers close to the patched-module row.
- Multi-GPU hosts: v1 unlocks the first `10de:1e09` the installer
  sees. Multi-card iteration is not ported from the 40HX tool yet.
- The EFI binary must match the host architecture (x64). Other 50HX
  cards with different firmware (20 GB cards) need a different FRTS
  constant — see `../efi-unlock/README.md`.

## Provenance and license

The Go sources and the BYOVD Gen2 runtime are derived from
[PZH1gdmu/CMP40HX-Unlock](https://github.com/PZH1gdmu/CMP40HX-Unlock)
(MIT, Copyright (c) 2026). That license is kept in
`tools/50hxcore/LICENSE-40HX-UNLOCK` for the runtime pieces; the EFI
binary in `tools/inst50hx/embed/` carries the same MIT notice from
the `../efi-unlock/LICENSE-40HX-UNLOCK`.
