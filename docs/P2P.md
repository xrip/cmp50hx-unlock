# P2P between CMP 50HX cards (and RTX 20 series) — verified recipe

Issue #14 (avb80) proved working peer-to-peer CUDA access between an
RTX 2080 Ti and 3× CMP 50HX on Proxmox 7.0.14, driver 610.43.03 built
from open-gpu-kernel-modules with the cmp50hx-unlock patches plus the
aikitoria P2P patch applied on top.

Kernel command line used:

```
intel_iommu=on iommu=pt video=efifb:off pci=realloc,hpmemsize=8G,hpmmiosize=256M disable_acs_redir=<bdf-of-each-switch-port>
```

Notes:

- `pci=realloc,hpmemsize=8G` makes Linux grow the prefetchable bridge
  windows at boot — the same effect the pre-OS ReBAR activation needs
  when the firmware-assigned window is too small.
- Each GPU needs ReBAR enabled: the kernel-side patch
  `patches/cmp50hx/03-cmp50-rebar.patch` (selector 8 = 16 GiB; #47 also
  proved selector 9 = 32 GiB on 20/22 GB mods) or the pre-OS activation
  in the unlock EFI (v1.1.13+).
- Verification: `p2pBandwidthLatencyTest` (CUDA samples) must print
  `CAN Access Peer Device` for every pair.

Full thread with lspci/ReBAR output and numbers:
https://github.com/xrip/cmp50hx-unlock/issues/14
