# A/B: stock driver vs stock driver + EFI unlock (2026-09-10, host .224)

Question: does the EFI unlock alone give a completely untouched system
(stock 610.43.03 open module, zero patches) full compute speed?

## Method

- Stock modules built from the pristine `cache/610.43.03.tar.gz`
  (`make modules KERNEL_UNAME=6.8.0-139-generic`, hash `221af479…`),
  swapped over the installed patched set (backed up, restored after).
- Benchmark: ProjectPhysX/OpenCL-Benchmark, one run per cell, `--device`-less
  full run on device 0. Raw outputs on the host: `~/ocl-{A,B,C,D}-*.txt`.
- Each cell is a fresh boot; `50hx_log.txt` and `dmesg` checked every time.

## Matrix

| Cell | Module | EFI | FP64 | FP32 | FP16 half2 | INT8 DP4A | Coalesc R/W | PCIe |
|---|---|---|---:|---:|---:|---:|---:|---:|
| A | patched | no | 0.463 | 14.874 | 29.390 | 48.169 | 540.6/509.5 | 1.59/1.71 (Gen2 x4) |
| B | patched | yes | — | 14.866 | 29.171 | 48.056 | ~same | 1.59/1.70 (Gen2 x4) |
| C | **stock** | no | 0.423 | **0.427** | 26.923 | **1.689** | 504.4/471.8 | 0.79/0.85 (**Gen1**) |
| D | **stock** | **yes** | 0.420 | **13.512** | 26.698 | **47.984** | 503.8/472.0 | 0.79/0.86 (**Gen1**) |

(TFLOP/s for FP*, TIOP/s for INT8, GB/s for memory/PCIe.)

## Results

1. **Cell D is the headline: with zero kernel patches, the EFI unlock alone
   restores full compute** — FP32 0.427 → 13.512 (31.7x), DP4A 1.689 →
   47.984 (28.4x). The stock driver booted the pre-unlocked state cleanly:
   no Xid, no GSP RPC timeout (the masked-timeout path in patch 01 is not
   needed when the state arrives pre-unlocked pre-OS).
2. Cells A vs B: the EFI path is performance-neutral on top of the patched
   module (deltas within run noise).
3. The 50HX lock profile on this driver: FFMA-FP32 and DP4A are clamped
   (~1/32, ~1/28); FP16 half2 FMA and INT32 are NOT clamped; memory
   bandwidth is not clamped.
4. Out of EFI scope, as designed: PCIe stays Gen1 without kernel patch 04
   (cells C/D), ReBAR and RT-count likewise need the module.
5. FP32 is ~10% lower with the stock module (13.5) than the patched module
   (14.9); the patched-module runs also carry Gen2. Likely clock/boost
   behavior under the module's flow — not investigated further.

Rollback: patched module restored from `~/cmp50hx-all-patched-backup-1029`,
verified by hash, dmesg marker (21 lines), and a clean P8 idle (zero Xid).
