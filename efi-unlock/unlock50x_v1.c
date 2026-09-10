/*
 * unlock50x_v1.c — NVIDIA CMP 50HX (TU102) compute unlock — UEFI application
 *
 * Ported from unlock40x_v70.c of the CMP40HX-Unlock project
 * (https://github.com/PZH1gdmu/CMP40HX-Unlock, MIT License, Copyright (c) 2026),
 * which itself descends from the CMP 90HX (GA102) unlock work and the V67
 * canary exploit published by Jon Pry, "A Canary in the Crypto Mine",
 * DOI 10.5281/zenodo.20916112. Their MIT license and this notice carry over.
 *
 * What this build changes relative to the 40HX v70 baseline:
 *   - target device 10de:1e09 only (CMP 50HX, TU102 = NV162);
 *   - chipId0 (FALCON_RM) 0x166000A1 -> 0x162000A1 (BOOT_0 of TU102);
 *   - fbSize in the fake WPR meta 8 GB -> 10 GB (0x280000000);
 *   - FWSEC blob: native TU102 FWSEC extracted from the board PROM dump
 *     CMP50HX.90.02.60.00.1A (see extract_fwsec.py; V2 desc geometry is
 *     identical to the 40HX blob, only FRTS/WPR2 use 10 GB values);
 *   - step [8b] runs the manual FWSEC boot only when WPR2 is down after
 *     the GFW kill: on CMP 50HX the VBIOS POST already latched WPR2
 *     (live dmesg FWSEC_COMPLETE_GSP_UNTOUCHED / WPR=027fee00:027fe000);
 *   - chainload ladder targets Linux (Ubuntu shim/grub, systemd-boot,
 *     generic \EFI\BOOT) instead of bootmgfw.efi, never chainloads itself,
 *     and falls back to returning to firmware (BDS continues BootOrder).
 *
 * Unlock protocol is unchanged (ported from open-gpu-kernel-modules
 * 610.43.03 init flow, proved on hardware by the 40HX project):
 *   find card -> BAR0 -> GFW wait + PTIMER seed -> alloc >4GB
 *   -> fake GSP fw image + radix3 + WPR meta (V67 payload as signature)
 *   -> kill GFW -> [FWSEC fallback] -> SEC2 Booter load (TU102 image,
 *   SIG_PROD patched at 0x8700) -> canary ROP opens FECS PLM
 *   -> SS0=0x88888888 / SS1=0x8 -> SEC2 sanitize -> chainload OS
 *   with no POST in between.
 *
 * Build flags: DIRECT_SEC2 RELEASE_BUILD VBIOS_DUMP (see build.sh).
 * Runtime messages keep the original Russian wording where inherited.
 */

#include <efi.h>
#include <efilib.h>
#include <efipciio.h>
#include <efiprot.h>
#include <efifs.h>
#include <efidevp.h>

/* ---- v1.50 (Linux build): gnu-efi's real uefi_call_wrapper is RESTORED. ----
 * The 40HX project overrode uefi_call_wrapper with a direct call because
 * their MSYS2/mingw toolchain builds everything ms_abi natively. On a Linux
 * ELF build that override breaks the SysV->MS-ABI switch and crashes at the
 * first protocol call (proved in QEMU/OVMF: #GP at efi_main start). The
 * stock wrapper is correct here, so the override is gone. */

/* ---- v34: log-to-file (40HX port) ---- */
#define FORCE_LOG 1
#if FORCE_LOG
#include <stdarg.h>
static EFI_FILE_PROTOCOL *u40x_log;
static EFI_GUID u40x_fs_guid = {0x0964E5B22,0x6459,0x11D2,{0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B}};
static CHAR16 u40x_wide[512];
static UINTN u40x_w2c(CHAR16 *src, char *dst, UINTN cap) {
    UINTN i = 0;
    while (src[i] && i + 1 < cap) { dst[i] = (char)src[i]; i++; }
    dst[i] = 0;
    return i;
}
/* v1.50 (Linux build): the upstream persistent-handle write produced a
 * 0-byte log on the real AMI 2.3.1 firmware while the same-boot VBIOS dump
 * (open->write->flush->close) worked. Write each line with that proven
 * pattern: open, seek to end, write, flush, close. Slower, but reliable. */
extern EFI_GUID u40x_li_guid;
static EFI_HANDLE g_IH;            /* defined with the other globals below */
static void u40x_flush(void) {
    EFI_FILE_PROTOCOL *root = NULL, *f = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    EFI_STATUS st;
    UINTN l = 0;
    char tmp[512];
    UINTN cl;
    static CHAR16 last[512];
    static BOOLEAN first = TRUE;

    while (u40x_wide[l]) l++;
    if (!l) return;
    /* skip exact duplicate lines (repeat polling would flood the log) */
    if (!first && CompareMem(last, u40x_wide, (l + 1) * sizeof(CHAR16)) == 0)
        return;
    CopyMem(last, u40x_wide, (l + 1) * sizeof(CHAR16));
    first = FALSE;

    cl = u40x_w2c(u40x_wide, tmp, sizeof(tmp));
    if (!cl) return;
    if (!BS || !g_IH) return;
    if (uefi_call_wrapper(BS->HandleProtocol, 3, g_IH, &u40x_li_guid, (void**)&li))
        return;
    if (!li || !li->DeviceHandle) return;
    if (uefi_call_wrapper(BS->HandleProtocol, 3, li->DeviceHandle, &u40x_fs_guid, (void**)&fs) || !fs)
        return;
    if (uefi_call_wrapper(fs->OpenVolume, 2, fs, &root) || !root)
        return;
    st = uefi_call_wrapper(root->Open, 5, root, &f, L"\\50hx_log.txt",
                           EFI_FILE_MODE_CREATE | EFI_FILE_MODE_READ |
                           EFI_FILE_MODE_WRITE, 0);
    if (EFI_ERROR(st) || !f) {
        uefi_call_wrapper(root->Close, 1, root);
        return;
    }
    uefi_call_wrapper(f->SetPosition, 2, f, 0xFFFFFFFFFFFFFFFFULL);
    uefi_call_wrapper(f->Write, 3, f, &cl, tmp);
    uefi_call_wrapper(f->Flush, 1, f);
    uefi_call_wrapper(f->Close, 1, f);
    uefi_call_wrapper(root->Close, 1, root);
}
extern EFI_HANDLE ImageHandle;
EFI_GUID u40x_li_guid = {0x5B1B31A1,0x9562,0x11D2,{0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B}};
static void u40x_open_log(EFI_HANDLE IH) {
    /* black-box proven method: LoadedImage -> DeviceHandle -> FS (direct
     * calls, no uefi_call_wrapper - LocateHandleBuffer hung on this board) */
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
    EFI_FILE_PROTOCOL *root = NULL, *f = NULL;
    EFI_STATUS st;
    if (!BS || !IH) return;
    st = uefi_call_wrapper(BS->HandleProtocol, 3, IH, &u40x_li_guid, (void**)&li);
    if (EFI_ERROR(st) || !li || !li->DeviceHandle) return;
    st = uefi_call_wrapper(BS->HandleProtocol, 3, li->DeviceHandle, &u40x_fs_guid, (void**)&fs);
    if (EFI_ERROR(st) || !fs) return;
    st = uefi_call_wrapper(fs->OpenVolume, 2, fs, &root);
    if (EFI_ERROR(st) || !root) return;
    uefi_call_wrapper(root->Open, 5, root, &f, L"\\50hx_log.txt",
               EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
    if (f) { uefi_call_wrapper(f->Delete, 1, f); f = NULL; }
    st = uefi_call_wrapper(root->Open, 5, root, &u40x_log, L"\\50hx_log.txt",
                    EFI_FILE_MODE_CREATE | EFI_FILE_MODE_READ |
                    EFI_FILE_MODE_WRITE, 0);
    if (EFI_ERROR(st)) u40x_log = NULL;
    uefi_call_wrapper(root->Close, 1, root);
}
/* v1.50 (Linux build): NO EFIAPI here. This is called as a plain C function
 * through the Print macro (SysV ABI on Linux ELF builds); the upstream
 * EFIAPI/ms_abi attribute comes from the MSYS2/mingw world where every
 * function is ms_abi and the attribute is a no-op. With it, the first
 * Print call reads its arguments from the wrong registers and faults. */
static void u40x_print(const CHAR16 *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    {
        UINTN w = 0;
        const CHAR16 *fptr = fmt;
        while (*fptr && w < 480) {
            if (*fptr == L'\n') {   /* EFI ConOut 需 \r\n */
                u40x_wide[w++] = L'\r';
                if (w < 480) u40x_wide[w++] = L'\n';
                fptr++;
                continue;
            }
            if (*fptr != L'%') { u40x_wide[w++] = *fptr++; continue; }
            fptr++;
            if (*fptr == L'%') { u40x_wide[w++] = L'%'; fptr++; continue; }
            int zero = 0, width = 0;
            while (*fptr == L'0' || (*fptr >= L'1' && *fptr <= L'9')) {
                if (*fptr == L'0') zero = 1; else width = width * 10 + (*fptr - L'0');
                fptr++;
            }
            int is64 = 0;
            while (*fptr == L'l') { is64 = 1; fptr++; }
            if (*fptr == L'x' || *fptr == L'X') {
                unsigned long long v = is64 ? va_arg(ap, unsigned long long)
                                            : (unsigned)va_arg(ap, unsigned int);
                CHAR16 tmp[24]; int i = 0;
                do { int d = (int)(v & 0xF); tmp[i++] = d < 10 ? L'0'+d : L'a'+d-10; v >>= 4; } while (v);
                while (i < (zero ? width : 0)) tmp[i++] = L'0';
                while (i > 0 && w < 480) u40x_wide[w++] = tmp[--i];
                fptr++;
            } else if (*fptr == L'u' || *fptr == L'd') {
                unsigned long long v = is64 ? va_arg(ap, unsigned long long)
                                            : (unsigned)va_arg(ap, unsigned int);
                CHAR16 tmp[24]; int i = 0;
                do { tmp[i++] = L'0' + (v % 10); v /= 10; } while (v);
                while (i > 0 && w < 480) u40x_wide[w++] = tmp[--i];
                fptr++;
            } else if (*fptr == L's') {
                const CHAR16 *s = va_arg(ap, const CHAR16 *);
                if (!s) s = L"(null)";
                while (*s && w < 480) u40x_wide[w++] = *s++;
                fptr++;
            } else if (*fptr == L'r') {
                unsigned long long v = va_arg(ap, unsigned long long);
                CHAR16 tmp[24]; int i = 0;
                do { int d = (int)(v & 0xF); tmp[i++] = d < 10 ? L'0'+d : L'a'+d-10; v >>= 4; } while (v);
                while (i > 0 && w < 480) u40x_wide[w++] = tmp[--i];
                fptr++;
            } else {
                u40x_wide[w++] = *fptr ? *fptr : L'?';
                if (*fptr) fptr++;
            }
        }
        u40x_wide[w] = 0;
    }
    va_end(ap);
    if (ST && ST->ConOut) uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, u40x_wide);
    u40x_flush();
}
#define Print u40x_print
#endif


/* ---- v36: crt0 replacement ----
 * gnu-efi normally has crt0-efi-x86_64.o set ST/BS/ImageHandle globals +
 * call efi_main. Our mingw chain has no crt0 -> globals were NULL ->
 * Print crashed immediately (flash-and-exit). Provide them + entry. */
extern EFI_SYSTEM_TABLE *ST;
extern EFI_BOOT_SERVICES *BS;
EFI_HANDLE ImageHandle = NULL; /* crt0 全局——我们自己提供 */

EFI_STATUS EFIAPI efi_main(EFI_HANDLE, EFI_SYSTEM_TABLE *);

EFI_STATUS EFIAPI
u40x_entry(EFI_HANDLE ImageHandle_, EFI_SYSTEM_TABLE *SystemTable_)
{
    static const CHAR16 ok1[] = L"\r\n[v37] entry OK, setting globals...\r\n";
    if (SystemTable_ && SystemTable_->ConOut)
        uefi_call_wrapper(SystemTable_->ConOut->OutputString, 2, SystemTable_->ConOut, (CHAR16*)ok1);
    ImageHandle = ImageHandle_;
    ST = SystemTable_;
    BS = SystemTable_ ? SystemTable_->BootServices : NULL;
    {
        static const CHAR16 ok2[] = L"[v37] globals set, opening log...\r\n";
        if (ST && ST->ConOut)
            uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, (CHAR16*)ok2);
    }
#if FORCE_LOG
    u40x_open_log(ImageHandle_);
#endif
    {
        static const CHAR16 ok3[] = L"[v41] log open done, calling efi_main...\r\n";
        if (ST && ST->ConOut)
            uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, (CHAR16*)ok3);
    }
    return efi_main(ImageHandle_, SystemTable_);
}

/* ==== CMP90HX/GA102 registers (BAR0 MMIO) ====
 * PLM/SS0/SS1 are the actual lock bits; the rest is referenced by the
 * unlock flow or diagnostics. Values verified against open-gpu-kernel-
 * modules GA102 regmaps. */
#define REG_FEAT_OVR_PLM       0x00409650UL   /* PLM (TU10x): 0xffffffff = open */
#define REG_FEAT_OVR_SM_SPD    0x00409664UL   /* SS0 (TU10x): 0x88888888 = full */
#define REG_FEAT_OVR_SM_SPD_1  0x0040966CUL   /* SS1 (TU10x): 0x00000008 = full */
#define REG_PCIE_FUSE_OVR       0x00823810UL
#define REG_PFB_MMU_WPR2_LO     0x001FA824UL
#define REG_PFB_MMU_WPR2_HI     0x001FA828UL
#define REG_PCIE_LINK_CTRL      0x0008C000UL
#define REG_GFW_BOOT_OK         0x00118234UL   /* 0xff == GFW booted */

#define VAL_PLM_OPEN            0xFFFFFFFFUL
#define VAL_SS0_UNLOCKED        0x88888888UL
#define VAL_SS1_UNLOCKED        0x00000008UL

/* ==== SEC2 Falcon microcontroller — hosts the signed "booter" ucode ====
 * This is where the exploit runs: we craft its IMEM/DMEM via DMA and let
 * its own signature check trip the canary bug (V67 payload). */
#define NV_PSEC_BASE            0x00840000UL
#define NV_PSEC_FBIF_BASE       0x00840600UL
#define NV_FALCON2_SEC_BASE     0x00841000UL

#define SEC2_MAILBOX0           (NV_PSEC_BASE + 0x040)
#define SEC2_MAILBOX1           (NV_PSEC_BASE + 0x044)
#define SEC2_IRQSTAT            (NV_PSEC_BASE + 0x008)
#define SEC2_IRQSCLR            (NV_PSEC_BASE + 0x004)
#define SEC2_DEBUGINFO          (NV_PSEC_BASE + 0x094)
#define SEC2_CPUCTL             (NV_PSEC_BASE + 0x100)
#define SEC2_BOOTVEC            (NV_PSEC_BASE + 0x104)
#define SEC2_DMACTL             (NV_PSEC_BASE + 0x10C)
#define SEC2_DMATRFBASE         (NV_PSEC_BASE + 0x110)
#define SEC2_DMATRFMOFFS        (NV_PSEC_BASE + 0x114)
#define SEC2_DMATRFCMD          (NV_PSEC_BASE + 0x118)
#define SEC2_DMATRFFBOFFS       (NV_PSEC_BASE + 0x11C)
#define SEC2_DMATRFBASE1        (NV_PSEC_BASE + 0x128)
#define SEC2_ENGINE             (NV_PSEC_BASE + 0x3C0)
#define SEC2_FBIF_CTL           (NV_PSEC_FBIF_BASE + 0x24)
#define SEC2_FBIF_TRANSCFG0     (NV_PSEC_FBIF_BASE + 0x00)
#define SEC2_BCR_CTRL           (NV_FALCON2_SEC_BASE + 0x668)  /* CORE_SELECT: 0=FALCON, 1=RISCV */
#define SEC2_RM                 (NV_PSEC_BASE + 0x084)  /* chipId0 (v2.24) */
/* Порты чтения/записи IMEM/DMEM (v2.17 диагностика DMA；v56 TU102 装载用) */
#define SEC2_IMEMT0             (NV_PSEC_BASE + 0x188)  /* IMEM block tag port (driver IMEMT(0)) */
#define SEC2_IMEMC0             (NV_PSEC_BASE + 0x180)
#define SEC2_IMEMD0             (NV_PSEC_BASE + 0x184)
#define SEC2_DMEMC0             (NV_PSEC_BASE + 0x1C0)
#define SEC2_DMEMD0             (NV_PSEC_BASE + 0x1C4)

/* ==== GSP Falcon registers ====
 * The kernel driver resets GSP before the SEC2 booter load:
 * Драйвер перед SEC2 booter load РЕСЕТИТ GSP (kflcnReset в _kgspBootGspRm) —
 * живой GFW из POST держит SEC2 залоченным (0xBADF5620). ENGINE (0x1103C0)
 * доступен из EFI → убиваем GFW тем же способом, что и драйвер. */
#define GSP_BASE                0x00110000UL
#define GSP_ENGINE              (GSP_BASE + 0x3C0)
#define GSP_MAILBOX0            (GSP_BASE + 0x040)
#define GSP_MAILBOX1            (GSP_BASE + 0x044)
#define SEC2_MOD_SEL            (NV_FALCON2_SEC_BASE + 0x180)
#define SEC2_BROM_CURR_UCODE_ID (NV_FALCON2_SEC_BASE + 0x198)
#define SEC2_BROM_ENGIDMASK     (NV_FALCON2_SEC_BASE + 0x19C)
#define SEC2_BROM_PARAADDR0     (NV_FALCON2_SEC_BASE + 0x210)

#define NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE   0x2   /* bit 1 */
#define NV_PFALCON_FALCON_CPUCTL_HALTED_TRUE     0x10  /* bit 4 */
#define NV_PFALCON_FALCON_ENGINE_RESET_TRUE      0x1   /* bit 0 */
#define NV_PFALCON_FALCON_DMATRFCMD_SEC_SHIFT    2
#define NV_PFALCON_FALCON_DMATRFCMD_IMEM_SHIFT   4
#define NV_PFALCON_FALCON_DMATRFCMD_WRITE_SHIFT  5
#define NV_PFALCON_FALCON_DMATRFCMD_SIZE_SHIFT   8
#define NV_PFALCON_FALCON_DMATRFCMD_CTXDMA_SHIFT 12
#define NV_PFALCON_FALCON_DMATRFCMD_SIZE_256B    6
#define NV_PFALCON_FALCON_DMATRFCMD_SET_DMTAG    0x10000
#define FLCN_BLK_ALIGNMENT                       256

#define NV_PTIMER_TIME_0        0x00009400UL
#define NV_PTIMER_TIME_1        0x00009410UL

/* ==== Boot (SEC2) ucode layout constants — ground truth from bindata ====
 *
 * v55 修正：这些几何量是 CHIP 相关的！unlock_v2 原值（imem 0x8900 @+0x100、
 * data 0x8A00/0x6200、patchLoc 0x8A10、ucodeId=3）来自 90HX GA102。40HX 是
 * TU106，驱动用 TU102 archive（kgspGetBinArchiveBooterLoadUcode_TU102），
 * nv616 booter (md5 52a65b17) 的真实几何 = 本地 610.43.03 源码
 * g_bindata_...TU102.c 的 HEADER_PROD（raw-deflate 解压 36B）：
 *   osCodeOffset=0x0   osCodeSize=0x100
 *   osDataOffset=0x8500 osDataSize=0x6200     ← 0x8500+0x6200 = 0xE700 = blob 全长（精确铺满）
 *   appCodeOffset=0x100 appCodeSize=0x8400    ← IMEM = image[0x100..0x8500)
 * PATCH_META={fuseVer=0,engineId=1,ucodeId=0xD=13}；PATCH_LOC=0x8700
 *   → hsSigDmemAddr = patchLoc - dataOffset = 0x8700-0x8500 = 0x200
 * 旧值 0x8900/0x8A00/0x6200 是 GA102 的，套在 0xE700 的 TU102 blob 上会
 * 把 DMEM 装载读到文件尾之外（0x8A00+0x6200=0xEC00 > 0xE700）——SIG 位
 * 置/DMEM 内容全错，booter 验签必败。
 */
#define BOOTER_UCODE_SIZE       0x0000E700UL   /* nv616 TU102 booter (blob 全长, md5 52a65b17) */
#define BOOTER_APP_CODE_OFFSET  0x00000100UL  /* header.appCodeOffset (imemVa/src 偏移) */
#define BOOTER_APP_CODE_SIZE    0x00008400UL  /* header.appCodeSize  (IMEM DMA 长度, TU102) */
#define BOOTER_OS_DATA_OFFSET   0x00008500UL  /* header.osDataOffset (DMEM src 偏移, TU102) */
#define BOOTER_OS_DATA_SIZE     0x00006200UL  /* header.osDataSize   (DMEM DMA 长度, TU102) */
#define BOOTER_SIG_PATCH_LOC    0x00008700UL  /* bindata PATCH_LOC（DMEM 内签名落点 = 0x200） */
#define BOOTER_HS_SIG_DMEM_ADDR 0x00000200UL  /* patchLoc(0x8700) - dataOffset(0x8500), TU102 */
#define BOOTER_UCODE_ID         13            /* PATCH_META.ucodeId (TU102 = 0xD; GA102 = 3) */
#define BOOTER_ENGINE_ID_MASK   1             /* PATCH_META.engineId */

/* ==== V67 payload — oversized "signature" that trips the canary ====
 * 0xFA00 bytes vs stock 0x1000; overflow -> ROP chain -> priv writes. */
#define V67_SIZE                0x0000FA00UL

/* ==== WPR meta (256 B) — boot argument block for the GSP bootloader ====
 * Field-for-field replica of GspFwWprMeta; geometry formulas live in
 * build_wpr_meta() further below. */
#define WPR_META_SIZE           256
#define GSP_FW_WPR_META_MAGIC   0xdc3aae21371a60b3ULL
#define GSP_FW_WPR_META_REVISION 1
#define GSP_FW_WPR_META_VERIFIED 0xa0a0a0a0a0a0a0a0ULL

typedef struct {
    UINT64 magic;
    UINT64 revision;
    UINT64 sysmemAddrOfRadix3Elf;
    UINT64 sizeOfRadix3Elf;
    UINT64 sysmemAddrOfBootloader;
    UINT64 sizeOfBootloader;
    UINT64 bootloaderCodeOffset;
    UINT64 bootloaderDataOffset;
    UINT64 bootloaderManifestOffset;
    union {
        struct { UINT64 sysmemAddrOfSignature; UINT64 sizeOfSignature; };
        struct { UINT32 gspFwHeapFreeListWprOffset; UINT32 unused0; UINT64 unused1; };
    };
    UINT64 gspFwRsvdStart;
    UINT64 nonWprHeapOffset;
    UINT64 nonWprHeapSize;
    UINT64 gspFwWprStart;
    UINT64 gspFwHeapOffset;
    UINT64 gspFwHeapSize;
    UINT64 gspFwOffset;
    UINT64 bootBinOffset;
    UINT64 frtsOffset;
    UINT64 frtsSize;
    UINT64 gspFwWprEnd;
    UINT64 fbSize;
    UINT64 vgaWorkspaceOffset;
    UINT64 vgaWorkspaceSize;
    UINT64 bootCount;
    union {
        struct {
            UINT64 partitionRpcAddr;
            UINT16 partitionRpcRequestOffset;
            UINT16 partitionRpcReplyOffset;
            UINT32 elfCodeOffset;
            UINT32 elfDataOffset;
            UINT32 elfCodeSize;
            UINT32 elfDataSize;
            UINT32 lsUcodeVersion;
        };
        struct {
            UINT32 partitionRpcPadding[4];
            UINT64 sysmemAddrOfCrashReportQueue;
            UINT32 sizeOfCrashReportQueue;
            UINT32 lsUcodeVersionPadding;
        };
    };
    UINT8  gspFwHeapVfPartitionCount;
    UINT8  flags;
    UINT8  padding[2];
    UINT32 pmuReservedSize;
    UINT64 verified;
} GspFwWprMeta;

/* radix3 */
#define RADIX_PAGE_LOG2  12
#define RADIX_PAGE_SIZE  (1ULL << RADIX_PAGE_LOG2)
#define RADIX_ENTRIES_LOG2 (RADIX_PAGE_LOG2 - 3)
#define RADIX_ENTRIES    (1ULL << RADIX_ENTRIES_LOG2)  /* 512 */

/* ==== Embedded blobs (linked by build.sh via objcopy --redefine-sym) ====
 * The extern symbol names MUST match --redefine-sym targets in build.sh,
 * otherwise references stay unresolved and the code dereferences NULL.
 * Blob provenance and extraction: see BUILDING.md. */
extern const UINT8 v67_payload_bin[];
extern const UINT8 booter_ucode_dbg[];      /* DBG (отвергается PROD-физами: 0x780009) */
extern const UINT8 booter_ucode_prod[];     /* PROD (стоковый, sig 0x303c3b1f — v2.57) */
extern const UINT8 gsp_rm_boot_dbg[];      /* BL (GspRmBoot GA102), 0x6000 */
#define GSP_RM_BOOT_SIZE  0x6000UL

/* v2.28: FWSEC ucode (извлечён из VBIOS 10de:220d через драйвер 610.43.03,
 * см. V2-27-FWSEC-CAPTURED.md): 0xEA00 = code(0xE200) + data(0x800);
 * сигнатура sig[2] (0x180, RSA3K) — выбрана fuse-версией (sigOffset=0x300). */
extern const UINT8 fwsec_ga102_bin[];
extern const UINT8 fwsec_ga102_sig[];

/* v66: 40HX (TU106) 原生 FWSEC — 提取自 40HX_board_rom.bin (2026-08-24 本机
 * PROM dump). V2 desc: code imemLoad=0x9a00 + data dmemLoad=0x3f0 连续
 * (stored=0x9df0). prod(md5 582d0377)/dbg(md5 f0e22c2c) 内容仅 sig 区不同.
 * data 段内 interface@0xe0 → DMEMMAPPER(id4)@0x360 → cmd_in@0x3b0 (size 0x40).
 * 编译时间戳 "Dec 18 2019 13:15:43". 见 research/FWSEC_40HX_EXTRACT_20260903.md */
extern const UINT8 fwsec_50hx_prod_bin[];
extern const UINT8 fwsec_50hx_dbg_bin[];

/* v2.54: SEC2 ucode из VBIOS (appid 0x49 DBG / 0x89 PROD): ucodeId=10,
 * engmask=1, imemLoad=0x4400, dmemLoad=0x8F4, pkc=0x6DC; sig[2] патчен. */
extern const UINT8 sec2_ucode_vbios_49[];
extern const UINTN sec2_ucode_vbios_49_size;
extern const UINT8 sec2_ucode_vbios_89[];
extern const UINTN sec2_ucode_vbios_89_size;

/* v70: generic falcon bootloader (sec2_bl_gp10x) — 从 OpenRM bindata
 * g_bindata_ksec2GetBinArchiveBlUcode_TU102.c 提取 (lz4/deflate 768B,
 * "works for both SEC2 and GSP"). FWSEC 是 WITH_LOADER 型 ucode
 * (kernel_gsp_fwsec.c:741 bootType=WITH_LOADER), secure code 必须由
 * generic BL 从 host 内存 DMA 拉进 secure IMEM — host 直写 secure IMEM
 * 在 v66-v69 全 scrub 已被实机证伪. 见 research/FWSEC_40HX_LOADER_20260903.md */
extern const UINT8 gsp_bl_tu102[];
#define GSP_BL_TU102_SIZE       0x00000300UL   /* image 768B = code 0x200 + data 0x100 */
#define GSP_BL_TU102_CODE_SIZE  0x00000200UL   /* blImgHeader.blCodeSize (只装 code) */
#define GSP_BL_TU102_START_TAG  0x000000FDUL   /* blStartTag (BOOTVEC = tag<<8 = 0xfd00) */

/* ==== GSP Falcon2/BROM registers + FWSEC constants (boot-rom params) ==== */
#define GSP_FALCON2_BASE        0x00111000UL   /* NV_FALCON2_GSP_BASE (GA102) */
#define GSP_BCR                 (GSP_FALCON2_BASE + 0x668)
#define GSP_BROM_PARAADDR0      (GSP_FALCON2_BASE + 0x210)
#define GSP_BROM_ENGIDMASK      (GSP_FALCON2_BASE + 0x19C)
#define GSP_BROM_CURR_UCODE_ID  (GSP_FALCON2_BASE + 0x198)
#define GSP_MOD_SEL             (GSP_FALCON2_BASE + 0x180)
#define GSP_CPUCTL              (GSP_BASE + 0x100)
#define GSP_BOOTVEC             (GSP_BASE + 0x104)
#define GSP_DMATRFBASE          (GSP_BASE + 0x110)
#define GSP_DMATRFBASE1         (GSP_BASE + 0x128)
#define GSP_DMATRFMOFFS         (GSP_BASE + 0x114)
#define GSP_DMATRFFBOFFS        (GSP_BASE + 0x11C)
#define GSP_DMATRFCMD           (GSP_BASE + 0x118)
#define GSP_FBIF_TRANSCFG0      (GSP_BASE + 0x600)
#define GSP_FBIF_CTL            (GSP_BASE + 0x624)
#define GSP_DMACTL              (GSP_BASE + 0x10C)
#define GSP_RM                  (GSP_BASE + 0x084)

#define FWSEC_SIZE              0x0000EA00UL
#define FWSEC_CODE_SIZE         0x0000E200UL   /* imemSize */
#define FWSEC_DATA_OFF          0x0000E200UL   /* dataOffset */
#define FWSEC_DMEM_SIZE         0x00000800UL   /* dmemSize */
#define FWSEC_SIG_DMEM_ADDR     0x000005A4UL   /* hsSigDmemAddr */
#define FWSEC_IFACE_OFF         0x0000001CUL   /* interfaceOffset */
#define FWSEC_UCORE_ID          9
#define FWSEC_ENGID_MASK        0x400
#define FWSEC_FRTS_OFFSET       0x27FE00000ULL /* frtsOffset (10GB FB - 2MB) */
#define FWSEC_CMD_FRTS          0x15           /* DMEM_MAPPER_V3_CMD_FRTS */
#define FWSEC_SIG_SIZE          0x180

/* ==== 40HX (TU106) FWSEC 装载常量（v66 40HX 实测；50HX blob 同几何，extract_fwsec.py 验证） ==== */
#define FW50_CODE_SIZE          0x00009A00UL   /* imemLoad */
#define FW50_DATA_OFF           0x00009A00UL   /* blob 内 data 起点 */
#define FW50_DMEM_SIZE          0x000003F0UL   /* dmemLoad */
#define FW50_BLOB_SIZE          0x00009DF0UL   /* code+data */
#define FW50_IFACE_OFF          0x000000E0UL   /* data 内 interface header */
#define FW50_MAPPER_OFF         0x00000360UL   /* DMEMMAPPER v3 (id4 entry) */
#define FW50_CMDIN_OFF          0x000003B0UL   /* cmd_in_buffer */
#define FW50_FRTS_OFFSET        0x27FE00000ULL /* frtsOffset (10GB FB；live dmesg WPR=027fee00:027fe000) */
#define FW50_WPR2_LO_UP         0x027FE000UL
#define FW50_WPR2_HI_UP         0x027FEE00UL
/* v68: 40HX FWSEC desc (V2 @0x3ec28) 真值 — Turing 是 NS+SEC 分段装载,
 * 不是 GA102 式整块 SEC=1 DMA:
 *   +0x18 imemLoad=0x9a00  +0x20 imemSecBase=0x400  +0x24 imemSecSize=0x9600
 *   +0x30 dmemLoad=0x3f0   +0x34 dmemOff=0x9a00     +0x10 iface_off=0xe0
 * image 内 code = [NS 0x0..0x400][SEC 0x400..0x9a00] 紧挨;
 * 装载到 IMEM: NS@0 (sec=0) → SEC@0x400 (sec=1), 每 256B 打 IMEMT tag
 * (TU102 驱动 s_prepareHsFalconDirect / s_imemCopyTo_TU102 同语义). */
#define FW50_NS_SIZE            0x00000400UL   /* image[0..0x400) NS 段 */
#define FW50_SEC_BASE           0x00000400UL   /* secure 段 IMEM/镜像起点 */
#define FW50_SEC_SIZE           0x00009600UL   /* image[0x400..0x9a00) SEC 段 */
#define FW50_TAG_NS             0x00000000UL   /* NS tag 起点 (目标>>8) */
#define FW50_TAG_SEC            0x00000004UL   /* SEC tag 起点 (0x400>>8) */

/* v70: WITH_LOADER 装载常量 (对照驱动 s_setupLoader/s_prepareHsFalconWithLoader)
 *   GSP IMEM 顶部装载 generic BL (tag=0xfd → BOOTVEC=0xfd00, 256B 对齐);
 *   BL DMEM DESC (RM_FLCN_BL_DMEM_DESC, 4B-align, sizeof=0x54) 拷 DMEM 0x0;
 *   ctxDma=4 → TRANSCFG(4) = GSP FBIF base(0x600) + 4*4 = 0x610 */
#define GSP_HWCFG               (GSP_BASE + 0x108)   /* NV_PFALCON_FALCON_HWCFG */
#define GSP_FBIF_TRANSCFG4      (GSP_BASE + 0x610)   /* TRANSCFG(dmaIdx=4) */
#define BL_DESC_SIZE            0x00000054UL   /* sizeof(RM_FLCN_BL_DMEM_DESC) */
#define BL_DESC_DMEM_LOAD_OFF   0x00000000UL   /* desc 拷 DMEM 偏移 (驱动硬编码 0) */
/* BL DMEM DESC 字段偏移 (4B-align u64@0x24/0x40): */
#define BL_DESC_CTXDMA          0x20
#define BL_DESC_CODEDMA_LO      0x24
#define BL_DESC_CODEDMA_HI      0x28
#define BL_DESC_NSOFF           0x2C
#define BL_DESC_NSSIZE          0x30
#define BL_DESC_SECOFF          0x34
#define BL_DESC_SECSIZE         0x38
#define BL_DESC_ENTRY           0x3C
#define BL_DESC_DATADMA_LO      0x40
#define BL_DESC_DATADMA_HI      0x44
#define BL_DESC_DATASIZE        0x48
#define BL_DESC_ARGC            0x4C
#define BL_DESC_ARGV            0x50

/* ==== Tiny hand-written RISC-V program (dev experiments only) ====
 * Writes through the SEC2 core's CSB mechanism (same primitive the V67
 * chain uses): csrrw 0x7c8 = data port, csrrw 0x7cc = address + commit.
 * Used by riscv_direct_start(); not part of the release path.
 * Прямая запись через CSB-механизм ядра SEC2 (как V67-цепочка в Linux):
 *   csrrw zero, 0x7c8, data_reg   — данные
 *   csrrw zero, 0x7cc, addr_reg   — адрес BAR0 + commit
 * Программа: PLM=0xffffffff @0x823804, SS0=0x88888888 @0x409664,
 * SS1=0x8 @0x823820, затем self-loop. 17 слов (68 байт). */
static const UINT32 own_code_67[] = {
    0xfff00513,  /* addi a0, zero, -1        x10 = 0xffffffff */
    0x7c851073,  /* csrw 0x7c8, a0           data */
    0x008245b7,  /* lui  a1, 0x824           x11 = 0x824000 */
    0xe0458593,  /* addi a1, a1, -0x7fc      x11 = 0x409650 */
    0x7cc59073,  /* csrw 0x7cc, a1           commit -> PLM = 0xffffffff */
    0x88889537,  /* lui  a0, 0x88889         x10 = 0x88889000 */
    0x88850513,  /* addi a0, a0, -0x778      x10 = 0x88888888 */
    0x7c851073,  /* csrw 0x7c8, a0 */
    0x008245b7,  /* lui  a1, 0x824 */
    0xe1c58593,  /* addi a1, a1, -0x7e4      x11 = 0x82381c */
    0x7cc59073,  /* csrw 0x7cc, a1           commit -> SS0 = 0x88888888 */
    0x00800513,  /* addi a0, zero, 8         x10 = 0x8 */
    0x7c851073,  /* csrw 0x7c8, a0 */
    0x008245b7,  /* lui  a1, 0x824 */
    0xe2058593,  /* addi a1, a1, -0x7e0      x11 = 0x40966C */
    0x7cc59073,  /* csrw 0x7cc, a1           commit -> SS1 = 0x8 */
    0x0000006f   /* j 0                       self-loop */
};

/* ==== PCI access layer: root-bridge config space + BAR0 MMIO ====
 * The firmware does NOT expose EFI_PCI_IO_PROTOCOL for a GPU that has
 * no UEFI driver bound (no GOP here), so config space is reached via
 * PCI Root Bridge IO protocols. gRb/gBus/gDev/gFn = current card;
 * gBar0Base = BAR0 base used by mmio_read32/mmio_write32.
 * EFI_PCI_IO_PROTOCOL НЕ выставляется для GPU без UEFI-драйвера (нет GOP)
 * на реальных прошивках → сканируем config space через root bridge.
 */
static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *gRb = NULL;
static UINTN gBus = 0, gDev = 0, gFn = 0;
static UINT32 gBar0Base = 0;

/* v1.50: WPR2 state captured before the GFW engine reset (step [7.6]),
 * used by step [8b] to decide whether the manual FWSEC boot is needed. */
static EFI_HANDLE g_IH = NULL;   /* real image handle under the crt0 entry */
static UINT32 g_Wpr2LoPreKill = 0;
static UINT32 g_Wpr2HiPreKill = 0;

static EFI_STATUS
pci_cfg_read(UINTN Reg, UINT32 *Out)
{
    /* BDF-адрес по спецификации UEFI: reg:12, fn:3<<12, dev:5<<15, bus:8<<20 */
    UINT64 Addr = ((UINT64)gBus << 20) | ((UINT64)gDev << 15) |
                  ((UINT64)gFn << 12) | ((UINT64)Reg & 0xFFF);
    return uefi_call_wrapper(gRb->Pci.Read, 5, gRb,
        EfiPciIoWidthUint32, Addr, 1, Out);
}

static EFI_STATUS
pci_cfg_write(UINTN Reg, UINT32 Value)
{
    UINT64 Addr = ((UINT64)gBus << 20) | ((UINT64)gDev << 15) |
                  ((UINT64)gFn << 12) | ((UINT64)Reg & 0xFFF);
    return uefi_call_wrapper(gRb->Pci.Write, 5, gRb,
        EfiPciIoWidthUint32, Addr, 1, &Value);
}

static UINT32
mmio_read32(UINTN offset)
{
    volatile UINT32 *p = (volatile UINT32 *)(UINTN)(gBar0Base + offset);
    return *p;
}
/* ---- v35: runtime VBIOS dump (branch-A prep) ---- */
#ifdef VBIOS_DUMP
static void u40x_vbios_dump(void) {
    /* v65: fs via LoadedImage->DeviceHandle (LocateHandleBuffer hangs on this
     * board — same as u40x_open_log); read via gBar0Base AFTER BAR enable.
     * NVIDIA PROM/vBIOS window: try BAR0+0x11000 (legacy), verify 55aa. */
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
    EFI_FILE_PROTOCOL *root = NULL, *f = NULL;
    EFI_STATUS st;
    UINT32 base;
    static UINT8 rom[0x100000] __attribute__((aligned(16)));
    UINTN wrote = sizeof(rom), i;
    if (!BS || !g_IH) return;
    st = uefi_call_wrapper(BS->HandleProtocol, 3, g_IH, &u40x_li_guid, (void**)&li);
    if (EFI_ERROR(st) || !li || !li->DeviceHandle) return;
    st = uefi_call_wrapper(BS->HandleProtocol, 3, li->DeviceHandle, &u40x_fs_guid, (void**)&fs);
    if (EFI_ERROR(st) || !fs) return;
    st = uefi_call_wrapper(fs->OpenVolume, 2, fs, &root);
    if (EFI_ERROR(st) || !root) return;
    uefi_call_wrapper(root->Open, 5, root, &f, L"\\50hx_vbios.bin",
               EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
    if (f) { uefi_call_wrapper(f->Delete, 1, f); f = NULL; }
    st = uefi_call_wrapper(root->Open, 5, root, &f, L"\\50hx_vbios.bin",
                    EFI_FILE_MODE_CREATE | EFI_FILE_MODE_READ |
                    EFI_FILE_MODE_WRITE, 0);
    if (EFI_ERROR(st) || !f) { Print(L"[vbios] open fail %r\n", st); uefi_call_wrapper(root->Close, 1, root); return; }
    base = gBar0Base ? gBar0Base : 0xF6000000U;
    Print(L"[vbios] dump 1MB from BAR0+0x11000 (bar=0x%x)...\n", base);
    for (i = 0; i < sizeof(rom); i += 4)
        *(UINT32*)(rom + i) = mmio_read32((base + 0x11000U + (UINT32)i) & 0xFFFFFFFFU);
    Print(L"[vbios] head=%02x%02x%02x%02x (55aa=PCI-ROM ok)\n",
          rom[0], rom[1], rom[2], rom[3]);
    uefi_call_wrapper(f->Write, 3, f, &wrote, rom);
    uefi_call_wrapper(f->Flush, 1, f);
    uefi_call_wrapper(f->Close, 1, f);
    Print(L"[vbios] dump 1MB OK -> \\50hx_vbios.bin\n");
    uefi_call_wrapper(root->Close, 1, root);
}
#endif


static void
mmio_write32(UINTN offset, UINT32 value)
{
    volatile UINT32 *p = (volatile UINT32 *)(UINTN)(gBar0Base + offset);
    *p = value;
}

static UINT32
cfg_read32(UINTN offset)
{
    UINT32 val = 0;
    if (gRb)
        pci_cfg_read(offset, &val);
    return val;
}

static void
cfg_write32(UINTN offset, UINT32 val)
{
    if (gRb)
        pci_cfg_write(offset, val);
}

/* ==== Config-space access to ARBITRARY BDF + PCIe capability helpers ====
 * Needed by the gen2 phase: retraining the link requires setting target
 * speed AND issuing Retrain Link on the UPSTREAM BRIDGE, not just GPU.
 * Нужны для phase3 референса: переобучение линка требует target speed
 * и Retrain Link на АПСТРИМ-БРИДЖЕ, не только на стороне GPU. */
static UINT32
pci_cfg_rd_bdf(UINTN bus, UINTN dev, UINTN fn, UINTN Reg)
{
    UINT32 val = 0xFFFFFFFFU;
    UINT64 Addr;
    if (!gRb) return val;
    Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
           ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
    uefi_call_wrapper(gRb->Pci.Read, 5, gRb,
        EfiPciIoWidthUint32, Addr, 1, &val);
    return val;
}

static void
pci_cfg_wr_bdf(UINTN bus, UINTN dev, UINTN fn, UINTN Reg, UINT32 v)
{
    UINT64 Addr;
    if (!gRb) return;
    Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
           ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
    uefi_call_wrapper(gRb->Pci.Write, 5, gRb,
        EfiPciIoWidthUint32, Addr, 1, &v);
}

/* ==== Multi-root-bridge support ====
 * On real HW bus 0 (home of the GPU's upstream bridge) may belong to a
 * DIFFERENT root bridge than the card's own bus; probing only gRb made
 * the bridge invisible. rb_collect() gathers up to 8 RBs; reads try
 * each until one answers non-0xFFFFFFFF, writes go to the RB index
 * recorded at discovery (a write through the wrong RB can alias
 * another device!).
 * На реальном HW шина 0 (апстрим-бридж GPU) может принадлежать ДРУГОМУ
 * RB, чем шина карты. v2.99l на реальном железе бридж не нашёлся именно
 * поэтому — find_bridge_to ходил только через gRb. */
#define V2100_RB_MAX 8
static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *gRbAll[V2100_RB_MAX];
static UINTN gRbAllN = 0;
static INTN  gBrIdx = -1;   /* индекс RB, отвечающего за шину бриджа */


/* ---- v47: dual SBR (black-box proven requirement on CMP50HX) ---- */
static void u40x_dual_sbr(UINTN bus, UINTN dev, UINTN fn)
{
    UINTN i;
    if (!gRb) return;
    for (i = 0; i < 2; i++) {
        UINT64 CB = ((UINT64)bus << 20) | ((UINT64)dev << 15) | ((UINT64)fn << 12);
        UINT64 BB = ((UINT64)(bus >= 1 ? bus - 1 : 0) << 20);
        UINT32 bctl = 0, bc = 0;
        gRb->Pci.Read(gRb, EfiPciIoWidthUint32, BB | 0x3E, 1, &bctl);
        Print(L"[sbr %d] bridge ctl before=0x%x\n", (int)i, bctl);
        bctl |= 0x40;
        gRb->Pci.Write(gRb, EfiPciIoWidthUint32, BB | 0x3E, 1, &bctl);
        gRb->Pci.Read(gRb, EfiPciIoWidthUint32, BB | 0x3E, 1, &bc);
        Print(L"[sbr %d] asserted (ctl=0x%x)\n", (int)i, bc);
        uefi_call_wrapper(BS->Stall, 1, 200000);
        bctl &= ~0x40;
        gRb->Pci.Write(gRb, EfiPciIoWidthUint32, BB | 0x3E, 1, &bctl);
        uefi_call_wrapper(BS->Stall, 1, 2000000);
        gRb->Pci.Read(gRb, EfiPciIoWidthUint32, CB, 1, &bc);
        Print(L"[sbr %d] post-reset id=0x%08x\n", (int)i, bc);
    }
}

static void
rb_collect(void)
{
    EFI_HANDLE *H = NULL;
    UINTN N = 0, i;
    EFI_STATUS st;
    if (gRbAllN) return;
    /* v43: direct BS calls (black-box proven; uefi_call_wrapper path
     * returned 0 bridges on this board) */
    st = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol, &gEfiPciRootBridgeIoProtocolGuid,
                                NULL, &N, &H);
    if (EFI_ERROR(st)) {
        Print(L"[rb] LocateHandleBuffer status=%r (N=%d)\n", st, (int)N);
        return;
    }
    Print(L"[rb] found %d root bridge handle(s)\n", (int)N);
    for (i = 0; i < N && gRbAllN < V2100_RB_MAX; i++) {
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *rb = NULL;
        st = uefi_call_wrapper(BS->HandleProtocol, 3, H[i], &gEfiPciRootBridgeIoProtocolGuid,
                                (void**)&rb);
        if (!EFI_ERROR(st) && rb)
            gRbAll[gRbAllN++] = rb;
    }
    Print(L"[rb] collected %d bridges\n", (int)gRbAllN);
}

/* чтение через первый RB, который отвечает НЕ FFFFFFFF без ошибки */
static UINT32
pci_cfg_rd_any(UINTN bus, UINTN dev, UINTN fn, UINTN Reg)
{
    UINTN i;
    for (i = 0; i < gRbAllN; i++) {
        UINT64 Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
                      ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
        UINT32 val = 0xFFFFFFFFU;
        if (!EFI_ERROR(gRbAll[i]->Pci.Read(gRbAll[i], EfiPciIoWidthUint32,
                Addr, 1, &val)) && val != 0xFFFFFFFFU)
            return val;
    }
    return 0xFFFFFFFFU;
}

/* запись по ЗАРАНЕЕ найденному индексу RB (не «первому отвечающему» —
 * запись через чужой RB может алиаситься на другое устройство!) */
static BOOLEAN
pci_cfg_wr_idx(INTN idx, UINTN bus, UINTN dev, UINTN fn, UINTN Reg, UINT32 v)
{
    UINT64 Addr;
    if (idx < 0 || (UINTN)idx >= gRbAllN) return FALSE;
    Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
           ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
    return !EFI_ERROR(uefi_call_wrapper(gRbAll[idx]->Pci.Write, 5, gRbAll[idx],
        EfiPciIoWidthUint32, Addr, 1, &v));
}

static UINT32
pci_cfg_rd_idx(INTN idx, UINTN bus, UINTN dev, UINTN fn, UINTN Reg)
{
    UINT64 Addr;
    if (idx < 0 || (UINTN)idx >= gRbAllN) return 0xFFFFFFFFU;
    Addr = ((UINT64)bus << 20) | ((UINT64)dev << 15) |
           ((UINT64)fn << 12) | ((UINT64)Reg & 0xFFF);
    {
        UINT32 val = 0xFFFFFFFFU;
        if (EFI_ERROR(uefi_call_wrapper(gRbAll[idx]->Pci.Read, 5, gRbAll[idx],
                EfiPciIoWidthUint32, Addr, 1, &val)))
            return 0xFFFFFFFFU;
        return val;
    }
}

/* найти PCI Express Capability (ID 0x10) у устройства; 0 = нет */
static UINTN
find_pcie_cap(UINTN bus, UINTN dev, UINTN fn)
{
    UINTN pos, guard = 0;
    if (pci_cfg_rd_bdf(bus, dev, fn, 0x00) == 0xFFFFFFFFU)
        return 0;
    /* v2.99i FIX: CapPtr — байт 0x07 (старший байт dword@0x04);
     * раньше брали >>8 (байт 0x05) и всегда промахивались */
    pos = (pci_cfg_rd_bdf(bus, dev, fn, 0x04) >> 24) & 0xFF;
    while (pos >= 0x40 && guard++ < 48) {
        UINT32 cdw = pci_cfg_rd_bdf(bus, dev, fn, pos & ~3U);
        UINTN off = pos & 3;
        UINTN id = (cdw >> (off * 8)) & 0xFF;
        UINTN next = (cdw >> (off * 8 + 8)) & 0xFF;
        if (id == 0x10) return pos;
        pos = next;
    }
    return 0;
}

/* найти мост, чья secondary bus == target_bus (для апстрима GPU).
 * v2.100: сканируем ВСЕ root bridges — на реальном HW шина 0 может жить
 * в другом RB, чем шина GPU (v2.99l: «бридж не нашёлся»). Индекс RB,
 * через который найден бридж, сохраняется в gBrIdx для записей phase3. */
static BOOLEAN
find_bridge_to(UINTN target_bus, UINTN *ob, UINTN *od, UINTN *of)
{
    static const struct { UINTN d, f; } cand[] = {
        {1,0}, {28,0}, {28,1}, {28,2}, {28,3},
        {28,4}, {28,5}, {28,6}, {28,7}, {2,0}, {3,0}
    };
    UINTN ri, ci, b, d, f;
    rb_collect();
    if (!gRbAllN) {
        Print(L"gen2: нет ни одного root bridge!\n");
        return FALSE;
    }
    Print(L"gen2: probe 00:01.0=%08x 00:1c.0=%08x (%d RB)\n",
          pci_cfg_rd_any(0, 1, 0, 0x00), pci_cfg_rd_any(0, 28, 0, 0x00),
          (INTN)gRbAllN);
    /* быстрые кандидаты (q35 root port 00:01.0, PCH 00:1c.x) на bus 0 */
    for (ri = 0; ri < gRbAllN; ri++)
        for (ci = 0; ci < sizeof(cand)/sizeof(cand[0]); ci++) {
            UINT64 A = ((UINT64)cand[ci].d << 15) | ((UINT64)cand[ci].f << 12);
            UINT32 dv = 0xFFFFFFFFU, ht = 0xFFFFFFFFU, br = 0xFFFFFFFFU;
            if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5, gRbAll[ri],
                    EfiPciIoWidthUint32, A, 1, &dv)) || dv == 0xFFFFFFFFU || dv == 0)
                continue;
            if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5, gRbAll[ri],
                    EfiPciIoWidthUint32, A | 0x0C, 1, &ht)) ||
                ((ht >> 16) & 0x7F) != 1)
                continue;                       /* header type 1 = мост */
            if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5, gRbAll[ri],
                    EfiPciIoWidthUint32, A | 0x18, 1, &br)) ||
                ((br >> 16) & 0xFF) != target_bus)
                continue;
            *ob = 0; *od = cand[ci].d; *of = cand[ci].f;
            gBrIdx = (INTN)ri;
            return TRUE;
        }
    /* полный скан по каждому RB */
    for (ri = 0; ri < gRbAllN; ri++)
        for (b = 0; b < 256; b++)
            for (d = 0; d < 32; d++)
                for (f = 0; f < 8; f++) {
                    UINT64 A = ((UINT64)b << 20) | ((UINT64)d << 15) |
                               ((UINT64)f << 12);
                    UINT32 dv = 0xFFFFFFFFU, ht = 0xFFFFFFFFU, br = 0xFFFFFFFFU;
                    if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5,
                            gRbAll[ri], EfiPciIoWidthUint32, A, 1, &dv)) ||
                        dv == 0xFFFFFFFFU || dv == 0)
                        continue;
                    if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5,
                            gRbAll[ri], EfiPciIoWidthUint32, A | 0x0C, 1, &ht)) ||
                        ((ht >> 16) & 0x7F) != 1)
                        continue;
                    if (EFI_ERROR(uefi_call_wrapper(gRbAll[ri]->Pci.Read, 5,
                            gRbAll[ri], EfiPciIoWidthUint32, A | 0x18, 1, &br)) ||
                        ((br >> 16) & 0xFF) != target_bus)
                        continue;
                    *ob = b; *od = d; *of = f;
                    gBrIdx = (INTN)ri;
                    return TRUE;
                }
    return FALSE;
}

/* Выделение страниц ниже 4ГБ для DMA.
 * ВАЖНО: для AllocateMaxAddress входное значение *Phys = МАКСИМАЛЬНЫЙ адрес,
 * иначе (0) → EFI_OUT_OF_RESOURCES. */
static EFI_STATUS
alloc_below_4g(UINTN Pages, EFI_PHYSICAL_ADDRESS *Phys)
{
    *Phys = 0xFFFFFFFFULL;
    return uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress,
                             EfiReservedMemoryType, Pages, Phys);
}

/* v2.62: буфер FWSEC ВЫШЕ 4ГБ — драйвер грузит с 0x110BB0000 (>4GB,
 * memdesc NV_MEMORY_CACHED). Наш ниже-4ГБ (0x7FB15000) — единственное
 * оставшееся различие с эталонным трейсом. Кандидаты 16MB-aligned,
 * фолбэк — ниже 4ГБ. */
static UINT64 cmp90_next_high_slot = 0x110000000ULL;   /* v2.63: след. своб. слот */
static EFI_STATUS
alloc_fwsec_buffer(UINTN Pages, EFI_PHYSICAL_ADDRESS *Phys)
{
    /* v2.63: ДИНАМИЧЕСКИЕ слоты — каждый вызов получает СВОЙ адрес
     * (шаг 16МБ), чтобы ВСЕ SEC-буферы (fwsec/v67/ucode/bl/wprmeta)
     * разместились выше 4ГБ. На залоченной карте ботер сам читает
     * WPR meta/V67 из sysmem — из <4ГБ чтение блокировано (exit 0x91)! */
    EFI_STATUS st;
    UINTN i;
    for (i = 0; i < 12; i++) {
        *Phys = cmp90_next_high_slot + i * 0x1000000ULL;
        st = uefi_call_wrapper(BS->AllocatePages, 4, AllocateAddress,
                               EfiReservedMemoryType, Pages, Phys);
        if (!EFI_ERROR(st)) {
            cmp90_next_high_slot = *Phys + ((UINT64)Pages << 12) + 0x1000000ULL;
            Print(L"alloc_high: OK @0x%lx (%d стр)\n", *Phys, (UINT32)Pages);
            return EFI_SUCCESS;
        }
    }
    {
        static const UINT64 cand[] = {
            0x1A0000000ULL, 0x1C0000000ULL, 0x1E0000000ULL,
        };
        for (i = 0; i < sizeof(cand)/sizeof(cand[0]); i++) {
            *Phys = cand[i];
            if (!EFI_ERROR(uefi_call_wrapper(BS->AllocatePages, 4, AllocateAddress,
                                             EfiReservedMemoryType, Pages, Phys))) {
                Print(L"alloc_high: OK (статик) @0x%lx\n", *Phys);
                return EFI_SUCCESS;
            }
        }
    }
    Print(L"alloc_high: выше 4ГБ не вышло — фолбэк ниже 4ГБ\n");
    return alloc_below_4g(Pages, Phys);
}

/* Включить MEM_EN + BUS_MASTER в command-регистре GPU.
 * У устройства без UEFI-драйвера (нет GOP) прошивка может оставить
 * command=0 → все MMIO-чтения BAR0 возвращают 0xFFFFFFFF. */
static void
enable_mem_decode(void)
{
    UINT32 cmd = cfg_read32(0x04);
    Print(L"cfg 0x04 (command) до  = 0x%08x\n", cmd);
    cfg_write32(0x04, cmd | 0x6);   /* bit1=Memory Space, bit2=Bus Master */
    cmd = cfg_read32(0x04);
    Print(L"cfg 0x04 (command) после = 0x%08x\n", cmd);
}

/* ==== Quick state snapshot + "already unlocked" check ==== */
static void
dump_regs(const CHAR16 *Tag)
{
    Print(L"%s: PLM=0x%08x SS0=0x%08x SS1=0x%08x GFW=0x%08x WPR2lo=0x%08x\n",
        Tag,
        mmio_read32(REG_FEAT_OVR_PLM),
        mmio_read32(REG_FEAT_OVR_SM_SPD),
        mmio_read32(REG_FEAT_OVR_SM_SPD_1),
        mmio_read32(REG_GFW_BOOT_OK),
        mmio_read32(REG_PFB_MMU_WPR2_LO));
}

static BOOLEAN
is_unlocked(void)
{
    return (mmio_read32(REG_FEAT_OVR_SM_SPD) == VAL_SS0_UNLOCKED &&
            mmio_read32(REG_FEAT_OVR_SM_SPD_1) == VAL_SS1_UNLOCKED);
}

/* ==== Read-only diagnostics dump (dev builds pause between sections) ====
 * Never touches file protocols here (they hang some AMI firmwares);
 * RELEASE_BUILD/EFI_AUTOTEST compile out the key waits:
 * БЕЗ файлового протокола (висит на любых прошивках с этой флешкой).
 * Только чтения, поэтапно; между секциями — ожидание клавиши. */
static void
pause_screen(EFI_SYSTEM_TABLE *ST)
{
#if defined(EFI_AUTOTEST) || defined(RELEASE_BUILD)
    Print(L"[паузы отключены]\n");
#else
    Print(L"\n[Enter] — дальше...\n");
    uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);
    WaitForSingleEvent(ST->ConIn->WaitForKey, 0);
    uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);
#endif
}

static void
diag_one(const CHAR16 *name, UINT32 addr)
{
    UINT32 v;
    Print(L"rd %s (0x%08x)...", name, addr);
    v = mmio_read32(addr);
    Print(L" = 0x%08x\n", v);
}

static void
diag_regs(EFI_SYSTEM_TABLE *ST)
{
    Print(L"\n--- DIAG v2.10 SEC2 ---\n");
    diag_one(L"SEC2_MBOX0", 0x840040);
    diag_one(L"SEC2_MBOX1", 0x840044);
    diag_one(L"SEC2_IRQSTAT", 0x840008);
    diag_one(L"SEC2_DEBUGINFO", 0x840094);
    diag_one(L"SEC2_CPUCTL", 0x840100);
    diag_one(L"SEC2_DMACTL", 0x84010c);
    diag_one(L"SEC2_DMATRFCMD", 0x840118);
    diag_one(L"SEC2_ENGINE", 0x8403c0);
    diag_one(L"SEC2_FBIF_CTL", 0x840624);
    pause_screen(ST);

    Print(L"--- DIAG v2.10 GSP (только чтения) ---\n");
    diag_one(L"GSP_MBOX0", 0x110040);
    diag_one(L"GSP_MBOX1", 0x110044);
    diag_one(L"GSP_CPUCTL", 0x110100);
    diag_one(L"GSP_ENGINE", 0x1103c0);
    diag_one(L"PGSP_MAILBOX", 0x110804);
    diag_one(L"GSP_0x110c38", 0x110c38);
    diag_one(L"GSP_0x110c3c", 0x110c3c);
    diag_one(L"PTIMER0", 0x9400);
    diag_one(L"PLM", REG_FEAT_OVR_PLM);
    diag_one(L"SS0", REG_FEAT_OVR_SM_SPD);
    diag_one(L"SS1", REG_FEAT_OVR_SM_SPD_1);
    diag_one(L"GFW", REG_GFW_BOOT_OK);
    Print(L"--- DIAG v2.10 ЗАВЕРШЕНА ---\n");
    pause_screen(ST);
}

static BOOLEAN cmp90_eqi(const CHAR16 *a, const CHAR16 *b);

#ifdef ENDGAME_WARMRESET
/* v2.90-WR: найти Boot#### с описанием "Windows Boot Manager" и выставить
 * BootNext. TRUE = переменная записана (далее ResetSystem Warm). */
static BOOLEAN set_bootnext_windows(void)
{
    static EFI_GUID gvGuid = EFI_GLOBAL_VARIABLE;
    UINT16 opt;

    Print(L"v2.90-WR: скан Boot#### (Windows Boot Manager)...\n");
    for (opt = 0; opt < 0xFFFF; opt++) {
        CHAR16 name[12];
        static UINT8 buf[2048];
        UINTN sz = sizeof(buf);
        UINT32 attr = 0;
        EFI_STATUS st;

        UnicodeSPrint(name, sizeof(name), L"Boot%04X", opt);
        st = uefi_call_wrapper(RT->GetVariable, 5, name, &gvGuid,
                               &attr, &sz, buf);
        /* v2.99o: прогресс каждые 256 слотов — видно, где застряли */
        if ((opt & 0xFF) == 0)
            Print(L"v2.90-WR: скан %04X...\n", opt);
        if (EFI_ERROR(st) || sz < 6) continue;
        {
            /* EFI_LOAD_OPTION: u32 Attributes, u16 FilePathListLength,
             * Description (CHAR16, NUL-терминированная) */
            CHAR16 *desc = (CHAR16 *)(buf + 6);
            if (cmp90_eqi(desc, L"Windows Boot Manager")) {
                Print(L"v2.90-WR: найден Boot%04X, пишу BootNext...\n", opt);
                st = uefi_call_wrapper(RT->SetVariable, 6, L"BootNext", &gvGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS, 2, &opt);
                Print(L"v2.90-WR: Boot%04X = Windows Boot Manager; BootNext: %r\n",
                      opt, st);
                return !EFI_ERROR(st);
            }
        }
    }
    Print(L"v2.90-WR: Boot#### с Windows Boot Manager не найден\n");
    return FALSE;
}
#endif

/* ==== MULTI-CARD: unlock several 220d cards without rebooting ====
 * Each app run unlocks ITS card (index in an NVRAM variable), sets
 * BootNext to its own Boot#### entry and returns to firmware — no POST
 * happens, the unlock survives, firmware re-runs us from USB for the
 * next card. Last iteration clears variables and lets Windows boot.
 * Scans every root bridge / bus 0..255 so slot width does not matter.
 * Каждая итерация приложения анлочит СВОЮ карту (индекс в NVRAM), затем
 * BootNext -> собственная Boot####-запись -> возврат в прошивку БЕЗ
 * перезагрузки (POST не происходит, анлок живёт) -> прошивка снова запускает
 * нас с флешки за следующей картой. Последняя итерация чистит переменные и
 * chainload'ит Windows как обычно. Работает через любые линии (x16/x4/x1),
 * т.к. скан обходит ВСЕ root bridge'и и шины 0..255. */
#ifdef MULTI_CARD
#define MC_MAX_CARDS 16
typedef struct {
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *rb;
    UINTN bus, dev, fn;
} MC_CARD;
static MC_CARD g_mcCards[MC_MAX_CARDS];
static UINTN g_mcCount = 0;
static UINTN g_mcIndex = 0;
static BOOLEAN g_mcAdvance = FALSE;   /* после этой карты есть ещё */
static EFI_GUID mcGuid =
    {0x9a3b7c41,0x2e5d,0x4f68,{0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x17,0x28}};

static VOID mc_var_set(CHAR16 *name, UINT32 val)
{
    uefi_call_wrapper(RT->SetVariable, 6, name, &mcGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
        4, &val);
}

static UINT32 mc_var_get(CHAR16 *name, BOOLEAN *ok)
{
    UINT32 v = 0;
    UINTN sz = sizeof(v);
    UINT32 attr = 0;
    EFI_STATUS st = uefi_call_wrapper(RT->GetVariable, 5, name, &mcGuid,
                                      &attr, &sz, &v);
    if (ok) *ok = (!EFI_ERROR(st) && sz == sizeof(v));
    return v;
}

static VOID mc_vars_clear(void)
{
    uefi_call_wrapper(RT->SetVariable, 6, L"CMP90IDX", &mcGuid, 0, 0, NULL);
    uefi_call_wrapper(RT->SetVariable, 6, L"CMP90CNT", &mcGuid, 0, 0, NULL);
}

/* Как find_cmp90hx, но собирает ВСЕ 220d (без раннего выхода) */
static void
find_all_cmp90hx(void)
{
    EFI_HANDLE *RbHandles = NULL;
    UINTN RbCount = 0, i;

    if (EFI_ERROR(uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
            &gEfiPciRootBridgeIoProtocolGuid, NULL, &RbCount, &RbHandles)))
        return;

    for (i = 0; i < RbCount && g_mcCount < MC_MAX_CARDS; i++) {
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *rb = NULL;
        UINTN Bus, Dev, Fn;

        if (EFI_ERROR(uefi_call_wrapper(BS->HandleProtocol, 3, RbHandles[i],
                &gEfiPciRootBridgeIoProtocolGuid, (VOID**)&rb))) continue;

        for (Bus = 0; Bus <= 255 && g_mcCount < MC_MAX_CARDS; Bus++) {
            UINT32 Id = 0;
            UINT64 A0 = ((UINT64)Bus << 20);

            if (EFI_ERROR(uefi_call_wrapper(rb->Pci.Read, 5, rb,
                    EfiPciIoWidthUint32, A0, 1, &Id)) || Id == 0xFFFFFFFF)
                continue;

            for (Dev = 0; Dev < 32 && g_mcCount < MC_MAX_CARDS; Dev++) {
                UINTN MaxFn = 1;
                UINT32 Hdr = 0;
                UINT64 AD = ((UINT64)Bus << 20) | ((UINT64)Dev << 15);

                if (EFI_ERROR(uefi_call_wrapper(rb->Pci.Read, 5, rb,
                        EfiPciIoWidthUint32, AD, 1, &Id)) || Id == 0xFFFFFFFF)
                    continue;
                if (!EFI_ERROR(uefi_call_wrapper(rb->Pci.Read, 5, rb,
                        EfiPciIoWidthUint32, AD | 0x0C, 1, &Hdr)) && (Hdr & 0x80))
                    MaxFn = 8;

                for (Fn = 0; Fn < MaxFn && g_mcCount < MC_MAX_CARDS; Fn++) {
                    UINT64 AF = AD | ((UINT64)Fn << 12);
                    if (EFI_ERROR(uefi_call_wrapper(rb->Pci.Read, 5, rb,
                            EfiPciIoWidthUint32, AF, 1, &Id)) ||
                        Id == 0xFFFFFFFF) continue;
                    if ((Id & 0xFFFF) == 0x10DE &&
                        ((Id >> 16) & 0xFFFF) == 0x1E09) {
                        g_mcCards[g_mcCount].rb  = rb;
                        g_mcCards[g_mcCount].bus = Bus;
                        g_mcCards[g_mcCount].dev = Dev;
                        g_mcCards[g_mcCount].fn  = Fn;
                        g_mcCount++;
                    }
                }
            }
        }
    }
    FreePool(RbHandles);
}

static BOOLEAN mc_pick(UINTN idx)
{
    if (idx >= g_mcCount) return FALSE;
    gRb  = g_mcCards[idx].rb;
    gBus = g_mcCards[idx].bus;
    gDev = g_mcCards[idx].dev;
    gFn  = g_mcCards[idx].fn;
    return TRUE;
}

/* Boot#### на САМОГО себя (по DevicePath загруженного образа) + BootNext.
 * Запись ищется по описанию и переиспользуется (не плодим слоты). */
static BOOLEAN mc_set_bootnext_self(EFI_HANDLE ImageHandle)
{
    static EFI_GUID gvGuid = EFI_GLOBAL_VARIABLE;
    static UINT8 opt[1024];
    UINTN off = 0;
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    EFI_DEVICE_PATH_PROTOCOL *dp = NULL, *e;
    UINTN dpSize = 0;
    UINT32 attrs = 0x1;               /* LOAD_OPTION_ACTIVE */
    UINT16 fpl;
    CHAR16 desc[] = L"CMP90HX unlock";
    UINT16 optNo;
    EFI_STATUS st;
    CHAR16 name[12];

    if (EFI_ERROR(uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle,
            &gEfiLoadedImageProtocolGuid, (VOID**)&li)) || !li->FilePath) {
        Print(L"multi-card: нет LoadedImage/FilePath\n");
        return FALSE;
    }
    dp = li->FilePath;
    for (e = dp; ; e = (EFI_DEVICE_PATH_PROTOCOL *)
             ((UINT8 *)e + (e->Length[0] | (e->Length[1] << 8)))) {
        UINTN len = e->Length[0] | (e->Length[1] << 8);
        dpSize += len;
        if (e->Type == 0x7F && e->SubType == 0xFF) break;
        if (len == 0) return FALSE;
    }
    fpl = (UINT16)dpSize;

    CopyMem(opt + off, &attrs, 4);                      off += 4;
    CopyMem(opt + off, &fpl, 2);                        off += 2;
    CopyMem(opt + off, desc, (StrLen(desc) + 1) * 2);   off += (StrLen(desc) + 1) * 2;
    CopyMem(opt + off, dp, dpSize);                     off += dpSize;

    /* найти существующую нашу запись или свободный слот Boot%04X.
     * v2.99b: break только по NOT_FOUND (свободный слот); прочие ошибки
     * (BufferTooSmall на крупной чужой записи и т.п.) = слот занят, ищем
     * дальше — раньше цикл уезжал на Boot0000 и перезаписывал UiApp
     * (Invalid Parameter). */
    {
        UINTN dbg = 0;
        for (optNo = 0; optNo < 0xFFFF; optNo++) {
            static UINT8 scr[4096];
            UINTN sz = sizeof(scr);
            UINT32 attr = 0;
            BOOLEAN ours;

            UnicodeSPrint(name, sizeof(name), L"Boot%04X", optNo);
            st = uefi_call_wrapper(RT->GetVariable, 5, name, &gvGuid,
                                   &attr, &sz, scr);
            if (dbg < 12)
                Print(L"mc-slot[%02d] st=%r attr=%x sz=%d\n",
                      (INTN)optNo, st, attr, (INTN)sz);
            dbg++;
            if (st == EFI_NOT_FOUND) break;           /* свободный слот */
            if (EFI_ERROR(st)) continue;              /* занят, но нечитаем */
            ours = (sz > 8) && StrnCmp((CHAR16 *)(scr + 6), desc,
                                       StrLen(desc)) == 0;
            if (ours) break;                          /* переиспользуем */
        }
        Print(L"mc: выбран слот %d, opt=%d байт (fpl=%d, dp=%d)\n",
              (INTN)optNo, (INTN)off, fpl, (INTN)dpSize);
    }

    st = uefi_call_wrapper(RT->SetVariable, 6, name, &gvGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS, off, opt);
    if (EFI_ERROR(st)) {
        Print(L"multi-card: Boot%04X запись: %r\n", (INTN)optNo, st);
        return FALSE;
    }
    st = uefi_call_wrapper(RT->SetVariable, 6, L"BootNext", &gvGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS, 2, &optNo);
    Print(L"multi-card: BootNext -> Boot%04X (сами): %r\n", (INTN)optNo, st);
    return !EFI_ERROR(st);
}
#endif /* MULTI_CARD */

/* ==== Render/priv mask table + fire-mode loop (rejoin16 method) ====
 * The Gen1 link cap and closed XVE/XP3G windows are PLM-protected
 * shadow registers, NOT fuses: with PLM open they become writable — but
 * the V67 chain fires exactly TWICE per boot cycle (#1 stock payload
 * opens PLM, #2 carries ONE crafted {addr,value} pair), and each pair
 * needs its own FLR-separated mini-cycle. Table = 37 pairs. After the
 * last pair the final pass applies GFX_SPEED_SELECT/SS0/SS1 and
 * (unless FULL_NOGEN2) the gen2 link configuration.
 * jdowning100/pearlfortune: Gen1 cap = PLM-защита XVE/XP3G (НЕ fuse!).
 * V67-цепь срабатывает ОДИН раз за FLR-разделённую загрузку → одна запись
 * {addr,value} за прогон. Таблица 36 пар из их rejoin16-apply-all.sh.
 * Цикл итерации: FLR на входе (разделение) → восстановление BAR0 →
 * полный ранний путь с пропатченным payload → verify readback до cleanup.
 * Финальная итерация: маски открыты → Gen2-конфиг хостом + GFX_SPEED_SELECT.
 * Требует MULTI_CARD (mc_var_get/set, mc_set_bootnext_self, mc_vars_clear). */
#ifdef PCIE_GEN2_REJOIN
static const struct { UINT32 addr, val; } g_rj16[] = {
    {0x00823804U,0xffffffffU},{0x00088fe8U,0xffffffffU},{0x00088fecU,0xffffffffU},
    {0x00088ff0U,0xffffffffU},{0x00088ff4U,0xffffffffU},{0x00088ff8U,0xffffffffU},
    {0x00088ab4U,0xffffffffU},{0x0008e1b0U,0xffffffffU},{0x0008e1b4U,0xffffffffU},
    {0x0008e1b8U,0xffffffffU},{0x0008e1bcU,0xffffffffU},{0x0008e1c0U,0xffffffffU},
    {0x0008e1c4U,0xffffffffU},{0x0008e1c8U,0xffffffffU},{0x0008e1ccU,0xffffffffU},
    {0x0008e1d0U,0xffffffffU},{0x0008e1d4U,0xffffffffU},{0x0008e1d8U,0xffffffffU},
    {0x0008e1dcU,0xffffffffU},{0x0008e1e0U,0xffffffffU},{0x0008e1e4U,0xffffffffU},
    {0x0008e1e8U,0xffffffffU},{0x0008e1ecU,0xffffffffU},{0x0008e1f0U,0xffffffffU},
    {0x008200d0U,0xffffffffU},{0x008200d4U,0xffffffffU},{0x008200d8U,0xffffffffU},
    {0x008200dcU,0xffffffffU},{0x008200e0U,0xffffffffU},{0x008200e4U,0xffffffffU},
    {0x008200e8U,0xffffffffU},{0x008200ecU,0xffffffffU},{0x008200f0U,0xffffffffU},
    {0x008200f4U,0xffffffffU},{0x00823800U,0xffffffffU},{0x00823b04U,0xffffffffU},
    /* v2.100: LINK_CAP = Gen2 (0x...02). Проба Gen3 (v2.99k) отклонена:
     * кремний жёстко клампит max_speed на 5 GT/s (запись 03 -> readback 02,
     * подтверждено и на хосте). Пишем детерминированное значение — свип
     * проходит, LnkCap анонсирует 5 GT/s («card advertises Gen2»). */
    {0x00088084U,0x00453d02U},
};
#define RJ16_N ((INTN)(sizeof(g_rj16)/sizeof(g_rj16[0])))
static BOOLEAN g_gen2Fire = FALSE;
static BOOLEAN g_gen2Quick = FALSE;   /* v2.99h: маски уже открыты — сразу конфиг */
static UINT32 g_gen2Addr = 0, g_gen2Val = 0;
#endif /* PCIE_GEN2_REJOIN */

/* ==== GPU wall-clock (PTIMER) ====
 * PLM anti-replay validation needs sane GPU time: seed PTIMER from RTC
 * (constant fallback) BEFORE touching any protected register. */
static void
set_gpu_time(void)
{
    EFI_TIME t;
    UINT64 ns;
    BOOLEAN bOk = FALSE;

    if (uefi_call_wrapper(ST->RuntimeServices->GetTime, 2, &t, NULL) == EFI_SUCCESS &&
        t.Year >= 2015 && t.Year < 2100)
    {
        Print(L"time: RTC %d-%02d-%02d %02d:%02d:%02d\n",
              t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second);
        bOk = TRUE;
    }
    else
    {
        /* RTC мёртв/не задан в EFI-контексте → константа 2026-08-19 00:00 UTC */
        Print(L"time: GetTime недоступен/мусор — константа 2026-08-19\n");
        t.Year = 2026; t.Month = 8; t.Day = 19;
        t.Hour = 0; t.Minute = 0; t.Second = 0;
    }

    if (bOk) {
        /* EFI_TIME → unix ns (примерное: без високосных поправок — достаточно) */
        UINTN days = 0;
        static const UINTN mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
        UINTN y, m;
        for (y = 1970; y < t.Year; y++)
            days += 365 + (((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0));
        for (m = 0; m < t.Month - 1; m++)
            days += mdays[m];
        if (t.Month > 2 && (((t.Year % 4 == 0) && (t.Year % 100 != 0)) || (t.Year % 400 == 0)))
            days++;
        ns = ((UINT64)days * 86400ULL + (UINT64)t.Hour * 3600ULL +
              (UINT64)t.Minute * 60ULL + t.Second) * 1000000000ULL;
    } else {
        ns = 1787011200000000000ULL;  /* 2026-08-19 00:00:00 UTC в наносекундах */
    }
    mmio_write32(NV_PTIMER_TIME_1, (UINT32)(ns >> 32));
    mmio_write32(NV_PTIMER_TIME_0, (UINT32)(ns & 0xFFFFFFFF));
    Print(L"time: GPU time set (ns>>32=0x%08x)\n", (UINT32)(ns >> 32));
}

/* ==== Falcon DMA engine primitives (SEC2) ====
 * 256-byte block transfers through DMATRF registers; wait helpers poll
 * the FULL/IDLE bits of DMATRFCMD. */
static void
falcon_dma_wait_not_full(void)
{
    UINTN i;
    for (i = 0; i < 1000000; i++) {
        if (!(mmio_read32(SEC2_DMATRFCMD) & 0x1))  /* FULL bit 0 */
            return;
    }
}

static void
falcon_dma_wait_idle(void)
{
    UINTN i;
    for (i = 0; i < 1000000; i++) {
        if (mmio_read32(SEC2_DMATRFCMD) & 0x2)  /* IDLE bit 1 */
            return;
    }
}

/* ==== Post-reset scrub wait (driver-equivalent, MANDATORY) ====
 * Mirrors kflcnPreResetWait/kflcnWaitForScrubbingToFinish: after an
 * ENGINE reset the Falcon scrubs IMEM/DMEM with DEAD5EC* patterns;
 * DMA issued during scrubbing races the scrubber and gets erased
 * ("DEAD5EC1 everywhere", halts). Wait for DMACTL[2:1]==0 && HWCFG2[12]==0:
 * Драйвер: kflcnPreResetWait_GA102 (HWCFG2.RESET_READY до сброса) +
 * kflcnWaitForResetToFinish_GA102 + _kflcnWaitForScrubbingToFinish
 * (DMACTL[2:1]=IMEM/DMEM скраббинг идёт, HWCFG2[12]=MEM_SCRUBBING идёт;
 * 0 = готово). После сброса Фалкон ЗАЧИЩАЕТ IMEM/DMEM паттерном DEAD5EC* —
 * без ожидания DMA-записи соревнуются со скраббером и стираются!
 * Именно это давало «DEAD5EC1 везде», «SEC=1 DMA не доставляет» и halt'ы. */
#define SEC2_HWCFG2             (NV_PSEC_BASE + 0x0F4)
#define GSP_HWCFG2              (GSP_BASE  + 0x0F4)
static BOOLEAN
falcon_wait_scrub_done(UINT32 dmactlReg, UINT32 hwcfg2Reg, const CHAR16 *tag)
{
    UINTN i;
    UINT32 dct = 0xFFFFFFFF, hcfg = 0xFFFFFFFF;
    for (i = 0; i < 30000; i++) {                 /* до ~3с */
        dct = mmio_read32(dmactlReg);
        if ((dct & 0x6) == 0) {                   /* IMEM[2]+DMEM[1] скраб завершён */
            hcfg = mmio_read32(hwcfg2Reg);
            if (!(hcfg & (1 << 12)))              /* HWCFG2.MEM_SCRUBBING готов */
                return TRUE;
        }
        uefi_call_wrapper(BS->Stall, 1, 100);
    }
    Print(L"%s: scrub-wait ТАЙМАУТ dmactl=0x%08x hwcfg2=0x%08x\n", tag, dct, hcfg);
    return FALSE;
}

/* ждать RESET_READY (HWCFG2[31]) ДО сброса — как kflcnPreResetWait_GA102 */
static void
falcon_wait_reset_ready(UINT32 hwcfg2Reg)
{
    UINTN i;
    for (i = 0; i < 10000; i++) {
        if (mmio_read32(hwcfg2Reg) & (1u << 31))
            return;
        uefi_call_wrapper(BS->Stall, 1, 100);
    }
}

static void
falcon_dma_transfer(UINT32 dest, UINT32 memOff, UINT64 srcPhys, UINT32 size, UINT32 dmaCmd)
{
    UINT32 bytesXfered = 0;

    falcon_dma_wait_not_full();
    mmio_write32(SEC2_DMATRFBASE, (UINT32)(srcPhys >> 8));
    mmio_write32(SEC2_DMATRFBASE1, (UINT32)((srcPhys >> 8) >> 32) & 0x1FF);

    while (bytesXfered < size) {
        falcon_dma_wait_not_full();
        mmio_write32(SEC2_DMATRFMOFFS, dest);
        mmio_write32(SEC2_DMATRFFBOFFS, memOff);
        mmio_write32(SEC2_DMATRFCMD, dmaCmd);
        bytesXfered += FLCN_BLK_ALIGNMENT;
        dest       += FLCN_BLK_ALIGNMENT;
        memOff     += FLCN_BLK_ALIGNMENT;
    }
    falcon_dma_wait_idle();
}

/* ==== Legacy: ucode upload via IMEMC/DMEMD debug ports (diagnostics) ====
 * When the DMA engine is priv-locked the window ports still answer, so
 * images can be poked word-by-word (IMEM needs the SECURE bit28, like
 * SEC=1 DMA). Not used by the release flow:
 * DMATRF-движок залочен привилегированным доступом (как WPR2 — v2.16:
 * запись не прилипает; v2.17: IMEM заскраблен DEAD5EC1 — DMA не передал).
 * Порты IMEMC/IMEMD (0x840180/4) и DMEMC/DMEMD (0x8401C0/4) доступны
 * (v2.17 прочитал через них DEAD5EC1). Грузим образ напрямую. */
static void
sec2_load_image_via_ports(UINT64 ucodePhys)
{
    const UINT8 *img = (const UINT8*)(UINTN)ucodePhys;
    UINTN i;
    UINT32 imemSec;

    /* v2.20: IMEM пишем с IMEMC_SECURE (bit28) — как DMA с SEC=1! Драйвер
     * грузит код secure-передачей; v2.19: сигнатура (DMEM non-secure) прошла,
     * но код в non-secure IMEM — BROM читает SECURE IMEM (пуст) → dbg=0x0. */
    imemSec = (1 << 28);            /* IMEMC_SECURE */
    Print(L"booter: загрузка IMEM через порты (SECURE, %d слов)...\n",
          BOOTER_APP_CODE_SIZE / 4);
    mmio_write32(SEC2_IMEMC0, imemSec | (1 << 24));  /* SECURE | AINCW */
    for (i = 0; i < BOOTER_APP_CODE_SIZE / 4; i++)
        mmio_write32(SEC2_IMEMD0, *(UINT32*)(img + BOOTER_APP_CODE_OFFSET + i * 4));

    /* DMEM: данные image[0x8A00..] → DMEM 0..0x6200 (dmemPa=0), SEC=0 как в DMA */
    Print(L"booter: загрузка DMEM через порты (%d слов)...\n",
          BOOTER_OS_DATA_SIZE / 4);
    mmio_write32(SEC2_DMEMC0, (1 << 24));  /* AINCW */
    for (i = 0; i < BOOTER_OS_DATA_SIZE / 4; i++)
        mmio_write32(SEC2_DMEMD0, *(UINT32*)(img + BOOTER_OS_DATA_OFFSET + i * 4));

    /* верификация: IMEM читаем с SECURE, DMEM без */
    mmio_write32(SEC2_IMEMC0, imemSec);   /* SECURE, addr 0 */
    Print(L"booter: IMEM[0x00]=%08x (ожидаю %08x)\n",
          mmio_read32(SEC2_IMEMD0), *(UINT32*)(img + BOOTER_APP_CODE_OFFSET));
    mmio_write32(SEC2_IMEMC0, imemSec | 0x100);
    Print(L"booter: IMEM[0x100]=%08x (ожидаю %08x)\n",
          mmio_read32(SEC2_IMEMD0), *(UINT32*)(img + BOOTER_APP_CODE_OFFSET + 0x100));
    mmio_write32(SEC2_DMEMC0, 0x10);
    Print(L"booter: DMEM[0x10]=%08x (ожидаю sig %08x)\n",
          mmio_read32(SEC2_DMEMD0), *(UINT32*)(img + BOOTER_OS_DATA_OFFSET + 0x10));
}

/* ==== Kill GFW — the GPU-firmware instance booted by VBIOS at POST ====
 * kgspResetHw_TU102 replica: ENGINE._RESET=TRUE -> reads -> FALSE.
 * While GFW lives, SEC2 answers 0xBADF5620 (priv lockdown); the driver
 * kills it right before the booter load:
 * kgspResetHw_TU102: NV_PGSP_FALCON_ENGINE._RESET=TRUE → чтения → FALSE.
 * Живой GFW (загруженный VBIOS при POST) держит SEC2 в priv-lock
 * (0xBADF5620 на CPUCTL/DMATRF/FBIF). Драйвер убивает его до booter load. */
static void
gsp_engine_reset(void)
{
    UINTN i;

    Print(L"gsp: ENGINE reset (0x1103C0) — убиваю GFW из POST...\n");
    mmio_write32(GSP_ENGINE, NV_PFALCON_FALCON_ENGINE_RESET_TRUE);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
}

/* ==== FWSEC HS-boot on GSP -> FRTS command -> WPR2 latched ====
 * Replica of kgspExecuteHsFalcon_GA102 + s_prepareForFwsec_TU102:
 * kflcnReset(GSP) -> patch DMEM (sig@0x5A4 + FRTS cmd interface) ->
 * FBIF/DMA setup -> DMA IMEM(SEC=1, 0xE200)+DMEM(SEC=0, 0x800) ->
 * BROM params (PKC RSA3K) -> BOOTVEC=0 -> STARTCPU -> poll WPR2
 * (FRTS programs NV_PFB_PRI_MMU_WPR2). With WPR2 up, the subsequent
 * SEC2 booter load proceeds. Driver reference values: frts_err=0,
 * Репликация kgspExecuteHsFalcon_GA102 + s_prepareForFwsec_TU102 (610.43.03):
 *   kflcnReset(GSP) → патчинг DMEM (sig@0x5A4 + FRTS-интерфейс) → TRANSCFG →
 *   DMA IMEM(SEC=1, 0xE200) + DMEM(SEC=0, 0x800) → BROM params (PKC RSA3K) →
 *   BOOTVEC=0 → STARTCPU → ждём WPR2 (FRTS ставит NV_PFB_PRI_MMU_WPR2).
 * Результат: WPR2 установлен → SEC2 booter load (v2.24) пройдёт (dbg≠0).
 * (В драйвере подтверждено: frts_err=0, wpr2_lo=0x027fe000 hi=0x027fee00.) */
static void
gsp_dma_wait_not_full(void)
{
    UINTN i;
    for (i = 0; i < 20000; i++) {
        if (!(mmio_read32(GSP_DMATRFCMD) & 0x1)) return;
    }
    Print(L"fwsec: ВНИМАНИЕ DMA queue FULL (cmd=0x%08x)\n", mmio_read32(GSP_DMATRFCMD));
}

static void
gsp_dma_wait_idle(void)
{
    UINTN i;
    for (i = 0; i < 20000; i++) {
        if (mmio_read32(GSP_DMATRFCMD) & 0x2) return;
    }
    Print(L"fwsec: ВНИМАНИЕ DMA не IDLE (cmd=0x%08x)\n", mmio_read32(GSP_DMATRFCMD));
}

static void
gsp_dma_transfer(UINT32 dest, UINT32 memOff, UINT64 srcPhys, UINT32 size, UINT32 dmaCmd)
{
    UINT32 bytesXfered = 0;

    gsp_dma_wait_not_full();
    mmio_write32(GSP_DMATRFBASE, (UINT32)(srcPhys >> 8));
    mmio_write32(GSP_DMATRFBASE1, (UINT32)((srcPhys >> 8) >> 32) & 0x1FF);

    while (bytesXfered < size) {
        gsp_dma_wait_not_full();
        mmio_write32(GSP_DMATRFMOFFS, dest);
        mmio_write32(GSP_DMATRFFBOFFS, memOff);
        mmio_write32(GSP_DMATRFCMD, dmaCmd);
        bytesXfered += FLCN_BLK_ALIGNMENT;
        dest       += FLCN_BLK_ALIGNMENT;
        memOff     += FLCN_BLK_ALIGNMENT;
    }
    gsp_dma_wait_idle();
}

static BOOLEAN
fwsec_boot_gsp(UINT64 fwsecPhys)
{
    UINTN i;
    UINT32 data;
    UINT8 *dmem = (UINT8*)(UINTN)(fwsecPhys + FWSEC_DATA_OFF);

    Print(L"\n--- v2.28: FWSEC HS-boot на GSP (0x110000) ---\n");

    /* 1. kflcnReset(GSP): ENGINE reset → BCR=FALCON → RM=PMC_BOOT_0 */
    Print(L"fwsec: kflcnReset(GSP)...\n");
    falcon_wait_reset_ready(GSP_HWCFG2);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(GSP_BCR, 0x1);                 /* CORE_SELECT=FALCON */
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, mmio_read32(0x00100000));  /* chipId0 = PMC_BOOT_0 */
    Print(L"fwsec: GSP после reset: cpuctl=0x%x bcr=0x%x engine=0x%x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BCR), mmio_read32(GSP_ENGINE));
    if ((mmio_read32(GSP_CPUCTL) & 0xBADF0000) == 0xBADF0000) {
        Print(L"fwsec: GSP залочен (0xBADF) — прерываю\n");
        return FALSE;
    }

    /* 2. Патчинг DMEM: сигнатура @0x5A4 + интерфейс FRTS (init_cmd + cmd) */
    Print(L"fwsec: патчинг DMEM (sig@0x5a4, iface@0x1c, FRTS cmd)...\n");
    CopyMem(dmem + FWSEC_SIG_DMEM_ADDR, fwsec_ga102_sig, FWSEC_SIG_SIZE);
    {
        /* DMEM_MAPPER_V3: signature@0, version(u16)@4, size(u16)@6,
         * cmd_in_buffer_offset@8, ..., init_cmd@44 (с u16-паддингом!) */
        UINT32 *mapper = (UINT32*)(dmem + 0x560);
        UINT32 cmdInOff = mapper[2];                /* cmd_in_buffer_offset */
        UINT32 *c = (UINT32*)(dmem + cmdInOff);     /* cmd_in буфер @0x7C0 */

        c[0] = 1; c[1] = 24;                        /* readVbiosDesc ver,size */
        c[2] = 0; c[3] = 0;                         /* gfwImageOffset lo,hi */
        c[4] = 0; c[5] = 2;                         /* gfwImageSize, flags=2 */
        c[6] = 1; c[7] = 20;                        /* frtsRegionDesc ver,size */
        c[8] = (UINT32)(FWSEC_FRTS_OFFSET >> 12);   /* frtsRegionOffset4K */
        c[9] = 0x100;                               /* 1MB в 4K-блоках */
        c[10] = 2;                                  /* frtsRegionMediaType=FB */
        mapper[11] = FWSEC_CMD_FRTS;                /* init_cmd @0x58C */
        Print(L"fwsec: mapper init_cmd=0x%x cmd_in_off=0x%x (размер буфера 0x%x)\n",
              mapper[11], cmdInOff, mapper[3]);
    }

    /* 3. kflcnDisableCtxReq (FBIF_CTL ALLOW_PHYS_NO_CTX + DMACTL=0) +
     *    TRANSCFG(0): TARGET=COHERENT_SYSMEM(1) | MEM_TYPE=PHYSICAL(1<<2) */
    data = mmio_read32(GSP_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(GSP_FBIF_CTL, data);
    mmio_write32(GSP_DMACTL, 0);
    data = mmio_read32(GSP_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(GSP_FBIF_TRANSCFG0, data);
    Print(L"fwsec: fbifctl=0x%x dmactl=0x%x transcfg0=0x%x dmatrfcmd=0x%x\n",
          mmio_read32(GSP_FBIF_CTL), mmio_read32(GSP_DMACTL),
          mmio_read32(GSP_FBIF_TRANSCFG0), mmio_read32(GSP_DMATRFCMD));

    /* диагностика DMATRF (как v2.21 для SEC2): write+readback */
    mmio_write32(GSP_DMATRFBASE, 0xDEADBEEF);
    Print(L"fwsec: DMATRFBASE write-test = 0x%08x (DEADBEEF = доступен)\n",
          mmio_read32(GSP_DMATRFBASE));
    mmio_write32(GSP_DMATRFBASE, 0);

    /* 4. DMA: IMEM SEC=1 (0xE200), DMEM SEC=0 (0x800) — как драйвер */
    Print(L"fwsec: DMA IMEM (SEC=1, 0x%x байт)...\n", FWSEC_CODE_SIZE);
    gsp_dma_transfer(0, 0, fwsecPhys, FWSEC_CODE_SIZE,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"fwsec: DMA DMEM (SEC=0, 0x%x байт)...\n", FWSEC_DMEM_SIZE);
    gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF, FWSEC_DMEM_SIZE,
                     0 | (6 << 8) | (0 << 12));

    /* 4b. Верификация: куда лёг код/данные (порты GSP IMEMC/DMEMC) */
    mmio_write32(GSP_BASE + 0x180, 0);          /* IMEMC0: addr 0, non-secure */
    Print(L"fwsec: GSP IMEM[0x00]=0x%08x (образ: 0x%08x)\n",
          mmio_read32(GSP_BASE + 0x184), *(UINT32*)(UINTN)fwsecPhys);
    mmio_write32(GSP_BASE + 0x180, (1 << 28));  /* IMEMC0: addr 0, SECURE bit */
    Print(L"fwsec: GSP IMEM_S[0x00]=0x%08x (secure view)\n", mmio_read32(GSP_BASE + 0x184));
    mmio_write32(GSP_BASE + 0x180, 0x100 | (1 << 28));
    Print(L"fwsec: GSP IMEM_S[0x100]=0x%08x\n", mmio_read32(GSP_BASE + 0x184));
    mmio_write32(GSP_BASE + 0x1C0, FWSEC_SIG_DMEM_ADDR);   /* DMEMC0 */
    Print(L"fwsec: GSP DMEM[0x5a4]=0x%08x (ожидаю 0x%08x — sig[2])\n",
          mmio_read32(GSP_BASE + 0x1C4), *(UINT32*)(UINTN)fwsec_ga102_sig);
    mmio_write32(GSP_BASE + 0x1C0, 0x7C0);      /* cmd_in буфер */
    Print(L"fwsec: GSP DMEM[0x7c0]=0x%08x (ожидаю 0x00000001 — FRTS readVbiosDesc.ver)\n",
          mmio_read32(GSP_BASE + 0x1C4));

    /* v2.40: диагностика порта GSP УБРАНА (v2.37: SEC=0 DMA на IMEM[0x8000]
     * ПЕРЕЗАПИСАЛ часть предзагруженного FWSEC-кода (0..0xE200) — FWSEC
     * перестал исполняться! В GSP IMEM до 0xE400 ничего не писать.) */

    /* v2.42: скан GSP IMEM — что предзагрузил VBIOS за пределами FWSEC
     * (0xE200)? Если там BL/booter-код — можно запустить через BROM params.
     * Читаем оба представления по сетке. */
    {
        static const UINT32 scan_offs[] = {
            0x000, 0x100, 0x1000, 0x4000, 0x8000, 0xC000, 0xE000, 0xE200,
            0xE400, 0xF000, 0x10000, 0x11000, 0x12000, 0x14000, 0x16000,
            0x18000, 0x1A000, 0x1C000, 0x20000, 0x24000, 0x28000, 0x30000,
            0x40000, 0x60000, 0x80000
        };
        UINTN s;
        Print(L"fwsec: GSP IMEM-скан (v2.42):\n");
        for (s = 0; s < sizeof(scan_offs)/sizeof(scan_offs[0]); s++) {
            UINT32 a = scan_offs[s];
            UINT32 vn, vs;
            mmio_write32(GSP_BASE + 0x180, a);
            vn = mmio_read32(GSP_BASE + 0x184);
            mmio_write32(GSP_BASE + 0x180, a | (1 << 28));
            vs = mmio_read32(GSP_BASE + 0x184);
            Print(L"fwsec:   IMEM[0x%05x]=0x%08x IMEM_S=0x%08x%s\n",
                  a, vn, vs,
                  (vn != 0xDEAD5EC1 && vs != 0xDEAD5EC1 && vn != 0) ? L" <<<" : L"");
        }
    }

    /* 5. BROM params (PKC RSA3K) — GSP FALCON2 @0x111000 */
    mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
    mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
    mmio_write32(GSP_MOD_SEL, 0x1);                    /* RSA3K */
    Print(L"fwsec: BROM: paraaddr=0x%x engmask=0x%x ucodeid=%d modsel=0x1\n",
          FWSEC_SIG_DMEM_ADDR, FWSEC_ENGID_MASK, FWSEC_UCORE_ID);

    /* 6. BOOTVEC=0 (imemVa) + STARTCPU */
    mmio_write32(GSP_BOOTVEC, 0);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
    Print(L"fwsec: STARTCPU (GSP), жду WPR2 до 5с...\n");

    /* 7. Поллинг WPR2 (FRTS ставит lo=0x27fe000 hi=0x27fee00) */
    for (i = 0; i < 5000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == 0x027FE000 && (hi & 0xFFFFFFF0) == 0x027FEE00) {
            Print(L"fwsec: *** WPR2 УСТАНОВЛЕН lo=0x%08x hi=0x%08x после %d ms ***\n",
                  lo, hi, i);

            /* v2.43: ПЕРЕБОР команд FWSEC (0x10..0x1F) — ищем команду записи
             * регистров (PLM!). Для каждой: патч init_cmd + re-DMA + STARTCPU
             * + 200мс poll → сравниваем PLM/privmask/WPR2 до/после. */
            {
                UINT8 *dmem2 = (UINT8*)(UINTN)(fwsecPhys + FWSEC_DATA_OFF);
                UINT32 cmd;
                Print(L"fwsec: v2.43 перебор команд 0x10..0x1F:\n");
                for (cmd = 0x10; cmd <= 0x1F; cmd++) {
                    UINT32 *mapper2 = (UINT32*)(dmem2 + 0x560);
                    UINT32 cmdInOff2 = mapper2[2];
                    UINT32 *c2 = (UINT32*)(dmem2 + cmdInOff2);
                    UINT32 plm0, priv0, wpr0;
                    UINT32 plmA, privA, wprA;

                    c2[0] = 1; c2[1] = 24;             /* readVbiosDesc */
                    c2[2] = 0; c2[3] = 0;
                    c2[4] = 0; c2[5] = 2;
                    mapper2[11] = cmd;
                    gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF,
                                     FWSEC_DMEM_SIZE,
                                     0 | (6 << 8) | (0 << 12));
                    plm0 = mmio_read32(REG_FEAT_OVR_PLM);
                    priv0 = mmio_read32(0x00118128);
                    wpr0 = mmio_read32(REG_PFB_MMU_WPR2_LO);
                    mmio_write32(GSP_BOOTVEC, 0);
                    __asm__ volatile("wbinvd" ::: "memory");
                    mmio_write32(GSP_CPUCTL,
                                 NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
                    uefi_call_wrapper(BS->Stall, 1, 200000);
                    plmA = mmio_read32(REG_FEAT_OVR_PLM);
                    privA = mmio_read32(0x00118128);
                    wprA = mmio_read32(REG_PFB_MMU_WPR2_LO);
                    Print(L"fwsec:   cmd=0x%02x: PLM=0x%08x priv=0x%08x "
                          L"wpr2lo=0x%08x gsp=0x%x dbg=0x%x%s\n",
                          cmd, plmA, privA, wprA,
                          mmio_read32(GSP_CPUCTL),
                          mmio_read32(GSP_BASE + 0x94),
                          (plmA != plm0 || privA != priv0 || wprA != wpr0)
                              ? L" <<< ИЗМЕНЕНИЕ" : L"");
                    if (plmA == VAL_PLM_OPEN) {
                        Print(L"fwsec:   *** cmd=0x%02x ОТКРЫЛ PLM! ***\n", cmd);
                        break;
                    }
                }
            }

            /* v2.45: ДИСКРИМИНАЦИЯ SEC=1 на GSP — загружаем МОДИФИЦИРОВАННЫЙ
             * FWSEC (frtsOffset=0x10000000 вместо 0x27FE00000) + sig[2] +
             * BROM params. Если SEC=1 DMA работает — BROM выполнит НАШ код →
             * WPR2 станет lo=0x00100000. Если нет — предзагруженный код
             * выполнится со стандартным offset → WPR2 останется 0x027FE000. */
            {
                UINT8 *buf = (UINT8*)(UINTN)fwsecPhys;   /* переиспользуем */
                UINT32 *mapper2 = (UINT32*)(buf + FWSEC_DATA_OFF + 0x560);
                UINT32 cmdInOff2 = mapper2[2];
                UINT32 *c2 = (UINT32*)(buf + cmdInOff2);
                UINTN p;

                CopyMem(buf, fwsec_ga102_bin, FWSEC_SIZE);
                CopyMem(buf + FWSEC_DATA_OFF + FWSEC_SIG_DMEM_ADDR,
                        fwsec_ga102_sig, FWSEC_SIG_SIZE);
                c2[0] = 1; c2[1] = 24;
                c2[2] = 0; c2[3] = 0;
                c2[4] = 0; c2[5] = 2;
                c2[6] = 1; c2[7] = 20;
                c2[8] = 0x10000;                       /* frtsOffset 0x10000000>>12 */
                c2[9] = 0x100;
                c2[10] = 2;
                mapper2[11] = 0x15;

                Print(L"fwsec: v2.45 модиф. FWSEC (frts=0x10000000)...\n");
                gsp_dma_transfer(0, 0, fwsecPhys, FWSEC_CODE_SIZE,
                                 0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
                gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF,
                                 FWSEC_DMEM_SIZE,
                                 0 | (6 << 8) | (0 << 12));
                mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
                mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
                mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
                mmio_write32(GSP_MOD_SEL, 0x1);
                mmio_write32(GSP_BOOTVEC, 0);
                __asm__ volatile("wbinvd" ::: "memory");
                mmio_write32(GSP_CPUCTL,
                             NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
                Print(L"fwsec:   жду WPR2 (модиф. код → lo=0x100000):\n");
                for (p = 0; p < 2000; p++) {
                    UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
                    UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
                    if ((lo & 0xFFFFFFF0) == 0x00100000) {
                        Print(L"fwsec:   *** WPR2=0x%08x%08x — НАШ модиф. код "
                              L"выполнился (SEC=1 на GSP РАБОТАЕТ!) ***\n",
                              hi, lo);
                        break;
                    }
                    if ((p % 200) == 0)
                        Print(L"fwsec:   t=%dms wpr2lo=0x%08x wpr2hi=0x%08x "
                              L"gsp=0x%x dbg=0x%x\n",
                              p, lo, hi, mmio_read32(GSP_CPUCTL),
                              mmio_read32(GSP_BASE + 0x94));
                    uefi_call_wrapper(BS->Stall, 1, 1000);
                }
                Print(L"fwsec:   итог: wpr2lo=0x%08x hi=0x%08x "
                      L"(0x027FE000 = предзагруженный код, SEC=1 не работает; "
                      L"0x100000 = НАШ код!)\n",
                      mmio_read32(REG_PFB_MMU_WPR2_LO),
                      mmio_read32(REG_PFB_MMU_WPR2_HI));
            }
            return TRUE;
        }
        if ((i % 200) == 0)
            Print(L"fwsec:   t=%dms wpr2lo=0x%08x wpr2hi=0x%08x gspcpuctl=0x%x dbg=0x%x scratch0e=0x%x\n",
                  i, lo, hi, mmio_read32(GSP_CPUCTL),
                  mmio_read32(GSP_BASE + 0x94), mmio_read32(0x001438));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"fwsec: WPR2 НЕ установлен: lo=0x%08x hi=0x%08x gspcpuctl=0x%x dbg=0x%x scratch0e=0x%x\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
          mmio_read32(0x001438));
    return FALSE;
}

/* ==== v66/v68: 40HX (TU106) 原生 FWSEC HS-boot on GSP → FRTS → WPR2 up ====
 * 对照驱动 s_prepareForFwsec_TU102 + kgspExecuteFwsec (frts_tu102.c):
 *  GSP kflcnReset → patch data(iface@0xe0 → DMEMMAPPER@0x360 → cmd_in@0x3b0,
 *  init_cmd=0x15) → 端口装载 IMEM NS(0x400)+SEC(0x9600@0x400, TU102 语义) →
 *  BROM(PARAADDR= sig DMEM 址) → BOOTVEC=0 → STARTCPU → poll WPR2.
 * v70: 装载改 WITH_LOADER — FWSEC 是 WITH_LOADER 型 ucode (驱动
 * kernel_gsp_fwsec.c:741 bootType=WITH_LOADER), secure code 必须由 generic
 * falcon BL (bindata sec2_bl_gp10x, 768B) 从 host 内存 DMA 拉进 secure IMEM.
 * v68/v69 端口写 NS+SEC (DIRECT 语义) 与 v66/v67 DMA SEC=1 在 TU106 上
 * secure IMEM 全 scrub 被实机证伪 — host 无 secure 写权限, BL 有.
 * 40HX FWSEC sig 位置假设 data@0x10 (prod 真值/dbg 0xff 填充; 0x180=RSA3K). */
static BOOLEAN
fwsec_boot_gsp_50hx(UINT64 fwsecPhys)
{
    UINTN i;
    UINT32 data;
    UINT8 *blob = (UINT8 *)(UINTN)fwsecPhys;
    UINT8 *dmem = blob + FW50_DATA_OFF;
    UINT32 *mapper;
    UINT32 *c;
    UINT32 blBootVec = GSP_BL_TU102_START_TAG << 8;  /* updated per real IMEM size */

    Print(L"\n--- v66: 40HX FWSEC HS-boot on GSP (blob 0x9a00+0x3f0) ---\n");

    /* 1. kflcnReset(GSP): ENGINE reset → BCR=FALCON(0x0) → RM=chipId0(40HX=
     *    0x162000A1). IRQMSET=0 同 E1 BL 装载.
     *    Turing 无显式 core switch (kflcnSwitchToFalcon_TU102 仅软状态),
     *    reset 后即 FALCON 模式; BCR 1=RISCV 是 GA102 语义 — TU102 驱动在
     *    FWSEC 装载前不切核, 故写 0x0 (FALCON). 读回恒 0x0 属正常. */
    Print(L"fwsec50: kflcnReset(GSP)...\n");
    mmio_write32(0x110080, 0x0);          /* IRQMSET=0 (E1 trace) */
    falcon_wait_reset_ready(GSP_HWCFG2);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp40-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(GSP_BCR, 0x0);           /* CORE_SELECT=FALCON (TU102) */
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, 0x162000A1);          /* chipId0 50HX (TU102) */
    for (i = 0; i < 16; i++) mmio_read32(GSP_RM);
    Print(L"fwsec50: GSP reset: cpuctl=0x%x bcr=0x%x hwcfg2=0x%08x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BCR),
          mmio_read32(GSP_HWCFG2));
    if ((mmio_read32(GSP_CPUCTL) & 0xBADF0000u) == 0xBADF0000u) {
        Print(L"fwsec50: GSP locked (0xBADF) — abort\n");
        return FALSE;
    }

    /* 2. patch data: mapper.init_cmd=FRTS(0x15), cmd_in = readVbiosDesc +
     *    frtsRegionDesc(40HX 8GB frtsOffset) — 同驱动 s_vbiosPatchInterfaceData */
    mapper = (UINT32 *)(dmem + FW50_MAPPER_OFF);
    c = (UINT32 *)(dmem + FW50_CMDIN_OFF);
    Print(L"fwsec50: data iface@0x%x hdr={%d,%d,%d,%d} mapper@0x%x "
          L"sig=0x%08x ver=%d cmd_in_off=0x%x size=0x%x\n",
          FW50_IFACE_OFF, dmem[FW50_IFACE_OFF], dmem[FW50_IFACE_OFF+1],
          dmem[FW50_IFACE_OFF+2], dmem[FW50_IFACE_OFF+3],
          FW50_MAPPER_OFF, mapper[0],
          (UINT16)((mapper[0]>>16) & 0xFFFF),
          mapper[2], mapper[3]);
    /* 若实测 mapper 布局偏移与常量不符（mapper[2]=cmd_in_off 非 0x3b0），
     * 则按 mapper 自述的 cmd_in_buffer_offset 重定位（驱动式） */
    if (mapper[2] < FW50_DMEM_SIZE && mapper[2] != FW50_CMDIN_OFF) {
        Print(L"fwsec50: mapper.cmd_in_off=0x%x (!=0x3b0) — 用 mapper 值\n",
              mapper[2]);
    }
    /* readVbiosDesc (24B): ver=1 size=24 gfwOff=0 gfwSize=0 flags=2 */
    c[0] = 1; c[1] = 24;
    c[2] = 0; c[3] = 0;
    c[4] = 0; c[5] = 2;
    /* frtsRegionDesc (20B): ver=1 size=20 off4k=frts>>12 size=0x100 media=2 */
    c[6] = 1; c[7] = 20;
    c[8] = (UINT32)(FW50_FRTS_OFFSET >> 12);
    c[9] = 0x100;
    c[10] = 2;
    mapper[11] = FWSEC_CMD_FRTS;           /* init_cmd = 0x15 (FRTS) */
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"fwsec50: mapper.init_cmd=0x%x frts4k=0x%x (frts=0x%llx)\n",
          mapper[11], c[8], FW50_FRTS_OFFSET);

    /* 3. kflcnDisableCtxReq + TRANSCFG (host DMA 到 falcon 需要):
     *    v70 BL 用 ctxDma=4 (PHYS_SYS_NCOH, BL 固件固定) → TRANSCFG(4).
     *    0x5 = COHERENT_SYSMEM(1) | MEM_TYPE_PHYSICAL(bit2) — 同驱动
     *    s_setupLoaderAperture(ADDR_SYSMEM+CACHED); v66 DMA 已用同值验证
     *    可 DMA 读 >4GB host 内存 (fwsecPhys=0x11982c000). */
    data = mmio_read32(GSP_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(GSP_FBIF_CTL, data);
    mmio_write32(GSP_DMACTL, 0);
    /* v1.52: driver writes TARGET=COHERENT_SYSMEM(5) | MEM_TYPE=PHYSICAL
     * (bit4) = 0x15 (s_setupLoaderAperture). The bare 0x5 left MEM_TYPE
     * virtual and the BL never completed its DMA on the live card. */
    mmio_write32(GSP_FBIF_TRANSCFG0, 0x15);
    mmio_write32(GSP_FBIF_TRANSCFG4, 0x15);
    Print(L"fwsec50: FBIF_CTL=0x%08x TRANSCFG4=0x%08x (want 0x15) DMACTL=%x\n",
          mmio_read32(GSP_FBIF_CTL), mmio_read32(GSP_FBIF_TRANSCFG4),
          mmio_read32(GSP_DMACTL));

    /* 4. v70 WITH_LOADER — TU102 FWSEC 权威装载 (kernel_gsp_fwsec.c:741
     *    bootType=WITH_LOADER; s_setupLoader + s_prepareHsFalconWithLoader):
     *    FWSEC code/data 留在 host 内存, 由 generic falcon BL (768B, ns) 在
     *    secure 上下文里 DMA 拉进 IMEM — host 直写 secure IMEM (v66-v69 端口
     *    SECURE / DMA SEC=1) 全 scrub 已被实机证伪, 此路不再走.
     *    (a) BL DMEM DESC (RM_FLCN_BL_DMEM_DESC, 0x54B, 4B-align) → DMEM 0x0
     *    (b) generic BL code (0x200B) → GSP IMEM 顶 (s_setupLoader 公式),
     *        tag=blStartTag(0xfd), BOOTVEC=0xfd00
     *    (c) STARTCPU: BL DMA code(ns@0→IMEM0, sec@0x400→secure IMEM) +
     *        data→DMEM0, 跳 codeEntryPoint=0 → FWSEC FRTS → WPR2 up. */
    {
        UINT8  desc[BL_DESC_SIZE];          /* 全 0 = reserved/sig/argc/argv=0 */
        UINT32 *d = (UINT32 *)desc;
        UINT32 imemSizeBlk, imemDstBlk, blDstAddr, v;
        UINT32 codePaLo = (UINT32)(fwsecPhys & 0xFFFFFFFF);
        UINT32 codePaHi = (UINT32)(fwsecPhys >> 32);
        UINT64 dataPhys = fwsecPhys + FW50_DATA_OFF;

        for (i = 0; i < BL_DESC_SIZE / 4; i++) d[i] = 0;
        d[BL_DESC_CTXDMA / 4]     = 4;      /* ctxDma (BL 用 TRANSCFG index 4) */
        d[BL_DESC_CODEDMA_LO / 4] = codePaLo;
        d[BL_DESC_CODEDMA_HI / 4] = codePaHi;
        d[BL_DESC_NSOFF / 4]      = 0;      /* imemNsPa (desc: nonSecureCodeOff) */
        d[BL_DESC_NSSIZE / 4]     = FW50_NS_SIZE;
        d[BL_DESC_SECOFF / 4]     = FW50_SEC_BASE;   /* imemSecPa */
        d[BL_DESC_SECSIZE / 4]    = FW50_SEC_SIZE;
        d[BL_DESC_ENTRY / 4]      = 0;      /* codeEntryPoint (IMEM 0) */
        d[BL_DESC_DATADMA_LO / 4] = (UINT32)(dataPhys & 0xFFFFFFFF);
        d[BL_DESC_DATADMA_HI / 4] = (UINT32)(dataPhys >> 32);
        d[BL_DESC_DATASIZE / 4]   = FW50_DMEM_SIZE;
        Print(L"fwsec50: BL DESC ctxDma=4 code=0x%llx(ns0x%x@0+sec0x%x@0x400)"
              L" data=0x%llx(0x%x)\n",
              fwsecPhys, FW50_NS_SIZE, FW50_SEC_SIZE, dataPhys, FW50_DMEM_SIZE);

        /* (a) BL DMEM DESC → DMEM 0x0 (AINCW 端口写) */
        mmio_write32(GSP_BASE + 0x1C0, (BL_DESC_DMEM_LOAD_OFF) | (1u << 24));
        for (i = 0; i < BL_DESC_SIZE / 4; i++)
            mmio_write32(GSP_BASE + 0x1C4, d[i]);
        __asm__ volatile("wbinvd" ::: "memory");
        mmio_write32(GSP_BASE + 0x1C0, 0);

        /* (b) generic BL code → IMEM 顶. 驱动 s_setupLoader 公式:
         *     imemSizeBlk = HWCFG.IMEM_SIZE[8:0] (GSP IMEM block 数, 256B/blk)
         *     imemDstBlk  = imemSizeBlk - blCodeSize/256; 装载 @imemDstBlk<<8
         *     tag = blStartTag 起 (0xfd), BOOTVEC = 0xfd00 (BL 固件编译期). */
        imemSizeBlk = mmio_read32(GSP_HWCFG) & 0x1FF;
        imemDstBlk  = imemSizeBlk - (GSP_BL_TU102_CODE_SIZE / 256);
        blDstAddr   = imemDstBlk << 8;
        Print(L"fwsec50: BL load IMEM top: hwcfg.IMEM_SIZE=%d blk "
              L"dst=0x%x (BOOTVEC=0x%x)%s\n",
              imemSizeBlk, blDstAddr, (UINT32)(GSP_BL_TU102_START_TAG << 8),
              (blDstAddr == (GSP_BL_TU102_START_TAG << 8)) ? L"" :
              L"  <== WARN dst!=0xfd00");
        mmio_write32(GSP_BASE + 0x180, blDstAddr | (1u << 24)); /* IMEMC0 AINCW */
        {
            /* v1.51: driver-faithful semantics (kernel_gsp_falcon_tu102.c
             * s_setupLoader): BL is written at IMEM top (imemDst) but tagged
             * and started at its LINK address blStartTag<<8 (bindata
             * RM_FLCN_BL_DESC: blStartTag=0xfd, blCodeSize=0x200). */
            UINT32 tag = GSP_BL_TU102_START_TAG;
            blBootVec = GSP_BL_TU102_START_TAG << 8;
            for (i = 0; i < GSP_BL_TU102_CODE_SIZE / 4; i++) {
                if ((i & 63u) == 0u) {
                    mmio_write32(GSP_BASE + 0x188, tag);   /* IMEMT0 */
                    tag++;
                }
                mmio_write32(GSP_BASE + 0x184,
                             *(UINT32 *)(UINTN)((UINTN)gsp_bl_tu102 + i * 4));
            }
        }
        __asm__ volatile("wbinvd" ::: "memory");
        mmio_write32(GSP_BASE + 0x180, 0);

        /* (c) readback: BL[0] 落位 + desc.ctxDma 落位 */
        mmio_write32(GSP_BASE + 0x180, blDstAddr);
        v = mmio_read32(GSP_BASE + 0x184);
        Print(L"fwsec50: rb IMEM[0x%x]=0x%08x (exp BL[0]=0x%08x)%s\n",
              blDstAddr, v, *(UINT32 *)(UINTN)gsp_bl_tu102,
              (v == *(UINT32 *)(UINTN)gsp_bl_tu102) ? L"  <== OK" :
              L"  <== MISMATCH");
        mmio_write32(GSP_BASE + 0x1C0, BL_DESC_CTXDMA);
        Print(L"fwsec50: rb DMEM[0x20]=0x%08x (exp ctxDma 0x4)%s\n",
              mmio_read32(GSP_BASE + 0x1C4),
              (mmio_read32(GSP_BASE + 0x1C4) == 4) ? L"" : L"  <== MISMATCH");
        mmio_write32(GSP_BASE + 0x1C0, 0);
    }

    /* 5. BOOTVEC = blStartTag<<8 (BL 自定位) + STARTCPU.
     *    无 BROM params (WITH_LOADER 无 PARAADDR/ENGIDMASK/ucodeId 语义 —
     *    kgspExecuteHsFalcon_TU102 仅 prepare+mailbox+start). */
    mmio_write32(GSP_BOOTVEC, blBootVec);
    __asm__ volatile("wbinvd" ::: "memory");
    /* v1.53: enable the execution trace ring before start (same recipe the
     * port uses for the SEC2 RISC-V booter) and probe whether a CPUCTL
     * write sticks at all. */
    mmio_write32(GSP_FALCON2_BASE + 0x400, 0x10B0FF00);
    mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
    Print(L"fwsec50: STARTCPU (BL@0x%x -> DMA FWSEC), poll WPR2 up 5s...\n",
          blBootVec);

    /* v1.51 diagnostics: did the start request stick at all? */
    Print(L"fwsec50: post-STARTCPU cpuctl=0x%08x hwcfg=0x%08x hwcfg2=0x%08x irqstat=0x%08x irqmask=0x%08x dbg=0x%08x mbox0=0x%08x mbox1=0x%08x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_HWCFG),
          mmio_read32(GSP_HWCFG2), mmio_read32(GSP_BASE + 0x008),
          mmio_read32(GSP_BASE + 0x140), mmio_read32(GSP_BASE + 0x094),
          mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_MAILBOX1));
    {   /* v1.53: execution trace ring (rdidx/wtidx at FALCON2+0x404/+0x408) */
        UINT32 rdidx = mmio_read32(GSP_FALCON2_BASE + 0x404) & 0xFF;
        UINT32 wtidx = mmio_read32(GSP_FALCON2_BASE + 0x408) & 0xFF;
        INT32 ti;
        Print(L"fwsec50: trace rdidx=0x%x wtidx=0x%x\n", rdidx, wtidx);
        for (ti = 0; ti < 8; ti++) {
            UINT32 ent;
            mmio_write32(GSP_FALCON2_BASE + 0x404, (UINT32)(((rdidx - ti - 1) & 0xFF)));
            ent = mmio_read32(GSP_FALCON2_BASE + 0x40C);
            Print(L"fwsec50: trace[-%d] ent=0x%08x\n", ti + 1, ent);
        }
    }
    {   /* v1.52: per-word desc readback with explicit DMEMC offset each
         * word (the port has no auto-increment-read) */
        UINT32 k;
        Print(L"fwsec50: desc rb:");
        for (k = 0; k < 0x54; k += 4) {
            mmio_write32(GSP_BASE + 0x1C0, k);
            Print(L" %08x", mmio_read32(GSP_BASE + 0x1C4));
        }
        Print(L"\n");
    }

    /* 7. poll WPR2 → FRTS 成功则 up；读 GSP cpu/dbg/scratch 判失败原因 */
    for (i = 0; i < 5000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0u) == FW50_WPR2_LO_UP &&
            (hi & 0xFFFFFFF0u) == FW50_WPR2_HI_UP) {
            Print(L"fwsec50: *** WPR2 UP lo=0x%08x hi=0x%08x after %dms ***\n",
                  lo, hi, (INTN)i);
            return TRUE;
        }
        if ((i % 500) == 0) {
            UINT32 vIM, vD;
            /* BL DMA 成功的判据: IMEM[0]=FWSEC ns code[0], DMEM[0x10]=data sig */
            mmio_write32(GSP_BASE + 0x180, 0);
            vIM = mmio_read32(GSP_BASE + 0x184);
            mmio_write32(GSP_BASE + 0x1C0, 0x10);
            vD  = mmio_read32(GSP_BASE + 0x1C4);
            mmio_write32(GSP_BASE + 0x1C0, 0);
            mmio_write32(GSP_BASE + 0x180, 0);
            Print(L"fwsec50: t=%dms wpr2lo=0x%08x wpr2hi=0x%08x gspcpu=0x%x "
                  L"dbg=0x%x mbox0=0x%x IMEM[0]=0x%08x(exp 0x%08x) "
                  L"DMEM[0x10]=0x%08x(exp 0x%08x)\n",
                  (INTN)i, lo, hi, mmio_read32(GSP_CPUCTL),
                  mmio_read32(GSP_BASE + 0x94), mmio_read32(GSP_MAILBOX0),
                  vIM, *(UINT32 *)(UINTN)fwsecPhys,
                  vD, *(UINT32 *)(UINTN)(fwsecPhys + FW50_DATA_OFF + 0x10));
        }
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"fwsec50: WPR2 NOT up: lo=0x%08x hi=0x%08x gspcpu=0x%x dbg=0x%x "
          L"mbox0=0x%x scratch0e=0x%x\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
          mmio_read32(GSP_MAILBOX0), mmio_read32(0x001438));
    return FALSE;
}

/* ==== THE EXPLOIT PRIMITIVE: SEC2 booter load with V67 signature ====
 * Full driver-equivalent sequence: pre-reset-wait -> ENGINE reset ->
 * scrub wait -> switch core to Falcon (BCR) -> FBIF/DMA setup -> DMA
 * IMEM(SEC=1)+DMEM -> PKC/BROM params (RSA3K) -> BOOTVEC/mailboxes
 * (WPR meta phys addr, <4GB copy!) -> STARTCPU. Returns EFI_SUCCESS the
 * moment PLM reads back open; on failure dumps DMEM/IMEM and the
 * RISC-V trace ring (last executed PCs) to serial. */
/* v2.64: WPR meta копия ниже 4ГБ (единая для ВСЕХ mailbox-сайтов).
 * Ботер/LibosBootArgs читают mailbox0 как 32-битный адрес; meta на >4ГБ
 * даёт мусор (exit 0x91). Копия СВЕЖАЯ при каждом вызове (контент мог
 * обновиться между стадиями). */
static UINT64 cmp90_metaLowPhys = 0;
static UINT64
cmp90_meta_low(UINT64 wprMetaPhys)
{
    if (cmp90_metaLowPhys == 0) {
        if (EFI_ERROR(alloc_below_4g(1, &cmp90_metaLowPhys))) {
            Print(L"meta-low: alloc FAIL — использую оригинал\n");
            return wprMetaPhys;
        }
    }
    CopyMem((VOID*)(UINTN)cmp90_metaLowPhys,
            (VOID*)(UINTN)wprMetaPhys, WPR_META_SIZE);
    __asm__ volatile("wbinvd" ::: "memory");
    {
        /* v2.64: верификация контента — magic + heap + sig + flags */
        UINT64 *m = (UINT64*)(UINTN)cmp90_metaLowPhys;
        /* поля: [9]=sigAddr [10]=sigSize [15]=heapOff [16]=heapSize
         * [17]=gspFwOffset [19]=frtsOff [20]=frtsSize; flags @байт 0xB4 */
        Print(L"meta-low @0x%lx: magic ok=%d sig@0x%llx sz=0x%llx "
              L"heapOff=0x%llx heapSz=0x%llx fwOff=0x%llx flags=0x%x\n",
              cmp90_metaLowPhys,
              (m[0] == 0xDC3AAE21371A60B3ULL),
              m[9], m[10], m[15], m[16], m[17],
              *(UINT32*)((UINT8*)cmp90_metaLowPhys + 0xB4));
    }
    return cmp90_metaLowPhys;
}

/* ==================== v2.69: поллинг mbox0 ВО ВРЕМЯ исполнения ботера =====
 * Пост-halt скраб (v2.67) уничтожает IMEM/DMEM, а промежуточные коды mbox0
 * перезаписываются финальным 0x91 ещё ДО halt. Единственное окно — опрос
 * регистров в реальном времени: история изменений пишется в RAM хоста
 * (скраб туда не достаёт) с PTIMER-таймштампами. */
typedef struct {
    UINT32 t_lo, t_hi;              /* PTIMER (нс) в момент изменения */
    UINT32 cpuctl, irqstat, dbg;
    UINT32 mbox0, mbox1;
    /* v2.72: расширенный срез состояния во время исполнения ботера */
    UINT32 wpr2lo, dmatrfcmd, gspmbox0;
    UINT32 dFF4c, dFF50, d10;       /* DMEM: canary 0xff4c/0xff50 (sec) + [0x10] ns */
} CMP90_MBOX_ENT;
#define CMP90_MBOX_HIST_MAX 4096

static UINT64 cmp90_ptimer64(void)
{
    /* чтение TIME_1 защёлкивает TIME_0 — порядок как в драйвере NV */
    UINT32 hi = mmio_read32(NV_PTIMER_TIME_1);
    UINT32 lo = mmio_read32(NV_PTIMER_TIME_0);
    return ((UINT64)hi << 32) | lo;
}

/* v2.69b: проба здоровья SEC2 — липнут ли записи в блок регистров.
 * Canary пишется в безвредные MAILBOX0/DMATRFBASE, читается обратно,
 * восстанавливается. Наблюдение v2.69: к моменту ботера записи НЕ липнут
 * (mbox0=0x91 пережил наш write 0x7FB38000), ботер не исполнялся вовсе.
 * HWCFG2=0 на GA102 SEC2 — НОРМА (так и в живом unlocked-свипе). */
static void sec2_health(const CHAR16 *tag)
{
    UINT32 m0old = mmio_read32(SEC2_MAILBOX0);
    UINT32 dbold = mmio_read32(SEC2_DMATRFBASE);
    UINT32 m0wr, dbwr;

    mmio_write32(SEC2_MAILBOX0, 0xA5A5C3C3);
    m0wr = mmio_read32(SEC2_MAILBOX0);
    mmio_write32(SEC2_DMATRFBASE, 0xDEADBEEF);
    dbwr = mmio_read32(SEC2_DMATRFBASE);
    mmio_write32(SEC2_MAILBOX0, m0old);
    mmio_write32(SEC2_DMATRFBASE, dbold);
    Print(L"[health %s] hwcfg2=0x%08x cpu=0x%08x irq=0x%08x "
          L"mbox0 0x%08x->wr=0x%08x dmabase 0x%08x->wr=0x%08x "
          L"| gsp cpu=0x%08x mbox0=0x%08x\n",
          tag, mmio_read32(0x84001C), mmio_read32(SEC2_CPUCTL),
          mmio_read32(SEC2_IRQSTAT), m0old, m0wr, dbold, dbwr,
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_MAILBOX0));
}

static EFI_STATUS
booter_load_v67(UINT64 wprMetaPhys, UINT64 ucodePhys)
{
    UINT32 data;
    UINTN i;

    sec2_health(L"7-booter-entry");

    /* v64: НЕ копируем meta ниже 4ГБ (v2.63 GA102-предположение). TU102
     * booter адресует mailbox0/1 = LO32/HI32 (64-бит, kernel_gsp_booter_tu102.c);
     * cmp90_meta_low() в прологе HANG'ал (EFI alloc/CopyMem/wbinvd) — то же,
     * что v59. Meta остаётся на >4ГБ, mailbox пишется ниже 64-битно. */
    wprMetaPhys = wprMetaPhys;

    /* kflcnReset (SEC2) — обязателен перед загрузкой ucode (kgspExecuteBooterLoad):
     * ENGINE._RESET=TRUE → чтения → _FALSE → чтения.
     * ПОТОМ kflcnSwitchToFalcon: BCR CORE_SELECT=FALCON — снимает priv lockdown.
     * (v2.12: CPUCTL 0xBADF5620 → 0x10 сразу после записи BCR=1; НО если BCR
     * писать ДО ENGINE reset — reset сбрасывает BCR обратно в RISC-V+BRFETCH
     * (0x110) и lockdown возвращается. Порядок драйвера: reset → BCR!) */
    /* v2.34: kflcnPreResetWait — ждать HWCFG2 RESET_READY (bit31), как драйвер */
    for (i = 0; i < 100000; i++) {
        data = mmio_read32(0x84001C);   /* SEC2 HWCFG2 */
        if (data & 0x80000000) break;
        if (i == 99999)
            Print(L"booter: ВНИМАНИЕ RESET_READY не пришёл (HWCFG2=0x%08x)\n", data);
    }
    Print(L"booter: SEC2 HWCFG2=0x%08x (RESET_READY=bit31)\n", data);

    Print(L"booter: SEC2 reset (ENGINE 0x8403C0)...\n");
    falcon_wait_reset_ready(SEC2_HWCFG2);
    mmio_write32(SEC2_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    mmio_write32(SEC2_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    falcon_wait_scrub_done(SEC2_DMACTL, SEC2_HWCFG2, L"sec2-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);   /* дать ресету дойти до конца */

    /* v2.41: kflcnSwitchToFalcon — ТРЕЙС драйвера: BCR_CTRL=0x0 (НЕ 0x1!).
     * VALID ставит HW. (Трейс 2026-08-21: 0x841668 = 0x00000000.) */
    mmio_write32(SEC2_BCR_CTRL, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
    uefi_call_wrapper(BS->Stall, 1, 10000);

    data = mmio_read32(SEC2_CPUCTL);
    Print(L"booter: CPUCTL после BCR=0 = 0x%08x (0xBADF = lockdown не снят)\n", data);
    if ((data & 0xBADF0000) == 0xBADF0000) {
        /* запасной вариант: BCR=0x1 (как в v2.12 — тоже снимал lockdown) */
        Print(L"booter: пробую BCR=0x1...\n");
        mmio_write32(SEC2_BCR_CTRL, 0x1);
        uefi_call_wrapper(BS->Stall, 1, 10000);
        data = mmio_read32(SEC2_CPUCTL);
        Print(L"booter: CPUCTL после BCR=1 = 0x%08x\n", data);
        if ((data & 0xBADF0000) == 0xBADF0000) {
            Print(L"booter: SEC2 lockdown НЕ снят — прерываю booter load\n");
            return EFI_DEVICE_ERROR;
        }
    }

    /* ждать завершение скраббинга (DMACTL теперь читается) */
    for (i = 0; i < 100000; i++) {
        data = mmio_read32(SEC2_DMACTL);
        if ((data & 0xBADF0000) != 0xBADF0000) {
            if (!(data & 0x6)) break;   /* DMEM/IMEM scrubbing done */
        }
    }
    Print(L"booter: reset ok (dmactl=0x%x)\n", mmio_read32(SEC2_DMACTL));
    sec2_health(L"8-booter-post-reset");

    /* v2.16: WPR2 = frtsOffset (эффект FWSEC/FRTS). В рабочем флоу перед
     * booter load драйвер имеет WPR2=0x27FE00000 (сырые: lo=0x027fe000,
     * hi=0x027fee00 — из FRTS_DIAG живой системы). У нас после POST
     * WPR2=0x1FFFFE00 — booter может валидировать WPR2 и выходить. */
    Print(L"booter: WPR2 до записи: lo=0x%08x hi=0x%08x\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));
    mmio_write32(REG_PFB_MMU_WPR2_LO, 0x027fe000);
    mmio_write32(REG_PFB_MMU_WPR2_HI, 0x027fee00);
    uefi_call_wrapper(BS->Stall, 1, 10000);
    Print(L"booter: WPR2 после записи: lo=0x%08x hi=0x%08x (не изменились = заблокировано)\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));

    /* kflcnDisableCtxReq: FBIF_CTL ALLOW_PHYS_NO_CTX + DMACTL=0 */
    data = mmio_read32(SEC2_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(SEC2_FBIF_CTL, data);
    data = mmio_read32(SEC2_FBIF_CTL);
    if ((data & 0xBADF0000) == 0xBADF0000)
        Print(L"booter: ВНИМАНИЕ FBIF_CTL всё ещё залочен (0x%08x)\n", data);
    mmio_write32(SEC2_DMACTL, 0);

    /* v2.41: RM = chipId0 — из ТРЕЙСА драйвера: 0xb72000a1 (НЕ PMC_BOOT_0!).
     * kflcnReset_TU102: kflcnRegWrite(RM, pGpu->chipId0). */
    mmio_write32(SEC2_RM, 0xb72000a1);
    Print(L"booter: RM записан = 0xb72000a1 (chipId0 из трейса драйвера)\n");

    /* TRANSCFG(0): TARGET=COHERENT_SYSMEM(1) | MEM_TYPE=PHYSICAL(1<<2)
     * (нужен и для внутреннего DMA booter'а при чтении WPR meta) */
    data = mmio_read32(SEC2_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(SEC2_FBIF_TRANSCFG0, data);

    /* v2.21: ТЕСТ доступности DMATRF (запись+readback). v2.17: DMA «не
     * передал» (IMEM=DEAD5EC1 через НЕ-secure порт) — но SEC=1 передача
     * могла писать в SECURE IMEM (невидимый не-secure чтению), а блобы тогда
     * были мусором (до --redefine-sym). Теперь блобы настоящие. */
    Print(L"booter: DMATRFBASE до = 0x%08x\n", mmio_read32(SEC2_DMATRFBASE));
    mmio_write32(SEC2_DMATRFBASE, 0xDEADBEEF);
    Print(L"booter: DMATRFBASE после = 0x%08x (DEADBEEF = пишется; 0xBADF = залочен)\n",
          mmio_read32(SEC2_DMATRFBASE));

    /* v2.71b comment retained; v55: TU102 (nv616) geometry replaces the GA102
     * numbers here — see BOOTER_* defines above. IMEM = image[0x100..0x8500)
     * (0x8400 B, SEC=1), DMEM = image[0x8500..0xE700) (0x6200 B, SEC=0);
     * signature patch site image[0x8700] lands on DMEM[0x200]=hsSigDmemAddr. */
    Print(L"booter: DMA IMEM SEC=1 (dest=0, src+0x100, 0x8400 байт)...\n");
    falcon_dma_transfer(0, BOOTER_APP_CODE_OFFSET, ucodePhys,
                        BOOTER_APP_CODE_SIZE,
                        0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"booter: DMA DMEM SEC=0 (dest=0, src+0x8500, 0x6200 байт)...\n");
    falcon_dma_transfer(0, 0, ucodePhys + BOOTER_OS_DATA_OFFSET,
                        BOOTER_OS_DATA_SIZE,
                        0 | (6 << 8) | (0 << 12));
    mmio_write32(SEC2_DMEMC0, BOOTER_HS_SIG_DMEM_ADDR);
    Print(L"booter: DMEM[0x%x]=0x%08x (ожидаю sig @image+0x%x = 0x%08x)\n",
          BOOTER_HS_SIG_DMEM_ADDR, mmio_read32(SEC2_DMEMD0),
          BOOTER_SIG_PATCH_LOC,
          *(UINT32*)((UINTN)ucodePhys + BOOTER_SIG_PATCH_LOC));

    /* PKC (RSA3K) параметры */
    mmio_write32(SEC2_BROM_PARAADDR0, BOOTER_HS_SIG_DMEM_ADDR);
    mmio_write32(SEC2_BROM_ENGIDMASK, BOOTER_ENGINE_ID_MASK);
    mmio_write32(SEC2_BROM_CURR_UCODE_ID, BOOTER_UCODE_ID);
    data = mmio_read32(SEC2_MOD_SEL);
    data = (data & ~0xFF) | 0x1;   /* RSA3K */
    mmio_write32(SEC2_MOD_SEL, data);

    /* BOOTVEC=0x100 (из ТРЕЙСА драйвера!) + mailboxes (WPR meta phys) + start */
    mmio_write32(SEC2_BOOTVEC, 0x100);
    mmio_write32(SEC2_MAILBOX0, (UINT32)(wprMetaPhys & 0xFFFFFFFF));
    mmio_write32(SEC2_MAILBOX1, (UINT32)((wprMetaPhys >> 32) & 0xFFFFFFFF));

    /* копируем booter ucode в кэш-безопасную область: DMA из sysmem идёт напрямую,
     * поэтому flush кэша перед стартом обязателен */
    __asm__ volatile("wbinvd" ::: "memory");

    /* v2.82: ВКЛЮЧАЕМ RISC-V ТРАССИРОВКУ до старта (dev_riscv_pri.h):
     * TRACECTL(+0x400): MMODE_ENABLE(bit23) + MODE=FULL(25:24=0) +
     * дефолтные пороги HIGH_THSHD=0xFF/LOW_THSHD=0x00.
     * После halt кольцо RDIDX/WTIDX(+404/+408) отдаст последние PC! */
    mmio_write32(NV_FALCON2_SEC_BASE + 0x400, 0x10B0FF00);

    /* старт CPU */
    mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    Print(L"booter: CPU started, v2.72 deep-poll...\n");

    /* v2.72: расширенный поллинг ВО ВРЕМЯ исполнения ботера. Быстрый набор
     * (mbox0/IRQSTAT/CPUCTL/DEBUGINFO) — каждую итерацию; медленный срез
     * (WPR2, DMATRFCMD, GSP mbox0, DMEM canary 0xff4c/0xff50 ns|sec,
     * DMEM[0x10] ns) — каждую 32-ю итерацию. Запись в историю: любое
     * изменение ИЛИ каждые 256 итераций (временные ряды). */
    {
        CMP90_MBOX_ENT *hist = NULL;
        UINTN hist_n = 0;
        UINT64 t0 = cmp90_ptimer64();
        UINT32 pm0 = mmio_read32(SEC2_MAILBOX0);
        UINT32 pir = mmio_read32(SEC2_IRQSTAT);
        UINT32 pcu = mmio_read32(SEC2_CPUCTL);
        UINT32 pdg = mmio_read32(SEC2_DEBUGINFO);
        UINT32 pw2 = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 pdm = mmio_read32(SEC2_DMATRFCMD);
        UINT32 pgm = mmio_read32(GSP_MAILBOX0);
        UINT32 pd4n, pd4s, pd5n, pd5s, pd10;
        BOOLEAN plmOpen = FALSE, halted = FALSE;
        UINT64 elapsed;
        UINTN j, it = 0, lastRec = 0;

        uefi_call_wrapper(BS->AllocatePool, 3, EfiBootServicesData,
                          CMP90_MBOX_HIST_MAX * sizeof(CMP90_MBOX_ENT),
                          (VOID **)&hist);

#define CMP90_DREAD(addr, sec) ({ \
    mmio_write32(SEC2_DMEMC0, (addr) | ((sec) ? (1u << 28) : 0)); \
    mmio_read32(SEC2_DMEMD0); })
        pd4n = CMP90_DREAD(0xFF4C, 0); pd4s = CMP90_DREAD(0xFF4C, 1);
        pd5n = CMP90_DREAD(0xFF50, 0); pd5s = CMP90_DREAD(0xFF50, 1);
        pd10 = CMP90_DREAD(0x10, 0);

        Print(L"booter: baseline m0=0x%08x irq=0x%x cpu=0x%x dbg=0x%x "
              L"w2=0x%08x dma=0x%08x gsp=0x%08x d[ff4c]=%08x/%08x "
              L"d[ff50]=%08x/%08x d[10]=%08x\n",
              pm0, pir, pcu, pdg, pw2, pdm, pgm, pd4n, pd4s, pd5n, pd5s, pd10);

        /* v2.77: трассировка исполнения через RISC-V wtidx (FALCON2+0x408):
         * индекс растёт, пока ботер исполняется; замирание = точка смерти.
         * MMIO-чит ~0.65мс, поэтому поллим только wtidx; mbox0/halt — реже.
         * После остановки — обход кольца назад даёт последние PC! */
        {
            UINT32 lastWt = mmio_read32(NV_FALCON2_SEC_BASE + 0x408);
            UINTN stable = 0;
            for (it = 0; it < 200000; it++) {
                UINT32 wt = mmio_read32(NV_FALCON2_SEC_BASE + 0x408);
                if (wt != lastWt) {
                    if (hist && hist_n < CMP90_MBOX_HIST_MAX &&
                        (it - lastRec) >= 24) {
                        UINT64 t = cmp90_ptimer64();
                        hist[hist_n].t_lo = (UINT32)t;
                        hist[hist_n].t_hi = (UINT32)(t >> 32);
                        hist[hist_n].cpuctl = mmio_read32(SEC2_CPUCTL);
                        hist[hist_n].irqstat = mmio_read32(SEC2_IRQSTAT);
                        hist[hist_n].dbg = mmio_read32(SEC2_DEBUGINFO);
                        hist[hist_n].mbox0 = mmio_read32(SEC2_MAILBOX0);
                        hist[hist_n].mbox1 = mmio_read32(SEC2_MAILBOX1);
                        hist[hist_n].wpr2lo = pw2;
                        hist[hist_n].dmatrfcmd = pdm;
                        hist[hist_n].gspmbox0 = pgm;
                        hist[hist_n].dFF4c = wt;      /* wtidx в момент среза */
                        hist[hist_n].dFF50 = pd5s;
                        hist[hist_n].d10 = pd10;
                        hist_n++;
                        lastRec = it;
                    }
                    lastWt = wt; stable = 0;
                } else {
                    stable++;
                    if (stable >= 6) break;   /* исполнение замерло */
                }
                if ((it & 7) == 7) {
                    UINT32 irx = mmio_read32(SEC2_IRQSTAT);
                    if (irx & 0x10) { pir = irx; halted = TRUE; break; }
                    if ((it & 31) == 31 &&
                        mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                        plmOpen = TRUE; break;
                    }
                }
            }
        }
        /* фаза B: редкий опрос до 5с (halt/PLM/mbox) */
        for (;;) {
            UINT32 ir = mmio_read32(SEC2_IRQSTAT);
            UINT32 m0;
            if (ir & 0x10) { pir = ir; halted = TRUE; break; }
            m0 = mmio_read32(SEC2_MAILBOX0);
            if (m0 != pm0) {
                if (hist && hist_n < CMP90_MBOX_HIST_MAX) {
                    UINT64 t = cmp90_ptimer64();
                    hist[hist_n].t_lo = (UINT32)t;
                    hist[hist_n].t_hi = (UINT32)(t >> 32);
                    hist[hist_n].mbox0 = m0;
                    hist[hist_n].irqstat = ir;
                    hist[hist_n].dbg = mmio_read32(SEC2_DEBUGINFO);
                    hist[hist_n].cpuctl = mmio_read32(SEC2_CPUCTL);
                    hist[hist_n].mbox1 = mmio_read32(SEC2_MAILBOX1);
                    hist[hist_n].wpr2lo = pw2;
                    hist[hist_n].dmatrfcmd = pdm;
                    hist[hist_n].gspmbox0 = pgm;
                    hist[hist_n].dFF4c = pd4s;
                    hist[hist_n].dFF50 = pd5s;
                    hist[hist_n].d10 = pd10;
                    hist_n++;
                }
                pm0 = m0;
            }
            if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                plmOpen = TRUE; break;
            }
            elapsed = cmp90_ptimer64() - t0;
            if (elapsed > 5000000000ULL) break;
            uefi_call_wrapper(BS->Stall, 1, 1000);
        }
#undef CMP90_DREAD

        elapsed = cmp90_ptimer64() - t0;
        Print(L"booter: hist %u записей за %u.%03u мс, iters=%u (%s)\n",
              (UINT32)hist_n,
              (UINT32)(elapsed / 1000000ULL),
              (UINT32)((elapsed / 1000ULL) % 1000ULL),
              (UINT32)it,
              plmOpen ? L"PLM OPEN" : halted ? L"HALT" : L"таймаут 5с");
        for (j = 0; j < hist_n; j++) {
            UINT64 tj = ((UINT64)hist[j].t_hi << 32) | hist[j].t_lo;
            UINT64 d = tj - t0;
            if (hist_n > 240 && j == 120) {
                Print(L"  ... пропущено %u записей ...\n", (UINT32)(hist_n - 240));
                j = hist_n - 121;   /* после j++ продолжим с n-120 */
            }
            Print(L"  hist[%03u] +%u.%03uмс cpu=0x%08x irq=0x%08x dbg=0x%08x "
                  L"m0=0x%08x w2=0x%08x dma=0x%08x gsp=0x%08x "
                  L"d[ff4c]=%08x d[ff50]=%08x d[10]=%08x\n",
                  (UINT32)j,
                  (UINT32)(d / 1000000ULL), (UINT32)((d / 1000ULL) % 1000ULL),
                  hist[j].cpuctl, hist[j].irqstat, hist[j].dbg,
                  hist[j].mbox0, hist[j].wpr2lo, hist[j].dmatrfcmd,
                  hist[j].gspmbox0, hist[j].dFF4c, hist[j].dFF50,
                  hist[j].d10);
        }
        Print(L"booter: финал: cpu=0x%x irq=0x%x dbg=0x%x m0=0x%08x m1=0x%08x\n",
              mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_IRQSTAT),
              mmio_read32(SEC2_DEBUGINFO),
              mmio_read32(SEC2_MAILBOX0), mmio_read32(SEC2_MAILBOX1));

        if (plmOpen) {
            Print(L"booter: PLM OPEN (cpu_ctl=0x%x irq=0x%x mbox0=0x%x)\n",
                  mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_IRQSTAT),
                  mmio_read32(SEC2_MAILBOX0));
            if (hist) uefi_call_wrapper(BS->FreePool, 1, hist);
            return EFI_SUCCESS;
        }
        if (hist) uefi_call_wrapper(BS->FreePool, 1, hist);
    }

    /* v2.67: ДМП DMEM ботера после halt — его рабочее состояние!
     * 0x00-0x1F: сигнатура (hsSigDmemAddr=0x10); дальше — переменные. */
    Print(L"booter: === DMEM DUMP (0x000-0x1FF, ns|sec) ===\n");
    {
        UINTN a;
        for (a = 0; a < 0x200; a += 4) {
            UINT32 vn, vs;
            mmio_write32(SEC2_DMEMC0, a);
            vn = mmio_read32(SEC2_DMEMD0);
            mmio_write32(SEC2_DMEMC0, a | (1 << 28));
            vs = mmio_read32(SEC2_DMEMD0);
            Print(L"booter: dmem %04x: %08x %08x\n", a, vn, vs);
        }
    }
    /* v2.67: IMEM первые 0x100 байт — доставился ли код? (шифртекст или скраб) */
    Print(L"booter: === IMEM DUMP (0x000-0x0FF, ns|sec) ===\n");
    {
        UINTN a;
        for (a = 0; a < 0x100; a += 4) {
            UINT32 vn, vs;
            mmio_write32(SEC2_IMEMC0, a);
            vn = mmio_read32(SEC2_IMEMD0);
            mmio_write32(SEC2_IMEMC0, a | (1 << 28));
            vs = mmio_read32(SEC2_IMEMD0);
            Print(L"booter: imem %04x: %08x %08x\n", a, vn, vs);
        }
    }

    /* v2.16: дамп RISC-V trace — где остановился booter (диагностика) */
    {
        UINTN t;
        UINT32 rdidx, wtidx;

        Print(L"booter: riscv: cpuctl=0x%x tracectl=0x%x rdidx=0x%x wtidx=0x%x bcr=0x%x\n",
              mmio_read32(NV_FALCON2_SEC_BASE + 0x388),
              mmio_read32(NV_FALCON2_SEC_BASE + 0x400),
              mmio_read32(NV_FALCON2_SEC_BASE + 0x404),
              mmio_read32(NV_FALCON2_SEC_BASE + 0x408),
              mmio_read32(NV_FALCON2_SEC_BASE + 0x668));
        rdidx = mmio_read32(NV_FALCON2_SEC_BASE + 0x404) & 0xFF;
        wtidx = mmio_read32(NV_FALCON2_SEC_BASE + 0x408) & 0xFF;
        Print(L"booter: trace rdidx=%d wtidx=%d (0xBADF = riscv блок залочен)\n",
              rdidx, wtidx);
        for (t = 0; t < 16; t++) {
            UINT32 idx = (wtidx + 0x100 - t) & 0xFF;
            UINT32 pcLo, pcHi;
            mmio_write32(NV_FALCON2_SEC_BASE + 0x404, idx);
            pcLo = mmio_read32(NV_FALCON2_SEC_BASE + 0x40C);
            pcHi = mmio_read32(NV_FALCON2_SEC_BASE + 0x410);
            Print(L"booter: trace[-%d] pc=0x%x%08x\n", t, pcHi, pcLo);
        }
    }
    return EFI_TIMEOUT;
}

/* ==== EARLY PATH — run the booter FIRST, on a fresh SEC2 (MAIN PATH) ====
 * Measured behaviour: only the FIRST booter start after POST actually
 * executes — afterwards the SEC2 register block wedges (writes stop
 * sticking, engine reset does NOT heal) and every later attempt runs a
 * corpse. Release order is therefore: BL(GSP) -> FWSEC(GSP) sets WPR2
 * -> ResetIntoRiscv + LibosBootArgs -> booter_load_v67 immediately.
 * Диагностика v2.69b (canary-пробы [health]): ПЕРВЫЙ же старт ботера на SEC2
 * (v251 шаг [3]) исполняется (dbg 0x8C00FF→0xDA550000), пишет mbox0=0x91 —
 * и КЛИНИТ блок регистров SEC2: записи больше не липнут, engine reset НЕ
 * лечит. Все последующие попытки (включая главный booter_load_v67) исполняли
 * «труп» и читали чужой 0x91. Новый порядок: BL(GSP) → FWSEC(GSP) → WPR2 →
 * ResetIntoRiscv+libos args → booter_load_v67 на ЖИВОМ SEC2 (поллинг v2.69). */
/* =====================================================================
 * v56: TU102 BOOT_DIRECT booter loader —— 完全按 OpenRM 610.43.03 驱动
 * （kernel_gsp_booter_tu102.c / kernel_gsp_falcon_tu102.c）复刻。
 *
 * 关键点（与 90HX/GA102 的 DMA 装载完全不同！）：
 *  - Turing 的 SEC2/GSP falcon 是 **BOOT_DIRECT**（kgspExecuteHsFalcon_TU102
 *    断言 !bBootFromHs；s_allocateUcodeFromBinArchive 选 BOOT_DIRECT 分支），
 *    装载走 **IMEMC/IMEMD + IMEMT 块 tag 端口**（不是 DMATRF DMA）。
 *  - s_prepareHsFalconDirect()：
 *      kflcnDisableCtxReq (FBIF_CTL bit7 + DMACTL=0)
 *      IMEM NS : dst=0x000 src=image+imemNsPa(0x0)   size=imemNsSize(0x100)  SEC=0 tag=0
 *      IMEM SEC: dst=0x100 src=image+imemSecPa(0x100) size=imemSecSize(0x8400) SEC=1 tag=1
 *      DMEM    : dst=0     src=image+dataOffset(0x8500) size=dmemSize(0x6200)（签名已 patch）
 *      **BOOTVEC = 0**（GA102 才是 0x100 —— v55 用错值！）
 *  - kflcnReset_TU102 写 RM = pGpu->chipId0；chipId0 = 原始 NV_PMC_BOOT_0
 *    （gpu_mgr.c: osDevReadReg032(NV_PMC_BOOT_0)），40HX = 0x166000A1，
 *    不是 GA102 的 0xb72000a1（v55 也用错值）。
 *  - 启动：MAILBOX0/1 = WPR meta 物理地址，STARTCPU=2，等 HALT，mbox0==0 成功。
 * ===================================================================== */

/* IMEM 端口装载：AINCW=1 + 每 256B(64 word) 打一次 IMEMT tag */
static void
u40x_imem_write(UINT32 dst, BOOLEAN sec, const UINT32 *src,
                UINT32 sizeBytes, UINT32 virtAddr)
{
    UINT32 words = sizeBytes >> 2;
    UINT32 tag = virtAddr >> 8;
    UINT32 i;

    mmio_write32(SEC2_IMEMC0,
                 (dst & 0xFFFFFCu) | (1u << 24) | (sec ? (1u << 28) : 0u));
    for (i = 0; i < words; i++) {
        if ((i & 63u) == 0u) {
            mmio_write32(SEC2_IMEMT0, tag & 0xFFFFu);
            tag++;
        }
        mmio_write32(SEC2_IMEMD0, src[i]);
    }
}

/* DMEM 端口装载：AINCW=1，连续写 DMEMD */
static void
u40x_dmem_write(UINT32 dst, const UINT32 *src, UINT32 sizeBytes)
{
    UINT32 words = sizeBytes >> 2;
    UINT32 i;

    mmio_write32(SEC2_DMEMC0, (dst & 0xFFFFFCu) | (1u << 24));
    for (i = 0; i < words; i++)
        mmio_write32(SEC2_DMEMD0, src[i]);
}

#define SEC2_RESET_PLM_REG      0x008403C4UL  /* SEC2 RESET_PRIV_LEVEL_MASK (cyridd CMP40_SEC2_RESET_PLM) */

/* =====================================================================
 * v58（参考 cmpunlocker 0001 patch 后重写装载器入口）：
 *   驱动 exploit 运行在 FWSEC 后 **已经 halted 的 SEC2** 上，_kgspCmp40
 *   ExecuteBooterFreshMeta → kgspExecuteBooterLoad 的 native-probe 路径
 *   **不再做 engine reset**（reset 会把 RESET_PLM 从 0xff 改成 0x8f 且被
 *   驱动判死）。因此 v58 先试 attempt A = 不复位直接端口装载+启动（驱动同款）；
 *   若未得 mbox0==0 再 attempt B = engine reset 版（v56/57 同款）兜底。
 *   前置探测打印 RESET_PLM/WPR2，对照驱动 CMP40_STOCKFLOW_V551 判定。
 * ===================================================================== */
static EFI_STATUS
booter_load_tu102_direct(UINT64 wprMetaPhys, UINT64 ucodePhys)
{
    UINT8 *img = (UINT8 *)(UINTN)ucodePhys;
    UINT64 metaLow = 0;
    UINT32 data;
    UINT32 cpu = 0, dbg = 0, irq = 0, m0 = 0, m1 = 0;
    UINTN attempt;
    UINTN i;

    Print(L"\n=== v67: TU102 BOOT + 40HX FWSEC (BCR=1, port-load code) ===\n");
    /* v60: pre 探测逐寄存器单发读（每行只读已证安全的寄存器；读挂时日志
     * 能精确定位）。RESET_PLM(0x8403C4) 在 kill-GFW 后的裸 SEC2 上读取会
     * 挂死（v59 实测：日志停在调用点，pre 参数求值阶段卡死）——故从 pre
     * 与 RESULT 探测中移除，改由 attempt 后 WPR2/SS 判定。 */
    Print(L"tu102 pre: hwcfg2...\n");
    data = mmio_read32(SEC2_HWCFG2);
    Print(L"tu102 pre:   hwcfg2=0x%08x\n", data);
    Print(L"tu102 pre: cpuctl/dmatrf...\n");
    data = mmio_read32(SEC2_CPUCTL);
    Print(L"tu102 pre:   cpuctl=0x%08x\n", data);
    data = mmio_read32(SEC2_DMATRFCMD);
    Print(L"tu102 pre:   dmatrf=0x%08x\n", data);
    Print(L"tu102 pre: wpr2...\n");
    data = mmio_read32(REG_PFB_MMU_WPR2_HI);
    Print(L"tu102 pre:   wpr2hi=0x%08x\n", data);
    data = mmio_read32(REG_PFB_MMU_WPR2_LO);
    Print(L"tu102 pre:   wpr2lo=0x%08x\n", data);
    /* v62: 尝试把 WPR2 拉 up（40HX 8GB 值，log53 真解 dmesg：
     * POST_FWSEC_PRE_GSP_ENTRY WPR=01ffee00:01ffe000）。90HX 参考
     * (unlock_v2.c v2.16) booter 前显式写 WPR2=frtsOffset；
     * REFERENCE_FLOW §3.1 推论 1：booter 可能校验 WPR2 后退出(=0x91)。
     * host 直写可能被锁——写后读回验证并打印结果。 */
    Print(L"tu102 v62: set WPR2 up (lo=0x01ffe000 hi=0x01ffee00)...\n");
    mmio_write32(REG_PFB_MMU_WPR2_LO, 0x01ffe000u);
    mmio_write32(REG_PFB_MMU_WPR2_HI, 0x01ffee00u);
    __asm__ volatile("wbinvd" ::: "memory");
    uefi_call_wrapper(BS->Stall, 1, 5000);
    Print(L"tu102 v62: rb wpr2hi=0x%08x wpr2lo=0x%08x\n",
          mmio_read32(REG_PFB_MMU_WPR2_HI), mmio_read32(REG_PFB_MMU_WPR2_LO));
    Print(L"tu102 v62: read SEC2_RESET_PLM(0x8403C4)...\n");
    data = mmio_read32(SEC2_RESET_PLM_REG);
    Print(L"tu102 v62:   reset_plm=0x%08x (cyridd 期望 0xff)\n", data);

    for (attempt = 0; attempt < 2; attempt++) {
        BOOLEAN bReset = (attempt == 1);
        UINT32 rbNs = 0, rbSec = 0;

        Print(L"\n--- tu102 attempt %d/%d: %s ---\n", (INTN)attempt + 1, 2,
              bReset ? L"engine-reset" : L"no-reset (driver-style)");

        /* 准备引擎（A: 不加复位——驱动 exploit 用 FWSEC 后 halted 的引擎；
         *  B: kflcnReset_TU102 = pre-wait→reset→scrub wait→BCR=0→RM=chipId0） */
        if (bReset) {
            Print(L"tu102: B-reset: pre-wait hwcfg2...\n");
            for (i = 0; i < 100000; i++) {
                data = mmio_read32(SEC2_HWCFG2);
                if (data & 0x80000000u)
                    break;
            }
            Print(L"tu102: B-reset: ENGINE reset...\n");
            mmio_write32(SEC2_ENGINE, 0x1);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            mmio_write32(SEC2_ENGINE, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            falcon_wait_scrub_done(SEC2_DMACTL, SEC2_HWCFG2, L"tu102-reset");
            uefi_call_wrapper(BS->Stall, 1, 50000);
            mmio_write32(SEC2_BCR_CTRL, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            uefi_call_wrapper(BS->Stall, 1, 10000);
            Print(L"tu102: B-reset: RM=chipId0...\n");
            mmio_write32(SEC2_RM, 0x162000A1u);   /* chipId0 = PMC_BOOT_0(40HX) */
            Print(L"tu102: B-reset: readback cpuctl...\n");
            cpu = mmio_read32(SEC2_CPUCTL);
            Print(L"tu102: B-reset: readback hwcfg2...\n");
            data = mmio_read32(SEC2_HWCFG2);
            Print(L"tu102: reset done RM=0x162000A1 CPUCTL=0x%x HWCFG2=0x%x\n",
                  cpu, data);
        } else {
            Print(L"tu102: A-no-reset: read cpuctl...\n");
            cpu = mmio_read32(SEC2_CPUCTL);
            Print(L"tu102:   cpuctl=0x%x (halted?=%d)\n", cpu,
                  (cpu & NV_PFALCON_FALCON_CPUCTL_HALTED_TRUE) ? 1 : 0);
        }

        /* kflcnDisableCtxReq */
        data = mmio_read32(SEC2_FBIF_CTL);
        data |= (1u << 7);
        mmio_write32(SEC2_FBIF_CTL, data);
        mmio_write32(SEC2_DMACTL, 0);

        /* IMEM/DMEM 端口装载（签名已由主线 patch 到 image+0x8700 = DMEM+0x200） */
        Print(L"tu102: port load IMEM ns+sec + DMEM...\n");
        u40x_imem_write(0x000u, FALSE, (const UINT32 *)(img + 0x0u), 0x100u, 0x0u);
        u40x_imem_write(0x100u, TRUE, (const UINT32 *)(img + 0x100u), 0x8400u, 0x100u);
        u40x_dmem_write(0x0u, (const UINT32 *)(img + 0x8500u), 0x6200u);
        __asm__ volatile("wbinvd" ::: "memory");

        /* readback 校验 */
        mmio_write32(SEC2_IMEMC0, 0x0u);
        rbNs = mmio_read32(SEC2_IMEMD0);
        mmio_write32(SEC2_IMEMC0, 0x100u | (1u << 28));
        rbSec = mmio_read32(SEC2_IMEMD0);
        mmio_write32(SEC2_DMEMC0, 0x200u);
        Print(L"tu102: rb IMEM[0]=0x%08x(exp 0x%08x) IMEM_S[0x100]=0x%08x "
              L"DMEM[0x200]=0x%08x(exp sig 0x%08x)\n",
              rbNs, *(UINT32 *)(img + 0x0u), rbSec, mmio_read32(SEC2_DMEMD0),
              *(UINT32 *)(img + 0x8700u));

        /* BOOTVEC=0（TU102 BOOT_DIRECT） */
        /* v61: meta 直传 >4GB 原址（wprMetaPhys），**不做 low-copy**。
         * 驱动 kgspExecuteBooterLoad_TU102: mailbox0/1 = LO32/HI32(sysmemAddr)
         * = 64 位寻址，meta 由 RM memdesc 分配在 >4GB（实测 0x110BB0000）。
         * v55 的 cmp90_meta_low(<4GB) 是 90HX/GA102 老假设；TU102 锁卡上
         * <4GB 读反而被锁（869 行 v2.63 注释：exit 0x91）。 */
        Print(L"tu102: mailbox=wprMetaPhys>4G (no low copy)...\n");
        metaLow = wprMetaPhys;
        Print(L"tu102: BOOTVEC=0, mailbox0=0x%08x mailbox1=0x%08x, STARTCPU...\n",
              (UINT32)(metaLow & 0xFFFFFFFFu), (UINT32)(metaLow >> 32));
        mmio_write32(SEC2_BOOTVEC, 0x0u);
        mmio_write32(SEC2_MAILBOX0, (UINT32)(metaLow & 0xFFFFFFFFu));
        mmio_write32(SEC2_MAILBOX1, (UINT32)(metaLow >> 32));
        __asm__ volatile("wbinvd" ::: "memory");
        mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
        Print(L"tu102: started; hold 3s WITHOUT reg reads (v57 lesson)\n");
        uefi_call_wrapper(BS->Stall, 1, 3000000);

        /* 稀疏单发读（每步先打点再读——读挂时日志能定位） */
        Print(L"tu102: read#1 cpu...\n");
        cpu = mmio_read32(SEC2_CPUCTL);
        Print(L"tu102:   cpu=0x%x\n", cpu);
        uefi_call_wrapper(BS->Stall, 1, 1000000);
        Print(L"tu102: read#2 irq...\n");
        irq = mmio_read32(SEC2_IRQSTAT);
        Print(L"tu102:   irq=0x%x\n", irq);
        Print(L"tu102: read#3 dbg...\n");
        dbg = mmio_read32(SEC2_DEBUGINFO);
        Print(L"tu102:   dbg=0x%x\n", dbg);
        Print(L"tu102: read#4 mbox...\n");
        m0  = mmio_read32(SEC2_MAILBOX0);
        m1  = mmio_read32(SEC2_MAILBOX1);
        Print(L"tu102:   m0=0x%x m1=0x%x\n", m0, m1);
        Print(L"tu102: RESULT: PLM=0x%08x SS0=0x%08x SS1=0x%08x\n",
              mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(REG_FEAT_OVR_SM_SPD),
              mmio_read32(REG_FEAT_OVR_SM_SPD_1));
        Print(L"tu102: RESULT: WPR2=0x%08x:0x%08x\n",
              mmio_read32(REG_PFB_MMU_WPR2_HI), mmio_read32(REG_PFB_MMU_WPR2_LO));

        if (m0 == 0u) {
            Print(L"tu102: *** mbox0=0 → booter OK (attempt %d) ***\n",
                  (INTN)attempt + 1);
            return EFI_SUCCESS;
        }
        Print(L"tu102: attempt %d not-OK (m0=0x%x halted=%d)\n",
              (INTN)attempt + 1, m0,
              (cpu & NV_PFALCON_FALCON_CPUCTL_HALTED_TRUE) ? 1 : 0);
        if (attempt == 0) {
            Print(L"tu102: -> retry with engine reset (attempt B)\n");
            continue;
        }
        break;
    }
    return EFI_DEVICE_ERROR;
}

static EFI_STATUS
early_unlock_path(UINT64 ucodePhys, UINT64 fwsecPhys, UINT64 wprMetaPhys)
{
    UINTN i;

    Print(L"\n=== v2.70: ранний путь — ботер ПЕРВЫЙ на свежем SEC2 ===\n");

    /* --- [E1] BL (ucodeId=1) на GSP — открывает secure-путь (урок v2.62b).
     *        Дословная копия стадии [1/3] v2.46 (эмпирически рабочая). --- */
    Print(L"[E1] GSP BL ucodeId=1 (IMEM 0x4000/DMEM 0x2400)...\n");
    mmio_write32(0x110080, 0x0);          /* из трейса (IRQMSET=0) */
    falcon_wait_reset_ready(GSP_HWCFG2);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(GSP_BCR, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, 0xb72000a1);
    mmio_write32(GSP_DMACTL, 0x0);
    gsp_dma_transfer(0, 0x100, ucodePhys, 0x4000,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    gsp_dma_transfer(0, 0, ucodePhys + 0x4100, 0x2400,
                     0 | (6 << 8) | (0 << 12));
    {
        /* сигнатура для DMEM[0x1F10]: src[0x4100+0x1F10=0x6010] ← sig(0x8A10) */
        UINT8 *img = (UINT8*)(UINTN)ucodePhys;
        CopyMem(img + 0x6010, img + 0x8A10, 0x180);
    }
    mmio_write32(GSP_BROM_PARAADDR0, 0x1F10);
    mmio_write32(GSP_BROM_ENGIDMASK, 0x400);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, 1);
    mmio_write32(GSP_MOD_SEL, 0x1);
    mmio_write32(GSP_MAILBOX0, 0xFE);     /* из трейса: 0x110040 = 0xfe */
    mmio_write32(GSP_BOOTVEC, 0x100);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, 2);          /* STARTCPU */
    mmio_write32(GSP_BCR, 0x111);         /* RISCV+BRFETCH после старта */
    uefi_call_wrapper(BS->Stall, 1, 1000000);
    Print(L"[E1] после BL: cpuctl=0x%x dbg=0x%x mbox0=0x%x bcr=0x%x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
          mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_BCR));

    /* --- [E2] FWSEC на GSP → WPR2 (fwsec_boot_gsp сам ресетит GSP) --- */
    Print(L"[E2] FWSEC на GSP (WPR2)...\n");
    CopyMem((VOID*)(UINTN)fwsecPhys, fwsec_ga102_bin, FWSEC_SIZE);
    if (!fwsec_boot_gsp(fwsecPhys)) {
        Print(L"[E2] WPR2 не встал — ранний путь не удался\n");
        return EFI_DEVICE_ERROR;
    }

    /* --- [E3] ResetIntoRiscv + LibosBootArgs.
     * v2.80: ТОЧНАЯ реплика kflcnResetIntoRiscv_GA102: PreResetWait →
     * ResetHw → WaitForResetToFinish (HWCFG2 bit31 — у GSP он РАБОТАЕТ,
     * в отличие от SEC2!) → ProgramBcr(RISCV|VALID|BRFETCH=0x111).
     * Раньше пропускали Wait → GSP оставался ЗАЛОЧЕННЫМ (BADF5620 на пробе
     * E4), а на живой карте SNAP-B даёт gsp cpuctl=0x10 на входе ботера! */
    Print(L"[E3] ResetIntoRiscv(GSP) + libos args...\n");
    falcon_wait_reset_ready(GSP_HWCFG2);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    for (i = 0; i < 100000; i++) {
        if (mmio_read32(GSP_HWCFG2) & 0x80000000) break;
        if (i == 99999)
            Print(L"[E3] ВНИМАНИЕ: GSP RESET_READY не пришёл\n");
    }
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(GSP_BCR, 0x111);
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    Print(L"[E3] GSP BCR=0x%x hwcfg2=0x%08x cpu=0x%08x\n",
          mmio_read32(GSP_BCR), mmio_read32(GSP_HWCFG2),
          mmio_read32(GSP_CPUCTL));
    mmio_write32(GSP_MAILBOX0, (UINT32)cmp90_meta_low(wprMetaPhys));
    mmio_write32(GSP_MAILBOX1, (UINT32)(cmp90_meta_low(wprMetaPhys) >> 32));

    sec2_health(L"E4-pre-booter");

    /* --- [E5] БОТЕР — ПЕРВАЯ попытка на СВЕЖЕМ SEC2.
     *        Свежая копия образа (патч 0x6010 от BL-шага затирался бы
     *        в DMEM-окне ботера 0x5000..0x9D00). --- */
    CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);
    return booter_load_v67(wprMetaPhys, ucodePhys);
}

/* ==== FALLBACK A: full replay of the kernel driver's 3-stage init ====
 * [1] GSP booter load (ucodeId=1, sizes from live trace) -> [2] MODIFIED
 * FWSEC (frts=0x10000000) as a discriminator (our code ran => WPR2 lands
 * at 0x100000 instead of 0x27FE000) -> [3] probes + SEC2 booter load
 * with correct sizes, DMA vs ports, plus a GSP-direct attempt.
 * Legacy fallback ladder member — early_unlock_path() supersedes it.
 * Идея пользователя: «вывалить на GPU то, что шлёт патченный драйвер».
 * Из полного трейса (V2-41) драйвер 610.43.03 при инициализации делает ТРИ
 * загрузки в строгом порядке:
 *   1) GSP ucodeId=1 (booter): BCR=0, RM=chipId0(0xb72000a1), DMACTL=0,
 *      IMEM 0x4000 SEC=1 (источник src+0x100 — пропуск заголовка образа!),
 *      DMEM 0x2400 SEC=0 (источник src+0x4100), PARAADDR0=0x1F10,
 *      ENGIDMASK=0x400, UCODE_ID=1, MOD_SEL=1, MAILBOX0=0xFE,
 *      BOOTVEC=0x100, STARTCPU=2, ПОСЛЕ старта BCR=0x111 (RISCV).
 *   2) GSP FWSEC ucodeId=9: BCR=0, RM, IMEM 0xE200 SEC=1, DMEM 0x800 SEC=0,
 *      PARAADDR0=0x5A4, ENGIDMASK=0x400, MOD_SEL=1, BOOTVEC=0, STARTCPU=2.
 *   3) SEC2 booter ucodeId=3: BCR=0, RM, IMEM 0x4F00 SEC=1, DMEM 0x4D00
 *      SEC=0 (источник +0x5000), PARAADDR0=0x10, ENGIDMASK=1, MOD_SEL=1,
 *      BOOTVEC=0x100, STARTCPU=2.
 * ГИПОТЕЗА v2.46: загрузка #1 (GSP booter) — недостающий ключ: в v2.28-45
 * мы грузили FWSEC БЕЗ неё, и SEC=1 DMA «не работал». После #1 грузим
 * МОДИФИЦИРОВАННЫЙ FWSEC (frts=0x10000000) — дискриминация:
 *   WPR2=0x100000 → НАШ код выполнился → SEC=1 на GSP РАБОТАЕТ после booter!
 *   WPR2=0x27FE000 → снова предзагруженный VBIOS-код → SEC=1 закрыт.
 * Возвращает TRUE при успехе (PLM открыт ИЛИ наш код выполнился). */
static BOOLEAN
driver_replay_v246(UINT64 booterPhys, UINT64 fwsecPhys, UINT64 ucodePhys,
                   UINT64 wprMetaPhys)
{
    UINTN i;
    UINT32 data;
    BOOLEAN ourCode = FALSE;
    BOOLEAN plmOpen = FALSE;

    Print(L"\n=== v2.46: ПОЛНЫЙ РЕПЛЕЙ ПОСЛЕДОВАТЕЛЬНОСТИ ДРАЙВЕРА ===\n");
    Print(L"исходное: PLM=0x%08x SS0=0x%08x SS1=0x%08x GFW=0x%08x WPR2lo=0x%08x\n",
          mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(REG_FEAT_OVR_SM_SPD),
          mmio_read32(REG_FEAT_OVR_SM_SPD_1), mmio_read32(REG_GFW_BOOT_OK),
          mmio_read32(REG_PFB_MMU_WPR2_LO));

    /* ---------- Стадия 1: GSP booter load (ucodeId=1) ---------- */
    Print(L"[1/3] GSP booter load ucodeId=1 (из трейса 538.881)\n");
    mmio_write32(0x110080, 0x0);          /* из трейса (IRQMSET=0) */
    falcon_wait_reset_ready(GSP_HWCFG2);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);

    mmio_write32(GSP_BCR, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, 0xb72000a1);
    mmio_write32(GSP_DMACTL, 0x0);

    Print(L"[1] DMA IMEM SEC=1 0x4000 б (src+0x100 — заголовок пропущен)...\n");
    gsp_dma_transfer(0, 0x100, booterPhys, 0x4000,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"[1] DMA DMEM SEC=0 0x2400 б (src+0x4100)...\n");
    gsp_dma_transfer(0, 0, booterPhys + 0x4100, 0x2400,
                     0 | (6 << 8) | (0 << 12));

    /* сигнатура booter'а: DMEM[0x1F10] (paraaddr) ← sig_dbg из образа.
     * DMEM грузится из src+0x4100 → DMEM[0x1F10] = src[0x4100+0x1F10=0x6010] */
    {
        UINT8 *img = (UINT8*)(UINTN)booterPhys;
        Print(L"[1] патч src[0x6010] ← sig_dbg (0x180 б) для DMEM[0x1F10]...\n");
        CopyMem(img + 0x6010, img + 0x8A10, 0x180);
    }

    mmio_write32(GSP_BROM_PARAADDR0, 0x1F10);
    mmio_write32(GSP_BROM_ENGIDMASK, 0x400);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, 1);
    mmio_write32(GSP_MOD_SEL, 0x1);
    mmio_write32(GSP_MAILBOX0, 0xFE);     /* из трейса: 0x110040 = 0xfe */
    mmio_write32(GSP_BOOTVEC, 0x100);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, 2);          /* STARTCPU */
    mmio_write32(GSP_BCR, 0x111);         /* RISCV+BRFETCH после старта (трейс!) */
    uefi_call_wrapper(BS->Stall, 1, 1000000);
    Print(L"[1] после booter: cpuctl=0x%x dbg=0x%x mbox0=0x%x bcr=0x%x "
          L"GFW=0x%x WPR2lo=0x%x PLM=0x%x\n",
          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
          mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_BCR),
          mmio_read32(REG_GFW_BOOT_OK), mmio_read32(REG_PFB_MMU_WPR2_LO),
          mmio_read32(REG_FEAT_OVR_PLM));
    dump_regs(L"[1-booter]");

    /* ---------- Стадия 2: FWSEC МОДИФИЦИРОВАННЫЙ (frts=0x10000000) ---------- */
    Print(L"\n[2/3] GSP FWSEC load ucodeId=9 (МОДИФ. frts=0x10000000, дискриминация)\n");
    {
        UINT8 *buf = (UINT8*)(UINTN)fwsecPhys;
        UINT32 *mapper2 = (UINT32*)(buf + FWSEC_DATA_OFF + 0x560);
        UINT32 cmdInOff2 = mapper2[2];
        UINT32 *c2 = (UINT32*)(buf + cmdInOff2);

        CopyMem(buf, fwsec_ga102_bin, FWSEC_SIZE);
        CopyMem(buf + FWSEC_DATA_OFF + FWSEC_SIG_DMEM_ADDR,
                fwsec_ga102_sig, FWSEC_SIG_SIZE);
        c2[0] = 1; c2[1] = 24;            /* readVbiosDesc ver,size */
        c2[2] = 0; c2[3] = 0;
        c2[4] = 0; c2[5] = 2;
        c2[6] = 1; c2[7] = 20;            /* frtsRegionDesc ver,size */
        c2[8] = 0x10000;                  /* frtsOffset 0x10000000 >> 12 */
        c2[9] = 0x100;
        c2[10] = 2;
        mapper2[11] = FWSEC_CMD_FRTS;
        Print(L"[2] mapper init_cmd=0x%x cmd_in_off=0x%x frts4k=0x%x\n",
              mapper2[11], cmdInOff2, c2[8]);
    }

    /* как драйвер (трейс 539.410): BCR=0, RM, DMACTL=0 + 0x110080/0x110004/0x1103e8 */
    mmio_write32(GSP_BCR, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, 0xb72000a1);
    mmio_write32(GSP_DMACTL, 0x0);
    mmio_write32(0x110080, 0x0);
    mmio_write32(0x110004, 0x40);
    mmio_write32(0x1103E8, 0x1);

    Print(L"[2] DMA IMEM SEC=1 0xE200 б...\n");
    gsp_dma_transfer(0, 0, fwsecPhys, FWSEC_CODE_SIZE,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"[2] DMA DMEM SEC=0 0x800 б...\n");
    gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF, FWSEC_DMEM_SIZE,
                     0 | (6 << 8) | (0 << 12));

    mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
    mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
    mmio_write32(GSP_MOD_SEL, 0x1);
    mmio_write32(GSP_BOOTVEC, 0);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, 2);

    Print(L"[2] жду WPR2 (наш код → lo=0x100000; предзагруженный → 0x27FE000):\n");
    for (i = 0; i < 2000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == 0x00100000) {
            Print(L"[2] *** WPR2=0x%08x%08x — НАШ модиф. код выполнился! "
                  L"SEC=1 на GSP РАБОТАЕТ после booter! ***\n", hi, lo);
            ourCode = TRUE;
            break;
        }
        if ((i % 200) == 0)
            Print(L"[2] t=%dms wpr2lo=0x%08x wpr2hi=0x%08x gsp=0x%x dbg=0x%x\n",
                  i, lo, hi, mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[2] итог: wpr2lo=0x%08x hi=0x%08x (%s)\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          ourCode ? L"НАШ КОД!" : L"предзагруженный код — SEC=1 всё ещё закрыт");
    dump_regs(L"[2-fwsec]");

    /* ---------- Стадия 3a (v2.48): ЗОНД ДОСТАВКИ DMA в IMEM SEC2 ----------
     * Вопрос: доставляет ли SEC2 IMEM DMA контент? Порты IMEM[0]=DEAD5EC1 —
     * не видно. Зонд: SEC=0 DMA маркер в IMEM[0x8000], SEC=1 DMA маркер в
     * IMEM[0x8400], читаем оба через порты (ns + secure bit28).
     *   SEC=0 лег, SEC=1 нет → SEC=1 на SEC2 scrub (канал закрыт) — H1.
     *   оба легли → 0x780009 от BROM-предусловия (не от пустого IMEM) — H2. */
    Print(L"\n[3a] ЗОНД доставки DMA в SEC2 IMEM (v2.48)...\n");
    {
        UINT32 marker0 = 0x11111111, marker1 = 0x22222222;
        UINT32 vns, vsec;

        /* SEC2 reset + BCR=0 */
        mmio_write32(SEC2_ENGINE, 0x1);
        for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
        mmio_write32(SEC2_ENGINE, 0x0);
        for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
        uefi_call_wrapper(BS->Stall, 1, 50000);
        mmio_write32(SEC2_BCR_CTRL, 0x0);
        for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
        uefi_call_wrapper(BS->Stall, 1, 10000);

        /* маркер-буфер: 0x100 байт = 64 × 0x11111111 */
        {
            UINT64 probePhys = 0;
            UINT32 *pbuf;

            if (!EFI_ERROR(alloc_below_4g(1, &probePhys))) {
                pbuf = (UINT32*)(UINTN)probePhys;
                for (i = 0; i < 0x100 / 4; i++) pbuf[i] = marker0;
                mmio_write32(SEC2_DMATRFBASE, (UINT32)(probePhys >> 8));
                mmio_write32(SEC2_DMATRFBASE1, 0);
                /* SEC=0 DMA → IMEM[0x8000] */
                mmio_write32(SEC2_DMATRFMOFFS, 0x8000);
                mmio_write32(SEC2_DMATRFFBOFFS, 0);
                mmio_write32(SEC2_DMATRFCMD, 0 | (6 << 8) | (1 << 4));
                falcon_dma_wait_idle();
                mmio_write32(SEC2_IMEMC0, 0x8000);
                vns = mmio_read32(SEC2_IMEMD0);
                mmio_write32(SEC2_IMEMC0, 0x8000 | (1 << 28));
                vsec = mmio_read32(SEC2_IMEMD0);
                Print(L"[3a] SEC=0 → IMEM[0x8000]: ns=0x%08x sec=0x%08x "
                      L"(ожидаю 0x11111111; DEAD5EC1 = scrub)\n", vns, vsec);

                for (i = 0; i < 0x100 / 4; i++) pbuf[i] = marker1;
                mmio_write32(SEC2_DMATRFBASE, (UINT32)(probePhys >> 8));
                mmio_write32(SEC2_DMATRFBASE1, 0);
                /* SEC=1 DMA → IMEM[0x8400] */
                mmio_write32(SEC2_DMATRFMOFFS, 0x8400);
                mmio_write32(SEC2_DMATRFFBOFFS, 0);
                mmio_write32(SEC2_DMATRFCMD, 0 | (6 << 8) | (1 << 4) | (1 << 2));
                falcon_dma_wait_idle();
                mmio_write32(SEC2_IMEMC0, 0x8400);
                vns = mmio_read32(SEC2_IMEMD0);
                mmio_write32(SEC2_IMEMC0, 0x8400 | (1 << 28));
                vsec = mmio_read32(SEC2_IMEMD0);
                Print(L"[3a] SEC=1 → IMEM[0x8400]: ns=0x%08x sec=0x%08x "
                      L"(ожидаю 0x22222222; DEAD5EC1 = scrub)\n", vns, vsec);
            } else {
                Print(L"[3a] alloc probe: %r\n", probePhys);
            }
        }
    }

    /* ---------- Стадия 3b (v2.49): SEC2 booter load — ПРАВИЛЬНЫЕ размеры ----
     * Ground truth (2026-08-21, живой драйвер, CMP90_BLDUMP_HS + трейс):
     *   imemSize=0x8900, imemVa=0x100 (FBOFFS стартует 0x100), dataOffset=0x8A00,
     *   dmemSize=0x6200, hsSigDmemAddr=0x10, ucodeId=3, engmask=1, BOOTVEC=0x100.
     * Размеры 0x4F00/0x5000/0x4D00 (v2.41) — ИЛЛЮЗИЯ обрезанного/rate-limited
     * трейса! При правильном dataOffset=0x8A00 сигнатура image[0x8A10]
     * естественно ложится на DMEM[0x10] (paraaddr) — патч не нужен.
     * WPR meta: sysmemAddrOfSignature = V67 (0xFA00) — canary-баг в booter'е
     * при обработке сигнатуры запустит ROP-цепочку → PLM OPEN.
     * Доставка IMEM: A) DMA SEC=1 (как драйвер), B) порты IMEMC (v2.18). */
    Print(L"\n[3b/3] SEC2 booter load ucodeId=3 — ПРАВИЛЬНЫЕ размеры "
          L"(0x8900/0x8A00/0x6200, V67-сигнатура)\n");
    /* свежая копия образа (стадия 1 патчила src[0x6010] внутри data-региона) */
    CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);

    {
        UINTN p;
        BOOLEAN portLoad;

        for (portLoad = FALSE; ; portLoad = TRUE) {
            Print(L"[3b] вариант %s (%s IMEM)...\n",
                  portLoad ? L"B: порты" : L"A: DMA",
                  portLoad ? L"IMEMC/IMEMD, SECURE bit28" : L"DMA SEC=1");

            /* WPR2 нормализуем (booter валидирует раскладку) */
            mmio_write32(REG_PFB_MMU_WPR2_LO, 0x027fe000);
            mmio_write32(REG_PFB_MMU_WPR2_HI, 0x027fee00);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            /* SEC2 reset + BCR=0 (kflcnReset как драйвер) */
            mmio_write32(SEC2_ENGINE, 0x1);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            mmio_write32(SEC2_ENGINE, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            uefi_call_wrapper(BS->Stall, 1, 50000);
            mmio_write32(SEC2_BCR_CTRL, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            data = mmio_read32(SEC2_FBIF_CTL);
            data |= (1 << 7);
            mmio_write32(SEC2_FBIF_CTL, data);
            mmio_write32(SEC2_DMACTL, 0);
            mmio_write32(SEC2_RM, 0xb72000a1);
            data = mmio_read32(SEC2_FBIF_TRANSCFG0);
            data = (data & ~0x7) | 0x5;
            mmio_write32(SEC2_FBIF_TRANSCFG0, data);

            if (!portLoad) {
                /* A: DMA — IMEM 0x8900 SEC=1 (src+0x100), DMEM 0x6200 SEC=0
                 * (src+0x8A00 — сигнатура ложится на DMEM[0x10] сама!) */
                Print(L"[3b-A] DMA IMEM SEC=1 (0x8900 б, src+0x100)...\n");
                falcon_dma_transfer(0, 0x100, ucodePhys, 0x8900,
                                    0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
                Print(L"[3b-A] DMA DMEM SEC=0 (0x6200 б, src+0x8A00)...\n");
                falcon_dma_transfer(0, 0, ucodePhys + 0x8A00, 0x6200,
                                    0 | (6 << 8) | (0 << 12));
            } else {
                /* B: порты — IMEM image[0x100..0x89FF] → IMEM[0..0x88FF]
                 * (SECURE bit28), DMEM image[0x8A00..0xEBFF] → DMEM[0..0x61FF] */
                const UINT8 *img = (const UINT8*)(UINTN)ucodePhys;
                Print(L"[3b-B] порты IMEM (SECURE, 0x8900 б)...\n");
                mmio_write32(SEC2_IMEMC0, (1 << 28) | (1 << 24));  /* SECURE|AINCW */
                for (i = 0; i < 0x8900 / 4; i++)
                    mmio_write32(SEC2_IMEMD0,
                        *(UINT32*)(img + 0x100 + i * 4));
                Print(L"[3b-B] порты DMEM (0x6200 б)...\n");
                mmio_write32(SEC2_DMEMC0, (1 << 24));              /* AINCW */
                for (i = 0; i < 0x6200 / 4; i++)
                    mmio_write32(SEC2_DMEMD0,
                        *(UINT32*)(img + 0x8A00 + i * 4));
            }

            /* верификация */
            mmio_write32(SEC2_IMEMC0, (1 << 28));
            data = mmio_read32(SEC2_IMEMD0);
            mmio_write32(SEC2_IMEMC0, (1 << 28) | 0x100);
            Print(L"[3b] IMEM_S[0]=0x%08x IMEM_S[0x100]=0x%08x "
                  L"(ожидаю %08x — код)\n", data, mmio_read32(SEC2_IMEMD0),
                  *(UINT32*)((UINTN)ucodePhys + 0x100));
            mmio_write32(SEC2_DMEMC0, 0x10);
            Print(L"[3b] DMEM[0x10]=0x%08x (ожидаю a9d43de4 — sig!)\n",
                  mmio_read32(SEC2_DMEMD0));

            mmio_write32(SEC2_BROM_PARAADDR0, BOOTER_HS_SIG_DMEM_ADDR);
            mmio_write32(SEC2_BROM_ENGIDMASK, BOOTER_ENGINE_ID_MASK);
            mmio_write32(SEC2_BROM_CURR_UCODE_ID, BOOTER_UCODE_ID);
            data = mmio_read32(SEC2_MOD_SEL);
            data = (data & ~0xFF) | 0x1;          /* RSA3K */
            mmio_write32(SEC2_MOD_SEL, data);
            mmio_write32(SEC2_BOOTVEC, 0x100);
            mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
            mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));
            __asm__ volatile("wbinvd" ::: "memory");
            mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

            Print(L"[3b] CPU started, polling PLM до 5с (V67-цепочка)...\n");
            for (p = 0; p < 5000; p++) {
                if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                    Print(L"[3b-%s] *** PLM OPEN после %d ms! ***\n",
                          portLoad ? L"B" : L"A", p);
                    plmOpen = TRUE;
                    break;
                }
                if ((p % 1000) == 0)
                    Print(L"[3b-%s] t=%dms PLM=0x%08x cpu=0x%x dbg=0x%x mbox0=0x%x\n",
                          portLoad ? L"B" : L"A", p, mmio_read32(REG_FEAT_OVR_PLM),
                          mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO),
                          mmio_read32(SEC2_MAILBOX0));
                uefi_call_wrapper(BS->Stall, 1, 1000);
            }
            Print(L"[3b-%s] итог: PLM=0x%08x cpu=0x%x irq=0x%x dbg=0x%x mbox0=0x%x\n",
                  portLoad ? L"B" : L"A", mmio_read32(REG_FEAT_OVR_PLM),
                  mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_IRQSTAT),
                  mmio_read32(SEC2_DEBUGINFO), mmio_read32(SEC2_MAILBOX0));
            if (plmOpen || portLoad)
                break;   /* оба варианта проверены */
        }
    }
    dump_regs(L"[3b-sec2]");

    /* ---------- Стадия 3c (v2.50): GSP-DIRECT booter load (SEC2 ucode на GSP)
     * SEC2 IMEM с хоста НЕ пишется (v2.48/2.49: DMA scrub, порты DEAD5EC1) —
     * а GSP IMEM пишется (v2.46: SEC=1 доставляет!). Грузим SEC2 booter
     * (правильные размеры 0x8900/0x8A00/0x6200!) в GSP IMEM/DMEM, BROM params
     * GSP (ucodeId=3, engmask=0x400), mailboxes=WPR meta (V67-сигнатура!).
     * Если GSP BROM верифицирует sig_dbg (DMEM[0x10]) и запустит booter —
     * booter обработает V67-сигнатуру → canary-баг → ROP → PLM OPEN! */
    Print(L"\n[3c] GSP-DIRECT booter load (SEC2 ucode на GSP, V67)...\n");
    {
        UINTN p;
        UINT32 ucodeIdTry;

        for (ucodeIdTry = 3; ucodeIdTry <= 9; ucodeIdTry += 6) {
            /* свежая копия образа */
            CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);

            Print(L"[3c] ucodeId=%d engmask=0x400 (GSP)...\n", ucodeIdTry);

            /* GSP ENGINE reset (как kflcnReset) */
            mmio_write32(GSP_ENGINE, 0x1);
            for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
            mmio_write32(GSP_ENGINE, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
            uefi_call_wrapper(BS->Stall, 1, 50000);
            mmio_write32(GSP_BCR, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            /* WPR2 нормализуем */
            mmio_write32(REG_PFB_MMU_WPR2_LO, 0x027fe000);
            mmio_write32(REG_PFB_MMU_WPR2_HI, 0x027fee00);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            data = mmio_read32(GSP_FBIF_CTL);
            data |= (1 << 7);
            mmio_write32(GSP_FBIF_CTL, data);
            mmio_write32(GSP_DMACTL, 0);
            mmio_write32(GSP_RM, 0xb72000a1);
            data = mmio_read32(GSP_FBIF_TRANSCFG0);
            data = (data & ~0x7) | 0x5;
            mmio_write32(GSP_FBIF_TRANSCFG0, data);

            Print(L"[3c] DMA IMEM SEC=1 (0x8900 б, src+0x100) в GSP IMEM...\n");
            gsp_dma_transfer(0, 0x100, ucodePhys, 0x8900,
                             0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
            Print(L"[3c] DMA DMEM SEC=0 (0x6200 б, src+0x8A00) в GSP DMEM...\n");
            gsp_dma_transfer(0, 0, ucodePhys + 0x8A00, 0x6200,
                             0 | (6 << 8) | (0 << 12));

            /* верификация */
            mmio_write32(GSP_BASE + 0x1C0, 0x10);
            Print(L"[3c] GSP DMEM[0x10]=0x%08x (ожидаю a9d43de4 — sig)\n",
                  mmio_read32(GSP_BASE + 0x1C4));
            mmio_write32(GSP_BASE + 0x180, (1 << 28));
            Print(L"[3c] GSP IMEM_S[0]=0x%08x (ожидаю 29f1b35e — код)\n",
                  mmio_read32(GSP_BASE + 0x184));

            mmio_write32(GSP_BROM_PARAADDR0, 0x10);
            mmio_write32(GSP_BROM_ENGIDMASK, 0x400);
            mmio_write32(GSP_BROM_CURR_UCODE_ID, ucodeIdTry);
            mmio_write32(GSP_MOD_SEL, 0x1);              /* RSA3K */
            mmio_write32(GSP_BOOTVEC, 0x100);
            mmio_write32(GSP_MAILBOX0, (UINT32)(wprMetaPhys & 0xFFFFFFFF));
            mmio_write32(GSP_MAILBOX1, (UINT32)((wprMetaPhys >> 32) & 0xFFFFFFFF));
            __asm__ volatile("wbinvd" ::: "memory");
            mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

            Print(L"[3c] STARTCPU (GSP), polling PLM до 5с (V67-цепочка)...\n");
            for (p = 0; p < 5000; p++) {
                if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                    Print(L"[3c] *** PLM OPEN после %d ms! ***\n", p);
                    plmOpen = TRUE;
                    break;
                }
                if ((p % 1000) == 0)
                    Print(L"[3c] t=%dms PLM=0x%08x gsp=0x%x dbg=0x%x mbox0=0x%x\n",
                          p, mmio_read32(REG_FEAT_OVR_PLM),
                          mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94),
                          mmio_read32(GSP_MAILBOX0));
                uefi_call_wrapper(BS->Stall, 1, 1000);
            }
            Print(L"[3c] итог: PLM=0x%08x gsp=0x%x dbg=0x%x bcr=0x%x mbox0=0x%x\n",
                  mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(GSP_CPUCTL),
                  mmio_read32(GSP_BASE + 0x94), mmio_read32(GSP_BCR),
                  mmio_read32(GSP_MAILBOX0));
            if (plmOpen || ucodeIdTry == 9)
                break;   /* оба ucodeId проверены */
        }
    }
    dump_regs(L"[3c-gsp-direct]");

    /* ---------- Финальные проверки ---------- */
    if (plmOpen || ourCode) {
        Print(L"v2.46: *** реплей дал результат — записываю SS0/SS1 ***\n");
        mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
        mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
        uefi_call_wrapper(BS->Stall, 1, 100000);
        dump_regs(L"[v2.46-unlock]");
    } else {
        Print(L"v2.46: результата нет. Пробую прямую запись SS0/SS1 "
              L"(rejoin15-style)...\n");
        mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
        mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
        uefi_call_wrapper(BS->Stall, 1, 100000);
        dump_regs(L"[v2.46-direct]");
    }
    return plmOpen || ourCode || is_unlocked();
}

/* ==== FALLBACK B: FWSEC re-load (FRTS then SB command) -> booter ====
 * Hypothesis: SEC2 IMEM DMA needs the HS state established by FWSEC's
 * SB command. Reloads our fwsec_ga102.bin onto GSP (GSP key, sig[2]),
 * FRTS (WPR2) -> SB (privmask) -> SEC2 booter load with correct sizes
 * + V67 signature; stage [4] also tries the VBIOS-preloaded SEC2 ucode
 * (ucodeId=10, appid 0x49 DBG / 0x89 PROD). Legacy ladder member.
 * Гипотеза: SEC2 IMEM DMA требует HS-состояния, которое задаёт SB-команда
 * FWSEC (v2.40: после SB halt SEC2 меняется 0x780009 → dbg=0x0). Драйвер
 * ПЕРЕЗАГРУЖАЕТ FWSEC на GSP (наш копия fwsec_ga102.bin — GSP-ключ! sig[2]
 * PROD) — если GSP BROM примет наш копию, FRTS+SB отработают и SEC2 откроется.
 * Порядок (как драйвер): FWSEC re-load (FRTS→WPR2, затем SB) → SEC2 booter
 * load (ПРАВИЛЬНЫЕ размеры 0x8900/0x8A00/0x6200, V67-сигнатура в meta).
 * БЕЗ разрушительной стадии 1 (не убиваем предзагруженный код заранее). */
static BOOLEAN
driver_replay_v251(UINT64 fwsecPhys, UINT64 ucodePhys, UINT64 wprMetaPhys)
{
    UINTN i;
    UINT32 data;
    BOOLEAN fwsecOk = FALSE;
    BOOLEAN sbChanged = FALSE;
    BOOLEAN plmOpen = FALSE;

    Print(L"\n=== v2.51: FWSEC re-load + SB → SEC2 booter (V67) ===\n");
    Print(L"исходное: PLM=0x%08x SS0=0x%08x WPR2lo=0x%08x privmask=0x%08x\n",
          mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(REG_FEAT_OVR_SM_SPD),
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(0x00118128));

    /* ---------- 1. FWSEC FRTS (ПОЛНАЯ последовательность v2.28-34!)
     * v2.51-1b показал: БЕЗ IMEM DMA STARTCPU не исполняет код (gsp halted
     * dbg=0x0). В v2.28-34 WPR2 ставился за 9мс — там был IMEM SEC=1 DMA
     * (0xE200) + DMEM (FRTS) + BROM + STARTCPU. Воспроизводим точно:
     * IMEM DMA доставляет (v2.46) — BROM принимает FWSEC (GSP-ключ + sig[2]). */
    Print(L"[1] FWSEC FRTS (полная v2.28-34: IMEM+DMEM+FRTS)...\n");
    {
        UINT8 *buf = (UINT8*)(UINTN)fwsecPhys;
        UINT32 *mapper2 = (UINT32*)(buf + FWSEC_DATA_OFF + 0x560);
        UINT32 cmdInOff2 = mapper2[2];
        UINT32 *c2 = (UINT32*)(buf + cmdInOff2);

        CopyMem(buf, fwsec_ga102_bin, FWSEC_SIZE);
        CopyMem(buf + FWSEC_DATA_OFF + FWSEC_SIG_DMEM_ADDR,
                fwsec_ga102_sig, FWSEC_SIG_SIZE);
        c2[0] = 1; c2[1] = 24;
        c2[2] = 0; c2[3] = 0;
        c2[4] = 0; c2[5] = 2;
        c2[6] = 1; c2[7] = 20;
        c2[8] = FWSEC_FRTS_OFFSET >> 12;      /* 0x27FE000 */
        c2[9] = 0x100;
        c2[10] = 2;
        mapper2[11] = FWSEC_CMD_FRTS;
    }

    /* GSP ENGINE reset (убить GFW, предзагруженный FWSEC переживает reset) */
    falcon_wait_reset_ready(GSP_HWCFG2);
    mmio_write32(GSP_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    falcon_wait_scrub_done(GSP_DMACTL, GSP_HWCFG2, L"gsp-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(GSP_BCR, 0x1);                 /* CORE_SELECT=FALCON (v2.28-34!) */
    for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
    mmio_write32(GSP_RM, mmio_read32(0x00100000));  /* PMC_BOOT_0 (v2.28-34!) */
    uefi_call_wrapper(BS->Stall, 1, 10000);

    data = mmio_read32(GSP_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(GSP_FBIF_CTL, data);
    mmio_write32(GSP_DMACTL, 0);
    data = mmio_read32(GSP_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(GSP_FBIF_TRANSCFG0, data);

    Print(L"[1] DMA IMEM SEC=1 (0xE200 б)...\n");
    gsp_dma_transfer(0, 0, fwsecPhys, FWSEC_CODE_SIZE,
                     0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"[1] DMA DMEM SEC=0 (0x800 б, FRTS cmd)...\n");
    gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF, FWSEC_DMEM_SIZE,
                     0 | (6 << 8) | (0 << 12));

    mmio_write32(GSP_BROM_PARAADDR0, FWSEC_SIG_DMEM_ADDR);
    mmio_write32(GSP_BROM_ENGIDMASK, FWSEC_ENGID_MASK);
    mmio_write32(GSP_BROM_CURR_UCODE_ID, FWSEC_UCORE_ID);
    mmio_write32(GSP_MOD_SEL, 0x1);              /* RSA3K */
    mmio_write32(GSP_BOOTVEC, 0);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    Print(L"[1] жду WPR2 до 5с (предзагруженный FWSEC + наш FRTS → 0x27FE000):\n");
    for (i = 0; i < 5000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == 0x027FE000 && (hi & 0xFFFFFFF0) == 0x027FEE00) {
            Print(L"[1] *** WPR2 УСТАНОВЛЕН lo=0x%08x hi=0x%08x после %d ms "
                  L"— предзагруженный FWSEC выполнил наш FRTS! ***\n",
                  lo, hi, i);
            fwsecOk = TRUE;
            break;
        }
        if ((i % 1000) == 0)
            Print(L"[1] t=%dms wpr2lo=0x%08x gsp=0x%x dbg=0x%x\n",
                  i, lo, mmio_read32(GSP_CPUCTL), mmio_read32(GSP_BASE + 0x94));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[1] итог: WPR2=%s (lo=0x%08x hi=0x%08x)\n",
          fwsecOk ? L"УСТАНОВЛЕН" : L"НЕ установлен",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));
    dump_regs(L"[1-fwsec]");

    /* ---------- 2. SB-команда (0x19) через FWSEC ---------- */
    {
        UINT8 *buf = (UINT8*)(UINTN)fwsecPhys;
        UINT32 *mapper2 = (UINT32*)(buf + FWSEC_DATA_OFF + 0x560);
        UINT32 priv0 = mmio_read32(0x00118128);
        UINT32 privA;

        mapper2[11] = 0x19;                    /* SB */
        gsp_dma_transfer(0, 0, fwsecPhys + FWSEC_DATA_OFF,
                         FWSEC_DMEM_SIZE, 0 | (6 << 8) | (0 << 12));
        mmio_write32(GSP_BOOTVEC, 0);
        __asm__ volatile("wbinvd" ::: "memory");
        mmio_write32(GSP_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
        uefi_call_wrapper(BS->Stall, 1, 500000);
        privA = mmio_read32(0x00118128);
        sbChanged = (privA != priv0);
        Print(L"[2] SB (0x19): privmask 0x%08x → 0x%08x%s\n",
              priv0, privA, sbChanged ? L" <<< ИЗМЕНЕНИЕ (SB сработал!)" : L"");
        dump_regs(L"[2-sb]");
    }

    /* ---------- 3. SEC2 booter load (правильные размеры + V67) ---------- */
    Print(L"[3] SEC2 booter load ucodeId=3 (0x8900/0x8A00/0x6200, V67)...\n");
    CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);

    mmio_write32(REG_PFB_MMU_WPR2_LO, 0x027fe000);
    mmio_write32(REG_PFB_MMU_WPR2_HI, 0x027fee00);
    uefi_call_wrapper(BS->Stall, 1, 10000);

    falcon_wait_reset_ready(SEC2_HWCFG2);
    mmio_write32(SEC2_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    mmio_write32(SEC2_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    falcon_wait_scrub_done(SEC2_DMACTL, SEC2_HWCFG2, L"sec2-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(SEC2_BCR_CTRL, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
    uefi_call_wrapper(BS->Stall, 1, 10000);

    data = mmio_read32(SEC2_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(SEC2_FBIF_CTL, data);
    mmio_write32(SEC2_DMACTL, 0);
    mmio_write32(SEC2_RM, 0xb72000a1);
    data = mmio_read32(SEC2_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(SEC2_FBIF_TRANSCFG0, data);

    Print(L"[3] DMA IMEM SEC=1 (0x8900 б, src+0x100)...\n");
    falcon_dma_transfer(0, 0x100, ucodePhys, 0x8900,
                        0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"[3] DMA DMEM SEC=0 (0x6200 б, src+0x8A00)...\n");
    falcon_dma_transfer(0, 0, ucodePhys + 0x8A00, 0x6200,
                        0 | (6 << 8) | (0 << 12));

    mmio_write32(SEC2_DMEMC0, 0x10);
    Print(L"[3] DMEM[0x10]=0x%08x (ожидаю a9d43de4 — sig)\n",
          mmio_read32(SEC2_DMEMD0));

    mmio_write32(SEC2_BROM_PARAADDR0, BOOTER_HS_SIG_DMEM_ADDR);
    mmio_write32(SEC2_BROM_ENGIDMASK, BOOTER_ENGINE_ID_MASK);
    mmio_write32(SEC2_BROM_CURR_UCODE_ID, BOOTER_UCODE_ID);
    data = mmio_read32(SEC2_MOD_SEL);
    data = (data & ~0xFF) | 0x1;          /* RSA3K */
    mmio_write32(SEC2_MOD_SEL, data);
    mmio_write32(SEC2_BOOTVEC, 0x100);
    mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
    mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    Print(L"[3] STARTCPU (SEC2), polling PLM до 5с (V67-цепочка)...\n");
    for (i = 0; i < 5000; i++) {
        if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
            Print(L"[3] *** PLM OPEN после %d ms! ***\n", i);
            plmOpen = TRUE;
            break;
        }
        if ((i % 1000) == 0)
            Print(L"[3] t=%dms PLM=0x%08x cpu=0x%x dbg=0x%x mbox0=0x%x\n",
                  i, mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(SEC2_CPUCTL),
                  mmio_read32(SEC2_DEBUGINFO), mmio_read32(SEC2_MAILBOX0));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[3] итог: PLM=0x%08x cpu=0x%x irq=0x%x dbg=0x%x mbox0=0x%x\n",
          mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(SEC2_CPUCTL),
          mmio_read32(SEC2_IRQSTAT), mmio_read32(SEC2_DEBUGINFO),
          mmio_read32(SEC2_MAILBOX0));
    dump_regs(L"[3-sec2-v251]");

    /* ---------- 4 (v2.54): SEC2 ПРЕДЗАГРУЖЕННЫЙ ucode (ucodeId=10!) ----------
     * В VBIOS есть SEC2 ucode (appid 0x49 DBG / 0x89 PROD): ucodeId=10,
     * engmask=1, imemLoad=0x4400, dmemLoad=0x8F4, pkc=0x6DC, iface=0x10.
     * VBIOS грузит его в SEC2 при POST (v2.38 «нет предзагрузки» — порты
     * врут!). BROM сверяет сигнатуру с РЕАЛЬНЫМ IMEM — у нас (ucodeId=3,
     * sig_dbg) сигнатура не совпадала → 0x780009! Теперь: ucodeId=10 +
     * сигнатура VBIOS на DMEM[0x6DC] — BROM проверит и ЗАПУСТИТ
     * предзагруженный код → он обработает WPR meta (V67-сигнатура!) →
     * canary-баг → ROP → PLM! IMEM DMA НЕ нужен (код уже там!). */
    Print(L"\n[4] SEC2 предзагруженный ucode (ucodeId=10, sig из VBIOS)...\n");
    {
        UINTN p;
        UINT32 appidTry = 0x89;
        UINT32 appidDone = 0;

        while (1) {
            const UINT8 *sec2img = (appidTry == 0x89)
                ? sec2_ucode_vbios_89 : sec2_ucode_vbios_49;
            const UINTN sec2size = (appidTry == 0x89)
                ? sec2_ucode_vbios_89_size : sec2_ucode_vbios_49_size;

            Print(L"[4] appid=0x%02x (ucodeId=10, 0x4400/0x8F4, pkc=0x6DC)...\n",
                  appidTry);
            CopyMem((VOID*)(UINTN)ucodePhys, sec2img, sec2size);

            /* SEC2 reset + BCR=0 + FBIF + DMACTL + RM */
            mmio_write32(SEC2_ENGINE, 0x1);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            mmio_write32(SEC2_ENGINE, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
            uefi_call_wrapper(BS->Stall, 1, 50000);
            mmio_write32(SEC2_BCR_CTRL, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            uefi_call_wrapper(BS->Stall, 1, 10000);

            data = mmio_read32(SEC2_FBIF_CTL);
            data |= (1 << 7);
            mmio_write32(SEC2_FBIF_CTL, data);
            mmio_write32(SEC2_DMACTL, 0);
            mmio_write32(SEC2_RM, 0xb72000a1);
            data = mmio_read32(SEC2_FBIF_TRANSCFG0);
            data = (data & ~0x7) | 0x5;
            mmio_write32(SEC2_FBIF_TRANSCFG0, data);

            /* DMEM: данные из образа (imemLoad=0x4400, 0x8F4 б) — сигнатура
             * патчена на DMEM[0x6DC] */
            Print(L"[4] DMA DMEM SEC=0 (0x8F4 б, src+0x4400)...\n");
            falcon_dma_transfer(0, 0, ucodePhys + 0x4400, 0x8F4,
                                0 | (6 << 8) | (0 << 12));
            mmio_write32(SEC2_DMEMC0, 0x6DC);
            Print(L"[4] DMEM[0x6DC]=0x%08x (ожидаю sig[2][0]: %08x)\n",
                  mmio_read32(SEC2_DMEMD0),
                  *(UINT32*)((UINTN)sec2img + 0x4400 + 0x6DC));
            /* v2.55: дамп DMEM[0x600..0x700] в NS и SECURE-представлениях */
            {
                UINTN di;
                Print(L"[4] DMEM dump (NS  |  SEC):\n");
                for (di = 0x600; di < 0x700; di += 0x40) {
                    UINT32 vn0, vs0;
                    mmio_write32(SEC2_DMEMC0, di);
                    vn0 = mmio_read32(SEC2_DMEMD0);
                    mmio_write32(SEC2_DMEMC0, di | (1 << 28));
                    vs0 = mmio_read32(SEC2_DMEMD0);
                    Print(L"[4]   %04x: ns=0x%08x sec=0x%08x\n", di, vn0, vs0);
                }
            }

            mmio_write32(SEC2_BROM_PARAADDR0, 0x6DC);
            mmio_write32(SEC2_BROM_ENGIDMASK, 1);
            mmio_write32(SEC2_BROM_CURR_UCODE_ID, 10);
            data = mmio_read32(SEC2_MOD_SEL);
            data = (data & ~0xFF) | 0x1;          /* RSA3K */
            mmio_write32(SEC2_MOD_SEL, data);
            mmio_write32(SEC2_BOOTVEC, 0);        /* imemVa=0 */
            mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
            mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));
            __asm__ volatile("wbinvd" ::: "memory");
            mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

            /* v2.56: BCR=RISCV после STARTCPU (как GSP booter load у драйвера) */
            mmio_write32(SEC2_BCR_CTRL, 0x111);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            Print(L"[4] BCR после STARTCPU+0x111 = 0x%x (0x111 = RISCV!)\n",
                  mmio_read32(SEC2_BCR_CTRL));

            Print(L"[4] STARTCPU (SEC2), polling PLM до 5с (V67-цепочка)...\n");
            for (p = 0; p < 5000; p++) {
                UINT32 trIdx = mmio_read32(NV_PSEC_BASE + 0x148);
                UINT32 trPc = mmio_read32(NV_PSEC_BASE + 0x14C);
                if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) {
                    Print(L"[4] *** PLM OPEN после %d ms! ***\n", p);
                    plmOpen = TRUE;
                    break;
                }
                                if ((p % 1000) == 0)
                    Print(L"[4] t=%dms PLM=0x%08x cpu=0x%x dbg=0x%x bcr=0x%x "
                          L"traceIdx=0x%x tracePc=0x%x mbox0=0x%x\n",
                          p, mmio_read32(REG_FEAT_OVR_PLM),
                          mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO),
                          mmio_read32(SEC2_BCR_CTRL), trIdx, trPc,
                          mmio_read32(SEC2_MAILBOX0));
                uefi_call_wrapper(BS->Stall, 1, 1000);
            }
            Print(L"[4] итог: PLM=0x%08x cpu=0x%x irq=0x%x dbg=0x%x mbox0=0x%x\n",
                  mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(SEC2_CPUCTL),
                  mmio_read32(SEC2_IRQSTAT), mmio_read32(SEC2_DEBUGINFO),
                  mmio_read32(SEC2_MAILBOX0));
            dump_regs(L"[4-sec2-v254]");

            if (plmOpen || appidDone)
                break;   /* оба appid проверены */
            appidDone = appidTry;
            appidTry = (appidTry == 0x89) ? 0x49 : 0x89;
        }
    }

    return fwsecOk || sbChanged || plmOpen || is_unlocked();
}

/* ==== Dev experiment: drive the VBIOS-preloaded SEC2 ucode directly ====
 * Preloaded ucode (ucodeId=10) is FWSEC-family: DMAP v3 mapper at
 * DMEM[0x698], init_cmd@0x6C4, cmd_in@0x23D0, sig@0x6DC (accepted by
 * BROM). Pokes FRTS(0x15)/SB(0x19) commands via port writes and watches
 * WPR2/privmask. Skipped by default (cmp90_skipMapper=1) — not part of
 * the real driver flow.
 * SEC2-ucode (ucodeId=10, предзагружен VBIOS при POST) = FWSEC-семья:
 * mapper "DMAP" v3 @DMEM[0x698] (init_cmd@+44=0x6C4, cmd_in@0x23D0,
 * cmd_out@0x2410), sig@DMEM[0x6DC] (fuse-выбор, предзагружен — BROM его
 * принимает: стадия 4 дала dbg=0x0 вместо 0x780009!). Стадия 4 НЕ ставила
 * команду → ucode ждал (cpu=0x10 halt). Драйвер для FWSEC патчит
 * init_cmd=0x15 (FRTS)/0x19 (SB) в DMEM-образ ДО DMA — но SEC2
 * DMEM[0x600..0x700] secure-защищён, NS-DMA туда НЕ пишет (v2.54).
 * ПРОВЕРЯЕМ: (a) читаем живой mapper (NS+SEC), (b) пишем cmd_in @0x23D0
 * (не-secure!) портами, (c) пробуем ПОРТОВУЮ запись init_cmd @0x6C4
 * (никогда не тестировалась!), (d) STARTCPU ucodeId=10 → FRTS ставит WPR2,
 * SB открывает privmask (0x118128). Потом booter load (PROD sig!) → V67. */
static BOOLEAN
sec2_ucode_mapper_cmd(UINT64 wprMetaPhys)
{
    UINTN i, p;
    UINT32 data;
    BOOLEAN wpr2set = FALSE;
    BOOLEAN sbChanged = FALSE;

    /* FRTS cmd (44Б): readVbiosDesc{ver=1,size=24,gfwOff=0,gfwSize=0,flags=2}
     * + frtsRegionDesc{ver=1,size=20,offset4K=0x27fe00,size=0x100,media=2} */
    static const UINT32 frtsCmd[11] = {
        1, 24, 0, 0, 0, 2,
        1, 20, 0x27fe00, 0x100, 2
    };
    /* SB cmd (24Б): readVbiosDesc{ver=1,size=24,gfwOff=0,gfwSize=0,flags=2} */
    static const UINT32 sbCmd[6] = { 1, 24, 0, 0, 0, 2 };

    Print(L"\n=== v2.57: SEC2 ucode mapper init_cmd (FRTS/SB) ===\n");

    /* ---------- подготовка SEC2 (reset + unlock, как стадия 4) ---------- */
    falcon_wait_reset_ready(SEC2_HWCFG2);
    mmio_write32(SEC2_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    mmio_write32(SEC2_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    falcon_wait_scrub_done(SEC2_DMACTL, SEC2_HWCFG2, L"sec2-reset");
    uefi_call_wrapper(BS->Stall, 1, 50000);
    mmio_write32(SEC2_BCR_CTRL, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
    uefi_call_wrapper(BS->Stall, 1, 10000);

    data = mmio_read32(SEC2_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(SEC2_FBIF_CTL, data);
    mmio_write32(SEC2_DMACTL, 0);
    mmio_write32(SEC2_RM, 0xb72000a1);
    data = mmio_read32(SEC2_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(SEC2_FBIF_TRANSCFG0, data);

    /* ---------- 1. дамп живого mapper (DMEM 0x680..0x710, NS | SEC) ---------- */
    Print(L"[5] mapper region (DMEM 0x680..0x710) NS | SEC:\n");
    for (i = 0x680; i < 0x710; i += 4) {
        UINT32 vn, vs;
        mmio_write32(SEC2_DMEMC0, i);
        vn = mmio_read32(SEC2_DMEMD0);
        mmio_write32(SEC2_DMEMC0, i | (1 << 28));
        vs = mmio_read32(SEC2_DMEMD0);
        Print(L"[5]   %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }

    /* ---------- 2. cmd_in буфер @0x23D0 (не-secure!) ← FRTS cmd ---------- */
    Print(L"[5] cmd_in @0x23D0 <- FRTS cmd (44Б, явная адресация)...\n");
    for (i = 0; i < 11; i++) {
        mmio_write32(SEC2_DMEMC0, 0x23D0 + i * 4);
        mmio_write32(SEC2_DMEMD0, frtsCmd[i]);
    }
    Print(L"[5]   cmd_in[0..5]: ");
    for (i = 0; i < 6; i++) {
        mmio_write32(SEC2_DMEMC0, 0x23D0 + i * 4);
        Print(L"%08x ", mmio_read32(SEC2_DMEMD0));
    }
    Print(L"\n");

    /* ---------- 3. порт-запись init_cmd @0x6C4 (secure-зона!?) ---------- */
    Print(L"[5] port-write init_cmd DMEM[0x6C4] <- 0x15 (FRTS)...\n");
    mmio_write32(SEC2_DMEMC0, 0x6C4);
    mmio_write32(SEC2_DMEMD0, 0x15);
    mmio_write32(SEC2_DMEMC0, 0x6C4);
    Print(L"[5]   ns =0x%08x", mmio_read32(SEC2_DMEMD0));
    mmio_write32(SEC2_DMEMC0, 0x6C4 | (1 << 28));
    Print(L" sec=0x%08x (0x15 = порт пишет secure-зону!)\n", mmio_read32(SEC2_DMEMD0));

    /* ---------- 4. BROM params + STARTCPU (ucodeId=10, как стадия 4) ----- */
    mmio_write32(SEC2_BROM_PARAADDR0, 0x6DC);
    mmio_write32(SEC2_BROM_ENGIDMASK, 1);
    mmio_write32(SEC2_BROM_CURR_UCODE_ID, 10);
    data = mmio_read32(SEC2_MOD_SEL);
    data = (data & ~0xFF) | 0x1;               /* RSA3K */
    mmio_write32(SEC2_MOD_SEL, data);
    mmio_write32(SEC2_BOOTVEC, 0);
    mmio_write32(SEC2_MAILBOX0, (UINT32)(cmp90_meta_low(wprMetaPhys) & 0xFFFFFFFF));
    mmio_write32(SEC2_MAILBOX1, (UINT32)((cmp90_meta_low(wprMetaPhys) >> 32) & 0xFFFFFFFF));
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    Print(L"[5] STARTCPU (ucodeId=10), polling WPR2 до 5с (FRTS)...\n");
    for (p = 0; p < 5000; p++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == 0x027FE000 && (hi & 0xFFFFFFF0) == 0x027FEE00) {
            Print(L"[5] *** WPR2 УСТАНОВЛЕН lo=0x%08x hi=0x%08x после %d ms — "
                  L"SEC2 ucode выполнил FRTS! ***\n", lo, hi, p);
            wpr2set = TRUE;
            break;
        }
        if ((p % 1000) == 0)
            Print(L"[5] t=%dms wpr2lo=0x%08x cpu=0x%x dbg=0x%x bcr=0x%x\n",
                  p, lo, mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO),
                  mmio_read32(SEC2_BCR_CTRL));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[5] FRTS итог: WPR2=%s lo=0x%08x hi=0x%08x cpu=0x%x dbg=0x%x\n",
          wpr2set ? L"УСТАНОВЛЕН" : L"НЕТ",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI),
          mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO));
    /* cmd_out @0x2410 — ucode пишет сюда результат команды (диагностика) */
    Print(L"[5] cmd_out @0x2410: ");
    for (i = 0; i < 4; i++) {
        mmio_write32(SEC2_DMEMC0, 0x2410 + i * 4);
        Print(L"%08x ", mmio_read32(SEC2_DMEMD0));
    }
    Print(L"\n");
    dump_regs(L"[5-frts]");

    /* ---------- 5. SB (init_cmd=0x19 + cmd @0x23D0) ---------- */
    Print(L"[5] SB: init_cmd=0x19 @0x6C4, cmd 24Б @0x23D0...\n");
    /* cmd_in <- SB cmd (readVbiosDesc) */
    for (i = 0; i < 6; i++) {
        mmio_write32(SEC2_DMEMC0, 0x23D0 + i * 4);
        mmio_write32(SEC2_DMEMD0, sbCmd[i]);
    }
    mmio_write32(SEC2_DMEMC0, 0x6C4);
    mmio_write32(SEC2_DMEMD0, 0x19);
    mmio_write32(SEC2_BOOTVEC, 0);
    __asm__ volatile("wbinvd" ::: "memory");
    mmio_write32(SEC2_CPUCTL, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);

    {
        UINT32 priv0 = mmio_read32(0x00118128);
        UINT32 privA;
        uefi_call_wrapper(BS->Stall, 1, 500000);
        privA = mmio_read32(0x00118128);
        sbChanged = (privA != priv0);
        Print(L"[5] SB (0x19): privmask 0x%08x -> 0x%08x%s\n",
              priv0, privA, sbChanged ? L" <<< ИЗМЕНЕНИЕ (SB сработал!)" : L"");
    }
    dump_regs(L"[5-sb]");

    Print(L"[5] итог: WPR2=%s SB=%s PLM=0x%08x\n",
          wpr2set ? L"OK" : L"нет", sbChanged ? L"OK" : L"нет",
          mmio_read32(REG_FEAT_OVR_PLM));

    return wpr2set || sbChanged || is_unlocked();
}

/* ==== Register monitor: key-register snapshots + block sweeps ====
 * Вывод доступен напрямую (serial → файл) — регулярно читаем ВСЕ ключевые
 * регистры: слепок + свипы блоков на каждой фазе, поллинг каждые 500мс. */
static void
dump_key_regs(const CHAR16 *tag)
{
    Print(L"\n--- REGS [%s] ---\n", tag);
    Print(L"PLM=0x%08x SS0=0x%08x SS1=0x%08x GFW=0x%08x WPR2lo=0x%08x WPR2hi=0x%08x\n",
        mmio_read32(REG_FEAT_OVR_PLM), mmio_read32(REG_FEAT_OVR_SM_SPD),
        mmio_read32(REG_FEAT_OVR_SM_SPD_1), mmio_read32(REG_GFW_BOOT_OK),
        mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));
    Print(L"SEC2: cpuctl=0x%08x irq=0x%08x dbg=0x%08x dmactl=0x%08x dmatrfcmd=0x%08x engine=0x%08x bcr=0x%08x\n",
        mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_IRQSTAT),
        mmio_read32(SEC2_DEBUGINFO), mmio_read32(SEC2_DMACTL),
        mmio_read32(SEC2_DMATRFCMD), mmio_read32(SEC2_ENGINE),
        mmio_read32(SEC2_BCR_CTRL));
    Print(L"RV:   cpuctl=0x%08x tracectl=0x%08x rdidx=0x%08x wtidx=0x%08x\n",
        mmio_read32(NV_FALCON2_SEC_BASE + 0x388),
        mmio_read32(NV_FALCON2_SEC_BASE + 0x400),
        mmio_read32(NV_FALCON2_SEC_BASE + 0x404),
        mmio_read32(NV_FALCON2_SEC_BASE + 0x408));
    Print(L"GSP:  cpuctl=0x%08x engine=0x%08x mbox0=0x%08x mbox1=0x%08x\n",
        mmio_read32(GSP_BASE + 0x100), mmio_read32(GSP_ENGINE),
        mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_MAILBOX1));
    Print(L"PTIMER=0x%08x PMC_BOOT0=0x%08x FBsz=0x%08x\n",
        mmio_read32(NV_PTIMER_TIME_0), mmio_read32(0x00100000),
        mmio_read32(0x00100440));
}

static void
sweep_regs(const CHAR16 *name, UINTN base, UINTN count)
{
    UINTN r;
    Print(L"SWEEP %s (0x%06x, %d regs):\n", name, (UINTN)base, (INTN)count);
    for (r = 0; r < count; r++) {
        UINT32 v = mmio_read32(base + r * 4);
        if (v != 0)
            Print(L"  0x%06x = 0x%08x\n", (UINTN)(base + r * 4), v);
    }
}

static void
sweep_all(const CHAR16 *tag)
{
    Print(L"\n######## SWEEPS [%s] ########\n", tag);
    sweep_regs(L"FEAT_OVR", 0x00823800, 12);
    sweep_regs(L"SEC2", 0x00840000, 256);
    sweep_regs(L"SEC2_FBIF", 0x00840600, 16);
    sweep_regs(L"FALCON2", 0x00841000, 192);
    sweep_regs(L"GSP", 0x00110000, 64);
    sweep_regs(L"GSP_MBOX", 0x00110800, 8);
    sweep_regs(L"PFB_WPR", 0x001FA800, 8);
    sweep_regs(L"GFW", 0x00118200, 16);
    sweep_regs(L"PTIMER", 0x00009400, 8);
}

/* ==== Preload probe: read GSP/SEC2 IMEM+DMEM (NS|SEC views) FIRST ====
 * Must run before ANY engine reset or DMA. Shows whether the VBIOS
 * preload (FWSEC in GSP secure IMEM, SEC2 ucode) is still alive:
 * Читаем GSP/SEC2 IMEM+DMEM (NS и SEC-виды) ПЕРВЫМИ действиями приложения —
 * до engine-reset'ов и DMA. Ответ: живёт ли предзагрузка VBIOS (FWSEC в GSP
 * secure IMEM, SEC2 ucode) внутри QEMU/vfio, или vfio/FLR её убил. */
#define GSP_IMEMC0   (GSP_BASE + 0x180)
#define GSP_IMEMD0   (GSP_BASE + 0x184)
#define GSP_DMEMC0   (GSP_BASE + 0x1C0)
#define GSP_DMEMD0   (GSP_BASE + 0x1C4)
static void
probe_preload(void)
{
    UINTN i;
    Print(L"\n=== v2.57-4: ЗОНД ПРЕДЗАГРУЗКИ (IMEM/DMEM GSP+SEC2, NS|SEC) ===\n");
    Print(L"[pre] GSP IMEM[0x00..0x2F]:\n");
    for (i = 0; i < 0x30; i += 4) {
        UINT32 vn, vs;
        mmio_write32(GSP_IMEMC0, i);
        vn = mmio_read32(GSP_IMEMD0);
        mmio_write32(GSP_IMEMC0, i | (1 << 28));
        vs = mmio_read32(GSP_IMEMD0);
        Print(L"[pre]   gsp-imem %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }
    Print(L"[pre] GSP DMEM[0x00..0x2F]:\n");
    for (i = 0; i < 0x30; i += 4) {
        UINT32 vn, vs;
        mmio_write32(GSP_DMEMC0, i);
        vn = mmio_read32(GSP_DMEMD0);
        mmio_write32(GSP_DMEMC0, i | (1 << 28));
        vs = mmio_read32(GSP_DMEMD0);
        Print(L"[pre]   gsp-dmem %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }
    Print(L"[pre] SEC2 IMEM[0x00..0x2F]:\n");
    for (i = 0; i < 0x30; i += 4) {
        UINT32 vn, vs;
        mmio_write32(SEC2_IMEMC0, i);
        vn = mmio_read32(SEC2_IMEMD0);
        mmio_write32(SEC2_IMEMC0, i | (1 << 28));
        vs = mmio_read32(SEC2_IMEMD0);
        Print(L"[pre]   sec2-imem %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }
    Print(L"[pre] SEC2 DMEM[0x00..0x2F]:\n");
    for (i = 0; i < 0x30; i += 4) {
        UINT32 vn, vs;
        mmio_write32(SEC2_DMEMC0, i);
        vn = mmio_read32(SEC2_DMEMD0);
        mmio_write32(SEC2_DMEMC0, i | (1 << 28));
        vs = mmio_read32(SEC2_DMEMD0);
        Print(L"[pre]   sec2-dmem %04x: ns=0x%08x sec=0x%08x\n", i, vn, vs);
    }
    Print(L"[pre] GSP BCR=0x%x SEC2 BCR=0x%x (CORE_SELECT: 0=FALCON 1=RISCV)\n",
          mmio_read32(GSP_BASE + 0x668), mmio_read32(SEC2_BCR_CTRL));
}

/* ==== Shortcut probe: do plain host MMIO writes stick? ====
 * If PLM accepts 0xFFFFFFFF written directly from the host side, the
 * whole booter path is unnecessary (unlock = 3 writes). On a locked
 * card the writes bounce back as RO patterns — costs nothing, saves
 * the full sequence on warm re-runs:
 * НЕ ТЕСТИРОВАЛОСЬ: прилипают ли записи PLM/SS0/SS1 с хоста (BAR0 MMIO)
 * напрямую, без GSP/booter (V67-цепочки). Если PLM=0xFFFFFFFF прилипает —
 * весь BROM/FWSEC/WPR2 путь не нужен: анлок = 3 записи.
 * Порядок: open (0xFFFFFFFF) → если прилипло, SS0/SS1 → полный анлок.
 * Если нет — диагностические значения (0x0, 0xFFFFFFFE, 0x11111111) при
 * закрытом PLM — ничего не теряем. */
static BOOLEAN
direct_write_probe(void)
{
    UINT32 v;

    Print(L"\n--- v2.26: ПРЯМАЯ запись FEAT_OVR (host probe) ---\n");
    mmio_write32(REG_FEAT_OVR_PLM, VAL_PLM_OPEN);
    v = mmio_read32(REG_FEAT_OVR_PLM);
    Print(L"probe: PLM=0x%08x после записи 0xFFFFFFFF (0xFFFFFF8F = запись игнор)\n", v);

    mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
    mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
    Print(L"probe: SS0=0x%08x SS1=0x%08x после записи 0x88888888/0x8\n",
          mmio_read32(REG_FEAT_OVR_SM_SPD), mmio_read32(REG_FEAT_OVR_SM_SPD_1));

    if (is_unlocked()) {
        Print(L"probe: *** ПРЯМЫЕ ЗАПИСИ РАБОТАЮТ — GPU открыт без booter ***\n");
        return TRUE;
    }

    Print(L"probe: диагностика (регистр закрыт?):\n");
    mmio_write32(REG_FEAT_OVR_PLM, 0x00000000);
    Print(L"probe:   PLM=0x%08x после 0x0 (закрыть)\n", mmio_read32(REG_FEAT_OVR_PLM));
    mmio_write32(REG_FEAT_OVR_PLM, 0xFFFFFFFE);
    Print(L"probe:   PLM=0x%08x после 0xFFFFFFFE (bit0 flip)\n", mmio_read32(REG_FEAT_OVR_PLM));
    mmio_write32(REG_FEAT_OVR_SM_SPD, 0x11111111);
    Print(L"probe:   SS0=0x%08x после 0x11111111\n", mmio_read32(REG_FEAT_OVR_SM_SPD));
    mmio_write32(REG_FEAT_OVR_SM_SPD_1, 0x00000000);
    Print(L"probe:   SS1=0x%08x после 0x0\n", mmio_read32(REG_FEAT_OVR_SM_SPD_1));
    return FALSE;
}

/* ==== Dev experiment: start the RISC-V core directly, bypassing BROM ====
 * Writes BCR CORE_SELECT=RISCV itself and starts the CPU without BROM
 * verification (no FWSEC/WPR2/signature), placing own_code_67 at several
 * IMEM addresses. Historically never opened PLM alone; diagnostic value.
 * v2.11-v2.24: BROM-хендофф (BOOTVEC+STARTCPU → BROM сам переключает ядро
 * в RISC-V). BROM отказывается (dbg=0x0, bcr=FALCON) — не из-за RM (v2.24),
 * не из-за контента IMEM (v2.23). НОВАЯ гипотеза: пишем BCR CORE_SELECT=
 * RISCV САМИ и стартуем ядро напрямую, минуя BROM-верификацию (без FWSEC/
 * WPR2/сигнатуры). Наш CSB-код разложен по IMEM (0/0x100/0x1000/0x2000/
 * 0x4000/0x8000). Старт: cpuctl SEC2 (0x840100) и/или cpuctl RISC-V (0x841388).
 * Наблюдаем каждые 500мс: PLM/SS0/SS1 + trace (0x841404/40C/410). */
static BOOLEAN
riscv_direct_start(void)
{
    UINTN a;
    BOOLEAN opened = FALSE;

    /* (bcr, bootvec, cpu: 0=SEC2 0x840100, 1=RV 0x841388) */
    static const UINT32 try_bcr[] = { 0x111, 0x110, 0x111, 0x110 };
    static const UINT32 try_vec[] = { 0x100, 0x000, 0x100, 0x000 };
    static const UINT32 try_cpu[] = {    0,    0,    1,    1 };

    Print(L"\n--- v2.25: ПРЯМОЙ запуск RISC-V (обход BROM) ---\n");
    for (a = 0; a < 4; a++) {
        UINT32 cpuAddr = try_cpu[a] ? (NV_FALCON2_SEC_BASE + 0x388) : SEC2_CPUCTL;
        UINTN  p;
        UINT32 bcrNow;

        mmio_write32(SEC2_BCR_CTRL, try_bcr[a]);
        {
            UINTN j;
            for (j = 0; j < 16; j++) mmio_read32(SEC2_BCR_CTRL);
        }
        bcrNow = mmio_read32(SEC2_BCR_CTRL);
        mmio_write32(SEC2_BOOTVEC, try_vec[a]);
        mmio_write32(cpuAddr, NV_PFALCON_FALCON_CPUCTL_STARTCPU_TRUE);
        Print(L"riscv: попытка %d: BCR=0x%x (читается 0x%x) BOOTVEC=0x%x cpu=0x%x STARTCPU\n",
              (INTN)a + 1, try_bcr[a], bcrNow, try_vec[a], cpuAddr);

        for (p = 0; p < 4; p++) {   /* 4 × 500мс = 2с */
            uefi_call_wrapper(BS->Stall, 1, 500000);
            dump_key_regs(L"riscv-poll");
            if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) break;
        }
        if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) { opened = TRUE; break; }
    }
    return opened;
}

/* ==== Legacy: GSP-mailbox booter-load command path ====
 * Driver protocol: mailboxes 0x110040/44 = phys(WPR meta), command port
 * 0x110804 (0x554 init, 0x57c booter load; 0x65 = OK, 0x55 = busy).
 * Superseded by direct falcon loading; retained for diagnostics.
 * Протокол Windows-драйвера (booter_load 0xb74240):
 *   GSP mailboxes 0x110040/0x110044 = phys(WPR meta) — аргумент команды
 *   PGSP_MAILBOX 0x110804 = команда (0x554 init, 0x57c booter load)
 *   статусы в 0x110804: 0x65 = OK, 0x55 = busy
 * GSP-блок доступен с хоста (v2.10: реальные значения, не 0xBADF),
 * в отличие от SEC2 (залочен PLM). */
static EFI_STATUS
gsp_mailbox_booter_load(UINT64 wprMetaPhys)
{
    UINTN i;
    UINT32 st = 0;

    Print(L"gspmail: WPR meta @0x%lx\n", wprMetaPhys);
    mmio_write32(0x110040, (UINT32)(wprMetaPhys & 0xFFFFFFFF));
    mmio_write32(0x110044, (UINT32)(wprMetaPhys >> 32));

    /* 0x554 — init */
    Print(L"gspmail: cmd 0x554 (init)...\n");
    mmio_write32(0x110804, 0x554);
    for (i = 0; i < 5000; i++) {
        st = mmio_read32(0x110804);
        if (st == 0x65 || st == 0x55) break;
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"gspmail: init -> status 0x%08x через %d ms (mbox0=0x%x mbox1=0x%x)\n",
          st, i, mmio_read32(0x110040), mmio_read32(0x110044));
    if (st != 0x65 && st != 0x55)
        Print(L"gspmail: ВНИМАНИЕ — статус init не 0x65/0x55\n");

    /* 0x57c — booter load (V67-сигнатура в WPR meta) */
    Print(L"gspmail: cmd 0x57c (booter load, V67)...\n");
    mmio_write32(0x110804, 0x57c);
    for (i = 0; i < 5000; i++) {
        st = mmio_read32(0x110804);
        if (st == 0x65 || st == 0x55) break;
        if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) break;
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"gspmail: load -> status 0x%08x через %d ms (mbox0=0x%x mbox1=0x%x PLM=0x%x)\n",
          st, i, mmio_read32(0x110040), mmio_read32(0x110044),
          mmio_read32(REG_FEAT_OVR_PLM));

    if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN)
        return EFI_SUCCESS;
    return EFI_TIMEOUT;
}

/* ==== PCIe Function Level Reset ====
 * Walks the capability list, sets Device Control bit 15. FLR is the ONLY
 * reset that clears a latched WPR2 (direct writes bounce even with PLM
 * open); the unlocked masks/selectors survive it. */
static EFI_STATUS
do_flr(void)
{
    UINT32 capPtr = cfg_read32(0x34) & 0xFF;
    while (capPtr && capPtr < 0x100) {
        UINT32 hdr = cfg_read32(capPtr);
        if ((hdr & 0xFF) == 0x10) {           /* PCIe Express capability */
            UINT16 devctl;                    /* Device Control = cap+0x08 */
            devctl = (UINT16)cfg_read32(capPtr + 0x08);
            cfg_write32(capPtr + 0x08, devctl | (1 << 15));  /* Initiate FLR */
            uefi_call_wrapper(BS->Stall, 1, 200000);  /* 200ms */
            Print(L"FLR: issued (pcie cap @0x%x)\n", capPtr);
            return EFI_SUCCESS;
        }
        capPtr = (hdr >> 8) & 0xFF;
    }
    Print(L"FLR: PCIe capability не найден\n");
    return EFI_NOT_FOUND;
}

/* ==== PCIe gen unlock experiments (flag PCIE_GEN_EXPERIMENT) ====
 * Method verified on CMP 170HX/GA100 (cmp170hx-gen2): phase 1 publishes
 * capabilities GPU-side (XVE window, BAR0 base 0x88000), phase 2
 * retrains the link. Offsets cross-checked against upstream regmap
 * dev_nv_pcfg_xve_regmap.h. Retrain happens naturally when the link
 * comes back, so this runs strictly BEFORE any FLR; no MMIO after.
 * Stand finding: a LIVE GSP guards link regs and discards writes —
 * on real HW phase3 runs pre-OS, before any GSP exists.
 * Метод верифицирован на CMP 170HX/GA100 (luannanxian/cmp170hx-gen2,
 * upstream amoghmunikote/cmpunlocker ветка Gen2): фаза 1 — публикация
 * capability на GPU-стороне, фаза 2 — ретрейн. У них каждая запись шла
 * через перезапуск SEC2-ботера (у RM нет priv); у нас PLM уже открыт —
 * пишем напрямую в XVE-окно BAR0. Смещения сверены с официальной regmap:
 * open-gpu-kernel-modules ampere/ga102/dev_nv_pcfg_xve_regmap.h
 * (XVE-окно GA102 = база 0x88000; LINK_CAP@0x84, LC_STATUS@0x88 speed[19:16]
 * width[9:4], CAP2@0xA4, LC2@0xA8 target[3:0], PRIV_MISC_1@0x41C,
 * VSEC@0x60C/0x610, XVE_D0/D4/D8@0xFE8/EC/F0).
 * Ретрейн происходит сам при восстановлении линка после FLR — поэтому
 * стадия строго ДО FLR (BAR живой), пост-FLR MMIO не трогаем (уроки v2.87). */
#ifdef PCIE_GEN_EXPERIMENT
#ifndef PCIE_GEN_TARGET
#define PCIE_GEN_TARGET 3   /* 2=Gen2, 3=Gen3, 4=Gen4 — лестница тестов */
#endif

#define XVE_LINK_CAP         0x00088084u
#define XVE_LINK_CTRL_STATUS 0x00088088u
#define XVE_LINK_CAP2        0x000880a4u
#define XVE_LINK_CTRL_2      0x000880a8u
#define XVE_PRIV_MISC_1      0x0008841cu
#define XVE_VSEC_DEVICE      0x0008860cu
#define XVE_VSEC_HIERARCHY   0x00088610u
#define XVE_LTSSM_OVR        0x0008872cu
#define XVE_D0               0x00088fe8u
#define XVE_D4               0x00088fecu
#define XVE_D8               0x00088ff0u

/* v2.93: priv-домены PCIe-блока. FEAT_OVR — РОДНОЕ семейство наших
 * PLM(0x823804)/SS0(0x82381C)/SS1(0x823820); у GA100 в этой же странице
 * сидит FEAT_OVR_ECC_PLM=0x00823800. OPT_* — fuse-shadow регистры
 * с битами поддерживаемых gen (имена из патча 0007 GA100).
 * XP3G — приватный домен PCIe IP (смещения GA100, регион валиден на
 * GA102 по regmap 0x8E000-0x8EFFC). */
#define PCIE_FEAT_OVR_ECC    0x00823800u
#define PCIE_OPT_MAGIC       0x00820520u
#define PCIE_OPT_GEN23       0x0082057cu
#define PCIE_OPT_GEN3        0x00820580u
/* v2.95: OPTB — priv-домен страницы 0x82xxxx (у GA100: 10 регов D0..F4=FF) */
#define PCIE_OPTB_BASE       0x008200d0u
#define PCIE_OPTB_COUNT      10u
/* v2.96: регистры из рабочего CMP90-патча (GA102, device 0x20B0):
 * FUSE_OVERRIDE — снятие fuse-лока PCIe gen (та же FEAT_OVR-страница,
 * что PLM/SS0/SS1!), LINK_CONTROL/LINK_SPEED — PL-блок как у GA100 */
#define PCIE_FUSE_OVERRIDE   0x00823810u
#define PCIE_LINK_CONTROL    0x0008c000u
#define PCIE_LINK_SPEED_CFG  0x0008c040u
#define PCIE_XP3G_PLM0       0x0008e1b0u
#define PCIE_XP3G_OVR0       0x0008e110u
#define PCIE_XP3G_VAL0       0x0008e120u
#define PCIE_XP3G_OVR3       0x0008e11cu
#define PCIE_XP3G_VAL3       0x0008e12cu

static int pcie_gen_fails;

static void
pcie_gen_status(const CHAR16 *tag)
{
    UINT32 st = mmio_read32(XVE_LINK_CTRL_STATUS);
    Print(L"pcie-gen %s: LNKSTA=0x%08x speed=%d width=%d CAP=0x%08x CAP2=0x%08x LC2=0x%08x\n",
          tag, st, (st >> 16) & 0xF, (st >> 4) & 0x3F,
          mmio_read32(XVE_LINK_CAP), mmio_read32(XVE_LINK_CAP2),
          mmio_read32(XVE_LINK_CTRL_2));
}

static void
pcie_gen_wr_verify(UINTN off, UINT32 want, const CHAR16 *name)
{
    UINT32 rd;
    mmio_write32(off, want);
    rd = mmio_read32(off);
    if (rd != want) {
        pcie_gen_fails++;
        Print(L"pcie-gen: FAIL %s(0x%06x): want=0x%08x got=0x%08x\n",
              name, off, want, rd);
    } else {
        Print(L"pcie-gen: ok %s=0x%08x\n", name, rd);
    }
}

static void
pcie_gen_unlock_debug(UINT64 wprMetaPhys, UINT64 ucodePhys, UINT64 v67Phys)
{
    UINT32 v;
    EFI_STATUS st;

    Print(L"\n=== pcie-gen: разблокировка PCIe Gen%d (v2.97 booter-write) ===\n",
          PCIE_GEN_TARGET);
    pcie_gen_fails = 0;
    pcie_gen_status(L"pre ");

    /* Шаг 0 (v2.97): снятие fuse-лока ЧЕРЕЗ БОТЕР (falcon priv, как
     * kgspCmp90RefillPayload у драйвера): патчим {value@0xf948,
     * addr@0xf960} в копии V67-payload в ОЗУ и гоним второй прогон ботера.
     * booter_load_v67 сам делает полный ресет SEC2 на входе. */
    if (v67Phys && ucodePhys) {
        volatile UINT32 *pv = (volatile UINT32 *)(UINTN)(v67Phys + 0xf948);
        volatile UINT32 *pa = (volatile UINT32 *)(UINTN)(v67Phys + 0xf960);
        Print(L"pcie-gen: v97: payload value@0xf948=0x%08x addr@0xf960=0x%08x\n",
              *pv, *pa);
        *pv = 0x00000000u;
        *pa = PCIE_FUSE_OVERRIDE;
        Print(L"pcie-gen: booter#2 (PCIE_FUSE=0)...\n");
        st = booter_load_v67(wprMetaPhys, ucodePhys);
        Print(L"pcie-gen: booter#2: %r, FUSE_OVR=0x%08x (want 0)\n",
              st, mmio_read32(PCIE_FUSE_OVERRIDE));
    } else {
        Print(L"pcie-gen: v97: нет payload-контекста — booter-запись пропущена\n");
    }

    /* v2.93: дамп fuse-shadow страницы FEAT_OVR/OPT (родня PLM/SS0/SS1).
     * OPT_MAGIC должен показать сигнатуру, если OPT-space живёт тут же. */
    Print(L"pcie-gen: FEAT_OVR[0x823800..04]=0x%08x/0x%08x  SS0=0x%08x SS1=0x%08x\n",
          mmio_read32(PCIE_FEAT_OVR_ECC), mmio_read32(REG_FEAT_OVR_PLM),
          mmio_read32(REG_FEAT_OVR_SM_SPD), mmio_read32(REG_FEAT_OVR_SM_SPD_1));
    Print(L"pcie-gen: OPT_MAGIC(0x820520)=0x%08x GEN23(0x82057c)=0x%08x GEN3(0x820580)=0x%08x\n",
          mmio_read32(PCIE_OPT_MAGIC), mmio_read32(PCIE_OPT_GEN23),
          mmio_read32(PCIE_OPT_GEN3));

    /* Шаг 1 (v2.95): OPTB priv-домен страницы 0x82xxxx — как у GA100,
     * 10 регистров 0x8200D0..F4 = FF. Открывает OPT/fuse-shadow записи. */
    {
        UINTN i;
        for (i = 0; i < PCIE_OPTB_COUNT; i++)
            pcie_gen_wr_verify(PCIE_OPTB_BASE + i * 4, 0xFFFFFFFFu, L"OPTB");
    }
    /* Шаг 1b: FEAT_OVR ECC-страница + XP3G PCIe IP (v2.93, ретрай) */
    pcie_gen_wr_verify(PCIE_FEAT_OVR_ECC, 0xFFFFFFFFu, L"FEAT_OVR_ECC");
    {
        int i;
        for (i = 0; i < 4; i++)
            pcie_gen_wr_verify(PCIE_XP3G_PLM0 + i * 4, 0xFFFFFFFFu, L"XP3G_PLM");
    }
    /* XP3G overrides как у GA100: OVR0=1/VAL0=0, OVR3=4/VAL3=0x00200000 */
    pcie_gen_wr_verify(PCIE_XP3G_VAL0, 0x00000000u, L"XP3G_VAL0");
    pcie_gen_wr_verify(PCIE_XP3G_OVR0, 0x00000001u, L"XP3G_OVR0");
    pcie_gen_wr_verify(PCIE_XP3G_VAL3, 0x00200000u, L"XP3G_VAL3");
    pcie_gen_wr_verify(PCIE_XP3G_OVR3, 0x00000004u, L"XP3G_OVR3");

    /* Шаг 2 (v2.95): OPT-биты gen — GA100 клал GEN23=0; пробуем и GEN3=0.
     * Это fuse-shadow — та же семья, что SS0/SS1, может принять запись. */
    pcie_gen_wr_verify(PCIE_OPT_GEN23, 0x00000000u, L"OPT_GEN23");
    pcie_gen_wr_verify(PCIE_OPT_GEN3, 0x00000000u, L"OPT_GEN3");

    /* Шаг 2: priv-домены XVE (как у GA100: XVE_D0/D4/D8 = FF) — повторно,
     * уже после открытия доменов шага 1 */
    mmio_write32(XVE_D0, 0xFFFFFFFFu);
    mmio_write32(XVE_D4, 0xFFFFFFFFu);
    mmio_write32(XVE_D8, 0xFFFFFFFFu);
    Print(L"pcie-gen: XVE_D0/D4/D8 = 0x%x/0x%x/0x%x\n",
          mmio_read32(XVE_D0), mmio_read32(XVE_D4), mmio_read32(XVE_D8));

    /* PRIV_MISC_1: set bits(11|13), clear bits(12|14) — семантика GA100 */
    v = mmio_read32(XVE_PRIV_MISC_1);
    pcie_gen_wr_verify(XVE_PRIV_MISC_1,
                       (v | (1u << 11) | (1u << 13)) & ~((1u << 12) | (1u << 14)),
                       L"PRIV_MISC_1");

    /* VSEC_HIERARCHY: clear bit12, set bit0 */
    v = mmio_read32(XVE_VSEC_HIERARCHY);
    pcie_gen_wr_verify(XVE_VSEC_HIERARCHY, (v & ~(1u << 12)) | 1u,
                       L"VSEC_HIERARCHY");

    /* VSEC_DEVICE: set bit0 */
    v = mmio_read32(XVE_VSEC_DEVICE);
    pcie_gen_wr_verify(XVE_VSEC_DEVICE, v | 1u, L"VSEC_DEVICE");

    /* LINK_CAP: MAX_LINK_SPEED[3:0] = target */
    v = mmio_read32(XVE_LINK_CAP);
    pcie_gen_wr_verify(XVE_LINK_CAP, (v & ~0xFu) | PCIE_GEN_TARGET, L"LINK_CAP");

    /* LINK_CAP2: как GA100 0x2→0x6 (set bits 1|2) */
    v = mmio_read32(XVE_LINK_CAP2);
    pcie_gen_wr_verify(XVE_LINK_CAP2, v | 0x6u, L"LINK_CAP2");

    /* LINK_CTRL_2: TARGET_LINK_SPEED = target + биты [19:16]=F как у GA100 */
    v = mmio_read32(XVE_LINK_CTRL_2);
    pcie_gen_wr_verify(XVE_LINK_CTRL_2,
                       (v & ~0xFu) | PCIE_GEN_TARGET | 0x000F0000u,
                       L"LINK_CTRL_2");

    /* Шаг 2b (v2.96): ГЛАВНАЯ ПРОБА — регистры из рабочего CMP90-патча.
     * FUSE_OVERRIDE=0 снимает fuse-лок gen; LINK_CONTROL=target выбирает
     * скорость. Оба пишутся хостом ПОСЛЕ открытия PLM (у нас он открыт). */
    pcie_gen_wr_verify(PCIE_FUSE_OVERRIDE, 0x00000000u, L"PCIE_FUSE_OVR");
    pcie_gen_wr_verify(PCIE_LINK_CONTROL, (UINT32)PCIE_GEN_TARGET,
                       L"LINK_CONTROL");
    Print(L"pcie-gen: LINK_SPEED_CFG(0x8c040)=0x%08x\n",
          mmio_read32(PCIE_LINK_SPEED_CFG));

    /* Шаг 3 (v2.95): фолбэк — запись Link Cap через ХОСТОВОЕ конфиг-
     * пространство. XVE-зеркало шарит смещения с cfg (Link Cap = pcie_cap
     * +0x0C); вдруг cfg-запись хоста обслуживается минуя MMIO-гейт. */
    {
        UINT32 capPtr = cfg_read32(0x34) & 0xFF, lnkcapOff = 0, cur;
        while (capPtr && capPtr < 0x100) {
            UINT32 hdr = cfg_read32(capPtr);
            if ((hdr & 0xFF) == 0x10) { lnkcapOff = capPtr + 0x0C; break; }
            capPtr = (hdr >> 8) & 0xFF;
        }
        if (lnkcapOff) {
            cur = cfg_read32(lnkcapOff);
            Print(L"pcie-gen: host-cfg LNKCAP(0x%02x)=0x%08x\n", lnkcapOff, cur);
            cfg_write32(lnkcapOff, (cur & ~0xFu) | PCIE_GEN_TARGET);
            Print(L"pcie-gen: host-cfg LNKCAP post=0x%08x (want max_speed=%d)\n",
                  cfg_read32(lnkcapOff), PCIE_GEN_TARGET);
        } else {
            Print(L"pcie-gen: host-cfg: PCIe capability не найден\n");
        }
    }

    Print(L"pcie-gen: LTSSM_OVR(0x8872c)=0x%08x (только чтение)\n",
          mmio_read32(XVE_LTSSM_OVR));

    pcie_gen_status(L"post");
    Print(L"pcie-gen: готово, fail=%d (ретрейн — при восстановлении линка после FLR)\n",
          pcie_gen_fails);
}
#endif /* PCIE_GEN_EXPERIMENT */

/* ==== gsp_ga10x.bin loader via SimpleFileSystem (LEGACY helper) ====
 * The main flow reads the firmware with raw BlockIo instead — SFS
 * operations hang on some AMI firmwares (see preload_bootmgfw). */
static EFI_STATUS
read_fwimage(EFI_HANDLE DeviceHandle, UINT8 **pOut, UINTN *pSize)
{
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FS = NULL;
    EFI_FILE_PROTOCOL *Root = NULL, *File = NULL;
    EFI_STATUS Status;
    UINT8 *Buf = NULL;
    UINTN BufSize = 0;
    static EFI_GUID FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    static EFI_GUID FileInfoGuid = EFI_FILE_INFO_ID;

    Status = uefi_call_wrapper(BS->HandleProtocol, 3, DeviceHandle,
                               &FsGuid, (VOID**)&FS);
    if (EFI_ERROR(Status)) { Print(L"fw: no FS: %r\n", Status); return Status; }

    Status = uefi_call_wrapper(FS->OpenVolume, 2, FS, &Root);
    if (EFI_ERROR(Status)) { Print(L"fw: OpenVolume: %r\n", Status); return Status; }

    Status = uefi_call_wrapper(Root->Open, 5, Root, &File, L"\\gsp_ga10x.bin", EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) { Print(L"fw: \\gsp_ga10x.bin: %r\n", Status); return Status; }

    /* размер файла */
    {
        EFI_FILE_INFO *Info = NULL;
        UINTN InfoSize = sizeof(EFI_FILE_INFO) + 256;
        Info = AllocatePool(InfoSize);
        if (!Info) return EFI_OUT_OF_RESOURCES;
        Status = uefi_call_wrapper(File->GetInfo, 4, File, &FileInfoGuid, &InfoSize, Info);
        if (EFI_ERROR(Status)) { FreePool(Info); return Status; }
        BufSize = Info->FileSize;
        FreePool(Info);
    }
    if (BufSize == 0 || BufSize > 0x6000000ULL) {  /* до 96MB */
        Print(L"fw: подозрительный размер %d\n", BufSize);
        return EFI_LOAD_ERROR;
    }

    Buf = AllocatePool(BufSize);
    if (!Buf) { Print(L"fw: no mem\n"); return EFI_OUT_OF_RESOURCES; }

    /* Читаем чанками по 2МБ (некоторые прошивки режут Read до малого размера;
     * 84МБ одним вызовом может висеть). Прогресс каждые 16МБ. */
    {
        UINTN total = 0;
        UINTN chunk = 0x200000;   /* 2MB */
        while (total < BufSize) {
            UINTN rd = (BufSize - total < chunk) ? (BufSize - total) : chunk;
            Status = uefi_call_wrapper(File->Read, 3, File, &rd, Buf + total);
            if (EFI_ERROR(Status)) {
                Print(L"fw: read err @%d: %r\n", total, Status);
                return EFI_LOAD_ERROR;
            }
            if (rd == 0) {
                Print(L"fw: EOF до конца файла (%d/%d)\n", total, BufSize);
                return EFI_LOAD_ERROR;
            }
            total += rd;
            if ((total & 0xFFFFFF) == 0 || total >= BufSize)
                Print(L"fw: ... %d / %d МБ\n", (total >> 20), (BufSize >> 20));
        }
    }
    uefi_call_wrapper(File->Close, 1, File);
    *pOut = Buf;
    *pSize = BufSize;
    Print(L"fw: прочитано %d байт gsp_ga10x.bin\n", BufSize);
    return EFI_SUCCESS;
}

/* ==== radix3 page-table builder (generic form) ====
 * NOTE: efi_main() builds the table inline following the exact driver
 * layout (root + L1 + nL2 pages + data); this generic variant is kept
 * for reference/experiments only. */
static UINT64
build_radix3(UINT8 *Buf, UINT64 physBase, const UINT8 *Data, UINT64 size)
{
    /* 4 уровня; размер данных страницами */
    UINT64 n3 = (size + RADIX_PAGE_SIZE - 1) >> RADIX_PAGE_LOG2;
    UINT64 n2 = (n3 - 1) / RADIX_ENTRIES + 1;
    UINT64 n1 = (n2 - 1) / RADIX_ENTRIES + 1;
    UINT64 off1 = (1ULL) << RADIX_PAGE_LOG2;                 /* L1 PDEs (L0=1 страница) */
    UINT64 off2 = (1ULL + n1) << RADIX_PAGE_LOG2;            /* L2 PTEs */
    UINT64 off3 = (1ULL + n1 + n2) << RADIX_PAGE_LOG2;       /* данные */
    UINT64 i;

    if (n1 != 1) { Print(L"radix3: n1=%d (ожидалось 1)\n", n1); return 0; }

    /* L0 PDE → страница L1 */
    *(UINT64*)(Buf + 0) = physBase + off1;
    /* L1 PDEs → страницы L2 */
    for (i = 0; i < n2; i++)
        *(UINT64*)(Buf + off1 + i*8) = physBase + off2 + i * RADIX_PAGE_SIZE;
    /* L2 PTEs → страницы данных */
    for (i = 0; i < n3; i++)
        *(UINT64*)(Buf + off2 + i*8) = physBase + off3 + i * RADIX_PAGE_SIZE;
    /* данные */
    CopyMem(Buf + off3, Data, size);

    Print(L"radix3: n3=%d n2=%d off3=0x%x total=0x%x\n", n3, n2, off3,
          off3 + (n3 << RADIX_PAGE_LOG2));
    return off3 + (n3 << RADIX_PAGE_LOG2);
}

/* ==== WPR meta construction — exact driver geometry ====
 * Formulas replicated from kgspPopulateWprMeta_TU102 (610.43.03).
 * fbSize proof: a working unlock's dmesg shows frts_offset=0x27fe00000,
 * back-solving to fbSize=0x280000000 (10 GB) with 1 MB PRAMIN and 1 MB
 * FRTS. An earlier fbSize 16x smaller gave garbage layout and the
 * booter bailed before touching the signature (halt 0x780009). Heap
 * size must be EXACTLY 0x7F00000 per live-driver dump — recomputing it
 * after alignment inflated the value and broke the layout (exit 0x91).=
 * Формулы из kgspPopulateWprMeta_TU102 (610.43.03).
 * ДОКАЗАТЕЛЬСТВО fbSize: dmesg рабочего анлока frts_offset=0x27fe00000 →
 * gspFwWprEnd=frtsOffset+frtsSize=0x27FF00000, vgaWorkspaceOffset+PRAMIN:
 * fbSize = 0x280000000 (10GB), PRAMIN = 1MB, frtsSize = 1MB (GA102).
 * Старый fbSize=0x28000000 (640MB!) был в 16 раз меньше — раскладка мусорная,
 * booter валился (v2.13: halt с DEBUGINFO=0x780009 до обработки сигнатуры). */
/* v2.78: 1 = СТОКОВЫЙ тест (настоящая подпись .fwsignature_ga10x из fw-контейнера,
 * sizeOfSignature=0x1000); 0 = V67-эксплойт (0xFA00). Один прогон = одна переменная. */
static UINTN cmp90_stockSig = 0;
/* v2.79: 1 = пропускать mapper-стадию [5] (ucodeId=10 на SEC2 — НЕТ в реальном
 * флоу драйвера; её abort-прогоны могут оставлять остатки в BROM-блоке) */
static UINTN cmp90_skipMapper = 1;
/* v2.81: бисекция abort-точки. 1 = портить magic в meta (если exit-код
 * изменится с 0x2 — ботер ДОХОДИТ до чтения meta и 0x2 возникает позже) */
static UINTN cmp90_corruptMeta = 0;

static void
build_wpr_meta(GspFwWprMeta *m, UINT64 elfPhys, UINT64 elfSize,
               UINT64 sigPhys, UINT64 fbSize, UINT64 blPhys, UINT64 blSize)
{
    UINT64 wprEnd;
    const UINT64 MB = 0x100000ULL;

    SetMem(m, sizeof(*m), 0);
    m->magic    = GSP_FW_WPR_META_MAGIC;
    m->revision = GSP_FW_WPR_META_REVISION;

    m->sysmemAddrOfRadix3Elf = elfPhys;
    m->sizeOfRadix3Elf       = elfSize;

    m->sysmemAddrOfSignature = sigPhys;
    m->sizeOfSignature = cmp90_stockSig ? 0x1000ULL : (UINT64)V67_SIZE;

    /* --- BL (GspRmBoot): сигнатура (V67) верифицируется ПРИ загрузке BL! ---
     * Оффсеты ПОДТВЕРЖДЕНЫ живым драйвером (2026-08-21, WPR meta дамп):
     * bootloaderCodeOffset=0x1800, bootloaderDataOffset=0x800,
     * bootloaderManifestOffset=0x0. (Правка v2.47 на 0x1000 была неверна —
     * декод desc дал сдвиг; живой дамп — истина.) */
    m->sysmemAddrOfBootloader = blPhys;
    m->sizeOfBootloader       = blSize;
    m->bootloaderCodeOffset   = 0x1800;
    m->bootloaderDataOffset   = 0x800;
    m->bootloaderManifestOffset = 0x0;

    /* --- FB layout (kgspPopulateWprMeta_TU102) --- */
    m->fbSize = fbSize;

    /* CMP90HX: нет display-fuse → vgaWorkspaceOffset = fbSize - PRAMIN(1MB) */
    m->vgaWorkspaceOffset = fbSize - 0x100000ULL;
    m->vgaWorkspaceSize   = fbSize - m->vgaWorkspaceOffset;   /* 1MB */

    /* End of WPR region, 128KB aligned (wprEndMargin=0 — по frts-математике dmesg) */
    wprEnd = m->vgaWorkspaceOffset & ~0x1FFFFULL;
    m->gspFwWprEnd = wprEnd;

    /* FRTS: 1MB на GA102 (kgspGetFrtsSize). FWSEC-шаг не выполняем, но регион
     * заявляем в meta — booter валидирует раскладку по этим полям */
    m->frtsSize   = 0x100000ULL;
    m->frtsOffset = m->gspFwWprEnd - m->frtsSize;    /* 0x27FE00000 */

    m->bootBinOffset = (m->frtsOffset - blSize) & ~0xFFFULL;  /* ALIGN_DOWN(4K) */

    /* Start of ELF (radix3), 64KB align */
    m->gspFwOffset = (m->bootBinOffset - elfSize) & ~0xFFFFULL;

    /* v2.63: ТОЧНЫЕ формулы kgspPopulateWprMeta_TU102 (дамп живого драйвера:
     * heap 0x272e00000-0x27acfffff size 0x7f00000, wprStart 0x272d00000,
     * nonWpr 0x272c00000/0x100000, flags=CLOCK_BOOST|0x1). Раньше heap был
     * 1MB вместо 127MB → ботер отбраковывал meta → exit 0x91!
     * v2.73: heapSize = РОВНО 0x7f00000 (живой дамп), БЕЗ перечета после
     * выравнивания offset — у драйвера между heap-end (0x27ad00000) и
     * gspFwOffset (0x27ada0000) гэп 0xA0000; наш перечет раздувал heap до
     * 0x7fa0000 и ломал раскладку.
     * v62: heap 依赖 FB 大小 — 0x7F00000 是 10GB(CMP90HX) 实测；40HX 8GB
     * 的 log53 真解 dmesg 显示 gspFwHeap=0x1f7900000+0x6900000 → 8GB 卡
     * heap = 0x6900000。按 fbSize 选值。 */
    m->gspFwHeapSize   = (fbSize == 0x280000000ULL) ? 0x7F00000ULL
                                                   : 0x6900000ULL;
    m->gspFwHeapOffset = (m->gspFwOffset - m->gspFwHeapSize) & ~(MB - 1);
    m->gspFwWprStart   = m->gspFwHeapOffset - MB;     /* wprMetaSize = 1MB */
    m->nonWprHeapSize  = MB;
    m->nonWprHeapOffset = m->gspFwWprStart - MB;
    m->gspFwRsvdStart  = m->nonWprHeapOffset;

    m->bootCount = 0;
    m->verified  = 0;
    m->pmuReservedSize = 0;
    m->gspFwHeapVfPartitionCount = 0;
    m->flags = 0x1;                    /* GSP_FW_FLAGS_CLOCK_BOOST */
}

#define WINDOWS_BOOT_PATH L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

/* ==== SFS-free bootmgfw preload — own FAT32 parser over BlockIo ====
 * This platform (X570 GAMING X, AMI F37d) HANGS on SimpleFileSystem
 * calls from loaded applications — hangs occurred on plain file reads
 * unrelated to the unlock. BlockIo ReadBlocks is stable (84 MB fw
 * reads OK). Solution: read bootmgfw.efi into RAM BEFORE the unlock
 * with our own FAT32 parser (MBR/GPT -> ESP -> path with LFN), keep
 * the ESP DevicePath, later LoadImage(SourceBuffer). Zero SFS calls
 * remain anywhere in the hot path.
 * Это железо (X570 GAMING X, AMI F37d) виснет на SimpleFileSystem-операциях
 * из загруженных приложений — история проекта (ранние версии висли на чтении
 * файла НЕЗАВИСИМО от анлока). BlockIo ReadBlocks стабилен (84МБ fw-read ОК).
 *
 * Решение: ЕЩЁ ДО разблокировки читаем bootmgfw.efi своим FAT32-парсером
 * поверх BlockIo (GPT→ESP→каталоги с LFN), держим в ОЗУ. После анлока:
 * LoadImage(DevicePath=<реальный ESP>, SourceBuffer=<ОЗУ>) + StartImage.
 * В нашем коде не остаётся НИ ОДНОЙ SimpleFileSystem-операции. */

static UINT8 *g_bmBuf = NULL;
static UINTN g_bmSize = 0;
static EFI_DEVICE_PATH *g_bmDp = NULL;

static EFI_GUID cmp90BioGuid = EFI_BLOCK_IO_PROTOCOL_GUID;
static UINT8 cmp90EspGuid[16] = { 0x28,0x73,0x2A,0xC1, 0x1F,0xF8, 0xD2,0x11,
                                  0xBA,0x4B, 0x00,0xA0,0xC9,0x3E,0xC9,0x3B };

/* аллокатор-обёртка (gnu-efi AllocatePool имеет другую арность) */
static VOID *cmp90_alloc(UINTN size)
{
    VOID *p = NULL;
    if (!size) return NULL;
    if (EFI_ERROR(uefi_call_wrapper(BS->AllocatePool, 3, EfiBootServicesData,
                                    size, &p)))
        return NULL;
    return p;
}

static void cmp90_free(VOID *p)
{
    if (p) uefi_call_wrapper(BS->FreePool, 1, p);
}

/* чтение байтового диапазона внутри раздела через BlockIo */
static EFI_STATUS
cmp90_bio_read(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
               UINT64 byteOff, UINTN size, VOID *dest)
{
    STATIC UINT8 bounce[4096];
    UINT32 bs = bio->Media->BlockSize;
    UINT64 off = byteOff;
    UINT8 *dst = (UINT8 *)dest;

    if (bs == 0 || bs > sizeof(bounce)) return EFI_INVALID_PARAMETER;
    while (size) {
        UINT64 lba = lbaPartStart + off / bs;
        UINTN inBlk = (UINTN)(off % bs);
        UINTN chunk = bs - inBlk;
        EFI_STATUS st;
        if (chunk > size) chunk = size;
        st = uefi_call_wrapper(bio->ReadBlocks, 5, bio, bio->Media->MediaId,
                               lba, bs, bounce);
        if (EFI_ERROR(st)) return st;
        CopyMem(dst, bounce + inBlk, chunk);
        dst += chunk; off += chunk; size -= chunk;
    }
    return EFI_SUCCESS;
}

static BOOLEAN cmp90_eqi(const CHAR16 *a, const CHAR16 *b)
{
    while (*a && *b) {
        CHAR16 ca = *a, cb = *b;
        if (ca >= L'a' && ca <= L'z') ca -= 0x20;
        if (cb >= L'a' && cb <= L'z') cb -= 0x20;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return *a == *b;
}

/* следующая FAT32-запись таблицы FAT */
static EFI_STATUS
cmp90_fat_next(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
               const UINT8 *bpb, UINT32 clus, UINT32 *next)
{
    UINT32 bps = bpb[11] | (bpb[12] << 8);
    UINT32 rsvd = bpb[14] | (bpb[15] << 8);
    UINT32 fatOff = rsvd * bps + clus * 4;
    UINT32 v = 0;
    EFI_STATUS st = cmp90_bio_read(bio, lbaPartStart, fatOff, 4, &v);
    if (!EFI_ERROR(st)) *next = v & 0x0FFFFFFFu;
    return st;
}

/* поиск компонента пути в каталоге FAT32 (с поддержкой LFN).
 * dirClus — первый кластер каталога; имя сравнивается без регистра. */
static EFI_STATUS
cmp90_fat_dir_find(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
                   const UINT8 *bpb, UINT32 dirClus,
                   const CHAR16 *name, UINT32 *outClus, UINT64 *outSize)
{
    UINT32 bps = bpb[11] | (bpb[12] << 8);
    UINT32 spc = bpb[13];
    UINT32 rsvd = bpb[14] | (bpb[15] << 8);
    UINT32 nfats = bpb[16];
    UINT32 fatsz = bpb[36] | (bpb[37]<<8) | (bpb[38]<<16) | (bpb[39]<<24);
    UINT32 dataOff = (rsvd + nfats * fatsz) * bps;
    UINT32 clus = dirClus;
    UINTN guard;

    for (guard = 0; guard < 65536 && clus >= 2 && clus < 0x0FFFFFF8; guard++) {
        UINTN csz = spc * bps;
        UINT64 cOff = dataOff + (UINT64)(clus - 2) * spc * bps;
        UINT8 *buf = cmp90_alloc(csz);
        UINTN e;
        EFI_STATUS st;
        if (!buf) return EFI_OUT_OF_RESOURCES;
        st = cmp90_bio_read(bio, lbaPartStart, cOff, csz, buf);
        if (EFI_ERROR(st)) { cmp90_free(buf); return st; }

        {
            CHAR16 lfn[260]; BOOLEAN haveLfn = FALSE;
            for (e = 0; e + 32 <= csz; e += 32) {
                UINT8 *ent = buf + e;
                UINT8 attr = ent[11];
                if (ent[0] == 0x00) { cmp90_free(buf); return EFI_NOT_FOUND; }
                if (ent[0] == 0xE5) { haveLfn = FALSE; continue; }
                if (attr == 0x0F) {
                    /* LFN-фрагмент: seq N хранит символы (N-1)*13 .. N*13-1.
                     * Физический порядок N|0x40, N-1, ..., 1 — раскладка
                     * base=(seq-1)*13 корректна при любом порядке прихода.
                     * После имени в чанке идёт 0x0000, дальше 0xFFFF —
                     * cmp90_eqi остановится на терминанте внутри. */
                    UINTN seq = ent[0] & 0x1F;
                    UINTN base, ci;
                    if (seq == 0 || seq > 20) { haveLfn = FALSE; continue; }
                    base = (seq - 1) * 13;
                    for (ci = 0; ci < 13; ci++) {
                        UINTN src;
                        UINT16 ch;
                        if (ci < 5) src = 1 + ci * 2;
                        else if (ci < 11) src = 14 + (ci - 5) * 2;
                        else src = 28 + (ci - 11) * 2;
                        ch = ent[src] | (ent[src + 1] << 8);
                        if (base + ci < 259) lfn[base + ci] = ch;
                    }
                    haveLfn = TRUE;
                    continue;
                }
                /* обычная запись каталога */
                {
                    BOOLEAN match = FALSE;
                    if (haveLfn && cmp90_eqi(lfn, name)) match = TRUE;
                    if (!match && !(attr & 0x08)) {   /* 0x08 = метка тома */
                        CHAR16 sfn[13]; UINTN si, sj = 0;
                        for (si = 0; si < 8; si++) {
                            UINT8 c = ent[si];
                            if (c == ' ') break;
                            sfn[sj++] = (CHAR16)c;
                        }
                        if (ent[8] != ' ') {
                            sfn[sj++] = L'.';
                            for (si = 8; si < 11; si++) {
                                UINT8 c = ent[si];
                                if (c == ' ') break;
                                sfn[sj++] = (CHAR16)c;
                            }
                        }
                        sfn[sj] = 0;
                        if (cmp90_eqi(sfn, name)) match = TRUE;
                    }
                    haveLfn = FALSE;
                    if (!match) continue;   /* v2.91: БЕЗ FreePool (был use-after-free) */
                    *outClus = (UINT32)(ent[26] | (ent[27] << 8)) |
                               ((UINT32)(ent[20] | (ent[21] << 8)) << 16);
                    *outSize = ent[28] | (ent[29]<<8) | (ent[30]<<16) |
                               ((UINT64)ent[31] << 24);
                    cmp90_free(buf);
                    return EFI_SUCCESS;
                }
            }
        }
        cmp90_free(buf);
        {
            EFI_STATUS st = cmp90_fat_next(bio, lbaPartStart, bpb, clus, &clus);
            if (EFI_ERROR(st)) return st;
        }
    }
    return EFI_NOT_FOUND;
}

/* чтение файла целиком по кластерной цепочке */
static EFI_STATUS
cmp90_fat_read_file(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
                    const UINT8 *bpb, UINT32 firstClus, UINT64 size,
                    UINT8 *dest)
{
    UINT32 bps = bpb[11] | (bpb[12] << 8);
    UINT32 spc = bpb[13];
    UINT32 rsvd = bpb[14] | (bpb[15] << 8);
    UINT32 nfats = bpb[16];
    UINT32 fatsz = bpb[36] | (bpb[37]<<8) | (bpb[38]<<16) | (bpb[39]<<24);
    UINT32 dataOff = (rsvd + nfats * fatsz) * bps;
    UINT32 clus = firstClus;
    UINT64 done = 0;
    UINTN guard;

    for (guard = 0; guard < 4000000 && done < size && clus >= 2 &&
                    clus < 0x0FFFFFF8; guard++) {
        UINT64 cOff = dataOff + (UINT64)(clus - 2) * spc * bps;
        UINTN take = spc * bps;
        if ((UINT64)take > size - done) take = (UINTN)(size - done);
        {
            EFI_STATUS st = cmp90_bio_read(bio, lbaPartStart,
                                           cOff, take, dest + done);
            if (EFI_ERROR(st)) return st;
        }
        done += take;
        {
            EFI_STATUS st = cmp90_fat_next(bio, lbaPartStart, bpb, clus, &clus);
            if (EFI_ERROR(st)) return st;
        }
    }
    return (done == size) ? EFI_SUCCESS : EFI_END_OF_FILE;
}

/* чтение bootmgfw.efi с тома: свой BPB → спуск по пути → кластерная цепочка */
static EFI_STATUS
cmp90_fat_load_bootmgfw(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart,
                        UINT8 **fileBuf, UINTN *fileSize)
{
    STATIC UINT8 bpb[512];
    UINT32 bps = 0, spc = 0, rsvd = 0, nfats = 0, fatsz = 0, rootClus = 0;
    static const CHAR16 *comps[4] = {
        L"EFI", L"Microsoft", L"Boot", L"bootmgfw.efi"
    };
    UINT32 cur = 0;
    UINT64 sz = 0;
    UINTN ci;
    UINT8 *buf = NULL;
    EFI_STATUS st;

    st = cmp90_bio_read(bio, lbaPartStart, 0, 512, bpb);
    if (EFI_ERROR(st)) return st;
    if (bpb[510] != 0x55 || bpb[511] != 0xAA) return EFI_UNSUPPORTED;

    bps   = bpb[11] | (bpb[12] << 8);
    spc   = bpb[13];
    rsvd  = bpb[14] | (bpb[15] << 8);
    nfats = bpb[16];
    fatsz = bpb[36] | (bpb[37]<<8) | (bpb[38]<<16) | (bpb[39]<<24);
    rootClus = bpb[44] | (bpb[45]<<8) | (bpb[46]<<16) | (bpb[47]<<24);

    if (bps < 512 || bps > 4096 || (bps & (bps-1)) ||
        spc == 0 || spc > 128 || nfats == 0 || nfats > 4 ||
        fatsz == 0 || rootClus < 2)
        return EFI_UNSUPPORTED;

    cur = rootClus;
    for (ci = 0; ci < 4; ci++) {
        Print(L"[preload] ищу \"%s\"...\n", comps[ci]);
        st = cmp90_fat_dir_find(bio, lbaPartStart, bpb, cur,
                                comps[ci], &cur, &sz);
        if (EFI_ERROR(st)) {
            Print(L"[preload] не найдено (%r)\n", st);
            return st;
        }
        if (ci < 3 && sz != 0) return EFI_NOT_FOUND; /* ждали каталог */
    }
    if (sz == 0 || sz > 0x02000000ull) return EFI_BAD_BUFFER_SIZE;

    buf = cmp90_alloc((UINTN)sz);
    if (!buf) return EFI_OUT_OF_RESOURCES;
    st = cmp90_fat_read_file(bio, lbaPartStart, bpb, cur, sz, buf);
    if (EFI_ERROR(st)) { cmp90_free(buf); return st; }

    /* PE-санити: 'MZ' и e_lfanew → 'PE\0\0' */
    if (!(buf[0] == 'M' && buf[1] == 'Z')) { cmp90_free(buf); return EFI_LOAD_ERROR; }

    *fileBuf = buf;
    *fileSize = (UINTN)sz;
    return EFI_SUCCESS;
}

/* обход всех BlockIo-дисков: GPT → ESP → загрузить bootmgfw в ОЗУ.
 * DevicePath запоминаем от ДИСКА с найденным ESP (для LoadImage). */
static void preload_bootmgfw(void)
{
    EFI_HANDLE *H = NULL;
    UINTN n = 0, k;
    EFI_STATUS st;

    Print(L"[preload v2.89] BlockIo перечисление (SFS не используем!)...\n");
    st = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
                           &cmp90BioGuid, NULL, &n, &H);
    if (EFI_ERROR(st)) { Print(L"[preload] LocateHandleBuffer: %r\n", st); return; }
    Print(L"[preload] блочных устройств: %d\n", n);

    for (k = 0; k < n && !g_bmBuf; k++) {
        EFI_BLOCK_IO_PROTOCOL *bio = NULL;
        BOOLEAN isPart;

        if (uefi_call_wrapper(BS->HandleProtocol, 3, H[k], &cmp90BioGuid,
                              (VOID **)&bio) || !bio || !bio->Media)
            continue;
        isPart = bio->Media->LogicalPartition;
        Print(L"[preload] хендл %d: bs=%d last=%llu removable=%d logical=%d\n",
              k, bio->Media->BlockSize,
              (UINT64)bio->Media->LastBlock,
              bio->Media->RemovableMedia, isPart);

        /* v2.90: пробуем КАЖДЫЙ хендл как FAT-том напрямую (партиционные
         * хендлы маппятся с LBA0 своего раздела!). Это покрывает MBR-диски,
         * GPT-ESP без парсинга таблиц и superfloppy. */
        {
            UINT8 *fb = NULL; UINTN fsz = 0;
            EFI_STATUS stf = cmp90_fat_load_bootmgfw(bio, 0, &fb, &fsz);
            if (!EFI_ERROR(stf)) {
                g_bmBuf = fb; g_bmSize = fsz;
                g_bmDp = FileDevicePath(H[k], WINDOWS_BOOT_PATH);
                Print(L"[preload] ✓ bootmgfw.efi %d байт в ОЗУ (хендл %d, direct)\n",
                      fsz, k);
                break;
            }
            if (stf != EFI_UNSUPPORTED && stf != EFI_NOT_FOUND)
                Print(L"[preload] хендл %d FAT: %r\n", k, stf);
        }

        /* для ЦЕЛЫХ дисков дополнительно — GPT: ESP-разделы внутри */
        if (!isPart) {
            STATIC UINT8 hdr[512];
            UINT64 partEntLba, espLba = 0;
            UINT32 num, esz;

            if (EFI_ERROR(cmp90_bio_read(bio, 0, 512, 512, hdr)) ||
                CompareMem(hdr, "EFI PART", 8) != 0)
                continue;   /* не GPT (или protective-MBR) — direct уже пробован */
            CopyMem(&partEntLba, hdr + 72, 8);
            CopyMem(&num,  hdr + 80, 4);
            CopyMem(&esz,  hdr + 84, 4);
            if (num == 0 || num > 128 || esz < 128 || esz > 1024) continue;

            {
                STATIC UINT8 ents[128 * 1024];
                UINTN cnt, j;
                UINT64 rdBytes = (UINT64)num * esz;
                if (rdBytes > sizeof(ents)) rdBytes = sizeof(ents);
                st = cmp90_bio_read(bio, 0, partEntLba * 512, (UINTN)rdBytes, ents);
                if (EFI_ERROR(st)) { Print(L"[preload] GPT entries: %r\n", st); continue; }
                cnt = (UINTN)(rdBytes / esz);
                for (j = 0; j < cnt && !espLba; j++) {
                    UINT8 *e = ents + j * esz;
                    UINT64 first;
                    if (CompareMem(e, cmp90EspGuid, 16) != 0) continue;
                    CopyMem(&first, e + 32, 8);
                    if (first) espLba = first;
                }
            }
            if (!espLba) { Print(L"[preload] ESP не найден в GPT\n"); continue; }
            Print(L"[preload] ESP @LBA %llu — читаю bootmgfw...\n", espLba);

            {
                UINT8 *fb = NULL; UINTN fsz = 0;
                st = cmp90_fat_load_bootmgfw(bio, espLba, &fb, &fsz);
                if (EFI_ERROR(st)) { Print(L"[preload] bootmgfw: %r\n", st); continue; }
                g_bmBuf = fb; g_bmSize = fsz;
                g_bmDp = FileDevicePath(H[k], WINDOWS_BOOT_PATH);
                Print(L"[preload] ✓ bootmgfw.efi %d байт в ОЗУ (GPT ESP@%llu)\n",
                      fsz, espLba);
            }
        }
    }
    if (H) FreePool(H);
}

static EFI_STATUS chainload_os(EFI_HANDLE ImageHandle);

/* финальный старт: из ОЗУ (SourceBuffer), DevicePath = реальный ESP */
static EFI_STATUS chainload_preloaded(EFI_HANDLE ImageHandle)
{
    EFI_HANDLE h = NULL;
    EFI_STATUS st;

    /* ===== v2.99m: лестница загрузки ОС БЕЗ единого ресета =====
     * Тёплый ресет = POST = VBIOS переинициализирует GPU и анлок гибнет
     * (подтверждено юзером на реальном HW 2026-08-23). Лестница:
     *   1) StartImage bootmgfw из ОЗУ (preload до анлока)
     *   2) любая ошибка -> SFS-цепочка с ESP
     *      (\EFI\Microsoft\Boot\bootmgfw.efi через SimpleFileSystem)
     *   3) и снова мимо -> BootNext->Windows + возврат из приложения:
     *      BDS продолжит boot-order и загрузит Windows БЕЗ POST,
     *      анлок сохраняется. */

    if (!g_bmBuf || !g_bmSize || !g_bmDp)
        Print(L"chainload-pre: preload пуст\n");
    else {
        Print(L"chainload-pre: LoadImage из ОЗУ (%d байт)...\n", g_bmSize);
        st = uefi_call_wrapper(BS->LoadImage, 6, FALSE, ImageHandle,
                               g_bmDp, g_bmBuf, g_bmSize, &h);
        if (EFI_ERROR(st)) {
            Print(L"chainload-pre: LoadImage: %r\n", st);
        } else {
            Print(L"chainload-pre: StartImage Windows Boot Manager...\n");
            st = uefi_call_wrapper(BS->StartImage, 3, h, NULL, NULL);
            Print(L"chainload-pre: StartImage вернул: %r\n", st);
            if (!EFI_ERROR(st))
                return EFI_SUCCESS;
        }
    }

    Print(L"chainload-pre: fallback на SFS-путь\n");
    st = chainload_os(ImageHandle);
    if (!EFI_ERROR(st))
        return EFI_SUCCESS;

    /* последняя ступень: возврат в прошивку. НИКАКОГО ResetSystem и
     * НИКАКОГО BootNext (NVRAM-записи на этой плате вешают систему). */
    Print(L"chainload-pre: возврат в прошивку (без POST)\n");
    return EFI_NOT_FOUND;
}


/* ==== v1.50: Linux chainload ladder (replaces the Windows bootmgfw path) ====
 * The unlock must hand over to the OS without a single reset: a warm reset
 * runs POST, VBIOS re-initializes the GPU and the unlock dies (40HX project,
 * confirmed on real HW). Ladder order mirrors the proven v2.99m shape:
 *   1) LoadImage+StartImage of the OS boot manager via SimpleFileSystem
 *      (Ubuntu shim first, then grub, systemd-boot, generic \EFI\BOOT)
 *   2) any error -> return to firmware: BDS continues BootOrder to the
 *      next entry without a POST. */

static const CHAR16 *os_loader_paths[] = {
    L"\\EFI\\ubuntu\\shimx64.efi",
    L"\\EFI\\ubuntu\\grubx64.efi",
    L"\\EFI\\systemd\\systemd-bootx64.efi",
    L"\\EFI\\BOOT\\bootx64.efi",
};

static BOOLEAN
is_own_image(EFI_HANDLE ImageHandle, EFI_HANDLE FsHandle, const CHAR16 *Path)
{
    EFI_LOADED_IMAGE *li = NULL;
    EFI_DEVICE_PATH *candDp = NULL;
    CHAR16 *self = NULL, *cand = NULL;
    UINTN sl, cl;
    BOOLEAN same = FALSE;

    if (uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle,
                          &LoadedImageProtocol, (VOID**)&li) || !li)
        return FALSE;
    if (!li->DeviceHandle || li->DeviceHandle != FsHandle)
        return FALSE;               /* different volume: cannot be us */
    candDp = FileDevicePath(FsHandle, (CHAR16*)Path);
    if (!candDp) return FALSE;
    self = DevicePathToStr(li->FilePath);
    cand = DevicePathToStr(candDp);
    if (self && cand) {
        sl = StrLen(self); cl = StrLen(cand);
        if (sl >= cl &&
            CompareMem(self + (sl - cl), cand, cl * sizeof(CHAR16)) == 0)
            same = TRUE;
    }
    if (self) FreePool(self);
    if (cand) FreePool(cand);
    FreePool(candDp);
    return same;
}

static EFI_STATUS
chainload_os_one(EFI_HANDLE ImageHandle, EFI_HANDLE FsHandle, const CHAR16 *Path)
{
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FS = NULL;
    EFI_FILE_PROTOCOL *Root = NULL, *File = NULL;
    EFI_DEVICE_PATH *Dp = NULL;
    EFI_HANDLE H = NULL;
    EFI_STATUS Status;

    Status = uefi_call_wrapper(BS->HandleProtocol, 3,
        FsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FS);
    if (EFI_ERROR(Status)) return Status;
    Status = uefi_call_wrapper(FS->OpenVolume, 2, FS, &Root);
    if (EFI_ERROR(Status)) return Status;
    Status = uefi_call_wrapper(Root->Open, 5, Root, &File, (CHAR16*)Path, EFI_FILE_MODE_READ, 0);
    if (!EFI_ERROR(Status)) uefi_call_wrapper(File->Close, 1, File);
    uefi_call_wrapper(Root->Close, 1, Root);
    if (EFI_ERROR(Status)) return Status;

    Dp = FileDevicePath(FsHandle, (CHAR16*)Path);
    if (!Dp) return EFI_OUT_OF_RESOURCES;
    Status = uefi_call_wrapper(BS->LoadImage, 6,
        FALSE, ImageHandle, Dp, NULL, 0, &H);
    if (EFI_ERROR(Status)) {
        Print(L"chainload: LoadImage %s: %r\n", Path, Status);
        return Status;
    }
    Print(L"chainload: старт %s...\n", Path);
    Status = uefi_call_wrapper(BS->StartImage, 3, H, NULL, NULL);
    Print(L"chainload: StartImage вернул: %r\n", Status);
    return Status;
}

static EFI_STATUS
chainload_os(EFI_HANDLE ImageHandle)
{
    EFI_HANDLE *Handles = NULL;
    UINTN n = 0, i, p;
    EFI_STATUS Status;
    static EFI_GUID FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

    Print(L"chainload: перечисляю SimpleFileSystem-хендлы...\n");
    Status = uefi_call_wrapper(BS->LocateHandleBuffer, 5,
        ByProtocol, &FsGuid, NULL, &n, &Handles);
    if (EFI_ERROR(Status)) {
        Print(L"chainload: LocateHandleBuffer: %r\n", Status);
        return Status;
    }
    Print(L"chainload: найдено FS-хендлов: %d\n", n);
    for (i = 0; i < n; i++)
        for (p = 0; p < sizeof(os_loader_paths)/sizeof(os_loader_paths[0]); p++) {
            if (is_own_image(ImageHandle, Handles[i], os_loader_paths[p]))
                continue;       /* never chainload ourselves */
            Status = chainload_os_one(ImageHandle, Handles[i], os_loader_paths[p]);
            if (!EFI_ERROR(Status)) {
                if (Handles) FreePool(Handles);
                return Status;
            }
        }
    if (Handles) FreePool(Handles);
    Print(L"chainload: загрузчик ОС не найден\n");
    return EFI_NOT_FOUND;
}
/* Scan config space of ALL root bridges looking for CMP90HX (10de:220d).
 * Multi-card builds use find_all_cmp90hx() instead. */
static EFI_STATUS
find_cmp90hx(void)
{
    EFI_STATUS Status;
    EFI_HANDLE *RbHandles = NULL;
    UINTN RbCount = 0;
    UINTN i;

    Status = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
        &gEfiPciRootBridgeIoProtocolGuid, NULL, &RbCount, &RbHandles);
    if (EFI_ERROR(Status)) {
        Print(L"PCI: root bridges not found: %r\n", Status);
        return Status;
    }
    Print(L"PCI: %d root bridge(s)\n", (INTN)RbCount);

    for (i = 0; i < RbCount; i++) {
        Status = uefi_call_wrapper(BS->HandleProtocol, 3, RbHandles[i],
            &gEfiPciRootBridgeIoProtocolGuid, (VOID**)&gRb);
        if (EFI_ERROR(Status)) continue;

        /* Полный скан bus 0-255 (Configuration() в этой gnu-efi нет).
         * Быстрый отбор: dev0 fn0 на каждой шине. */
        UINTN Bus, Dev, Fn;
                /* v52: fast-probe (black-box proven on 40HX - full sweep hangs) */
        {
            static const UINT8 fastB[][3] = {
                {2, 0, 0}, {1, 0, 0}, {3, 0, 0},
                {0, 0, 0}, {4, 0, 0}, {5, 0, 0}
            };
            UINTN fi;
            for (fi = 0; fi < sizeof(fastB)/sizeof(fastB[0]); fi++) {
                UINT32 Id = 0;
                UINT64 AF = ((UINT64)fastB[fi][0] << 20) |
                            ((UINT64)fastB[fi][1] << 15) |
                            ((UINT64)fastB[fi][2] << 12);
                if (EFI_ERROR(gRb->Pci.Read(gRb, EfiPciIoWidthUint32, AF, 1, &Id))
                    || Id == 0xFFFFFFFF) continue;
                if ((Id & 0xFFFF) == 0x10DE && ((Id >> 16) & 0xFFFF) == 0x1E09) {
                    gBus = fastB[fi][0]; gDev = fastB[fi][1]; gFn = fastB[fi][2];
                    Print(L"PCI: CMP50HX fast-found (bus=%d dev=%d fn=%d)\n",
                          (INTN)gBus, (INTN)gDev, (INTN)gFn);
                    uefi_call_wrapper(BS->FreePool, 1, RbHandles);
                    return EFI_SUCCESS;
                }
            }
        }
    }

    uefi_call_wrapper(BS->FreePool, 1, RbHandles);
    Print(L"PCI: CMP50HX не найдена (scanned %d bridges)\n", (INTN)RbCount);
    return EFI_NOT_FOUND;
}

/* ==== Application entry point — release flow map (v3.03) ====
 * banner -> locate card(s) -> gen2 fire-mode decision (NVRAM counter
 * CMP90G2; quick-check whether masks are already open) -> BAR0 + MEM_EN ->
 * preload bootmgfw into RAM (skipped on intermediate fire iterations) ->
 * preload probe / sweeps / diag -> shortcut if ALREADY unlocked -> shortcut
 * if direct MMIO probe sticks -> seed GPU time -> allocate payloads
 * (v67/booter/BL/fwsec above 4GB; <4GB copies of meta+v67 for 32-bit
 * readers) -> read ~84MB firmware via raw BlockIo -> build radix3 table +
 * WPR meta -> kill GFW -> verify SEC2 unlocked -> [mapper skipped] ->
 * EARLY PATH (BL->FWSEC->WPR2->booter#1) opens PLM; fallbacks if not:
 * v251 -> v246 -> fwsec retries x3 -> plain booter -> riscv-direct ->
 * then EITHER the gen2/fire multipass table (when armed) OR the plain
 * finish: SS0/SS1 -> kill SEC2 spinner -> final FLR -> return to firmware
 * (BDS boots Windows with NO POST; the unlock survives).
 * Every failure path also returns to firmware — release never resets.
 * ============================================================
 * v55: 上面这份 90HX 全流程被 #if U40X_LEGACY_FULL 收编（默认关闭）。
 * 40HX/TU106 实机主线改用文件末尾重写的 efi_main（DIRECT_SEC2：
 * 黑盒版同款枚举/BAR + 跳过 GSP-BL/FWSEC/磁盘预载/诊断扫描，直连
 * SEC2 booter，几何已按 TU102 bindata 修正）。见文件尾部。 */
#if defined(U40X_LEGACY_FULL)
EFI_STATUS EFIAPI
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status;
    UINT64 wprMetaPhys = 0, ucodePhys = 0, v67Phys = 0, radixPhys = 0, blPhys = 0;
    UINT64 fwsecPhys = 0;
    UINTN radixSize = 0, fwimageSizeUsed = 0;
    GspFwWprMeta *wprMeta = NULL;
    UINTN i;
    BOOLEAN directOk = FALSE;
    BOOLEAN earlyOk = FALSE;

    InitializeLib(ImageHandle, SystemTable);
#ifdef RELEASE_BUILD
#ifdef PCIE_GEN2_REJOIN
# ifdef FULL_NOGEN2
    Print(L"\n=== CMP50HX Unlock v3.03-40HX (TU106, DIRECT_SEC2) ===\n");
# else
    Print(L"\n=== CMP50HX Unlock v3.03-40HX (TU106, DIRECT_SEC2) ===\n");
# endif
#else
    Print(L"\n=== CMP50HX Unlock v3.03-40HX (TU106, DIRECT_SEC2) ===\n");
#endif
#elif defined(EFI_AUTOTEST)
# ifdef FULL_NOGEN2
    Print(L"\n=== CMP50HX Unlock v3.03-40HX [AUTOTEST] ===\n");
# else
    Print(L"\n=== CMP50HX Unlock v3.03-40HX [AUTOTEST] ===\n");
# endif
#else
    Print(L"\n=== CMP50HX Unlock v3.03-40HX (TU106, DIRECT_SEC2) ===\n");
#endif

#ifdef MULTI_CARD
    {
        BOOLEAN have = FALSE;
        find_all_cmp90hx();
        g_mcIndex = mc_var_get(L"CMP90IDX", &have);
        if (!have || g_mcIndex >= g_mcCount) {
            if (have) mc_vars_clear();   /* устаревший индекс (карт стало меньше) */
            g_mcIndex = 0;
        }
        g_mcAdvance = (g_mcCount > 0) && (g_mcIndex + 1 < g_mcCount);
        Print(L"MULTI-CARD: найдено %d карт(ы), итерация %d, advance=%d\n",
              (INTN)g_mcCount, (INTN)g_mcIndex + 1, g_mcAdvance ? 1 : 0);
        if (g_mcAdvance)
            mc_var_set(L"CMP90CNT", (UINT32)g_mcCount);
        if (!mc_pick(g_mcIndex)) {
            Print(L"ERROR: CMP90HX не найден\n");
            Status = EFI_NOT_FOUND;
            goto done;
        }
        Status = EFI_SUCCESS;
    }
#else
    Print(L"[40HX step 1] find_cmp90hx...\n");
    Status = find_cmp90hx();
    Print(L"[40HX 1.5] find_cmp90hx returned\n");
    Print(L"[40HX step 2] card found (bus=%d dev=%d fn=%d), preparing\n",
          (INTN)gBus, (INTN)gDev, (INTN)gFn);

#ifdef SBR_FIRST
    Print(L"[40HX step 2b] dual SBR (clean GPU state)...\n");
    u40x_dual_sbr((UINTN)gBus, (UINTN)gDev, (UINTN)gFn);
#endif
    if (EFI_ERROR(Status)) { Print(L"ERROR: CMP90HX не найден: %r\n", Status); goto done; }
#endif

#ifdef PCIE_GEN2_REJOIN
    /* v2.99: активен, если в NVRAM есть счётчик gen2-циклов (пишется после
     * первого успешного анлока). Каждый прогон = одна запись из таблицы.
     * FLR на входе = разделение прогонов (как reload модуля у rejoin16);
     * после FLR восстанавливаем BAR0/command сами. */
    {
        BOOLEAN have2 = FALSE;
    #ifndef DIRECT_SEC2
    /* 90HX: gen2 fire 决策 — 40HX (DIRECT_SEC2) 跳过 */
        UINTN gi = mc_var_get(L"CMP90G2", &have2);
        if (have2 && gi <= RJ16_N && g_mcCount > 0) {
            UINT32 saveBar;
            g_gen2Fire = TRUE;
            Print(L"gen2: fire-режим (счётчик %d/%d)\n",
                  (INTN)gi, (INTN)RJ16_N);
            saveBar = cfg_read32(0x10) & ~0xF;
        #ifndef DIRECT_SEC2
    /* 90HX: FLR in prepare (40HX skip - DIRECT_SEC2) */
#endif
    do_flr();
            uefi_call_wrapper(BS->Stall, 1, 300000);
            cfg_write32(0x10, saveBar);
                Print(L"[40HX 2a] enable_mem_decode (BAR0+MEM_EN)...\n");
enable_mem_decode();
            gBar0Base = saveBar;
            Print(L"gen2: BAR0 восстановлен = 0x%08x\n", gBar0Base);
        #endif
    /* v2.99h: быстрый путь — маски переживают перезапуск стенда
             * (гибнут только при повторном POST/VBIOS). Если все
             * обязательные маски уже FF — таблицу не гоняем. Обязательные =
             * все, кроме OPTB-блока и трёх «упрямых» регистров, чей
             * readback не показывает FF даже при проставленной записи. */
            {
                INTN k;
                BOOLEAN allOpen = TRUE;
                for (k = 0; k < RJ16_N && allOpen; k++) {
                    UINT32 a = g_rj16[k].addr;
                    /* v2.100a: 0x88084 исключён — его speed-ниббл следует за
                     * ФАКТИЧЕСКИМ линком (в госте Gen1 -> читается ...D01),
                     * строгое сравнение там невозможно в принципе */
                    if ((a >= 0x008200d0U && a <= 0x008200f4U) ||
                        a == 0x00088084U)
                        continue;                       /* OPTB / LINK_CAP */
                    /* v2.100: критерий — ТОЛЬКО точный 0xFFFFFFFF. Скипы
                     * «readback-упрямцев» и приём FFFFFF8F/7F за открытое
                     * УБРАНЫ: на хосте эти семейства дали точный FF вторым
                     * проходом (rejoin16-apply round 2); без точного FF
                     * запись GFX_SPEED_SELECT и XP3G-фичи молча не работают. */
                    if (mmio_read32(a) != g_rj16[k].val) {
                        Print(L"gen2: quick-check: 0x%08x не точный FF (%08x) — "
                              L"полная таблица\n", a, mmio_read32(a));
                        allOpen = FALSE;
                    }
                }
                if (allOpen) {
                    g_gen2Quick = TRUE;
                    Print(L"gen2: все обязательные маски уже открыты — "
                          L"сразу Gen2-конфиг\n");
                }
            }
        } else if (have2 && gi > RJ16_N) {
            /* счётчик больше таблицы = аномалия; чистим и работаем как без него */
            mc_var_set(L"CMP90G2", 0);
        }
    }
#endif

    gBar0Base = cfg_read32(0x10) & ~0xF;
    Print(L"BAR0 = 0x%08x\n", gBar0Base);
    enable_mem_decode();
#ifndef DIRECT_SEC2
    dump_regs(L"[POST]");
#else
    Print(L"[40HX 2a2] skip dump_regs (DIRECT_SEC2 - no 90HX sweep)\n");
#endif
    /* v2.57-4: зонд предзагрузки — ПЕРВЫМ (до любых сбросов/DMA!) */
    /* v2.89: ПРЕДЗАГРУЗКА bootmgfw в ОЗУ ДО разблокировки (SFS не трогаем) */
#ifdef MULTI_CARD
    /* v2.99n: в gen2-режиме preload НЕ нужен вовсе — ОС грузится через
     * BootNext без POST, а не chainload'ом из ОЗУ */
    {
        BOOLEAN skipPreload = g_mcAdvance;
#ifdef PCIE_GEN2_REJOIN
        skipPreload |= g_gen2Fire;
#endif
        if (!skipPreload) {
                Print(L"[40HX 2b] preload_bootmgfw (Windows 引导预载)...\n");
preload_bootmgfw();
        } else if (g_mcAdvance) {
            Print(L"multi-card: preload пропущен (не последняя карта)\n");
        } else {
            Print(L"gen2: preload пропущен (OS via BootNext)\n");
        }
    }
#else
    preload_bootmgfw();
#endif

    probe_preload();
#ifdef PCIE_GEN2_REJOIN
    if (!g_gen2Fire)   /* v2.99b: fire-итерациям не нужен гигантский свип */
#endif
        sweep_all(L"POST");

    /* v2.10: ДИАГНОСТИКА (SEC2 + GSP, только чтения, с паузами) + АНЛОК */
    diag_regs(SystemTable);

    /* v2.36: [POST] IMEM-содержимое ДО любых сбросов — проверка предзагрузки
     * кода VBIOS (гипотеза: GSP FWSEC выполнился из secure IMEM, оставленного
     * VBIOS при POST; SEC=1 DMA не работает нигде). */
    mmio_write32(SEC2_IMEMC0, 0);
    Print(L"diag: [POST] SEC2 IMEM[0]=0x%08x (ns)\n", mmio_read32(SEC2_IMEMD0));
    mmio_write32(SEC2_IMEMC0, (1 << 28));
    Print(L"diag: [POST] SEC2 IMEM_S[0]=0x%08x (secure)\n", mmio_read32(SEC2_IMEMD0));
    mmio_write32(SEC2_IMEMC0, 0x100 | (1 << 28));
    Print(L"diag: [POST] SEC2 IMEM_S[0x100]=0x%08x\n", mmio_read32(SEC2_IMEMD0));
    mmio_write32(GSP_BASE + 0x180, 0);
    Print(L"diag: [POST] GSP IMEM[0]=0x%08x (ns)\n", mmio_read32(GSP_BASE + 0x184));
    mmio_write32(GSP_BASE + 0x180, (1 << 28));
    Print(L"diag: [POST] GSP IMEM_S[0]=0x%08x (secure)\n", mmio_read32(GSP_BASE + 0x184));
    mmio_write32(GSP_BASE + 0x180, 0x100 | (1 << 28));
    Print(L"diag: [POST] GSP IMEM_S[0x100]=0x%08x\n", mmio_read32(GSP_BASE + 0x184));
    mmio_write32(SEC2_DMEMC0, 0x10);
    Print(L"diag: [POST] SEC2 DMEM[0x10]=0x%08x\n", mmio_read32(SEC2_DMEMD0));

#ifdef PCIE_GEN2_REJOIN
    if (is_unlocked() && !g_gen2Fire) {
#else
    if (is_unlocked()) {
#endif
        /* v2.28: карта уже открыта (анлок пережил vfio/rmmod) — но FWSEC/WPR2
         * не зависит от PLM: прогоняем диагностику (WPR2 установится), затем выход */
        Print(L"GPU уже разблокирован — v2.89: chainload из ОЗУ...\n");
#ifdef PCIE_GEN_EXPERIMENT
        /* v2.97: PLM открыт, но ботер-контекста нет (короткий путь) —
         * booter-запись пропустится, останутся прямые пробы */
        pcie_gen_unlock_debug(0, 0, 0);
#endif
#ifdef PCIE_GEN2_REJOIN
        {
            BOOLEAN hv2 = FALSE;
            mc_var_get(L"CMP90G2", &hv2);
            if (!hv2) {
                mc_var_set(L"CMP90G2", 0);
                Print(L"gen2: счётчик засеян (0) из короткого пути\n");
            }
        }
#endif
#ifdef MULTI_CARD
        if (g_mcAdvance) {
            Print(L"multi-card: карта %d уже разлочена -> следующая\n",
                  (INTN)g_mcIndex + 1);
            mc_var_set(L"CMP90IDX", (UINT32)(g_mcIndex + 1));
            mc_set_bootnext_self(ImageHandle);
            goto done;
        }
        mc_vars_clear();   /* последняя карта — грузим Windows */
#endif
        /* v2.99n: на этой плате SFS/StartImage ненадёжны (No mapping,
         * OpenVolume-висняк). Выход: возврат в прошивку — BDS грузит
         * Windows по BootOrder БЕЗ POST, анлок живёт */
        Print(L"v3.0: возврат в прошивку — Windows по BootOrder без POST\n");
        goto done;
        /* v2.62: буфер ВЫШЕ 4ГБ (как у драйвера 0x110BB0000) — единственное
     * оставшееся различие с эталонным трейсом HS-загрузки */
    Status = alloc_fwsec_buffer((FWSEC_SIZE + 0xFFF) >> 12, &fwsecPhys);
        if (EFI_ERROR(Status)) { Print(L"alloc fwsec: %r\n", Status); goto chainload; }
        Print(L"alloc fwsec @0x%lx (0x%lx bytes)\n", fwsecPhys, FWSEC_SIZE);
        CopyMem((VOID*)(UINTN)fwsecPhys, fwsec_ga102_bin, FWSEC_SIZE);
        Print(L"[40HX step 5] kill GFW (GSP engine reset)\n");
        Print(L"[40HX 2d] gsp_engine_reset (kill GFW)...\n");
gsp_engine_reset();
        fwsec_boot_gsp(fwsecPhys);

        /* v2.41 diag: SEC2 DMA с ПРАВИЛЬНЫМИ размерами (0x4F00/0x5000/0x4D00
         * из трейса драйвера) — проверка: ломал ли размер 0x8900 SEC=1? */
        {
            UINT64 ucodePhys2 = 0;
            UINT32 vv;
            Print(L"diag: SEC2 DMA 0x4F00 (правильный размер)...\n");
            Status = alloc_below_4g((0xEC00 + 0xFFF) >> 12, &ucodePhys2);
            if (EFI_ERROR(Status)) {
                Print(L"diag: alloc ucode: %r\n", Status);
            } else {
                CopyMem((VOID*)(UINTN)ucodePhys2, booter_ucode_dbg, 0xEC00);
                /* SEC2 reset */
                mmio_write32(SEC2_ENGINE, 0x1);
                for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
                mmio_write32(SEC2_ENGINE, 0x0);
                for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
                uefi_call_wrapper(BS->Stall, 1, 50000);
                mmio_write32(SEC2_BCR_CTRL, 0x0);
                for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
                mmio_write32(SEC2_RM, 0xb72000a1);
                Print(L"diag: CPUCTL после reset = 0x%x\n", mmio_read32(SEC2_CPUCTL));
                falcon_dma_transfer(0, 0, ucodePhys2, 0x4F00,
                                    0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
                mmio_write32(SEC2_IMEMC0, 0);
                vv = mmio_read32(SEC2_IMEMD0);
                mmio_write32(SEC2_IMEMC0, (1 << 28));
                Print(L"diag: IMEM[0]=0x%08x (ns) IMEM_S[0]=0x%08x (secure; "
                      L"ожидаю 0x%08x — код)\n", vv, mmio_read32(SEC2_IMEMD0),
                      *(UINT32*)(UINTN)ucodePhys2);
                mmio_write32(SEC2_BROM_PARAADDR0, 0x10);
                mmio_write32(SEC2_BROM_ENGIDMASK, 1);
                mmio_write32(SEC2_BROM_CURR_UCODE_ID, 3);
                mmio_write32(SEC2_BOOTVEC, 0x100);
                mmio_write32(SEC2_CPUCTL, 0x2);
                uefi_call_wrapper(BS->Stall, 1, 500000);
                Print(L"diag: после STARTCPU: dbg=0x%x cpuctl=0x%x\n",
                      mmio_read32(SEC2_DEBUGINFO), mmio_read32(SEC2_CPUCTL));
            }
        }
        goto chainload;
    }

    /* v2.26: ПРЯМАЯ запись FEAT_OVR (host probe) — если прилипает, booter не нужен.
     * v2.99b: в gen2 fire-режиме НЕ используем: PLM остаётся открыт с прошлого
     * прогона (переживает FLR), probe «успешен» и уводит путь мимо ботера,
     * а XVE/XP3G/OPTB без ботера всё равно не пишутся. */
    if (
#ifdef PCIE_GEN2_REJOIN
        !g_gen2Fire &&
#endif
        direct_write_probe()) {
        Print(L"probe: GPU разблокирован ПРЯМЫМИ записями — пропуск booter-пути\n");
        directOk = TRUE;
    }

    if (!directOk) {
    /* GFW_BOOT_OK: регистр 0x118234, прогресс в младшем байте (0xFF = COMPLETED);
     * старшие биты — доп. флаги (наблюдалось 0x3FF = 0x300|0xFF — GPU готов). */
    if ((mmio_read32(REG_GFW_BOOT_OK) & 0xFF) != 0xFF) {
        Print(L"GFW не готов (0x%08x), жду...\n", mmio_read32(REG_GFW_BOOT_OK));
        for (i = 0; i < 200; i++) {
            uefi_call_wrapper(BS->Stall, 1, 50000);
            if ((mmio_read32(REG_GFW_BOOT_OK) & 0xFF) == 0xFF) break;
        }
        if ((mmio_read32(REG_GFW_BOOT_OK) & 0xFF) != 0xFF)
            Print(L"GFW таймаут — продолжаю вслепую\n");
        else
            Print(L"GFW OK после ожидания (0x%08x)\n", mmio_read32(REG_GFW_BOOT_OK));
    } else {
        Print(L"GFW OK (0x%08x)\n", mmio_read32(REG_GFW_BOOT_OK));
    }

    set_gpu_time();

    /* --- Выделение памяти (ниже 4ГБ — для DMA) --- */
    Status = alloc_fwsec_buffer((V67_SIZE + 0xFFF) >> 12, &v67Phys);
    if (EFI_ERROR(Status)) { Print(L"alloc v67: %r\n", Status); goto done; }
    Print(L"alloc v67  @0x%lx\n", v67Phys);
    CopyMem((VOID*)(UINTN)v67Phys, v67_payload_bin, V67_SIZE);
#ifdef PCIE_GEN2_REJOIN
    /* v2.99c: ЗДЕСЬ НЕ ПАТЧИМ! Тёплый ресет закрывает PLM (доказано
     * итерацией 3: XVE-запись при закрытом PLM = mbox 0x15, регистр
     * 0x4ABCF вместо FF). Итерация стала двухфазной: ботер#1 идёт с
     * ОРИГИНАЛЬНЫМ payload (открывает PLM как в обычном анлоке),
     * ботер#2 с патченной парой пишется уже при открытом PLM
     * (см. gen2-блок после раннего пути; booter_load_v67 сам ресетит SEC2,
     * механика второго прогона проверена в v2.97). */
    if (g_gen2Fire)
        Print(L"gen2: ботер#1 с оригинальным payload (фаза открытия PLM)\n");
#endif

    Status = alloc_fwsec_buffer((BOOTER_UCODE_SIZE + 0xFFF) >> 12, &ucodePhys);
    if (EFI_ERROR(Status)) { Print(L"alloc ucode: %r\n", Status); goto done; }
    Print(L"alloc ucode @0x%lx\n", ucodePhys);
    CopyMem((VOID*)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);

    /* --- BL (GspRmBoot): сигнатура V67 верифицируется при загрузке BL --- */
    Status = alloc_fwsec_buffer((GSP_RM_BOOT_SIZE + 0xFFF) >> 12, &blPhys);
    if (EFI_ERROR(Status)) { Print(L"alloc bl: %r\n", Status); goto done; }
    Print(L"alloc bl    @0x%lx\n", blPhys);
    CopyMem((VOID*)(UINTN)blPhys, gsp_rm_boot_dbg, GSP_RM_BOOT_SIZE);

    /* --- v2.28: FWSEC ucode (из VBIOS) — для FRTS/WPR2 на GSP --- */
    /* v2.62: буфер ВЫШЕ 4ГБ (как у драйвера 0x110BB0000) — единственное
     * оставшееся различие с эталонным трейсом HS-загрузки */
    Status = alloc_fwsec_buffer((FWSEC_SIZE + 0xFFF) >> 12, &fwsecPhys);
    if (EFI_ERROR(Status)) { Print(L"alloc fwsec: %r\n", Status); goto done; }
    Print(L"alloc fwsec @0x%lx (0x%lx bytes)\n", fwsecPhys, FWSEC_SIZE);
    CopyMem((VOID*)(UINTN)fwsecPhys, fwsec_ga102_bin, FWSEC_SIZE);

    /* --- ЭКСПЕРИМЕНТ v2.4: БЕЗ чтения gsp_ga10x.bin ---
     * USB-чтение 84МБ через EFI-файловый протокол ЖЁСТКО фризит прошивку
     * (AMI 2012). Гипотеза: V67-переполнение происходит при обработке
     * СИГНАТУРЫ (64КБ пейлоад), а не образа → реальный .fwimage не нужен.
     * Фиктивный образ: 1МБ нулей в radix3. Если PLM откроется — образ не нужен. */
    /* --- v2.68: ЧИТАЕМ РЕАЛЬНЫЙ gsp_ga10x.bin с блочного устройства --- */
    {
        EFI_GUID bioGuid = EFI_BLOCK_IO_PROTOCOL_GUID;
        UINTN HandleCount = 0, h;
        EFI_HANDLE *Handles = NULL;
        /* v2.78b: читаем С ЛИШНИМ хвостом — секции .fwsignature_* лежат в
         * файле ПОСЛЕ .fwimage (0x5053040..); ga10x sig @0x505e06e+0x1000 */
        UINT64 fwSize = 0x5060000;
        BOOLEAN fwLoaded = FALSE;

        Status = alloc_fwsec_buffer((fwSize + 0xFFF) >> 12, &radixPhys);
        if (EFI_ERROR(Status)) { Print(L"alloc fw: %r\n", Status); goto done; }

        Status = uefi_call_wrapper(BS->LocateHandleBuffer, 5,
                                   ByProtocol, &bioGuid, NULL, &HandleCount, &Handles);
        if (!EFI_ERROR(Status) && Handles) {
            for (h = 0; h < HandleCount && !fwLoaded; h++) {
                EFI_BLOCK_IO *bio = NULL;
                Status = uefi_call_wrapper(BS->HandleProtocol, 3,
                                           Handles[h], &bioGuid, (VOID**)&bio);
                if (EFI_ERROR(Status) || !bio || !bio->Media || !bio->Media->MediaPresent)
                    continue;
                UINT64 devSz = (UINT64)(bio->Media->LastBlock + 1) * bio->Media->BlockSize;
                Print(L"fw-read: BlkIo[%d] blk=%d last=%lx dev=0x%lx\n",
                      h, bio->Media->BlockSize, bio->Media->LastBlock, devSz);
                if (devSz < fwSize) continue;
                Status = uefi_call_wrapper(bio->ReadBlocks, 5,
                                           bio, bio->Media->MediaId,
                                           0, fwSize, (VOID*)(UINTN)radixPhys);
                if (!EFI_ERROR(Status)) {
                    UINT32 *p = (UINT32*)(UINTN)radixPhys;
                    UINT32 nz = 0;
                    for (UINTN z = 0; z < 64; z++) { if (p[z] != 0) nz++; }
                    if (nz > 8) {
                        fwLoaded = TRUE;
                        Print(L"fw-read: OK! %08x %08x %08x %08x\n",
                              p[0], p[1], p[2], p[3]);
                    } else {
                        Print(L"fw-read: нули — пропуск\n");
                    }
                }
            }
            uefi_call_wrapper(BS->FreePool, 1, Handles);
        }

        if (fwLoaded) {
            /* gsp_ga10x.bin — ELF обёртка; .fwimage секция на офсете 0x40.
             * Пропускаем ELF заголовок — meta указывает на .fwimage данные.
             * v2.78b: sizeOfRadix3Elf = РОВНО размер .fwimage (0x5053000),
             * как в живом дампе драйвера (было 0x5052FC0 — расхождение!). */
            radixPhys += 0x40;
            fwimageSizeUsed = 0x5053000;
            Print(L"fw-read: РЕАЛЬНЫЙ firmware загружен! radix@0x%lx sz=0x%lx\n",
                  radixPhys, fwimageSizeUsed);
        } else {
            Print(L"fw-read: FAIL — dummy fallback (1МБ нулей)\n");
            {
                UINTN DummySize = 0x5053000;   /* ПОЛНЫЙ размер как у драйвера */
                Status = alloc_fwsec_buffer((DummySize + 0xFFF) >> 12, &radixPhys);
                if (EFI_ERROR(Status)) { Print(L"alloc dummy: %r\n", Status); goto done; }
                SetMem((VOID*)(UINTN)radixPhys, DummySize, 0x00);
                
                fwimageSizeUsed = DummySize;
            }
        }
    }

    /* --- WPR meta --- */
    /* v2.86: СТРОИМ НАСТОЯЩУЮ radix-3 таблицу (реплика kgspCreateRadix3_IMPL).
     * Живой драйвер кладёт в sysmemAddrOfRadix3Elf НЕ сырой образ, а
     * page-table: корень(+0) -> L1(+0x1000) -> L2(+0x2000, 41 шт) ->
     * данные(+0x2B000). PTE = чистый физадрес 4K-страницы.
     * Наш сырой ELF ботер парсил как таблицу -> мусорные PTE -> exit 0x2! */
    {
        UINT64 radTabPhys = 0;
        UINT64 nData = (fwimageSizeUsed + 0xFFF) >> 12;      /* 0x5053 */
        UINT64 nL2   = ((nData - 1) >> 9) + 1;               /* 41     */
        UINT64 ptSize  = (2 + nL2) << 12;                    /* корень+L1+L2 */
        UINT64 dataOff = ptSize;
        UINT64 allocSz = dataOff + fwimageSizeUsed;
        Status = alloc_fwsec_buffer((allocSz + 0xFFF) >> 12, &radTabPhys);
        if (!EFI_ERROR(Status)) {
            UINT8 *rb = (UINT8 *)(UINTN)radTabPhys;
            UINT64 i;
            SetMem(rb, ptSize, 0);
            CopyMem(rb + dataOff, (VOID *)(UINTN)radixPhys, fwimageSizeUsed);
            for (i = 0; i < nData; i++)
                *(UINT64 *)(rb + 0x2000 + i * 8) =
                    radTabPhys + dataOff + (i << 12);
            for (i = 0; i < nL2; i++)
                *(UINT64 *)(rb + 0x1000 + i * 8) =
                    radTabPhys + 0x2000 + (i << 12);
            *(UINT64 *)rb = radTabPhys + 0x1000;
            __asm__ volatile("wbinvd" ::: "memory");
            Print(L"v2.86: radix-таблица @0x%lx: L2=%llu стр, данные@+%lx (%lx байт)\n",
                  radTabPhys, nL2, (UINT64)dataOff, fwimageSizeUsed);
            radixPhys = radTabPhys;   /* meta теперь указывает на ТАБЛИЦУ */
        } else {
            Print(L"v2.86: alloc radix-table: %r — остаёмся на сыром образе\n", Status);
        }
    }
    Status = alloc_fwsec_buffer((WPR_META_SIZE + 0xFFF) >> 12, &wprMetaPhys);
    if (EFI_ERROR(Status)) { Print(L"alloc meta: %r\n", Status); goto done; }
    Print(L"alloc meta  @0x%lx\n", wprMetaPhys);
    wprMeta = (GspFwWprMeta*)(UINTN)wprMetaPhys;
    /* fbSize: регистр 0x100440 отдаёт 0xBADF-паттерн (PLM-лок) — константа 10GB.
     * CMP90HX: 10GB GDDR6X → usable FB = 0x280000000 (доказано: frts_offset
     * 0x27fe00000 в dmesg рабочего анлока). */
        /* v2.66: V67-сигнатура дублируется НИЖЕ 4ГБ — ботер может читать
     * sysmemAddrOfSignature 32-битным путём; >4ГБ адрес = мусор для него */
    {
        UINT64 v67LowPhys = 0;
        if (!EFI_ERROR(alloc_below_4g((V67_SIZE + 0xFFF) >> 12, &v67LowPhys))) {
            CopyMem((VOID*)(UINTN)v67LowPhys, (VOID*)(UINTN)v67Phys, V67_SIZE);
            __asm__ volatile("wbinvd" ::: "memory");
            Print(L"v67-low копия @0x%lx (оригинал 0x%lx)\n", v67LowPhys, v67Phys);
            v67Phys = v67LowPhys;   /* meta указывает на <4ГБ копию */
        }
    }
    if (cmp90_stockSig) {
        /* v2.78: настоящая подпись BL — секция .fwsignature_ga10x из fw-ELF.
         * Файл читается с LBA0 ЦЕЛИКОМ (с ELF-хедером 0x40), поэтому в
         * radix-буфере сигнатура лежит на 0x505e06e - 0x40 = 0x505e02e.
         * Копируем 0x1000 в выровненный v67-буфер (Booter DMA требует
         * выравнивание 256). */
        CopyMem((VOID *)(UINTN)v67Phys,
                (VOID *)(UINTN)(radixPhys + 0x505E02EULL), 0x1000);
        __asm__ volatile("wbinvd" ::: "memory");
        {
            const UINT32 *s = (const UINT32 *)(UINTN)v67Phys;
            Print(L"v2.78: stock sig @0x%lx head=%08x %08x %08x\n",
                  v67Phys, s[0], s[1], s[2]);
        }
    }
    Print(L"[40HX step 4] build_wpr_meta (fbSize=8GB)\n");
    build_wpr_meta(wprMeta, radixPhys, fwimageSizeUsed, v67Phys, 0x280000000ULL,
                   blPhys, GSP_RM_BOOT_SIZE);
    if (cmp90_corruptMeta) {
        /* v2.85: бисекция указателей. BL->0x300 дал 0x2, SIG->0x300 дал 0x2.
         * Теперь RADIX3 addr (поле 2): если снова 0x2 — НИ ОДИН указатель
         * не разыменовывается до abort => чистый environment-check. */
        wprMeta->sysmemAddrOfRadix3Elf = 0x300;
        Print(L"v2.85: RADIX ADDR ПОРЧЕН -> 0x%lx\n", wprMeta->sysmemAddrOfRadix3Elf);
    }
    {
        /* v2.84: полный дамп meta (248 байт) для побайтового сравнения с живым */
        UINT8 *mb = (UINT8 *)(UINTN)wprMetaPhys;
        UINTN r, c;
        for (r = 0; r < 248; r += 32) {
            Print(L"m[%02x]:", r);
            for (c = 0; c < 32; c++)
                Print(L"%02x", mb[r + c]);
            Print(L"\n");
        }
    }
    {
        UINT32 fbsz = mmio_read32(0x00100440);
        Print(L"fb size reg 0x440 = 0x%08x (0xBADF = залочен → константа 10GB)\n", fbsz);
    }
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"meta@0x%lx radix@0x%lx ucode@0x%lx v67@0x%lx fb=0x%lx\n",
          wprMetaPhys, radixPhys, ucodePhys, v67Phys, wprMeta->fbSize);

    /* --- v2.12: убить GFW (как драйвер: kflcnReset(GSP) перед booter load) ---
     * Живой GFW из POST держит SEC2 залоченным. GSP ENGINE (0x1103C0)
     * доступен из EFI (v2.10: читался 0x0). */
    gsp_engine_reset();
    uefi_call_wrapper(BS->Stall, 1, 200000);

    /* --- v2.12: проверка разлочки SEC2 после смерти GFW --- */
    {
        UINT32 cpuctl = mmio_read32(SEC2_CPUCTL);
        UINT32 dmatrf = mmio_read32(SEC2_DMATRFCMD);
        UINT32 fbictl = mmio_read32(SEC2_FBIF_CTL);
        UINT32 bcr    = mmio_read32(SEC2_BCR_CTRL);
        Print(L"sec2: после убийства GFW: CPUCTL=0x%08x DMATRFCMD=0x%08x FBIF_CTL=0x%08x BCR=0x%08x\n",
              cpuctl, dmatrf, fbictl, bcr);
        if (((cpuctl & 0xBADF0000) == 0xBADF0000) ||
            ((dmatrf & 0xBADF0000) == 0xBADF0000)) {
            /* priv lockdown не снят — пробую BCR CORE_SELECT=FALCON
             * (kflcnSwitchToFalcon: "Switch the core to FALCON. Releases priv lockdown.") */
            Print(L"sec2: залочен — пишу BCR CORE_SELECT=FALCON (0x841668 = 0x1)...\n");
            mmio_write32(SEC2_BCR_CTRL, 0x1);  /* VALID=1, CORE_SELECT=FALCON(0), BRFETCH=0 */
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            uefi_call_wrapper(BS->Stall, 1, 10000);
            cpuctl = mmio_read32(SEC2_CPUCTL);
            Print(L"sec2: CPUCTL после BCR = 0x%08x\n", cpuctl);
        }
        if ((cpuctl & 0xBADF0000) == 0xBADF0000) {
            Print(L"sec2: ВСЁ ЕЩЁ ЗАЛОЧЕН (0xBADF) — SEC2-путь недоступен, останов.\n");
            goto done;
        }
        Print(L"sec2: РАЗЛОЧЕН! (CPUCTL=0x%08x) — запускаю SEC2 booter load (механизм Linux-драйвера)\n", cpuctl);
    }
        Print(L"[40HX 2c] sweep_all 诊断...\n");
sweep_all(L"SEC2-unlocked");

    /* v2.57: SEC2 ucode mapper init_cmd (FRTS/SB) — ПЕРВЫМ (до v2.51!):
     * предзагруженный VBIOS-ucode (ucodeId=10) живёт в SEC2 DMEM только до
     * первых инженерных операций (v2.51/stage-4 убивают secure-зону —
     * DEAD5EC2). Mapper@DMEM[0x698], init_cmd@0x6C4, cmd_in@0x23D0.
     * FRTS→WPR2, SB→privmask. На свежем POST secure-зона цела. */
    sec2_health(L"1-post-unlock");
    if (!cmp90_skipMapper) {
        if (sec2_ucode_mapper_cmd(wprMetaPhys)) {
            Print(L"v2.57: *** SEC2 ucode команда сработала (WPR2/SB) ***\n");
        }
    } else {
        Print(L"v2.79: mapper-стадия пропущена (приближение к флоу драйвера)\n");
    }
    sec2_health(L"2-post-mapper");

    /* === v2.70: РАННИЙ ПРЯМОЙ ПУТЬ — ботер ПЕРВЫЙ на свежем SEC2 ===
     * v2.69b: первый же старт ботера на SEC2 (v251[3]) клинит блок регистров
     * (записи не липнут, reset не лечит) — все последующие попытки исполняли
     * труп. Теперь BL(GSP)→FWSEC(GSP)→WPR2→libos→booter_load_v67 на живом. */
    earlyOk = FALSE;
    {
u40x_early:
        Print(L"[40HX 2x] gsp_engine_reset (kill GFW) before early...\n");
        gsp_engine_reset();
        Print(L"[40HX step 6] early_unlock_path (SEC2 booter V67)...\n");
        EFI_STATUS earlySt = early_unlock_path(ucodePhys, fwsecPhys, wprMetaPhys);
        sec2_health(L"9-post-early");
        if (earlySt == EFI_SUCCESS) {
            Print(L"v2.70: *** ранний путь: PLM открыт ***\n");
            earlyOk = TRUE;
        }
    }

    if (!earlyOk) {
    /* --- v2.28/32: FWSEC на GSP (FRTS/WPR2) + kflcnResetIntoRiscv + LibosBootArgs
     * Драйвер: kflcnReset(GSP) → kgspExecuteFwsec(FRTS) → kflcnResetIntoRiscv(GSP) →
     * kgspProgramLibosBootArgsAddr(GSP) → BooterLoad(SEC2). Без FWSEC SEC2 BROM
     * не стартует (dbg=0x0); после WPR2 добавлены шаги ResetIntoRiscv (BCR=RISCV)
     * и LibosBootArgs (mailbox), т.к. booter load всё ещё dbg=0x0 (v2.31). */
    /* v2.51: FWSEC re-load + SB → SEC2 booter (V67) — ПЕРВЫЙ тест на свежем
     * POST. Если наш FWSEC выполнится (WPR2) — SEC=1+BROM на GSP работают;
     * SB откроет SEC2; booter load с правильными размерами запустит V67. */
    {
        BOOLEAN v251ok = driver_replay_v251(fwsecPhys, ucodePhys, wprMetaPhys);
        sec2_health(L"3-post-v251");
        if (v251ok) {
            Print(L"v2.51: *** результат получен — разблокирую ***\n");
            Status = EFI_SUCCESS;
        } else {
            Print(L"v2.51: без результата — пробую v2.46 полный реплей\n");
    /* v2.46: ПОЛНЫЙ РЕПЛЕЙ последовательности драйвера (3 стадии) — замена
     * v2.45 flow. Если реплей дал результат (наш код выполнился / PLM открыт) —
     * пишем SS0/SS1, FLR, chainload. Иначе — fallback на v2.45 flow. */
    {
        BOOLEAN replayOk = driver_replay_v246(ucodePhys, fwsecPhys,
                                              ucodePhys, wprMetaPhys);
        sec2_health(L"4-post-v246");
        if (replayOk) {
            Print(L"v2.46: *** ПОЛНЫЙ РЕПЛЕЙ УСПЕШЕН — разблокирую ***\n");
            Status = EFI_SUCCESS;
        } else {
            /* v2.62: ретрай-луп FWSEC с паузами — гипотеза асинхронного
             * процесса GPU (скраб/GFW-хвост), мешающего первому прогону */
            BOOLEAN fwOk = FALSE;
            UINTN attempt;
            for (attempt = 1; attempt <= 3 && !fwOk; attempt++) {
                Print(L"v2.62: fwsec попытка %d/3 (пауза 3с перед прогоном)...\n",
                      attempt);
                uefi_call_wrapper(BS->Stall, 1, 3000000);
                CopyMem((VOID*)(UINTN)fwsecPhys, fwsec_ga102_bin, FWSEC_SIZE);
                if (fwsec_boot_gsp(fwsecPhys)) {
                    fwOk = TRUE;
                    Print(L"v2.62: *** FWSEC СРАБОТАЛ на попытке %d ***\n", attempt);
                } else {
                    Print(L"v2.62: попытка %d — WPR2 не встал\n", attempt);
                }
                sec2_health(L"5-fwsec-retry");
            }
            if (fwOk) {
        Print(L"fwsec: OK — WPR2 установлен. kflcnResetIntoRiscv(GSP)...\n");
        mmio_write32(GSP_ENGINE, 0x1);
        for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
        mmio_write32(GSP_ENGINE, 0x0);
        for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
        uefi_call_wrapper(BS->Stall, 1, 50000);
        mmio_write32(GSP_BCR, 0x111);            /* VALID|CORE_SELECT=RISCV|BRFETCH */
        for (i = 0; i < 16; i++) mmio_read32(GSP_BCR);
        Print(L"fwsec: GSP BCR после ResetIntoRiscv = 0x%x (0x111 = RISCV)\n",
              mmio_read32(GSP_BCR));
        mmio_write32(GSP_MAILBOX0, (UINT32)cmp90_meta_low(wprMetaPhys));   /* LibosBootArgs */
        mmio_write32(GSP_MAILBOX1, (UINT32)(cmp90_meta_low(wprMetaPhys) >> 32));
        Print(L"fwsec: GSP mbox0=0x%08x mbox1=0x%08x (libos args = WPR meta)\n",
              mmio_read32(GSP_MAILBOX0), mmio_read32(GSP_MAILBOX1));
        Print(L"fwsec: запускаю SEC2 booter load\n");
    } else {
        Print(L"fwsec: НЕ отработал — SEC2 booter load без WPR2 (как v2.24)\n");
    }

    /* --- SEC2 booter load (V67) — тот же механизм, что в Linux (rejoin15) --- */
    sec2_health(L"6-pre-booter");
    Status = booter_load_v67(wprMetaPhys, ucodePhys);

    /* v2.25: если BROM-путь не сработал — прямой запуск RISC-V (обход BROM) */
    if (Status != EFI_SUCCESS && riscv_direct_start()) {
        Print(L"riscv: *** ПРЯМОЙ запуск RISC-V открыл PLM ***\n");
        Status = EFI_SUCCESS;
    }
        }   /* конец else (fallback v2.45) */
    }   /* конец replay-блока v2.46 */
        }   /* конец else v2.51 */
    }   /* конец блока v2.51 */
    }   /* !directOk */
    }   /* !earlyOk (v2.70) */

#ifdef PCIE_GEN2_REJOIN
    /* v2.99: gen2-цикл — verify + advance (или финальный конфиг) */
    {
        BOOLEAN have2 = FALSE;
        UINTN gi = mc_var_get(L"CMP90G2", &have2);
        if (g_gen2Fire && have2) {
            /* v2.99f: каждая пара = ПОЛНЫЙ FLR-миницикл внутри EFI,
             * 1:1 как «module reload» у rejoin16:
             *   FLR → ранний путь (BL→FWSEC→WPR2→RISCV→ботер#1 со stock-
             *   payload, открывает PLM заново — он ПЕРЕЖИВАЕТ FLR) →
             *   ботер#2 с патченной парой → поллинг readback.
             * Эмпирика стенда: за один бут-цикл стреляют ровно 2 исполнения
             * ботера (#1 stock + #2 crafted); третье и далее — никогда,
             * FWSEC-рефилл между ними не помогает (v2.99e).
             * Маски переживают FLR, но гибнут при тёплом/холодном ресете
             * (доказано: 0x88fe8 откатился в CF после ResetSystem-Warm) —
             * поэтому после любого сбоя таблица перепроходится с начала.
             * v2.99h: при g_gen2Quick цикл не выполняется (маски уже
             * открыты) — сразу свип и Gen2-конфиг ниже. */
            INTN i, pass;
            BOOLEAN done = FALSE;
            Print(L"gen2: ботер#1 открыл PLM=0x%08x\n",
                  mmio_read32(0x00823804U));
            /* v2.100: МУЛЬТИПРОХОД. На хосте семейства с RO-нулями
             * (0xFFFFFFCF/8F) дали точный FF только на ВТОРОМ проходе,
             * после открытия соседних PLM. Один проход = один полный обход
             * таблицы с FLR-минициклами; перед выстрелом — pre-check:
             * уже точный FF => миницикл не нужен. До 3 проходов. */
            for (pass = 0; pass < 3 && !g_gen2Quick && !done; pass++) {
                Print(L"gen2: === ПРОХОД %d/3 ===\n", (INTN)pass + 1);
                for (i = 1; i < RJ16_N; i++) {
                    volatile UINT32 *pv =
                        (volatile UINT32 *)(UINTN)(v67Phys + 0xf948);
                    volatile UINT32 *pa =
                        (volatile UINT32 *)(UINTN)(v67Phys + 0xf960);
                    UINT32 rd, saveBar;
                    UINTN tries;
                    /* v2.99g: SKIP OPTB-блока (0x8200d0..f4). У rejoin16 прямо
                     * написано: «Gen2 provably works with OPTB locked». У нас
                     * записи в этой зоне стабильно валят гостя в ресет на
                     * итерациях [29-31] (3 прогона подряд, QEMU exit=0).
                     * v2.100a: SKIP и 0x88084 LINK_CAP — speed-ниббл живой,
                     * следует за фактическим линком, записью не фиксируется. */
                    if ((g_rj16[i].addr >= 0x008200d0U && g_rj16[i].addr <= 0x008200f4U) ||
                        g_rj16[i].addr == 0x00088084U) {
                        Print(L"gen2[%d/%d] SKIP 0x%08x\n",
                              (INTN)i + 1, (INTN)RJ16_N, g_rj16[i].addr);
                        continue;
                    }
                    /* v2.100: уже точный FF — миницикл не тратим */
                    if (mmio_read32(g_rj16[i].addr) == g_rj16[i].val)
                        continue;
                    Print(L"gen2[%d/%d] 0x%08x <- 0x%08x\n",
                          (INTN)i + 1, (INTN)RJ16_N,
                          g_rj16[i].addr, g_rj16[i].val);
                    /* --- FLR-разделение: маски переживают, счётчик выстрелов
                     *      сбрасывается; BAR0 восстанавливаем сами --- */
                    saveBar = cfg_read32(0x10) & ~0xF;
                    do_flr();
                    uefi_call_wrapper(BS->Stall, 1, 300000);
                    cfg_write32(0x10, saveBar);
                    enable_mem_decode();
                    gBar0Base = saveBar;
                    /* --- ранний путь: ботер#1 со stock-payload (PLM) --- */
                    CopyMem((VOID*)(UINTN)v67Phys, v67_payload_bin, V67_SIZE);
                    early_unlock_path(ucodePhys, fwsecPhys, wprMetaPhys);
                    /* --- ботер#2 с нашей парой (второй разрешённый выстрел) --- */
                    *pv = g_rj16[i].val;
                    *pa = g_rj16[i].addr;
                    booter_load_v67(wprMetaPhys, ucodePhys);
                    /* запись асинхронная: у референса ~147-1000 polls×1мс */
                    rd = mmio_read32(g_rj16[i].addr);
                    for (tries = 0; rd != g_rj16[i].val && tries < 1000; tries++) {
                        uefi_call_wrapper(BS->Stall, 1, 1000);
                        rd = mmio_read32(g_rj16[i].addr);
                    }
                    if (rd == g_rj16[i].val)
                        continue;
                    /* v2.99g: НЕ ПРЕРЫВАЕМСЯ — недостrel попадёт в свип и
                     * будет перепроверен следующим проходом (v2.100). */
                    Print(L"gen2[%d]: readback 0x%08x != FF — продолжаю "
                          L"(перепроверка в свипе)\n", (INTN)i + 1, rd);
                }
                /* --- v2.100: свип прохода — критерий ТОЛЬКО точный FF --- */
                done = TRUE;
                for (i = 0; i < RJ16_N; i++) {
                    UINT32 a = g_rj16[i].addr, cur;
                    /* v2.100a: OPTB не обязателен; 0x88084 живой (см. выше) */
                    if ((a >= 0x008200d0U && a <= 0x008200f4U) ||
                        a == 0x00088084U)
                        continue;
                    cur = mmio_read32(a);
                    if (cur != g_rj16[i].val) {
                        Print(L"gen2: свип п%d [%d] 0x%08x = 0x%08x — НЕ точный\n",
                              (INTN)pass + 1, (INTN)i + 1, a, cur);
                        done = FALSE;
                    }
                }
                Print(L"gen2: проход %d завершён — маски %s\n",
                      (INTN)pass + 1,
                      done ? L"ВСЕ ТОЧНЫЕ FF" : L"НЕ все точные (ещё проход)");
            }
            mc_var_set(L"CMP90G2", (UINT32)RJ16_N);
            Print(L"gen2: таблица пройдена — состояние масок перед конфигом:\n");
            {
                INTN k;
                for (k = 0; k < RJ16_N; k++)
                    Print(L"gen2: [%d] 0x%08x = 0x%08x\n", (INTN)k,
                          g_rj16[k].addr, mmio_read32(g_rj16[k].addr));
            }
            Print(L"gen2: применяю конфиг\n");
#ifndef FULL_NOGEN2
            {   /* xrip-рецепт: порядок важен, PL_LINK_RATE НЕ трогаем! */
                UINT32 v2;
                v2 = mmio_read32(0x0008841cU);   /* PRIV_MISC_1 */
                mmio_write32(0x0008841cU,
                    (v2 | (1u<<11)|(1u<<13)) & ~((1u<<12)|(1u<<14)));
                mmio_write32(0x0008c2c0U,          /* CYA_0: bit2=0 */
                             mmio_read32(0x0008c2c0U) & ~(1u<<2));
                mmio_write32(0x0008e120U, 0x00000000u);   /* XP3G VAL0 */
                mmio_write32(0x0008e110U, 0x00000001u);   /* XP3G OVR0 */
                mmio_write32(0x0008e12cU, 0x00200000u);   /* XP3G VAL3 */
                mmio_write32(0x0008e11cU, 0x00000004u);   /* XP3G OVR3 */
                v2 = mmio_read32(0x0008c040U);             /* LINK_CONFIG_0 */
                /* v2.99o: MAX_RATE=2 (Gen3 клампится кремнием, v2.99k) */
                mmio_write32(0x0008c040U, (v2 & ~0x000C0000U) | (2u<<18));
                /* v2.99o: LTSSM kick УБРАН! На реальном HW он бьёт по линку
                 * в момент, когда консоль идёт через эту же карту — экран
                 * «замерзает» (ложный висяк). Тренинг сделает драйвер
                 * Windows при инициализации: LINK_CAP=Gen2 уже стоит. */
                v2 = mmio_read32(0x000880a8U);             /* LC2 TLS=Gen2 */
                mmio_write32(0x000880a8U, (v2 & ~0xFu) | 2u);
            }
#endif /* !FULL_NOGEN2 */
                {   /* v2.100: GFX_SPEED_SELECT=4 + верификация readback.
                     * Бин 0x4 открывает следующий gfx-бин (на хосте это
                     * дало 214.7 -> 4236.7 fps в vkrenderbench). Запись
                     * липнет только при открытом PLM 0x823b04 — поэтому
                     * проверяем и повторяем, иначе «3D не ускоряется». */
                    INTN t;
                    UINT32 gv;
                    mmio_write32(0x00823830U, 0x00000004u);
                    uefi_call_wrapper(BS->Stall, 1, 50000);
                    gv = mmio_read32(0x00823830U);
                    for (t = 0; gv != 0x00000004u && t < 5; t++) {
                        Print(L"gen2: GFX_SEL readback 0x%08x != 4 — повтор\n",
                              gv);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        mmio_write32(0x00823830U, 0x00000004u);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        gv = mmio_read32(0x00823830U);
                    }
                    Print(L"gen2: GFX_SPEED_SELECT %s\n",
                          gv == 0x00000004u
                              ? L"OK = 0x4 (3D-бин открыт)"
                              : L"НЕ ВСТАЛ — маска 0x823b04 не точный FF?");
                }
                /* ===== v2.101: SS0/SS1 — compute-селекторы напрямую =====
                 * Ванильный драйвер ОС не восстанавливает их (это был
                 * stockflow-патч). Прямые записи при открытом PLM
                 * 0x823804 липнут и применяются живой системой без
                 * ресета (хост, 2026-08-24: bench2 18.27 TFLOP/s FP32).
                 * Порядок: до phase3, как GFX_SEL выше. */
                {
                    INTN t;
                    UINT32 sv;
                    mmio_write32(REG_FEAT_OVR_SM_SPD, 0x88888888u);
                    uefi_call_wrapper(BS->Stall, 1, 50000);
                    sv = mmio_read32(REG_FEAT_OVR_SM_SPD);
                    for (t = 0; sv != 0x88888888u && t < 5; t++) {
                        Print(L"gen2: SS0 readback 0x%08x — повтор\n", sv);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        mmio_write32(REG_FEAT_OVR_SM_SPD, 0x88888888u);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        sv = mmio_read32(REG_FEAT_OVR_SM_SPD);
                    }
                    mmio_write32(REG_FEAT_OVR_SM_SPD_1, 0x00000008u);
                    uefi_call_wrapper(BS->Stall, 1, 50000);
                    sv = mmio_read32(REG_FEAT_OVR_SM_SPD_1);
                    for (t = 0; sv != 0x00000008u && t < 5; t++) {
                        Print(L"gen2: SS1 readback 0x%08x — повтор\n", sv);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        mmio_write32(REG_FEAT_OVR_SM_SPD_1, 0x00000008u);
                        uefi_call_wrapper(BS->Stall, 1, 50000);
                        sv = mmio_read32(REG_FEAT_OVR_SM_SPD_1);
                    }
                    Print(L"gen2: SS0=%08x SS1=%08x %s\n",
                          mmio_read32(REG_FEAT_OVR_SM_SPD),
                          mmio_read32(REG_FEAT_OVR_SM_SPD_1),
                          (mmio_read32(REG_FEAT_OVR_SM_SPD) == 0x88888888u &&
                           mmio_read32(REG_FEAT_OVR_SM_SPD_1) == 0x8u)
                              ? L"OK (compute-бин открыт)"
                              : L"НЕ ВСТАЛИ");
                }
#ifndef FULL_NOGEN2
                /* ===== v2.100: phase3 — ОЕ СТОРОНЫ ЛИНКА (рецепт хоста) =====
                 * Доказано на хосте: TLS=5GT/s в LNKCTL2 ОБОИХ концов +
                 * Retrain Link на бридже -> линк 5 GT/s, и драйвер ОС при
                 * инициализации САМ удерживает/возвращает Gen2. Два бага
                 * v2.99k исправлены: (1) LNKCTL2 = cap+0x30, а НЕ cap+0x2C
                 * (= LNKCAP2, read-only — записи игнорировались!);
                 * (2) TLS = 2 (5 GT/s), а НЕ 3 — Gen3 клампится кремнием.
                 * Бридж ищется через ВСЕ root bridges (v2.99l-баг). */
                {
                    UINTN bb = 0, bd = 0, bf = 0;
                    UINTN gc = find_pcie_cap(gBus, gDev, gFn);
                    if (gc) {
                        UINT32 lc2 = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x30);
                        lc2 = (lc2 & ~0xFu) | 2u;      /* TLS = 5 GT/s */
                        pci_cfg_wr_bdf(gBus, gDev, gFn, gc + 0x30, lc2);
                        Print(L"gen2: GPU LNKCTL2(cap+30) <- %04x (TLS=5GT/s)\n",
                              (INTN)(lc2 & 0xFFFF));
                    }
                    if (find_bridge_to(gBus, &bb, &bd, &bf)) {
                        UINTN bc = find_pcie_cap(bb, bd, bf);
                        Print(L"gen2: апстрим-бридж %02lx:%02lx.%lx "
                              L"pcie_cap@%02lx (RB %d)\n",
                              (INT64)bb, (INT64)bd, (INT64)bf, (INT64)bc,
                              (INTN)gBrIdx);
                        if (bc) {
                            UINT32 lc2 = pci_cfg_rd_idx(gBrIdx, bb, bd, bf,
                                                        bc + 0x30);
                            UINT32 lc;
                            lc2 = (lc2 & ~0xFu) | 2u;  /* v2.100: TLS=5GT/s */
                            pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x30, lc2);
                            lc = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, bc + 0x10);
                            pci_cfg_wr_idx(gBrIdx, bb, bd, bf, bc + 0x10,
                                           lc | (1u << 5));/* Retrain Link */
                            Print(L"gen2: бридж LNKCTL2=%04x TLS=5GT/s + RL "
                                  L"— тренинг запущен\n", (INTN)(lc2 & 0xFFFF));
                        }
                    } else {
                        /* v2.99j: на стенде QEMU GPU висит на root complex
                         БЕЗ апстрим-бриджа (гость его не видит) — это НЕ
                         ошибка; на реальном HW бридж будет найден и
                         настроен здесь же. */
                        Print(L"gen2: upstream bridge not found (OK on "
                              L"q35 stand)\n");
                    }
                    uefi_call_wrapper(BS->Stall, 1, 3000000);
                    /* ===== v2.99l: retrain-check БЕЗ FLR =====
                     * FLR стирал внутренний скоростной конфиг (MAX_RATE/
                     * TLS) сразу после записи — хостовый setpci-ретрейн
                     * опаздывал, линк возвращался на Gen1. Теперь конфиг
                     * живёт; фактический ретрейн делает хост через бридж
                     * (host-retrain-trigger.sh) или phase3 на реальном HW. */
                    {
                        UINTN k;
                        UINT32 spd = 0;
                        for (k = 0; k < 20; k++) {
                            uefi_call_wrapper(BS->Stall, 1, 100000);
                            spd = (mmio_read32(0x00088088U) >> 16) & 0xF;
                            Print(L"gen2: retrain-check %d00ms speed=%d\n",
                                  (INTN)k + 1, (INTN)spd);
                            if (spd >= 2) break;   /* Gen2 ИЛИ Gen3 */
                        }
                        Print(L"gen2: %s\n",
                              spd == 3 ? L"*** GEN3! 8 GT/s PODTVERZHDEN ***"
                              : spd == 2 ? L"*** GEN2 PODTVERZHDEN (speed=2) ***"
                                       : L"link speed unchanged in-guest "
                                         L"(host will retrain)");
                    }
                    /* итоговое состояние LNKSTA обеих сторон:
                     * dword@cap+0x10 = LNKCTL | LNKSTA<<16,
                     * speed = LNKSTA[3:0], width = LNKSTA[9:4] */
                    if (find_bridge_to(gBus, &bb, &bd, &bf)) {
                        UINTN bc = find_pcie_cap(bb, bd, bf);
                        if (bc) {
                            UINT32 ls = pci_cfg_rd_idx(gBrIdx, bb, bd, bf,
                                                       bc + 0x10);
                            Print(L"gen2: бридж LNKSTA speed=%d width=%d\n",
                                  (INTN)((ls >> 16) & 0xF),
                                  (INTN)((ls >> 20) & 0xF));
                        }
                    }
                    if (gc) {
                        UINT32 ls = pci_cfg_rd_bdf(gBus, gDev, gFn, gc + 0x10);
                        Print(L"gen2: GPU   LNKSTA speed=%d width=%d\n",
                              (INTN)((ls >> 16) & 0xF),
                              (INTN)((ls >> 20) & 0xF));
                    }
                }
#endif /* !FULL_NOGEN2 */
#ifndef FULL_NOGEN2
                /* v2.99l: счётчик НЕ чистим (dev) — каждый следующий бут
                 * снова идёт по fire+quick пути без прогона A. Для релиза
                 * очистку вернуть. */
#ifdef RELEASE_BUILD
                uefi_call_wrapper(RT->SetVariable, 6, L"CMP90G2", &mcGuid,
                                  0, 0, NULL);
#endif
                Print(L"gen2: Gen2-конфиг применён\n");
                /* v2.99n: НИКАКОГО SFS/chainload из EFI — OpenVolume виснет
                 * на этой прошивке (стенд + реальный HW), а preload пуст
                 * (bootmgfw живёт на системном ESP, не на USB).
                 * Вместо этого: BootNext -> Windows + возврат в прошивку.
                 * BDS грузит Windows БЕЗ POST: анлок, маски и Gen2-конфиг
                 * сохраняются; драйвер при инициализации сам тренирует
                 * линк до 5GT/s (наш LINK_CAP уже анонсирует Gen2,
                 * TLS бриджа по умолчанию = max). */
                uefi_call_wrapper(BS->Stall, 1, 2000000);
                /* v2.99o: BootNext-запись убрана — NVRAM-операции
                 * (GetVariable/SetVariable) в этом месте вешают систему
                 * при нашем состоянии GPU (caps lock мёртв у юзера).
                 * Возврат в прошивку: BDS продолжит BootOrder и загрузит
                 * Windows БЕЗ POST — анлок, маски и Gen2-конфиг живы;
                 * драйвер при инициализации тренирует линк до 5GT/s. */
                Print(L"gen2: возврат в прошивку — Windows по BootOrder "
                      L"без POST (анлок и Gen2 сохранятся)\n");
#else
                /* ===== v3.03 FIX Code 43 (DIAG-2026-08-25) =====
                 * Хвостовой cleanup КАК В ОБЫЧНОМ ПУТИ v3.01 (проверен на
                 * этой машине): fire-путь оставлял GSP с защёлкнутым WPR2
                 * последнего мини-цикла и ЖИВЫМ SEC2-ROP-спиннером — GSP-RM
                 * виндового драйвера падал при старте (frts_err=0xbe класс,
                 * bugcheck 0x1B0/C000009A). Сначала глушим спиннер, затем
                 * финальный FLR — единственный сброс защёлкнутого WPR2.
                 * Маски/селекторы FLR переживают (доказано). После FLR MMIO
                 * не трогаем — функция мертва до конца загрузки ОС. */
                Print(L"gen2: cleanup — глушу SEC2-спиннер...\n");
                mmio_write32(SEC2_ENGINE, 0x1);
                { INTN k; for (k = 0; k < 16; k++) mmio_read32(SEC2_ENGINE); }
                mmio_write32(SEC2_ENGINE, 0x0);
                { INTN k; for (k = 0; k < 16; k++) mmio_read32(SEC2_ENGINE); }
                uefi_call_wrapper(BS->Stall, 1, 200000);
                Print(L"gen2: финальный FLR (сброс защёлкнутого WPR2)...\n");
                do_flr();
                uefi_call_wrapper(BS->Stall, 1, 300000);
                Print(L"v3.03: возврат в прошивку — Windows по BootOrder "
                      L"без POST (маски/GFX/SS сохранятся)\n");
#endif
                goto done;
        } else if (!have2 && (Status == EFI_SUCCESS || directOk || earlyOk)) {
            mc_var_set(L"CMP90G2", 0);   /* первый успешный анлок — старт циклов */
            Print(L"gen2: счётчик инициализирован (следующий бут = цикл 1)\n");
        }
    }
#endif

#ifdef PCIE_GEN2_REJOIN
    if ((Status == EFI_SUCCESS || directOk || earlyOk) && !g_gen2Fire) {
#else
    if (Status == EFI_SUCCESS || directOk || earlyOk) {
#endif
        /* --- Селекторы --- */
        mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
        mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
        dump_regs(L"[unlock]");

        /* v2.88: БЕЗ FLR! На реальном железе (X570 F37d) FLR обнуляет BARs/
         * command → функция «умирает» → виснет обход устройств/консоль.
         * Вместо него, пока PLM открыт:
         *   1) глушим SEC2 (ROP-спиннер продолжает писать PLM);
         *   2) WPR2 → POST-дефолт 0x1FFFFE00/0 (драйверу нужен чистый WPR2,
         *      иначе его FWSEC/FRTS падает frts_err=0xbe — проверено);
         * Селекторы в fuse-shadow — переживают всё это без FLR. */
        Print(L"cleanup: глушу SEC2-спиннер...\n");
        mmio_write32(SEC2_ENGINE, 0x1);
        { UINTN k; for (k = 0; k < 16; k++) mmio_read32(SEC2_ENGINE); }
        mmio_write32(SEC2_ENGINE, 0x0);
        { UINTN k; for (k = 0; k < 16; k++) mmio_read32(SEC2_ENGINE); }
        uefi_call_wrapper(BS->Stall, 1, 200000);   /* скраб после ресета */
        dump_regs(L"[cleanup]");

#ifdef PCIE_GEN_EXPERIMENT
        /* v2.97: PCIe gen unlock — строго ДО FLR (BAR живой, PLM открыт);
         * передаём контекст ботера для booter-опосредованной записи */
        pcie_gen_unlock_debug(wprMetaPhys, ucodePhys, v67Phys);
#endif

#ifdef ENDGAME_WARMRESET
        /* ПЛАН B: BootNext → тёплый ресет. Если POST сохраняет fuse-shadow
         * селекторы — Windows поднимется разлоченной, весь chainload не нужен. */
        if (set_bootnext_windows()) {
            Print(L"v2.90-WR: тёплый ресет через 3с (BootNext→Windows)...\n");
            uefi_call_wrapper(BS->Stall, 1, 3000000);
            uefi_call_wrapper(RT->ResetSystem, 4, EfiResetWarm, EFI_SUCCESS, 0, NULL);
        }
        Print(L"v2.90-WR: BootNext не удался — fallback на chainload\n");
#endif

        /* v2.90: FLR ВОЗВРАЩАЕТСЯ — он единственный способ сбросить
         * защёлкнутый WPR2 (записи не липнут даже при открытом PLM, проверено
         * на реальном железе), а драйверу нужен чистый WPR2 иначе FWSEC/FRTS
         * падает frts_err=0xbe. Селекторы переживают FLR (доказано 2 раза).
         * СРАЗУ после FLR — StartImage из ОЗУ, БЕЗ печатей и чтений MMIO
         * (функция «мертва» до конца загрузки; консоль на второй ГПУ). */
        Print(L"FLR (сброс защёлкнутого WPR2)...\n");
        do_flr();
        uefi_call_wrapper(BS->Stall, 1, 300000);   /* PCIe: 100мс + запас */

#ifdef MULTI_CARD
        if (g_mcAdvance) {
            Print(L"multi-card: карта %d разлочена -> BootNext на себя (без ребута)\n",
                  (INTN)g_mcIndex + 1);
            mc_var_set(L"CMP90IDX", (UINT32)(g_mcIndex + 1));
            mc_set_bootnext_self(ImageHandle);
            goto done;   /* возврат в прошивку: она перезапустит нас с флешки */
        }
        mc_vars_clear();   /* последняя карта — дальше как обычно chainload */
#endif

        /* v2.99n: Chainload Windows из ОЗУ заменён на BootNext -> Windows:
         * SFS/StartImage ненадёжны на этой плате (No mapping, OpenVolume
         * висняк). Возврат в прошивку: BDS грузит Windows БЕЗ POST,
         * анлок и Gen2-конфиг сохраняются */
        /* v2.99n/o: SFS/StartImage/BootNext ненадёжны на этой плате
         * (No mapping, OpenVolume-висняк, NVRAM-висяк). Возврат в
         * прошивку: BDS грузит Windows по BootOrder БЕЗ POST */
        Print(L"v3.0: возврат в прошивку — Windows по BootOrder без POST\n");
        goto done;
    }

chainload:
    dump_regs(L"[pre-Windows]");
    if (is_unlocked())
        Print(L"*** CMP 90HX РАЗБЛОКИРОВАН ***\n");
    else
        Print(L"*** ВНИМАНИЕ: GPU НЕ разблокирован (SS0=0x%08x SS1=0x%08x) ***\n",
              mmio_read32(REG_FEAT_OVR_SM_SPD), mmio_read32(REG_FEAT_OVR_SM_SPD_1));

done:
    Print(L"\nКонец.\n");
#if !defined(EFI_AUTOTEST) && !defined(RELEASE_BUILD)
    WaitForSingleEvent(SystemTable->ConIn->WaitForKey, 0);
#endif
#ifdef RELEASE_BUILD
    /* релиз: НИКАКИХ перезагрузок — POST сбросит анлок!
     * Возврат в прошивку: если анлок успел примениться, состояние
     * сохраняется; firmware продолжит boot-порядок (Windows). */
    Print(L"v3.01: возврат в прошивку без перезагрузки (анлок волатилен)\n");
    uefi_call_wrapper(BS->Stall, 1, 2000000);
#endif
    return EFI_SUCCESS;
}
#endif /* U40X_LEGACY_FULL —— 上面的 90HX 全流程到此结束；以下是 v55 40HX DIRECT 主线 */

/* =====================================================================
 * v55：40HX (TU106, 10de:1f0b) DIRECT-SEC2 主线（重写，2026-09-03）
 * ---------------------------------------------------------------------
 * 为什么黑盒混合版（CMP50HX-WindowsUnlock-v0.2.1，main.c+core）在这块
 * 主板上能一路跑完枚举/BAR/SBR/booter 执行器，而本源码版此前不行：
 *   1) 配置空间地址编码不同 —— 混合版 rb->Pci.Read 用
 *      EFI_PCI_ADDRESS = bus<<24|dev<<16|fn<<8|reg（本主板固件接受）；
 *      unlock_v2 移植版沿用 GA102 工程的 bus<<20|dev<<15|fn<<12|reg，
 *      在这块主板上读到的根本不是同一设备（find/BAR 全乱）。
 *   2) BAR0 未先 command|=MEMORY|BUS_MASTER 就 MMIO 直读 → 寄存器全 0。
 *   3) 移植版主流程混入大量 90HX 专属阶段（NVRAM fire 决策、bootmgfw
 *      磁盘预载、probe/sweep/DIAG 全扫、GSP-BL+FWSEC(GA102) 前置），
 *      在本板上要么挂死要么执行语义不对的 GA102 固件。
 *   4) booter 几何：原移植把 GA102 的 imem 0x8900@+0x100 / data
 *      0x8A00/0x6200 / ucodeId=3 / hsSig=0x10 套在 TU102(nv616) 的
 *      0xE700 blob 上（data 读到文件尾外）。真实值见 BOOTER_* 宏。
 *
 * 本主线 = 黑盒混合版（找卡/BAR/读 BOOT0）+ DIRECT_SEC2（不跑 GSP
 * BL/FWSEC/磁盘预载，直接 SEC2 booter 注入），几何用 TU102 真值。
 * 编译：见 tools/unlock40x/build40x.sh（-DDIRECT_SEC2 -DRELEASE_BUILD
 * 不开 U40X_LEGACY_FULL、不开 EFI_FUNCTION_WRAPPER）。
 * ===================================================================== */

/* 配置空间地址：UEFI 规范布局（=混合版 uefi_min.h 的 EFI_PCI_ADDRESS） */
#define U40X_CFG_ADDR(bus, dev, fn, reg) \
    ((((UINT64)(UINTN)(bus)) << 24) | (((UINT64)(UINTN)(dev)) << 16) | \
     (((UINT64)(UINTN)(fn)) << 8) | ((UINT64)(reg)))
/* 紧凑布局（unlock_v2/GA102 工程用；仅找卡第二遍兜底） */
#define U40X_CFG_ADDR_COMPACT(bus, dev, fn, reg) \
    ((((UINT64)(UINTN)(bus)) << 20) | (((UINT64)(UINTN)(dev)) << 15) | \
     (((UINT64)(UINTN)(fn)) << 12) | ((UINT64)(reg)))

static UINT32 u40x_pci_rbdf(UINTN bus, UINTN dev, UINTN fn, UINTN off, INTN enc)
{
    UINT32 v = 0xFFFFFFFFu;
    UINT64 A;
    if (enc == 2) {              /* CF8/CFC 直读兜底（与 WinRing0 同路径） */
        UINT32 a = 0x80000000u | ((UINT32)bus << 16) |
                   ((UINT32)dev << 11) | ((UINT32)fn << 8) | ((UINT32)off & 0xFCu);
        __asm__ __volatile__("outl %0, %w1" : : "a"(a), "Nd"(0xCF8));
        __asm__ __volatile__("inl %w1, %0" : "=a"(v) : "Nd"(0xCFC));
        return v;
    }
    if (!gRb)
        return v;
    A = enc ? U40X_CFG_ADDR_COMPACT(bus, dev, fn, off)
            : U40X_CFG_ADDR(bus, dev, fn, off);
    /* 直调 rb->Pci（黑盒验证：本主板固件只吃直调 + 规范地址） */
    if (EFI_ERROR(gRb->Pci.Read(gRb, EfiPciIoWidthUint32, A, 1, &v)))
        v = 0xFFFFFFFFu;
    return v;
}

static void u40x_pci_wbdf(UINTN bus, UINTN dev, UINTN fn, UINTN off,
                          UINT32 val, INTN enc)
{
    UINT64 A;
    if (enc == 2) {              /* CF8/CFC 直写兜底（与 WinRing0 同路径） */
        UINT32 a = 0x80000000u | ((UINT32)bus << 16) |
                   ((UINT32)dev << 11) | ((UINT32)fn << 8) | ((UINT32)off & 0xFCu);
        __asm__ __volatile__("outl %0, %w1" : : "a"(a), "Nd"(0xCF8));
        __asm__ __volatile__("outl %0, %w1" : : "a"(val), "Nd"(0xCFC));
        return;
    }
    if (!gRb)
        return;
    A = enc ? U40X_CFG_ADDR_COMPACT(bus, dev, fn, off)
            : U40X_CFG_ADDR(bus, dev, fn, off);
    gRb->Pci.Write(gRb, EfiPciIoWidthUint32, A, 1, &val);
}

/* 找到卡时用的地址编码（0=规范 bus<<24，1=紧凑 bus<<20）——BAR/command
 * 的后续配置读必须沿用同一编码，否则在非规范固件上会读错设备。 */
static INTN u40x_enc_found = 0;

/* 找卡：fast-probe（bus 2/1/3/0/4/5）+ 初扫 bus 0..16（AGESA 实测把
 * PEG 槽编到 bus 0x10、核显到 0x30，0..16 已含该极端值）；enc=2(CF8) 全
 * 0..255 兜底。先规范地址(enc=0)再紧凑地址(enc=1)再 CF8(enc=2)。 */
static int u40x_find_gpu_pass(INTN enc)
{
    static const UINT8 fastL[][3] = {
        {2, 0, 0}, {1, 0, 0}, {3, 0, 0},
        {0, 0, 0}, {4, 0, 0}, {5, 0, 0}
    };
    UINTN k, b, d, f;
    const UINTN maxBus = (enc == 2) ? 256u : 17u;   /* 初扫 0..16；CF8 全扫 */

    for (k = 0; k < sizeof(fastL) / sizeof(fastL[0]); k++) {
        UINT32 id = u40x_pci_rbdf(fastL[k][0], fastL[k][1], fastL[k][2], 0, enc);
        if (id == 0xFFFFFFFFu)
            continue;
        if ((id & 0xFFFFu) == 0x10DEu &&
            ((id >> 16) & 0xFFFFu) == 0x1E09u) {
            gBus = fastL[k][0]; gDev = fastL[k][1]; gFn = fastL[k][2];
            u40x_enc_found = enc;
            Print(L"[50HX f] fast hit enc=%d %02x:%02x.%x id=0x%08x\n",
                  (INTN)enc, (INTN)gBus, (INTN)gDev, (INTN)gFn, id);
            return 1;
        }
    }
    for (b = 0; b < maxBus; b++) {
        for (d = 0; d < 32; d++) {
            UINT32 id0 = u40x_pci_rbdf(b, d, 0, 0, enc);
            UINTN maxf = 1;
            UINT32 hdr;
            if (id0 == 0xFFFFFFFFu || (id0 & 0xFFFFu) == 0u)
                continue;                       /* 空槽先跳过，不再多读 hdr */
            hdr = u40x_pci_rbdf(b, d, 0, 0x0C, enc);
            if (hdr & 0x800000u)    /* multifunction: HT bit7 = dword bit23 */
                maxf = 8;
            for (f = 0; f < maxf; f++) {
                UINT32 id = (f == 0) ? id0 : u40x_pci_rbdf(b, d, f, 0, enc);
                if (id == 0xFFFFFFFFu)
                    continue;
                if ((id & 0xFFFFu) == 0x10DEu &&
                    ((id >> 16) & 0xFFFFu) == 0x1E09u) {
                    gBus = b; gDev = d; gFn = f;
                    u40x_enc_found = enc;
                    Print(L"[50HX f] sweep hit enc=%d %02x:%02x.%x id=0x%08x\n",
                          (INTN)enc, (INTN)b, (INTN)d, (INTN)f, id);
                    return 1;
                }
            }
        }
    }
    return 0;
}

static int u40x_find_gpu(void)
{
    EFI_HANDLE *H = NULL;
    UINTN N = 0, i;
    EFI_STATUS st;

    st = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
            &gEfiPciRootBridgeIoProtocolGuid, NULL, &N, &H);
    if (EFI_ERROR(st)) {
        Print(L"[50HX f] RB LocateHandleBuffer: %r\n", st);
        N = 0;      /* 拿不到 RB 句柄也继续走 CF8 直读兜底 */
        H = NULL;
    } else {
        Print(L"[50HX f] %d root bridge(s)\n", (INTN)N);
    }
    for (i = 0; i < N; i++) {
        EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *rb = NULL;
        st = uefi_call_wrapper(BS->HandleProtocol, 3, H[i], &gEfiPciRootBridgeIoProtocolGuid,
                                (VOID **)&rb);
        if (EFI_ERROR(st) || !rb)
            continue;
        gRb = rb;
        if (u40x_find_gpu_pass(0)) { uefi_call_wrapper(BS->FreePool, 1, H); return 1; }
        if (u40x_find_gpu_pass(1)) { uefi_call_wrapper(BS->FreePool, 1, H); return 1; }
    }
    if (H)
        uefi_call_wrapper(BS->FreePool, 1, H);
    /* enc=2: CF8/CFC 端口直读兜底 —— 个别固件的 RootBridgeIo 协议存在
     * 总线范围限制/地址解析怪癖；legacy conf1 机制在硬件层覆盖 bus 0-255
     * （Windows 侧 WinRing0 同路径，AGESA 板上实测可达 10:00.0）。 */
    if (u40x_find_gpu_pass(2))
        return 1;
    /* 全失败：CF8 只读扫一遍，把可见设备映射写进 50hx_log.txt（≤96 条），
     * 下次定位“卡到底在不在 PCI 上 / 在哪个 BDF”一目了然。 */
    {
        UINTN b2, d2, f2, cnt = 0;
        Print(L"[50HX f] diag: CF8 visible devices (VEN:DEV @ BDF):\n");
        for (b2 = 0; b2 < 256; b2++) {
            for (d2 = 0; d2 < 32; d2++) {
                for (f2 = 0; f2 < 8; f2++) {
                    UINT32 id = u40x_pci_rbdf(b2, d2, f2, 0, 2);
                    if (id == 0xFFFFFFFFu || (id & 0xFFFFu) == 0u)
                        continue;
                    Print(L"%02x:%02x.%x  %04x:%04x\n",
                          (UINT32)b2, (UINT32)d2, (UINT32)f2,
                          (UINT32)(id & 0xFFFFu),
                          (UINT32)((id >> 16) & 0xFFFFu));
                    if (++cnt >= 96)
                        goto diag_done;
                }
            }
        }
diag_done: ;
    }
    Print(L"[50HX f] 40HX/90HX not found (both encodings)\n");
    return 0;
}

/* BAR0 解码 + command|=MEMORY|BUS_MASTER（黑盒 prepare_pci_resources 简化版） */
static int u40x_enable_bar(void)
{
    INTN enc = u40x_enc_found;
    UINT32 cmd = u40x_pci_rbdf(gBus, gDev, gFn, 0x04, enc);
    UINT32 bar0 = u40x_pci_rbdf(gBus, gDev, gFn, 0x10, enc);
    UINT32 bar0hi = 0;
    UINT32 type;

    if (cmd == 0xFFFFFFFFu || bar0 == 0xFFFFFFFFu) {
        Print(L"[40HX bar] config read failed (cmd=0x%08x bar0=0x%08x)\n",
              cmd, bar0);
        return -1;
    }
    if ((bar0 & 1u) != 0) {          /* I/O BAR? */
        Print(L"[40HX bar] BAR0 is I/O (0x%08x) — unexpected\n", bar0);
        return -2;
    }
    type = (bar0 >> 1) & 3u;
    if (type == 2u) {                /* 64-bit */
        bar0hi = u40x_pci_rbdf(gBus, gDev, gFn, 0x14, enc);
        if (bar0hi != 0) {
            Print(L"[40HX bar] WARNING BAR0 64-bit @0x%08x%08x (>4G MMIO not "
                  L"supported by 32-bit gBar0Base)\n", bar0hi, bar0 & ~0xFu);
            return -3;
        }
    }
    gBar0Base = bar0 & ~0xFu;
    Print(L"[40HX bar] cmd=0x%08x BAR0=0x%08x gBar0Base=0x%08x (enc=%d)\n",
          cmd, bar0, gBar0Base, (INTN)enc);
    u40x_pci_wbdf(gBus, gDev, gFn, 0x04, cmd | 0x6u, enc);  /* MEM | BUS_MASTER */
    cmd = u40x_pci_rbdf(gBus, gDev, gFn, 0x04, enc);
    Print(L"[40HX bar] command after |=0x6 = 0x%08x\n", cmd);
    return (cmd & 0x6u) == 0x6u ? 0 : -4;
}

/* 84MB 全零 dummy fw（无磁盘依赖；unlock_v2 同款 fallback） */
static EFI_STATUS u40x_build_dummy_fw(UINT64 *dataPhys, UINT64 *dataSize)
{
    EFI_STATUS st;
    /* v63: ELF size 必须 = log53 真解（Linux 40HX 成功 dmesg）：
     * "40HX GSP_FW: fwOffset=0x1fe200000 size=0x1bfadc8 ..."
     * = linux/firmware/gsp_tu10x.bin .fwimage 尺寸 = 28.9MB 真 GSP-RM。
     * gspFwOffset = bootBinOffset - elfSize → ELF size 决定整条 WPR 布局；
     * 旧值 0x5053000(80MB dummy) 让 gspFwOffset/heap 全错位 → booter
     * 校验 meta 布局失败 → exit 0x91（4166-4169 注释语义）。 */
    UINT64 sz = 0x1bfadc8ULL;    /* 真 GSP-RM ELF 尺寸（log53/gsp_tu10x .fwimage） */

    st = alloc_fwsec_buffer((UINTN)((sz + 0xFFF) >> 12), dataPhys);
    if (EFI_ERROR(st)) {
        Print(L"[40HX fw] alloc dummy: %r\n", st);
        return st;
    }
    SetMem((VOID *)(UINTN)*dataPhys, (UINTN)sz, 0);
    *dataSize = sz;
    Print(L"[40HX fw] dummy %dMB @0x%lx (ELF sz=0x%lx = log53 真值)\n",
          (INTN)(sz >> 20), *dataPhys, sz);
    return EFI_SUCCESS;
}

/* radix-3 页表（root→L1→L2→data，v2.86 教训：booter 要页表非 raw ELF） */
static EFI_STATUS u40x_build_radix(UINT64 dataPhys, UINT64 dataSize,
                                   UINT64 *tabPhysOut)
{
    UINT64 nData = (dataSize + 0xFFFu) >> 12;
    UINT64 nL2 = ((nData - 1) >> 9) + 1;
    UINT64 ptSize = (2 + nL2) << 12;
    UINT64 dataOff = ptSize;
    UINT64 allocSz = dataOff + dataSize;
    UINT64 tab = 0;
    UINT64 i;
    EFI_STATUS st;

    st = alloc_fwsec_buffer((UINTN)((allocSz + 0xFFFu) >> 12), &tab);
    if (EFI_ERROR(st)) {
        Print(L"[40HX rt] alloc radix-table: %r\n", st);
        return st;
    }
    SetMem((VOID *)(UINTN)tab, (UINTN)ptSize, 0);
    CopyMem((VOID *)(UINTN)(tab + dataOff), (VOID *)(UINTN)dataPhys,
            (UINTN)dataSize);
    for (i = 0; i < nData; i++)
        *(UINT64 *)(UINTN)(tab + 0x2000 + i * 8) = tab + dataOff + (i << 12);
    for (i = 0; i < nL2; i++)
        *(UINT64 *)(UINTN)(tab + 0x1000 + i * 8) = tab + 0x2000 + (i << 12);
    *(UINT64 *)(UINTN)tab = tab + 0x1000;
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"[40HX rt] radix-3 @0x%lx (L2=%d, data@+0x%lx)\n",
          tab, (INTN)nL2, dataOff);
    *tabPhysOut = tab;
    return EFI_SUCCESS;
}

/* ===== v55 主入口（DIRECT_SEC2，40HX） ===== */
EFI_STATUS EFIAPI
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status = EFI_SUCCESS;
    UINT64 v67Phys = 0, v67LowPhys = 0;
    UINT64 ucodePhys = 0, blPhys = 0;
    UINT64 radixPhys = 0, radixTabPhys = 0, radixSize = 0;
    UINT64 fwPhys = 0, fwSize = 0;
    UINT64 wprMetaPhys = 0;
    GspFwWprMeta *wprMeta = NULL;
    UINT32 boot0 = 0;
    UINTN i;

    InitializeLib(ImageHandle, SystemTable);
    /* v1.50 (Linux build): with the stock crt0 entry the u40x_entry wrapper
     * never runs, so open the ESP log here instead (same effect: all later
     * Print output lands in \50hx_log.txt on our boot device). The gnu-efi
     * ImageHandle global is also unset under crt0 (u40x_entry used to set
     * it), so record the real handle for the VBIOS dumper as well. */
    g_IH = ImageHandle;
    u40x_open_log(ImageHandle);
    Print(L"\n=== CMP50HX Unlock v1-50HX (TU102 GSP WITH_LOADER) ===\n");

    /* ---------- [1] 找卡（黑盒 fast-probe + 有界） ---------- */
    if (!u40x_find_gpu()) {
        Print(L"[50HX] GPU not found; abort\n");
        return EFI_NOT_FOUND;
    }

    /* ---------- [2] BAR0 使能 ---------- */
    if (u40x_enable_bar()) {
        Print(L"[50HX] BAR enable failed; abort\n");
        return EFI_DEVICE_ERROR;
    }
#ifdef VBIOS_DUMP
    u40x_vbios_dump();          /* v65: after BAR enable; -> \50hx_vbios.bin */
#endif

    /* ---------- [3] BOOT0 芯片校验 ---------- */
    boot0 = mmio_read32(0x00000000UL);
    Print(L"[50HX] BOOT0=0x%08x (expect arch 0x16<<24 = TU10x)\n", boot0);
    if ((boot0 & 0xFF000000u) != 0x16000000u && boot0 != 0x0FFFFFFFu) {
        Print(L"[50HX] BOOT0 unexpected — continue anyway (readback may be "
              L"gated); dumping key regs\n");
    }
    dump_regs(L"[v55 boot]");

    /* ---------- [4] 快捷路径：已解锁 / 直写可粘 ---------- */
    if (is_unlocked()) {
        Print(L"[50HX] already unlocked (SS0/SS1 exact) — skip injection\n");
        goto done;
    }
    if (direct_write_probe()) {
        Print(L"[50HX] direct MMIO probe succeeded — skip booter\n");
        goto done;
    }

    /* ---------- [5] GFW 状态 + 时间种子 ---------- */
    if ((mmio_read32(REG_GFW_BOOT_OK) & 0xFFu) != 0xFFu) {
        Print(L"[50HX] GFW not ready (0x%08x), waiting...\n",
              mmio_read32(REG_GFW_BOOT_OK));
        for (i = 0; i < 200; i++) {
            uefi_call_wrapper(BS->Stall, 1, 50000);
            if ((mmio_read32(REG_GFW_BOOT_OK) & 0xFFu) == 0xFFu)
                break;
        }
        Print(L"[50HX] GFW after wait = 0x%08x\n", mmio_read32(REG_GFW_BOOT_OK));
    } else {
        Print(L"[50HX] GFW OK (0x%08x)\n", mmio_read32(REG_GFW_BOOT_OK));
    }
    set_gpu_time();

    /* ---------- [6] 载荷/ucode/BL 分配（>4G 高槽，与 unlock_v2 同策略） ---------- */
    Status = alloc_fwsec_buffer((V67_SIZE + 0xFFFu) >> 12, &v67Phys);
    if (EFI_ERROR(Status)) { Print(L"[50HX] alloc v67: %r\n", Status); goto done; }
    CopyMem((VOID *)(UINTN)v67Phys, v67_payload_bin, V67_SIZE);
    /* v61: **不再 low-copy 到 <4GB**。869 行注释（v2.63 实测，锁卡 40HX）：
     * "booter 从 sysmem 读 WPR meta/V67——<4GB 读取被锁 (exit 0x91)"。
     * 驱动 TU102 (kgspExecuteBooterLoad_TU102) 用 mailbox0/1 = LO32/HI32
     * 传 64 位物理地址，meta 本体在 >4GB (驱动 0x110BB0000)。v55 引入的
     * "签名缓冲 <4G（booter 32 位读）" 是 90HX 老假设，在 TU102 上反了。
     * v60 实机 mbox0=0x91 可复现 → v67/meta 都在 <4GB，booter 读被锁。 */
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"[50HX] v67 payload @0x%lx (0x%x B, >4GB)\n", v67Phys, V67_SIZE);

    Status = alloc_fwsec_buffer((BOOTER_UCODE_SIZE + 0xFFFu) >> 12, &ucodePhys);
    if (EFI_ERROR(Status)) { Print(L"[50HX] alloc ucode: %r\n", Status); goto done; }
    CopyMem((VOID *)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);
    Print(L"[50HX] booter ucode @0x%lx (0x%x B, TU102 geom)\n",
          ucodePhys, BOOTER_UCODE_SIZE);

    Status = alloc_fwsec_buffer((GSP_RM_BOOT_SIZE + 0xFFFu) >> 12, &blPhys);
    if (EFI_ERROR(Status)) { Print(L"[50HX] alloc bl: %r\n", Status); goto done; }
    CopyMem((VOID *)(UINTN)blPhys, gsp_rm_boot_dbg, GSP_RM_BOOT_SIZE);

    /* ---------- [7] dummy fw + radix-3 表 + WPR meta (fbSize=8GB) ---------- */
    if (EFI_ERROR(u40x_build_dummy_fw(&fwPhys, &fwSize)))
        goto done;
    if (EFI_ERROR(u40x_build_radix(fwPhys, fwSize, &radixTabPhys)))
        goto done;
    radixPhys = radixTabPhys;
    radixSize = fwSize;

    Status = alloc_fwsec_buffer((WPR_META_SIZE + 0xFFFu) >> 12, &wprMetaPhys);
    if (EFI_ERROR(Status)) { Print(L"[50HX] alloc meta: %r\n", Status); goto done; }
    wprMeta = (GspFwWprMeta *)(UINTN)wprMetaPhys;
    Print(L"[50HX] build_wpr_meta (fbSize=0x280000000 = 10GB)\n");
    build_wpr_meta(wprMeta, radixPhys, radixSize, v67Phys,
                   0x280000000ULL, blPhys, GSP_RM_BOOT_SIZE);
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"[50HX] meta@0x%lx radix@0x%lx ucode@0x%lx v67@0x%lx fb=0x%lx\n",
          wprMetaPhys, radixPhys, ucodePhys, v67Phys, wprMeta->fbSize);

    /* ---------- [7.5] v69: 预载探测（必须在任何 engine reset 之前） ----------
     * log53: FWSEC_COMPLETE_GSP_UNTOUCHED — Linux 成功路径里 FWSEC 由
     * POST/VBIOS 预载在 GSP secure IMEM，驱动只触发不重装。若 40HX 同样
     * 预载，则 [8b] 的 code 装载纯属多余（且 SEC 写不入的原因=硬件已锁
     * 该区）。探测放在 kill GFW 前，对比 kill 后差异。 */
    probe_preload();

    /* ---------- [7.6] v1.50: WPR2 snapshot before any engine reset ----------
     * On CMP 50HX the VBIOS POST already ran FWSEC (GFW), so WPR2 is up
     * before we touch anything (live proof: dmesg
     * FWSEC_COMPLETE_GSP_UNTOUCHED / WPR=027fee00:027fe000). Capture it so
     * step [8b] can skip the manual FWSEC boot when the state survives. */
    g_Wpr2LoPreKill = mmio_read32(REG_PFB_MMU_WPR2_LO);
    g_Wpr2HiPreKill = mmio_read32(REG_PFB_MMU_WPR2_HI);
    Print(L"[50HX] WPR2 pre-kill: hi=0x%08x lo=0x%08x\n",
          g_Wpr2HiPreKill, g_Wpr2LoPreKill);

    /* ---------- [8] kill GFW + SEC2 解锁检查 ---------- */
    gsp_engine_reset();
    uefi_call_wrapper(BS->Stall, 1, 200000);
    {
        UINT32 cpuctl = mmio_read32(SEC2_CPUCTL);
        UINT32 dmatrf = mmio_read32(SEC2_DMATRFCMD);
        UINT32 fbictl = mmio_read32(SEC2_FBIF_CTL);
        UINT32 bcr    = mmio_read32(SEC2_BCR_CTRL);
        Print(L"[50HX] SEC2 post-kill: CPUCTL=0x%08x DMATRFCMD=0x%08x "
              L"FBIF_CTL=0x%08x BCR=0x%08x\n", cpuctl, dmatrf, fbictl, bcr);
        if (((cpuctl & 0xBADF0000u) == 0xBADF0000u) ||
            ((dmatrf & 0xBADF0000u) == 0xBADF0000u)) {
            Print(L"[50HX] SEC2 locked — BCR CORE_SELECT=FALCON (0x841668=0)...\n");
            mmio_write32(SEC2_BCR_CTRL, 0x0);
            for (i = 0; i < 16; i++) mmio_read32(SEC2_BCR_CTRL);
            uefi_call_wrapper(BS->Stall, 1, 10000);
            cpuctl = mmio_read32(SEC2_CPUCTL);
            Print(L"[50HX] SEC2 CPUCTL after BCR=0: 0x%08x\n", cpuctl);
        }
        if ((cpuctl & 0xBADF0000u) == 0xBADF0000u) {
            Print(L"[50HX] SEC2 still locked — stop\n");
            goto done;
        }
        Print(L"[50HX] SEC2 unlocked — direct booter load (DIRECT_SEC2)\n");
    }

    /* ---------- [8b] FWSEC on GSP → FRTS → WPR2 up (fallback only) ---------
     * v1.50: 50HX native FWSEC (extracted from the board ROM 90.02.60.00.1A,
     * geometry identical to the 40HX blob). Run it ONLY when WPR2 is down
     * after the GFW kill: our dmesg evidence shows POST leaves WPR2 up, and
     * if that state survives the kill the manual FWSEC boot is redundant.
     * Failure is not fatal: step [9] proceeds as a control either way. */
    {
        EFI_PHYSICAL_ADDRESS fwsecPhys = 0;
        BOOLEAN wprUp = FALSE;
        BOOLEAN wpr2UpNow =
            (mmio_read32(REG_PFB_MMU_WPR2_LO) == FW50_WPR2_LO_UP &&
             mmio_read32(REG_PFB_MMU_WPR2_HI) == FW50_WPR2_HI_UP);
        if (wpr2UpNow) {
            Print(L"[50HX fwsec50] WPR2 up after GFW kill — skip FWSEC\n");
        } else {
        if (g_Wpr2LoPreKill == FW50_WPR2_LO_UP)
            Print(L"[50HX fwsec50] WPR2 was up pre-kill but dropped — re-run FWSEC\n");
        Status = alloc_fwsec_buffer((UINTN)((FW50_BLOB_SIZE + 0xFFFu) >> 12),
                                    &fwsecPhys);
        if (!EFI_ERROR(Status) && fwsecPhys) {
            CopyMem((VOID *)(UINTN)fwsecPhys, fwsec_50hx_prod_bin,
                    FW50_BLOB_SIZE);
            __asm__ volatile("wbinvd" ::: "memory");
            Print(L"[50HX fwsec50] prod blob @0x%lx (0x%x B, 50HX native)\n",
                  fwsecPhys, FW50_BLOB_SIZE);
            wprUp = fwsec_boot_gsp_50hx(fwsecPhys);
        } else {
            Print(L"[50HX fwsec50] alloc fail %r\n", Status);
        }
        } /* WPR2 was down: manual FWSEC path */
        Print(L"[50HX fwsec50] WPR2 now: hi=0x%08x lo=0x%08x %s\n",
              mmio_read32(REG_PFB_MMU_WPR2_HI), mmio_read32(REG_PFB_MMU_WPR2_LO),
              wprUp ? L"(UP!)" : L"(still down)");
    }

    /* ---------- [9] DIRECT_SEC2：SEC2 booter（V67 canary） ---------- */
    sec2_health(L"v55-pre-booter");
    CopyMem((VOID *)(UINTN)ucodePhys, booter_ucode_prod, BOOTER_UCODE_SIZE);
    /* 驱动装载前把 SIG_PROD(16B AES) 写入 image[PATCH_LOC=0x8700]
     * (= DMEM[hsSigDmemAddr=0x200])——BROM 验签就从这个 DMEM 位读签名；
     * 不写则 booter 走验签直接失败。字节取自已解压 bindata
     * kgspGetBinArchiveBooterLoadUcode_TU102 ...SIG_PROD.bin。 */
    {
        static const UINT8 u40x_booter_sig_prod[16] = {
            0x32,0x60,0x43,0x67, 0x98,0x89,0x7b,0x06,
            0xe8,0x5f,0x1a,0xa8, 0x71,0x43,0x5d,0xcb
        };
        CopyMem((VOID *)(UINTN)(ucodePhys + BOOTER_SIG_PATCH_LOC),
                u40x_booter_sig_prod, sizeof(u40x_booter_sig_prod));
    }
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"[50HX] booter_load_tu102_direct (ports, BOOTVEC=0, RM=0x162000A1)...\n");
    Status = booter_load_tu102_direct(wprMetaPhys, ucodePhys);
    Print(L"[50HX] booter_load_tu102_direct returned %r\n", Status);
    if (EFI_ERROR(Status)) {
        /* v56 fallback：GA102 风格 DMA 路径（v55 用的那套），结果对比用 */
        Print(L"[50HX] fallback: booter_load_v67 (DMA path, GA102-style)...\n");
        Status = booter_load_v67(wprMetaPhys, ucodePhys);
        Print(L"[50HX] booter_load_v67 returned %r\n", Status);
    }
    sec2_health(L"v55-post-booter");
    uefi_call_wrapper(BS->Stall, 1, 500000);
    dump_regs(L"[v55 post-booter]");

    /* ---------- [10] 判定 + 清理 ---------- */
    {
        UINT32 plm = mmio_read32(REG_FEAT_OVR_PLM);
        UINT32 ss0 = mmio_read32(REG_FEAT_OVR_SM_SPD);
        UINT32 ss1 = mmio_read32(REG_FEAT_OVR_SM_SPD_1);
        Print(L"[50HX] RESULT: PLM=0x%08x SS0=0x%08x SS1=0x%08x\n", plm, ss0, ss1);
        if (is_unlocked())
            Print(L"[50HX] *** UNLOCKED (SS0=0x88888888 SS1=0x8) ***\n");
        else if (plm == VAL_PLM_OPEN || plm == 0xFFFFFF8Fu)
            Print(L"[50HX] PLM %s — SS0 still gated\n",
                  plm == VAL_PLM_OPEN ? L"OPEN" : L"STAGED");
        else
            Print(L"[50HX] PLM closed — no booter effect observed\n");
    }
    /* v89: SEC2 Sanitize（cyridd kgspCmp40SanitizeSec2AfterExploit 简版——
     * 解锁后 SEC2 回冷态：engine reset + MB 清——验证黑屏=非冷态，sanitize 解） */
    Print(L"[40HX v89] SEC2 sanitize (engine reset + MB clear)...\n");
    {
        UINTN it;
        /* kflcnWaitForHalt → ksec2ResetHw（engine reset） */
        for (it = 0; it < 100000; it++) {
            if (mmio_read32(SEC2_CPUCTL) & NV_PFALCON_FALCON_CPUCTL_HALTED_TRUE)
                break;
            if (it == 99999)
                Print(L"[40HX v89] SEC2 not halted (cpu=0x%x)\n",
                      mmio_read32(SEC2_CPUCTL));
        }
        mmio_write32(SEC2_ENGINE, 0x1);
        for (it = 0; it < 16; it++) mmio_read32(SEC2_ENGINE);
        mmio_write32(SEC2_ENGINE, 0x0);
        for (it = 0; it < 16; it++) mmio_read32(SEC2_ENGINE);
        uefi_call_wrapper(BS->Stall, 1, 100000);
        /* MB 清（cyridd: MB0=0, MB1=0/1） */
        mmio_write32(SEC2_MAILBOX0, 0);
        mmio_write32(SEC2_MAILBOX1, 0);
        Print(L"[40HX v89] sanitize done cpu=0x%x mbox0=0x%x\n",
              mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_MAILBOX0));
    }
    /* 停掉可能的 SEC2 ROP 自旋（写读回；如已死无害） */
    mmio_write32(SEC2_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    mmio_write32(SEC2_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);

done:
    dump_regs(L"[v55 final]");
    /* v71fix: 黑屏很久+驱动掉根因 = return firmware → BDS 重跑 POST →
     * GPU 重新初始化/unlock 丢失。改用黑盒式链载（chainload_preloaded：
     * preload bootmgfw → LoadImage → StartImage → SFS fallback），
     * 不回固件、无第二 POST，SS0 保持、驱动正常。 */
    {
        EFI_STATUS cst = chainload_preloaded(ImageHandle);
        Print(L"[50HX] chainload result: %r\n", cst);
        if (EFI_ERROR(cst)) {
            Print(L"[50HX] chainload failed - last resort return firmware\n");
        }
    }
    uefi_call_wrapper(BS->Stall, 1, 2000000);
    return EFI_SUCCESS;
}
