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
 *   - chainload ladder targets Linux (Debian/Ubuntu shim/grub,
 *     systemd-boot, generic \EFI\BOOT) and Windows bootmgfw.efi, never
 *     chainloads itself, and falls back to returning to firmware
 *     (BDS continues BootOrder). No SimpleFileSystem anywhere: OpenVolume
 *     from a loaded app hard-hangs whole firmware families.
 *   - optional --return-to-grub load option skips that ladder and returns
 *     EFI_SUCCESS to the caller, allowing GRUB to chainload the OS next.
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
 * Runtime messages are English-only: the UEFI console has no Cyrillic
 * font, and Russian strings rendered as boxes in user logs.
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

/* GRUB's EFI chainloader passes arguments as the loaded image's UTF-16
 * LoadOptions. Match a complete whitespace-delimited token without assuming
 * the firmware supplied a trailing NUL (LoadOptionsSize is authoritative).
 *
 * All options are deliberately opt-in: a BootNext/BootOrder launch with no
 * optional data keeps the historical unlock, Gen2, and chainload behavior. */
static BOOLEAN u40x_has_load_option(EFI_HANDLE IH, const CHAR16 *Option) {
    EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
    const CHAR16 *opts;
    UINTN chars, optionLen = 0, i = 0;

    if (!BS || !IH || !Option)
        return FALSE;
    if (uefi_call_wrapper(BS->HandleProtocol, 3, IH, &u40x_li_guid,
                          (void **)&li) ||
        !li || !li->LoadOptions || li->LoadOptionsSize < sizeof(CHAR16))
        return FALSE;

    while (Option[optionLen])
        optionLen++;
    if (!optionLen)
        return FALSE;

    opts = (const CHAR16 *)li->LoadOptions;
    chars = li->LoadOptionsSize / sizeof(CHAR16);
    while (i < chars && opts[i]) {
        UINTN start;
        while (i < chars && opts[i] &&
               (opts[i] == L' ' || opts[i] == L'\t' ||
                opts[i] == L'\r' || opts[i] == L'\n'))
            i++;
        start = i;
        while (i < chars && opts[i] &&
               opts[i] != L' ' && opts[i] != L'\t' &&
               opts[i] != L'\r' && opts[i] != L'\n')
            i++;
        if (i - start == optionLen &&
            CompareMem(opts + start, Option,
                       optionLen * sizeof(CHAR16)) == 0)
            return TRUE;
    }
    return FALSE;
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
            if (*fptr == L'\n') {   /* EFI ConOut needs \r\n */
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
EFI_HANDLE ImageHandle = NULL; /* crt0 global - provided by ourselves */

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

/* ==== CMP 50HX (TU102/TU10x) registers (BAR0 MMIO) ====
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
/* IMEM/DMEM read/write ports (v2.17 DMA diagnostics; v56 TU102 load use) */
#define SEC2_IMEMT0             (NV_PSEC_BASE + 0x188)  /* IMEM block tag port (driver IMEMT(0)) */
#define SEC2_IMEMC0             (NV_PSEC_BASE + 0x180)
#define SEC2_IMEMD0             (NV_PSEC_BASE + 0x184)
#define SEC2_DMEMC0             (NV_PSEC_BASE + 0x1C0)
#define SEC2_DMEMD0             (NV_PSEC_BASE + 0x1C4)

/* ==== GSP Falcon registers ====
 * The kernel driver resets GSP before the SEC2 booter load:
 * The driver before SEC2 booter load RESETS GSP (kflcnReset in _kgspBootGspRm) -
 * the live GFW from POST holds SEC2 locked (0xBADF5620). ENGINE (0x1103C0)
 * is accessible from EFI -> kill GFW in the same way the driver does. */
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

/* ==== Boot (SEC2) ucode layout constants - ground truth from bindata ====
 *
 * v55 fix: these geometric values are CHIP-dependent! unlock_v2 original values
 * (imem 0x8900 @+0x100, data 0x8A00/0x6200, patchLoc 0x8A10, ucodeId=3) come from
 * the 90HX GA102. The 40HX is TU106, and the driver uses the TU102 archive
 * (kgspGetBinArchiveBooterLoadUcode_TU102). The real geometry of nv616 booter
 * (md5 52a65b17) = the HEADER_PROD in the local 610.43.03 source code
 * g_bindata_...TU102.c (raw-deflate decompress 36B):
 *   osCodeOffset=0x0   osCodeSize=0x100
 *   osDataOffset=0x8500 osDataSize=0x6200     <- 0x8500+0x6200 = 0xE700 = full blob length (exactly filled)
 *   appCodeOffset=0x100 appCodeSize=0x8400    <- IMEM = image[0x100..0x8500)
 * PATCH_META={fuseVer=0,engineId=1,ucodeId=0xD=13}; PATCH_LOC=0x8700
 *   -> hsSigDmemAddr = patchLoc - dataOffset = 0x8700-0x8500 = 0x200
 * The old values 0x8900/0x8A00/0x6200 are GA102's; applied to the 0xE700 TU102
 * blob they would read DMEM past the end of the file (0x8A00+0x6200=0xEC00 > 0xE700)
 * -- the SIG bit is wrong and the DMEM contents are all wrong, so the booter's
 * signature verification will inevitably fail.
 */
#define BOOTER_UCODE_SIZE       0x0000E700UL   /* nv616 TU102 booter (full blob length, md5 52a65b17) */
#define BOOTER_APP_CODE_OFFSET  0x00000100UL  /* header.appCodeOffset (imemVa/src offset) */
#define BOOTER_APP_CODE_SIZE    0x00008400UL  /* header.appCodeSize  (IMEM DMA length, TU102) */
#define BOOTER_OS_DATA_OFFSET   0x00008500UL  /* header.osDataOffset (DMEM src offset, TU102) */
#define BOOTER_OS_DATA_SIZE     0x00006200UL  /* header.osDataSize   (DMEM DMA length, TU102) */
#define BOOTER_SIG_PATCH_LOC    0x00008700UL  /* bindata PATCH_LOC (signature landing slot inside DMEM = 0x200) */
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

/* v66: 40HX (TU106) native FWSEC - extracted from 40HX_board_rom.bin (2026-08-24 local
 * PROM dump). V2 desc: code imemLoad=0x9a00 + data dmemLoad=0x3f0 contiguous
 * (stored=0x9df0). prod (md5 582d0377) / dbg (md5 f0e22c2c) differ only in the sig area.
 * In the data segment: interface@0xe0 -> DMEMMAPPER(id4)@0x360 -> cmd_in@0x3b0 (size 0x40).
 * compile-time stamp "Dec 18 2019 13:15:43". See research/FWSEC_40HX_EXTRACT_20260903.md */
extern const UINT8 fwsec_50hx_prod_bin[];
extern const UINT8 fwsec_50hx_dbg_bin[];

/* v2.54: SEC2 ucode из VBIOS (appid 0x49 DBG / 0x89 PROD): ucodeId=10,
 * engmask=1, imemLoad=0x4400, dmemLoad=0x8F4, pkc=0x6DC; sig[2] патчен. */
extern const UINT8 sec2_ucode_vbios_49[];
extern const UINTN sec2_ucode_vbios_49_size;
extern const UINT8 sec2_ucode_vbios_89[];
extern const UINTN sec2_ucode_vbios_89_size;

/* v70: generic falcon bootloader (sec2_bl_gp10x) - extracted from OpenRM bindata
 * g_bindata_ksec2GetBinArchiveBlUcode_TU102.c (lz4/deflate 768B,
 * "works for both SEC2 and GSP"). FWSEC is a WITH_LOADER-type ucode
 * (kernel_gsp_fwsec.c:741 bootType=WITH_LOADER); secure code must be DMA'd
 * from host memory into secure IMEM by the generic BL - direct host writes to secure IMEM
 * were empirically disproven across v66-v69 (always scrubbed). See research/FWSEC_40HX_LOADER_20260903.md */
extern const UINT8 gsp_bl_tu102[];
#define GSP_BL_TU102_SIZE       0x00000300UL   /* image 768B = code 0x200 + data 0x100 */
#define GSP_BL_TU102_CODE_SIZE  0x00000200UL   /* blImgHeader.blCodeSize (code only) */
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

/* ==== 40HX (TU106) FWSEC load constants (v66 40HX real measurement; 50HX blob has the same geometry, extract_fwsec.py verified) ==== */
#define FW50_CODE_SIZE          0x00009A00UL   /* imemLoad */
#define FW50_DATA_OFF           0x00009A00UL   /* data start inside the blob */
#define FW50_DMEM_SIZE          0x000003F0UL   /* dmemLoad */
#define FW50_BLOB_SIZE          0x00009DF0UL   /* code+data */
#define FW50_IFACE_OFF          0x000000E0UL   /* interface header inside data */
#define FW50_MAPPER_OFF         0x00000360UL   /* DMEMMAPPER v3 (id4 entry) */
#define FW50_CMDIN_OFF          0x000003B0UL   /* cmd_in_buffer */
#define FW50_FRTS_OFFSET        0x27FE00000ULL /* frtsOffset (10GB FB；live dmesg WPR=027fee00:027fe000) */
#define FW50_WPR2_LO_UP         0x027FE000UL
#define FW50_WPR2_HI_UP         0x027FEE00UL
static UINT64 g_fbSize     = 0x280000000ULL;
static UINT64 g_frtsOffset = FW50_FRTS_OFFSET;
static UINT32 g_wpr2LoUp   = FW50_WPR2_LO_UP;
static UINT32 g_wpr2HiUp   = FW50_WPR2_HI_UP;

/* Forward decl required by GCC 14: -Wimplicit-function-declaration is an
 * error, and detect_fb_size() below uses mmio_read32() before it is defined
 * further down. */
static UINT32 mmio_read32(UINTN offset);

/* fb=20g override (issue #39): some modified 20 GB cards latch a WPR2 that
 * lies (seen: 0x1ffffe00 ≈ 8 GiB), so the SKU heuristic picks 10 GiB and
 * half the VRAM is lost. The override arrives either as the "fb=20g"
 * LoadOptions token (efibootmgr -u / GRUB) or as the 50HXFB="20G" UEFI
 * variable (Windows installer: bcdedit firmware entries carry no load
 * options). */
static BOOLEAN
u40x_force_fb20g(EFI_HANDLE IH)
{
    static EFI_GUID gvGuid = EFI_GLOBAL_VARIABLE;
    UINTN sz = 8;
    CHAR16 buf[4] = {0, 0, 0, 0};
    UINT32 attr = 0;
    EFI_STATUS st;

    if (IH && u40x_has_load_option(IH, L"fb=20g"))
        return TRUE;
    st = uefi_call_wrapper(RT->GetVariable, 5, L"50HXFB", &gvGuid,
                           &attr, &sz, buf);
    return !EFI_ERROR(st) && sz >= 6 &&
           buf[0] == L'2' && buf[1] == L'0' && buf[2] == L'G';
}

static VOID
detect_fb_size(EFI_HANDLE IH)
{
    UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO) & 0xFFFFFFF0U;
    UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI) & 0xFFFFFFF0U;
    UINT32 span = hi - lo;

    if (u40x_force_fb20g(IH)) {
        /* Mirror the proven 10 GiB layout: FRTS 2 MiB below top-of-FB,
         * WPR2 window (span 0xE00) right at it. */
        g_fbSize     = 0x500000000ULL;
        g_frtsOffset = g_fbSize - 0x200000ULL;
        g_wpr2LoUp   = (UINT32)(g_frtsOffset >> 8);
        g_wpr2HiUp   = g_wpr2LoUp + 0xE00U;
        Print(L"[50HX] fb=20g override: forcing 20 GiB geometry "
              L"(latched WPR2_LO=0x%08x ignored)\n", lo);
        return;
    }
    if (span == 0xE00U && lo >= 0x04000000U && lo < 0x06000000U) {
        g_fbSize     = 0x500000000ULL;
        g_frtsOffset = (UINT64)lo << 8;
        g_wpr2LoUp   = lo;
        g_wpr2HiUp   = hi;
        Print(L"[50HX] detected 20 GiB card (WPR2_LO=0x%08x, fbSize=0x%llx)\n",
              lo, g_fbSize);
    } else {
        Print(L"[50HX] using 10 GiB geometry (WPR2_LO=0x%08x)\n", lo);
    }
}
/* v68: real values for the 40HX FWSEC descriptor (V2 @0x3ec28) - on Turing it is an NS+SEC
 * split-segment load, not a whole-block SEC=1 DMA like GA102:
 *   +0x18 imemLoad=0x9a00  +0x20 imemSecBase=0x400  +0x24 imemSecSize=0x9600
 *   +0x30 dmemLoad=0x3f0   +0x34 dmemOff=0x9a00     +0x10 iface_off=0xe0
 * Inside the image: code = [NS 0x0..0x400][SEC 0x400..0x9a00] laid back-to-back;
 * Loaded to IMEM: NS@0 (sec=0) -> SEC@0x400 (sec=1), tag each 256B with IMEMT
 * (same semantics as the TU102 driver s_prepareHsFalconDirect / s_imemCopyTo_TU102). */
#define FW50_NS_SIZE            0x00000400UL   /* image[0..0x400) NS segment */
#define FW50_SEC_BASE           0x00000400UL   /* secure segment IMEM / image start */
#define FW50_SEC_SIZE           0x00009600UL   /* image[0x400..0x9a00) SEC segment */
#define FW50_TAG_NS             0x00000000UL   /* NS tag start (target>>8) */
#define FW50_TAG_SEC            0x00000004UL   /* SEC tag start (0x400>>8) */

/* v70: WITH_LOADER load constants (matches driver s_setupLoader / s_prepareHsFalconWithLoader)
 *   Load generic BL at the top of GSP IMEM (tag=0xfd -> BOOTVEC=0xfd00, 256B alignment);
 *   Copy BL DMEM DESC (RM_FLCN_BL_DMEM_DESC, 4B-align, sizeof=0x54) to DMEM 0x0;
 *   ctxDma=4 -> TRANSCFG(4) = GSP FBIF base(0x600) + 4*4 = 0x610 */
#define GSP_HWCFG               (GSP_BASE + 0x108)   /* NV_PFALCON_FALCON_HWCFG */
#define GSP_FBIF_TRANSCFG4      (GSP_BASE + 0x610)   /* TRANSCFG(dmaIdx=4) */
#define BL_DESC_SIZE            0x00000054UL   /* sizeof(RM_FLCN_BL_DMEM_DESC) */
#define BL_DESC_DMEM_LOAD_OFF   0x00000000UL   /* desc copy-DMEM offset (driver hard-codes 0) */
/* BL DMEM DESC wordsegmentoffset (4B-align u64@0x24/0x40): */
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
static UINTN     g_ourImageSize = 0; /* size of our loaded EFI binary, used by
                                      * is_our_binary() for content-based check
                                      * when the path differs (issue #36) */
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
        Print(L"gen2: no root bridge found!\n");
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
            Print(L"alloc_high: OK @0x%lx (%d pages)\n", *Phys, (UINT32)Pages);
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
                Print(L"alloc_high: OK (static) @0x%lx\n", *Phys);
                return EFI_SUCCESS;
            }
        }
    }
    Print(L"alloc_high: above 4GB failed - falling back below 4GB\n");
    return alloc_below_4g(Pages, Phys);
}

/* Включить MEM_EN + BUS_MASTER в command-регистре GPU.
 * У устройства без UEFI-драйвера (нет GOP) прошивка может оставить
 * command=0 → все MMIO-чтения BAR0 возвращают 0xFFFFFFFF. */
static void
enable_mem_decode(void)
{
    UINT32 cmd = cfg_read32(0x04);
    Print(L"cfg 0x04 (command) before= 0x%08x\n", cmd);
    cfg_write32(0x04, cmd | 0x6);   /* bit1=Memory Space, bit2=Bus Master */
    cmd = cfg_read32(0x04);
    Print(L"cfg 0x04 (command) after = 0x%08x\n", cmd);
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
    Print(L"[pauses disabled]\n");
#else
    Print(L"\n[Enter] - continue...\n");
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

    Print(L"--- DIAG v2.10 GSP (read-only) ---\n");
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
    Print(L"--- DIAG v2.10 DONE ---\n");
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

    Print(L"v2.90-WR: scanning Boot#### (Windows Boot Manager)...\n");
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
            Print(L"v2.90-WR: scan %04X...\n", opt);
        if (EFI_ERROR(st) || sz < 6) continue;
        {
            /* EFI_LOAD_OPTION: u32 Attributes, u16 FilePathListLength,
             * Description (CHAR16, NUL-терминированная) */
            CHAR16 *desc = (CHAR16 *)(buf + 6);
            if (cmp90_eqi(desc, L"Windows Boot Manager")) {
                Print(L"v2.90-WR: found Boot%04X, writing BootNext...\n", opt);
                st = uefi_call_wrapper(RT->SetVariable, 6, L"BootNext", &gvGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS, 2, &opt);
                Print(L"v2.90-WR: Boot%04X = Windows Boot Manager; BootNext: %r\n",
                      opt, st);
                return !EFI_ERROR(st);
            }
        }
    }
    Print(L"v2.90-WR: Boot#### with Windows Boot Manager not found\n");
    return FALSE;
}
#endif

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
        Print(L"time: GetTime unavailable/garbage - constant 2026-08-19\n");
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
    Print(L"%s: scrub-wait TIMEOUT dmactl=0x%08x hwcfg2=0x%08x\n", tag, dct, hcfg);
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

    Print(L"gsp: ENGINE reset (0x1103C0) - killing GFW from POST...\n");
    mmio_write32(GSP_ENGINE, NV_PFALCON_FALCON_ENGINE_RESET_TRUE);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
    mmio_write32(GSP_ENGINE, 0);
    for (i = 0; i < 16; i++) mmio_read32(GSP_ENGINE);
}

/* ==== v66/v68: 40HX (TU106) 原生 FWSEC HS-boot on GSP → FRTS → WPR2 up ====
 * 对照driver s_prepareForFwsec_TU102 + kgspExecuteFwsec (frts_tu102.c):
 *  GSP kflcnReset → patch data(iface@0xe0 → DMEMMAPPER@0x360 → cmd_in@0x3b0,
 *  init_cmd=0x15) → portload IMEM NS(0x400)+SEC(0x9600@0x400, TU102 语义) →
 *  BROM(PARAADDR= sig DMEM 址) → BOOTVEC=0 → STARTCPU → poll WPR2.
 * v70: load改 WITH_LOADER — FWSEC 是 WITH_LOADER 型 ucode (driver
 * kernel_gsp_fwsec.c:741 bootType=WITH_LOADER), secure code 必须由 generic
 * falcon BL (bindata sec2_bl_gp10x, 768B) 从 host memory DMA 拉进 secure IMEM.
 * v68/v69 port写 NS+SEC (DIRECT 语义) 与 v66/v67 DMA SEC=1 在 TU106 上
 * secure IMEM 全 scrub 被实机证伪 — host 无 secure 写permission, BL 有.
 * 40HX FWSEC sig position假设 data@0x10 (prod 真值/dbg 0xff padding; 0x180=RSA3K). */
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
     *    0x162000A1). IRQMSET=0 同 E1 BL load.
     *    Turing 无显式 core switch (kflcnSwitchToFalcon_TU102 仅软status),
     *    reset 后即 FALCON mode; BCR 1=RISCV 是 GA102 语义 — TU102 driver在
     *    FWSEC load前不切核, 故写 0x0 (FALCON). 读回恒 0x0 属正常. */
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
     *    frtsRegionDesc(40HX 8GB frtsOffset) — 同driver s_vbiosPatchInterfaceData */
    mapper = (UINT32 *)(dmem + FW50_MAPPER_OFF);
    c = (UINT32 *)(dmem + FW50_CMDIN_OFF);
    Print(L"fwsec50: data iface@0x%x hdr={%d,%d,%d,%d} mapper@0x%x "
          L"sig=0x%08x ver=%d cmd_in_off=0x%x size=0x%x\n",
          FW50_IFACE_OFF, dmem[FW50_IFACE_OFF], dmem[FW50_IFACE_OFF+1],
          dmem[FW50_IFACE_OFF+2], dmem[FW50_IFACE_OFF+3],
          FW50_MAPPER_OFF, mapper[0],
          (UINT16)((mapper[0]>>16) & 0xFFFF),
          mapper[2], mapper[3]);
    /* 若实测 mapper layoutoffset与constant不符（mapper[2]=cmd_in_off 非 0x3b0），
     * 则按 mapper 自述的 cmd_in_buffer_offset 重定bit（driver式） */
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
    c[8] = (UINT32)(g_frtsOffset >> 12);
    c[9] = 0x100;
    c[10] = 2;
    mapper[11] = FWSEC_CMD_FRTS;           /* init_cmd = 0x15 (FRTS) */
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"fwsec50: mapper.init_cmd=0x%x frts4k=0x%x (frts=0x%llx)\n",
          mapper[11], c[8], g_frtsOffset);

    /* 3. kflcnDisableCtxReq + TRANSCFG (host DMA 到 falcon 需要):
     *    v70 BL 用 ctxDma=4 (PHYS_SYS_NCOH, BL firmware固定) → TRANSCFG(4).
     *    0x5 = COHERENT_SYSMEM(1) | MEM_TYPE_PHYSICAL(bit2) — 同driver
     *    s_setupLoaderAperture(ADDR_SYSMEM+CACHED); v66 DMA 用同值verify
     *    可 DMA 读 >4GB host memory (fwsecPhys=0x11982c000). */
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

    /* 4. v70 WITH_LOADER — TU102 FWSEC 权威load (kernel_gsp_fwsec.c:741
     *    bootType=WITH_LOADER; s_setupLoader + s_prepareHsFalconWithLoader):
     *    FWSEC code/data 留在 host memory, 由 generic falcon BL (768B, ns) 在
     *    secure context里 DMA 拉进 IMEM — host 直写 secure IMEM (v66-v69 port
     *    SECURE / DMA SEC=1) 全 scrub 被实机证伪, 此路不再走.
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

        /* (a) BL DMEM DESC → DMEM 0x0 (AINCW port写) */
        mmio_write32(GSP_BASE + 0x1C0, (BL_DESC_DMEM_LOAD_OFF) | (1u << 24));
        for (i = 0; i < BL_DESC_SIZE / 4; i++)
            mmio_write32(GSP_BASE + 0x1C4, d[i]);
        __asm__ volatile("wbinvd" ::: "memory");
        mmio_write32(GSP_BASE + 0x1C0, 0);

        /* (b) generic BL code → IMEM 顶. driver s_setupLoader 公式:
         *     imemSizeBlk = HWCFG.IMEM_SIZE[8:0] (GSP IMEM block 数, 256B/blk)
         *     imemDstBlk  = imemSizeBlk - blCodeSize/256; load @imemDstBlk<<8
         *     tag = blStartTag 起 (0xfd), BOOTVEC = 0xfd00 (BL firmwarecompile期). */
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

        /* (c) readback: BL[0] 落bit + desc.ctxDma 落bit */
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

    /* 5. BOOTVEC = blStartTag<<8 (BL 自定bit) + STARTCPU.
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

    /* 7. poll WPR2 → FRTS succeeded则 up；读 GSP cpu/dbg/scratch 判failed原因 */
    for (i = 0; i < 5000; i++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0u) == g_wpr2LoUp &&
            (hi & 0xFFFFFFF0u) == g_wpr2HiUp) {
            Print(L"fwsec50: *** WPR2 UP lo=0x%08x hi=0x%08x after %dms ***\n",
                  lo, hi, (INTN)i);
            return TRUE;
        }
        if ((i % 500) == 0) {
            UINT32 vIM, vD;
            /* BL DMA succeeded的判据: IMEM[0]=FWSEC ns code[0], DMEM[0x10]=data sig */
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
            Print(L"meta-low: alloc FAIL - using original\n");
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
            Print(L"booter: WARNING RESET_READY did not arrive (HWCFG2=0x%08x)\n", data);
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
    Print(L"booter: CPUCTL after BCR=0 = 0x%08x (0xBADF = lockdown not lifted)\n", data);
    if ((data & 0xBADF0000) == 0xBADF0000) {
        /* запасной вариант: BCR=0x1 (как в v2.12 — тоже снимал lockdown) */
        Print(L"booter: trying BCR=0x1...\n");
        mmio_write32(SEC2_BCR_CTRL, 0x1);
        uefi_call_wrapper(BS->Stall, 1, 10000);
        data = mmio_read32(SEC2_CPUCTL);
        Print(L"booter: CPUCTL after BCR=1 = 0x%08x\n", data);
        if ((data & 0xBADF0000) == 0xBADF0000) {
            Print(L"booter: SEC2 lockdown NOT lifted - aborting booter load\n");
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
    Print(L"booter: WPR2 before write: lo=0x%08x hi=0x%08x\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));
    mmio_write32(REG_PFB_MMU_WPR2_LO, 0x027fe000);
    mmio_write32(REG_PFB_MMU_WPR2_HI, 0x027fee00);
    uefi_call_wrapper(BS->Stall, 1, 10000);
    Print(L"booter: WPR2 after write: lo=0x%08x hi=0x%08x (unchanged = locked)\n",
          mmio_read32(REG_PFB_MMU_WPR2_LO), mmio_read32(REG_PFB_MMU_WPR2_HI));

    /* kflcnDisableCtxReq: FBIF_CTL ALLOW_PHYS_NO_CTX + DMACTL=0 */
    data = mmio_read32(SEC2_FBIF_CTL);
    data |= (1 << 7);
    mmio_write32(SEC2_FBIF_CTL, data);
    data = mmio_read32(SEC2_FBIF_CTL);
    if ((data & 0xBADF0000) == 0xBADF0000)
        Print(L"booter: WARNING FBIF_CTL still locked (0x%08x)\n", data);
    mmio_write32(SEC2_DMACTL, 0);

    /* v2.41: RM = chipId0 — из ТРЕЙСА драйвера: 0xb72000a1 (НЕ PMC_BOOT_0!).
     * kflcnReset_TU102: kflcnRegWrite(RM, pGpu->chipId0). */
    mmio_write32(SEC2_RM, 0xb72000a1);
    Print(L"booter: RM written = 0xb72000a1 (chipId0 from driver trace)\n");

    /* TRANSCFG(0): TARGET=COHERENT_SYSMEM(1) | MEM_TYPE=PHYSICAL(1<<2)
     * (нужен и для внутреннего DMA booter'а при чтении WPR meta) */
    data = mmio_read32(SEC2_FBIF_TRANSCFG0);
    data = (data & ~0x7) | 0x5;
    mmio_write32(SEC2_FBIF_TRANSCFG0, data);

    /* v2.21: ТЕСТ доступности DMATRF (запись+readback). v2.17: DMA «не
     * передал» (IMEM=DEAD5EC1 через НЕ-secure порт) — но SEC=1 передача
     * могла писать в SECURE IMEM (невидимый не-secure чтению), а блобы тогда
     * были мусором (до --redefine-sym). Теперь блобы настоящие. */
    Print(L"booter: DMATRFBASE before = 0x%08x\n", mmio_read32(SEC2_DMATRFBASE));
    mmio_write32(SEC2_DMATRFBASE, 0xDEADBEEF);
    Print(L"booter: DMATRFBASE after = 0x%08x (DEADBEEF = writable; 0xBADF = locked)\n",
          mmio_read32(SEC2_DMATRFBASE));

    /* v2.71b comment retained; v55: TU102 (nv616) geometry replaces the GA102
     * numbers here — see BOOTER_* defines above. IMEM = image[0x100..0x8500)
     * (0x8400 B, SEC=1), DMEM = image[0x8500..0xE700) (0x6200 B, SEC=0);
     * signature patch site image[0x8700] lands on DMEM[0x200]=hsSigDmemAddr. */
    Print(L"booter: DMA IMEM SEC=1 (dest=0, src+0x100, 0x8400 bytes)...\n");
    falcon_dma_transfer(0, BOOTER_APP_CODE_OFFSET, ucodePhys,
                        BOOTER_APP_CODE_SIZE,
                        0 | (6 << 8) | (0 << 12) | (1 << 4) | (1 << 2));
    Print(L"booter: DMA DMEM SEC=0 (dest=0, src+0x8500, 0x6200 bytes)...\n");
    falcon_dma_transfer(0, 0, ucodePhys + BOOTER_OS_DATA_OFFSET,
                        BOOTER_OS_DATA_SIZE,
                        0 | (6 << 8) | (0 << 12));
    mmio_write32(SEC2_DMEMC0, BOOTER_HS_SIG_DMEM_ADDR);
    Print(L"booter: DMEM[0x%x]=0x%08x (expecting sig @image+0x%x = 0x%08x)\n",
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
        Print(L"booter: hist %u entries in %u.%03u ms, iters=%u (%s)\n",
              (UINT32)hist_n,
              (UINT32)(elapsed / 1000000ULL),
              (UINT32)((elapsed / 1000ULL) % 1000ULL),
              (UINT32)it,
              plmOpen ? L"PLM OPEN" : halted ? L"HALT" : L"timeout 5s");
        for (j = 0; j < hist_n; j++) {
            UINT64 tj = ((UINT64)hist[j].t_hi << 32) | hist[j].t_lo;
            UINT64 d = tj - t0;
            if (hist_n > 240 && j == 120) {
                Print(L"  ... skipped %u entries ...\n", (UINT32)(hist_n - 240));
                j = hist_n - 121;   /* после j++ продолжим с n-120 */
            }
            Print(L"  hist[%03u] +%u.%03ums cpu=0x%08x irq=0x%08x dbg=0x%08x "
                  L"m0=0x%08x w2=0x%08x dma=0x%08x gsp=0x%08x "
                  L"d[ff4c]=%08x d[ff50]=%08x d[10]=%08x\n",
                  (UINT32)j,
                  (UINT32)(d / 1000000ULL), (UINT32)((d / 1000ULL) % 1000ULL),
                  hist[j].cpuctl, hist[j].irqstat, hist[j].dbg,
                  hist[j].mbox0, hist[j].wpr2lo, hist[j].dmatrfcmd,
                  hist[j].gspmbox0, hist[j].dFF4c, hist[j].dFF50,
                  hist[j].d10);
        }
        Print(L"booter: final: cpu=0x%x irq=0x%x dbg=0x%x m0=0x%08x m1=0x%08x\n",
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
        Print(L"booter: trace rdidx=%d wtidx=%d (0xBADF = riscv block locked)\n",
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
 * v56: TU102 BOOT_DIRECT booter loader —— 完全按 OpenRM 610.43.03 driver
 * （kernel_gsp_booter_tu102.c / kernel_gsp_falcon_tu102.c）复刻。
 *
 * 关键点（与 90HX/GA102 的 DMA load完全不同！）：
 *  - Turing 的 SEC2/GSP falcon 是 **BOOT_DIRECT**（kgspExecuteHsFalcon_TU102
 *    断言 !bBootFromHs；s_allocateUcodeFromBinArchive 选 BOOT_DIRECT branch），
 *    load走 **IMEMC/IMEMD + IMEMT block tag port**（不是 DMATRF DMA）。
 *  - s_prepareHsFalconDirect()：
 *      kflcnDisableCtxReq (FBIF_CTL bit7 + DMACTL=0)
 *      IMEM NS : dst=0x000 src=image+imemNsPa(0x0)   size=imemNsSize(0x100)  SEC=0 tag=0
 *      IMEM SEC: dst=0x100 src=image+imemSecPa(0x100) size=imemSecSize(0x8400) SEC=1 tag=1
 *      DMEM    : dst=0     src=image+dataOffset(0x8500) size=dmemSize(0x6200)（signature patch）
 *      **BOOTVEC = 0**（GA102 才是 0x100 —— v55 用错值！）
 *  - kflcnReset_TU102 写 RM = pGpu->chipId0；chipId0 = 原始 NV_PMC_BOOT_0
 *    （gpu_mgr.c: osDevReadReg032(NV_PMC_BOOT_0)），40HX = 0x166000A1，
 *    不是 GA102 的 0xb72000a1（v55 也用错值）。
 *  - start：MAILBOX0/1 = WPR meta physicaladdress，STARTCPU=2，等 HALT，mbox0==0 succeeded。
 * ===================================================================== */

/* IMEM portload：AINCW=1 + 每 256B(64 word) 打一次 IMEMT tag */
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

/* DMEM portload：AINCW=1，连续写 DMEMD */
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
 * v58（参考 cmpunlocker 0001 patch 后重写load器entry）：
 *   driver exploit run在 FWSEC 后 **经 halted 的 SEC2** 上，_kgspCmp40
 *   ExecuteBooterFreshMeta → kgspExecuteBooterLoad 的 native-probe path
 *   **不再做 engine reset**（reset 会把 RESET_PLM 从 0xff 改成 0x8f 且被
 *   driver判死）。因此 v58 先试 attempt A = 不复bit直接portload+start（driver同款）；
 *   若未得 mbox0==0 再 attempt B = engine reset 版（v56/57 同款）兜底。
 *   前置探测print RESET_PLM/WPR2，对照driver CMP40_STOCKFLOW_V551 判定。
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
    /* v60: pre 探测逐register单发读（每行只读证security的register；读挂时log
     * 能精确定bit）。RESET_PLM(0x8403C4) 在 kill-GFW 后的裸 SEC2 上read会
     * 挂死（v59 实测：log停在call点，pre parameter求值阶segment卡死）——故从 pre
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
     * REFERENCE_FLOW §3.1 推论 1：booter 可能verify WPR2 后exit(=0x91)。
     * host 直写可能被lock——写后读回verify并print结果。 */
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

        /* 准备engine（A: 不加复bit——driver exploit 用 FWSEC 后 halted 的engine；
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

        /* IMEM/DMEM portload（signature由主线 patch 到 image+0x8700 = DMEM+0x200） */
        Print(L"tu102: port load IMEM ns+sec + DMEM...\n");
        u40x_imem_write(0x000u, FALSE, (const UINT32 *)(img + 0x0u), 0x100u, 0x0u);
        u40x_imem_write(0x100u, TRUE, (const UINT32 *)(img + 0x100u), 0x8400u, 0x100u);
        u40x_dmem_write(0x0u, (const UINT32 *)(img + 0x8500u), 0x6200u);
        __asm__ volatile("wbinvd" ::: "memory");

        /* readback verify */
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
         * driver kgspExecuteBooterLoad_TU102: mailbox0/1 = LO32/HI32(sysmemAddr)
         * = 64 bit寻址，meta 由 RM memdesc allocate在 >4GB（实测 0x110BB0000）。
         * v55 的 cmp90_meta_low(<4GB) 是 90HX/GA102 老假设；TU102 lock卡上
         * <4GB 读反而被lock（869 行 v2.63 comment：exit 0x91）。 */
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

        /* 稀疏单发读（每步先打点再读——读挂时log能定bit） */
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
    Print(L"[5] cmd_in @0x23D0 <- FRTS cmd (44B, explicit addressing)...\n");
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
    Print(L" sec=0x%08x (0x15 = port writes the secure zone!)\n", mmio_read32(SEC2_DMEMD0));

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

    Print(L"[5] STARTCPU (ucodeId=10), polling WPR2 up to 5s (FRTS)...\n");
    for (p = 0; p < 5000; p++) {
        UINT32 lo = mmio_read32(REG_PFB_MMU_WPR2_LO);
        UINT32 hi = mmio_read32(REG_PFB_MMU_WPR2_HI);
        if ((lo & 0xFFFFFFF0) == 0x027FE000 && (hi & 0xFFFFFFF0) == 0x027FEE00) {
            Print(L"[5] *** WPR2 UP lo=0x%08x hi=0x%08x after %d ms - "
                  L"SEC2 ucode executed FRTS! ***\n", lo, hi, p);
            wpr2set = TRUE;
            break;
        }
        if ((p % 1000) == 0)
            Print(L"[5] t=%dms wpr2lo=0x%08x cpu=0x%x dbg=0x%x bcr=0x%x\n",
                  p, lo, mmio_read32(SEC2_CPUCTL), mmio_read32(SEC2_DEBUGINFO),
                  mmio_read32(SEC2_BCR_CTRL));
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"[5] FRTS result: WPR2=%s lo=0x%08x hi=0x%08x cpu=0x%x dbg=0x%x\n",
          wpr2set ? L"UP" : L"NO",
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
    Print(L"[5] SB: init_cmd=0x19 @0x6C4, cmd 24B @0x23D0...\n");
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
              priv0, privA, sbChanged ? L" <<< CHANGED (SB fired!)" : L"");
    }
    dump_regs(L"[5-sb]");

    Print(L"[5] result: WPR2=%s SB=%s PLM=0x%08x\n",
          wpr2set ? L"OK" : L"no", sbChanged ? L"OK" : L"no",
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
    Print(L"\n=== v2.57-4: PRELOAD PROBE (GSP+SEC2 IMEM/DMEM, NS|SEC) ===\n");
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

    Print(L"\n--- v2.26: direct FEAT_OVR write (host probe) ---\n");
    mmio_write32(REG_FEAT_OVR_PLM, VAL_PLM_OPEN);
    v = mmio_read32(REG_FEAT_OVR_PLM);
    Print(L"probe: PLM=0x%08x after writing 0xFFFFFFFF (0xFFFFFF8F = write ignored)\n", v);

    mmio_write32(REG_FEAT_OVR_SM_SPD, VAL_SS0_UNLOCKED);
    mmio_write32(REG_FEAT_OVR_SM_SPD_1, VAL_SS1_UNLOCKED);
    Print(L"probe: SS0=0x%08x SS1=0x%08x after writing 0x88888888/0x8\n",
          mmio_read32(REG_FEAT_OVR_SM_SPD), mmio_read32(REG_FEAT_OVR_SM_SPD_1));

    if (is_unlocked()) {
        Print(L"probe: *** DIRECT WRITES WORK - GPU open without booter ***\n");
        return TRUE;
    }

    Print(L"probe: diagnostics (register locked?):\n");
    mmio_write32(REG_FEAT_OVR_PLM, 0x00000000);
    Print(L"probe:   PLM=0x%08x after 0x0 (close)\n", mmio_read32(REG_FEAT_OVR_PLM));
    mmio_write32(REG_FEAT_OVR_PLM, 0xFFFFFFFE);
    Print(L"probe:   PLM=0x%08x after 0xFFFFFFFE (bit0 flip)\n", mmio_read32(REG_FEAT_OVR_PLM));
    mmio_write32(REG_FEAT_OVR_SM_SPD, 0x11111111);
    Print(L"probe:   SS0=0x%08x after 0x11111111\n", mmio_read32(REG_FEAT_OVR_SM_SPD));
    mmio_write32(REG_FEAT_OVR_SM_SPD_1, 0x00000000);
    Print(L"probe:   SS1=0x%08x after 0x0\n", mmio_read32(REG_FEAT_OVR_SM_SPD_1));
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

    Print(L"\n--- v2.25: direct RISC-V start (BROM bypass) ---\n");
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
        Print(L"riscv: attempt %d: BCR=0x%x (reads 0x%x) BOOTVEC=0x%x cpu=0x%x STARTCPU\n",
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
    Print(L"gspmail: init -> status 0x%08x after %d ms (mbox0=0x%x mbox1=0x%x)\n",
          st, i, mmio_read32(0x110040), mmio_read32(0x110044));
    if (st != 0x65 && st != 0x55)
        Print(L"gspmail: WARNING - init status not 0x65/0x55\n");

    /* 0x57c — booter load (V67-сигнатура в WPR meta) */
    Print(L"gspmail: cmd 0x57c (booter load, V67)...\n");
    mmio_write32(0x110804, 0x57c);
    for (i = 0; i < 5000; i++) {
        st = mmio_read32(0x110804);
        if (st == 0x65 || st == 0x55) break;
        if (mmio_read32(REG_FEAT_OVR_PLM) == VAL_PLM_OPEN) break;
        uefi_call_wrapper(BS->Stall, 1, 1000);
    }
    Print(L"gspmail: load -> status 0x%08x after %d ms (mbox0=0x%x mbox1=0x%x PLM=0x%x)\n",
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
    Print(L"FLR: PCIe capability not found\n");
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

    Print(L"\n=== pcie-gen: PCIe Gen%d unlock (v2.97 booter-write) ===\n",
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
        Print(L"pcie-gen: v97: no payload context - booter write skipped\n");
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
            Print(L"pcie-gen: host-cfg: PCIe capability not found\n");
        }
    }

    Print(L"pcie-gen: LTSSM_OVR(0x8872c)=0x%08x (read-only)\n",
          mmio_read32(XVE_LTSSM_OVR));

    pcie_gen_status(L"post");
    Print(L"pcie-gen: done, fail=%d (retrain - on link recovery after FLR)\n",
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
        Print(L"fw: suspicious size %d\n", BufSize);
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
                Print(L"fw: EOF before end of file (%d/%d)\n", total, BufSize);
                return EFI_LOAD_ERROR;
            }
            total += rd;
            if ((total & 0xFFFFFF) == 0 || total >= BufSize)
                Print(L"fw: ... %d / %d MB\n", (total >> 20), (BufSize >> 20));
        }
    }
    uefi_call_wrapper(File->Close, 1, File);
    *pOut = Buf;
    *pSize = BufSize;
    Print(L"fw: read %d bytes gsp_ga10x.bin\n", BufSize);
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

    if (n1 != 1) { Print(L"radix3: n1=%d (expected 1)\n", n1); return 0; }

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
     * v62: heap 依赖 FB size — 0x7F00000 是 10GB(CMP90HX) 实测；40HX 8GB
     * 的 log53 真解 dmesg 显示 gspFwHeap=0x1f7900000+0x6900000 → 8GB 卡
     * heap = 0x6900000。按 fbSize 选值。 */
    m->gspFwHeapSize   = (fbSize == 0x280000000ULL) ? 0x7F00000ULL   /* 10 GiB */
                       : (fbSize == 0x500000000ULL) ? 0xFE00000ULL   /* 20 GiB */
                                                   : 0x6900000ULL;   /* 8 GiB */
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

/* Loader ladder for the BlockIo preload. Windows first: most reporters boot
 * Windows; Debian next — a v1.1.19 reporter (issue #25, X299/Debian 12)
 * hung because the ladder had Ubuntu but not Debian, and the preload fell
 * through to the (removed) SFS fallback. Paths the firmware itself knows
 * (BootOrder) are tried before this list. */
static const CHAR16 *os_loader_paths[] = {
    L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
    L"\\EFI\\debian\\shimx64.efi",
    L"\\EFI\\debian\\grubx64.efi",
    L"\\EFI\\ubuntu\\shimx64.efi",
    L"\\EFI\\ubuntu\\grubx64.efi",
    L"\\EFI\\systemd\\systemd-bootx64.efi",
    L"\\EFI\\BOOT\\bootx64.efi",
};
#define OS_LOADER_PATH_CNT (sizeof(os_loader_paths)/sizeof(os_loader_paths[0]))

/* ==== SFS-free OS loader preload — own FAT parser over BlockIo ====
 * Some AMI firmwares (X570 GAMING X F37d, X99-E WS) HANG inside
 * SimpleFileSystem calls made from a loaded application — plain file reads
 * unrelated to the unlock hang there too. BlockIo ReadBlocks is stable
 * (the 84 MB firmware read goes through it). So the OS loader is read into
 * RAM BEFORE the unlock with our own FAT16/FAT32 parser (partition or
 * MBR/GPT -> ESP -> path with LFN); afterwards LoadImage(SourceBuffer) +
 * StartImage hands over without touching SimpleFileSystem at all. */

static UINT8 *g_bmBuf = NULL;
static UINTN g_bmSize = 0;
static EFI_DEVICE_PATH *g_bmDp = NULL;
static const CHAR16 *g_bmPath = NULL;   /* loader path that won, for the log */

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

/* Geometry of one FAT volume, parsed once from the BPB. FAT16 ESPs are
 * common on Linux installs (mkfs.vfat picks FAT16 below ~260 MB), FAT32 is
 * what Windows setup creates — both must work or the preload silently
 * gives up and the hangy SFS fallback runs instead. */
typedef struct {
    EFI_BLOCK_IO_PROTOCOL *bio;
    UINT64 lba;             /* partition start LBA */
    UINT32 bps, spc;
    UINT32 fatOff;          /* byte offset of FAT #0 */
    UINT32 dataOff;         /* byte offset of cluster 2 */
    UINT32 rootOff;         /* FAT16 only: fixed root directory region */
    UINT32 rootEnts;        /* FAT16 only: entries in that region */
    UINT32 rootClus;        /* FAT32 only: first cluster of the root dir */
    UINT32 eocMark;         /* end-of-chain marker (0xFFF8 / 0x0FFFFFF8) */
    BOOLEAN fat32;
} Cmp90Fat;

static EFI_STATUS
cmp90_fat_open(EFI_BLOCK_IO_PROTOCOL *bio, UINT64 lbaPartStart, Cmp90Fat *f)
{
    UINT8 bpb[512];
    UINT32 rsvd, nfats, fatsz, rootEnts, rootDirSz;
    EFI_STATUS st = cmp90_bio_read(bio, lbaPartStart, 0, 512, bpb);

    if (EFI_ERROR(st)) return st;
    if (bpb[510] != 0x55 || bpb[511] != 0xAA) return EFI_UNSUPPORTED;

    f->bio = bio;
    f->lba = lbaPartStart;
    f->bps = bpb[11] | (bpb[12] << 8);
    f->spc = bpb[13];
    rsvd     = bpb[14] | (bpb[15] << 8);
    nfats    = bpb[16];
    rootEnts = bpb[17] | (bpb[18] << 8);
    fatsz    = bpb[22] | (bpb[23] << 8);                  /* FAT12/16 */
    if (fatsz == 0) {
        fatsz = bpb[36] | (bpb[37]<<8) | (bpb[38]<<16) | (bpb[39]<<24);
        f->fat32 = TRUE;
    } else {
        f->fat32 = FALSE;
    }
    if (f->bps < 512 || f->bps > 4096 || (f->bps & (f->bps - 1)) ||
        f->spc == 0 || f->spc > 128 || nfats == 0 || nfats > 4 || fatsz == 0)
        return EFI_UNSUPPORTED;

    f->fatOff = rsvd * f->bps;
    rootDirSz = f->fat32 ? 0 : ((rootEnts * 32 + f->bps - 1) / f->bps) * f->bps;
    f->rootOff  = f->fatOff + nfats * fatsz * f->bps;
    f->dataOff  = f->rootOff + rootDirSz;
    f->rootEnts = f->fat32 ? 0 : rootEnts;
    f->rootClus = f->fat32 ? (bpb[44] | (bpb[45]<<8) | (bpb[46]<<16) |
                              (bpb[47]<<24)) : 0;
    f->eocMark  = f->fat32 ? 0x0FFFFFF8u : 0xFFF8u;
    if (f->fat32 && f->rootClus < 2) return EFI_UNSUPPORTED;
    if (!f->fat32 && rootEnts == 0) return EFI_UNSUPPORTED;
    return EFI_SUCCESS;
}

/* next cluster in the chain (FAT32: 32-bit entries, FAT16: 16-bit) */
static EFI_STATUS
cmp90_fat_next(Cmp90Fat *f, UINT32 clus, UINT32 *next)
{
    UINT32 v = 0;
    UINTN w = f->fat32 ? 4 : 2;
    EFI_STATUS st = cmp90_bio_read(f->bio, f->lba, f->fatOff + clus * w,
                                   w, &v);
    if (!EFI_ERROR(st)) *next = f->fat32 ? (v & 0x0FFFFFFFu) : (v & 0xFFFFu);
    return st;
}

/* перечисление записей каталога: cb получает имя (LFN, иначе SFN), атрибут,
 * первый кластер и размер; cb == FALSE — остановить обход. dirClus==0 —
 * плоский корень FAT16. */
typedef BOOLEAN (*cmp90_ent_cb)(Cmp90Fat *f, const CHAR16 *name, UINT8 attr,
                                UINT32 firstClus, UINT64 size, VOID *ctx);

static EFI_STATUS
cmp90_fat_dir_enum(Cmp90Fat *f, UINT32 dirClus, cmp90_ent_cb cb, VOID *ctx)
{
    UINT32 clus = dirClus;
    UINTN guard;

    for (guard = 0; guard < 65536; guard++) {
        /* clus == 0 is the FAT16 fixed root directory: a flat region outside
         * the cluster area, so this walk runs exactly once for it. */
        UINTN csz = clus ? (UINTN)f->spc * f->bps : (UINTN)f->rootEnts * 32;
        UINT64 cOff = clus ? f->dataOff + (UINT64)(clus - 2) * f->spc * f->bps
                           : f->rootOff;
        UINT8 *buf;
        UINTN e;
        EFI_STATUS st;
        if (clus && (clus < 2 || clus >= f->eocMark)) return EFI_NOT_FOUND;
        if (!csz) return EFI_NOT_FOUND;
        buf = cmp90_alloc(csz);
        if (!buf) return EFI_OUT_OF_RESOURCES;
        st = cmp90_bio_read(f->bio, f->lba, cOff, csz, buf);
        if (EFI_ERROR(st)) { cmp90_free(buf); return st; }

        {
            CHAR16 lfn[260]; BOOLEAN haveLfn = FALSE;
            for (e = 0; e + 32 <= csz; e += 32) {
                UINT8 *ent = buf + e;
                UINT8 attr = ent[11];
                if (ent[0] == 0x00) { cmp90_free(buf); return EFI_SUCCESS; }
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
                    CHAR16 nm[260]; BOOLEAN haveName = FALSE;
                    if (haveLfn) {
                        UINTN i;
                        for (i = 0; i < 259 && lfn[i] && lfn[i] != 0xFFFF; i++)
                            nm[i] = lfn[i];
                        nm[i] = 0;
                        haveName = TRUE;
                    }
                    if (!haveName && !(attr & 0x08)) {   /* 0x08 = метка тома */
                        UINTN si, sj = 0;
                        for (si = 0; si < 8; si++) {
                            UINT8 c = ent[si];
                            if (c == ' ') break;
                            nm[sj++] = (CHAR16)c;
                        }
                        if (ent[8] != ' ') {
                            nm[sj++] = L'.';
                            for (si = 8; si < 11; si++) {
                                UINT8 c = ent[si];
                                if (c == ' ') break;
                                nm[sj++] = (CHAR16)c;
                            }
                        }
                        nm[sj] = 0;
                        haveName = TRUE;
                    }
                    haveLfn = FALSE;
                    if (!haveName) continue;   /* метка тома без LFN */
                    if (!cb(f, nm, attr,
                            (UINT32)(ent[26] | (ent[27] << 8)) |
                            ((UINT32)(ent[20] | (ent[21] << 8)) << 16),
                            ent[28] | (ent[29]<<8) | (ent[30]<<16) |
                            ((UINT64)ent[31] << 24),
                            ctx)) {
                        cmp90_free(buf);
                        return EFI_SUCCESS;    /* остановлено колбэком */
                    }
                }
            }
        }
        cmp90_free(buf);
        if (!clus) return EFI_SUCCESS;         /* flat root: one pass only */
        {
            EFI_STATUS st = cmp90_fat_next(f, clus, &clus);
            if (EFI_ERROR(st)) return st;
        }
    }
    return EFI_NOT_FOUND;
}

/* поиск компонента пути в каталоге (обёртка над перечислением);
 * имя сравнивается без регистра */
typedef struct {
    const CHAR16 *name;
    UINT32 clus;
    UINT64 size;
    BOOLEAN found;
} Cmp90FindCtx;

static BOOLEAN
cmp90_find_cb(Cmp90Fat *f, const CHAR16 *name, UINT8 attr,
              UINT32 firstClus, UINT64 size, VOID *p)
{
    Cmp90FindCtx *c = (Cmp90FindCtx *)p;
    (void)f; (void)attr;
    if (!cmp90_eqi(name, c->name)) return TRUE;
    c->clus = firstClus;
    c->size = size;
    c->found = TRUE;
    return FALSE;
}

static EFI_STATUS
cmp90_fat_dir_find(Cmp90Fat *f, UINT32 dirClus,
                   const CHAR16 *name, UINT32 *outClus, UINT64 *outSize)
{
    Cmp90FindCtx c = { name, 0, 0, FALSE };
    EFI_STATUS st = cmp90_fat_dir_enum(f, dirClus, cmp90_find_cb, &c);
    if (EFI_ERROR(st)) return st;
    if (!c.found) return EFI_NOT_FOUND;
    *outClus = c.clus;
    *outSize = c.size;
    return EFI_SUCCESS;
}

/* чтение файла целиком по кластерной цепочке */
static EFI_STATUS
cmp90_fat_read_file(Cmp90Fat *f, UINT32 firstClus, UINT64 size, UINT8 *dest)
{
    UINT32 clus = firstClus;
    UINT64 done = 0;
    UINTN guard;

    for (guard = 0; guard < 4000000 && done < size && clus >= 2 &&
                    clus < f->eocMark; guard++) {
        UINT64 cOff = f->dataOff + (UINT64)(clus - 2) * f->spc * f->bps;
        UINTN take = f->spc * f->bps;
        if ((UINT64)take > size - done) take = (UINTN)(size - done);
        {
            EFI_STATUS st = cmp90_bio_read(f->bio, f->lba,
                                           cOff, take, dest + done);
            if (EFI_ERROR(st)) return st;
        }
        done += take;
        {
            EFI_STATUS st = cmp90_fat_next(f, clus, &clus);
            if (EFI_ERROR(st)) return st;
        }
    }
    return (done == size) ? EFI_SUCCESS : EFI_END_OF_FILE;
}

/* read "\DIR\SUB\FILE.EFI" from a FAT volume: BPB -> directory walk -> data */
static EFI_STATUS
cmp90_fat_load_path(Cmp90Fat *f, const CHAR16 *path,
                    UINT8 **fileBuf, UINTN *fileSize)
{
    UINT32 cur = f->fat32 ? f->rootClus : 0;   /* 0 = FAT16 flat root */
    UINT64 sz = 0;
    const CHAR16 *p = path;
    UINT8 *buf = NULL;
    EFI_STATUS st;
    BOOLEAN last = FALSE;

    while (!last) {
        CHAR16 comp[64];
        UINTN n = 0;
        while (*p == L'\\') p++;
        while (p[n] && p[n] != L'\\' && n < sizeof(comp)/sizeof(comp[0]) - 1)
            n++;
        if (!n || (p[n] && p[n] != L'\\'))      /* empty or oversized name */
            return EFI_INVALID_PARAMETER;
        CopyMem(comp, (VOID *)p, n * sizeof(CHAR16));
        comp[n] = 0;
        p += n;
        last = (*p == 0);

        st = cmp90_fat_dir_find(f, cur, comp, &cur, &sz);
        if (EFI_ERROR(st)) return st;
        if (!last && sz != 0) return EFI_NOT_FOUND;   /* expected a directory */
    }
    if (sz == 0 || sz > 0x02000000ull) return EFI_BAD_BUFFER_SIZE;

    buf = cmp90_alloc((UINTN)sz);
    if (!buf) return EFI_OUT_OF_RESOURCES;
    st = cmp90_fat_read_file(f, cur, sz, buf);
    if (EFI_ERROR(st)) { cmp90_free(buf); return st; }

    /* PE-санити: 'MZ' и e_lfanew → 'PE\0\0' */
    if (!(buf[0] == 'M' && buf[1] == 'Z')) { cmp90_free(buf); return EFI_LOAD_ERROR; }

    *fileBuf = buf;
    *fileSize = (UINTN)sz;
    return EFI_SUCCESS;
}

/* ==== #25: рекурсивный поиск лоадера ПО ИМЕНИ файла ====
 * When every BootOrder path and hardcoded path misses (a distro we did not
 * list, an unusual ESP layout), walk the whole FAT tree and match by file
 * name — Windows first, then Linux — instead of giving up (and, in older
 * builds, falling into the removed SFS path that hangs some boards). */
static const CHAR16 *scan_loader_names[] = {
    L"bootmgfw.efi",             /* Windows Boot Manager */
    L"shimx64.efi",              /* secure-boot Linux entry point */
    L"grubx64.efi",
    L"systemd-bootx64.efi",
    L"bootx64.efi",              /* generic removable fallback */
};
#define SCAN_LOADER_CNT (sizeof(scan_loader_names)/sizeof(scan_loader_names[0]))
#define SCAN_MAX_DEPTH 6
#define SCAN_MAX_DIRS  2048

typedef struct {
    INT32 bestPrio;              /* -1 = ничего не найдено */
    CHAR16 bestPath[160];
    UINT32 bestClus;
    UINT64 bestSize;
    CHAR16 path[160];            /* текущая цепочка каталогов */
    UINTN pathLen, depth, dirs;
} Cmp90ScanCtx;

static BOOLEAN
cmp90_scan_cb(Cmp90Fat *f, const CHAR16 *name, UINT8 attr,
              UINT32 firstClus, UINT64 size, VOID *p)
{
    Cmp90ScanCtx *c = (Cmp90ScanCtx *)p;
    UINTN i, nlen = StrLen(name);

    if (attr & 0x10) {           /* подкаталог — рекурсия */
        if (name[0] == L'.' &&
            (nlen == 1 || (nlen == 2 && name[1] == L'.')))
            return TRUE;         /* ".", ".." */
        if (c->depth >= SCAN_MAX_DEPTH || c->dirs >= SCAN_MAX_DIRS)
            return TRUE;
        if (c->pathLen + nlen + 2 >= sizeof(c->path)/sizeof(CHAR16))
            return TRUE;         /* не влезает — пропускаем ветку */
        c->path[c->pathLen++] = L'\\';
        CopyMem(c->path + c->pathLen, name, nlen * sizeof(CHAR16));
        c->pathLen += nlen;
        c->path[c->pathLen] = 0;
        c->depth++; c->dirs++;
        cmp90_fat_dir_enum(f, firstClus, cmp90_scan_cb, c);
        c->depth--;
        c->pathLen -= nlen + 1;
        c->path[c->pathLen] = 0;
        return TRUE;
    }

    for (i = 0; i < SCAN_LOADER_CNT; i++)
        if (cmp90_eqi(name, scan_loader_names[i])) break;
    if (i == SCAN_LOADER_CNT) return TRUE;           /* не лоадер */
    if (c->bestPrio >= 0 && (INT32)i >= c->bestPrio) return TRUE;
    if (c->pathLen + nlen + 2 >= sizeof(c->bestPath)/sizeof(CHAR16))
        return TRUE;
    c->bestPrio = (INT32)i;                          /* новый лучший */
    c->bestClus = firstClus;
    c->bestSize = size;
    CopyMem(c->bestPath, c->path, c->pathLen * sizeof(CHAR16));
    c->bestPath[c->pathLen] = L'\\';
    CopyMem(c->bestPath + c->pathLen + 1, name, nlen * sizeof(CHAR16));
    c->bestPath[c->pathLen + 1 + nlen] = 0;
    return TRUE;             /* идём дальше: может встретиться более приоритетный */
}

static BOOLEAN
preload_scan_volume(EFI_HANDLE h, Cmp90Fat *f)
{
    Cmp90ScanCtx c;
    UINT8 *buf;
    CHAR16 *keep;
    EFI_STATUS st;

    SetMem(&c, sizeof(c), 0);
    c.bestPrio = -1;
    c.path[0] = L'\\';
    c.pathLen = 1;

    cmp90_fat_dir_enum(f, f->fat32 ? f->rootClus : 0, cmp90_scan_cb, &c);
    if (c.bestPrio < 0) {
        Print(L"[preload] scan: no known loader name on this volume\n");
        return FALSE;
    }
    Print(L"[preload] scan: best candidate %s (priority %d)\n",
          c.bestPath, (INT32)c.bestPrio);
    if (c.bestSize == 0 || c.bestSize > 0x02000000ull) {
        Print(L"[preload] scan: bad size %llu - skipped\n", c.bestSize);
        return FALSE;
    }
    /* issue #36: our own binary deployed as \EFI\Boot\bootx64.efi */
    if ((UINTN)c.bestSize == g_ourImageSize) {
        Print(L"[preload] scan: %s is our own image - skipped\n", c.bestPath);
        return FALSE;
    }
    buf = cmp90_alloc((UINTN)c.bestSize);
    if (!buf) return FALSE;
    st = cmp90_fat_read_file(f, c.bestClus, c.bestSize, buf);
    if (EFI_ERROR(st) || !(buf[0] == 'M' && buf[1] == 'Z')) {
        Print(L"[preload] scan: read/PE check failed (%r)\n", st);
        cmp90_free(buf);
        return FALSE;
    }
    keep = StrDuplicate(c.bestPath);
    if (!keep) { cmp90_free(buf); return FALSE; }
    g_bmBuf = buf;
    g_bmSize = (UINTN)c.bestSize;
    g_bmPath = keep;
    g_bmDp = FileDevicePath(h, keep);
    Print(L"[preload] OK %s, %d bytes in RAM (scan)\n", keep, (UINTN)c.bestSize);
    return TRUE;
}

/* Candidate loaders the firmware itself boots: BootOrder -> Boot#### -> the
 * FILEPATH node of each entry. Read-only GetVariable calls, so none of the
 * NVRAM-write hangs seen on these boards apply. This is what lets custom
 * installs (rEFInd, fedora/debian shim, renamed Windows entries) hand over
 * without us guessing paths; our own entry is skipped. */
#define BOOT_PATH_MAX 8
static CHAR16 *g_bootPaths[BOOT_PATH_MAX];
static UINTN   g_bootPathCnt;

static BOOLEAN path_is_our_efi(const CHAR16 *p)
{
    const CHAR16 *base = p, *q;
    for (q = p; *q; q++)
        if (*q == L'\\') base = q + 1;
    return cmp90_eqi(base, L"50HXUNLK.EFI");
}

static void collect_boot_order_paths(void)
{
    static EFI_GUID gvGuid = EFI_GLOBAL_VARIABLE;
    static UINT8 opt[1024];
    UINT16 order[64], current = 0xFFFF;
    UINTN sz = sizeof(current), i;
    EFI_STATUS st;

    uefi_call_wrapper(RT->GetVariable, 5, L"BootCurrent", &gvGuid,
                      NULL, &sz, &current);
    sz = sizeof(order);
    st = uefi_call_wrapper(RT->GetVariable, 5, L"BootOrder", &gvGuid,
                           NULL, &sz, order);
    if (EFI_ERROR(st)) { Print(L"[preload] BootOrder: %r\n", st); return; }

    for (i = 0; i < sz / sizeof(UINT16) && g_bootPathCnt < BOOT_PATH_MAX; i++) {
        CHAR16 name[9];
        UINTN osz = sizeof(opt), off;
        UINT32 attr = 0;
        EFI_DEVICE_PATH *dp;

        if (order[i] == current) continue;          /* that entry is us */
        SPrint(name, sizeof(name), L"Boot%04X", order[i]);
        if (EFI_ERROR(uefi_call_wrapper(RT->GetVariable, 5, name, &gvGuid,
                                        NULL, &osz, opt)))
            continue;
        if (osz < 8) continue;
        CopyMem(&attr, opt, 4);
        if (!(attr & 1)) continue;                  /* LOAD_OPTION_ACTIVE off */
        /* EFI_LOAD_OPTION: attributes, path list length, description, path */
        off = 6;
        while (off + 1 < osz && (opt[off] || opt[off + 1])) off += 2;
        off += 2;
        dp = (EFI_DEVICE_PATH *)(opt + off);
        while ((UINT8 *)dp + 4 <= opt + osz && !IsDevicePathEnd(dp) &&
               DevicePathNodeLength(dp) >= 4) {
            if (DevicePathType(dp) == MEDIA_DEVICE_PATH &&
                DevicePathSubType(dp) == MEDIA_FILEPATH_DP) {
                CHAR16 *fp = ((FILEPATH_DEVICE_PATH *)dp)->PathName;
                CHAR16 *keep = (*fp && !path_is_our_efi(fp)) ? StrDuplicate(fp)
                                                             : NULL;
                if (keep) {
                    Print(L"[preload] %s -> %s\n", name, keep);
                    g_bootPaths[g_bootPathCnt++] = keep;
                }
                break;
            }
            dp = NextDevicePathNode(dp);
        }
    }
    /* #25 (X299/Debian): zero lines above although Debian boots from
     * BootOrder — the next log must show which case this is. */
    Print(L"[preload] BootOrder: %d entries, %d loader path(s) collected\n",
          (INT32)(sz / sizeof(UINT16)), (INT32)g_bootPathCnt);
}

/* try every candidate loader on one FAT volume; the first hit is taken */
static BOOLEAN preload_try_volume(EFI_HANDLE h, EFI_BLOCK_IO_PROTOCOL *bio,
                                  UINT64 lbaStart)
{
    Cmp90Fat f;
    UINTN i;

    if (EFI_ERROR(cmp90_fat_open(bio, lbaStart, &f)))
        return FALSE;

    for (i = 0; i < g_bootPathCnt + OS_LOADER_PATH_CNT; i++) {
        const CHAR16 *path = (i < g_bootPathCnt)
                           ? g_bootPaths[i]
                           : os_loader_paths[i - g_bootPathCnt];
        UINT8 *fb = NULL;
        UINTN fsz = 0;

        if (EFI_ERROR(cmp90_fat_load_path(&f, path, &fb, &fsz)))
            continue;
        /* issue #36: the Windows installer also copies our EFI to
         * \EFI\Boot\bootx64.efi — loading that would restart us in a loop */
        if (fsz == g_ourImageSize) { cmp90_free(fb); continue; }
        g_bmBuf = fb;
        g_bmSize = fsz;
        g_bmPath = path;
        g_bmDp = FileDevicePath(h, (CHAR16 *)path);
        Print(L"[preload] OK %s, %d bytes in RAM\n", path, fsz);
        return TRUE;
    }
    /* FAT parsed fine but every path missed — walk the tree by file name
     * (#25: Debian was missing from the ladder; the scan catches any distro) */
    Print(L"[preload] ladder miss - scanning the volume by loader name...\n");
    return preload_scan_volume(h, &f);
}

/* Walk every BlockIo volume — our own boot volume first, since that ESP
 * holds the OS loader on virtually every install — and keep the loader in
 * RAM. The DevicePath is kept too: LoadImage hands the real ESP to the
 * loader, which Windows Boot Manager needs to find its BCD. */
static void preload_os_loader(EFI_HANDLE ImageHandle)
{
    EFI_HANDLE *H = NULL, self = NULL;
    UINTN n = 0, k;
    EFI_STATUS st;

    collect_boot_order_paths();
    {
        EFI_LOADED_IMAGE *li = NULL;
        if (!uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle,
                               &LoadedImageProtocol, (VOID **)&li) && li)
            self = li->DeviceHandle;
    }

    Print(L"[preload] BlockIo enumeration (SFS not used)...\n");
    st = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
                           &cmp90BioGuid, NULL, &n, &H);
    if (EFI_ERROR(st)) { Print(L"[preload] LocateHandleBuffer: %r\n", st); return; }
    Print(L"[preload] block devices: %d\n", n);

    for (k = 0; k < n; k++)
        if (H[k] == self) { H[k] = H[0]; H[0] = self; break; }

    for (k = 0; k < n && !g_bmBuf; k++) {
        EFI_BLOCK_IO_PROTOCOL *bio = NULL;
        BOOLEAN isPart;

        if (uefi_call_wrapper(BS->HandleProtocol, 3, H[k], &cmp90BioGuid,
                              (VOID **)&bio) || !bio || !bio->Media)
            continue;
        isPart = bio->Media->LogicalPartition;
        Print(L"[preload] handle %d%s: bs=%d last=%llu removable=%d logical=%d\n",
              k, (H[k] == self) ? L" (ours)" : L"", bio->Media->BlockSize,
              (UINT64)bio->Media->LastBlock,
              bio->Media->RemovableMedia, isPart);

        /* every handle is tried as a FAT volume directly: partition handles
         * map to LBA 0 of their own partition, which covers MBR disks,
         * GPT ESPs without parsing tables, and superfloppy media */
        if (preload_try_volume(H[k], bio, 0))
            break;

        /* whole disks additionally: find the ESP through the GPT */
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
            if (!espLba) { Print(L"[preload] ESP not found in GPT\n"); continue; }
            Print(L"[preload] ESP @LBA %llu - looking for a loader...\n", espLba);
            preload_try_volume(H[k], bio, espLba);
        }
    }
    if (H) FreePool(H);
    if (!g_bmBuf)
        Print(L"[preload] no OS loader found on any volume\n");
}

/* финальный старт: из ОЗУ (SourceBuffer), DevicePath = реальный ESP */
/* EFI_DEVICE_PATH_PROTOCOL — for the "which volume am I on / booting from"
 * chainload diagnostics (issue #43/#47: identify the ESP in the log). */
static EFI_GUID u40x_dp_guid = {0x09576e91,0x6d3f,0x11d2,
    {0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};

static EFI_STATUS chainload_preloaded(EFI_HANDLE ImageHandle)
{
    EFI_HANDLE h = NULL;
    EFI_STATUS st;

    /* which volume WE were loaded from - correlates with the FS#N list below */
    {
        EFI_LOADED_IMAGE *li = NULL;
        EFI_DEVICE_PATH *dp = NULL;
        if (!EFI_ERROR(uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle,
                &LoadedImageProtocol, (VOID**)&li)) && li &&
            !EFI_ERROR(uefi_call_wrapper(BS->HandleProtocol, 3,
                li->DeviceHandle, &u40x_dp_guid, (VOID**)&dp)) && dp) {
            CHAR16 *vol = DevicePathToStr(dp);
            CHAR16 *fp  = li->FilePath ? DevicePathToStr(li->FilePath) : NULL;
            if (vol) {
                Print(L"chainload: we were loaded from volume: %s\n", vol);
                FreePool(vol);
            }
            if (fp) {
                Print(L"chainload: our path: %s\n", fp);
                FreePool(fp);
            }
        }
    }

    /* ===== v2.99m: лестница загрузки ОС БЕЗ единого ресета =====
     * Тёплый ресет = POST = VBIOS переинициализирует GPU и анлок гибнет
     * (подтверждено юзером на реальном HW 2026-08-23). Две ступени:
     *   1) StartImage лоадера из ОЗУ (BlockIo-preload до анлока — ни
     *      одного вызова SimpleFileSystem во всей программе)
     *   2) мимо -> возврат из приложения: BDS продолжит boot-order и
     *      сам стартует следующий пункт БЕЗ POST, анлок сохраняется.
     *      SFS-ступени больше НЕТ: OpenVolume из загруженного приложения
     *      наглухо вешает целые семейства прошивок (X570/X99-E WS AMI,
     *      X299 — лог #25 обрывается на первом же SFS-пробе). */

    if (!g_bmBuf || !g_bmSize || !g_bmDp)
        Print(L"chainload-pre: preload empty\n");
    else {
        Print(L"chainload-pre: LoadImage %s from RAM (%d bytes)...\n",
              g_bmPath, g_bmSize);
        st = uefi_call_wrapper(BS->LoadImage, 6, FALSE, ImageHandle,
                               g_bmDp, g_bmBuf, g_bmSize, &h);
        if (EFI_ERROR(st)) {
            Print(L"chainload-pre: LoadImage: %r\n", st);
        } else {
            Print(L"chainload-pre: StartImage %s...\n", g_bmPath);
            st = uefi_call_wrapper(BS->StartImage, 3, h, NULL, NULL);
            Print(L"chainload-pre: StartImage returned: %r\n", st);
            if (!EFI_ERROR(st))
                return EFI_SUCCESS;
        }
    }

    /* последняя ступень: возврат в прошивку. НИКАКОГО ResetSystem и
     * НИКАКОГО BootNext (NVRAM-записи на этой плате вешают систему). */
    Print(L"chainload-pre: returning to firmware (no POST)\n");
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
 * v55: 上面这份 90HX 全flow被 #if U40X_LEGACY_FULL 收编（默认close）。
 * 40HX/TU106 实机主线改用file末尾重写的 efi_main（DIRECT_SEC2：
 * 黑盒版同款enum/BAR + skip GSP-BL/FWSEC/磁盘预载/诊断扫描，直连
 * SEC2 booter，几何按 TU102 bindata 修正）。见filetail。 */

/* =====================================================================
 * v55：40HX (TU106, 10de:1f0b) DIRECT-SEC2 主线（重写，2026-09-03）
 * ---------------------------------------------------------------------
 * 为什么黑盒hybrid版（CMP50HX-WindowsUnlock-v0.2.1，main.c+core）在这block
 * 主板上能一路跑完enum/BAR/SBR/booter execute器，而本source码版此前不行：
 *   1) configspaceaddressencode不同 —— hybrid版 rb->Pci.Read 用
 *      EFI_PCI_ADDRESS = bus<<24|dev<<16|fn<<8|reg（本主板firmware接受）；
 *      unlock_v2 移植版沿用 GA102 工程的 bus<<20|dev<<15|fn<<12|reg，
 *      在这block主板上读到的根本不是同一device（find/BAR 全乱）。
 *   2) BAR0 未先 command|=MEMORY|BUS_MASTER 就 MMIO 直读 → register全 0。
 *   3) 移植版主flow混入大量 90HX 专属阶segment（NVRAM fire 决策、bootmgfw
 *      磁盘预载、probe/sweep/DIAG 全扫、GSP-BL+FWSEC(GA102) 前置），
 *      在本板上要么挂死要么execute语义不对的 GA102 firmware。
 *   4) booter 几何：原移植把 GA102 的 imem 0x8900@+0x100 / data
 *      0x8A00/0x6200 / ucodeId=3 / hsSig=0x10 套在 TU102(nv616) 的
 *      0xE700 blob 上（data 读到file尾外）。真实值见 BOOTER_* macro。
 *
 * 本主线 = 黑盒hybrid版（找卡/BAR/读 BOOT0）+ DIRECT_SEC2（不跑 GSP
 * BL/FWSEC/磁盘预载，直接 SEC2 booter 注入），几何用 TU102 真值。
 * compile：见 tools/unlock40x/build40x.sh（-DDIRECT_SEC2 -DRELEASE_BUILD
 * 不开 U40X_LEGACY_FULL、不开 EFI_FUNCTION_WRAPPER）。
 * ===================================================================== */

/* configspaceaddress：UEFI specificationlayout（=hybrid版 uefi_min.h 的 EFI_PCI_ADDRESS） */
#define U40X_CFG_ADDR(bus, dev, fn, reg) \
    ((((UINT64)(UINTN)(bus)) << 24) | (((UINT64)(UINTN)(dev)) << 16) | \
     (((UINT64)(UINTN)(fn)) << 8) | ((UINT64)(reg)))
/* 紧凑layout（unlock_v2/GA102 工程用；仅找卡第二遍兜底） */
#define U40X_CFG_ADDR_COMPACT(bus, dev, fn, reg) \
    ((((UINT64)(UINTN)(bus)) << 20) | (((UINT64)(UINTN)(dev)) << 15) | \
     (((UINT64)(UINTN)(fn)) << 12) | ((UINT64)(reg)))

static UINT32 u40x_pci_rbdf(UINTN bus, UINTN dev, UINTN fn, UINTN off, INTN enc)
{
    UINT32 v = 0xFFFFFFFFu;
    UINT64 A;
    if (enc == 2) {              /* CF8/CFC 直读兜底（与 WinRing0 同path） */
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
    /* 直调 rb->Pci（黑盒verify：本主板firmware只吃直调 + specificationaddress） */
    if (EFI_ERROR(gRb->Pci.Read(gRb, EfiPciIoWidthUint32, A, 1, &v)))
        v = 0xFFFFFFFFu;
    return v;
}

static void u40x_pci_wbdf(UINTN bus, UINTN dev, UINTN fn, UINTN off,
                          UINT32 val, INTN enc)
{
    UINT64 A;
    if (enc == 2) {              /* CF8/CFC 直写兜底（与 WinRing0 同path） */
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

/* 找到卡时用的addressencode（0=specification bus<<24，1=紧凑 bus<<20）——BAR/command
 * 的后续config读必须沿用同一encode，否则在非specificationfirmware上会读错device。 */
static INTN u40x_enc_found = 0;

/* issue #24: on AGESA / Ryzen APU boards the spec/compact RootBridgeIo
 * paths corrupt the stack (AGESA bug on unmodelled Type-0 devices —
 * typically the APU iGPU).
 * Detect via CF8 only — the detection itself must not use the
 * unsafe RootBridgeIo path.
 *
 * v1.1.1 only scanned bus 0 and missed hosts where AGESA puts the
 * iGPU elsewhere. v1.1.2 widened to bus 0..255 — still misses hosts
 * where AGESA hides the iGPU from CF8 enumeration entirely (user on
 * issue #24: iGPU at 0xB per Windows, but CF8 reads at bus 0xB return
 * 0xFFFFFFFF, same way enc=0/1 couldn't see the cmp50). v1.1.3
 * switches the primary check to CPUID — the only path that doesn't
 * go through AGESA — and keeps CF8 as a fallback for exotic topologies.
 *
 * Trade-off: every AMD CPU triggers the APU path, including Threadripper
 * / EPYC (which have no iGPU). The cost is small — we only skip the
 * per-bridge RootBridgeIo fallback (CF8 stays the primary find path) —
 * and the upside (no hangs on real Ryzen APU hosts) is much larger. */
static BOOLEAN g_ryzenApu = FALSE;

static BOOLEAN u40x_is_ryzen_apu(void)
{
    UINT32 eax, ebx, ecx, edx;

    /* Primary: CPUID leaf 0 returns a 12-char vendor string in
     * EBX, EDX, ECX. "AuthenticAMD" = 0x68747541 0x69746E65 0x444D4163.
     * Modern Ryzen desktop CPUs all have iGPU, so AMD ≈ APU here. */
    __asm__ __volatile__("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0));
    if (ebx == 0x68747541u && edx == 0x69746E65u && ecx == 0x444D4163u)
        return TRUE;

    /* Non-AMD CPU. CF8 fallback for exotic topologies where an
     * AMD iGPU sits on an Intel host (rare, but free to check). */
    {
        UINTN bus, d, f;
        for (bus = 0; bus < 256; bus++) {
            for (d = 0; d < 32; d++) {
                for (f = 0; f < 8; f++) {
                    UINT32 id = u40x_pci_rbdf(bus, d, f, 0, 2);
                    UINT32 cc;
                    if (id == 0xFFFFFFFFu || (id & 0xFFFFu) == 0u)
                        continue;
                    if ((id & 0xFFFFu) != 0x1022u)
                        continue;
                    cc = u40x_pci_rbdf(bus, d, f, 0x08, 2);
                    if (((cc >> 24) & 0xFFu) == 0x03u)
                        return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/* 找卡：fast-probe（bus 2/1/3/0/4/5）+ 初扫 bus 0..16（AGESA 实测把
 * PEG 槽编到 bus 0x10、核显到 0x30，0..16 含该极端值）；enc=2(CF8) 全
 * 0..255 兜底。先specificationaddress(enc=0)再紧凑address(enc=1)再 CF8(enc=2)。 */
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
                continue;                       /* 空槽先skip，不再多读 hdr */
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

    g_ryzenApu = u40x_is_ryzen_apu();
    if (g_ryzenApu)
        Print(L"[50HX f] Ryzen APU detected (AMD iGPU on bus 0) — "
              L"skipping enc=0,1 (AGESA RootBridgeIo unsafe)\n");

    st = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
            &gEfiPciRootBridgeIoProtocolGuid, NULL, &N, &H);
    if (EFI_ERROR(st)) {
        Print(L"[50HX f] RB LocateHandleBuffer: %r\n", st);
        N = 0;      /* 拿不到 RB handle也continue走 CF8 直读兜底 */
        H = NULL;
    } else {
        Print(L"[50HX f] %d root bridge(s)\n", (INTN)N);
    }

    /* issue #25: try CF8 (enc=2) FIRST. enc=2 uses raw CPU CF8/CFC port I/O,
     * never goes through RootBridgeIo->Pci.Read, and covers bus 0..255
     * globally — so it doesn't depend on a working per-bridge enumeration.
     * On Intel X99 / X299 firmware the RootBridgeIo Pci.Read path can hang
     * mid-scan (user-reported: hang right after "[50HX f] N root bridge(s)"
     * with no further log lines), which corrupts the unlock. By trying
     * enc=2 first, on systems where CF8 sees the dGPU (the common case —
     * the existing comment at u40x_find_gpu_pass explicitly notes "X79
     * boards need the CF8 path") we never touch RootBridgeIo and never
     * hit that hang. enc=0/1 stays as a fallback for the rare firmware
     * where CF8 can't reach the card but a working RootBridgeIo can.
     * On AGESA / AMD Ryzen APU hosts (g_ryzenApu == TRUE) RootBridgeIo
     * is also unsafe (issue #24 stack corruption), so the fallback
     * is skipped in that case too. */
    if (u40x_find_gpu_pass(2)) {
        if (H)
            uefi_call_wrapper(BS->FreePool, 1, H);
        return 1;
    }

    if (g_ryzenApu) {
        if (H)
            uefi_call_wrapper(BS->FreePool, 1, H);
        Print(L"[50HX f] CF8 didn't find the card on Ryzen APU host; "
              L"RootBridgeIo is unsafe, aborting\n");
        return 0;
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
    /* 全failed：CF8 只读扫一遍，把可见devicemapping写进 50hx_log.txt（≤96 条），
     * 下次定bit“卡到底在不在 PCI 上 / 在哪个 BDF”一目了然。 */
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

/* BAR0 decode + command|=MEMORY|BUS_MASTER（黑盒 prepare_pci_resources 简化版） */
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
    /* v63: ELF size 必须 = log53 真解（Linux 40HX succeeded dmesg）：
     * "40HX GSP_FW: fwOffset=0x1fe200000 size=0x1bfadc8 ..."
     * = linux/firmware/gsp_tu10x.bin .fwimage 尺寸 = 28.9MB 真 GSP-RM。
     * gspFwOffset = bootBinOffset - elfSize → ELF size 决定整条 WPR layout；
     * 旧值 0x5053000(80MB dummy) 让 gspFwOffset/heap 全错bit → booter
     * verify meta layoutfailed → exit 0x91（4166-4169 comment语义）。 */
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

/* radix-3 page表（root→L1→L2→data，v2.86 教训：booter 要page表非 raw ELF） */
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

/* ===== [11] best-effort ReBAR activation (BAR1, 16 or 32 GiB) =====
 * GPU-side port of the Linux 03-cmp50-rebar.patch: unlock the TU102 XVE
 * CYA and set the BAR1 size selector (8 = 16 GiB default; 9 = 32 GiB
 * via the rebar=32g override, proven on 20/22 GB mods in issue #47).
 * We run AFTER firmware
 * enumeration, so the enlarged BAR1 sticks only when the upstream bridge's
 * prefetchable window already covers a 16 GiB-aligned span — on other
 * boards every write is reverted and the boot continues stock
 * ("activated — lucky; failed — exactly as it was"). The kernel-side
 * pci_resize_resource equivalent is done directly: spec sizing probe via
 * CF8 (no ECAM dependency — works on CF8-only hosts) + base reassignment
 * inside the existing window. */
#define XVE_CYA_OFF      0x88724UL   /* CYA unlock (write 0x30 to unlock) */
#define XVE_CAP_OFF      0x88bbcUL   /* size mask (0x400 stock -> 0x7fc00) */
#define XVE_CFG_OFF      0x88dccUL   /* size selector (0 stock -> 8) */
#define XVE_CFG_SEL_MASK 0x0000000FU
#define XVE_CFG_ENABLE   0x80000000U

/* Config access MUST reuse the GPU's discovery encode: cfg_read/write32 go
 * through gRb with one fixed layout and return zeros on CF8-found (enc=2)
 * hosts — the issue #47 log showed cmd=0x0 / BAR1=0x0 on a live card. */
static UINT32 rebar_rd(UINTN reg)
{
    return u40x_pci_rbdf(gBus, gDev, gFn, reg, u40x_enc_found);
}

static VOID rebar_wr(UINTN reg, UINT32 v)
{
    u40x_pci_wbdf(gBus, gDev, gFn, reg, v, u40x_enc_found);
}

static VOID
u40x_rebar_revert(UINT32 cfg, UINT32 cya, UINT32 cmd, UINT32 b1lo, UINT32 b1hi)
{
    rebar_wr(0x14, b1lo);
    rebar_wr(0x18, b1hi);
    rebar_wr(0x04, cmd);             /* decode back on first... */
    mmio_write32(XVE_CFG_OFF, cfg);  /* ...then XVE via BAR0 MMIO */
    mmio_write32(XVE_CYA_OFF, cya);
    (void)mmio_read32(XVE_CYA_OFF);
}

/* rebar=32g override (issue #47: selector 9 proven on 20/22 GB mods).
 * Same two channels as fb=20g: the "rebar=32g" LoadOptions token
 * (efibootmgr -u / GRUB) or the 50HXRB="32G" UEFI variable (Windows).
 * Default stays the proven selector 8 (16 GiB). */
static BOOLEAN
u40x_rebar32(EFI_HANDLE IH)
{
    static EFI_GUID gvGuid = EFI_GLOBAL_VARIABLE;
    UINTN sz = 8;
    CHAR16 buf[4] = {0, 0, 0, 0};
    UINT32 attr = 0;
    EFI_STATUS st;

    if (IH && u40x_has_load_option(IH, L"rebar=32g"))
        return TRUE;
    st = uefi_call_wrapper(RT->GetVariable, 5, L"50HXRB", &gvGuid,
                           &attr, &sz, buf);
    return !EFI_ERROR(st) && sz >= 6 &&
           buf[0] == L'3' && buf[1] == L'2' && buf[2] == L'G';
}

static VOID
u40x_rebar_try(UINT64 want, UINT32 selector)
{
    UINT32 cya, cfg, cap, cmd, b1lo, b1hi, rlo, rhi, dw;
    UINT64 b1base, wbase, wlim, cand;
    UINTN bb = 0, bd = 0, bf = 0;

    cya    = mmio_read32(XVE_CYA_OFF);
    cfg    = mmio_read32(XVE_CFG_OFF);
    cap    = mmio_read32(XVE_CAP_OFF);
    cmd    = rebar_rd(0x04);
    b1lo   = rebar_rd(0x14);
    b1hi   = rebar_rd(0x18);
    b1base = (UINT64)(b1lo & 0xFFFFFFF0U) | ((UINT64)b1hi << 32);
    Print(L"[rebar] XVE cya=0x%08x cfg=0x%08x cap=0x%08x\n", cya, cfg, cap);
    Print(L"[rebar] BAR1 base=0x%llx flags=0x%x cmd=0x%08x\n",
          b1base, b1lo & 0xFU, cmd);

    if ((b1lo & 0xFU) != 0xCU) {
        Print(L"[rebar] BAR1 is not 64-bit prefetchable — skip\n");
        return;
    }
    if (!find_bridge_to(gBus, &bb, &bd, &bf)) {
        Print(L"[rebar] upstream bridge not found — skip\n");
        return;
    }
    /* prefetchable window of the upstream bridge (type-1 regs 0x24..0x2C) */
    dw    = pci_cfg_rd_idx(gBrIdx, bb, bd, bf, 0x24);
    wbase = (UINT64)(((dw >> 4) & 0xFFFU) << 20) |
            ((UINT64)pci_cfg_rd_idx(gBrIdx, bb, bd, bf, 0x28) << 32);
    wlim  = (UINT64)(((dw >> 20) & 0xFFFU) << 20) |
            ((UINT64)pci_cfg_rd_idx(gBrIdx, bb, bd, bf, 0x2C) << 32) |
            0xFFFFFULL;
    Print(L"[rebar] bridge %02x:%02x.%x pref window 0x%llx..0x%llx\n",
          (UINT32)bb, (UINT32)bd, (UINT32)bf, wbase, wlim);
    if (((dw >> 4) & 0xFFFU) == 0 && ((dw >> 20) & 0xFFFU) == 0) {
        Print(L"[rebar] prefetch window disabled — skip\n");
        return;
    }

    /* keep the current base when it is already size-aligned and fits;
     * otherwise relocate to the lowest aligned span in the window
     * (the prefetchable window hosts only the GPU BAR1 on these hosts) */
    if ((b1base & (want - 1)) == 0 && b1base + want - 1 <= wlim) {
        cand = b1base;
    } else {
        cand = (wbase + want - 1) & ~(want - 1);
        if (cand + want - 1 > wlim) {
            Print(L"[rebar] no %d GiB-aligned span in window — skip\n",
                  (INT32)(want >> 30));
            return;
        }
        Print(L"[rebar] relocating BAR1 0x%llx -> 0x%llx\n", b1base, cand);
    }

    /* activate: CYA unlock + size selector, verified by readback */
    mmio_write32(XVE_CYA_OFF, 0x30U);
    mmio_write32(XVE_CFG_OFF, (cfg & ~XVE_CFG_SEL_MASK) | XVE_CFG_ENABLE | selector);
    if ((mmio_read32(XVE_CFG_OFF) & (XVE_CFG_ENABLE | XVE_CFG_SEL_MASK))
        != (XVE_CFG_ENABLE | selector)) {
        Print(L"[rebar] XVE readback failed (cfg now 0x%08x) — revert\n",
              mmio_read32(XVE_CFG_OFF));
        u40x_rebar_revert(cfg, cya, cmd, b1lo, b1hi);
        return;
    }

    /* resize + reassign BAR1 with decode off (spec sizing sequence) */
    rebar_wr(0x04, cmd & ~0x2U);
    rebar_wr(0x14, 0xFFFFFFFFU);
    rebar_wr(0x18, 0xFFFFFFFFU);
    rlo = rebar_rd(0x14);
    rhi = rebar_rd(0x18);
    if (rlo != 0xFFFFFFFCU || rhi != (UINT32)((want - 1) >> 32)) {
        Print(L"[rebar] size probe 0x%08x/0x%08x (want FFFFFFFC/%08x)"
              L" — revert\n", rlo, rhi, (UINT32)((want - 1) >> 32));
        u40x_rebar_revert(cfg, cya, cmd, b1lo, b1hi);
        return;
    }
    rebar_wr(0x14, (UINT32)cand | 0xCU);
    rebar_wr(0x18, (UINT32)(cand >> 32));
    rebar_wr(0x04, cmd);                 /* original cmd = decode on */

    /* verify the assignment and that VRAM really answers through it */
    {
        UINT32 vlo = rebar_rd(0x14), vhi = rebar_rd(0x18);
        volatile UINT32 *p0 = (volatile UINT32 *)(UINTN)cand;
        volatile UINT32 *p1 = (volatile UINT32 *)(UINTN)(cand + want / 2);
        UINT32 v0 = *p0, v1 = *p1;
        if ((((UINT64)(vlo & 0xFFFFFFF0U)) | ((UINT64)vhi << 32)) != cand ||
            (v0 == 0xFFFFFFFFU && v1 == 0xFFFFFFFFU)) {
            Print(L"[rebar] aperture verify failed (base %08x_%08x, "
                  L"v0=0x%08x v1=0x%08x) — revert\n", vhi, vlo, v0, v1);
            u40x_rebar_revert(cfg, cya, cmd, b1lo, b1hi);
            return;
        }
        Print(L"[rebar] aperture ok: [+0]=0x%08x [+mid]=0x%08x\n", v0, v1);
    }
    Print(L"[rebar] BAR1 %d GiB active @ 0x%llx (was 0x%llx) — lucky!\n",
          (INT32)(want >> 30), cand, b1base);
}

/* ===== v55 主entry（DIRECT_SEC2，40HX） ===== */
EFI_STATUS EFIAPI
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status = EFI_SUCCESS;
    BOOLEAN returnToGrub;
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
    /* issue #36: capture our loaded binary size for the chainload
     * self-detection fallback. The Windows installer deploys our
     * binary to two paths (\EFI\50HX\50HXUNLK.EFI + \EFI\Boot\bootx64.efi);
     * a path-only "is this me" check misses the second copy and lets
     * the chainload load it (which restarts the EFI = loop). */
    {
        EFI_LOADED_IMAGE *li0 = NULL;
        if (!uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle,
                &LoadedImageProtocol, (VOID**)&li0) && li0)
            g_ourImageSize = (UINTN)li0->ImageSize;
    }
    u40x_open_log(ImageHandle);
    Print(L"\n=== CMP50HX Unlock v1-50HX (TU102 GSP WITH_LOADER) ===\n");
    returnToGrub = u40x_has_load_option(ImageHandle, L"--return-to-grub");
    if (returnToGrub)
        Print(L"[50HX] GRUB handoff mode: internal chainload disabled\n");
    else
        /* Read the OS loader into RAM BEFORE the unlock: the SFS fallback in
         * chainload_preloaded() hangs on some AMI firmwares, so this is the
         * path that must succeed. The call was lost when the 90HX branch was
         * dropped (fffb5b9), which left every boot on the hangy fallback. */
        preload_os_loader(ImageHandle);

    /* ---------- [1] 找卡（黑盒 fast-probe + 有界） ---------- */
    if (!u40x_find_gpu()) {
        Print(L"[50HX] GPU not found; abort\n");
        return returnToGrub ? EFI_SUCCESS : EFI_NOT_FOUND;
    }

    /* ---------- [2] BAR0 enable ---------- */
    if (u40x_enable_bar()) {
        Print(L"[50HX] BAR enable failed; abort\n");
        return returnToGrub ? EFI_SUCCESS : EFI_DEVICE_ERROR;
    }
    /* Detect the card SKU from the WPR2 the VBIOS POST latched (10 GiB vs 20 GiB).
     * Must happen before any code path that consumes g_fbSize / g_frtsOffset
     * (build_wpr_meta below, fwsec_boot_gsp_50hx in step [8b]). Cold POST with
     * no VBIOS FWSEC keeps the 10 GiB defaults — same fallback as before. */
    detect_fb_size(ImageHandle);
#ifdef VBIOS_DUMP
    u40x_vbios_dump();          /* v65: after BAR enable; -> \50hx_vbios.bin */
#endif

    /* ---------- [3] BOOT0 芯片verify ---------- */
    boot0 = mmio_read32(0x00000000UL);
    Print(L"[50HX] BOOT0=0x%08x (expect arch 0x16<<24 = TU10x)\n", boot0);
    if ((boot0 & 0xFF000000u) != 0x16000000u && boot0 != 0x0FFFFFFFu) {
        Print(L"[50HX] BOOT0 unexpected — continue anyway (readback may be "
              L"gated); dumping key regs\n");
    }
    dump_regs(L"[v55 boot]");

    /* ---------- [4] 快捷path：unlock / 直写可粘 ---------- */
    if (is_unlocked()) {
        Print(L"[50HX] already unlocked (SS0/SS1 exact) — skip injection\n");
        goto done;
    }
    if (direct_write_probe()) {
        Print(L"[50HX] direct MMIO probe succeeded — skip booter\n");
        goto done;
    }

    /* ---------- [5] GFW status + timeseed ---------- */
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

    /* ---------- [6] 载荷/ucode/BL allocate（>4G 高槽，与 unlock_v2 同policy） ---------- */
    Status = alloc_fwsec_buffer((V67_SIZE + 0xFFFu) >> 12, &v67Phys);
    if (EFI_ERROR(Status)) { Print(L"[50HX] alloc v67: %r\n", Status); goto done; }
    CopyMem((VOID *)(UINTN)v67Phys, v67_payload_bin, V67_SIZE);
    /* v61: **不再 low-copy 到 <4GB**。869 行comment（v2.63 实测，lock卡 40HX）：
     * "booter 从 sysmem 读 WPR meta/V67——<4GB read被lock (exit 0x91)"。
     * driver TU102 (kgspExecuteBooterLoad_TU102) 用 mailbox0/1 = LO32/HI32
     * 传 64 bitphysicaladdress，meta 本体在 >4GB (driver 0x110BB0000)。v55 引入的
     * "signaturebuffer <4G（booter 32 bit读）" 是 90HX 老假设，在 TU102 上反了。
     * v60 实机 mbox0=0x91 可复现 → v67/meta 都在 <4GB，booter 读被lock。 */
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
    Print(L"[50HX] build_wpr_meta (fbSize=0x%llx)\n", g_fbSize);
    build_wpr_meta(wprMeta, radixPhys, radixSize, v67Phys,
                   g_fbSize, blPhys, GSP_RM_BOOT_SIZE);
    __asm__ volatile("wbinvd" ::: "memory");
    Print(L"[50HX] meta@0x%lx radix@0x%lx ucode@0x%lx v67@0x%lx fb=0x%lx\n",
          wprMetaPhys, radixPhys, ucodePhys, v67Phys, wprMeta->fbSize);

    /* ---------- [7.5] v69: 预载探测（必须在任何 engine reset 之前） ----------
     * log53: FWSEC_COMPLETE_GSP_UNTOUCHED — Linux succeededpath里 FWSEC 由
     * POST/VBIOS 预载在 GSP secure IMEM，driver只trigger不重装。若 40HX 同样
     * 预载，则 [8b] 的 code load纯属多余（且 SEC 写不入的原因=hardwarelock
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

    /* ---------- [8] kill GFW + SEC2 unlock检查 ---------- */
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
            (mmio_read32(REG_PFB_MMU_WPR2_LO) == g_wpr2LoUp &&
             mmio_read32(REG_PFB_MMU_WPR2_HI) == g_wpr2HiUp);
        if (wpr2UpNow) {
            Print(L"[50HX fwsec50] WPR2 up after GFW kill — skip FWSEC\n");
        } else {
        if (g_Wpr2LoPreKill == g_wpr2LoUp)
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
    /* driverload前把 SIG_PROD(16B AES) write image[PATCH_LOC=0x8700]
     * (= DMEM[hsSigDmemAddr=0x200])——BROM verify signature就从这个 DMEM bit读signature；
     * 不写则 booter 走verify signature直接failed。byte取自decompress bindata
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
        /* v56 fallback：GA102 风格 DMA path（v55 用的那套），结果对比用 */
        Print(L"[50HX] fallback: booter_load_v67 (DMA path, GA102-style)...\n");
        Status = booter_load_v67(wprMetaPhys, ucodePhys);
        Print(L"[50HX] booter_load_v67 returned %r\n", Status);
    }
    sec2_health(L"v55-post-booter");
    uefi_call_wrapper(BS->Stall, 1, 500000);
    dump_regs(L"[v55 post-booter]");

    /* ---------- [10] 判定 + cleanup ---------- */
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
     * unlock后 SEC2 回冷态：engine reset + MB 清——verify黑屏=非冷态，sanitize 解） */
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
    /* 停掉可能的 SEC2 ROP 自旋（写读回；如死无害） */
    mmio_write32(SEC2_ENGINE, 0x1);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);
    mmio_write32(SEC2_ENGINE, 0x0);
    for (i = 0; i < 16; i++) mmio_read32(SEC2_ENGINE);

    /* ---------- [10.5] PCIe Gen2 - OS-side only (removed in v1.1.8,
     * re-tested and re-confirmed dead 2026-09-17) -----------------------
     * The pre-OS Gen2 attempt never trained on any host (X79: LNKCTL2
     * reads back read-only; AGESA: the retrain relinks the root port
     * that also serves the iGPU), and on Intel X99/X299 boards the
     * retrain pulse hung the boot entirely. A 2026-09-17 opt-in retry
     * (policy + LTSSM + TLS, no retrain pulse) proved the deeper wall:
     * the XP3G privilege gate (BAR0 0x8e1b0) reads 0xffffff8f (closed)
     * at the pre-OS stage and refuses writes there - it is opened by
     * GSP-RM in the OS only. Gen2 needs: BIOS PCIe slot link speed =
     * Gen2 (not Auto/Gen1; makes PL_LINK_RATE come up 0x00240032),
     * kernel patch 04 + cmp50hx-gen2.service / the Windows logon task. */
    Print(L"[gen2] not attempted pre-OS - OS-side Gen2 only (issue #25)\n");

done:
    dump_regs(L"[v55 final]");
    /* ---------- [11] best-effort ReBAR (BAR1); reverts on any failed
     * check — see u40x_rebar_try ---------- */
    if (u40x_rebar32(ImageHandle)) {
        Print(L"[rebar] rebar=32g: attempting 32 GiB BAR1 (issue #47)\n");
        u40x_rebar_try(0x800000000ULL, 9U);
    } else {
        u40x_rebar_try(0x400000000ULL, 8U);
    }
    /* v71fix: 黑屏很久+driver掉根因 = return firmware → BDS 重跑 POST →
     * GPU 重新initialize/unlock 丢失。改用黑盒式链载（chainload_preloaded：
     * preload loader → LoadImage → StartImage，мимо — возврат в BDS），
     * 不回firmware、无第二 POST，SS0 保持、driver正常。 */
    if (returnToGrub) {
        Print(L"[50HX] returning to GRUB; it may now start the OS loader\n");
    } else {
        EFI_STATUS cst = chainload_preloaded(ImageHandle);
        Print(L"[50HX] chainload result: %r\n", cst);
        if (EFI_ERROR(cst)) {
            Print(L"[50HX] chainload failed - last resort return firmware\n");
        }
    }
    uefi_call_wrapper(BS->Stall, 1, 2000000);
    return EFI_SUCCESS;
}
