#!/bin/bash
# build.sh — CMP 50HX (TU102) EFI unlock build (Linux host, gnu-efi)
#
# Prerequisites (Ubuntu):
#   sudo apt install build-essential gnu-efi
#
# Output: 50HXUNLK.EFI — deploy to the ESP as \EFI\50HX\50HXUNLK.EFI and put
# a "50HX Unlock" boot entry first in BootOrder (see README.md).
set -e
cd "$(dirname "$0")"

EFI_INC="${EFI_INC:-/usr/include/efi}"
EFI_LIB="${EFI_LIB:-/usr/lib}"

if [ ! -d "$EFI_INC" ]; then
    echo "gnu-efi headers not found at $EFI_INC (sudo apt install gnu-efi)" >&2
    exit 1
fi

SRC=unlock50x_v1.c
OBJ=unlock50x_v1.o
OUT=unlock50x_v1.so
EFIOUT=50HXUNLK.EFI

echo "=== 1. compile $SRC ==="
gcc -c -O2 -fno-stack-protector -fpic -ffreestanding \
    -fno-asynchronous-unwind-tables -fno-unwind-tables \
    -fshort-wchar -mno-red-zone -maccumulate-outgoing-args \
    -fno-builtin -fno-strict-aliasing -Wno-unused-function \
    -I "$EFI_INC" -I "$EFI_INC/x86_64" \
    -DDIRECT_SEC2 -DRELEASE_BUILD -DVBIOS_DUMP \
    -o "$OBJ" "$SRC"

echo "=== 2. embed blobs ==="
# Debian/Ubuntu gnu-efi archives hold ELF objects, so the whole link is ELF
# (crt0 + elf_x86_64_efi.lds) and the blob objects must be ELF too.
embed() {
  local f="$1" tgt="$2"
  local base="${f//./_}"
  # objcopy derives the symbol name from the FILENAME AS GIVEN, so run it
  # from blobs/ with a bare name; otherwise the symbols carry a "blobs_"
  # prefix, the redefines below become no-ops, and the C externs resolve
  # to zero at runtime (the live 2026-09-10 failure: all payloads were
  # copied from address 0 and every falcon ran zero-filled code).
  ( cd blobs && objcopy --input-target binary --output-target elf64-x86-64 \
      --binary-architecture i386:x86-64 \
      --redefine-sym "_binary_${base}_start=${tgt}" \
      --redefine-sym "_binary_${base}_end=${tgt}_end" \
      --redefine-sym "_binary_${base}_size=${tgt}_size" \
      "$f" "../${tgt}.o" )
  if ! nm "${tgt}.o" | grep -qE "^[0-9a-f]+ [A-Za-z] ${tgt}$"; then
    echo "  EMBED FAILED for $f (symbol ${tgt} not defined)" >&2
    exit 1
  fi
  echo "  embedded $f -> ${tgt}"
}
embed v67_payload.bin         v67_payload_bin
embed booter_ucode_dbg.bin    booter_ucode_dbg
embed booter_ucode_prod.bin   booter_ucode_prod
embed gsp_rm_boot_dbg.bin     gsp_rm_boot_dbg
embed fwsec_ga102.bin         fwsec_ga102_bin
embed fwsec_ga102_sig.bin     fwsec_ga102_sig
embed fwsec_50hx_prod.bin     fwsec_50hx_prod_bin
embed fwsec_50hx_dbg.bin      fwsec_50hx_dbg_bin
embed sec2_ucode_vbios_49.bin sec2_ucode_vbios_49
embed sec2_ucode_vbios_89.bin sec2_ucode_vbios_89
embed bl_gsp_tu102.bin        gsp_bl_tu102

OBJS="$OBJ v67_payload_bin.o booter_ucode_dbg.o booter_ucode_prod.o \
gsp_rm_boot_dbg.o fwsec_ga102_bin.o fwsec_ga102_sig.o \
fwsec_50hx_prod_bin.o fwsec_50hx_dbg_bin.o \
sec2_ucode_vbios_49.o sec2_ucode_vbios_89.o gsp_bl_tu102.o"

echo "=== 3. link ==="
ld -nostdlib -znocombreloc -T "$EFI_LIB/elf_x86_64_efi.lds" -shared -Bsymbolic \
    "$EFI_LIB/crt0-efi-x86_64.o" $OBJS \
    -L"$EFI_LIB" -lgnuefi -lefi -o "$OUT" 2>&1 | tail -12

if [ ! -f "$OUT" ]; then
    echo "link failed" >&2
    exit 1
fi

echo "=== 4. convert ==="
objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
    -j .reloc -j .rel -j .rela -j .rel.* -j .rela.* \
    --target=efi-app-x86_64 "$OUT" "$EFIOUT" 2>&1 | tail -4 || true
ls -la "$EFIOUT" && sha256sum "$EFIOUT" && echo BUILD_OK
