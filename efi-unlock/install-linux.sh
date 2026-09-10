#!/usr/bin/env bash
# install-linux.sh — one-click ESP deployment of the 50HX UEFI unlock.
#
# Runs from the unpacked release payload (50HXUNLK.EFI beside this file).
# Root required. Steps (see efi-unlock/README.md for the full guide):
#   1. verify the card is present (10de:1e09, warning-only)
#   2. mount the ESP if needed
#   3. copy 50HXUNLK.EFI to \EFI\50HX\
#   4. create the "50HX Unlock" boot entry (idempotent), first in BootOrder
#   5. set BootNext so the very next boot runs the unlock once (safe test)
#
# Rollback: bash install-linux.sh --remove
set -euo pipefail

EFI_NAME="50HXUNLK.EFI"
EFI_DIR="EFI/50HX"
ENTRY_LABEL="50HX Unlock"
ESP_MNT=""
MOUNTED_BY_US=0

say() { printf '[50hx] %s\n' "$*"; }
die() { printf '[50hx] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)"

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EFI_FILE="$SELF_DIR/$EFI_NAME"
[[ -f "$EFI_FILE" ]] || die "$EFI_NAME not found next to this script"

for cmd in efibootmgr mountpoint findmnt; do
    command -v "$cmd" >/dev/null || die "missing command: $cmd (apt install efibootmgr util-linux)"
done

cleanup() {
    [[ $MOUNTED_BY_US -eq 1 && -n "$ESP_MNT" ]] && umount "$ESP_MNT" 2>/dev/null || true
}
trap cleanup EXIT

# --- 1. card check (informational) -----------------------------------
if lspci -n -d 10de:1e09: >/dev/null 2>&1 && [[ -n "$(lspci -n -d 10de:1e09: 2>/dev/null)" ]]; then
    say "card found: $(lspci -n -d 10de:1e09: | head -1)"
else
    say "WARNING: no 10de:1e09 visible — the EFI will scan for it at boot"
    say "(installing anyway; the unlock only runs when the card is present)"
fi

# --- 2. locate the ESP -------------------------------------------------
find_esp() {
    local d
    for d in /boot/efi /boot /efi; do
        if mountpoint -q "$d" 2>/dev/null; then
            findmnt -n -o FSTYPE "$d" | grep -qi vfat && { echo "$d"; return 0; }
        fi
    done
    # any mounted vfat with an EFI dir
    findmnt -rn -t vfat -o TARGET | while read -r d; do
        [[ -d "$d/EFI" ]] && { echo "$d"; return 0; }
    done
    return 1
}

remove_entry() {
    local id
    for id in $(efibootmgr | grep -E "^Boot[0-9A-F]{4}\*? $ENTRY_LABEL" | sed -E 's/^Boot([0-9A-F]{4}).*/\1/'); do
        say "removing boot entry Boot$id ($ENTRY_LABEL)"
        efibootmgr -q -B -b "$id" || true
    done
    if [[ -n "$ESP_MNT" && -d "$ESP_MNT/$EFI_DIR" ]]; then
        rm -rf "$ESP_MNT/$EFI_DIR"
        say "removed $ESP_MNT/$EFI_DIR"
    fi
    say "rollback complete; reboot to return to stock behavior"
}

# --- removal mode ------------------------------------------------------
if [[ "${1:-}" == "--remove" ]]; then
    ESP_MNT="$(find_esp || true)"
    if [[ -z "$ESP_MNT" ]]; then
        die "ESP not mounted; mount it and retry"
    fi
    remove_entry
    exit 0
fi

ESP_MNT="$(find_esp || true)"
if [[ -z "$ESP_MNT" ]]; then
    # try to mount by GPT type code (c12a7328-f81f-11d2-ba4b-00a0c93ec93b)
    ESP_MNT="/tmp/50hx-esp"
    mkdir -p "$ESP_MNT"
    ESP_PART="$(lsblk -rno PATH,PARTTYPE | awk '$2=="c12a7328-f81f-11d2-ba4b-00a0c93ec93b"{print $1; exit}')"
    [[ -n "$ESP_PART" ]] || die "no mounted ESP and no GPT ESP partition found"
    mount -t vfat "$ESP_PART" "$ESP_MNT" || die "failed to mount $ESP_PART"
    MOUNTED_BY_US=1
    say "mounted $ESP_PART at $ESP_MNT"
else
    say "ESP found at $ESP_MNT"
fi

# --- 3. deploy ----------------------------------------------------------
mkdir -p "$ESP_MNT/$EFI_DIR"
cp -f "$EFI_FILE" "$ESP_MNT/$EFI_DIR/"
cmp -s "$EFI_FILE" "$ESP_MNT/$EFI_DIR/$EFI_NAME" || die "copy verification failed"
say "deployed $EFI_DIR/$EFI_NAME ($(stat -c%s "$EFI_FILE") bytes, verified)"

# --- 4. boot entry ------------------------------------------------------
ESP_PART="${ESP_PART:-$(findmnt -n -o SOURCE "$ESP_MNT")}"
ESP_DISK="/dev/$(lsblk -no PKNAME "$ESP_PART" | head -1)"
ESP_PARTNUM="$(lsblk -no PARTN "$ESP_PART" | head -1)"
[[ -b "$ESP_DISK" && -n "$ESP_PARTNUM" ]] || die "could not derive disk/partition from $ESP_PART"

remove_entry_quiet() {
    local id
    for id in $(efibootmgr | grep -E "^Boot[0-9A-F]{4}\*? $ENTRY_LABEL" | sed -E 's/^Boot([0-9A-F]{4}).*/\1/'); do
        efibootmgr -q -B -b "$id" || true
    done
}
remove_entry_quiet
NEWID="$(efibootmgr -c -d "$ESP_DISK" -p "$ESP_PARTNUM" \
    -L "$ENTRY_LABEL" -l "\$EFI_DIR\\$EFI_NAME" 2>/dev/null | \
    sed -nE 's/^Boot([0-9A-F]{4})\*? .*/\1/p' | head -1)"
[[ -n "$NEWID" ]] || die "efibootmgr failed to create the entry"

# order: unlock first, then everything else in current order
REST="$(efibootmgr | sed -nE 's/^BootOrder: //p' | tr ',' ' ' | tr ' ' '\n' | grep -v "^$NEWID$" | tr '\n' ',' | sed 's/,$//')"
efibootmgr -q -o "$NEWID,$REST"
say "boot entry Boot$NEWID '$ENTRY_LABEL' created and placed first in BootOrder"

# --- 5. one-shot BootNext for the next boot -----------------------------
efibootmgr -q -n "$NEWID"
say "BootNext=$NEWID: the NEXT boot runs the unlock once, then falls back"

say ""
say "Done. Reboot to activate. After reboot verify with:"
say "  sudo grep -a UNLOCKED /boot/efi/50hx_log.txt"
say "Every later boot unlocks automatically (entry is first in BootOrder)."
say "Rollback: sudo bash $0 --remove"
