#!/usr/bin/env bash
# Rebuild the initramfs with the patched CMP 50HX modules
# (Ubuntu/Debian). Card-neutral: the install puts the modules in
# /lib/modules/$(uname -r)/updates/.
# Run this AFTER install.sh and AFTER you confirmed the card works:
# the module must be verified good before it is made boot-persistent.
#
#   sudo install-initramfs.sh             backup + rebuild + verify
#   sudo install-initramfs.sh --rollback  restore the newest backup
set -Eeuo pipefail

krel="$(uname -r)"
image=''
for candidate in "/boot/initrd.img-${krel}" "/boot/initramfs.img-${krel}"; do
    [[ -e "${candidate}" ]] && image="${candidate}"
done

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line ${LINENO}"' ERR
[[ ${EUID} -eq 0 ]] || die "run as root (sudo)"

if [[ "${1:-}" == "--rollback" ]]; then
    [[ -n "${image}" ]] || die "no initramfs image found for kernel ${krel}"
    backup="$(ls -1t "${image}".cmp50-bak-* 2>/dev/null | head -n 1 || true)"
    [[ -n "${backup}" ]] || die "no backup found for ${image}"
    cp -a "${backup}" "${image}"
    log "restored ${image} from ${backup}"
    log "reboot to use the restored initramfs"
    exit 0
fi
[[ -z "${1:-}" ]] || die "unknown option: ${1} (only --rollback is supported)"

[[ -n "${image}" ]] || die "no initramfs image found for kernel ${krel}"
command -v update-initramfs >/dev/null || die "update-initramfs not found; only Ubuntu/Debian are supported"
ours="/lib/modules/${krel}/updates/nvidia.ko"
[[ -f "${ours}" ]] || die "patched module ${ours} not found; run install.sh first"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
backup="${image}.cmp50-bak-${ts}"
cp -a "${image}" "${backup}"
log "backup: ${backup}"
ls -1t "${image}".cmp50-bak-* 2>/dev/null | tail -n +4 | xargs -r rm -f --

log "rebuilding initramfs for ${krel}"
update-initramfs -u -k "${krel}"

# --- verify what actually went into the image -------------------------------
#
# Compare srcversion instead of raw bytes: signing (kmodsign) and
# module compression (zstd/xz/gz) both change the bytes but leave
# srcversion intact, and modinfo reads srcversion out of all three
# directly.

module_srcversion() {
    modinfo -F srcversion "$1" 2>/dev/null || echo ""
}

status="no nvidia module is inside the initramfs; the patched module loads from disk at boot"
if command -v unmkinitramfs >/dev/null 2>&1; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp}"' EXIT
    unmkinitramfs "${image}" "${tmp}"

    found=0
    bad=0
    while IFS= read -r -d '' mod; do
        found=1
        # canonical .ko name (strip any of the three module compressions)
        name="$(basename "${mod}")"
        for ext in zst xz gz; do
            [[ "${name}" == *.${ext} ]] && name="${name%.${ext}}"
        done
        installed="/lib/modules/${krel}/updates/${name}"
        [[ -f "${installed}" ]] || continue
        a="$(module_srcversion "${mod}")"
        b="$(module_srcversion "${installed}")"
        if [[ -n "${a}" && "${a}" == "${b}" ]]; then
            log "verified: ${name} in the initramfs matches the patched module"
        elif [[ -z "${a}" && -z "${b}" ]]; then
            log "WARNING: ${name} srcversion is empty on both sides; could not verify"
            bad=1
        else
            log "MISMATCH: ${name} in the initramfs is NOT the patched module (srcversion initramfs='${a}' updates='${b}')"
            bad=1
        fi
    done < <(find "${tmp}" -name 'nvidia*.ko*' -print0)
    if [[ ${found} -eq 0 ]]; then
        log "INFO: ${status}"
    elif [[ ${bad} -ne 0 ]]; then
        die "initramfs contains a wrong nvidia module; restore with: $0 --rollback"
    fi

    if find "${tmp}" -name 'nouveau.ko*' | grep -q . \
            && ! grep -rq 'nouveau' "${tmp}"/*/etc/modprobe.d 2>/dev/null; then
        log "WARNING: nouveau is in the initramfs without a blacklist; it may grab the card at early boot"
    fi
else
    log "WARNING: unmkinitramfs not found; could not verify the image content"
fi

cat <<EOF

PASS_CMP_INITRAMFS
Reboot now. After reboot, verify every card (indices per nvidia-smi -L):
  cmp50hx: for i in 0 1 2; do
             /opt/cmp50hx-unlock/artifacts/610.43.03-${krel}/rm-issue-rate \$i > /tmp/cmp50-probe-\$i.json
             python3 /opt/cmp50hx-unlock/verify/verify.py /tmp/cmp50-probe-\$i.json
           done
Rollback:
  sudo $0 --rollback
EOF
