#!/usr/bin/env bash
# CMP 50HX (10de:1e09) all-feature installer for
# Ubuntu/Debian. The card is auto-detected; force it with --card.
#
#   curl -fsSL https://raw.githubusercontent.com/xrip/cmp50hx-unlock/master/install.sh | sudo bash
#
# Options:
#   --card cmp50hx           force the card instead of auto-detecting
#   --idle-governor          also enable the optional idle P-state governor,
#                            which drops idle power to about 2 W (see idle-governor/)
#   --rebar-32g              ask for a 32 GiB BAR1 instead of the default 16 GiB
#                            (selector 9; needs a host that can place the window)
#
# What it does, in order:
#   1. detects the card (or takes --card cmp50hx)
#   2. installs build tools and kernel headers
#   3. installs the NVIDIA 610.43.03 userland from the official .run package
#   4. builds the patched kernel modules for the running kernel (build.sh)
#   5. installs the modules with a backup of any previous ones, runs depmod
#   6. installs the optional idle governor unit, enabled only with
#      --idle-governor
#   7. installs the cmp-tune profile tuning utility
#   8. best-effort live check of the card
#   9. rebuilds and verifies the initramfs for the running kernel
#
# It never reboots or unloads a loaded driver. Reboot after the installer
# reports PASS_CMP_INITRAMFS to load the patched module at boot.
set -Eeuo pipefail

readonly driver_version="610.43.03"
readonly repo_tarball="https://github.com/xrip/cmp50hx-unlock/archive/refs/heads/master.tar.gz"
readonly nvidia_run_url="https://us.download.nvidia.com/XFree86/Linux-x86_64/${driver_version}/NVIDIA-Linux-x86_64-${driver_version}.run"
# SHA-256 of the .run package above, pinned from the official download.
readonly nvidia_run_sha256="45e2d4c134a23c35e50f253a4aa63e7e5e8d17e3d185d4a07c8a58e9612ed392"
readonly install_dir="/opt/cmp50hx-unlock"
readonly krel="$(uname -r)"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "install failed at line ${LINENO}; see output above"' ERR

card=''
idle_governor=0
rebar_selector=8
while [[ $# -gt 0 ]]; do
    case "$1" in
        --card)
            card="${2:?--card needs cmp50hx}"
            [[ "${card}" == cmp50hx ]] \
                || die "unknown card: ${card} (supported: cmp50hx)"
            shift 2
            ;;
        --idle-governor)
            idle_governor=1
            shift
            ;;
        --rebar-32g)
            rebar_selector=9
            shift
            ;;
        -h|--help)
            awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' \
                "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            die "unknown argument: $1 (supported: --card, --idle-governor, --rebar-32g)"
            ;;
    esac
done

[[ ${EUID} -eq 0 ]] || die "run as root (sudo)"
[[ -r /etc/os-release ]] || die "cannot read /etc/os-release"
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*|*" linuxmint "*) ;;
    *) die "only Ubuntu/Debian and their derivatives are supported (this system is ${ID:-unknown})" ;;
esac

# --- 1. detect the card -------------------------------------------------------

# device id -> card name; one build serves exactly one card type
detect_cards() {
    local dev vendor device
    for dev in /sys/bus/pci/devices/*/; do
        [[ -r "${dev}vendor" && -r "${dev}device" ]] || continue
        read -r vendor < "${dev}vendor"
        read -r device < "${dev}device"
        [[ "${vendor}" == "0x10de" ]] || continue
        case "${device}" in
            0x1e09) echo cmp50hx ;;
        esac
    done | sort -u
}

mapfile -t present_cards < <(detect_cards)
if [[ -n "${card}" ]]; then
    log "card forced by --card: ${card}"
elif [[ ${#present_cards[@]} -eq 1 ]]; then
    card="${present_cards[0]}"
    log "detected card: ${card}"
else
    die "no CMP 50HX (10de:1e09) found on the PCI bus; use --card to force"
fi

readonly pci_device="0x1e09"

cmp_subsystem=''
for dev in /sys/bus/pci/devices/*/; do
    [[ -r "${dev}vendor" && -r "${dev}device" ]] || continue
    read -r vendor < "${dev}vendor"
    read -r device < "${dev}device"
    [[ "${vendor}" == "0x10de" && "${device}" == "${pci_device}" ]] || continue
    read -r sv < "${dev}subsystem_vendor"
    read -r sd < "${dev}subsystem_device"
    cmp_subsystem="${sv}:${sd}"
done
[[ -n "${cmp_subsystem}" ]] || die "no card with device ${pci_device} found on the PCI bus"

case "${cmp_subsystem}" in
    0x10de:0x1554|0x1462:0x371f)
        log "found CMP 50HX 10de:1e09 subsystem ${cmp_subsystem} (tested board)" ;;
    *)
        log "WARNING: subsystem ${cmp_subsystem} is not a tested board (tested: 10de:1554, 1462:371f); continuing" ;;
esac

if [[ -d /sys/firmware/efi ]] && command -v mokutil >/dev/null 2>&1 \
        && mokutil --sb-state 2>/dev/null | grep -q 'Secure Boot enabled'; then
    log "WARNING: Secure Boot is enabled; the unsigned patched module will most likely not load."
    log "         Disable Secure Boot in firmware setup, or sign the module with your own MOK."
fi

old_version="$(modinfo -F version nvidia 2>/dev/null || true)"
if [[ -n "${old_version}" && "${old_version}" != "${driver_version}" ]]; then
    log "note: driver ${old_version} is installed; it is replaced by ${driver_version}, reboot to switch fully"
fi

# --- 2. packages ------------------------------------------------------------

export DEBIAN_FRONTEND=noninteractive
log "installing build tools and kernel headers"
apt-get update -y
apt-get install -y build-essential curl patch xz-utils kmod binutils ca-certificates mokutil lsb-release python3 pciutils
apt-get install -y "linux-headers-${krel}" \
    || die "no linux-headers package for kernel ${krel}; install the matching headers first"

# --- 3. fetch this repository ----------------------------------------------

ts="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -d "${install_dir}" ]]; then
    mv "${install_dir}" "${install_dir}.old-${ts}"
fi
mkdir -p "${install_dir}/logs" "${install_dir}/cache" "${install_dir}/artifacts" "${install_dir}/backups"
exec 3>&1 4>&2
exec > >(tee -a "${install_dir}/logs/install-${ts}.log") 2>&1
log "CMP unlock install start: card ${card}, driver ${driver_version}, kernel ${krel}, subsystem ${cmp_subsystem}"

if [[ -d "${install_dir}.old-${ts}" ]]; then
    for keep in cache artifacts backups; do
        if [[ -e "${install_dir}.old-${ts}/${keep}" ]]; then
            rm -rf "${install_dir:?}/${keep}"
            mv "${install_dir}.old-${ts}/${keep}" "${install_dir}/${keep}"
        fi
    done
    rm -rf "${install_dir}.old-${ts}"
fi

repo_tar="$(mktemp)"
log "downloading repository"
curl -fsSL --retry 3 -o "${repo_tar}" "${repo_tarball}"
tar -xzf "${repo_tar}" -C "${install_dir}" --strip-components=1
rm -f "${repo_tar}"
[[ -f "${install_dir}/build.sh" ]] || die "repository layout broken: build.sh missing"

# --- 4. NVIDIA userland (.run, no kernel module) ----------------------------

run_file="${install_dir}/cache/NVIDIA-Linux-x86_64-${driver_version}.run"
if [[ ! -f "${run_file}" ]]; then
    log "downloading NVIDIA ${driver_version} .run installer (several hundred MB)"
    curl -fL --retry 3 --show-error -o "${run_file}.part" "${nvidia_run_url}"
    mv "${run_file}.part" "${run_file}"
fi
if [[ -n "${nvidia_run_sha256}" ]]; then
    printf '%s  %s\n' "${nvidia_run_sha256}" "${run_file}" | sha256sum -c - \
        || die "NVIDIA .run SHA-256 mismatch"
else
    log "WARNING: the .run SHA-256 is not pinned in this script; continuing over TLS"
fi

log "installing NVIDIA userland (the kernel module comes from this repo, not the .run)"
sh "${run_file}" --silent --no-kernel-modules --no-dkms --no-backup \
    --no-rebuild-initramfs --no-x-check --no-nouveau-check --skip-module-unload

if ! find /lib/firmware/nvidia -name 'gsp*.bin' -print -quit 2>/dev/null | grep -q .; then
    log "GSP firmware not present; extracting it from the .run package"
    fw_dir="$(mktemp -d)"
    sh "${run_file}" -x --target "${fw_dir}" >/dev/null
    if [[ -d "${fw_dir}/firmware" ]]; then
        cp -a "${fw_dir}/firmware/." /lib/firmware/
    else
        log "WARNING: no firmware directory inside the .run package"
    fi
    rm -rf "${fw_dir}"
fi

# --- 5. build the patched modules ------------------------------------------

artifact_dir="${install_dir}/artifacts/${driver_version}-${krel}"
if [[ -f "${artifact_dir}/checksums.sha256" ]] \
        && (cd "${artifact_dir}" && sha256sum -c checksums.sha256 >/dev/null 2>&1); then
    log "reusing the previous build in ${artifact_dir}"
else
    rm -rf "${artifact_dir}"
    log "building the patched ${card} modules for kernel ${krel} (this can take a while)"
    (cd "${install_dir}" && KERNEL_RELEASE="${krel}" bash build.sh --card "${card}")
fi

# --- 6. install the modules -------------------------------------------------

backup_dir="${install_dir}/backups/modules-${ts}"
dest_dir="/lib/modules/${krel}/updates"
for mod in nvidia nvidia-uvm nvidia-modeset nvidia-drm nvidia-peermem; do
    path="$(modinfo -n "${mod}" 2>/dev/null || true)"
    [[ -n "${path}" && -f "${path}" ]] || continue
    [[ "${path}" == "${dest_dir}/${mod}.ko" ]] && continue
    mkdir -p "${backup_dir}$(dirname "${path}")"
    case "${path}" in
        "${dest_dir}"/*)
            mv "${path}" "${backup_dir}${path}"
            log "moved ${path} aside (inside updates/, it would shadow the new module)" ;;
        *)
            cp -a "${path}" "${backup_dir}${path}"
            log "backed up ${path}" ;;
    esac
done
[[ -d "${backup_dir}" ]] || log "no previous modules to back up (fresh system)"

mkdir -p "/lib/modules/${krel}/updates"
for mod in nvidia nvidia-uvm nvidia-modeset nvidia-drm nvidia-peermem; do
    src="${artifact_dir}/${mod}.ko"
    [[ -f "${src}" ]] || continue
    install -m 0644 "${src}" "/lib/modules/${krel}/updates/${mod}.ko"
    log "installed /lib/modules/${krel}/updates/${mod}.ko"
done

# nouveau must not claim the card before the patched module at boot
printf 'blacklist nouveau\n' > /etc/modprobe.d/cmp-unlock.conf

# the patched cmp50hx module carries the ReBAR size as a module option
printf 'options nvidia cmp50_rebar_size=%s\n' "${rebar_selector}" \
    > /etc/modprobe.d/cmp50hx-unlock.conf
log "BAR1 selector ${rebar_selector} ($(( 1 << (rebar_selector + 6) )) MiB)"
depmod -a "${krel}"

[[ "$(modinfo -F version nvidia)" == "${driver_version}" ]] || die "installed nvidia.ko has the wrong version"
[[ "$(modinfo -F vermagic nvidia)" == "${krel} "* ]] || die "installed nvidia.ko has the wrong vermagic"

# --- 6a. make the patched module boot-persistent -----------------------------
initramfs_state="SKIPPED"
log "making the patched modules boot-persistent"
if bash "${install_dir}/install-initramfs.sh"; then
    initramfs_state="PASS_CMP_INITRAMFS"
else
    die "initramfs setup failed"
fi

# --- 6b. cmp50hx: PCIe Gen2 boot service --------------------------------------

if [[ "${card}" == cmp50hx ]]; then
    runtime_dir="${install_dir}/cmp50hx"
    [[ -f "${runtime_dir}/cmp50hx-gen2.sh" ]] || die "repository layout broken: cmp50hx/cmp50hx-gen2.sh missing"
    install -m 0755 "${runtime_dir}/cmp50hx-gen2.sh" /usr/local/sbin/cmp50hx-gen2
    install -m 0644 "${runtime_dir}/cmp50hx-gen2.service" /etc/systemd/system/cmp50hx-gen2.service
    systemctl daemon-reload
    systemctl enable cmp50hx-gen2.service >/dev/null
    log "installed and enabled cmp50hx-gen2.service (the card unlocks its PCIe speed registers a few minutes after boot; the service retrains to Gen2 then; NOT started now)"
fi

# --- 6c. optional idle P-state governor -------------------------------------

# CMP cards do not lower their own P-state request, so this supervisor forces
# P8 while idle and returns to P16 on load. Optional and independent of the
# unlock: the unit is always installed, but only enabled on request.
governor_state="installed, NOT enabled (enable: systemctl enable --now cmp-idle-governor)"
governor_dir="${install_dir}/idle-governor"
if [[ -f "${governor_dir}/cmp-governor.c" ]]; then
    log "building the single-process C idle governor"
    cc -O2 -Wall -Wextra -Werror -std=c11 \
        "${governor_dir}/cmp-governor.c" -ldl \
        -o "${governor_dir}/cmp-governor" \
        || die "could not build the C idle governor"
    chmod 0755 "${governor_dir}/cmp-governor"
    install -m 0644 "${governor_dir}/cmp-idle-governor.service" \
        /etc/systemd/system/cmp-idle-governor.service
    systemctl daemon-reload
    if [[ "${idle_governor}" -eq 1 ]]; then
        if systemctl enable cmp-idle-governor.service >/dev/null 2>&1 \
                && systemctl restart cmp-idle-governor.service >/dev/null 2>&1; then
            governor_state="ENABLED and running (idle power should drop within ~30s)"
            log "idle governor enabled and started"
        else
            governor_state="install ok, but enable failed (see: journalctl -u cmp-idle-governor)"
            log "WARNING: could not enable the idle governor"
        fi
    else
        if systemctl is-enabled cmp-idle-governor.service >/dev/null 2>&1; then
            systemctl restart cmp-idle-governor.service >/dev/null 2>&1 || \
                log "WARNING: could not restart the enabled idle governor"
        fi
        log "idle governor installed but not enabled (pass --idle-governor to enable)"
    fi
else
    governor_state="not present in this repository copy"
fi

# --- 6d. tuning utility -----------------------------------------------------

# Profile-driven power/clock/offset tuning. Ships a default profile file and
# seeds /etc/cmp-tune.conf once, so later upgrades never clobber local edits.
tuning_dir="${install_dir}/tuning"
if [[ -f "${tuning_dir}/cmp-tune" ]]; then
    chmod 0755 "${tuning_dir}/cmp-tune"
    ln -sf "${tuning_dir}/cmp-tune" /usr/local/bin/cmp-tune
    if [[ ! -f /etc/cmp-tune.conf ]]; then
        install -m 0644 "${tuning_dir}/profiles.conf" /etc/cmp-tune.conf
        log "seeded /etc/cmp-tune.conf with the default tuning profiles"
    else
        log "kept the existing /etc/cmp-tune.conf"
    fi
    log "installed cmp-tune (try: cmp-tune list, cmp-tune status)"
fi

# --- 7. best-effort live check (never fatal) --------------------------------

live_check="SKIPPED"
if lsmod | grep -q '^nvidia '; then
    log "an nvidia module is already loaded; reboot to test the new one"
elif lsmod | grep -q '^nouveau '; then
    if rmmod nouveau 2>/dev/null; then
        log "unloaded the nouveau module"
    else
        log "could not unload nouveau; reboot to test"
    fi
fi
if ! lsmod | grep -q '^nvidia ' && modprobe nvidia 2>/dev/null; then
    log "loaded nvidia"
    command -v nvidia-modprobe >/dev/null 2>&1 && nvidia-modprobe -c 0 -u || true
    # verify every card, not just the first (multi-GPU hosts)
    gpu_count="$(nvidia-smi -L 2>/dev/null | grep -c 'CMP 50HX' || true)"
    [[ "${gpu_count}" -ge 1 ]] || gpu_count=1
    live_check="PASS_CMP50HX_ISSUE_RATE_AND_COUNTS"
    for dev_index in $(seq 0 $((gpu_count - 1))); do
        probe_json="${install_dir}/logs/rm-probe-${ts}-dev${dev_index}.json"
        if timeout 180 "${artifact_dir}/rm-issue-rate" "${dev_index}" >"${probe_json}" \
                && python3 "${install_dir}/verify/verify.py" "${probe_json}" > /dev/null; then
            log "device ${dev_index}: PASS_CMP50HX_ISSUE_RATE_AND_COUNTS"
        else
            log "device ${dev_index}: verify FAILED (probe kept at ${probe_json})"
            live_check="FAILED (device ${dev_index}; a warm load after a driver swap can fail, reboot usually fixes it)"
        fi
    done
fi

# --- summary ----------------------------------------------------------------

exec 1>&3 2>&4
[[ -d "${backup_dir}" ]] || backup_dir="(none; fresh system)"
cat <<EOF

PASS_CMP50HX_INSTALL
Modules    : /lib/modules/${krel}/updates/nvidia*.ko (patched ${driver_version})
Repository : ${install_dir}
Log        : ${install_dir}/logs/install-${ts}.log
Live check : ${live_check}
Initramfs  : ${initramfs_state}
Idle governor: ${governor_state}
Tuning     : cmp-tune list | cmp-tune status | sudo cmp-tune apply PROFILE

Next steps:
  1. Reboot to load the patched module at boot.

Rollback:
  modules : copy files from ${backup_dir:-/opt/cmp50hx-unlock/backups/} back to
            their original paths, then run: depmod -a ${krel}
  userland: sh ${run_file} --uninstall
EOF
