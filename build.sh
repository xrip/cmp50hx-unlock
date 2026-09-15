#!/usr/bin/env bash
set -Eeuo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly driver_version="610.43.03"
readonly kernel_release="${KERNEL_RELEASE:-$(uname -r)}"
readonly jobs="${JOBS:-$(nproc)}"
readonly cache_dir="${CMP_UNLOCK_CACHE_DIR:-${CMP50_ALL_CACHE_DIR:-${script_dir}/cache}}"
readonly work_dir="${CMP_UNLOCK_WORK_DIR:-${CMP50_ALL_WORK_DIR:-${script_dir}/work}}"
readonly artifact_dir="${CMP_UNLOCK_ARTIFACT_DIR:-${CMP50_ALL_ARTIFACT_DIR:-${script_dir}/artifacts/${driver_version}-${kernel_release}}}"

card="${CARD:-cmp50hx}"
source_dir_input=''
source_tarball=''

usage() {
    cat <<'EOF'
usage: bash ./build.sh [--card cmp50hx] [--source-dir DIR | --source-tarball FILE]

Card defaults to cmp50hx, or the CARD environment variable.

With no source option, the exact NVIDIA 610.43.03 source archive is downloaded
and checked by SHA-256. The script builds artifacts only.
It does not install, load, unload, or reset a GPU.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --card)
            card="${2:?--card needs cmp50hx}"
            shift 2
            ;;
        --source-dir)
            source_dir_input="${2:?--source-dir needs a directory}"
            shift 2
            ;;
        --source-tarball)
            source_tarball="${2:?--source-tarball needs a file}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "${card}" in
    cmp50hx)
        readonly source_url="https://github.com/NVIDIA/open-gpu-kernel-modules/archive/refs/tags/${driver_version}.tar.gz"
        readonly source_sha256="9df87d753cd9c05aa0eedc462af9b35debb549a657136e863282f94c96ee2640"
        readonly patch_dir="${script_dir}/patches/cmp50hx"
        # 05-cmp50-auto-pstate.patch is deliberately not built. A cold-boot A/B
        # on 2026-08-26 proved it pins the card at P8 645/405 even at 100% load
        # (22x memory bandwidth, 2.9x compute), and it breaks the idle
        # governor: with it applied, the P16 release leaves the card at P8. Use
        # the idle governor instead, which reaches about 2 W idle and restores
        # full clocks on release. Evidence:
        # experiments/cmp50-pstate-20260824/runs/20260826T092500Z-patch05-ab-cold-boot/
        patch_order=(
            01-cmp50-stockflow.patch
            02-cmp50-rt-core-count.patch
            03-cmp50-rebar.patch
            04-cmp50-pcie-gen2.patch
        )
        ;;
    *)
        printf 'unknown card: %s (supported: cmp50hx)\n' "${card}" >&2
        exit 2
        ;;
esac

if [[ -n "${source_dir_input}" && -n "${source_tarball}" ]]; then
    printf 'use only one source option\n' >&2
    exit 2
fi

for command in awk cat cc cp curl find grep install make mkdir mktemp modinfo mv nproc patch sha256sum sort strings tar xz; do
    command -v "${command}" >/dev/null || {
        printf 'missing command: %s\n' "${command}" >&2
        exit 3
    }
done

[[ -d "/lib/modules/${kernel_release}/build" ]] || {
    printf 'kernel headers not found for %s\n' "${kernel_release}" >&2
    exit 4
}
patch_files=()
[[ -f "${script_dir}/verify/rm_issue_rate.c" ]]
for patch_name in "${patch_order[@]}"; do
    patch_file="${patch_dir}/${patch_name}"
    [[ -f "${patch_file}" ]] || {
        printf 'missing patch: %s\n' "${patch_file}" >&2
        exit 5
    }
    patch_files+=("${patch_file}")
done
[[ ! -e "${artifact_dir}" ]] || {
    printf 'artifact directory already exists: %s\n' "${artifact_dir}" >&2
    exit 10
}

mkdir -p "${cache_dir}" "${work_dir}" "$(dirname "${artifact_dir}")"
readonly build_dir="$(mktemp -d "${work_dir}/build.XXXXXX")"
readonly source_dir="${build_dir}/source"

if [[ -n "${source_dir_input}" ]]; then
    [[ -d "${source_dir_input}" ]]
    cp -a "${source_dir_input}" "${source_dir}"
else
    if [[ -z "${source_tarball}" ]]; then
        source_tarball="${cache_dir}/$(basename "${source_url}")"
        if [[ ! -f "${source_tarball}" ]]; then
            curl -L --fail --show-error -o "${source_tarball}.part" "${source_url}"
            mv "${source_tarball}.part" "${source_tarball}"
        fi
    fi
    [[ -f "${source_tarball}" ]]
    actual_sha256="$(sha256sum "${source_tarball}" | awk '{print $1}')"
    [[ "${actual_sha256}" == "${source_sha256}" ]] || {
        printf 'source SHA-256 mismatch: expected %s, got %s\n' "${source_sha256}" "${actual_sha256}" >&2
        exit 11
    }
fi

if [[ -z "${source_dir_input}" ]]; then
    mkdir "${build_dir}/extract"
    tar -xzf "${source_tarball}" -C "${build_dir}/extract"
    mapfile -t roots < <(find "${build_dir}/extract" -mindepth 1 -maxdepth 1 -type d | sort)
    [[ ${#roots[@]} -eq 1 ]] || {
        printf 'unexpected source archive layout\n' >&2
        exit 12
    }
    mv "${roots[0]}" "${source_dir}"
fi

for patch_file in "${patch_files[@]}"; do
    patch --dry-run -d "${source_dir}" -p1 < "${patch_file}" >/dev/null
    patch -d "${source_dir}" -p1 < "${patch_file}" >/dev/null
done

grep -q 'CMP50_GEN2: POLICY_PASS' \
    "${source_dir}/src/nvidia/src/kernel/gpu/gsp/arch/turing/kernel_gsp_tu102.c"
grep -q 'CMP50_GEN2: RETRAIN_PASS' \
    "${source_dir}/kernel-open/nvidia/nv.c"
grep -q 'CMP50_PCIE_DIAG_V1' "${source_dir}/kernel-open/nvidia/nv.c"
if grep -Eq '0x0008E1B[48C]U|0x008205(7C|80|20)U' "${patch_files[@]}"; then
    printf 'the patch contains a GA100-only PCIe register\n' >&2
    exit 13
fi

make -C "${source_dir}" modules -j"${jobs}" KERNEL_UNAME="${kernel_release}"

mkdir "${artifact_dir}"
for module in nvidia nvidia-uvm nvidia-modeset nvidia-drm nvidia-peermem; do
    if [[ -f "${source_dir}/kernel-open/${module}.ko" ]]; then
        install -m 0644 "${source_dir}/kernel-open/${module}.ko" "${artifact_dir}/${module}.ko"
    fi
done

cc -O2 -Wall -Wextra -Werror -std=c11 "${script_dir}/verify/rm_issue_rate.c" \
    -o "${artifact_dir}/rm-issue-rate"

[[ -f "${artifact_dir}/nvidia.ko" ]]
[[ "$(modinfo -F version "${artifact_dir}/nvidia.ko")" == "${driver_version}" ]]
[[ "$(modinfo -F vermagic "${artifact_dir}/nvidia.ko" | awk '{print $1}')" == "${kernel_release}" ]]
grep -a -q 'CMP50_STOCKFLOW_' "${artifact_dir}/nvidia.ko"
grep -a -q 'CMP50_GSP_READY_' "${artifact_dir}/nvidia.ko"
grep -a -q 'CMP50_REBAR' "${artifact_dir}/nvidia.ko"
grep -a -q 'CMP50_PCIE_DIAG_V1' "${artifact_dir}/nvidia.ko"
grep -q 'NV2080_CTRL_GR_INFO_INDEX_RT_CORE_COUNT' "${source_dir}/src/nvidia/src/kernel/gpu/gr/kernel_graphics.c"
grep -q 'data = 56U' "${source_dir}/src/nvidia/src/kernel/gpu/gr/kernel_graphics.c"

(cd "${artifact_dir}" && sha256sum ./* > checksums.sha256)
printf 'PASS_CMP50HX_ALL_BUILD\n%s\n' "${artifact_dir}"
printf 'Build source kept at %s for review.\n' "${source_dir}"
