#!/usr/bin/env bash
# Sign a local EFI build with a key trusted by UEFI Secure Boot.
# The unsigned build stays unchanged and reproducible.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
usage: bash ./sign-efi.sh [INPUT.EFI] [OUTPUT.EFI]

Default input:  ./50HXUNLK.EFI
Default output: ./50HXUNLK.signed.EFI

With sbctl, the default key is /var/lib/sbctl/keys/db/db.key and its
certificate is /var/lib/sbctl/keys/db/db.pem. Set KEY and CERT to use
another PEM key pair with sbsign.
EOF
}

[[ $# -le 2 ]] || { usage >&2; exit 2; }

IN="${1:-${IN:-${SCRIPT_DIR}/50HXUNLK.EFI}}"
OUT="${2:-${OUT:-${SCRIPT_DIR}/50HXUNLK.signed.EFI}}"
SBCTL="${SBCTL:-sbctl}"
SBSIGN="${SBSIGN:-sbsign}"
SBVERIFY="${SBVERIFY:-sbverify}"
CUSTOM_PAIR=0
if [[ -n "${KEY:-}" || -n "${CERT:-}" ]]; then
    [[ -n "${KEY:-}" && -n "${CERT:-}" ]] || {
        echo "set both KEY and CERT to use a custom key pair" >&2
        exit 1
    }
    CUSTOM_PAIR=1
fi
KEY="${KEY:-/var/lib/sbctl/keys/db/db.key}"
CERT="${CERT:-/var/lib/sbctl/keys/db/db.pem}"

die() {
    echo "sign-efi.sh: $*" >&2
    exit 1
}

[[ -f "${IN}" ]] || die "input EFI not found: ${IN}"
[[ "${IN}" != "${OUT}" ]] || die "IN and OUT must differ; keep the unsigned build"
[[ ! -e "${OUT}" ]] || die "output already exists: ${OUT}; remove it or set OUT"
[[ "$(head -c 2 "${IN}")" == "MZ" ]] || die "input is not a PE/EFI image: ${IN}"
command -v "${SBVERIFY}" >/dev/null || die "missing sbverify (install sbsigntool)"

if "${SBVERIFY}" --list "${IN}" >/dev/null 2>&1; then
    die "input is already signed; rebuild a clean unsigned EFI first"
fi

if (( CUSTOM_PAIR )); then
    SIGNER=sbsign
elif command -v "${SBCTL}" >/dev/null 2>&1; then
    SIGNER=sbctl
elif command -v "${SBSIGN}" >/dev/null 2>&1; then
    SIGNER=sbsign
else
    die "missing sbctl or sbsign (install sbctl or sbsigntool)"
fi

[[ -r "${KEY}" && -r "${CERT}" ]] || die "key pair not readable; create/enroll sbctl keys or set KEY and CERT"

stage="$(mktemp "${TMPDIR:-/tmp}/50hx-efi-sign.XXXXXXXX")"
trap 'rm -f -- "${stage}"' EXIT

if [[ "${SIGNER}" == sbctl ]]; then
    if ! "${SBCTL}" sign -o "${stage}" "${IN}"; then
        echo "sbctl sign failed; retrying with landlock disabled" >&2
        "${SBCTL}" --disable-landlock sign -o "${stage}" "${IN}"
    fi
else
    command -v "${SBSIGN}" >/dev/null || die "missing ${SBSIGN}"
    "${SBSIGN}" --key "${KEY}" --cert "${CERT}" --output "${stage}" "${IN}"
fi

[[ -s "${stage}" ]] || die "signer produced no output"
"${SBVERIFY}" --cert "${CERT}" "${stage}"

mkdir -p "$(dirname "${OUT}")"
cp -- "${stage}" "${OUT}"
if [[ -n "${SUDO_UID:-}" ]]; then
    chown -- "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "${OUT}" || true
fi

echo "Signed EFI: ${OUT}"
echo "SHA-256: $(sha256sum "${OUT}" | awk '{print $1}')"
echo "The signer certificate must be trusted in UEFI db. MOK alone is not used by a direct firmware boot entry."
echo "Keep this signed file local; do not publish it or replace the reproducible unsigned build."
