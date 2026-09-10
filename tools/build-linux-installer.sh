#!/usr/bin/env bash
# build-linux-installer.sh — produce a self-extracting installer.
#
# Wraps a prebuilt payload tarball into a single shell script that
# downloads its own tail, verifies the SHA-256, extracts, and runs
# install.sh as root. No network fetch at run time when the local
# --tar path is used; --url-mode=download downloads from GitHub.
#
# Output: cmp50hx-unlock-linux.run (executable)
#
# Usage:
#   CMP_VERSION=v0.1.30 CMP_RELEASE_URL=https://github.com/... \
#   CMP_RELEASE_SHA=$(sha256sum payload.tar.gz | awk '{print $1}') \
#     bash build-linux-installer.sh --tar payload.tar.gz --out cmp50hx-unlock-linux.run
#
# Or wire into the GitHub Actions workflow (see .github/workflows/release.yml).

set -euo pipefail
PROG=${0##*/}

usage() {
  cat <<EOF
$PROG --tar <payload.tar.gz> --out <installer.run> [options]

Options:
  --tar FILE        Payload tarball (install.sh + blobs + patch + module tarball).
  --out FILE        Self-extracting installer output.
  --name NAME       Friendly installer name (default: cmp50hx-unlock).
  --version V       Version string (default: from CMP_VERSION env or "dev").
  --url-mode URL    Network fetch mode at run time: "download" (default)
                    or "embedded" (extract local tarball only).
  --sha256 HEX      Override SHA-256 (else read from <tar>.sha256).
  -h, --help
Environment (preferred for CI):
  CMP_VERSION       Version string embedded in the installer.
  CMP_RELEASE_URL   Default URL the installer fetches at run time.
  CMP_RELEASE_SHA   Default SHA-256 to verify (optional but recommended).
EOF
}

TAR=""
OUT=""
NAME="cmp50hx-unlock"
VERSION="${CMP_VERSION:-dev}"
URL_MODE="download"
SHA="${CMP_RELEASE_SHA:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tar)        TAR="${2:?}"; shift 2 ;;
    --out)        OUT="${2:?}"; shift 2 ;;
    --name)       NAME="${2:?}"; shift 2 ;;
    --version)    VERSION="${2:?}"; shift 2 ;;
    --url-mode)   URL_MODE="${2:?}"; shift 2 ;;
    --sha256)     SHA="${2:?}"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "unknown: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$TAR" && -f "$TAR" ]] || { echo "--tar file required" >&2; exit 2; }
[[ -n "$OUT" ]] || { echo "--out file required" >&2; exit 2; }

# Default SHA: look for <tar>.sha256 beside the tarball
if [[ -z "$SHA" && -f "$TAR.sha256" ]]; then
  SHA=$(awk '{print $1}' "$TAR.sha256")
fi
[[ -z "$SHA" ]] && SHA="$(sha256sum "$TAR" | awk '{print $1}')"
echo "using sha256: $SHA"

# Sanity: verify our own tarball hash so the embedded installer is honest
ACTUAL="$(sha256sum "$TAR" | awk '{print $1}')"
if [[ "$ACTUAL" != "$SHA" ]]; then
  echo "SHA mismatch: tar=$ACTUAL expected=$SHA" >&2
  exit 3
fi

PAYLOAD_SIZE=$(wc -c < "$TAR")

# We embed the tarball as raw bytes after a sentinel line — a small
# awk script in the runtime strips it. This keeps the installer close
# to the tarball's natural size (no base64 inflation).

cat > "$OUT" <<HEADER
#!/usr/bin/env bash
# $NAME $VERSION — one-click CMP 50HX unlock installer
# This is a self-extracting installer: the payload is appended below
# the sentinel line "CMP_PAYLOAD_TGZ_BELOW". See tools/build-linux-installer.sh
# for the build recipe and install.sh for what runs after extraction.
set -euo pipefail
PROG=\$0
VERSION="$VERSION"
NAME="$NAME"
SHA256="$SHA"
PAYLOAD_SIZE="$PAYLOAD_SIZE"
DEFAULT_URL="${CMP_RELEASE_URL:-}"
INSTALL_SH="install.sh"
TMP=\$(mktemp -d -t cmp50hx.XXXXXX)
trap "rm -rf "\$TMP"" EXIT

die() { echo "\$PROG: \$*" >&2; exit 1; }

# --- 1. resolve payload ------------------------------------------------
WORKDIR=""
PAYLOAD=""
URL_MODE_DEFAULT="$URL_MODE"

while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --self-check)       echo "embedded payload size: \$PAYLOAD_SIZE bytes"; echo "sha256: \$SHA256"; exit 0 ;;
    --unpack-only)      URL_MODE_DEFAULT="unpack-only"; shift ;;
    --use-embedded)     URL_MODE_DEFAULT="embedded"; shift ;;
    --url URL)          PAYLOAD_URL="\${2:?}"; shift 2 ;;
    --tarball FILE)     PAYLOAD="\${2:?}"; shift 2 ;;
    --workdir DIR)      WORKDIR="\${2:?}"; shift 2 ;;
    --no-elevate)       ELEVATE=0; shift ;;
    --version)          echo "\$NAME \$VERSION"; exit 0 ;;
    -h|--help)
      cat <<USAGE
\$NAME \$VERSION

Usage: sudo \$PROG [options]

Options:
  --url URL         Download payload from URL instead of embedded copy.
  --tarball FILE    Use a local tarball instead of the embedded one.
  --workdir DIR     Extract into DIR (default: \$TMP).
  --use-embedded    Use the embedded payload even if --url is set.
  --unpack-only     Extract only, do not run install.sh.
  --no-elevate      Skip sudo (assume you are already root).
  --self-check      Print embedded payload size + sha256 and exit.
  --version         Print version and exit.
USAGE
      exit 0 ;;
    *) die "unknown option: \$1 (try --help)" ;;
  esac
done

# Always prefer --tarball if given (debugging / dev)
if [[ -n "\${PAYLOAD:-}" ]]; then
  echo ">> using local tarball: \$PAYLOAD"
  WORKDIR="\${WORKDIR:-\$TMP}"
  mkdir -p "\$WORKDIR"
  tar -C "\$WORKDIR" -xzf "\$PAYLOAD"
elif [[ "\$URL_MODE_DEFAULT" == "embedded" ]]; then
  echo ">> extracting embedded payload..."
  WORKDIR="\${WORKDIR:-\$TMP}"
  mkdir -p "\$WORKDIR"
  # Find the sentinel and extract everything after it. GNU sed passes
  # NUL bytes through; mawk truncates at NUL, so awk is not binary-safe.
  sed '1,/^__CMP_PAYLOAD_TGZ_BELOW__$/d' "\$0" > "\$WORKDIR/payload.tar.gz"
else
  URL="\${PAYLOAD_URL:-\$DEFAULT_URL}"
  [[ -n "\$URL" ]] || die "no payload URL available (CMP_RELEASE_URL was empty)"
  echo ">> downloading \$URL"
  WORKDIR="\${WORKDIR:-\$TMP}"
  mkdir -p "\$WORKDIR"
  if command -v curl >/dev/null; then
    curl --fail --location --show-error --silent -o "\$WORKDIR/payload.tar.gz" "\$URL"
  elif command -v wget >/dev/null; then
    wget --quiet -O "\$WORKDIR/payload.tar.gz" "\$URL"
  else
    die "need curl or wget to download"
  fi
fi

# --- 2. verify checksum ------------------------------------------------
SHA_ACTUAL="\$(sha256sum "\$WORKDIR/payload.tar.gz" | awk '{print \$1}')"
if [[ "\$SHA_ACTUAL" != "\$SHA256" ]]; then
  die "payload checksum mismatch (got \$SHA_ACTUAL, expected \$SHA256)"
fi

# --- 3. install --------------------------------------------------------
if [[ "\$URL_MODE_DEFAULT" == "unpack-only" ]]; then
  echo ">> unpacked at: \$WORKDIR"
  exit 0
fi

# Re-extract on top if we used the embedded/download path with WORKDIR
[[ -f "\$WORKDIR/payload.tar.gz" && ! -f "\$WORKDIR/\$INSTALL_SH" ]] && \
  tar -C "\$WORKDIR" -xzf "\$WORKDIR/payload.tar.gz"

[[ -f "\$WORKDIR/\$INSTALL_SH" ]] || die "install.sh not found inside payload"

cd "\$WORKDIR"

# Elevation (interactive only — CI users pass --no-elevate)
if [[ "\${ELEVATE:-1}" == "1" && "\$(id -u)" != "0" ]]; then
  echo ">> this installer needs root; re-running via sudo"
  exec sudo -E bash "\$WORKDIR/\$INSTALL_SH" "\$@"
else
  exec bash "\$WORKDIR/\$INSTALL_SH" "\$@"
fi

# Below this line: the base64-encoded payload
__CMP_PAYLOAD_TGZ_BELOW__
HEADER

# Append payload (raw, NOT base64 — saves 30% size and a runtime decode)
# Above header uses a heredoc + sentinel; here we just cat the tarball.
cat "$TAR" >> "$OUT"
chmod +x "$OUT"

echo "wrote $OUT ($(wc -c < "$OUT") bytes)"
echo "  version: $VERSION"
echo "  sha256:  $SHA"
echo "  size:    $PAYLOAD_SIZE bytes payload"
