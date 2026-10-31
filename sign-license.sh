#!/bin/bash
# Sign a Mattermost license JSON with the key pair used by `patch.sh --keyswap`.
#
# A Mattermost license file is base64( json_plaintext || 256-byte RSA signature )
# where the signature is PKCS#1 v1.5 over SHA-512 of the plaintext. The server
# verifies it against the RSA public key embedded in the binary. After
# `patch.sh --keyswap` that embedded key is ours, so a license signed here is
# accepted and a license signed by Mattermost is not.
#
# Usage: sign-license.sh [OPTIONS] <license.json>
#
# Exit codes:
#   0  Success
#   1  General error
#   2  Missing dependency
#   3  Bad arguments
#   4  Signing failed
#   5  Verification of our own signature failed
set -euo pipefail

# Private half of the key pair whose public half patch.sh installs into the
# binary. Regenerate both together: `openssl genrsa -out keyswap-key.pem 2048`
# then `openssl rsa -in keyswap-key.pem -pubout`.
KEY_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/keyswap-key.pem"

INPUT=""
OUTPUT=""
QUIET=0

show_help() {
    cat << EOF
Usage: $0 [OPTIONS] <license.json>

Signs a Mattermost license JSON so it is accepted by a binary patched with
'patch.sh --keyswap'. Writes the base64 license blob (no trailing newline) to
stdout, or to the file given with -o.

Options:
  -o, --out <file>   Write the license to <file> instead of stdout
  -k, --key <file>   Use a different private key (default: keyswap-key.pem
                     next to this script)
  -q, --quiet        Suppress the summary on stderr
  -h, --help         Show this help message and exit

Example:
  $0 -o license my-license.json
  ./patch.sh --keyswap ./mattermost
  ./mmctl --local license upload license

Exit codes:
  0  Success
  1  General error
  2  Missing dependency
  3  Bad arguments
  4  Signing failed
  5  Verification of our own signature failed
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -o|--out)
            [ $# -ge 2 ] || { echo "Error: $1 requires an argument." >&2; exit 3; }
            OUTPUT="$2"
            shift 2
            ;;
        -k|--key)
            [ $# -ge 2 ] || { echo "Error: $1 requires an argument." >&2; exit 3; }
            KEY_FILE="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            echo "Use '$0 --help' for usage information." >&2
            exit 3
            ;;
        *)
            if [ -z "$INPUT" ]; then
                INPUT="$1"
            else
                echo "Error: Multiple input files specified." >&2
                exit 3
            fi
            shift
            ;;
    esac
done

log() {
    if [ "$QUIET" -eq 0 ]; then
        echo "$@" >&2
    fi
}

MISSING_DEPS=()
for dep in openssl base64 mktemp; do
    command -v "$dep" >/dev/null 2>&1 || MISSING_DEPS+=("$dep")
done
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "Error: The following required commands are not installed:" >&2
    for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep" >&2
    done
    exit 2
fi

if [ -z "$INPUT" ]; then
    echo "Error: No license JSON specified." >&2
    show_help >&2
    exit 3
fi

[ -f "$INPUT" ] || { echo "Error: File '$INPUT' does not exist." >&2; exit 3; }
[ -r "$INPUT" ] || { echo "Error: Cannot read '$INPUT'." >&2; exit 3; }

if [ ! -f "$KEY_FILE" ]; then
    # Same on-demand behaviour as patch.sh: create the pair on first use so the
    # two scripts cannot end up with different keys.
    if [ "$KEY_FILE" = "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/keyswap-key.pem" ] \
        && command -v openssl >/dev/null 2>&1 \
        && openssl genrsa -out "$KEY_FILE" 2048 >/dev/null 2>&1; then
        chmod 600 "$KEY_FILE"
        log "Generated a new signing key: $KEY_FILE"
    else
        echo "Error: Private key '$KEY_FILE' not found." >&2
        exit 4
    fi
fi

# The binary must be patched with the public half of the signing key, otherwise
# the license we produce is silently rejected by the server. Mirror patch.sh's
# logic: it installs the public half of keyswap-key.pem when that file exists,
# and the baked-in OUR_KEY constant otherwise.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_SCRIPT="$SCRIPT_DIR/patch.sh"
DEFAULT_KEY="$SCRIPT_DIR/keyswap-key.pem"
if [ -f "$PATCH_SCRIPT" ]; then
    if [ -f "$DEFAULT_KEY" ]; then
        PATCHED_PUB=$(openssl rsa -in "$DEFAULT_KEY" -pubout 2>/dev/null | sed '/^$/d')
    else
        PATCHED_PUB=$(awk '/^OUR_KEY=/,/^-----END PUBLIC KEY-----/ {print}' "$PATCH_SCRIPT" \
            | sed "1s/^OUR_KEY='//" \
            | sed 's/^-----END PUBLIC KEY-----.*$/-----END PUBLIC KEY-----/' \
            | sed '/^$/d')
    fi
    SIGNING_PUB=$(openssl rsa -in "$KEY_FILE" -pubout 2>/dev/null | sed '/^$/d')
    if [ -n "$PATCHED_PUB" ] && [ -n "$SIGNING_PUB" ] && [ "$PATCHED_PUB" != "$SIGNING_PUB" ]; then
        echo "Error: '$KEY_FILE' does not match the public key patch.sh installs." >&2
        echo "Signing with it would produce a license the patched server rejects." >&2
        echo "patch.sh installs the public half of: $DEFAULT_KEY" >&2
        echo "Either sign with that key, or patch the binary with this one's public half:" >&2
        echo "$SIGNING_PUB" >&2
        exit 4
    fi
fi

# The plaintext must be valid JSON: the server unmarshals it after the
# signature check, so a broken file fails late and confusingly otherwise.
if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$INPUT" 2>/dev/null || {
        echo "Error: '$INPUT' is not valid JSON." >&2
        exit 3
    }
fi

WORK_DIR=$(mktemp -d) || { echo "Error: failed to create a temporary directory." >&2; exit 1; }
trap 'rm -rf "$WORK_DIR"' EXIT

SIG_FILE="$WORK_DIR/signature.bin"
LICENSE_FILE="$WORK_DIR/license.b64"

# Sign the exact bytes of the file: PKCS#1 v1.5 over SHA-512, 256-byte output.
if ! openssl dgst -sha512 -sign "$KEY_FILE" -out "$SIG_FILE" "$INPUT" 2>"$WORK_DIR/err"; then
    echo "Error: Failed to sign '$INPUT':" >&2
    cat "$WORK_DIR/err" >&2
    exit 4
fi

SIG_SIZE=$(wc -c < "$SIG_FILE")
if [ "$SIG_SIZE" -ne 256 ]; then
    echo "Error: Signature is $SIG_SIZE bytes, expected 256 (is the key 2048-bit?)." >&2
    exit 4
fi

# Verify our own signature before handing the license out.
PUB_FILE="$WORK_DIR/pub.pem"
if ! openssl rsa -in "$KEY_FILE" -pubout -out "$PUB_FILE" 2>"$WORK_DIR/err"; then
    echo "Error: Cannot derive the public key from '$KEY_FILE':" >&2
    cat "$WORK_DIR/err" >&2
    exit 4
fi
if ! openssl dgst -sha512 -verify "$PUB_FILE" -signature "$SIG_FILE" "$INPUT" >/dev/null 2>&1; then
    echo "Error: Self-verification of the signature failed." >&2
    exit 5
fi

# base64(plaintext || signature), single line, no trailing newline.
cat "$INPUT" "$SIG_FILE" | base64 -w0 > "$LICENSE_FILE"

if [ -n "$OUTPUT" ]; then
    cp "$LICENSE_FILE" "$OUTPUT" || { echo "Error: Cannot write '$OUTPUT'." >&2; exit 1; }
    log "Wrote signed license to '$OUTPUT' ($(wc -c < "$OUTPUT") bytes)."
else
    cat "$LICENSE_FILE"
    log "Signed license written to stdout ($(wc -c < "$LICENSE_FILE") bytes)."
fi

log "Signed with: $KEY_FILE"
log "Upload with: mmctl --local license upload <file>"
