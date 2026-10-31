#!/bin/bash
set -euo pipefail
# The byte patterns contain "??" wildcards and are expanded word-by-word in
# several helpers. Without noglob, a two-character filename in the current
# directory would be substituted for the wildcard and silently corrupt the
# pattern.
set -f

# CLI options
QUIET=0
DRY_RUN=0
BINARY_FILE=""
METHOD="branch"

# Embedded license public keys (see `--keyswap` below). These are the PEM
# bodies Mattermost ships in server/channels/utils/license-public-key{,-test}.txt.
# The trailing newline is deliberately excluded: builds before 8.0 store the
# PEM without it, so the 450-byte core matches every version.
VENDOR_KEY_PROD='-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyZmShlU8Z8HdG0IWSZ8r
tSyzyxrXkJjsFUf0Ke7bm/TLtIggRdqOcUF3XEWqQk5RGD5vuq7Rlg1zZqMEBk8N
EZeRhkxyaZW8pLjxwuBUOnXfJew31+gsTNdKZzRjrvPumKr3EtkleuoxNdoatu4E
HrKmR/4Yi71EqAvkhk7ZjQFuF0osSWJMEEGGCSUYQnTEqUzcZSh1BhVpkIkeu8Kk
1wCtptODixvEujgqVe+SrE3UlZjBmPjC/CL+3cYmufpSNgcEJm2mwsdaXp2OPpfn
a0v85XL6i9ote2P+fLZ3wX9EoioHzgdgB7arOxY50QRJO7OyCqpKFKv6lRWTXuSt
hwIDAQAB
-----END PUBLIC KEY-----'

VENDOR_KEY_TEST='-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwVMaUtQMFtQsRoa2FQd+
17+acMRMqzPsFTJEix7n+tA8ieCAX0lvNBOjVh8lrt/AUe7B3ZJ0HE6v8xuKj9YA
zUqV8R27UmnIxf5TCXFWrt+fnzX31yLjqK4Fd6JmiDheUatd1hG+gkScMAPuj+Xw
4O+V5sMwaVusytVgmehqcVKYrKpDyhBDUEbDRbKKbP4YAHbmNs3AzlGBbQtvc1fi
0ww7oNKs9cZVcCIeNdwbkXmf8pK5zSXqVsmyPyH3Ue8M6JMNGuPGh1fyHRhFdIiD
lxd7LBKSh7BTjbRtG9DEt1dyMnYQDgRVAdpururuK/otowCowr6X/Etnk2NNeXcZ
4QIDAQAB
-----END PUBLIC KEY-----'

# Public half of keyswap-key.pem, installed by --keyswap. Used when no private
# key is available locally (e.g. the binary was patched elsewhere). If
# keyswap-key.pem sits next to this script, its public half is derived from it
# instead, so the two cannot drift apart.
OUR_KEY='-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzsyRgL+IwTzjrk6+ogS6
e3XbhNYj6ZW6Ohp36UPrGNJ8GfTJEe+u+73PdijUszSuhFqeXrI5b7cVTsw0leO6
+x1JWMqjb3B+WgS3flxtZGAwWrS1GPzdzO0Bn4/7IIzEXoPeUXQ5J777Xah5elX1
19mumiMceZVLl1xvcGS9jpmWak69/uDwjp0tUNpJHovOTKx5k1wf7zcFCUgk+fPx
EnSuSe9X7coybU/dr+KupNlqpwK65y0CMNAqlYZccJ5LxT5Efj/Hu+L/6csoHeo4
sg6jqOUL9DG9f8KHLh1ggPi5UIE6k4Zkjb4CbMyA+2AqcUdWEYexXMH54wVGlkD9
kwIDAQAB
-----END PUBLIC KEY-----'

# Help text
show_help() {
    cat << EOF
Usage: $0 [OPTIONS] <binary_file>

Patches Mattermost Enterprise Edition binary to bypass license validation.

Supports x86-64 and ARM64 (aarch64) binaries; the architecture is detected
from the ELF header. The license verification code differs between Mattermost
versions, so this script contains a table of known byte patterns per
architecture. The version is auto-detected by searching for each pattern; the
one that matches exactly once is used.

The table entries are version *ranges*: a pattern that still matches a newer
release than the one it was written for keeps working, so the release is read
from the binary itself (its embedded build version) and reported as the
detected version. The pattern range is only used for matching.

Options:
  -h, --help     Show this help message and exit
  -q, --quiet    Suppress non-error output
  --dry-run      Show what would be patched without making changes
  --list         List supported Mattermost versions and exit
  --method <m>   How to patch: 'branch' (default) or 'keyswap'
  --keyswap      Shorthand for --method keyswap

Patch methods:
  branch    Invert the conditional branch after the signature check, so any
            signature is accepted. Needs a per-version byte pattern, but works
            with the license file this repo ships.
  keyswap   Replace the RSA public key embedded in the binary with the one in
            keyswap-key.pem. The signature check still runs, so only licenses
            signed with that private key are accepted - generate them with
            './sign-license.sh <license.json>'. The vendor keys are identical
            across all supported versions, so this needs no pattern table and
            is unaffected by Mattermost code changes.

Exit codes:
  0  Success
  1  General error
  2  Missing dependencies
  3  No binary file specified
  4  File does not exist
  5  No write permission
  6  Already patched
  7  Pattern not found (unsupported version)
  8  Invalid offset calculated
  9  Failed to write patch
  10 Patch verification failed
  11 Not an ELF binary
  12 Unsupported architecture

EOF
}

# Pattern table: "versions|pattern|offset|replacement"
#   versions    Human-readable list of Mattermost versions this pattern covers
#   pattern     Hex bytes of the license check, "??" = any single byte
#   offset      Byte offset into the pattern of the byte to modify
#   replacement Hex value to write at that byte (e.g. 0F 84 jz -> 0F 85 jnz)
#
# x86-64: the check is 'test rax,rax; jz' right after the rsa.VerifyPKCS1v15
# call; the 0F 84 (jz) is inverted to 0F 85 (jnz).
#
# ARM64: the check is a 'cbz' (compare-and-branch-on-zero) on the returned
# error right after the call. ARM64 is little-endian, so the opcode's high
# byte is the LAST byte of the 4-byte instruction: cbz = ?? ?? ?? B4,
# cbnz = ?? ?? ?? B5. The B4 is inverted to B5.
PATTERNS_X86_64=(
    "5.39|48 8B 84 24 48 01 00 00 48 89 44 24 28 48 C7 44 24 30 00 01 00 00 48 8B 44 24 68 48 89 44 24 38 E8 ?? ?? ?? ?? 48 8B 44 24 40 48 8B 4C 24 48 48 83 7C 24 40 00 0F 84 ?? ?? ?? ??|54|85"
    "6.0-6.6|48 8B 44 24 70 48 89 44 24 38 E8 ?? ?? ?? ?? 48 8B 44 24 40 48 8B 4C 24 48 48 83 7C 24 40 00 0F 84 ?? ?? ?? ??|32|85"
    "6.7-7.10|48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 0A FF D1 48 89 84 24 68 01 00 00 48 89 9C 24 70 01 00 00 88 8C 24 78 01 00 00 48 89 BC 24 80 01 00 00 F2 0F 11 84 24 88 01 00 00 48 89 B4 24 90 01 00 00 4C 89 84 24 98 01 00 00 4C 89 8C 24 A0 01 00 00 4C 89 94 24 A8 01 00 00 48 8B 8C 24 68 01 00 00 48 89 8C 24 40 02 00 00 0F 10 84 24 70 01 00 00 0F 11 84 24 48 02 00 00 0F 10 84 24 80 01 00 00 0F 11 84 24 58 02 00 00 0F 10 84 24 90 01 00 00 0F 11 84 24 68 02 00 00 0F 10 84 24 A0 01 00 00 0F 11 84 24 78 02 00 00 48 8D 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8|4|85"
    "8.0-9.7|48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 0A FF D1 48 89 84 24 68 01 00 00 48 89 9C 24 70 01 00 00 88 8C 24 78 01 00 00 48 89 BC 24 80 01 00 00 F2 0F 11 84 24 88 01 00 00 48 89 B4 24 90 01 00 00 4C 89 84 24 98 01 00 00 4C 89 8C 24 A0 01 00 00 4C 89 94 24 A8 01 00 00 48 8B 8C 24 68 01 00 00 48 89 8C 24 40 02 00 00 0F 10 84 24 70 01 00 00 0F 11 84 24 48 02 00 00 0F 10 84 24 80 01 00 00 0F 11 84 24 58 02 00 00 0F 10 84 24 90 01 00 00 0F 11 84 24 68 02 00 00 0F 10 84 24 A0 01 00 00 0F 11 84 24 78 02 00 00 48 8D 05 ?? ?? ?? ?? E8|4|85"
    "9.8-11.7|48 89 C1 48 8B 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 53|19|75"
    "11.8-11.9|48 85 C0 0F 84 ?? ?? ?? ?? 44 0F 11 BC 24 ?? ?? ?? ?? 74 04 48 8B 40 08 48 89 84 24 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? BB 15 00 00 00|4|85"
    "11.10-12.1|E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 89 9C 24 B8 01 00 00 48 89 44 24 70|9|85"
)

# ARM64 (aarch64) patterns. Note that Mattermost only ships ARM64 enterprise
# builds starting with 6.1 (no ARM64 build exists for 5.39/6.0).
# The byte to flip is the cbz -> cbnz opcode byte at the END of the 4-byte
# little-endian branch instruction.
PATTERNS_ARM64=(
    "6.0-6.6|E0 03 78 B2 E0 1F 00 F9 E0 37 40 F9 E0 23 00 F9 ?? ?? ?? ?? E0 27 40 F9 E1 2B 40 F9 E2 27 40 F9 ?? ?? ?? B4|35|B5"
    "6.7-9.7|E7 2F 40 F9 E1 0B 40 B2 E2 03 00 AA E0 AB 40 F9 ?? ?? ?? ?? ?? ?? ?? B4|23|B5"
    "9.8-11.6|E7 2B 40 F9 E1 0B 40 B2 E2 03 00 AA E0 A7 40 F9 ?? ?? ?? ?? ?? ?? ?? B4|23|B5"
    "11.7|E7 2B 40 F9 E1 0B 40 B2 E2 03 00 AA E0 B7 40 F9 ?? ?? ?? ?? ?? ?? ?? B4|23|B5"
    "11.8-11.9|E7 2F 40 F9 E1 0B 40 B2 E2 03 00 AA E0 BF 40 F9 ?? ?? ?? ?? ?? ?? ?? B4|23|B5"
    "11.10-12.1|E8 33 40 F9 E0 DF 40 F9 E1 37 40 F9 E2 3B 40 F9 ?? ?? ?? ?? ?? ?? ?? B4|23|B5"
)

# List supported versions
list_versions() {
    echo "Supported Mattermost versions:"
    echo "x86-64:"
    for entry in "${PATTERNS_X86_64[@]}"; do
        versions="${entry%%|*}"
        echo "  - $versions"
    done
    echo "ARM64 (aarch64):"
    for entry in "${PATTERNS_ARM64[@]}"; do
        versions="${entry%%|*}"
        echo "  - $versions"
    done
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --list)
            list_versions
            exit 0
            ;;
        --keyswap)
            METHOD="keyswap"
            shift
            ;;
        --method)
            [ $# -ge 2 ] || { echo "Error: --method requires an argument." >&2; exit 1; }
            METHOD="$2"
            shift 2
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            echo "Use '$0 --help' for usage information." >&2
            exit 1
            ;;
        *)
            if [ -z "$BINARY_FILE" ]; then
                BINARY_FILE="$1"
            else
                echo "Error: Multiple binary files specified." >&2
                exit 1
            fi
            shift
            ;;
    esac
done

# Helper for conditional output
log() {
    if [ "$QUIET" -eq 0 ]; then
        echo "$@"
    fi
}

# Build a PCRE byte pattern from the hex pattern ("??" -> any byte)
# Note: grep -P treats a literal 0x0a (newline) byte in the pattern as a line
# terminator, which would make such patterns unmatchable. We therefore emit a
# wildcard for any fixed 0x0a byte; the surrounding context keeps the pattern
# specific enough.
# Usage: hex_to_pcre <hex_pattern>
hex_to_pcre() {
    local pattern="$1" token out="" lower
    for token in $pattern; do
        if [ "$token" = "??" ]; then
            out+='[\x00-\xff]'
        else
            lower=$(echo "$token" | LC_ALL=C tr 'A-F' 'a-f')
            if [ "$lower" = "0a" ]; then
                out+='[\x00-\xff]'
            else
                out+="\\x$lower"
            fi
        fi
    done
    echo "$out"
}

# Build a plain regex from the hex pattern for the hexdump fallback.
# Each "??" becomes "." (one hex char pair = one byte).
# Usage: hex_to_regex <hex_pattern>
hex_to_regex() {
    local pattern="$1" token out=""
    for token in $pattern; do
        if [ "$token" = "??" ]; then
            out+='..'
        else
            out+="$(echo "$token" | LC_ALL=C tr 'A-F' 'a-f')"
        fi
    done
    echo "$out"
}

# Replace the byte at a given offset inside a hex pattern
# Usage: pattern_set_byte <hex_pattern> <offset> <value>
pattern_set_byte() {
    local pattern="$1" offset="$2" value="$3"
    local tokens=() i=0
    for token in $pattern; do
        tokens+=("$token")
    done
    tokens[$offset]="$value"
    echo "${tokens[*]}"
}

# Get the byte at a given offset inside a hex pattern
# Usage: pattern_get_byte <hex_pattern> <offset>
pattern_get_byte() {
    local pattern="$1" offset="$2"
    local tokens=() token
    for token in $pattern; do
        tokens+=("$token")
    done
    echo "${tokens[$offset]}"
}

# Read the release version embedded in the binary.
#
# The pattern table only knows version *ranges*, so a newer release that still
# compiles to the same code would be reported under the old label. The binary
# itself knows its exact version: `mattermost version` prints it.
#
# Probing is skipped for the oldest pattern groups (5.39, 6.0-6.6): those
# builds ignore the `version` subcommand and boot a server instead, which
# would block until the timeout and try to reach a database. Their group label
# is exact anyway, so there is nothing to gain.
#
# Prints the version (e.g. "12.0.1"), or nothing if it cannot be determined.
# Usage: probe_binary_version <binary_file> <pattern_group>
probe_binary_version() {
    local binary="$1" group="$2" out="" rc=0
    case "$group" in
        5.39|6.0-6.6) return 0 ;;
    esac
    command -v timeout >/dev/null 2>&1 || return 0

    out=$(cd "$(dirname "$binary")" && timeout 5 "./$(basename "$binary")" version 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ] || return 0

    # "Version: 12.0.1" - take the first line, strip the label.
    printf '%s\n' "$out" \
        | LC_ALL=C awk -F': ' '/^Version: / {print $2; exit}' \
        | LC_ALL=C grep -Ex '[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?' \
        || true
}

# Setup cleanup for temp files
TEMP_FILE=""
FLAT_FILE=""
cleanup() {
    if [ -n "$TEMP_FILE" ] && [ -f "$TEMP_FILE" ]; then
        rm -f "$TEMP_FILE"
    fi
    if [ -n "$FLAT_FILE" ] && [ -f "$FLAT_FILE" ]; then
        rm -f "$FLAT_FILE"
    fi
}
trap cleanup EXIT

# Check for required dependencies
DEPENDENCIES=(xxd grep awk dd tr mktemp file fold)
MISSING_DEPS=()

for dep in "${DEPENDENCIES[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "Error: The following required commands are not installed:"
    for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep"
    done
    echo "Please install them and try again."
    exit 2
fi

# Check if grep supports PCRE (-P). BusyBox grep does not.
if echo "x" | grep -qP "x" 2>/dev/null; then
    HAVE_PCRE=1
else
    HAVE_PCRE=0
    log "Warning: grep does not support -P (PCRE). Falling back to hexdump method (slower)."
    if ! command -v hexdump >/dev/null 2>&1; then
        echo "Error: grep without -P support requires hexdump, which is not installed." >&2
        exit 2
    fi
fi

# Check binary file argument exists and is writable
if [ -z "$BINARY_FILE" ]; then
    echo "Error: No binary file specified." >&2
    show_help >&2
    exit 3
fi

if [ ! -f "$BINARY_FILE" ]; then
    echo "Error: File '$BINARY_FILE' does not exist." >&2
    exit 4
fi

if [ ! -w "$BINARY_FILE" ]; then
    echo "Error: No write permission for '$BINARY_FILE'." >&2
    exit 5
fi

# Check if file is an ELF binary
FILE_TYPE=$(file -bL "$BINARY_FILE") || {
    echo "Error: Unable to determine file type for '$BINARY_FILE'." >&2
    exit 1
}
if ! echo "$FILE_TYPE" | grep -q "ELF"; then
    echo "Error: '$BINARY_FILE' does not appear to be an ELF binary (detected: $FILE_TYPE)." >&2
    exit 11
fi

# Select the pattern table matching the binary's architecture
if echo "$FILE_TYPE" | grep -q "x86-64"; then
    ARCH="x86-64"
    PATTERNS=("${PATTERNS_X86_64[@]}")
elif echo "$FILE_TYPE" | grep -q "ARM aarch64"; then
    ARCH="arm64"
    PATTERNS=("${PATTERNS_ARM64[@]}")
else
    echo "Error: Unsupported architecture (detected: $FILE_TYPE)." >&2
    echo "Supported architectures: x86-64 and ARM aarch64." >&2
    exit 1
fi
log "Detected architecture: $ARCH"

# ---------------------------------------------------------------------------
# keyswap: replace the embedded RSA license public key instead of flipping the
# branch. The signature check keeps running, so only licenses signed with
# keyswap-key.pem are accepted.
# ---------------------------------------------------------------------------

# The PEM keys span many lines, and `grep -F` treats a newline in the pattern as
# a pattern separator (it would match each PEM line separately). So both the
# binary and the needle are flattened - 0x0a -> 0x0d - which is a 1:1 byte
# mapping that keeps offsets valid, and every hit is then re-checked against the
# raw bytes so a genuine 0x0d cannot produce a false positive.
FLAT_FILE=""

flatten_0a() {
    printf '%s' "$1" | tr '\n' '\r'
}

prepare_flat_copy() {
    FLAT_FILE=$(mktemp) || {
        echo "Error: failed to create a temporary file (is TMPDIR writable and not full?)." >&2
        exit 1
    }
    if ! tr '\n' '\r' < "$BINARY_FILE" > "$FLAT_FILE"; then
        echo "Error: Failed to prepare '$BINARY_FILE' for search." >&2
        exit 1
    fi
}

# Print the byte offsets of every genuine occurrence of a (multi-line) needle.
# Usage: find_occurrences <needle>
find_occurrences() {
    local needle="$1" flat_needle off raw
    flat_needle=$(flatten_0a "$needle")

    while IFS= read -r off; do
        [ -n "$off" ] || continue
        raw=$(dd if="$BINARY_FILE" bs=1 skip="$off" count=${#needle} 2>/dev/null)
        [ "$raw" = "$needle" ] && printf '%s\n' "$off"
    done < <(LC_ALL=C grep -aboF -- "$flat_needle" "$FLAT_FILE" 2>/dev/null | cut -d: -f1)
    return 0
}

# Replace every occurrence of the vendor key with ours, then read back.
# Usage: keyswap_replace <vendor_key> <our_key> <label>
keyswap_replace() {
    local vendor="$1" ours="$2" label="$3"
    local off got replaced=0

    while IFS= read -r off; do
        [ -n "$off" ] || continue
        if [ "$DRY_RUN" -eq 1 ]; then
            log "Dry run: would replace $label key at offset 0x$(printf '%x' "$off")"
            replaced=$((replaced + 1))
            continue
        fi
        if ! printf '%s' "$ours" | dd of="$BINARY_FILE" bs=1 seek="$off" conv=notrunc >/dev/null 2>&1; then
            echo "Error: Failed to write $label key at offset 0x$(printf '%x' "$off")." >&2
            exit 9
        fi
        got=$(dd if="$BINARY_FILE" bs=1 skip="$off" count=${#ours} 2>/dev/null)
        if [ "$got" != "$ours" ]; then
            echo "Error: Read-back mismatch for the $label key at offset 0x$(printf '%x' "$off")." >&2
            exit 10
        fi
        log "Replaced $label key at offset 0x$(printf '%x' "$off")"
        replaced=$((replaced + 1))
    done < <(find_occurrences "$vendor")

    printf '%s' "$replaced"
}

run_keyswap() {
    local prod_count test_count our_count total

    # The key pair lives next to this script and is created on first use, so
    # patching and signing always share it.
    local key_file
    key_file="$(dirname "$0")/keyswap-key.pem"
    if [ ! -f "$key_file" ] && command -v openssl >/dev/null 2>&1; then
        if openssl genrsa -out "$key_file" 2048 >/dev/null 2>&1; then
            chmod 600 "$key_file"
            log "Generated a new signing key: $key_file"
        fi
    fi
    if [ -f "$key_file" ] && command -v openssl >/dev/null 2>&1; then
        local derived
        derived=$(openssl rsa -in "$key_file" -pubout 2>/dev/null | sed '/^$/d' || true)
        if [ -n "$derived" ]; then
            if [ "$derived" != "$OUR_KEY" ]; then
                log "Using the public key derived from $key_file"
            fi
            OUR_KEY="$derived"
        fi
    fi

    prepare_flat_copy
    log "Searching for the embedded license public key"

    prod_count=$(find_occurrences "$VENDOR_KEY_PROD" | wc -l)
    test_count=$(find_occurrences "$VENDOR_KEY_TEST" | wc -l)
    our_count=$(find_occurrences "$OUR_KEY" | wc -l)

    if [ "$prod_count" -eq 0 ] && [ "$test_count" -eq 0 ]; then
        if [ "$our_count" -ge 1 ]; then
            log "Binary appears to already be patched (our public key is present)."
            exit 6
        fi
        echo "Error: No Mattermost license public key found in '$BINARY_FILE'." >&2
        echo "This binary may not be a Mattermost server build." >&2
        exit 7
    fi

    if [ "$prod_count" -eq 0 ]; then
        echo "Error: The production license key was not found, but the test key was" >&2
        echo "($test_count occurrence(s)). Refusing to patch a partially recognised binary." >&2
        exit 7
    fi

    log "Production key: $prod_count occurrence(s)"
    if [ "$test_count" -gt 0 ]; then
        log "Test key: $test_count occurrence(s)"
    else
        log "Test key: not present (pre-8.0 layout)"
    fi

    total=$((prod_count + test_count))

    keyswap_replace "$VENDOR_KEY_PROD" "$OUR_KEY" "production" >/dev/null
    if [ "$test_count" -gt 0 ]; then
        keyswap_replace "$VENDOR_KEY_TEST" "$OUR_KEY" "test" >/dev/null
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        log "Dry run: would replace $total key(s)."
        log "No changes made to '$BINARY_FILE'."
        exit 0
    fi

    log "License public key replaced ($total occurrence(s))."
    log "Sign a license with: $(dirname "$0")/sign-license.sh <license.json>"
}

if [ "$METHOD" = "keyswap" ]; then
    run_keyswap
    exit 0
elif [ "$METHOD" != "branch" ]; then
    echo "Error: Unknown patch method '$METHOD' (expected 'branch' or 'keyswap')." >&2
    exit 1
fi

# Prepare a searchable copy of the binary.
# Fast path: strip newlines (1:1 byte mapping, preserves offsets) so grep -P
# can match byte sequences that would otherwise span line boundaries.
TEMP_FILE=$(mktemp) || {
    echo "Error: failed to create a temporary file (is TMPDIR writable and not full?)." >&2
    exit 1
}
if [ "$HAVE_PCRE" -eq 1 ]; then
    log "Preparing binary for search"
    if ! tr '\n' '\r' < "$BINARY_FILE" > "$TEMP_FILE"; then
        echo "Error: Failed to prepare '$BINARY_FILE' for search (unreadable file, or no space left in TMPDIR)." >&2
        exit 1
    fi
else
    log "Dumping hexcode of original binary"
    # Fold the hexdump into lines so grep processes short lines: a single
    # 2x-file-size line would exhaust memory on constrained systems and is
    # orders of magnitude slower. Byte offsets stay valid because grep -b
    # reports absolute file offsets; search_pattern() corrects for the
    # inserted newlines.
    if ! hexdump -ve '1/1 "%.2x"' "$BINARY_FILE" | fold -w 65536 > "$TEMP_FILE"; then
        echo "Error: Failed to hexdump '$BINARY_FILE' (unreadable file, or no space left in TMPDIR)." >&2
        exit 1
    fi
fi

if [ ! -s "$TEMP_FILE" ]; then
    echo "Error: Failed to extract binary data (empty output)." >&2
    exit 1
fi

# Search a pattern in the binary.
# Prints one "<byte_offset>" per match (byte offset into the original file).
#
# Patterns that contain a literal 0x0a byte are searched in the prepared
# newline-flattened copy (grep cannot match across line boundaries). All
# other patterns are searched in the raw binary: grep then processes short
# lines instead of one giant line, which keeps memory usage low even for
# huge binaries. (grep -P buffers the whole flattened line, which can
# exhaust memory on constrained systems and fail silently.)
#
# Usage: search_pattern <hex_pattern> <pcre_pattern> <plain_regex> <hex_mode(0|1)>
search_pattern() {
    local hex_pattern="$1" pcre="$2" plain="$3" hex_mode="$4"
    local search_file="$BINARY_FILE" result rc errf

    if [ "$hex_mode" -eq 1 ] || echo "$hex_pattern" | tr ' ' '\n' | grep -qxi '0a'; then
        search_file="$TEMP_FILE"
    fi

    errf=$(mktemp) || { echo "Error: failed to create a temporary file (is TMPDIR writable and not full?)." >&2; exit 1; }
    if [ "$hex_mode" -eq 1 ]; then
        # The hexdump is folded at 65536 chars per line. Unfold its offsets:
        # true_offset = p - floor((p + 1) / 65537).
        if result=$(LC_ALL=C grep -Eo -b "$plain" "$search_file" 2>"$errf" | LC_ALL=C awk -F: 'NF {print $1 - int(($1 + 1) / 65537)}'); then
            rc=0
        else
            rc=$?
        fi
    else
        # grep -o writes "<offset>:<raw match>". The match can contain NUL
        # bytes, so extract the offset before command substitution: Bash
        # cannot store NUL bytes and would otherwise warn while silently
        # dropping them. (With pipefail the pipeline still reports grep's
        # exit status, so the error handling below keeps working.)
        if result=$(LC_ALL=C grep -aboP "$pcre" "$search_file" 2>"$errf" | LC_ALL=C awk -F: 'NF {print $1}'); then
            rc=0
        else
            rc=$?
        fi
        # A pattern whose wildcard bytes span a literal 0x0a byte in the
        # binary can never match in the raw file (grep cannot match across
        # line boundaries). If the raw search found nothing, retry on the
        # newline-flattened copy before giving up on this pattern.
        if [ "$rc" -eq 1 ] && [ "$search_file" != "$TEMP_FILE" ]; then
            result=$(LC_ALL=C grep -aboP "$pcre" "$TEMP_FILE" 2>"$errf" | LC_ALL=C awk -F: 'NF {print $1}'); rc=$?
        fi
    fi

    if [ "$rc" -eq 2 ]; then
        echo "Warning: grep failed on '$search_file' ($(cat "$errf")), skipping this pattern" >&2
        result=""
    fi
    rm -f "$errf"
    printf '%s\n' "$result"
}

log "Searching for license validation code inside LicenseValidatorImpl.ValidateLicense()"

FOUND_PATTERN_INDEX=""
FOUND_MATCH_COUNT=0
FOUND_OFFSET=""
ANY_PATCHED=0

for idx in "${!PATTERNS[@]}"; do
    entry="${PATTERNS[$idx]}"
    IFS='|' read -r versions pattern offset replacement <<< "$entry"

    search_pcre=$(hex_to_pcre "$pattern")
    search_plain=$(hex_to_regex "$pattern")
    patched_pattern=$(pattern_set_byte "$pattern" "$offset" "$replacement")
    patched_pcre=$(hex_to_pcre "$patched_pattern")
    patched_plain=$(hex_to_regex "$patched_pattern")

    patched_matches=$(search_pattern "$patched_pattern" "$patched_pcre" "$patched_plain" "$((1 - HAVE_PCRE))")
    if [ -n "$patched_matches" ]; then
        ANY_PATCHED=1
    fi

    matches=$(search_pattern "$pattern" "$search_pcre" "$search_plain" "$((1 - HAVE_PCRE))")
    count=0
    first=""
    for off in $matches; do
        count=$((count + 1))
        [ -z "$first" ] && first="$off"
    done

    if [ "$count" -gt 0 ]; then
        log "Pattern for $versions: $count match(es)"
    fi

    if [ "$count" -eq 1 ] && [ -z "$FOUND_PATTERN_INDEX" ]; then
        FOUND_PATTERN_INDEX="$idx"
        FOUND_OFFSET="$first"
        FOUND_MATCH_COUNT=1
    elif [ "$count" -eq 1 ] && [ -n "$FOUND_PATTERN_INDEX" ]; then
        # More than one pattern matched: abort rather than guess.
        echo "Error: Multiple patterns matched the binary. This is unexpected and could" >&2
        echo "patch the wrong code. Please report this at:" >&2
        echo "  https://github.com/WasserEsser/mattermost-patched-enterprise/issues" >&2
        exit 1
    elif [ "$count" -gt 1 ]; then
        echo "Error: Pattern for $versions matched $count times. Cannot determine which" >&2
        echo "occurrence is the license check. Please report this at:" >&2
        echo "  https://github.com/WasserEsser/mattermost-patched-enterprise/issues" >&2
        exit 1
    fi
done

if [ "$ANY_PATCHED" -eq 1 ]; then
    log "Binary appears to already be patched (conditional branch already inverted)."
    exit 6
fi

if [ -z "$FOUND_PATTERN_INDEX" ]; then
    echo "Call not found!" >&2
    echo "Your Mattermost version may not be supported yet." >&2
    echo "Supported versions:" >&2
    for entry in "${PATTERNS[@]}"; do
        echo "  - ${entry%%|*}" >&2
    done
    echo "If your version is not listed, update this script or report the issue at:" >&2
    echo "  https://github.com/WasserEsser/mattermost-patched-enterprise/issues" >&2
    exit 7
fi

entry="${PATTERNS[$FOUND_PATTERN_INDEX]}"
IFS='|' read -r versions pattern offset replacement <<< "$entry"

# Fast path offsets are already in bytes. Hexdump path needs /2.
if [ "$HAVE_PCRE" -eq 1 ]; then
    BYTE_OFFSET=$((FOUND_OFFSET + offset))
else
    BYTE_OFFSET=$((FOUND_OFFSET / 2 + offset))
fi
BYTE_OFFSET_HEX=$(printf "%x" "$BYTE_OFFSET")

if [ "$BYTE_OFFSET" -lt 0 ]; then
    echo "Error: Calculated offset is before the start of the file!" >&2
    exit 8
fi

ORIGINAL_BYTE=$(pattern_get_byte "$pattern" "$offset")
if [ "$ORIGINAL_BYTE" = "??" ]; then
    echo "Error: Pattern offset $offset for $versions points at a wildcard byte." >&2
    exit 8
fi

# The table label is a range; prefer the exact release the binary reports.
BINARY_VERSION=$(probe_binary_version "$BINARY_FILE" "$versions")
if [ -n "$BINARY_VERSION" ]; then
    log "Detected version: $BINARY_VERSION (pattern group $versions)"
else
    log "Detected version: $versions"
fi
log "Call found, inverting conditional branch at offset 0x$BYTE_OFFSET_HEX ($ORIGINAL_BYTE -> $replacement)"

if [ "$DRY_RUN" -eq 1 ]; then
    log "Dry run: Would patch byte at offset 0x$BYTE_OFFSET_HEX from 0x$ORIGINAL_BYTE to 0x$replacement"
    log "No changes made to '$BINARY_FILE'."
    exit 0
fi

# Write the patch byte. The version probe executes the binary, and Linux keeps
# a freshly exited executable mapped for a moment (ETXTBSY on write), so retry
# briefly before giving up.
WRITE_OK=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if printf "$replacement" | xxd -r -p | dd of="$BINARY_FILE" bs=1 seek="$BYTE_OFFSET" conv=notrunc > /dev/null 2>&1; then
        WRITE_OK=1
        break
    fi
    sleep 0.2
done

if [ "$WRITE_OK" -ne 1 ]; then
    echo "Error: Failed to write patch to '$BINARY_FILE'." >&2
    exit 9
fi

# Verify the patch was applied
WRITTEN_BYTE=$(dd if="$BINARY_FILE" bs=1 skip="$BYTE_OFFSET" count=1 2>/dev/null | xxd -p) || {
    echo "Error: Failed to read back patched byte at offset 0x$BYTE_OFFSET_HEX for verification." >&2
    exit 1
}
if [ "$(echo "$WRITTEN_BYTE" | tr "A-F" "a-f")" != "$(echo "$replacement" | tr "A-F" "a-f")" ]; then
    echo "Error: Patch verification failed! Expected '$replacement' but found '$WRITTEN_BYTE' at offset 0x$BYTE_OFFSET_HEX." >&2
    exit 10
fi

log "Licensing code patched!"
