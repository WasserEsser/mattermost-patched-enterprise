#!/bin/bash
set -euo pipefail

# CLI options
QUIET=0
DRY_RUN=0
BINARY_FILE=""

# Help text
show_help() {
    cat << EOF
Usage: $0 [OPTIONS] <binary_file>

Patches Mattermost Enterprise Edition binary to bypass license validation.

The license verification code differs between Mattermost versions, so this
script contains a table of known byte patterns. The version is auto-detected
by searching for each pattern; the one that matches exactly once is used.

Options:
  -h, --help     Show this help message and exit
  -q, --quiet    Suppress non-error output
  --dry-run      Show what would be patched without making changes
  --list         List supported Mattermost versions and exit

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

EOF
}

# Pattern table: "versions|pattern|offset|replacement"
#   versions    Human-readable list of Mattermost versions this pattern covers
#   pattern     Hex bytes of the license check, "??" = any single byte
#   offset      Byte offset into the pattern of the byte to modify
#   replacement Hex value to write at that byte (e.g. 0F 84 jz -> 0F 85 jnz)
PATTERNS=(
    "5.39|48 8B 84 24 48 01 00 00 48 89 44 24 28 48 C7 44 24 30 00 01 00 00 48 8B 44 24 68 48 89 44 24 38 E8 ?? ?? ?? ?? 48 8B 44 24 40 48 8B 4C 24 48 48 83 7C 24 40 00 0F 84 ?? ?? ?? ??|54|85"
    "6.0-6.6|48 8B 44 24 70 48 89 44 24 38 E8 ?? ?? ?? ?? 48 8B 44 24 40 48 8B 4C 24 48 48 83 7C 24 40 00 0F 84 ?? ?? ?? ??|32|85"
    "6.7-7.10|48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 0A FF D1 48 89 84 24 68 01 00 00 48 89 9C 24 70 01 00 00 88 8C 24 78 01 00 00 48 89 BC 24 80 01 00 00 F2 0F 11 84 24 88 01 00 00 48 89 B4 24 90 01 00 00 4C 89 84 24 98 01 00 00 4C 89 8C 24 A0 01 00 00 4C 89 94 24 A8 01 00 00 48 8B 8C 24 68 01 00 00 48 89 8C 24 40 02 00 00 0F 10 84 24 70 01 00 00 0F 11 84 24 48 02 00 00 0F 10 84 24 80 01 00 00 0F 11 84 24 58 02 00 00 0F 10 84 24 90 01 00 00 0F 11 84 24 68 02 00 00 0F 10 84 24 A0 01 00 00 0F 11 84 24 78 02 00 00 48 8D 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8|4|85"
    "8.0-9.7|48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 0A FF D1 48 89 84 24 68 01 00 00 48 89 9C 24 70 01 00 00 88 8C 24 78 01 00 00 48 89 BC 24 80 01 00 00 F2 0F 11 84 24 88 01 00 00 48 89 B4 24 90 01 00 00 4C 89 84 24 98 01 00 00 4C 89 8C 24 A0 01 00 00 4C 89 94 24 A8 01 00 00 48 8B 8C 24 68 01 00 00 48 89 8C 24 40 02 00 00 0F 10 84 24 70 01 00 00 0F 11 84 24 48 02 00 00 0F 10 84 24 80 01 00 00 0F 11 84 24 58 02 00 00 0F 10 84 24 90 01 00 00 0F 11 84 24 68 02 00 00 0F 10 84 24 A0 01 00 00 0F 11 84 24 78 02 00 00 48 8D 05 ?? ?? ?? ?? E8|4|85"
    "9.8-11.7|48 89 C1 48 8B 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 53|19|75"
    "11.8-11.9|48 85 C0 0F 84 ?? ?? ?? ?? 44 0F 11 BC 24 ?? ?? ?? ?? 74 04 48 8B 40 08 48 89 84 24 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? BB 15 00 00 00|4|85"
    "11.10|48 85 C0 0F 84 ?? ?? ?? ?? 48 89 9C 24 B8 01 00 00 48 89 44 24 70|4|85"
)

# List supported versions
list_versions() {
    echo "Supported Mattermost versions:"
    for entry in "${PATTERNS[@]}"; do
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
            lower=$(echo "$token" | tr 'A-F' 'a-f')
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
            out+="$(echo "$token" | tr 'A-F' 'a-f')"
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

# Setup cleanup for temp files
TEMP_FILE=""
cleanup() {
    if [ -n "$TEMP_FILE" ] && [ -f "$TEMP_FILE" ]; then
        rm -f "$TEMP_FILE"
    fi
}
trap cleanup EXIT

# Check for required dependencies
DEPENDENCIES=(xxd grep awk dd tr mktemp file)
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
FILE_TYPE=$(file -b "$BINARY_FILE") || {
    echo "Error: Unable to determine file type for '$BINARY_FILE'." >&2
    exit 1
}
if ! echo "$FILE_TYPE" | grep -q "ELF"; then
    echo "Error: '$BINARY_FILE' does not appear to be an ELF binary (detected: $FILE_TYPE)." >&2
    exit 11
fi

# Prepare a searchable copy of the binary.
# Fast path: strip newlines (1:1 byte mapping, preserves offsets) so grep -P
# can match byte sequences that would otherwise span line boundaries.
TEMP_FILE=$(mktemp)
if [ "$HAVE_PCRE" -eq 1 ]; then
    log "Preparing binary for search"
    if ! tr '\n' '\r' < "$BINARY_FILE" > "$TEMP_FILE"; then
        echo "Error: Failed to read binary file '$BINARY_FILE'." >&2
        exit 1
    fi
else
    log "Dumping hexcode of original binary"
    if ! hexdump -ve '1/1 "%.2x"' "$BINARY_FILE" > "$TEMP_FILE"; then
        echo "Error: Failed to read binary file '$BINARY_FILE'." >&2
        exit 1
    fi
fi

if [ ! -s "$TEMP_FILE" ]; then
    echo "Error: Failed to extract binary data (empty output)." >&2
    exit 1
fi

# Search a pattern in the prepared file.
# Prints one "<byte_offset>" per match (byte offset into the original file).
# Usage: search_pattern <prepared_file> <pcre_pattern> <plain_regex> <hex_mode(0|1)>
search_pattern() {
    local file="$1" pcre="$2" plain="$3" hex_mode="$4"
    if [ "$hex_mode" -eq 1 ]; then
        LC_ALL=C grep -Eo -b "$plain" "$file" 2>/dev/null || true
    else
        LC_ALL=C grep -aboP "$pcre" "$file" 2>/dev/null || true
    fi | awk -F: '{print $1}'
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

    patched_matches=$(search_pattern "$TEMP_FILE" "$patched_pcre" "$patched_plain" "$((1 - HAVE_PCRE))")
    if [ -n "$patched_matches" ]; then
        ANY_PATCHED=1
    fi

    matches=$(search_pattern "$TEMP_FILE" "$search_pcre" "$search_plain" "$((1 - HAVE_PCRE))")
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
    log "Binary appears to already be patched (jnz instruction found)."
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

log "Detected version: $versions"
log "Call found, patching jz at offset 0x$BYTE_OFFSET_HEX with jnz"

if [ "$DRY_RUN" -eq 1 ]; then
    log "Dry run: Would patch byte at offset 0x$BYTE_OFFSET_HEX from 0x$ORIGINAL_BYTE to 0x$replacement"
    log "No changes made to '$BINARY_FILE'."
    exit 0
fi

if ! printf "$replacement" | xxd -r -p | dd of="$BINARY_FILE" bs=1 seek="$BYTE_OFFSET" conv=notrunc > /dev/null 2>&1; then
    echo "Error: Failed to write patch to '$BINARY_FILE'." >&2
    exit 9
fi

# Verify the patch was applied
WRITTEN_BYTE=$(dd if="$BINARY_FILE" bs=1 skip="$BYTE_OFFSET" count=1 2>/dev/null | xxd -p) || {
    echo "Error: Failed to read back patched byte at offset 0x$BYTE_OFFSET_HEX for verification." >&2
    exit 1
}
if [ "$WRITTEN_BYTE" != "$replacement" ]; then
    echo "Error: Patch verification failed! Expected '$replacement' but found '$WRITTEN_BYTE' at offset 0x$BYTE_OFFSET_HEX." >&2
    exit 10
fi

log "Licensing code patched!"
