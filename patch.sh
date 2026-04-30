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

Options:
  -h, --help     Show this help message and exit
  -q, --quiet    Suppress non-error output
  --dry-run      Show what would be patched without making changes

Exit codes:
  0  Success
  1  General error
  2  Missing dependencies
  3  No binary file specified
  4  File does not exist
  5  No write permission
  6  Already patched
  7  Pattern not found
  8  Invalid offset calculated
  9  Failed to write patch
  10 Patch verification failed
  11 Not an ELF binary

EOF
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
PATTERN="48 89 C1 48 8B 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 53"
REPLACEMENT="75"
OFFSET=19

# Setup cleanup for temp files
TEMP_FILE=""
cleanup() {
    if [ -n "$TEMP_FILE" ] && [ -f "$TEMP_FILE" ]; then
        rm -f "$TEMP_FILE"
    fi
}
trap cleanup EXIT

# Check for required dependencies
DEPENDENCIES=(hexdump xxd grep awk dd tr mktemp file)
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

SEARCH_PATTERN=$(echo "$PATTERN" | tr -d ' ' | tr '?' '.' | tr 'A-Z' 'a-z')
PATCHED_PATTERN=$(echo "$PATTERN" | sed 's/74 53/75 53/' | tr -d ' ' | tr '?' '.' | tr 'A-Z' 'a-z')

log "Dumping hexcode of original binary"

TEMP_FILE=$(mktemp)
hexdump -ve '1/1 "%.2x"' "$BINARY_FILE" > "$TEMP_FILE" || {
    echo "Error: Failed to read binary file '$BINARY_FILE'." >&2
    exit 1
}
# Verify temp file has content
if [ ! -s "$TEMP_FILE" ]; then
    echo "Error: Failed to extract hex data from binary (empty output)." >&2
    exit 1
fi

log "Searching for rsa.VerifyPKCS1v15 call inside LicenseValidatorImpl.ValidateLicense()"

# Check if already patched (grep returns 1 for no matches, which is OK; only exit 2 is an error)
PATCHED_OUTPUT=$(grep -Eo -b "$PATCHED_PATTERN" "$TEMP_FILE" 2>/dev/null) || {
    GREP_EXIT=$?
    # Exit code 1 means no matches found (OK), exit code 2 means actual error
    if [ "$GREP_EXIT" -eq 2 ]; then
        echo "Error: Failed to search for existing patch pattern in binary." >&2
        exit 1
    fi
}
# Check if output is non-empty (wc -l on empty string returns 1, not 0)
if [ -n "$PATCHED_OUTPUT" ]; then
    log "Binary appears to already be patched (jnz instruction found)."
    exit 6
fi

# Search for pattern to patch (grep returns 1 for no matches, which is handled below)
MATCH_OUTPUT=$(grep -Eo -b "$SEARCH_PATTERN" "$TEMP_FILE" 2>/dev/null) || {
    GREP_EXIT=$?
    # Exit code 1 means no matches found (handled below), exit code 2 means actual error
    if [ "$GREP_EXIT" -eq 2 ]; then
        echo "Error: Failed to search for patch pattern in binary." >&2
        exit 1
    fi
}
# Count matches (wc -l on empty string returns 1, use grep -c instead)
MATCH_COUNT=$(echo "$MATCH_OUTPUT" | grep -c .)
if [ "$MATCH_COUNT" -gt 1 ]; then
    log "Warning: Found $MATCH_COUNT matches for the pattern. Using the first match."
    log "If patching fails or produces unexpected results, please report this at:"
    log "  https://github.com/<your-repo>/issues"
fi

FOUND_OFFSET=$(echo "$MATCH_OUTPUT" | awk -F: '{print $1}' | head -n 1)

if [ -z "$FOUND_OFFSET" ]; then
  echo "Call not found!" >&2
  exit 7
fi

BYTE_OFFSET=$((FOUND_OFFSET / 2 + OFFSET))
BYTE_OFFSET_HEX=$(printf "%x" "$BYTE_OFFSET")

if [ "$BYTE_OFFSET" -lt 0 ]; then
  echo "Error: Calculated offset is before the start of the file!" >&2
  exit 8
fi

log "Call found, patching jz at offset 0x$BYTE_OFFSET_HEX with jnz"

if [ "$DRY_RUN" -eq 1 ]; then
    log "Dry run: Would patch byte at offset 0x$BYTE_OFFSET_HEX from 0x74 to 0x75"
    log "No changes made to '$BINARY_FILE'."
    exit 0
fi

if ! printf "$REPLACEMENT" | xxd -r -p | dd of="$BINARY_FILE" bs=1 seek="$BYTE_OFFSET" conv=notrunc > /dev/null 2>&1; then
    echo "Error: Failed to write patch to '$BINARY_FILE'." >&2
    exit 9
fi

# Verify the patch was applied
WRITTEN_BYTE=$(dd if="$BINARY_FILE" bs=1 skip="$BYTE_OFFSET" count=1 2>/dev/null | xxd -p) || {
    echo "Error: Failed to read back patched byte at offset 0x$BYTE_OFFSET_HEX for verification." >&2
    exit 1
}
if [ "$WRITTEN_BYTE" != "$REPLACEMENT" ]; then
    echo "Error: Patch verification failed! Expected '$REPLACEMENT' but found '$WRITTEN_BYTE' at offset 0x$BYTE_OFFSET_HEX." >&2
    exit 10
fi

log "Licensing code patched!"