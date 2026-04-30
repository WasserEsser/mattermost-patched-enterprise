#!/bin/bash

BINARY_FILE=$1
PATTERN="48 89 C1 48 8B 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 53"
REPLACEMENT="75"
OFFSET=19

# Check for required dependencies
DEPENDENCIES=(hexdump xxd grep awk dd tr)
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
    exit 1
fi

SEARCH_PATTERN=$(echo "$PATTERN" | tr -d ' ' | tr '?' '.' | tr 'A-Z' 'a-z')

echo "Dumping hexcode of original binary"

hexdump -ve '1/1 "%.2x"' "$BINARY_FILE" > temp_hex_dump

echo "Searching for rsa.VerifyPKCS1v15 call inside LicenseValidatorImpl.ValidateLicense()"

FOUND_OFFSET=$(grep -Eo -b "$SEARCH_PATTERN" temp_hex_dump | awk -F: '{print $1}' | head -n 1)

if [ -z "$FOUND_OFFSET" ]; then
  echo "Call not found!"
  rm temp_hex_dump
  exit 1
fi

BYTE_OFFSET=$((FOUND_OFFSET / 2 + OFFSET))
BYTE_OFFSET_HEX=$(printf "%x" "$BYTE_OFFSET")

if [ "$BYTE_OFFSET" -lt 0 ]; then
  echo "Error: Calculated offset is before the start of the file!"
  rm temp_hex_dump
  exit 1
fi

echo "Call found, patching jz at offset 0x$BYTE_OFFSET_HEX with jnz"

printf "$REPLACEMENT" | xxd -r -p | dd of="$BINARY_FILE" bs=1 seek="$BYTE_OFFSET" conv=notrunc > /dev/null 2>&1

rm temp_hex_dump

echo "Licensing code patched!"