#!/bin/bash
# ICC Profile Metadata Extractor
# Extracts structural signature from ICC profile header (first 128 bytes)
# Compatible with icc2txt.zsh approach but self-contained

set -e

# Check if file argument provided
if [ $# -ne 1 ]; then
  echo "Usage: $0 <icc_file>"
  exit 1
fi

ICC_FILE="$1"

if [ ! -f "$ICC_FILE" ]; then
  echo "Error: File not found: $ICC_FILE"
  exit 1
fi

# Check file size (minimum 128 bytes for ICC header)
FILE_SIZE=$(stat -f%z "$ICC_FILE" 2>/dev/null || stat -c%s "$ICC_FILE" 2>/dev/null)
if [ "$FILE_SIZE" -lt 128 ]; then
  echo "Error: File too small (< 128 bytes): $ICC_FILE"
  exit 1
fi

# Extract ICC header fields using dd and hexdump
# Based on ICC specification: http://www.color.org/specification/ICC1v43_2010-12.pdf

# Profile size (bytes 0-3, big-endian)
PROFILE_SIZE=$(dd if="$ICC_FILE" bs=1 count=4 skip=0 2>/dev/null | od -An -t u4 -N4 --endian=big | tr -d ' ')

# Preferred CMM (bytes 4-7, ASCII signature)
CMM=$(dd if="$ICC_FILE" bs=1 count=4 skip=4 2>/dev/null | tr -d '\0' | cat -v)

# Profile version (bytes 8-11, hex)
VERSION=$(dd if="$ICC_FILE" bs=1 count=4 skip=8 2>/dev/null | hexdump -e '4/1 "%02x"')

# Device class (bytes 12-15, ASCII signature)
DEVICE_CLASS=$(dd if="$ICC_FILE" bs=1 count=4 skip=12 2>/dev/null | tr -d '\0' | cat -v)

# Color space (bytes 16-19, ASCII signature)
COLOR_SPACE=$(dd if="$ICC_FILE" bs=1 count=4 skip=16 2>/dev/null | tr -d '\0' | cat -v)

# PCS (bytes 20-23, ASCII signature)
PCS=$(dd if="$ICC_FILE" bs=1 count=4 skip=20 2>/dev/null | tr -d '\0' | cat -v)

# Creation date/time (bytes 24-35, 12 bytes)
CREATION_DATE=$(dd if="$ICC_FILE" bs=1 count=12 skip=24 2>/dev/null | hexdump -e '12/1 "%02x"')

# Magic bytes "acsp" (bytes 36-39)
MAGIC=$(dd if="$ICC_FILE" bs=1 count=4 skip=36 2>/dev/null | hexdump -e '4/1 "%02x"')

# Platform signature (bytes 40-43, ASCII)
PLATFORM=$(dd if="$ICC_FILE" bs=1 count=4 skip=40 2>/dev/null | tr -d '\0' | cat -v)

# Profile flags (bytes 44-47, hex)
FLAGS=$(dd if="$ICC_FILE" bs=1 count=4 skip=44 2>/dev/null | hexdump -e '4/1 "%02x"')

# Device manufacturer (bytes 48-51, ASCII)
MANUFACTURER=$(dd if="$ICC_FILE" bs=1 count=4 skip=48 2>/dev/null | tr -d '\0' | cat -v)

# Device model (bytes 52-55, ASCII)
MODEL=$(dd if="$ICC_FILE" bs=1 count=4 skip=52 2>/dev/null | tr -d '\0' | cat -v)

# Tag count (bytes 128-131, big-endian)
if [ "$FILE_SIZE" -ge 132 ]; then
  TAG_COUNT=$(dd if="$ICC_FILE" bs=1 count=4 skip=128 2>/dev/null | od -An -t u4 -N4 --endian=big | tr -d ' ')
else
  TAG_COUNT=0
fi

# Output JSON
cat << JSON_OUTPUT
{
  "structural_sig": {
    "profile_size": $PROFILE_SIZE,
    "cmm": "$CMM",
    "version": "0x$VERSION",
    "device_class": "$DEVICE_CLASS",
    "color_space": "$COLOR_SPACE",
    "pcs": "$PCS",
    "creation_date": "0x$CREATION_DATE",
    "magic": "0x$MAGIC",
    "platform": "$PLATFORM",
    "flags": "0x$FLAGS",
    "manufacturer": "$MANUFACTURER",
    "model": "$MODEL",
    "tag_count": $TAG_COUNT,
    "actual_file_size": $FILE_SIZE
  }
}
JSON_OUTPUT
