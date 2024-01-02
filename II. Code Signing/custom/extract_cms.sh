#!/bin/bash

# Path to the binary
binary_path="$1"
cms_sign_out="$2"

# Extract magic bytes offset
binary_in_hex=$(xxd -p -u -c0 "$binary_path")
offset=$(echo -n "$binary_in_hex" | grep -ob 'FADE0B01' | awk -F: 'NR==1{print $1}')

# CMS data starts after the magic bytes and length, so you must add 8B to the offset value.
CMS_offset_in_dec=$(( ($offset / 2) + 8))

# Extract blob length
CMS_length=$(echo -n "$binary_in_hex" | awk 'match($0, /FADE0B01/) { print substr($0, RSTART + RLENGTH, 8) }')

# Extract the CMS Signature from the binary
dd bs=1 skip="$CMS_offset_in_dec" count="0x$CMS_length" if="$binary_path" of="$cms_sign_out" 2>/dev/null
