#!/bin/bash
# This script checks if a given UUID is present in a list of files using dwarfdump.
# Usage: ./uuid_checker.sh <UUID> <file_list>

# Check if exactly two arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: ./uuid_checker.sh <UUID> <file_list>"
    exit 1
fi

# UUID to search for (first argument)
search_uuid="$1"

# File list (second argument)
file_list="$2"

# Check if the file list exists
if [ ! -f "$file_list" ]; then
    echo "File list not found: $file_list"
    exit 1
fi

# Read each file path from the file list
while IFS= read -r file_path; do
    # Skip empty lines
    if [ -z "$file_path" ]; then
        continue
    fi

    # Use dwarfdump to get UUIDs for all architectures in the file
    uuids=$(dwarfdump --uuid "$file_path" 2>/dev/null)

    # Check if the search UUID is in the output
    if echo "$uuids" | grep -qi "$search_uuid"; then
        echo "Match found in: $file_path"
    fi
done < "$file_list"