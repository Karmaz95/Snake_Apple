#!/bin/bash

# This version uses dwarfdump to get the UUIDs for all architectures

# UUID to search for
search_uuid="5B5E7D61-6508-33C9-AC9B-6146AF7200C0"  # Replace with the UUID you're searching for

# Function to check UUIDs using dwarfdump
check_uuid_in_app() {
    app_path=$1
    executable_path="${app_path}/Contents/MacOS/"*

    for exe in $executable_path; do
        # Check if the executable exists
        if [ -f "$exe" ]; then
            # Get the UUIDs for all architectures using dwarfdump
            uuids=$(dwarfdump --uuid "$exe" 2>/dev/null)

            # Check if the search UUID is in the output, case-insensitive
            if echo "$uuids" | grep -qi "$search_uuid"; then
                echo "Found: $app_path"
                return
            fi
        fi
    done
}

# Iterate through all applications in /Applications
for app in /Applications/*.app; do
    if [ -d "$app" ]; then
        check_uuid_in_app "$app"
    fi
done