#!/bin/bash

# UUID to search for
search_uuid="9A749379-B169-3F21-B2B0-8EAA50D13820"  # Replace with the UUID you're searching for

# Function to check UUIDs using CrimsonUroboros
check_uuid_in_app() {
    app_path=$1

    # Get the UUIDs using CrimsonUroboros
    uuids=$(CrimsonUroboros -b "$app_path" --uuid 2>/dev/null)

    # Check if the search UUID is in the output
    if echo "$uuids" | grep -qi "$search_uuid"; then
        echo "Found: $app_path"
    fi
}

# Iterate through all applications in /Applications
for app in /Applications/*.app; do
    if [ -d "$app" ]; then
        check_uuid_in_app "$app"
    fi
done