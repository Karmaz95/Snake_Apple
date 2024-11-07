#!/bin/bash

# Function to determine the Mach-O type based on `file` command output
get_macho_type() {
    local file_path="$1"
    file_info=$(/usr/bin/file "$file_path")  # Ensure full path to `file` for consistency

    if [[ "$file_info" == *"Mach-O"* && "$file_info" == *"bundle"* ]]; then
        echo "BUNDLE_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"core"* ]]; then
        echo "CORE_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"dSYM"* ]]; then
        echo "DSYM_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"dynamically linked shared library stub"* ]]; then
        echo "DYLIB_STUB_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"dynamically linked shared library"* ]]; then
        echo "DYLIB_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"dynamic linker"* ]]; then
        echo "DYLINKER_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"executable"* ]]; then
        echo "EXECUTE_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"fixed virtual memory shared library"* ]]; then
        echo "FVMLIB_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"kext bundle"* ]]; then
        echo "KEXT_BUNDLE_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"object"* ]]; then
        echo "OBJECT_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* && "$file_info" == *"preload executable"* ]]; then
        echo "PRELOAD_type:$file_path"
    elif [[ "$file_info" == *"Mach-O"* ]]; then
        echo "UNKNOWN_type:$file_path"
    fi
}

# Main function to process files recursively in the specified directory
process_directory_recursively() {
    local dir_path="$1"
    
    # Use find to get all files in the directory tree
    find "$dir_path" -type f | while read -r file; do
        get_macho_type "$file"
    done
}

# Check if the directory path is provided as an argument
if [[ "$#" -lt 1 ]]; then
    echo "Usage: $0 <directory_path>"
    exit 1
fi

directory_path="$1"

# Check if the directory exists
if [[ ! -d "$directory_path" ]]; then
    echo "Error: $directory_path is not a valid directory."
    exit 1
fi

# Process files in the directory recursively
process_directory_recursively "$directory_path"

