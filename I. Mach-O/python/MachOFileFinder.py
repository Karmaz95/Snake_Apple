#!/usr/bin/env python3
import os
import magic
import sys
import argparse

# Mapping for known file types based on `python-magic` output strings
FILE_TYPE_MAP = {
    "bundle": "BUNDLE",
    "dSYM companion file": "DSYM",
    "dynamic linker": "DYLINKER",
    "kext bundle": "KEXT_BUNDLE",
    "dynamically linked shared library": "DYLIB",
    "dynamically linked shared library stub": "DYLIB_STUB",
    "preload executable": "PRELOAD",
    "fixed virtual memory shared library": "FVMLIB",
    "core": "CORE",
    "object": "OBJECT",
    "executable": "EXECUTE"
}

class MachOFileFinder:
    '''Class for finding Mach-O binaries in a given directory, with an option to filter for ARM64 architecture only.'''

    def __init__(self, directory_path, recursive=False, only_arm64=False):
        '''Initialize the directory path, recursive flag, and architecture filter.'''
        self.directory_path = directory_path
        self.recursive = recursive
        self.only_arm64 = only_arm64

    def is_mach_o(self, file_path):
        '''Check if a file is a Mach-O binary and optionally filter by ARM64 architecture.'''
        try:
            mime = magic.Magic()
            file_type = mime.from_file(file_path)

            # Check if it's a Mach-O file and filter by ARM64 if needed
            if "Mach-O" in file_type:
                if self.only_arm64 and "arm64" not in file_type:
                    return None
                return file_type
        except Exception:
            pass  # Ignore errors for non-Mach-O files or inaccessible files
        return None

    def map_file_type(self, file_type):
        '''Map the file type string from python-magic to the required output format.'''
        for key, label in FILE_TYPE_MAP.items():
            if key in file_type:
                return label
        return "UNKNOWN"  # Default to UNKNOWN if no known type is found

    def process_directory(self, root, files):
        '''Process all files in the specified directory.'''
        for file_name in files:
            file_path = os.path.abspath(os.path.join(root, file_name))
            file_type = self.is_mach_o(file_path)
            if file_type:
                mapped_type = self.map_file_type(file_type)
                print(f"{mapped_type}:{file_path}")

    def process_files(self):
        '''Process files based on the specified search type.'''
        for root, dirs, files in os.walk(self.directory_path):
            self.process_directory(root, files)
            if not self.recursive:
                break  # Stop if not searching recursively

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find Mach-O binaries in a directory with an option to filter for ARM64.')
    parser.add_argument('path', metavar='PATH', type=str, help='the directory path to search for Mach-O binaries')
    parser.add_argument('-r', '--recursive', action='store_true', help='search recursively (default: false)')
    parser.add_argument('--only_arm64', action='store_true', help='only match ARM64 architecture binaries')

    args = parser.parse_args()
    directory_path = args.path

    if not os.path.isdir(directory_path):
        print(f"Error: {directory_path} is not a valid directory.")
        sys.exit(1)

    macho_finder = MachOFileFinder(directory_path, recursive=args.recursive, only_arm64=args.only_arm64)
    macho_finder.process_files()