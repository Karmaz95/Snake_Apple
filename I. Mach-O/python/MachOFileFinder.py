#!/usr/bin/env python3
import os
import lief
import sys
import argparse

class MachOFileFinder:
    '''Class for finding Mach-O binaries in a given directory, with an option to filter for ARM64 architecture only.'''

    def __init__(self, directory_path, recursive=False, only_arm64=False):
        '''Constructor to initialize the directory path, recursive flag, and architecture filter.'''
        self.directory_path = directory_path
        self.recursive = recursive
        self.only_arm64 = only_arm64

    def parse_fat_binary(self, binaries):
        '''Function to parse Mach-O files and check for architecture type.
        If only_arm64 is set, it returns only ARM64 binaries; otherwise, it returns the first valid binary.'''
        for binary in binaries:
            if not self.only_arm64 or binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
                return binary
        return None

    def process_directory(self, root, files):
        '''Method to process all files in the specified directory.'''
        for file_name in files:
            file_path = os.path.abspath(os.path.join(root, file_name))
            try:
                binaries = lief.MachO.parse(file_path)
                binary = self.parse_fat_binary(binaries)
                if binary is not None:
                    print(f"{binary.header.file_type.__name__}:{file_path}")
            except:
                pass  # Ignore parsing errors or non-Mach-O files

    def process_files(self):
        '''Method to process files based on the specified search type.'''
        for root, dirs, files in os.walk(self.directory_path):
            self.process_directory(root, files)

            if not self.recursive:
                break  # Break the loop if not searching recursively

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