#!/usr/bin/env python3
import os
import lief
import sys
import argparse

class MachOFileFinder:
    '''Class for finding ARM64 Mach-O binaries in a given directory.'''

    def __init__(self, directory_path, recursive=False):
        '''Constructor to initialize the directory path and recursive flag.'''
        self.directory_path = directory_path
        self.recursive = recursive

    def parse_fat_binary(self, binaries):
        '''Function to parse Mach-O file, whether compiled for multiple architectures or just for a single one.
        It returns the ARM64 binary if it exists. If not, it exits the program.'''
        arm64_bin = None
        for binary in binaries:
            if binary.header.cpu_type == lief.MachO.CPU_TYPES.ARM64:
                arm64_bin = binary
        return arm64_bin

    def process_directory(self, root, files):
        '''Method to process all files in the specified directory.'''
        for file_name in files:
            file_path = os.path.abspath(os.path.join(root, file_name))
            try:
                binaries = lief.MachO.parse(file_path)
                binary = self.parse_fat_binary(binaries)
                if binary is not None:
                    print(f"{binary.header.file_type.name}:{file_path}")
            except:
                pass  # Ignore parsing errors or non-Mach-O files

    def process_files(self):
        '''Method to process files based on the specified search type.'''
        for root, dirs, files in os.walk(self.directory_path):
            self.process_directory(root, files)

            if not self.recursive:
                break  # Break the loop if not searching recursively

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find ARM64 Mach-O binaries in a directory.')
    parser.add_argument('path', metavar='PATH', type=str, help='the directory path to search for Mach-O binaries')
    parser.add_argument('-r', '--recursive', action='store_true', help='search recursively (default: false)')

    args = parser.parse_args()
    directory_path = args.path

    if not os.path.isdir(directory_path):
        print(f"Error: {directory_path} is not a valid directory.")
        sys.exit(1)

    macho_finder = MachOFileFinder(directory_path, recursive=args.recursive)
    macho_finder.process_files()
