#!/usr/bin/env python3
import os
import sys
import argparse
import struct
from concurrent.futures import ThreadPoolExecutor

class MachOFileFinder:
    # Mach-O and FAT magic numbers
    MACHO_MAGIC = 0xFEEDFACE
    MACHO_MAGIC_64 = 0xFEEDFACF
    MACHO_CIGAM = 0xCEFAEDFE
    MACHO_CIGAM_64 = 0xCFFAEDFE
    FAT_MAGIC = 0xCAFEBABE
    FAT_CIGAM = 0xBEBAFECA

    # Supported Mach-O file types
    FILE_TYPE_MAP = {
        0x1: "OBJECT",
        0x2: "EXECUTE",
        0x3: "FVMLIB",
        0x4: "CORE",
        0x5: "PRELOAD",
        0x6: "DYLIB",
        0x7: "DYLINKER",
        0x8: "BUNDLE",
        0x9: "DYLIB_STUB",
        0xA: "DSYM",
        0xB: "KEXT_BUNDLE",
    }

    # CPU type constant for ARM64
    CPU_TYPE_ARM64 = 0x0100000C

    def __init__(self, directory_path, recursive=False, only_arm64=False):
        self.directory_path = directory_path
        self.recursive = recursive
        self.only_arm64 = only_arm64

    def determineFileEndianness(self, magic):
        """Determine the endianness of the file based on the magic number."""
        if magic in (self.MACHO_CIGAM, self.MACHO_CIGAM_64, self.FAT_CIGAM):
            return '<'  # Little-endian file
        else:
            return '>'  # Big-endian file

    def getMachoInfo(self, file_path):
        """Check if a file is a Mach-O binary or FAT binary and optionally filter for ARM64."""
        try:
            with open(file_path, 'rb') as f:
                file_size = os.path.getsize(file_path)
                # Read the first 4 bytes to check the magic number
                magic_data = f.read(4)
                if len(magic_data) < 4:
                    return None
                
                magic = struct.unpack(">I", magic_data)[0]
                
                # Determine file endianness
                endian = self.determineFileEndianness(magic)

                # Check if the file is a single-architecture Mach-O binary
                if magic in (self.MACHO_MAGIC, self.MACHO_MAGIC_64, self.MACHO_CIGAM, self.MACHO_CIGAM_64):
                    header_data = f.read(12)  # Read CPU type, subtype, and file type fields

                    if len(header_data) < 12:
                        return "UNKNOWN"

                    cpu_type, cpu_subtype, file_type = struct.unpack(endian + "Iii", header_data)
                    
                    if self.only_arm64 and cpu_type != self.CPU_TYPE_ARM64:
                        return None
                    
                    return self.FILE_TYPE_MAP.get(file_type, "UNKNOWN")

                # Check if the file is a FAT binary
                elif magic in (self.FAT_MAGIC, self.FAT_CIGAM):
                    num_archs = struct.unpack(endian + "I", f.read(4))[0]
                    arm64_offset = None

                    # First pass: Find ARM64 architecture if present
                    for _ in range(num_archs):
                        arch_info = f.read(20)  # Read architecture info (CPU type, subtype, offset, size, align)
                        if len(arch_info) < 20:
                            continue

                        cpu_type, _, offset, _, _ = struct.unpack(endian + "IIIII", arch_info)

                        # Validate offset before any further processing to avoid unnecessary reads
                        if offset < 0 or offset >= file_size:
                            continue  # Skip this architecture if offset is invalid

                        if self.only_arm64 and cpu_type == self.CPU_TYPE_ARM64:
                            arm64_offset = offset
                            break  # Stop once we find ARM64

                    # If only_arm64 is specified and no ARM64 architecture was found, skip this file
                    if self.only_arm64 and arm64_offset is None:
                        return None

                    # If ARM64 was found, process only that architecture
                    if arm64_offset is not None:
                        f.seek(arm64_offset)
                        macho_magic_data = f.read(4)
                        if len(macho_magic_data) < 4:
                            return None

                        macho_magic = struct.unpack(">I", macho_magic_data)[0]
                        arch_endian = self.determineFileEndianness(macho_magic)

                        if macho_magic in (self.MACHO_MAGIC, self.MACHO_MAGIC_64, self.MACHO_CIGAM, self.MACHO_CIGAM_64):
                            arch_header_data = f.read(12)
                            if len(arch_header_data) < 12:
                                return None
                            _, _, file_type = struct.unpack(arch_endian + "Iii", arch_header_data)
                            return self.FILE_TYPE_MAP.get(file_type, "UNKNOWN")

                    # If not only_arm64, process all architectures in FAT binary
                    if not self.only_arm64:
                        f.seek(8)  # Seek back to after the FAT magic and num_archs
                        for _ in range(num_archs):
                            arch_info = f.read(20)  # Read architecture info (CPU type, subtype, offset, size, align)
                            if len(arch_info) < 20:
                                continue

                            cpu_type, _, offset, _, _ = struct.unpack(endian + "IIIII", arch_info)

                            # Validate offset before any further processing to avoid unnecessary reads
                            if offset < 0 or offset >= file_size:
                                continue  # Skip this architecture if offset is invalid
                            
                            # Move to offset to read Mach-O header for this architecture
                            f.seek(offset)
                            
                            # Read Mach-O magic and check for valid Mach-O binary
                            macho_magic_data = f.read(4)
                            if len(macho_magic_data) < 4:
                                continue
                            
                            macho_magic = struct.unpack(">I", macho_magic_data)[0]
                            
                            # Determine endianness for this architecture
                            arch_endian = self.determineFileEndianness(macho_magic)
                            
                            if macho_magic in (self.MACHO_MAGIC, self.MACHO_MAGIC_64, self.MACHO_CIGAM, self.MACHO_CIGAM_64):
                                arch_header_data = f.read(12)
                                
                                if len(arch_header_data) < 12:
                                    continue
                                
                                _, _, file_type = struct.unpack(arch_endian + "Iii", arch_header_data)
                                file_type_name = self.FILE_TYPE_MAP.get(file_type, "UNKNOWN")
                                return file_type_name

            return None
        except (IOError, OSError) as e:
            return None

    def processDirectory(self, root, files):
        """Process all files in the specified directory."""
        for file_name in files:
            file_path = os.path.abspath(os.path.join(root, file_name))
            
            # Check if the file is a Mach-O binary or FAT binary
            file_type = self.getMachoInfo(file_path)
            if file_type:
                print(f"{file_type}:{file_path}")

    def processFiles(self):
        """Walk through the directory and process files using threading for faster execution."""
        with ThreadPoolExecutor() as executor:
            for root, dirs, files in os.walk(self.directory_path):
                executor.submit(self.processDirectory, root, files)
                if not self.recursive:
                    break  # Stop recursion if not recursive

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

    finder = MachOFileFinder(directory_path, recursive=args.recursive, only_arm64=args.only_arm64)
    finder.processFiles()
