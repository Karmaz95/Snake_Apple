#!/usr/bin/env python3
import os
import sys
import argparse
import struct

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

# Determine system endianness
system_endianness = sys.byteorder  # "little" or "big"

def determine_file_endianness(magic):
    """Determine the endianness of the file based on the magic number and system endianness."""
    if magic in (MACHO_CIGAM, MACHO_CIGAM_64, FAT_CIGAM):
        return '<'  # Little-endian file
    else:
        return '>'  # Big-endian file

def get_macho_info(file_path, only_arm64):
    """Check if a file is a Mach-O binary or FAT binary and optionally filter for ARM64."""
    with open(file_path, 'rb') as f:
        file_size = os.path.getsize(file_path)
        # Read the first 4 bytes to check the magic number
        magic_data = f.read(4)
        if len(magic_data) < 4:
            return None
        
        magic = struct.unpack(">I", magic_data)[0]
        
        # Determine file endianness
        endian = determine_file_endianness(magic)

        # Check if the file is a single-architecture Mach-O binary
        if magic in (MACHO_MAGIC, MACHO_MAGIC_64, MACHO_CIGAM, MACHO_CIGAM_64):
            header_data = f.read(12)  # Read CPU type, subtype, and file type fields

            if len(header_data) < 12:
                return "UNKNOWN"

            cpu_type, cpu_subtype, file_type = struct.unpack(endian + "Iii", header_data)
            
            if only_arm64 and cpu_type != CPU_TYPE_ARM64:
                return None
            
            return FILE_TYPE_MAP.get(file_type, "UNKNOWN")

        # Check if the file is a FAT binary
        elif magic in (FAT_MAGIC, FAT_CIGAM):
            num_archs = struct.unpack(endian + "I", f.read(4))[0]
            
            # Process each architecture entry in FAT binary
            for _ in range(num_archs):
                arch_info = f.read(20)  # Read architecture info (CPU type, subtype, offset, size, align)
                if len(arch_info) < 20:
                    continue

                cpu_type, _, offset, _, _ = struct.unpack(endian + "IIIII", arch_info)

                # Ensure offset is within file bounds
                if offset >= file_size:
                    continue  # Skip this architecture if offset is beyond file size
                
                # Move to offset to read Mach-O header for this architecture
                current_pos = f.tell()
                f.seek(offset)
                
                # Read Mach-O magic and check for valid Mach-O binary
                macho_magic_data = f.read(4)
                if len(macho_magic_data) < 4:
                    f.seek(current_pos)
                    continue
                
                macho_magic = struct.unpack(">I", macho_magic_data)[0]
                
                # Determine endianness for this architecture
                arch_endian = determine_file_endianness(macho_magic)
                
                if macho_magic in (MACHO_MAGIC, MACHO_MAGIC_64, MACHO_CIGAM, MACHO_CIGAM_64):
                    arch_header_data = f.read(12)
                    
                    if len(arch_header_data) < 12:
                        f.seek(current_pos)
                        continue
                    
                    _, _, file_type = struct.unpack(arch_endian + "Iii", arch_header_data)
                    
                    if only_arm64 and cpu_type != CPU_TYPE_ARM64:
                        f.seek(current_pos)
                        continue
                    
                    file_type_name = FILE_TYPE_MAP.get(file_type, "UNKNOWN")
                    return file_type_name

                # Reset to the position in the FAT header
                f.seek(current_pos)

        return None

def process_directory(root, files, recursive, only_arm64):
    """Process all files in the specified directory."""
    for file_name in files:
        file_path = os.path.abspath(os.path.join(root, file_name))
        
        # Check if the file is a Mach-O binary or FAT binary
        file_type = get_macho_info(file_path, only_arm64)
        if file_type:
            print(f"{file_type}:{file_path}")

def process_files(directory_path, recursive, only_arm64):
    """Walk through the directory and process files."""
    for root, dirs, files in os.walk(directory_path):
        process_directory(root, files, recursive, only_arm64)
        if not recursive:
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

    process_files(directory_path, recursive=args.recursive, only_arm64=args.only_arm64)
