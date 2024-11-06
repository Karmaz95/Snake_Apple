import struct

# Mach-O magic number for 64-bit
MAGIC_64 = 0xFEEDFACF

# Correct file type codes for each specified Mach-O file type
file_types = {
    "FVMLIB": 0x3,       # MH_FVMLIB
    "PRELOAD": 0x5,      # MH_PRELOAD
    "CORE": 0x4,         # MH_CORE
    "DYLIB_STUB": 0x9,   # MH_DYLIB_STUB
}

def create_macho_file(file_type_name, file_type_code):
    # Updated settings for ARM64 architecture
    magic = MAGIC_64
    cpu_type = 0x100000C  # CPU_TYPE_ARM64
    cpu_subtype = 0x0     # ARM64 subtype
    ncmds = 0             # Number of load commands
    sizeofcmds = 0        # Total size of all load commands
    flags = 0x0           # No special flags

    # Pack the Mach-O header for a 64-bit file
    header = struct.pack(
        "<Iiiiiii",  # Format for Mach-O 64-bit header
        magic,
        cpu_type,
        cpu_subtype,
        file_type_code,
        ncmds,
        sizeofcmds,
        flags
    )

    # Write the header to a new file
    with open(f"{file_type_name}.macho", "wb") as f:
        f.write(header)
        f.write(b'\x00' * 1024)  # Add some padding as placeholder content

# Generate files with the correct headers
for name, code in file_types.items():
    create_macho_file(name, code)
    print(f"Created {name}.macho with ARM64 and file type {hex(code)}")