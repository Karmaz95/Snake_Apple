#!/usr/bin/env python3
import lief
import argparse
import subprocess

class ModifyMachOFlags:
    """Class for modifying Mach-O binary flags and signing the binary."""

    def __init__(self, input_path=None, output_path=None, sign_identity=None):
        """Initialize the ModifyMachOFlags instance with input, output, and signing identity."""
        self.input_path = input_path
        self.output_path = output_path
        self.sign_identity = sign_identity
        self.macho_flags = {
            'NOUNDEFS': 0x1,
            'INCRLINK': 0x2,
            'DYLDLINK': 0x4,
            'BINDATLOAD': 0x8,
            'PREBOUND': 0x10,
            'SPLIT_SEGS': 0x20,
            'LAZY_INIT': 0x40,
            'TWOLEVEL': 0x80,
            'FORCE_FLAT': 0x100,
            'NOMULTIDEFS': 0x200,
            'NOFIXPREBINDING': 0x400,
            'PREBINDABLE': 0x800,
            'ALLMODSBOUND': 0x1000,
            'SUBSECTIONS_VIA_SYMBOLS': 0x2000,
            'CANONICAL': 0x4000,
            'WEAK_DEFINES': 0x8000,
            'BINDS_TO_WEAK': 0x10000,
            'ALLOW_STACK_EXECUTION': 0x20000,
            'ROOT_SAFE': 0x40000,
            'SETUID_SAFE': 0x80000,
            'NO_REEXPORTED_DYLIBS': 0x100000,
            'PIE': 0x200000,
            'DEAD_STRIPPABLE_DYLIB': 0x400000,
            'HAS_TLV_DESCRIPTORS': 0x800000,
            'NO_HEAP_EXECUTION': 0x1000000,
            'APP_EXTENSION_SAFE': 0x02000000,
            'NLIST_OUTOFSYNC_WITH_DYLDINFO': 0x04000000,
            'SIM_SUPPORT': 0x08000000,
            'DYLIB_IN_CACHE': 0x80000000,
        }

    def parseFatBinary(self, binaries, arch):
        """Parse the specified architecture from the given binaries."""
        bin_by_arch = next((bin for bin in binaries if bin.header.cpu_type == arch), None)
        if bin_by_arch is None:
            print(f'The specified Mach-O file is not in {arch} architecture.')
            exit()
        return bin_by_arch

    def modifyMachOFlags(self, flags):
        """Modify Mach-O binary flags based on the provided dictionary of flags and values."""
        try:
            binaries = lief.MachO.parse(self.input_path)
        except Exception as e:
            print(f"An error occurred: {e}")
            exit()

        arch = lief.MachO.CPU_TYPES.ARM64  # Modify the architecture as needed
        binary = self.parseFatBinary(binaries, arch)

        for flag, value in flags.items():
            self.setFlag(binary, flag, value)

        binary.write(self.output_path)

    def signBinary(self):
        """Sign the modified binary using the specified or default identity."""
        if self.sign_identity:
            if self.sign_identity == 'adhoc':
                subprocess.run(["codesign", "-s", "-", "-f", self.output_path], check=True)
            else:
                subprocess.run(["codesign", "-s", self.sign_identity, "-f", self.output_path], check=True)

    def setFlag(self, binary, flag, value):
        """Set or clear the specified flag in the Mach-O binary based on the given value."""
        if value:
            binary.header.flags |= flag
        else:
            binary.header.flags &= ~flag

if __name__ == "__main__":
    default_instance = ModifyMachOFlags()  # Create an instance with default values

    parser = argparse.ArgumentParser(description="Modify the Mach-O binary flags.")
    parser.add_argument('-i', '--input', required=True, help="Path to the Mach-O file.")
    parser.add_argument('-o', '--out', required=True, help="Where to save a modified file.")
    parser.add_argument('--flag', action='append', type=str, help=f"Specify the flag constant name and value (e.g., NO_HEAP_EXECUTION=1). Can be used multiple times. Available flags: \n{', '.join(default_instance.macho_flags.keys())}\n")
    parser.add_argument('--sign_binary', help="Sign binary using specified identity - use : 'security find-identity -v -p codesigning' to get the identity. (default: adhoc)", nargs='?', const='adhoc', metavar='adhoc|identity_number')

    args = parser.parse_args()

    modifier = ModifyMachOFlags(args.input, args.out, args.sign_binary)

    # Process flags provided by the user
    flags = {}
    if args.flag:
        for flag_str in args.flag:
            flag_parts = flag_str.split('=')
            if len(flag_parts) == 2:
                flag_name, flag_value = flag_parts
                flag_name = flag_name.upper()
                if flag_name in modifier.macho_flags:
                    flags[modifier.macho_flags[flag_name]] = int(flag_value)
                else:
                    print(f"Invalid flag constant: {flag_name}")
                    exit()
            else:
                print(f"Invalid flag format: {flag_str}")
                exit()

    modifier.modifyMachOFlags(flags)
    modifier.signBinary()