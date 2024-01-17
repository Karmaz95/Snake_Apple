#!/usr/bin/env python3
import os
import lief


class MachODylibLoadCommandsFinder:
    '''
    Recursively crawl the system and parse Mach-O files to find DYLIB related load commands.
    1. Check if the file is a Mach-O.
    2. List all Load Commands.
    3. Check if any DYLIB-related LC exists.
        LC_LOAD_DYLIB
        LC_ID_DYLIB
        LC_PREBOUND_DYLIB
        LC_LOAD_WEAK_DYLIB
        LC_REEXPORT_DYLIB
        LC_LAZY_LOAD_DYLIB
        LC_LOAD_UPWARD_DYLIB
        LC_RPATH
    4. Print the total Mach-O files analyzed and how many DYLIB-related LCs existed.
    '''
    def __init__(self):
        self.total_files_analyzed = 0
        self.binary_dylibs = {}
        self.dylib_counts = {
            "LC_LOAD_DYLIB" : 0,
            "LC_ID_DYLIB": 0,
            "LC_PREBOUND_DYLIB": 0,
            "LC_LOAD_WEAK_DYLIB": 0,
            "LC_REEXPORT_DYLIB": 0,
            "LC_LAZY_LOAD_DYLIB": 0,
            "LC_LOAD_UPWARD_DYLIB": 0,
            "LC_RPATH": 0,
        }

    def parseDirectory(self, directory_path):
        '''Recursively check if the path is a file. If it is, use checkIfMacho method.'''
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    self.checkIfMacho(file_path)

    def checkIfMacho(self, file_path):
        binaries = lief.MachO.parse(file_path)
        if binaries:
            self.parseFatBinary(binaries, file_path)

    def parseFatBinary(self, binaries, file_path):
        for binary in binaries:
            if binary.header.cpu_type == lief.MachO.CPU_TYPES.ARM64:
                self.total_files_analyzed += 1
                self.checkDylibLoadCommands(binary, file_path)

    def checkDylibLoadCommands(self, binary, file_path):
        dylib_related_lcs = {
            lief.MachO.LOAD_COMMAND_TYPES.LOAD_DYLIB: "LC_LOAD_DYLIB",
            lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB: "LC_ID_DYLIB",
            lief.MachO.LOAD_COMMAND_TYPES.PREBOUND_DYLIB: "LC_PREBOUND_DYLIB",
            lief.MachO.LOAD_COMMAND_TYPES.LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
            lief.MachO.LOAD_COMMAND_TYPES.REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
            lief.MachO.LOAD_COMMAND_TYPES.LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB",
            lief.MachO.LOAD_COMMAND_TYPES.LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
            lief.MachO.LOAD_COMMAND_TYPES.RPATH: "LC_RPATH",
        }

        binary_dylibs_set = set()
        
        for cmd in binary.commands:
            if cmd.command in dylib_related_lcs: 
                lc_name = dylib_related_lcs[cmd.command]
                self.dylib_counts[lc_name] += 1
                binary_dylibs_set.add(lc_name)

        self.binary_dylibs[file_path] = binary_dylibs_set
                   
    def print_results(self):
        print(f"Total Mach-O files analyzed: {self.total_files_analyzed}")
        print("DYLIB-related LC counts:")
        for lc, count in self.dylib_counts.items():
            print(f"{lc}: {count}")
        
        print("\nBinary Dylibs:")
        for binary, dylibs in self.binary_dylibs.items():
            print(f"{binary}: {dylibs}")

    def save_results(self):
        with open("MachODylibLoadCommandsFinder_results.txt", "a") as f:
            f.write(f"Total Mach-O files analyzed: {self.total_files_analyzed}\n")
            f.write("DYLIB-related LC counts:\n")
            for lc, count in self.dylib_counts.items():
                f.write(f"{lc}: {count}\n")
            for binary, dylibs in self.binary_dylibs.items():
                f.write(f"{binary}: {', '.join(dylibs)}\n")
                

macho_checker = MachODylibLoadCommandsFinder()
macho_checker.parseDirectory("/")
macho_checker.print_results()
macho_checker.save_results()