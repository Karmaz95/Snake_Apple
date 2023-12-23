#!/usr/bin/env python3
import lief
import uuid
import argparse
import subprocess
from asn1crypto.cms import ContentInfo
import os
import sys

### --- I. MACH-O --- ###
class SnakeI:
    def __init__(self, binaries):
        '''When initiated, the program parses a Universal binary (binaries parameter) and extracts the ARM64 Mach-O. If the file is not in a universal format but is a valid ARM64 Mach-O, it is taken as a binary parameter during initialization.'''
        self.binary = self.parseFatBinary(binaries)
        self.fat_offset = self.binary.fat_offset # For various calculations, if ARM64 Mach-O extracted from Universal Binary 
        self.prot_map = {
        0: '---',
        1: 'r--',
        2: '-w-',
        3: 'rw-',
        4: '--x',
        5: 'r-x',
        6: '-wx',
        7: 'rwx'
        }
        self.segment_flags_map = {
        0x1: 'SG_HIGHVM',
        0x2: 'SG_FVMLIB',
        0x4: 'SG_NORELOC',
        0x8: 'SG_PROTECTED_VERSION_1',
        0x10: 'SG_READ_ONLY',
        }
    
    def mapProtection(self, numeric_protection):
        '''Maps numeric protection to its string representation.'''
        return self.prot_map.get(numeric_protection, 'Unknown')
    
    def getSegmentFlags(self, flags):
        '''Maps numeric segment flags to its string representation.'''
        return self.segment_flags_map.get(flags, '')
        #return " ".join(activated_flags)
        
    def parseFatBinary(self, binaries):
        '''Parse Mach-O file, whether compiled for multiple architectures or just for a single one. It returns the ARM64 binary if it exists. If not, it exits the program.'''
        for binary in binaries:
            if binary.header.cpu_type == lief.MachO.CPU_TYPES.ARM64:
                arm64_bin = binary
        if arm64_bin == None:
            print('The specified Mach-O file is not in ARM64 architecture.')
            exit()
        return arm64_bin

    def getFileType(self):
        """Extract and return the file type from a binary object's header."""
        return self.binary.header.file_type.name

    def getHeaderFlags(self):
        '''Return binary header flags.'''
        return self.binary.header.flags_list

    def getEndianess(self):
        '''Check the endianness of a binary based on the system and binary's magic number.'''
        magic = self.binary.header.magic.name
        endianness = sys.byteorder
        if endianness == 'little' and (magic == 'MAGIC_64' or magic == 'MAGIC' or magic == 'FAT_MAGIC'):
            return 'little'
        else:
            return 'big'
    
    def getBinaryHeader(self):
        '''https://lief-project.github.io/doc/stable/api/python/macho.html#header'''
        return self.binary.header

    def getLoadCommands(self):
        '''https://lief-project.github.io/doc/stable/api/python/macho.html#loadcommand'''
        return self.binary.commands

    def getSegments(self):
        '''Extract segmenents from binary and return a human readable string: https://lief-project.github.io/doc/stable/api/python/macho.html#lief.MachO.SegmentCommand'''
        segment_info = []
        for segment in self.binary.segments:
            name = segment.name
            va_start = '0x' + format(segment.virtual_address, '016x')
            va_end = '0x' + format(int(va_start, 16) + segment.virtual_size, '016x')
            file_start = hex(segment.file_size + self.fat_offset)
            file_end = hex(int(file_start, 16) + segment.file_size)
            init_prot = self.mapProtection(segment.init_protection)
            max_prot = self.mapProtection(segment.max_protection)            
            flags = self.getSegmentFlags(segment.flags)
            if flags != '':
                segment_info.append(f'{name.ljust(16)}{init_prot}/{max_prot.ljust(8)} VM: {va_start}-{va_end.ljust(24)} FILE: {file_start}-{file_end} ({flags})')
            else:
                segment_info.append(f'{name.ljust(16)}{init_prot}/{max_prot.ljust(8)} VM: {va_start}-{va_end.ljust(24)} FILE: {file_start}-{file_end}')                
        return segment_info

    def getSections(self):
        '''Extract sections from binary and return in human readable format: https://lief-project.github.io/doc/stable/api/python/macho.html#lief.MachO.Section'''
        sections_info = []
        sections_info.append("SEGMENT".ljust(14) + "SECTION".ljust(20) + "TYPE".ljust(28) + "VIRTUAL MEMORY".ljust(32) + "FILE".ljust(26) + "FLAGS".ljust(40))
        sections_info.append(len(sections_info[0])*"=")
        for section in self.binary.sections:
            segment_name = section.segment_name
            section_name = section.fullname
            section_type = section.type.name
            section_va_start = hex(section.virtual_address)
            section_va_end = hex(section.virtual_address + section.offset)
            section_size_start = hex(section.offset + self.fat_offset)
            section_size_end = hex(section.size + section.offset + self.fat_offset)
            section_flags_list = section.flags_list
            flags_strings = [flag.name for flag in section_flags_list]
            flags = " ".join(flags_strings)
            sections_info.append((f'{segment_name.ljust(14)}{section_name.ljust(20)}{section_type.ljust(28)}{section_va_start}-{section_va_end.ljust(20)}{section_size_start}-{section_size_end}\t\t({flags})'))
        return sections_info

    def getSymbols(self):
        '''Get all symbols from the binary (LC_SYMTAB, Chained Fixups, Exports Trie): https://lief-project.github.io/doc/stable/api/python/macho.html#symbol'''
        return self.binary.symbols

    def getChainedFixups(self):
        '''Return Chained Fixups information: https://lief-project.github.io/doc/latest/api/python/macho.html#chained-binding-info'''
        return self.binary.dyld_chained_fixups
        
    def getExportTrie(self):
        '''Return Export Trie information: https://lief-project.github.io/doc/latest/api/python/macho.html#dyldexportstrie-command'''
        try:
            return self.binary.dyld_exports_trie.show_export_trie()
        except:
            return "NO EXPORT TRIE"

    def getUUID(self):
        '''Return UUID as string and in UUID format: https://lief-project.github.io/doc/stable/api/python/macho.html#uuidcommand'''
        for cmd in self.binary.commands:
            if isinstance(cmd, lief.MachO.UUIDCommand):
                uuid_bytes = cmd.uuid
                break
        uuid_string = str(uuid.UUID(bytes=bytes(uuid_bytes)))
        return uuid_string

    def getMain(self):
        '''Determine the entry point of an executable.'''
        return self.binary.main_command
    
    def getStringSection(self):
        '''Return strings from the __cstring (string table).'''
        extracted_strings = set()
        for section in self.binary.sections:
            if section.type == lief.MachO.SECTION_TYPES.CSTRING_LITERALS:
                extracted_strings.update(section.content.tobytes().split(b'\x00'))
        return extracted_strings

    def findAllStringsInBinary(self):
        '''Check every binary section to find strings.'''
        extracted_strings = ""
        byte_set = set()
        for section in self.binary.sections:
            byte_set.update(section.content.tobytes().split(b'\x00'))
        for byte_item in byte_set:
            try:
                decoded_string = byte_item.decode('utf-8')
                extracted_strings += decoded_string + "\n"
            except UnicodeDecodeError:
                pass
        return extracted_strings
### --- --- --- ### 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mach-O files parser for binary analysis.")
    ### --- I. MACH-O --- ### 
    parser.add_argument('-p', '--path', required=True, help="Path to the Mach-O file.")
    parser.add_argument('--file_type', action='store_true', help="Print binary file type.")
    parser.add_argument('--header_flags', action='store_true', help="Print binary header flags.")
    parser.add_argument('--endian', action='store_true', help="Print binary endianess.")
    parser.add_argument('--header', action='store_true', help="Print binary header.")
    parser.add_argument('--load_commands', action='store_true', help="Print binary load commands names.")
    parser.add_argument('--segments', action='store_true', help="Print binary segments in human friendly form.")
    parser.add_argument('--sections', action='store_true', help="Print binary sections in human friendly form.")
    parser.add_argument('--symbols', action='store_true', help="Print all binary symbols.")
    parser.add_argument('--chained_fixups', action='store_true', help="Print Chained Fixups information.")
    parser.add_argument('--exports_trie', action='store_true', help="Print Export Trie information.")
    parser.add_argument('--uuid', action='store_true', help="Print UUID.")
    parser.add_argument('--main', action='store_true', help="Print entry point and stack size.")
    parser.add_argument('--strings_section', action='store_true', help="Print strings from __cstring section.")
    parser.add_argument('--all_strings', action='store_true', help="Print strings from all sections.")
    parser.add_argument('--save_strings', help="Parse all sections, detect strings and save them to a file.")
    parser.add_argument('--info', action='store_true', default=False , help="Print header, load commands, segments, sections, symbols and strings.")
    
    args = parser.parse_args()
    file_path = os.path.abspath(args.path)
    
    ### --- I. MACH-O --- ###
    try: # Check if the file is in a valid Mach-O format
        if os.path.exists(file_path):
            binaries = lief.MachO.parse(file_path)
            snake_instance = SnakeI(binaries)
        else:
            print(f'The file {file_path} does not exist.')
            exit()
    except Exception as e: # Exit if not
        print(f"An error occurred: {e}")
        exit()
    
    if args.file_type: # Print binary file type
        print(f'File type: {snake_instance.getFileType()}')
    
    if args.header_flags: # Print binary header flags
        header_flag_list = snake_instance.getHeaderFlags()
        print("Header flags:", " ".join(header_flag.name for header_flag in header_flag_list))

    if args.endian: # Print binary endianess
        print(f'Endianess: {snake_instance.getEndianess()}')
        
    if args.header: # Print binary header
        print(snake_instance.getBinaryHeader())

    if args.load_commands: # Print binary load commands
        load_commands_list = snake_instance.getLoadCommands()
        print("Load Commands:", " ".join(load_command.command.name for load_command in load_commands_list))
          
    if args.segments: # Print binary segments in human friendly form
        for segment in snake_instance.getSegments():
            print(segment)
    
    if args.sections: # Print binary sections in human friendly form
        for section in snake_instance.getSections():
            print(section)
            
    if args.symbols: # Print symbols
        for symbol in snake_instance.getSymbols():
            print(symbol.name)

    if args.chained_fixups: # Print Chained Fixups information
        print(snake_instance.getChainedFixups())
        
    if args.exports_trie: # Print Exports Trie information 
        print(snake_instance.getExportTrie())    
        
    if args.uuid: # Print UUID
        print(f'UUID: {snake_instance.getUUID()}')

    if args.main: # Print entry point and stack size
        print(f'Entry point: {hex(snake_instance.getMain().entrypoint)}')
        print(f'Stack size: {hex(snake_instance.getMain().stack_size)}')
        
    if args.strings_section: # Print strings from __cstring section
        print('Strings from __cstring section:')
        print('-------------------------------')
        for string in (snake_instance.getStringSection()):
            print(string)
    
    if args.all_strings: # Print strings from all sections.
        print(snake_instance.findAllStringsInBinary())

    if args.save_strings: # Parse all sections, detect strings and save them to a file
        extracted_strings = snake_instance.findAllStringsInBinary()
        with open(args.save_strings, 'a') as f:
            for s in extracted_strings:
                f.write(s)

    if args.info: # Print all info about the binary
        print('\n<=== HEADER ===>')
        print(snake_instance.getBinaryHeader())
        print('\n<=== LOAD COMMANDS ===>')
        for lcd in snake_instance.getLoadCommands():
            print(lcd)
            print("="*50)
        print('\n<=== SEGMENTS ===>')
        for segment in snake_instance.getSegments():
            print(segment)
        print('\n<=== SECTIONS ===>')
        for section in snake_instance.getSections():
            print(section)
        print('\n<=== SYMBOLS  ===>')
        for symbol in snake_instance.getSymbols():
            print(symbol.name)
        print('\n<=== STRINGS ===>')
        print('Strings from __cstring section:')
        print('-------------------------------')
        for string in (snake_instance.getStringSection()):
            print(string)
        print('\n<=== UUID ===>')
        print(f'{snake_instance.getUUID()}')
        print('\n<=== ENDIANESS ===>')
        print(snake_instance.getEndianess())
        print('\n<=== ENTRYPOINT ===>')
        print(f'{hex(snake_instance.getMain().entrypoint)}')