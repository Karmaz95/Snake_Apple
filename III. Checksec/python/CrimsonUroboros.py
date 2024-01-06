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

'''*** REMAINDER ***
Change initialization in MachOProcessoer -> process -> try block.
Always initialize the latest Snake class:

snake_instance = SnakeII(binaries)
'''
### --- I. MACH-O --- ###
class MachOProcessor:
    def __init__(self, file_path):
        '''This class contains part of the code from the main() for the SnakeI: Mach-O part.'''
        self.file_path = file_path
    
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
            snake_instance = SnakeIII(binaries) # Initialize the latest Snake class
                
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
            print(f"An error occurred during Mach-O processing: {e}")
            exit()
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
            print(f"An error occurred during Code Signing processing: {e}") 
class SnakeII(SnakeI):
    def __init__(self, binaries):
        super().__init__(binaries)
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
                print("APP SANDBOX: " + str(snake_instance.hasAppSandbox()))
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
                print("APP SANDBOX: ".ljust(16) + str(snake_instance.hasAppSandbox()))
                fortified_symbols = snake_instance.getForifiedSymbols()
                print("FORTIFIED: ".ljust(16) + str(snake_instance.isFortified(fortified_symbols)))
                print("RPATH: ".ljust(16) + str(snake_instance.hasRpath()))
                print("=====================>")
        except Exception as e:
            print(f"An error occurred during Checksec processing: {e}")
class SnakeIII(SnakeII):
    def __init__(self, binaries):
        super().__init__(binaries)

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
    
    def checkIfEntitlementIsUsed(self, entitlement_name, entitlement_value):
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
        
    def hasAllowJITentitlement(self):
        '''Checks if the binary has missing com.apple.security.cs.allow-jit entitlement that allows the app to create writable and executable memory using the MAP_JIT flag.'''
        if self.checkIfEntitlementIsUsed('com.apple.security.cs.allow-jit', 'true'):
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
        if self.hasAllowJITentitlement() or self.checkIfCompiledForOtherThanARM():
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
    
    def hasAppSandbox(self):
        '''Check if App Sandbox is in use (com.apple.security.app-sandbox entitlement is set).'''
        if self.checkIfEntitlementIsUsed('com.apple.security.app-sandbox', 'true'):
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
### --- ARGUMENT PARSER --- ###  
class ArgumentParser:
    def __init__(self):
        '''Class for parsing arguments from the command line. I decided to remove it from main() for additional readability and easier code maintenance in the VScode'''
        self.parser = argparse.ArgumentParser(description="Mach-O files parser for binary analysis")
        self.addGeneralArgs()
        self.addMachOArgs()
        self.addCodeSignArgs()
        self.addChecksecArgs()

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
        
    def parseArgs(self):
        return self.parser.parse_args()

    def printAllArgs(self, args):
        '''Just for debugging. This method is a utility designed to print all  parsed arguments and their corresponding values.'''
        for arg, value in vars(args).items():
            print(f"{arg}: {value}")

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