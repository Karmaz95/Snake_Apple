#!/usr/bin/env python3
import lief
import uuid
import argparse
import subprocess
import os
import sys

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

    def process(self):
        '''Executes the code for the SnakeI: Mach-O. *** '''
        if not os.path.exists(self.file_path): # Check if file_path specified in the --path argument exists.
            print(f'The file {self.file_path} does not exist.')
            exit()
        
        try: # Check if the file has a valid Mach-O format
            global binaries # It must be global, becuase after the class is destructed, the snake_instance would point to invalid memory ("binary" is dependant on "binaries").
            binaries = lief.MachO.parse(file_path) 
            if binaries == None:
                exit() # Exit if not

            global snake_instance # Must be globall for further processors classes.
            snake_instance = SnakeII(binaries) # Initialize the latest Snake class
                
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
### --- II. CODE SIGNING --- ### 
class CodeSigningProcessor:
    def __init__(self):
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
### --- ARGUMENT PARSER --- ###  
class ArgumentParser:
    def __init__(self):
        '''Class for parsing arguments from the command line. I decided to remove it from main() for additional readability and easier code maintenance in the VScode'''
        self.parser = argparse.ArgumentParser(description="Mach-O files parser for binary analysis")
        self.addGeneralArgs()
        self.addMachOArgs()
        self.addCodeSignArgs()

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
        codesign_group.add_argument('--sign_binary', help="Sign binary using specified identity - use : 'security find-identity -v -p codesigning' to get the identity. (default: adhoc)", nargs='?', const='adhoc', metavar='adhoc|identity_number')
    
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