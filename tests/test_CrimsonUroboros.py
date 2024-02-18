import os
import sys
import lief
import plistlib
from uuid import UUID
from io import StringIO
from CrimsonUroboros import *

# HOW TO TEST
'''
Each TestSnake class should have a method for each option in the Snake class being tested.
During setup phase for each TestSnake class, we prepare tests samples and assert that they exists.
Then, we run the testing methods and assert the outputs for each CrimsonUroboros option.
Finally, we purge the test samples.
We do it for each TestSnake class.

.vscode/settings.json:
{
    "python.testing.pytestArgs": [
        ".",
        "--disable-warnings",
        "-vv",
        "--rootdir=.",
    ],
    "python.testing.unittestEnabled": false,
    "python.testing.pytestEnabled": true,
    "python.testing.cwd": "${workspaceFolder}/tests",
    "python.REPL.enableREPLSmartSend": false,
    "python.testing.autoTestDiscoverOnSaveEnabled": true
}
'''

class Compiler:
    """
    A class for compiling C code using clang.

    Usage:
        compiler = Compiler()
        compiler.compileIt("../I. Mach-O/custom/hello.c", "hello", ["-arch", "arm64"])
        compiler.purgeCompiledFiles()
    """

    def __init__(self):
        self.compiled_files = []  # Stores the paths to the compiled files.

    def compile(self, cmd):
        """
        Compile C code using the given compile command.

        Args:
            cmd (str): The compile command to run.

        Returns:
            int: Return code of the compilation process.
        """
        result = os.system(cmd)

    def buildClangCommand(self, source, output, flags=None):
        """
        Build a clang compile command string based on the source file, output file, and optional flags.

        Args:
            source (str): Path to the source file.
            output (str): Path to the output file.
            flags (list, optional): List of additional flags. Defaults to None.

        Returns:
            str: Compiled clang command string.
        """
        cmd_parts = ["clang"]
        cmd_parts.append(source)
        cmd_parts.extend(["-o", output])
        if flags:
            cmd_parts.extend(flags)

        return ' '.join(cmd_parts)

    def compileIt(self, source, output, flags=None):
        """
        Compile the given source file using clang.

        Args:
            source (str): The path to the source file.
            output (str): The path to the output file.
            flags (list, optional): Additional compilation flags. Defaults to None.

        Returns:
            int: The exit code of the compilation process.
        """
        cmd = self.buildClangCommand(source, output, flags)
        self.compile(cmd)
        self.compiled_files.append(output)

    def purgeCompiledFiles(self):
        """
        Remove all compiled files.
        """
        for file in self.compiled_files:
            os.remove(file)

class CodeSigner:
    """
    # Example usage:
    code_signer = CodeSigner()
    entitlements = {
        "com.apple.security.app-sandbox": "true",
        "com.apple.security.cs.allow-jit": "true"
    }
    certificate = '-'
    code_signer.signBinary("../../../snake_apple/simple/hello", certificate, entitlements)
    """
    def __init__(self):
        self.signed_files = []
    
    def writeEntitlementsToFile(self, entitlements, filename):
        """Write entitlements dictionary to a plist file."""
        with open(filename, 'wb') as f:
            plistlib.dump(entitlements, f)

    def signBinary(self, binary_path, certificate_name=None, entitlements=None):
        """
        Sign binary using codesign.
        (optional) Add entitlements to a binary using codesign. Example:
            entitlements = {
                "com.apple.security.app-sandbox": "true",
                "com.apple.security.cs.allow-jit": "true"
            }
        
        Parameters:
        - binary_path: Path to the binary file.
        - certificate_name (optional): Name of the certificate to sign the binary.
        - entitlements (optional): Dictionary of entitlements to add to the binary.
        """
        # Write entitlements to a plist file
        if entitlements:
            entitlements_file = "unpredictable_entitlements_1029384756.plist"
            self.writeEntitlementsToFile(entitlements, entitlements_file)
        else:
            entitlements_file = None

        # Construct the codesign command
        command = " ".join([
        "codesign",
        "-f",
        "--entitlements",
        entitlements_file,
        "-s",
        certificate_name,
        binary_path
    ])
        # Execute the codesign command
        os.system(command)

def argumentWrapper(args_list):
    """
    Wrapper function to parse command line arguments.

    Args:
        args_list (list): List of command line arguments.

    Returns:
        tuple: A tuple containing the parsed arguments and the absolute file path.
    """
    sys.argv[1:] = args_list # Example: ['-p', 'hello', '--file_type']
    arg_parser = ArgumentParser()
    args = arg_parser.parseArgs()
    file_path = os.path.abspath(args.path)
    return args, file_path

def executeCodeBlock(func):
    """
    Executes the provided function and captures its output.

    Args:
        func: The function to be executed.

    Returns:
        The captured output of the function.
    """
    # Redirect stdout and stderr to capture the output
    captured_output = StringIO()
    sys.stdout = sys.stderr = captured_output

    # Execute the provided function
    func()

    # Restore stdout and stderr
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__

    # Get the captured output
    output = captured_output.getvalue().strip()

    return output

class TestSnakeI():
    '''Testing I. MACH-O'''
    @classmethod
    def setup_class(cls):
        # Set up the compilation process
        cls.compiler = Compiler()
        cls.compiler.compileIt("../I.\ Mach-O/custom/hello.c", "hello_1", ["-arch", "arm64"])
        assert os.path.exists("hello_1")  # Check if the file exists after compilation

    @classmethod
    def teardown_class(cls):
        # Purge the compiled files
        cls.compiler.purgeCompiledFiles()
        assert not os.path.exists("hello_1")  # Check if the file is removed after purging
    
    def test_MachOProcessor(self):
        '''Test the initialization of MachOProcessor.

        This test checks if the snake_instance is created by using the MachOProcessor class.
        It sets up arguments for testing, defines the code block to be executed, executes the code block,
        and asserts that there are no errors by checking the output.
        '''

        # Set up arguments for testing
        args_list = ['-p', 'hello_1'] 
        args, file_path = argumentWrapper(args_list)

        # Define the code block to be executed
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)

        # Execute the code block using the wrapper function and capture the output
        uroboros_output = executeCodeBlock(code_block)

        # Assert there are no errors by checking the output - when using only --path there is no output if file exists and is valid arm64 Mach-O file
        expected_output = ''
        assert uroboros_output == expected_output
    
    def test_file_type(self):
        '''Test the --file_type flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--file_type']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'File type: EXECUTE'
        
        assert uroboros_output == expected_output
    
    def test_header_flags(self):
        '''Test the --header_flags flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--header_flags']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'Header flags: TWOLEVEL NOUNDEFS DYLDLINK PIE'
        
        assert uroboros_output == expected_output
    
    def test_endian(self):
        '''Test the --endian flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--endian']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'Endianess: little'
        
        assert uroboros_output == expected_output
    
    def test_header(self):
        '''Test the --header flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--header']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = 'ARM64'
        expected_output_2 = 'EXECUTE'
        expected_output_3 = 'NOUNDEFS DYLDLINK TWOLEVEL PIE'
        
        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
        assert expected_output_3 in uroboros_output
    
    def test_load_commands(self):
        '''Test the --load_commands flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--load_commands']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'Load Commands: SEGMENT_64 SEGMENT_64 SEGMENT_64 SEGMENT_64 DYLD_CHAINED_FIXUPS DYLD_EXPORTS_TRIE SYMTAB DYSYMTAB LOAD_DYLINKER UUID BUILD_VERSION SOURCE_VERSION MAIN LOAD_DYLIB FUNCTION_STARTS DATA_IN_CODE CODE_SIGNATURE'
        
        assert expected_output in uroboros_output
    
    def test_segments(self):
        '''Test the --segments flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--segments']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = '__PAGEZERO      ---/---      VM: 0x0000000000000000-0x0000000100000000       FILE: 0x0-0x0'
        expected_output_2 = '__TEXT          r-x/r-x      VM: 0x0000000100000000-0x0000000100004000       FILE: 0x4000-0x8000'
        expected_output_3 = '__DATA_CONST    rw-/rw-      VM: 0x0000000100004000-0x0000000100008000       FILE: 0x4000-0x8000 (SG_READ_ONLY)'
        expected_output_4 = '__LINKEDIT      r--/r--      VM: 0x0000000100008000-0x000000010000c000       FILE: 0x298-0x530'
        
        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
        assert expected_output_3 in uroboros_output
        assert expected_output_4 in uroboros_output
    
    def test_sections(self):
        '''Test the --sections flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--sections']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = '__TEXT        __text              REGULAR                     0x100003f58-0x100007eb0         0x3f58-0x3f8c		(SOME_INSTRUCTIONS PURE_INSTRUCTIONS)'
        expected_output_2 = '__TEXT        __stubs             SYMBOL_STUBS                0x100003f8c-0x100007f18         0x3f8c-0x3f98		(SOME_INSTRUCTIONS PURE_INSTRUCTIONS)'
        expected_output_3 = '__TEXT        __cstring           CSTRING_LITERALS            0x100003f98-0x100007f30         0x3f98-0x3fa7		()'
        expected_output_4 = '__TEXT        __unwind_info       REGULAR                     0x100003fa8-0x100007f50         0x3fa8-0x4000		()'
        expected_output_5 = '__DATA_CONST  __got               NON_LAZY_SYMBOL_POINTERS    0x100004000-0x100008000         0x4000-0x4008		()'
        
        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
        assert expected_output_3 in uroboros_output
        assert expected_output_4 in uroboros_output
        assert expected_output_5 in uroboros_output
    
    def test_symbols(self):
        '''Test the --symbols flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--symbols']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = '__mh_execute_header'
        expected_output_2 = '_main'
        expected_output_3 = '_printf'

        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
        assert expected_output_3 in uroboros_output

    def test_imported_symbols(self):
        '''Test the --imported_symbols flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--imported_symbols']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output = '_printf : /usr/lib/libSystem.B.dylib'
        
        assert uroboros_output == expected_output
    
    def test_chained_fixups(self):
        '''Test the --chained_fixups flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--chained_fixups']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output = '_DATA_CONST0x100004000: _printf (libSystem.B.dylib) addend: 0x0'
        
        assert expected_output in uroboros_output
    
    def test_exports_trie(self):
        '''Test the --exports_trie flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--exports_trie']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output = '_main{addr: 0x3f58, flags: 0}'
        
        assert expected_output in uroboros_output
    
    def test_uuid(self):
        '''Test the --uuid flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--uuid']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        try:
            is_valid = UUID(uroboros_output.split('UUID: ')[-1], version=4) # this returns the UUID string if it is valid and stores it in is_valid
        except ValueError:
            is_valid = False

        assert is_valid
    
    def test_main(self):
        '''Test the --main flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--main']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = 'Entry point: 0x3f58'
        expected_output_2 = 'Stack size: 0x0'
        
        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
    
    def test_encryption_info(self):
        '''Test the --encryption_info flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--encryption_info']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'hello_1 binary does not have encryption info.'
        
        assert expected_output in uroboros_output
    
    def test_strings_section(self):
        '''Test the --strings_section flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--strings_section']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = 'Hello, World!'
        expected_output_2 = '__cstring'
        
        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
    
    def test_all_strings(self):
        '''Test the --all_strings flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--all_strings']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = 'Hello, World!'
        
        assert expected_output_1 in uroboros_output
    
    def test_save_strings(self):
        '''Test the --save_strings flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--save_strings', 'testing_strings.txt']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)

        assert os.path.exists('testing_strings.txt')
        
        with open('testing_strings.txt', 'r') as file:
            file_output = file.read()
        expected_output = 'Hello, World'
        
        assert expected_output in file_output
        os.remove('testing_strings.txt')

    def test_info(self):
        '''Test the --info flag of SnakeI.'''
        args_list = ['-p', 'hello_1', '--info']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)

        expected_output_1 = 'Entry point: 0x3f58'
        expected_output_2 = '__mh_execute_header'
        expected_output_3 = '__PAGEZERO      ---/---      VM: 0x0000000000000000-0x0000000100000000       FILE: 0x0-0x0'
        expected_output_4 = '__DATA_CONST0x100004000: _printf (libSystem.B.dylib) addend: 0x0'
        expected_output_5 = 'Command : SEGMENT_64'

        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
        assert expected_output_3 in uroboros_output
        assert expected_output_4 in uroboros_output
        assert expected_output_5 in uroboros_output

class TestSnakeII():
    '''Testing II. CODE SIGNING'''
    @classmethod
    def setup_class(cls):
        # Set up the compilation process
        cls.compiler = Compiler()
        cls.compiler.compileIt("../III.\ Checksec/custom/hello.c", "hello_2", ["-arch", "arm64"])
        assert os.path.exists("hello_2")  # Check if the file exists after compilation
        
        # Prepare signed binary for test_remove_sig
        cls.compiler.compileIt("../III.\ Checksec/custom/hello.c", "hello_2_test_remove_sig", ["-arch", "arm64"])
        assert os.path.exists("hello_2_test_remove_sig")  # Check if the file exists after compilation

        # Prepare unsigned binary for test_sign_binary
        binary2 = lief.parse('hello_2')
        binary2.remove_signature()
        binary2.write('hello_2_unsigned_binary')
        cls.compiler.compiled_files.append("hello_2_unsigned_binary")
        assert os.path.exists("hello_2_unsigned_binary")

        # Code sign and set entitlements
        cls.code_signer = CodeSigner()
        cls.entitlements = {
            "com.apple.security.app-sandbox": "true",
            "com.apple.security.cs.allow-jit": "true"
        }
        cls.certificate = '-'
        cls.code_signer.signBinary("hello_2", cls.certificate, cls.entitlements)

    @classmethod
    def teardown_class(cls):
        # Purge the compiled files
        cls.compiler.purgeCompiledFiles()
        assert not os.path.exists("hello_2")
        assert not os.path.exists("hello_2_unsigned_binary")

        # Purge entitlements file
        os.remove('unpredictable_entitlements_1029384756.plist')
        assert not os.path.exists('unpredictable_entitlements_1029384756.plist')

    def test_verify_signature(self):
        '''Test the --verify_signature flag of SnakeII.'''
        args_list = ['-p', 'hello_2', '--verify_signature']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'Valid Code Signature (matches the content)'

        assert uroboros_output == expected_output
        
        args_list = ['-p', 'hello_2_unsigned_binary', '--verify_signature']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'Invalid Code Signature (does not match the content)'

        assert uroboros_output == expected_output
        
    def test_cd_info(self):
        '''Test the --cd_info flag of SnakeII.'''
        args_list = ['-p', 'hello_2', '--cd_info']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'flags=0x2(adhoc)'

        assert expected_output in uroboros_output

    def test_cd_requirements(self):
        '''Test the --cd_requirements flag of SnakeII.'''
        args_list = ['-p', 'hello_2', '--cd_requirements']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'designated'

        assert expected_output in uroboros_output

    def test_entitlements(self):
        '''Test the --entitlements flag of SnakeII.'''
        args_list = ['-p', 'hello_2', '--entitlements']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = 'com.apple.security.app-sandbox'
        expected_output_2 = 'com.apple.security.cs.allow-jit'

        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output

    def test_extract_cms(self):
        '''Test the --extract_cms flag of SnakeII.''' # TODO - this test can be improved, but we need to create a security-identity for tests
        args_list = ['-p', 'hello_2', '--extract_cms', 'hello_2_unpredictable_name.cms']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)
            
        uroboros_output = executeCodeBlock(code_block)

        assert os.path.exists('hello_2_unpredictable_name.cms')
        os.remove('hello_2_unpredictable_name.cms')

    def test_extract_certificates(self):
        '''Test the --extract_certificates flag of SnakeII.'''
        args_list = ['-p', '/usr/lib/dyld', '--extract_certificates', 'hello_2_unpredictable_name']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)

            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)

        executeCodeBlock(code_block)

        for i in range(3):
            assert os.path.exists(f'hello_2_unpredictable_name_{i}')
            os.remove(f'hello_2_unpredictable_name_{i}')

    def test_remove_sig(self):
        '''Test the --remove_code_signature flag of SnakeII.'''
        args_list = ['-p', 'hello_2', '--remove_sig', 'hello_2_test_remove_sig']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)

        executeCodeBlock(code_block)

        assert os.path.exists('hello_2_test_remove_sig')
        binary1 = lief.parse('hello_2_test_remove_sig')
        assert not binary1.has_code_signature

    """# sign_binary is problematic, because of race condition on codesign tool, but we do not need to test that since we are testing verify_signature. The test can be reimplemented when I rewrite codesigning utility in python.
    
    def test_sign_binary(self):
        '''Test the --sign_binary flag of SnakeII.'''
        args_list = ['-p', 'hello_2_unsigned_binary', '--sign_binary']
        args, file_path = argumentWrapper(args_list)
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            
            code_signing_processor = CodeSigningProcessor()
            code_signing_processor.process(args)

        # Sign it
        executeCodeBlock(code_block)
        
        binary3 = lief.parse('hello_2_unsigned_binary')
        assert binary3.has_code_signature"""

class TestSnakeIII():
    '''Testing III. CHECKSEC'''
    @classmethod
    def setup_class(cls):
        # Set up the compilation process
        cls.compiler = Compiler()
        cls.compiler.compileIt("../I.\ Mach-O/custom/hello.c", "hello_3", ["-arch", "arm64"])
        assert os.path.exists("hello_3")

        # ARC binary
        cls.compiler.compileIt("../III.\ Checksec/custom/example.m", "hello_3_arc", ["-arch", "arm64", "-fobjc-arc", "-framework", "Foundation"])
        assert os.path.exists("hello_3_arc")

        # Stripped binary
        os.system('strip hello_3_arc -o hello_3_stripped')
        assert os.path.exists("hello_3_stripped")
        cls.compiler.compiled_files.append("hello_3_stripped")

        # Stack guard binary
        cls.compiler.compileIt("../III.\ Checksec/custom/example.m", "hello_3_sc", ["-arch", "arm64", "-fstack-protector-all", "-framework", "Foundation"])
        assert os.path.exists("hello_3_sc")
        
        # Code sign and set entitlements
        cls.code_signer = CodeSigner()
        cls.entitlements = {
            "com.apple.security.app-sandbox": "true",
            "com.apple.security.cs.allow-jit": "true"
        }
        cls.certificate = '-'
        cls.code_signer.signBinary("hello_3", cls.certificate, cls.entitlements)


    @classmethod
    def teardown_class(cls):
        # Purge the compiled files
        cls.compiler.purgeCompiledFiles()
        assert not os.path.exists("hello_3")  # Check if the file is removed after purging
        
        # Purge entitlements file
        os.remove('unpredictable_entitlements_1029384756.plist')
        assert not os.path.exists('unpredictable_entitlements_1029384756.plist')

    def test_has_pie(self):
        '''Test the --has_pie flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--has_pie']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'PIE: True'

        assert uroboros_output == expected_output

    def test_has_arc(self):
        '''Test the --has_arc flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--has_arc']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'ARC: False'

        assert uroboros_output == expected_output
        
        args_list = ['-p', 'hello_3_arc', '--has_arc']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)
        
        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'ARC: True'
        
        assert uroboros_output == expected_output

    def test_is_stripped(self):
        '''Test the --is_stripped flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--is_stripped']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'STRIPPED: False'

        assert uroboros_output == expected_output

        args_list = ['-p', 'hello_3_stripped', '--is_stripped']
        args, file_path = argumentWrapper(args_list)
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'STRIPPED: True'

        assert uroboros_output == expected_output

    def test_has_canary(self):
        '''Test the --has_canary flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--has_canary']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'CANARY: False'

        assert uroboros_output == expected_output

        args_list = ['-p', 'hello_3_sc', '--has_canary']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'CANARY: True'
        
        assert uroboros_output == expected_output
        
    def test_has_nx_stack(self):
        '''Test the --has_nx_stack flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--has_nx_stack']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'NX STACK: True'

        assert uroboros_output == expected_output
        
    def test_has_nx_heap(self):
        '''Test the --has_nx_heap flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--has_nx_heap']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'NX HEAP: False'

        assert uroboros_output == expected_output
    
    def test_has_xn(self):
        '''Test the --has_xn flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--has_xn']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'eXecute Never: False'

        assert expected_output in uroboros_output        
        
    def test_is_notarized(self):
        '''Test the --is_notarized flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--is_notarized']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'NOTARIZED: False'

        assert uroboros_output == expected_output
    
    def test_is_encrypted(self):
        '''Test the --is_encrypted flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--is_encrypted']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'ENCRYPTED: False'

        assert uroboros_output == expected_output
    
    def test_is_restricted(self):
        '''Test the --is_restricted flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--is_restricted']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'RESTRICTED: False'

        assert uroboros_output == expected_output
    
    def test_is_hr(self):
        '''Test the --is_hr flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--is_hr']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'HARDENED: False'

        assert uroboros_output == expected_output
    
    def test_is_as(self):
        '''Test the --is_as flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--is_as']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'APP SANDBOX: True'

        assert uroboros_output == expected_output
        
    def test_is_fort(self):
        '''Test the --is_fort flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--is_fort']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'FORTIFIED: False'

        assert uroboros_output == expected_output
    
    def test_has_rpath(self):
        '''Test the --has_rpath flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--has_rpath']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'RPATH: False'

        assert uroboros_output == expected_output
        
    def test_has_lv(self):
        '''Test the --has_lv flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--has_lv']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'LIBRARY VALIDATION: False'

        assert uroboros_output == expected_output
    
    def test_checksec(self):
        '''Test the --checksec flag of SnakeIII.'''
        args_list = ['-p', 'hello_3', '--checksec']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            checksec_processor = ChecksecProcessor()
            checksec_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)

        expected_output_1 = 'PIE:            True'
        expected_output_2 = 'ARC:            False'
        expected_output_3 = 'STRIPPED:       False'
        expected_output_4 = 'CANARY:         False'
        expected_output_5 = 'NX STACK:       True'
        expected_output_6 = 'NX HEAP:        False'
        expected_output_7 = 'XN'
        expected_output_8 = 'NOTARIZED:      False'
        expected_output_9 = 'ENCRYPTED:      False'
        expected_output_10 = 'RESTRICTED:     False'
        expected_output_11 = 'HARDENED:       False'
        expected_output_12 = 'APP SANDBOX:    True'
        expected_output_13 = 'FORTIFIED:      False'
        expected_output_14 = 'RPATH:          False'
        expected_output_15 = 'LV:             False'

        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
        assert expected_output_3 in uroboros_output
        assert expected_output_4 in uroboros_output
        assert expected_output_5 in uroboros_output
        assert expected_output_6 in uroboros_output
        assert expected_output_7 in uroboros_output
        assert expected_output_8 in uroboros_output
        assert expected_output_9 in uroboros_output
        assert expected_output_10 in uroboros_output
        assert expected_output_11 in uroboros_output
        assert expected_output_12 in uroboros_output
        assert expected_output_13 in uroboros_output
        assert expected_output_14 in uroboros_output
        assert expected_output_15 in uroboros_output

class TestSnakeIV():
    '''Testing IV. DYLIBS'''
    @classmethod
    def setup_class(cls):
        # Set up the compilation process
        cls.compiler = Compiler()
        cls.compiler.compileIt("../I.\ Mach-O/custom/hello.c", "hello_4", ["-arch", "arm64"])
        assert os.path.exists("hello_4")
        
        cls.compiler.compileIt("../I.\ Mach-O/custom/mylib.c", "mylib", ["-arch", "arm64", "-dynamiclib"])
        os.system('install_name_tool -add_rpath "lc_rpath_test" "mylib"')
        assert os.path.exists("mylib")
        
        # Code sign and set entitlements
        cls.code_signer = CodeSigner()
        cls.entitlements = {
            "com.apple.security.app-sandbox": "true",
            "com.apple.security.cs.allow-jit": "true"
        }
        cls.certificate = '-'
        cls.code_signer.signBinary("hello_4", cls.certificate, cls.entitlements)

    @classmethod
    def teardown_class(cls):
        # Purge the compiled files
        cls.compiler.purgeCompiledFiles()
        assert not os.path.exists("hello_4")  # Check if the file is removed after purging
        
        # Purge entitlements file
        os.remove('unpredictable_entitlements_1029384756.plist')
        assert not os.path.exists('unpredictable_entitlements_1029384756.plist')

    def test_dylibs(self):
        '''Test the --dylibs flag of SnakeIV.'''
        args_list = ['-p', 'hello_4', '--dylibs']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'libSystem.B.dylib'

        assert expected_output in uroboros_output
        assert len(uroboros_output.splitlines()) == 2
        
    def test_rpaths(self):
        '''Test the --rpaths flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--rpaths']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'lc_rpath_test'

        assert expected_output in uroboros_output
        
    def test_rpaths_u(self):
        '''Test the --rpaths_u flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--rpaths_u']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'lc_rpath_test'

        assert expected_output in uroboros_output

    def test_dylibs_paths(self):
        '''Test the --dylibs_paths flag of SnakeIV.'''
        args_list = ['-p', 'hello_4', '--dylibs_paths']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = '/usr/lib/libSystem.B.dylib'

        assert expected_output in uroboros_output
        
    def test_broken_relative_paths(self):
        '''Test the --broken_relative_paths flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--broken_relative_paths']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = ''

        assert expected_output == uroboros_output
    
    def test_dylibtree(self):
        '''Test the --dylibtree flag of SnakeIV.'''
        args_list = ['-p', 'hello_4', '--dylibtree']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = 'hello_4'
        expected_output_2 = '/usr/lib/libSystem.B.dylib'

        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
        os.system('rm -rf extracted_dyld_share_cache')
        assert not os.path.exists('extracted_dyld_share_cache')

    def test_dylib_id(self):
        '''Test the --dylib_id flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--dylib_id']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'mylib'

        assert expected_output == uroboros_output
        
    def test_reexport_paths(self):
        '''Test the --reexport_paths flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--reexport_paths']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = ''

        assert expected_output == uroboros_output
        
    def test_hijack_sec(self):
        '''Test the --hijack_sec flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--hijack_sec']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        exepected_output = 'DYLIB HIJACKIG PROTECTION: False'
        
        assert exepected_output == uroboros_output
        
    def test_dylib_hijacking(self):
        '''Test the --dylib_hijacking flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--dylib_hijacking']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'ROOT BINARY NOT PROTECTED'

        assert expected_output in uroboros_output
    
    def test_dylib_hijacking_a(self):
        '''Test the --dylib_hijacking_a flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--dylib_hijacking_a']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = ''

        assert expected_output == uroboros_output
    
    def test_prepare_dylib(self):
        '''Test the --prepare_dylib flag of SnakeIV.'''
        args_list = ['-p', 'mylib', '--prepare_dylib']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dylibs_processor = DylibsProcessor()
            dylibs_processor.process(args)

        executeCodeBlock(code_block)
        
        assert os.path.exists('m.dylib')
        assert os.path.exists('m.c')
        os.remove('m.dylib')
        os.remove('m.c')

class TestSnakeV():
    '''Testing V. DYLD'''
    @classmethod
    def setup_class(cls):
        # Set up the compilation process
        cls.compiler = Compiler()
        cls.compiler.compileIt("../I.\ Mach-O/custom/hello.c", "hello_5", ["-arch", "arm64", "-Wl,-dyld_env,DYLD_LIBRARY_PATH='@executable_path/dylibs'"])
        assert os.path.exists("hello_5")
        
        cls.compiler.compileIt("../V.\ Dyld/custom/interpose.c", "libinterpose.dylib", ["-dynamiclib", "-arch", "arm64"])
        assert os.path.exists("libinterpose.dylib")

    @classmethod
    def teardown_class(cls):
        # Purge the compiled files
        cls.compiler.purgeCompiledFiles()
        assert not os.path.exists("hello_5")
        assert not os.path.exists("libinterpose.dylib")

    def test_is_built_for_sim(self):
        '''Test the --is_built_for_sim flag of SnakeV.'''
        args_list = ['-p', 'hello_5', '--is_built_for_sim']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dyld_processor = DyldProcessor()
            dyld_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'PLATFORM_MACOS'

        assert expected_output in uroboros_output

    def test_get_dyld_env(self):
        '''Test the --get_dyld_env flag of SnakeV.'''
        args_list = ['-p', '/usr/lib/dyld', '--get_dyld_env']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dyld_processor = DyldProcessor()
            dyld_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output_1 = 'DYLD_SHARED_CACHE_DIR'
        expected_output_2 = 'DYLD_IN_CACHE'
        expected_output_3 = 'DYLD_PRINT_SEGMENTS'
        expected_output_4 = 'DYLD_AMFI_FAKE'
        expected_output_5 = 'DYLD_FALLBACK_FRAMEWORK_PATH'

        assert expected_output_1 in uroboros_output
        assert expected_output_2 in uroboros_output
        assert expected_output_3 in uroboros_output
        assert expected_output_4 in uroboros_output
        assert expected_output_5 in uroboros_output
    
    def test_compiled_with_dyld_env(self):
        '''Test the --compiled_with_dyld_env flag of SnakeV.'''
        args_list = ['-p', 'hello_5', '--compiled_with_dyld_env']
        args, file_path = argumentWrapper(args_list)

        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dyld_processor = DyldProcessor()
            dyld_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'DYLD_LIBRARY_PATH'

        assert expected_output in uroboros_output
        
    def test_has_interposing(self):
        '''Test the --has_interposing flag of SnakeV.'''
        args_list = ['-p', 'hello_5', '--has_interposing']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dyld_processor = DyldProcessor()
            dyld_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'INTERPOSING: False'

        assert expected_output in uroboros_output
        
        args_list = ['-p', 'libinterpose.dylib', '--has_interposing']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dyld_processor = DyldProcessor()
            dyld_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = 'INTERPOSING: True'

    def test_interposing_symbols(self):
        '''Test the --interposing_symbols flag of SnakeV.'''
        args_list = ['-p', 'libinterpose.dylib', '--interposing_symbols']
        args, file_path = argumentWrapper(args_list)
        
        def code_block():
            macho_processor = MachOProcessor(file_path)
            macho_processor.process(args)
            dyld_processor = DyldProcessor()
            dyld_processor.process(args)

        uroboros_output = executeCodeBlock(code_block)
        expected_output = '_my_printf'

        assert expected_output in uroboros_output