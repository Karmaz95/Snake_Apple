import pytest
import subprocess
from CrimsonUroboros import * # Symlinked to the source file, which is the latest version of the CrimsonUroboros.py file.

class Compiler:
    def __init__(self):
        self.compiled_files = [] # Stores the paths to the compiled files.
    
    def compile(self, cmd):
        """
        Compile C code using the given compile command.

        Args:
            cmd (str): The compile command to run.

        Returns:
            int: Return code of the compilation process.
        """
        result = subprocess.run(cmd, shell=True)
        return result.returncode

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
        result = self.compile(cmd)
        self.compiled_files.append(output)
        return result
        
    def purgeCompiledFiles(self):
        """
        Remove all compiled files.
        """
        for file in self.compiled_files:
            subprocess.run(["rm", file])

'''# TODO:
compiler = Compiler()
compiler.compileIt("../I.\ Mach-O/custom/hello.c", "hello")

print(compiler.compiled_files)


class TestSnakeI:
    def test_method1(self):
        ''''''
        # Test_
        obj = CrimsonUroboros()
        input_data = 1
        expected_output = 2
        assert obj.method1(input_data) == expected_output
'''