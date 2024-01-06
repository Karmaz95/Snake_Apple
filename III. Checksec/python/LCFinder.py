#!/usr/bin/env python3
import argparse
import lief


class LCFinder:
    def __init__(self, args):
        """
        Initialize CheckLC object.

        :param args: Command-line arguments.
        """
        self.path = args.path if args.path else None
        self.list_path = args.list_path if args.list_path else None
        self.load_command = args.lc

    def parseFatBinary(self, binaries):
        """
        Parse the fat binary and return the ARM64 binary if found.

        :param binaries: List of binaries in the fat binary.
        :return: ARM64 binary if found, else None.
        """
        arm64_bin = None
        for binary in binaries:
            if binary.header.cpu_type == lief.MachO.CPU_TYPES.ARM64:
                arm64_bin = binary
        return arm64_bin

    def getLoadCommands(self, binary):
        """
        Get the list of load commands from the binary.

        :param binary: MachO binary.
        :return: List of load commands.
        """
        return binary.commands

    def checkLoadCommand(self, binary, target_load_command):
        """
        Check if the specified load command is present in the binary.

        :param binary: MachO binary.
        :param target_load_command: The load command to check for.
        :return: True if the load command is found, else False.
        """
        load_commands_list = self.getLoadCommands(binary)
        for lc in load_commands_list:
            load_command = str(lc.command)
            parts = load_command.split('.')
            name = parts[-1]
            lc_name = "LC_" + name
            lc_filter = [name.lower(), lc_name.lower()]
            if target_load_command.lower() in lc_filter:
                return True
        return False

    def processPath(self, path):
        """
        Process a single binary file.

        :param path: Path to the binary file.
        """
        try:
            binary = lief.MachO.parse(path)
            arm64_bin = self.parseFatBinary(binary)
            if arm64_bin and self.checkLoadCommand(arm64_bin, self.load_command):
                print(f"Load Command '{self.load_command}' found in: {path}")
        except Exception as e:
            print(f"Error processing {path}: {e}")

    def processList(self, list_path):
        """
        Process a list of binary files.

        :param list_path: Path to the file containing a list of binary paths.
        """
        try:
            with open(list_path, 'r') as file:
                paths = file.readlines()
                for path in paths:
                    self.processPath(path.strip())
        except Exception as e:
            print(f"Error processing list: {e}")

    def run(self):
        """
        Run the check based on provided input.
        """
        if self.path:
            self.processPath(self.path)
        elif self.list_path:
            self.processList(self.list_path)
        else:
            print("Please provide either a single path or a list path.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for a specific load command in Mach-O binaries.")
    parser.add_argument("--path", "-p", help="Absolute path to the valid MachO binary.")
    parser.add_argument("--list_path", "-l", help="Path to a wordlist file containing absolute paths.")
    parser.add_argument("--lc", help="The load command to check for.", required=True)

    args = parser.parse_args()
    checker = LCFinder(args)
    checker.run()
