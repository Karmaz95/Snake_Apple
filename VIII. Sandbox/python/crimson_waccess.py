import os
import time
import subprocess
import sys

class Waccess:
    '''Class to check write permissions on directories and files.'''

    def log_issue(self, path, issue_type, output_path):
        '''Log an issue when write permissions are unexpectedly granted.'''
        with open(output_path, "a") as log_file:
            log_data = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {issue_type}: {path}\n")
            log_file.write(log_data)
            print(log_data, end="")

    def check_write_permission(self, path, output_path):
        '''Check write permission for a directory or file.'''
        if os.path.isdir(path):
            self.check_directory_write_permission(path, output_path)
        elif os.path.isfile(path):
            self.check_file_write_permission(path, output_path)
        else:
            sys.stderr.write(f"Path {path} does not exist.\n")

    def check_directory_write_permission(self, directory_path, output_path):
        '''Check if a directory is writable by attempting to create a test file.'''
        test_file_path = os.path.join(directory_path, f"{int(time.time())}_crimson_write_test.txt")
        try:
            with open(test_file_path, "w") as f:
                f.write("This is a test.")
            os.remove(test_file_path)
            self.log_issue(directory_path, "Directory writable", output_path)
        except Exception:
            pass  # Suppress errors for denied write operations

    def check_file_write_permission(self, file_path, output_path):
        '''Check if a file is writable by attempting to 'touch' it.'''
        result = subprocess.run(['touch', file_path], capture_output=True)
        if result.returncode == 0:
            self.log_issue(file_path, "File writable", output_path)

    def check_paths(self, paths_to_check, output_path, recursive):
        '''Iterate through paths and check permissions.'''
        checked_paths = set()
        while paths_to_check:
            path = paths_to_check.pop()
            if path in checked_paths:
                continue
            checked_paths.add(path)

            base_path = path.rstrip('*')  # Remove trailing asterisks for checking
            if path.endswith('*'):
                self.check_write_permission(base_path, output_path)
                # Always check recursively if '*' is present
                if os.path.isdir(base_path):
                    self.add_child_paths(base_path, paths_to_check, checked_paths)
            else:
                self.check_write_permission(path, output_path)
                if recursive and os.path.isdir(path):
                    self.add_child_paths(path, paths_to_check, checked_paths)

        return checked_paths

    def add_child_paths(self, base_path, paths_to_check, checked_paths):
        '''Add child directories and files to the list to check.'''
        for root, dirs, files in os.walk(base_path):
            for dir_name in dirs:
                child_path = os.path.join(root, dir_name)
                if child_path not in checked_paths:
                    paths_to_check.add(child_path)
            for file_name in files:
                child_file_path = os.path.join(root, file_name)
                if child_file_path not in checked_paths:
                    paths_to_check.add(child_file_path)

    def check_sip_fp(self, file_path, output_path, recursive):
        '''Main function to check each file and directory from the provided list.'''
        try:
            with open(file_path, "r") as paths_file:
                paths_to_check = {line.strip() for line in paths_file if line.strip()}

            checked_paths = self.check_paths(paths_to_check, output_path, recursive)

            # Save all checked paths to a log file
            with open("crimson_waccess_checked_paths.log", "w") as checked_paths_file:
                for checked_path in checked_paths:
                    checked_paths_file.write(f"{checked_path}\n")

        except FileNotFoundError:
            sys.stderr.write(f"The file {file_path} does not exist.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Check SIP-protected file and directory permissions.")
    parser.add_argument("-f", "--file", required=True, help="Path to the file containing paths to check.")
    parser.add_argument("-o", "--output", default="crimson_waccess.log", help="Path to the log file to write issues to.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Check directories recursively.")

    args = parser.parse_args()
    waccess = Waccess()
    waccess.check_sip_fp(args.file, args.output, args.recursive)