#!/usr/bin/env python3
'''
Example usage - find _sandbox_check function across extracted libraries from Dyld Shared Cache:
$ python3 find_symbol.py . _sandbox_check
./usr/lib/libspindump.dylib
                 U _sandbox_check
----
./usr/lib/dyld
0000000180141a6c T _sandbox_check
0000000180141b4c t _sandbox_check_common
----
./usr/lib/libnetworkextension.dylib
                 U _sandbox_check
'''

import os
import subprocess
import sys

def find_symbol(target_dir, symbol):
    if not os.path.exists(target_dir):
        print(f"Error: Directory '{target_dir}' does not exist.")
        sys.exit(1)

    # Walk recursively through all files
    for root, _, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)

            # Construct the command using nm instead of disarm
            # nm FILE_PATH | grep SYMBOL
            cmd = f"nm \"{file_path}\" 2>/dev/null | grep \"{symbol}\""

            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )

                if result.stdout:
                    print(file_path)
                    print(result.stdout.rstrip())
                    print("----")

            except Exception:
                continue

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <directory_path> <symbol>")
        sys.exit(1)

    target_dir = sys.argv[1]
    symbol = sys.argv[2]

    find_symbol(target_dir, symbol)

if __name__ == "__main__":
    main()