#!/usr/bin/env python3

import xattr
import uuid
import sys
import argparse

class XattrReader:
    def __init__(self, file_path):
        self.file_path = file_path

    def get_all_xattrs(self):
        """Return all extended attribute names."""
        return xattr.listxattr(self.file_path)

    def get_all_xattr_values(self):
        """Return a dictionary of attribute names and their raw values."""
        attributes = self.get_all_xattrs()
        all_attributes_values = {}
        for attr in attributes:
            value = xattr.getxattr(self.file_path, attr)
            all_attributes_values[attr] = value
        return all_attributes_values

    def hexdump(self, byte_data):
        """Convert raw byte data to a hex string."""
        return byte_data.hex()

    def print_all_xattr_values(self, raw=False):
        """Print each attribute and its value in hex format or human-readable format."""
        all_attributes_values = self.get_all_xattr_values()
        for k, v in all_attributes_values.items():
            if raw:
                # Print raw hex values
                hex_value = self.hexdump(v)
                print(f"{k}: {hex_value}")
            else:
                # Human-readable format, interpreting 'com.apple.macl' if found
                if k == "com.apple.macl":
                    print("com.apple.macl: ", end="")
                    self.parse_macl(v)
                    print()
                else:
                    try:
                        # Attempt to decode as UTF-8
                        print(f"{k}: {v.decode('utf-8')}")
                    except UnicodeDecodeError:
                        # Fallback to hex if decoding fails
                        print(f"{k}: {self.hexdump(v)}")

    def parse_macl(self, macl_data):
        """Parse the 'com.apple.macl' extended attribute for header and UUIDs."""
        if len(macl_data) % 18 != 0:
            print("Unexpected macl attribute length.")
            return

        for i in range(0, len(macl_data), 18):
            entry = macl_data[i:i+18]
            header = entry[:2].hex()
            uuid_bytes = entry[2:]
            entry_uuid = str(uuid.UUID(bytes=uuid_bytes))

            if header == "0000" and entry_uuid == "00000000-0000-0000-0000-000000000000":
                continue

            print(f"{header},{entry_uuid}", end="")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Display extended attributes in raw or human-readable format.")
    parser.add_argument("file_path", help="Path to the file with extended attributes.")
    parser.add_argument(
        "--raw", 
        action="store_true", 
        help="Display output in raw hex format."
    )
    parser.add_argument(
        "--human", 
        action="store_true", 
        help="Display output in human-readable format (default)."
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    reader = XattrReader(args.file_path)

    # Determine output mode: default to human-readable if neither --raw nor --human is set
    if args.raw:
        reader.print_all_xattr_values(raw=True)
    else:
        reader.print_all_xattr_values(raw=False)