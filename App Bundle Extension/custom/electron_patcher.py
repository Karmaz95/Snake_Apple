import sys
import struct
import hashlib
import argparse
import os

class ASARCalculator:
    def __init__(self, file_path):
        self.file_path = file_path
        self.asar_header_size = self.getASARHeaderSize()
        self.asar_header_bytes = self.readASARHeader()
        self.asar_header_hash = self.calcASARHeaderHash()

    def getASARHeaderSize(self):
        with open(self.file_path, 'rb') as f:
            asar_header = f.read(16)
            asar_header_size_bytes = asar_header[12:16]
            header_size = struct.unpack('<I', asar_header_size_bytes)[0]
            return header_size

    def readASARHeader(self):
        with open(self.file_path, 'rb') as f:
            f.seek(16)
            asar_header = f.read(self.asar_header_size)
            return asar_header

    def calcASARHeaderHash(self):
        return hashlib.sha256(self.asar_header_bytes).hexdigest()

class ASARPatcher:
    def __init__(self):
        pass

    def extractASAR(self, app_path, output_path):
        '''Extracts {input_path} asar file to {output_path} directory.'''
        input_path = os.path.join(app_path, "Contents/Resources/app.asar")
        status_code = os.system(f"npx @electron/asar extract '{input_path}' '{output_path}'")

        if status_code == 0:
            print(f"Extracted {input_path} to {output_path} directory.")

        else:
            print(f"Failed to extract {input_path} to {output_path} directory. Error code: {status_code}")

    def dumpEntitlements(self, app_path):
        output_path='/tmp/extracted_entitlements.xml'
        status_code = os.system(f"codesign -d --entitlements :- '{app_path}' > '{output_path}'")

        if status_code == 0:
            print(f"Dumped entitlements from {app_path} to {output_path}")

        else:
            print(f"Failed to dump entitlements from {app_path} to {output_path}. Error code: {status_code}")

    def checkIfElectronAsarIntegrityIsUsed(self, app_path):
        status_code = os.system(f"plutil -p '{app_path}/Contents/Info.plist' | grep -q ElectronAsarIntegrity")
        if status_code == 0:
            return True
        else:
            return False

    def packASAR(self, input_path, app_path):
        '''Packs {input_path} directory to {output_path} asar file.
        Check if ElectronAsarIntegrity is used in Info.plist, and if so, calculate hash and replace it.
        Codesign the
        '''
        output_path = os.path.join(app_path, "Contents/Resources/app.asar")
        info_plist_path = os.path.join(app_path, "Contents/Info.plist")

        status_code =  os.system(f"npx @electron/asar pack '{input_path}' '{output_path}'")
        if status_code == 0:
            print(f"Packed {input_path} into {output_path}")

            if self.checkIfElectronAsarIntegrityIsUsed(app_path):
                print("ElectronAsarIntegrity is used in Info.plist. Calculating hash and replacing it.")
                asar_calculator = ASARCalculator(output_path)
                new_hash = asar_calculator.calcASARHeaderHash()
                print(f"New hash: {new_hash}")
                print("Replacing ElectronAsarIntegrity in Info.plist")
                os.system(f"/usr/libexec/PlistBuddy -c 'Set :ElectronAsarIntegrity:Resources/app.asar:hash {new_hash}' '{info_plist_path}'")

            print("Resigning app")
            self.dumpEntitlements(app_path)

            os.system(f"codesign --force --entitlements /tmp/extracted_entitlements.xml --sign - '{app_path}'")
            os.remove('/tmp/extracted_entitlements.xml')

            print("Done!")

def main():
    parser = argparse.ArgumentParser(description="ASAR File Operations")
    subparsers = parser.add_subparsers(dest='command')

    # Subparser for the extract command
    extract_parser = subparsers.add_parser('extract', help='Extract an ASAR file')
    extract_parser.add_argument('input_path', type=str, help='Path to the ASAR file to extract')
    extract_parser.add_argument('output_path', type=str, help='Directory to extract the ASAR file into')

    # Subparser for the pack command
    pack_parser = subparsers.add_parser('pack', help='Pack files into an ASAR file')
    pack_parser.add_argument('input_directory', type=str, help='Directory to pack into an ASAR file')
    pack_parser.add_argument('output_path', type=str, help='Path to the output ASAR file')

    args = parser.parse_args()

    patcher = ASARPatcher()

    if args.command == 'extract':
        patcher.extractASAR(args.input_path, args.output_path)
    elif args.command == 'pack':
        patcher.packASAR(args.input_directory, args.output_path)
    else:
        print("Invalid command. Use 'extract' or 'pack'.")

if __name__ == "__main__":
    main()
