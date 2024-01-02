#!/usr/bin/env python3
import glob
import shutil
import os
import argparse
import subprocess
from pyimg4 import *

class TrustCacheParser:
    def __init__(self, file_patterns):
        self.file_patterns = file_patterns

    def copyFiles(self, destination_dir):
        """
        Copy Trust Cache files to the specified destination directory.

        Parameters:
        - destination_dir (str): Destination directory to copy files to.
        """
        current_dir = os.getcwd()
        if not destination_dir:
            destination_dir = current_dir

        for file_pattern in self.file_patterns:
            for file_path in glob.glob(file_pattern):
                filename = os.path.basename(file_path)
                new_file_path = os.path.join(destination_dir, filename)

                if os.path.exists(new_file_path):
                    base, ext = os.path.splitext(filename)
                    i = 1
                    while os.path.exists(new_file_path):
                        new_file_path = os.path.join(destination_dir, f"{base}_{i}{ext}")
                        i += 1

                shutil.copy(file_path, new_file_path)

    def parseIMG4(self):
        """
        Parse Image4 files, extract payload data, and save to new files with .payload extension.
        """
        current_dir = os.getcwd()

        for idx, file_pattern in enumerate(self.file_patterns[:2]):  # Only BaseSystemTrustCache and StaticTrustCache
            for file_path in glob.glob(file_pattern):
                with open(file_path, 'rb') as infile:
                    img4 = IMG4(infile.read())

                    # Determine the output file path
                    base_name, _ = os.path.splitext(os.path.basename(file_path))
                    output_name = f"{base_name}.payload"
                    output_path = os.path.join(current_dir, output_name)

                    # Check if a file with the same name already exists in the current directory
                    if os.path.exists(output_path):
                        i = 1
                        while os.path.exists(output_path):
                            output_name = f"{base_name}_{i}.payload"
                            output_path = os.path.join(current_dir, output_name)
                            i += 1

                    # Write the parsed data to the new file
                    with open(output_path, 'wb') as outfile:
                        outfile.write(img4.im4p.payload.output().data)

    def parseIMP4(self, imp4_path="/System/Library/Security/OSLaunchPolicyData", output_name="OSLaunchPolicyData"):
        """
        Parse IMP4 file, extract payload data, and save to a new file with .payload extension.

        Parameters:
        - imp4_path (str): Path to the IMP4 file.
        - output_name (str): Name for the output file.
        """
        output_path = os.path.join(os.getcwd(), f"{output_name}.payload")
        with open(output_path, 'wb') as outfile:
            with open(imp4_path, 'rb') as infile:
                im4p = IM4P(infile.read())
                outfile.write(im4p.payload.output().data)

    def parseTrustCache(self):
        """
        Parse Trust Cache files, run trustcache info command, and save output to .trust_cache files.
        """
        current_dir = os.getcwd()

        for file_path in glob.glob(os.path.join(current_dir, '*.payload')):
            output_name = f"{os.path.splitext(os.path.basename(file_path))[0]}.trust_cache"
            output_path = os.path.join(current_dir, output_name)

            # Run the trustcache info command and save the output to a file
            with open(output_path, 'w') as outfile:
                subprocess.run(["trustcache", "info", file_path], stdout=outfile)

    def printTrustCacheContents(self):
        """
        Print the contents of trust_cache files in the current directory.
        """
        current_dir = os.getcwd()

        for file_path in glob.glob(os.path.join(current_dir, '*.trust_cache')):
            with open(file_path, 'r') as trust_cache_file:
                print(trust_cache_file.read())


def main():
    parser = argparse.ArgumentParser(description="Copy Trust Cache files to a specified destination.")
    parser.add_argument('--dst', '-d', required=False, help='Destination directory to copy Trust Cache files to.')
    parser.add_argument('--parse_img', action='store_true', help='Parse copied Image4 to extract payload data.')
    parser.add_argument('--parse_tc', action='store_true', help='Parse extract payload data to human-readable form trust cache using trustcache.')
    parser.add_argument('--print_tc', action='store_true', help='Print the contents of trust_cache (files must be in the current directory and ends with .trust_cache)')
    parser.add_argument('--all', action='store_true', help='parse_img -> parse_tc -> print_tc')

    args = parser.parse_args()

    file_patterns = [
        "/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4",
        "/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4",
        "/System/Library/Security/OSLaunchPolicyData"  # IMP4
    ]

    copy_trust_cache = TrustCacheParser(file_patterns)
    
    if args.dst:
        copy_trust_cache.copyFiles(args.dst)

    if args.parse_img:
        copy_trust_cache.parseIMG4()
        copy_trust_cache.parseIMP4()

    if args.parse_tc:
        copy_trust_cache.parseTrustCache()

    if args.print_tc:
        copy_trust_cache.printTrustCacheContents()
        
    if args.all:
        copy_trust_cache.parseIMG4()
        copy_trust_cache.parseIMP4()
        copy_trust_cache.parseTrustCache()
        copy_trust_cache.printTrustCacheContents()

if __name__ == "__main__":
    main()
