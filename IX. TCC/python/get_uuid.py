import os
import subprocess
import argparse

def extract_uuids(path):
    """Extract UUIDs from a Mach-O file using dwarfdump."""
    uuids = []
    try:
        # Run dwarfdump command to get UUIDs
        result = subprocess.run(['dwarfdump', '--uuid', path], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'UUID:' in line:
                    uuid = line.split(':')[1].strip().split()[0]  # Extract UUID part only
                    uuids.append(uuid)
        else:
            print(f"Error running dwarfdump: {result.stderr.strip()}")
    except Exception as e:
        print(f"Error extracting UUIDs from {path}: {e}")
    return uuids

def process_path(path, add_record=False):
    """Process a single path to extract UUIDs and optionally add them to the database."""
    absolute_path = os.path.abspath(path)
    if not os.path.isfile(absolute_path) or not os.access(absolute_path, os.X_OK):
        print(f"Invalid path or not an executable: {absolute_path}")
        return

    # Extract UUIDs from the Mach-O file
    uuids = extract_uuids(absolute_path)

    # Output or add UUIDs to the database
    if uuids:
        uuid_string = ','.join(uuids)  # Combine UUIDs into a single comma-separated string
        if add_record:
            # Call uuid_manager.py with the combined UUID string
            subprocess.run(['python3', 'uuid_manager.py', '-p', absolute_path, '-u', uuid_string])
        else:
            print(f"{absolute_path}: {uuid_string}")
    else:
        print(f"No UUIDs found in {absolute_path}")

def main():
    parser = argparse.ArgumentParser(description='Extract UUIDs from specified Mach-O binaries using dwarfdump.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--path', '-p', type=str, help='Path to the Mach-O binary')
    group.add_argument('--list', '-l', type=str, help='Path to a file containing a list of binaries')
    parser.add_argument('--add_record', action='store_true', help='Add extracted UUIDs to the database')
    args = parser.parse_args()

    if args.path:
        # Process a single path
        process_path(args.path, add_record=args.add_record)
    elif args.list:
        # Process a list of paths
        if os.path.isfile(args.list):
            with open(args.list, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        process_path(line, add_record=args.add_record)
        else:
            print(f"Invalid list file: {args.list}")

if __name__ == "__main__":
    main()
