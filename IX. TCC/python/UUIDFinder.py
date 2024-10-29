#!/usr/bin/env python3
import os
import json
import subprocess
import argparse
from typing import List, Optional, Dict

home_directory = os.path.expanduser("~")
DEFAULT_DATABASE_FILE = os.path.join(home_directory, '.uuid_database.json')

class UUIDFinder:
    def __init__(self, db_location: str = DEFAULT_DATABASE_FILE):
        """Initialize UUIDFinder with database location."""
        self.db_location = db_location
        self.database = self.load_database()

    def load_database(self) -> dict:
        """Load the UUID database from a JSON file."""
        if os.path.exists(self.db_location):
            with open(self.db_location, 'r') as file:
                return json.load(file)
        return {}

    def save_database(self):
        """Save the UUID database to a JSON file."""
        with open(self.db_location, 'w') as file:
            json.dump(self.database, file, indent=4)

    def extract_uuids(self, path: str) -> List[str]:
        """Extract UUIDs from a Mach-O file using dwarfdump."""
        uuids = []
        try:
            result = subprocess.run(['dwarfdump', '--uuid', path], 
                                 capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'UUID:' in line:
                        uuid = line.split(':')[1].strip().split()[0].lower()
                        uuids.append(uuid)
        except Exception as e:
            print(f"Error extracting UUIDs from {path}: {e}")
        return uuids

    def get_path_uuids(self, path: str) -> Optional[List[str]]:
        """Get UUIDs for a given path from the database."""
        return self.database.get(path)

    def get_path_by_uuid(self, uuid: str) -> Optional[str]:
        """Find path corresponding to a given UUID."""
        uuid = uuid.lower()
        for path, uuids in self.database.items():
            if uuid in uuids:
                return path
        return None

    def handle_path_uuid(self, path: str, uuid: str):
        """Handle path and UUID combination for database operations."""
        absolute_path = os.path.abspath(path)
        uuid = uuid.lower()
        
        if absolute_path in self.database:
            if uuid in self.database[absolute_path]:
                print(f"Record with UUID {uuid} already exists for {absolute_path}")
            else:
                print(f"Adding UUID {uuid} to existing record for {absolute_path}")
                self.database[absolute_path].append(uuid)
        else:
            print(f"Creating new record for {absolute_path} with UUID {uuid}")
            self.database[absolute_path] = [uuid]

    def delete_path(self, path: str):
        """Delete a path and its UUIDs from the database."""
        absolute_path = os.path.abspath(path)
        if absolute_path in self.database:
            print(f"Deleting record for: {absolute_path}")
            del self.database[absolute_path]
        else:
            print(f"No record found for: {absolute_path}")

    def resolve_uuid(self, path: str):
        """Get UUIDs for a path and add them to the database."""
        absolute_path = os.path.abspath(path)
        if not os.path.isfile(absolute_path) or not os.access(absolute_path, os.X_OK):
            print(f"Invalid path or not an executable: {absolute_path}")
            return

        uuids = self.extract_uuids(absolute_path)
        if uuids:
            print(f"{absolute_path}: {', '.join(uuids)}")
            self.database[absolute_path] = uuids
        else:
            print(f"No UUIDs found in {absolute_path}")

    def show_database(self):
        """Display all records in the database."""
        if not self.database:
            print("Database is empty")
            return

        print("\nDatabase contents:")
        print("-----------------")
        for path, uuids in self.database.items():
            print(f"{path} ", end="")
            print(f"{', '.join(uuids)}")
        print("\n-----------------")

def process_paths(args):
    """Process paths based on provided arguments."""
    finder = UUIDFinder(args.db_location)

    # Handle show_db flag
    if args.show_db:
        finder.show_database()
        return

    # Handle UUID lookup without path
    if args.uuid and not args.path and not args.list:
        path = finder.get_path_by_uuid(args.uuid)
        if path:
            print(f"Path for UUID {args.uuid}: {path}")
        else:
            print(f"No path found for UUID: {args.uuid}")
        return
    
    paths = []
    if args.path:
        paths = [args.path]
    elif args.list:
        if os.path.isfile(args.list):
            with open(args.list, 'r') as file:
                paths = [line.strip() for line in file if line.strip()]
        else:
            print(f"Invalid list file: {args.list}")
            return

    for path in paths:
        absolute_path = os.path.abspath(path)
        
        if args.delete:
            finder.delete_path(absolute_path)
        elif args.uuid:
            finder.handle_path_uuid(absolute_path, args.uuid)
        elif args.resolve:
            finder.resolve_uuid(absolute_path)
        else:
            # Default behavior: display UUIDs for the path
            uuids = finder.get_path_uuids(absolute_path)
            if uuids:
                print(f"UUIDs for {absolute_path}: {', '.join(uuids)}")
            else:
                print(f"No UUIDs found for {absolute_path}")

    finder.save_database()

def main():
    parser = argparse.ArgumentParser(
        description='UUIDFinder - A tool for managing Mach-O executable UUIDs',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
---------

1. Display UUIDs for a single executable from database:
   --path /path/to/executable
   -p /path/to/executable

2. Find path for a specific UUID in database:
   --uuid 123e4567-e89b-12d3-a456-426614174000
   -u 123e4567-e89b-12d3-a456-426614174000

3. Add or update UUID for a path:
   --path /path/to/executable --uuid 123e4567-e89b-12d3-a456-426614174000
   -p /path/to/executable -u 123e4567-e89b-12d3-a456-426614174000

4. Extract and add UUIDs from executable to database:
   --path /path/to/executable --resolve
   -p /path/to/executable -r

5. Delete path and its UUIDs from database:
   --path /path/to/executable --delete
   -p /path/to/executable -d

6. Process multiple executables from a list file:
   --list /path/to/list.txt --resolve
   -l /path/to/list.txt -r

7. Show all records in the database:
   --show_db
   -s

8. Use custom database location:
   --path /path/to/executable --db_location /custom/path/db.json
   -p /path/to/executable --db_location /custom/path/db.json

Notes:
------
- All UUIDs are stored in lowercase in the database
- The default database file is 'uuid_database.json' in the current directory
- When using --list, each path should be on a new line in the list file
- The tool automatically converts relative paths to absolute paths
""")
    
    # Path specification group
    path_group = parser.add_mutually_exclusive_group()
    path_group.add_argument('--path', '-p', help='Path to the executable')
    path_group.add_argument('--list', '-l', help='Path to a file containing a list of executables')
    
    # Action group
    parser.add_argument('--uuid', '-u', help='UUID to lookup or add')
    parser.add_argument('--delete', '-d', action='store_true', help='Delete the path record from database')
    parser.add_argument('--resolve', '-r', action='store_true', help='Get UUIDs for the path and add to database')
    parser.add_argument('--show_db', '-s', action='store_true', help='Show all records in the database')
    
    # Database location
    parser.add_argument('--db_location', default=DEFAULT_DATABASE_FILE,
                      help='Location of the UUID database file')

    args = parser.parse_args()
    
    # Validate that at least one argument is provided
    if not any([args.path, args.list, args.show_db, args.uuid]):
        parser.error("At least one of --path, --list, --show_db, or --uuid is required")

    process_paths(args)

if __name__ == "__main__":
    main()