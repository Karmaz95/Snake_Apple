import json
import os
import argparse

DEFAULT_DATABASE_FILE = 'uuid_database.json'

def load_database(db_location):
    """Load the UUID database from a JSON file."""
    if os.path.exists(db_location):
        with open(db_location, 'r') as file:
            return json.load(file)
    return {}

def save_database(database, db_location):
    """Save the UUID database to a JSON file."""
    with open(db_location, 'w') as file:
        json.dump(database, file, indent=4)

def add_record(database, path, uuids):
    """Overwrite or add new UUIDs for the executable path, converting them to lowercase."""
    uuids_lower = [uuid.lower() for uuid in uuids]
    print(f"Adding/updating record: {path} -> [{', '.join(uuids_lower)}]")
    database[path] = uuids_lower

def remove_record(database, path):
    """Remove the record for the specified executable path."""
    if path in database:
        print(f"Removing record for: {path}")
        del database[path]
    else:
        print(f"No record found for: {path}")

def append_uuid(database, path, uuids):
    """Append UUIDs to the existing list for the executable path, ensuring all UUIDs are lowercase."""
    if path in database:
        for uuid in uuids:
            uuid_lower = uuid.lower()
            if uuid_lower not in database[path]:
                print(f"Appending UUID to existing record: {path} -> {uuid_lower}")
                database[path].append(uuid_lower)
            else:
                print(f"UUID already exists for {path}: {uuid_lower}")
    else:
        print(f"Path does not exist in the database: {path}")

def display_uuids(database, path):
    """Display existing UUIDs for a given executable path."""
    if path in database:
        print(f"UUIDs for {path}: {', '.join(database[path])}")
    else:
        print(f"No record found for path: {path}")

def main():
    parser = argparse.ArgumentParser(
        description='Manage UUID database for Mach-O executables.',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\
Examples of usage:

  Add or update (replace existing) UUIDs for an executable path:
    python uuid_manager.py -p /path/to/executable -u "uuid1,uuid2,uuid3"

  Remove a record for an executable:
    python uuid_manager.py -p /path/to/executable -r

  Append UUIDs to an existing record:
    python uuid_manager.py -p /path/to/executable -a "uuid4,uuid5"

  Display UUIDs for a specified path:
    python uuid_manager.py -p /path/to/executable

  Specify a custom database location:
    python uuid_manager.py -p /path/to/executable -u "uuid1,uuid2" -d /custom/path/uuid_database.json
""")
    
    parser.add_argument('--path', '-p', type=str, help='Path to the executable')
    parser.add_argument('--uuid', '-u', type=str, help='Comma-separated UUIDs to associate with the executable')
    parser.add_argument('-r', '--remove', action='store_true', help='Remove the record for the specified executable path')
    parser.add_argument('-a', '--append_uuid', type=str, help='Comma-separated UUIDs to append to the existing record')
    parser.add_argument('--db_location', '-d', type=str, default=DEFAULT_DATABASE_FILE, help='Location of the UUID database file')
    
    args = parser.parse_args()

    # Load the specified database location
    database = load_database(args.db_location)

    # Handle removing records if -r is specified
    if args.remove and args.path:
        remove_record(database, args.path)

    # Handle adding/updating UUIDs if --path and --uuid are provided and -r is not specified
    elif args.path and args.uuid:
        uuids = args.uuid.split(',')
        add_record(database, args.path, uuids)

    # Handle appending UUIDs if --append_uuid and --path are specified
    elif args.append_uuid and args.path:
        append_uuids = args.append_uuid.split(',')
        append_uuid(database, args.path, append_uuids)

    # If only --path is specified, display existing UUIDs for that path
    elif args.path:
        display_uuids(database, args.path)

    # Save the database
    save_database(database, args.db_location)

if __name__ == "__main__":
    main()