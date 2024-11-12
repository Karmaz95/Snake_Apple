#!/usr/bin/env python3
import sqlite3
import base64
import os
import argparse
import datetime
import pandas as pd

# Function to query and display the TCC schema
def query_schema(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info('access')")
        columns = cursor.fetchall()
        for column in columns:
            print(column[1], "|", end=" ")
        print("")
    except sqlite3.Error as e:
        print(f"Query failed: {e}")
    finally:
        conn.close()

# Function to query TCC data
def query_access(db_path, output_as_table):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM access")
        rows = cursor.fetchall()
        columns = [
            "service", "client", "client_type", "auth_value", "auth_reason", "auth_version",
            "csreq", "policy_id", "indirect_object_identifier_type", "indirect_object_identifier",
            "indirect_object_code_identity", "flags", "last_modified"
        ]
        data = []

        for row in rows:
            # Decode BLOB data where applicable
            csreq = base64.b64encode(row[6]).decode() if row[6] else "<NULL>"
            indirect_object_code_identity = base64.b64encode(row[10]).decode() if row[10] else "<NULL>"
            
            # Process fields with specific values
            client_type = {"0": "Bundle Identifier", "1": "Absolute Path"}.get(str(row[2]), "Unknown")
            auth_value = {
                "0": "Access Denied", "1": "Unknown", "2": "Allowed", "3": "Limited"
            }.get(str(row[3]), "Unknown")
            auth_reason = {
                "1": "Error", "2": "User Content", "3": "User Set", "4": "System Set",
                "5": "Service Policy", "6": "MDM Policy", "7": "Override Policy",
                "8": "Missing Usage String", "9": "Prompt Timeout", "10": "Preflight Unknown",
                "11": "Entitled", "12": "App Type Policy"
            }.get(str(row[4]), "Unknown")
            
            # Format last_modified
            last_modified = datetime.datetime.fromtimestamp(row[12]).strftime('%b %d %Y %I:%M %p') if row[12] else "<NULL>"

            data.append([
                row[0], row[1], client_type, auth_value, auth_reason, row[5], csreq, row[7] or "<NULL>",
                row[8] or "<NULL>", row[9] or "<NULL>", indirect_object_code_identity, row[11] or "<NULL>", last_modified
            ])

        if output_as_table:
            # Use pandas to print the table
            df = pd.DataFrame(data, columns=columns)
            print(df.to_string(index=False))
        else:
            for record in data:
                print(" | ".join([str(item) for item in record]))
    except sqlite3.Error as e:
        print(f"Query failed: {e}")
    finally:
        conn.close()

# Function to automatically query all available TCC databases on the system
def query_all_databases(output_as_table):
    potential_paths = [
        "/Library/Application Support/com.apple.TCC/TCC.db",
        os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
    ]

    for db_path in potential_paths:
        if os.path.exists(db_path):
            print(f"\nQuerying {db_path}:")
            query_access(db_path, output_as_table)

# Function to get available TCC databases from REG.db
def get_available_databases():
    reg_db_path = "/Library/Application Support/com.apple.TCC/REG.db"
    if not os.path.exists(reg_db_path):
        return []

    try:
        conn = sqlite3.connect(reg_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT abs_path FROM registry")
        rows = cursor.fetchall()
        return [row[0] for row in rows if os.path.exists(row[0])]
    except sqlite3.Error as e:
        print(f"Query failed: {e}")
        return []
    finally:
        conn.close()

# Function to list available TCC databases
def list_available_databases():
    available_databases = get_available_databases()
    if available_databases:
        for db in available_databases:
            print(f"{db}")
    else:
        print("No available databases found.")

# Main script execution
def main():
    parser = argparse.ArgumentParser(description='Parse TCC Database for Permissions Information')
    parser.add_argument('-p', '--path', type=str, help='Path to TCC.db file')
    parser.add_argument('-t', '--table', action='store_true', help='Output results in table format')
    parser.add_argument('-a', '--all', action='store_true', help='Automatically query all available TCC databases on the system')
    parser.add_argument('-l', '--list_db', action='store_true', help='List all available TCC databases on the system')

    args = parser.parse_args()

    if args.list_db:
        list_available_databases()
    elif args.all:
        query_all_databases(output_as_table=args.table)
    elif args.path:
        db_path = os.path.expanduser(args.path)
        if not os.path.exists(db_path):
            print(f"Error: Could not open {db_path}")
            exit(1)

        if args.table:
            query_access(db_path, output_as_table=True)
        else:
            query_schema(db_path)
            print("")
            query_access(db_path, output_as_table=False)
    else:
        parser.print_help()
        exit(0)

if __name__ == "__main__":
    main()
