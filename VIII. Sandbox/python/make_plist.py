# make_plist.py

import sys
import plistlib

def convert_xml_to_plist(xml_file, plist_file):
    try:
        with open(xml_file, 'rb') as f:
            xml_content = f.read()

        plist = plistlib.loads(xml_content)

        with open(plist_file, 'wb') as f:
            plistlib.dump(plist, f, fmt=plistlib.FMT_BINARY)

    except FileNotFoundError:
        print(f"Error: File '{xml_file}' not found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 make_plist.py <input_xml_file> <output_plist_file>")
        sys.exit(1)

    input_xml_file = sys.argv[1]
    output_plist_file = sys.argv[2]

    convert_xml_to_plist(input_xml_file, output_plist_file)
