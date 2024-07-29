import sys
import lief

def extract_sandbox_operations(binary):
    """Extract sandbox operations from the Sandbox.kext file."""
    extracted_strings = []

    # Get strings from the __cstring (string table)
    for section in binary.sections:
        if section.type == lief.MachO.SECTION_TYPES.CSTRING_LITERALS:
            strings_bytes = section.content.tobytes()
            strings = strings_bytes.decode('utf-8', errors='ignore')
            extracted_strings.extend(strings.split('\x00'))

    operations = []
    capture = False

    # Extract operations based on specific markers
    for string in extracted_strings:
        if string == 'default':
            capture = True
        if capture:
            operations.append(string)
        if string == 'xpc-message-send':
            capture = False

    return operations

def main(file_path):
    # Load the Mach-O binary using LIEF
    binary = lief.parse(file_path)

    # Extract and print sandbox operations
    operations = extract_sandbox_operations(binary)
    for operation in operations:
        print(operation)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sandbox_operations.py <path_to_sandbox_kext>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)
