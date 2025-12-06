#!/usr/bin/env python3
import sys
import subprocess
import os

def print_usage():
    print("Usage: r2_dd BINARY_PATH START_ADDR END_ADDR OUT_FILE")
    print("Example: r2_dd ./kernelcache 0xFFFFFF80002A0000 0xFFFFFF80002A0500 ./dump.bin")
    print("\nNote: Addresses can be Hex (0x...) or Decimal.")

def parse_addr(addr_str):
    """Parses hex or decimal string to integer."""
    try:
        if addr_str.lower().startswith("0x"):
            return int(addr_str, 16)
        else:
            return int(addr_str)
    except ValueError:
        print(f"Error: Invalid address format '{addr_str}'")
        sys.exit(1)

def main():
    if len(sys.argv) != 5:
        print_usage()
        sys.exit(1)

    bin_path = sys.argv[1]
    start_str = sys.argv[2]
    end_str = sys.argv[3]
    out_file = sys.argv[4]

    if not os.path.exists(bin_path):
        print(f"Error: Binary file not found at '{bin_path}'")
        sys.exit(1)

    start_ea = parse_addr(start_str)
    end_ea = parse_addr(end_str)

    if end_ea <= start_ea:
        print("Error: END_ADDR must be greater than START_ADDR")
        sys.exit(1)

    size = end_ea - start_ea

    print(f"--- Extraction Details ---")
    print(f"Binary: {bin_path}")
    print(f"Start : {hex(start_ea)}")
    print(f"End   : {hex(end_ea)}")
    print(f"Size  : {size} bytes")
    print(f"--------------------------")

    # We use radare2 (r2) because it automatically maps Virtual Addresses 
    # to file offsets for Mach-O/ELF files.
    # -q : quiet mode
    # -N : no user settings (clean environment)
    # -c : execute command
    # s  : seek to address
    # pr : print raw bytes
    
    r2_cmd = ["r2", "-q", "-N", "-c", f"s {start_str}; pr {size}", bin_path]

    try:
        print("Running r2...")
        with open(out_file, "wb") as f:
            # We pipe stderr to DEVNULL to avoid r2 warnings cluttering output
            result = subprocess.run(r2_cmd, stdout=f, stderr=subprocess.DEVNULL)
        
        if result.returncode == 0:
            print(f"Success! Saved to: {out_file}")
            # Verify file size
            if os.path.exists(out_file):
                dump_size = os.path.getsize(out_file)
                if dump_size == size:
                    print("Verification: File size matches requested size.")
                else:
                    print(f"Warning: Dumped size ({dump_size}) differs from expected ({size}).")
        else:
            print("Error: r2 command failed. Do you have radare2 installed?")
            
    except FileNotFoundError:
        print("Error: 'r2' command not found. Please install radare2 (brew install radare2).")

if __name__ == "__main__":
    main()
