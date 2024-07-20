import sys
import struct
import hashlib

def getASARHeaderSize(file_path):
    with open(file_path, 'rb') as f:
        asar_header = f.read(16)
        asar_header_size_bytes = asar_header[12:16]
        header_size = struct.unpack('<I', asar_header_size_bytes)[0]
        return(header_size)

def readASARHeader(file_path, header_size):
    with open(file_path, 'rb') as f:
        f.seek(16)
        asar_header = f.read(header_size)
        return(asar_header)

def calcASARHeaderHash(asar_header):
    return(hashlib.sha256(asar_header).hexdigest())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ElectronAsarIntegrityCalculator.py PATH_TO_ASAR_FILE")
        sys.exit(1)

    file_path = sys.argv[1]
    asar_header_size = getASARHeaderSize(file_path)
    asar_header_bytes = readASARHeader(file_path, asar_header_size)
    asar_header_hash = calcASARHeaderHash(asar_header_bytes)
    print(asar_header_hash)