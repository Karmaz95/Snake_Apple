#!/usr/bin/env python3
from asn1crypto.cms import ContentInfo
import argparse
import subprocess

def read_file_to_bytes(filename):
    '''Read a file and return its contents as bytes.'''
    with open(filename, 'rb') as file:
        file_contents = file.read()
    return file_contents

def loadCMS(cms_signature, human_readable=False):
    '''Returns SignedData information in a human-readable or native format about the CMS Signature loaded from a file.'''
    # Load the CMS signature using asn1crypto
    content_info = ContentInfo.load(cms_signature)
    # Access the SignedData structure
    cms = content_info['content']

    if human_readable:
        openssl_cmd = ['openssl', 'cms', '-cmsout', '-print', '-inform', 'DER', '-in', args.load_cms]
        result = subprocess.run(openssl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    else:
        return cms.native

def extractSignature(cms_signature, human_readable=False):
    '''Return Signature from the CMS Signature'''
    content_info = ContentInfo.load(cms_signature)
    # Access the SignedData structure
    signed_data = content_info['content']
    # Access the SignerInfo structure
    signer_info = signed_data['signer_infos'][0]
    # Extract the signature
    signature = signer_info['signature']
   
    if human_readable:
        return f"0x{signature.contents.hex()}"
    else:
        return signature.native

def extractPubKeyFromCert():
    openssl_cmd = ['openssl', 'x509', '-inform', 'DER', '-in', args.extract_pubkey, '-pubkey', '-noout']
    result = subprocess.run(openssl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        with open('extracted_pubkey.pem', 'wb') as pubkey_file:
            pubkey_file.write(result.stdout)
    else:
        print("Error:", result.stderr.decode('utf-8'))

# Argument parsing
parser = argparse.ArgumentParser(description='CMS Signature Loader')
parser.add_argument('--load_cms', help="Load the DER encoded CMS Signature from the filesystem and print it", metavar='cms_signature.der')
parser.add_argument('--extract_signature', help="Extract and print the signature part from the DER encoded CMS Signature", metavar='cms_signature.der')
parser.add_argument('--extract_pubkey', help="Extract public key from the given certificate and save it to extracted_pubkey.pem", metavar='cert_0')
parser.add_argument('--human', help="Print in human-readable format", action='store_true')
args = parser.parse_args()

if args.load_cms:
    cms_signature = read_file_to_bytes(args.load_cms)
    print(loadCMS(cms_signature, args.human))

if args.extract_signature:
    cms_signature = read_file_to_bytes(args.extract_signature)
    print(extractSignature(cms_signature, args.human))

if args.extract_pubkey:
    extractPubKeyFromCert()