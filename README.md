# Snake & Apple
The code repository for the `Snake&Apple` article series, which documents my research about macOS security.

Each article directory contains three subdirectories:
* `mac` - source code of macOS for references.
* `custom` - code, for example, programs written for articles.
* `python` - contains the latest CrimsonUroboros and other Python scripts created during research. 

## ARTICLES
![alt](img/Snake_Apple.jpg)
* &#9745; [I. Mach-O](https://medium.com/p/a8eda4b87263)
* &#9744; [II. Code Signing]()
* &#9744; [III. Checksec]()
* &#9744; [IV. Dylibs]()

## TOOLS
### [CrimsonUroboros](II.%20Code%20Signing//python/CrimsonUroboros.py)
![alt](img/CrimsonUroboros.jpg)
Core program resulting from the Snake&Apple article series for binary analysis. You may find older versions of this script in each article directory in this repository.
* Usage
```console
usage: CrimsonUroboros [-h] -p PATH [--file_type] [--header_flags] [--endian]
                       [--header] [--load_commands] [--segments] [--sections]
                       [--symbols] [--chained_fixups] [--exports_trie] [--uuid]
                       [--main] [--strings_section] [--all_strings]
                       [--save_strings all_strings.txt] [--info]
                       [--verify_signature] [--cd_info] [--cd_requirements]
                       [--entitlements [human|xml|var]]
                       [--extract_cms cms_signature.der]
                       [--extract_certificates certificate_name]
                       [--remove_sig unsigned_binary]
                       [--sign_binary [adhoc|identity_number]]

Mach-O files parser for binary analysis

options:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to the Mach-O file

MACH-O ARGS:
  --file_type           Print binary file type
  --header_flags        Print binary header flags
  --endian              Print binary endianess
  --header              Print binary header
  --load_commands       Print binary load commands names
  --segments            Print binary segments in human-friendly form
  --sections            Print binary sections in human-friendly form
  --symbols             Print all binary symbols
  --chained_fixups      Print Chained Fixups information
  --exports_trie        Print Export Trie information
  --uuid                Print UUID
  --main                Print entry point and stack size
  --strings_section     Print strings from __cstring section
  --all_strings         Print strings from all sections
  --save_strings all_strings.txt
                        Parse all sections, detect strings, and save them to a
                        file
  --info                Print header, load commands, segments, sections,
                        symbols, and strings

CODE SIGNING ARGS:
  --verify_signature    Code Signature verification (if the contents of the
                        binary have been modified)
  --cd_info             Print Code Signature information
  --cd_requirements     Print Code Signature Requirements
  --entitlements [human|xml|var]
                        Print Entitlements in a human-readable, XML, or DER
                        format (default: human)
  --extract_cms cms_signature.der
                        Extract CMS Signature from the Code Signature and save
                        it to a given file
  --extract_certificates certificate_name
                        Extract Certificates and save them to a given file. To
                        each filename will be added an index at the end: _0 for
                        signing, _1 for intermediate, and _2 for root CA
                        certificate
  --remove_sig unsigned_binary
                        Save the new file on a disk with removed signature
  --sign_binary [adhoc|identity_number]
                        Sign binary using specified identity - use : 'security
                        find-identity -v -p codesigning' to get the identity.
                        (default: adhoc)
```
* Example:
```bash
CrimsonUroboros.py -p PATH --info
```
***
### [MachOFileFinder](I.%20Mach-O/python/MachOFileFinder.py)
Designed to find ARM64 Mach-O binaries within a specified directory and print their file type.
* Usage:
```bash
python MachOFileFinder.py PATH
```
* Example:
```bash
python MachOFileFinder.py . -r 2>/dev/null
EXECUTE:/Users/karmaz95/t/pingsender
DYLIB:/Users/karmaz95/t/dylibs/use_dylib_app/customs/custom.dylib
BUNDLE:/Users/karmaz95/t/bundles/MyBundle
```
***
### [TrustCacheParser](II.%20Code%20Signing/python/TrustCacheParser.py)
Designed to parse trust caches and print it in human readable form (based on [PyIMG4](https://github.com/m1stadev/PyIMG4) and [trustcache](https://github.com/CRKatri/trustcache))
* Usage:
```console
usage: TrustCacheParser [-h] [--dst DST] [--parse_img] [--parse_tc] [--print_tc] [--all]

Copy Trust Cache files to a specified destination.

options:
  -h, --help         show this help message and exit
  --dst DST, -d DST  Destination directory to copy Trust Cache files to.
  --parse_img        Parse copied Image4 to extract payload data.
  --parse_tc         Parse extract payload data to human-readable form trust cache using
                     trustcache.
  --print_tc         Print the contents of trust_cache (files must be in the current
                     directory and ends with .trust_cache)
  --all              parse_img -> parse_tc -> print_tc
```
***
### [SignatureReader](II.%20Code%20Signing/python/SignatureReader.py)
Designed to parse extracted cms sginature from Mach-O files.
* Usage:
```bash
# First extract CMS Signature using CrimsonUroboros 
CrimsonUroboros -p target_binary --extract_cms cms_sign
# or using extract_cms.sh script
./extract_cms.sh target_binary cms_sign
```

```console
usage: SignatureReader [-h] [--load_cms cms_signature.der]
                       [--extract_signature cms_signature.der]
                       [--extract_pubkey cert_0] [--human]

CMS Signature Loader

options:
  -h, --help            show this help message and exit
  --load_cms cms_signature.der
                        Load the DER encoded CMS Signature from the filesystem
                        and print it
  --extract_signature cms_signature.der
                        Extract and print the signature part from the DER
                        encoded CMS Signature
  --extract_pubkey cert_0
                        Extract public key from the given certificate and save
                        it to extracted_pubkey.pem
  --human               Print in human-readable format
❯ CrimsonUroboros -p signed_ad_hoc_example --extract_cms cms_sign
```
* Example:
```bash
SignatureReader --extract_signature cms_sign --human
0x25ca80ad5f11be197dc7a2d53f3db5b6bf463a38224db8c0a17fa4b8fd5ad7e0c60f2be8e8849cf2e581272290991c0db40b0d452b2d2dbf230c0ccab3a6d78e0230bca7bccbc50d379372bcddd8d8542add5ec59180bc3409b2df3bd8995301b9ba1e65ac62420c75104f12cb58b430fde8a177a1cd03940d4b0e77a9d875d65552cf96f03cb63b437c36d9bab12fa727e17603da49fcb870edaec115f90def1ac2ad12c2e9349a5470b5ed2f242b5566cd7ddee785eff8ae5484f145a8464d4dc3891b10a3b2981e9add1e4c0aec31fa80320eb5494d9623400753adf24106efdd07ad657035ed2876e9460219944a4730b0b620954961350ddb1fcf0ea539
```
***
### [extract_cms.sh](II.%20Code%20Signing/custom/extract_cms.sh)
Designed to extract cms sginature from Mach-O files (bash alternative to `SingatureReader --extract_signature`).
* Example:
```
./extract_cms.sh target_binary cms_sign
```
***
## INSTALL
```
pip -r requirements.txt
python3 -m pip install pyimg4
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64 -O /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache
xattr -d com.apple.quarantine /usr/local/bin/trustcache
```

## LIMITATIONS
* Codesigning module(codesign wrapper) works only on macOS.

## WHY UROBOROS? 
I will write the code for each article as a class SnakeX, where X will be the article number. To make it easier for the audience to follow. Each Snake class will be a child of the previous one and infinitely "eat itself" (inherit methods of the previous class), like Uroboros.

## ADDITIONAL LINKS
* [Apple Open Source](https://opensource.apple.com/releases/)
* [XNU](https://github.com/apple-oss-distributions/xnu)
* [dyld](https://github.com/apple-oss-distributions/dyld)