# TOOLS
Here is the list of all tools in this repository:  
[CrimsonUroboros](#crimsonuroboros) • [MachOFileFinder](#machofilefinder) • [TrustCacheParser](#trustcacheparser) • [SignatureReader](#signaturereader) • [extract_cms.sh](#extract_cmssh) • [ModifyMachOFlags](#modifymachoflags) • [LCFinder](#lcfinder) • [MachODylibLoadCommandsFinder](#machodylibloadcommandsfinder) • [AMFI_test.sh](VI.%20AMFI/custom/AMFI_test.sh) • [make_plist](VIII.%20Sandbox/python/make_plist.py) • [sandbox_inspector](VIII.%20Sandbox/python/sandbox_inspector.py) • [spblp_compiler_wrapper](VIII.%20Sandbox/custom/sbpl_compiler_wrapper) • [make_bundle](#make_bundle) • [make_bundle_exe](#make_bundle_exe) • [make_dmg](#make_dmg) • [electron_patcher](#electron_patcher) • [sandbox_validator](#sandbox_validator) • [sandblaster](#sandblaster) • [sip_check](#sip_check) • [crimson_waccess.py](#crimson_waccesspy) • [sip_tester](#sip_tester) • [UUIDFinder](#uuidfinder) • [IOVerify](#ioverify)  • [r2_dd](#r2_dd)
***

### [CrimsonUroboros](tests/CrimsonUroboros.py)
Core program resulting from the Snake&Apple article series for binary analysis. You may find older versions of this script in each article directory in this repository.

![alt](img/CrimsonUroboros.jpg)

#### WHY UROBOROS? 
I wrote the code for each article as a class `SnakeX`. The `X` was the article number, to make it easier for the audience to follow. Each `Snake` class is a child of the previous one. It infinitely "eats itself" (inherits methods of the last class), like Uroboros.

#### INSTALLATION
```
pip3 install -r requirements.txt
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64 -O /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache
xattr -d com.apple.quarantine /usr/local/bin/trustcache
brew install keith/formulae/dyld-shared-cache-extractor
brew install blacktop/tap/ipsw
brew install tree
```

#### LIMITATIONS
* Codesigning module(codesign wrapper) works only on macOS.
* `--dylib_hijacking` needs [ipsw](https://github.com/blacktop/ipsw) to be installed.
* `--dylibtree` needs the [dyld-shared-cache-extractor](https://github.com/keith/dyld-shared-cache-extractor) to be installed.

#### Usage
```console
usage: CrimsonUroboros [-h] [-p PATH] [-b BUNDLE] [--bundle_structure] [--bundle_info] [--bundle_info_syntax_check]
                       [--bundle_frameworks] [--bundle_plugins] [--bundle_id] [--file_type] [--header_flags]
                       [--endian] [--header] [--load_commands] [--has_cmd LC_MAIN] [--segments]
                       [--has_segment __SEGMENT] [--sections] [--has_section __SEGMENT,__section] [--symbols]
                       [--imports] [--exports] [--imported_symbols] [--chained_fixups] [--exports_trie] [--uuid]
                       [--main] [--encryption_info [(optional) save_path.bytes]] [--strings_section]
                       [--all_strings] [--save_strings all_strings.txt] [--info]
                       [--dump_data [offset,size,output_path]] [--calc_offset vm_offset] [--constructors]
                       [--dump_section __SEGMENT,__section] [--dump_binary output_path] [--verify_signature]
                       [--cd_info] [--cd_requirements] [--entitlements [human|xml|var]]
                       [--extract_cms cms_signature.der] [--extract_certificates certificate_name]
                       [--remove_sig unsigned_binary] [--sign_binary [adhoc|identity]] [--cs_offset] [--cs_flags]
                       [--verify_bundle_signature] [--remove_sig_from_bundle] [--has_pie] [--has_arc]
                       [--is_stripped] [--has_canary] [--has_nx_stack] [--has_nx_heap] [--has_xn] [--is_notarized]
                       [--is_encrypted] [--is_restricted] [--is_hr] [--is_as] [--is_fort] [--has_rpath] [--has_lv]
                       [--checksec] [--dylibs] [--rpaths] [--rpaths_u] [--dylibs_paths] [--dylibs_paths_u]
                       [--broken_relative_paths] [--dylibtree [cache_path,output_path,is_extracted]] [--dylib_id]
                       [--reexport_paths] [--hijack_sec] [--dylib_hijacking [(optional) cache_path]]
                       [--dylib_hijacking_a [cache_path]] [--prepare_dylib [(optional) target_dylib_name]]
                       [--is_built_for_sim] [--get_dyld_env] [--compiled_with_dyld_env] [--has_interposing]
                       [--interposing_symbols] [--has_suid] [--has_sgid] [--has_sticky] [--injectable_dyld]
                       [--test_insert_dylib] [--test_prune_dyld] [--test_dyld_print_to_file] [--test_dyld_SLC]
                       [--xattr] [--xattr_value xattr_name] [--xattr_all] [--has_quarantine] [--remove_quarantine]
                       [--add_quarantine] [--sandbox_container_path] [--sandbox_container_metadata]
                       [--sandbox_redirectable_paths] [--sandbox_parameters] [--sandbox_entitlements]
                       [--sandbox_build_uuid] [--sandbox_redirected_paths] [--sandbox_system_images]
                       [--sandbox_system_profiles] [--sandbox_content_protection] [--sandbox_profile_data]
                       [--extract_sandbox_operations] [--extract_sandbox_platform_profile] [--tcc] [--tcc_fda]
                       [--tcc_automation] [--tcc_sysadmin] [--tcc_desktop] [--tcc_documents] [--tcc_downloads]
                       [--tcc_photos] [--tcc_contacts] [--tcc_calendar] [--tcc_camera] [--tcc_microphone]
                       [--tcc_location] [--tcc_recording] [--tcc_accessibility] [--tcc_icloud]
                       [--parse_mpo mpo_addr] [--dump_prelink_info [(optional) out_name]]
                       [--dump_prelink_text [(optional) out_name]] [--dump_prelink_kext [kext_name]]
                       [--kext_prelinkinfo [kext_name]] [--kmod_info kext_name] [--kext_entry kext_name]
                       [--kext_exit kext_name] [--mig] [--dump_kext kext_name]

Mach-O files parser for binary analysis

options:
  -h, --help            show this help message and exit

GENERAL ARGS:
  -p, --path PATH       Path to the Mach-O file
  -b, --bundle BUNDLE   Path to the App Bundle (can be used with -p to change path of binary which is by default
                        set to: /target.app/Contents/MacOS/target)

BUNDLE ARGS:
  --bundle_structure    Print the structure of the app bundle
  --bundle_info         Print the Info.plist content of the app bundle (JSON format)
  --bundle_info_syntax_check
                        Check if bundle info syntax is valid
  --bundle_frameworks   Print the list of frameworks in the bundle
  --bundle_plugins      Print the list of plugins in the bundle
  --bundle_id           Print the CFBundleIdentifier value from the Info.plist file if it exists

MACH-O ARGS:
  --file_type           Print binary file type
  --header_flags        Print binary header flags
  --endian              Print binary endianess
  --header              Print binary header
  --load_commands       Print binary load commands names
  --has_cmd LC_MAIN     Check of binary has given load command
  --segments            Print binary segments in human-friendly form
  --has_segment __SEGMENT
                        Check if binary has given '__SEGMENT'
  --sections            Print binary sections in human-friendly form
  --has_section __SEGMENT,__section
                        Check if binary has given '__SEGMENT,__section'
  --symbols             Print all binary symbols
  --imports             Print imported symbols
  --exports             Print exported symbols
  --imported_symbols    Print symbols imported from external libraries with dylib names
  --chained_fixups      Print Chained Fixups information
  --exports_trie        Print Export Trie information
  --uuid                Print UUID
  --main                Print entry point and stack size
  --encryption_info [(optional) save_path.bytes]
                        Print encryption info if any. Optionally specify an output path to dump the encrypted data
                        (if cryptid=0, data will be in plain text)
  --strings_section     Print strings from __cstring section
  --all_strings         Print strings from all sections
  --save_strings all_strings.txt
                        Parse all sections, detect strings, and save them to a file
  --info                Print header, load commands, segments, sections, symbols, and strings
  --dump_data [offset,size,output_path]
                        Dump {size} bytes starting from {offset} to a given {filename} (e.g.
                        '0x1234,0x1000,out.bin')
  --calc_offset vm_offset
                        Calculate the real address (file on disk) of the given Virtual Memory {vm_offset} (e.g.
                        0xfffffe000748f580)
  --constructors        Print binary constructors
  --dump_section __SEGMENT,__section
                        Dump '__SEGMENT,__section' to standard output as a raw bytes
  --dump_binary output_path
                        Dump arm64 binary to a given file

CODE SIGNING ARGS:
  --verify_signature    Code Signature verification (if the contents of the binary have been modified)
  --cd_info             Print Code Signature information
  --cd_requirements     Print Code Signature Requirements
  --entitlements [human|xml|var]
                        Print Entitlements in a human-readable, XML, or DER format (default: human)
  --extract_cms cms_signature.der
                        Extract CMS Signature from the Code Signature and save it to a given file
  --extract_certificates certificate_name
                        Extract Certificates and save them to a given file. To each filename will be added an index
                        at the end: _0 for signing, _1 for intermediate, and _2 for root CA certificate
  --remove_sig unsigned_binary
                        Save the new file on a disk with removed signature
  --sign_binary [adhoc|identity]
                        Sign binary using specified identity - use : 'security find-identity -v -p codesigning' to
                        get the identity (default: adhoc)
  --cs_offset           Print Code Signature file offset
  --cs_flags            Print Code Signature flags
  --verify_bundle_signature
                        Code Signature verification (if the contents of the bundle have been modified)
  --remove_sig_from_bundle
                        Remove Code Signature from the bundle

CHECKSEC ARGS:
  --has_pie             Check if Position-Independent Executable (PIE) is set
  --has_arc             Check if Automatic Reference Counting (ARC) is in use (can be false positive)
  --is_stripped         Check if binary is stripped
  --has_canary          Check if Stack Canary is in use (can be false positive)
  --has_nx_stack        Check if stack is non-executable (NX stack)
  --has_nx_heap         Check if heap is non-executable (NX heap)
  --has_xn              Check if binary is protected by eXecute Never (XN) ARM protection
  --is_notarized        Check if the application is notarized and can pass the Gatekeeper verification
  --is_encrypted        Check if the application is encrypted (has LC_ENCRYPTION_INFO(_64) and cryptid set to 1)
  --is_restricted       Check if binary has __RESTRICT segment or CS_RESTRICT flag set
  --is_hr               Check if the Hardened Runtime is in use
  --is_as               Check if the App Sandbox is in use
  --is_fort             Check if the binary is fortified
  --has_rpath           Check if the binary utilise any @rpath variables
  --has_lv              Check if the binary has Library Validation (protection against Dylib Hijacking)
  --checksec            Run all checksec module options on the binary

DYLIBS ARGS:
  --dylibs              Print shared libraries used by specified binary with compatibility and the current version
                        (loading paths unresolved, like @rpath/example.dylib)
  --rpaths              Print all paths (resolved) that @rpath can be resolved to
  --rpaths_u            Print all paths (unresolved) that @rpath can be resolved to
  --dylibs_paths        Print absolute dylib loading paths (resolved @rpath|@executable_path|@loader_path) in order
                        they are searched for
  --dylibs_paths_u      Print unresolved dylib loading paths.
  --broken_relative_paths
                        Print 'broken' relative paths from the binary (cases where the dylib source is specified
                        for an executable directory without @executable_path)
  --dylibtree [cache_path,output_path,is_extracted]
                        Print the dynamic dependencies of a Mach-O binary recursively. You can specify the Dyld
                        Shared Cache path in the first argument, the output directory as the 2nd argument, and if
                        you have already extracted DSC in the 3rd argument (0 or 1). The output_path will be used
                        as a base for dylibtree. For example, to not extract DSC, use: --dylibs ",,1", or to
                        extract from default to default use just --dylibs or --dylibs ",,0" which will extract DSC
                        to extracted_dyld_share_cache/ in the current directory
  --dylib_id            Print path from LC_ID_DYLIB
  --reexport_paths      Print paths from LC_REEXPORT_DLIB
  --hijack_sec          Check if binary is protected against Dylib Hijacking
  --dylib_hijacking [(optional) cache_path]
                        Check for possible Direct and Indirect Dylib Hijacking loading paths. The output is printed
                        to console and saved in JSON format to /tmp/dylib_hijacking_log.json(append mode).
                        Optionally, specify the path to the Dyld Shared Cache
  --dylib_hijacking_a [cache_path]
                        Like --dylib_hijacking, but shows only possible vectors (without protected binaries)
  --prepare_dylib [(optional) target_dylib_name]
                        Compile rogue dylib. Optionally, specify target_dylib_path, it will search for the imported
                        symbols from it in the dylib specified in the --path argument and automatically add it to
                        the source code of the rogue lib. Example: --path lib1.dylib --prepare_dylib
                        /path/to/lib2.dylib

DYLD ARGS:
  --is_built_for_sim    Check if binary is built for simulator platform.
  --get_dyld_env        Extract Dyld environment variables from the loader binary.
  --compiled_with_dyld_env
                        Check if binary was compiled with -dyld_env flag and print the environment variables and
                        its values.
  --has_interposing     Check if binary has interposing sections.
  --interposing_symbols
                        Print interposing symbols if any.

AMFI ARGS:
  --has_suid            Check if the file has SetUID bit set
  --has_sgid            Check if the file has SetGID bit set
  --has_sticky          Check if the file has sticky bit set
  --injectable_dyld     Check if the binary is injectable using DYLD_INSERT_LIBRARIES
  --test_insert_dylib   Check if it is possible to inject dylib using DYLD_INSERT_LIBRARIES (INVASIVE - the binary
                        is executed)
  --test_prune_dyld     Check if Dyld Environment Variables are cleared (using DYLD_PRINT_INITIALIZERS=1) (INVASIVE
                        - the binary is executed)
  --test_dyld_print_to_file
                        Check if DYLD_PRINT_TO_FILE Dyld Environment Variables works (INVASIVE - the binary is
                        executed)
  --test_dyld_SLC       Check if DYLD_SHARED_REGION=private Dyld Environment Variables works and code can be
                        injected using DYLD_SHARED_CACHE_DIR (INVASIVE - the binary is executed)

ANTIVIRUS ARGS:
  --xattr               Print all extended attributes names
  --xattr_value xattr_name
                        Print single extended attribute value
  --xattr_all           Print all extended attributes names and their values
  --has_quarantine      Check if the file has quarantine extended attribute
  --remove_quarantine   Remove com.apple.quarantine extended attribute from the file
  --add_quarantine      Add com.apple.quarantine extended attribute to the file

SANDBOX ARGS:
  --sandbox_container_path
                        Print the sandbox container path
  --sandbox_container_metadata
                        Print the .com.apple.containermanagerd.metadata.plist contents for the given bundlein XML
                        format
  --sandbox_redirectable_paths
                        Print the redirectable paths from the sandbox container metadata as list
  --sandbox_parameters  Print the parameters from the sandbox container metadata as key-value pairs
  --sandbox_entitlements
                        Print the entitlements from the sandbox container metadata in JSON format
  --sandbox_build_uuid  Print the sandbox build UUID from the sandbox container metadata
  --sandbox_redirected_paths
                        Print the redirected paths from the sandbox container metadata as list
  --sandbox_system_images
                        Print the system images from the sandbox container metadata as key-value pairs
  --sandbox_system_profiles
                        Print the system profile from the sandbox container metadata in JSON format
  --sandbox_content_protection
                        Print the content protection from the sandbox container metadata
  --sandbox_profile_data
                        Print raw bytes ofthe sandbox profile data from the sandbox container metadata
  --extract_sandbox_operations
                        Extract sandbox operations from the Sandbox.kext file
  --extract_sandbox_platform_profile
                        Extract sandbox platform profile from the Sandbox.kext file

TCC ARGS:
  --tcc                 Print TCC permissions of the binary
  --tcc_fda             Check Full Disk Access (FDA) TCC permission for the binary
  --tcc_automation      Check Automation TCC permission for the binary
  --tcc_sysadmin        Check System Policy SysAdmin Files TCC permission for the binary
  --tcc_desktop         Check Desktop Folder TCC permission for the binary
  --tcc_documents       Check Documents Folder TCC permission for the binary
  --tcc_downloads       Check Downloads Folder TCC permission for the binary
  --tcc_photos          Check Photos Library TCC permission for the binary
  --tcc_contacts        Check Contacts TCC permission for the binary
  --tcc_calendar        Check Calendar TCC permission for the binary
  --tcc_camera          Check Camera TCC permission for the binary
  --tcc_microphone      Check Microphone TCC permission for the binary
  --tcc_location        Check Location Services TCC permission for the binary
  --tcc_recording       Check Screen Recording TCC permission for the binary
  --tcc_accessibility   Check Accessibility TCC permission for the binary
  --tcc_icloud          Check iCloud (Ubiquity) TCC permission for the binary

XNU ARGS:
  --parse_mpo mpo_addr  Parse mac_policy_ops at given address from Kernel Cache and print pointers in use (not
                        zeroed)
  --dump_prelink_info [(optional) out_name]
                        Dump "__PRELINK_INFO,__info" to a given file (default: "PRELINK_info.txt")
  --dump_prelink_text [(optional) out_name]
                        Dump "__PRELINK_TEXT,__text" to a given file (default: "PRELINK_text.txt")
  --dump_prelink_kext [kext_name]
                        Dump prelinked KEXT {kext_name} from decompressed Kernel Cache PRELINK_TEXT segment to a
                        file named: prelinked_{kext_name}.bin
  --kext_prelinkinfo [kext_name]
                        Print _Prelink properties from PRELINK_INFO,__info for a give {kext_name}
  --kmod_info kext_name
                        Parse kmod_info structure for the given {kext_name} from Kernel Cache
  --kext_entry kext_name
                        Calculate the virtual memory address of the __start (entrypoint) for the given {kext_name}
                        Kernel Extension
  --kext_exit kext_name
                        Calculate the virtual memory address of the __stop (exitpoint) for the given {kext_name}
                        Kernel Extension
  --mig                 Search for MIG subsystem and prints message handlers
  --dump_kext kext_name
                        Dump the kernel extension binary from the kernelcache.decompressed file
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
### [ModifyMachOFlags](III.%20Checksec/python/ModifyMachOFlags.py)
Designed to change Mach-O header flags.
* Usage:
```console
usage: ModifyMachOFlags [-h] -i INPUT -o OUT [--flag FLAG] [--sign_binary [adhoc|identity_number]]

Modify the Mach-O binary flags.

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to the Mach-O file.
  -o OUT, --out OUT     Where to save a modified file.
  --flag FLAG           Specify the flag constant name and value (e.g., NO_HEAP_EXECUTION=1). Can be used multiple times. Available
                        flags: NOUNDEFS, INCRLINK, DYLDLINK, BINDATLOAD, PREBOUND, SPLIT_SEGS, LAZY_INIT, TWOLEVEL, FORCE_FLAT,
                        NOMULTIDEFS, NOFIXPREBINDING, PREBINDABLE, ALLMODSBOUND, SUBSECTIONS_VIA_SYMBOLS, CANONICAL, WEAK_DEFINES,
                        BINDS_TO_WEAK, ALLOW_STACK_EXECUTION, ROOT_SAFE, SETUID_SAFE, NO_REEXPORTED_DYLIBS, PIE,
                        DEAD_STRIPPABLE_DYLIB, HAS_TLV_DESCRIPTORS, NO_HEAP_EXECUTION, APP_EXTENSION_SAFE,
                        NLIST_OUTOFSYNC_WITH_DYLDINFO, SIM_SUPPORT, DYLIB_IN_CACHE
  --sign_binary [adhoc|identity_number]
                        Sign binary using specified identity - use : 'security find-identity -v -p codesigning' to get the
                        identity. (default: adhoc)
```
* Example:
```bash
ModifyMachOFlags -i hello -o hello_modified --flag NO_HEAP_EXECUTION=1 --sign_binary
```
***
### [LCFinder](III.%20Checksec/python/LCFinder.py)
Designed to find if specified Load Command exist in the binary or list of binaries.
* Usage:
```console
usage: LCFinder [-h] [--path PATH] [--list_path LIST_PATH] --lc LC

Check for a specific load command in Mach-O binaries.

options:
  -h, --help            show this help message and exit
  --path PATH, -p PATH  Absolute path to the valid MachO binary.
  --list_path LIST_PATH, -l LIST_PATH
                        Path to a wordlist file containing absolute paths.
  --lc LC               The load command to check for.
```
* Example:
```bash
LCFinder -l macho_paths.txt --lc SEGMENT_64 2>/dev/null
LCFinder -p hello --lc lc_segment_64 2>/dev/null
```
***
### [MachODylibLoadCommandsFinder](IV.%20Dylibs/python/MachODylibLoadCommandsFinder.py)
Designed to Recursively crawl the system and parse Mach-O files to find DYLIB related load commands.
Print the total Mach-O files analyzed and how many DYLIB-related LCs existed
* Usage:
```console
MachODylibLoadCommandsFinder 2>/dev/null
```
***
### [check_amfi](VI.%20AMFI/python/check_amfi.py)
Simple script for calculating `amfiFlags` (described [here](https://karol-mazurek.medium.com/dyld-do-you-like-death-vi-1013a69118ff) in `ProcessConfig — AMFI properties`)
* Usage:
```console
python3 check_amfi.py 0x1df
```
***
### [make_bundle](App%20Bundle%20Extension/custom/make_bundle.sh)
Build a codeless bundle with a red icon.
* Usage:
```console
./make_bundle.sh
```
***
### [make_bundle_exe](App%20Bundle%20Extension/custom/make_bundle_exe.sh)
Bash template for building a PoC app bundle with Mach-O binary that utilizes Framework:
* Usage:
```console
./make_bundle_exe.sh
```
***
### [make_dmg](App%20Bundle%20Extension/custom/make_dmg.sh)
Script for packing the app in a compressed DMG container:
* Usage (change names in the script):
```console
./make_dmg.sh
```
### [electron_patcher](App%20Bundle%20Extension/custom/electron_patcher.py)
Python script for extracting ASAR files from Electron apps and patching them with a custom ASAR file. 
```
python3 electron_patcher.py extract app_bundle.app extracted_asar
python3 electron_patcher.py pack extracted_asar app_bundle.app
```
### [sandbox_validator](VIII.%20Sandbox/custom/sandbox_validator.c)
It can be used to quickly check if a given process is allowed to perform a particular operation while it is sandboxed.
```bash
# Compile
clang -o sandbox_validator sandbox_validator.c

# Usage: sandbox_validator PID "OPERATION" "FILTER_NAME" "FILTER_VALUE"
sandbox_validator 93298
sandbox_validator 93298 "file-read*"
sandbox_validator 93298 "file-read*" PATH "/users/karmaz/.trash"
sandbox_validator 93298 "authorization-right-obtain" RIGHT_NAME "system.burn"
```
### [sandblaster](https://github.com/Karmaz95/sandblaster)
This is my forked version of [sandblaster](https://github.com/cellebrite-labs/sandblaster) with MacOS Support:
```bash
python3 reverse_sandbox.py -o sonoma_sandbox_operations.txt profile_sb -r 17
```
### [sip_check](VIII.%20Sandbox/custom/sip_check.py)
A simple program to check if SIP is enabled in the system with more details.  
It was introduced in [the article about SIP](https://karol-mazurek.medium.com/system-integrity-protection-sip-140562b07fea?sk=v2%2F9c293b8f-c376-4603-b8a1-2872ba3395cf)
```bash
python3 sip_check.py
SIP Configuration Flags:
CSR_ALLOW_UNTRUSTED_KEXTS: Off
CSR_ALLOW_UNRESTRICTED_FS: Off
CSR_ALLOW_TASK_FOR_PID: Off
CSR_ALLOW_KERNEL_DEBUGGER: Off
CSR_ALLOW_APPLE_INTERNAL: Off
CSR_ALLOW_UNRESTRICTED_DTRACE: Off
CSR_ALLOW_UNRESTRICTED_NVRAM: Off
CSR_ALLOW_DEVICE_CONFIGURATION: Off
CSR_ALLOW_ANY_RECOVERY_OS: Off
CSR_ALLOW_UNAPPROVED_KEXTS: Off
CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE: Off
CSR_ALLOW_UNAUTHENTICATED_ROOT: Off
```
### [crimson_waccess.py](VIII.%20Sandbox/python/crimson_waccess.py)
It can be use for checking the possibility of file modification and creation in a given directory.  
It was introduced in [the article about SIP](https://karol-mazurek.medium.com/system-integrity-protection-sip-140562b07fea?sk=v2%2F9c293b8f-c376-4603-b8a1-2872ba3395cf)
```bash
python3 crimson_waccess.py -f sip_protected_paths.txt
```
### [sip_tester](VIII.%20Sandbox/python/sip_tester)
It can be used to check if a given path, process or service is SIP-protected and also to check missing paths from `rootless.conf`.  
It was introduced in [the article about SIP](https://karol-mazurek.medium.com/system-integrity-protection-sip-140562b07fea?sk=v2%2F9c293b8f-c376-4603-b8a1-2872ba3395cf)
```bash
sip_tester --path /bin
sip_tester --pid 1234
sip_tester --service com.apple.kernelmanager_helper
sip_tester --missing_paths
```
### [UUIDFinder](IX.%20TCC/python/UUIDFinder.py)
A tool for creating a centralized UUID database for macOS. It is used to find UUIDs of files and directories.
It was introduced in the article [Apple UUID Finder](https://karol-mazurek.medium.com/apple-uuid-finder-a5173bdd1a8a?sk=v2%2F04bb0d32-6dc9-437d-bf72-8f65e03fed90)
```bash
usage: UUIDFinder [-h] [--path PATH | --list LIST] [--uuid UUID] [--delete] [--resolve] [--show_db] [--db_location DB_LOCATION]

UUIDFinder - A tool for managing Mach-O executable UUIDs

options:
  -h, --help            show this help message and exit
  --path, -p PATH       Path to the executable
  --list, -l LIST       Path to a file containing a list of executables
  --uuid, -u UUID       UUID to lookup or add
  --delete, -d          Delete the path record from database
  --resolve, -r         Get UUIDs for the path and add to database
  --show_db, -s         Show all records in the database
  --db_location DB_LOCATION
                        Location of the UUID database file

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
```
### [TCCParser](IX.%20TCC/python/TCCParser.py)
A tool for querying macOS TCC (Transparency, Consent, and Control) databases.
It was introduced in the article [](todo)
```bash
usage: TCCParser [-h] [-p PATH] [-t] [-a] [-l]

Parse TCC Database for Permissions Information

options:
  -h, --help            Show this help message and exit
  -p PATH, --path PATH  Path to TCC.db file to analyze
  -t, --table           Output results in table format
  -a, --all             Automatically query all available TCC databases on the system
  -l, --list_db         List all available TCC databases on the system

Examples:
---------

1. List all available TCC databases on the system:
   --list_db
   -l

2. Query a specific TCC database:
   --path /path/to/TCC.db
   -p /path/to/TCC.db

3. Display the query results in a formatted table:
   --path /path/to/TCC.db --table
   -p /path/to/TCC.db -t

4. Automatically query all known TCC databases:
   --all
   -a

Notes:
------
- The tool retrieves details such as client, service, and authorization status for each entry in the TCC database.
- The `--list_db` option helps users locate all known TCC databases on the system, sourced from `REG.db`.
```

### [IOVerify](X.%20NU/custom/drivers/IOVerify.c)
This tool allows for direct interaction with macOS IOKit drivers using IOConnectCallMethod. It was introduced in the article I made for PHRACK - [Mapping IOKit Methods Exposed to User Space on macOS](https://phrack.org/issues/72/9_md#article). 
```bash
❯ ./IOVerify -h
Usage: ./IOVerify -n <name> (-m <method> | -y <spec>) [options]
Options:
  -n <name>      Target driver class name (required).
  -t <type>      Connection type (default: 0).
  -m <id>        Method selector ID.
  -y <spec>      Specify method and buffer sizes in one string.
                 Format: "ID: [IN_SCA, IN_STR, OUT_SCA, OUT_STR]"
                 Example: -y "0: [0, 96, 0, 96]"
  -p <string>    Payload as a string.
  -f <file>      File path for payload.
  -b <hex_str>   Space-separated hex string payload.
  -i <size>      Input buffer size (ignored if -y is used).
  -o <size>      Output buffer size (ignored if -y is used).
  -s <value>     Scalar input (uint64_t). Can be specified multiple times.
  -S <count>     Scalar output count (ignored if -y is used).
  -h             Show this help message.


❯ ./IOVerify -n "H11ANEIn" -t 1 -y "0: [0,1,0,1]"
Starting verification for driver: H11ANEIn

--- [VERIFY] Event Log ---
Driver:          H11ANEIn
Connection Type: 1
Method Selector: 0
Result:          0xe00002c2 ((iokit/common) invalid argument)

--- Scalar I/O ---
Scalar In Cnt:   0
Scalar Out Cnt:  0

--- Structure I/O ---
Input Size:  1 bytes
Input Data:
00

Output Size: 1 bytes
Output Data:
00
--- End of Log ---
```
### [r2_dd](I.%20Mach-O/python/r2_dd.py)
A wrapper script that uses radare2 to dump binary data from Mach-O files between specified virtual addresses. It automatically maps virtual addresses to file offsets.
* Usage:
```bash
python3 r2_dd.py BINARY_PATH START_ADDR END_ADDR OUT_FILE
```

* Example:
```bash
python3 r2_dd.py ./kernelcache 0xFFFFFF80002A0000 0xFFFFFF80002A0500 ./dump.bin
```

* Note: Requires `radare2` to be installed:
```bash
brew install radare2
```