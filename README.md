# Snake & Apple
![alt](img/Snake_Apple.jpg)
The code repository for the `Snake&Apple` article series, which documents my research about macOS security.

Each article directory contains three subdirectories:
* `mac` - source code of macOS for references.
* `custom` - code, for example, programs written for articles.
* `python` - contains the latest CrimsonUroboros and other Python scripts created during research. 

## ARTICLES

* &#9745; [I. Mach-O](https://karol-mazurek95.medium.com/snake-apple-i-mach-o-a8eda4b87263?sk=v2%2Ffc1cbfa4-e2d4-4387-9a82-b27191978b5b)
* &#9745; [II. Code Signing](https://karol-mazurek95.medium.com/snake-apple-ii-code-signing-f0a9967b7f02?sk=v2%2Fbbc87007-89ca-4135-91d6-668b5d2fe9ae)
* &#9745; [III. Checksec](https://karol-mazurek95.medium.com/snake-apple-iii-checksec-ed64a4b766c1?sk=v2%2Fb4b8d637-e906-4b6b-8088-ca1f893cd787)
* &#9745; [IV. Dylibs](https://karol-mazurek.medium.com/snake-apple-iv-dylibs-2c955439b94e?sk=v2%2Fdef72b7a-121a-47a1-af89-7bf53aed1ea2)
* &#9745; [V. Dyld](https://karol-mazurek.medium.com/snake-apple-v-dyld-8b36b674cc44?sk=v2%2F4acb16f8-fa88-41f0-8d7c-1362f4060010)
  * &#9745; [DYLD — Do You Like Death? (I)](https://karol-mazurek.medium.com/dyld-do-you-like-death-i-8199faad040e?sk=v2%2F359b081f-d944-409b-9e7c-95f7c171b969) - Startup | kernArgs | rebaseSelf | initializeLibc | task_self_trap | stack_guard | findArgv | findEnvp | findApple
  * &#9745; [DYLD — Do You Like Death? (II)](https://karol-mazurek.medium.com/dyld-do-you-like-death-ii-b74360b8af47?sk=v2%2Ff0cff71c-5345-4228-a639-653325fc979d) - handleDyldInCache| isBuiltForSimulator | isTranslated | crossarch_trap | Calling Convention on ARM64v8 | __unused attribute | Dyld Shared Region | thisDyldUuid | hasExistingDyldCache | shared_region_check_np | Carry flag | dynamic data header | dyldInCacheMH
  * &#9745; [DYLD — Do You Like Death? (III)](https://karol-mazurek.medium.com/dyld-do-you-like-death-iii-af77701a3034?sk=v2%2F06c92503-2db9-40e2-b139-c9ae0a35e7b3) - handleDyldInCache | DYLD_IN_CACHE | restartWithDyldInCache | dyld_all_image_infos | calculating offset for debugging Dyld in Cache
  * &#9745; [DYLD — Do You Like Death? (IV)](https://karol-mazurek.medium.com/dyld-do-you-like-death-iv-ede6b157752c?sk=v2%2F87ebe38d-004c-41a6-bc1f-43898494a512) - RuntimeLocks | MemoryManager | dyld_hw_tpro | Lambda Capture | withWritableMemory | PAC | arm64e_preview_abi | __ptrauth_dyld_tpro0 | WriteProtectionState | previousState | os_compiler_barrier | 
  * &#9745; [DYLD — Do You Like Death? (V)](https://karol-mazurek.medium.com/dyld-do-you-like-death-v-c40a267573cb?sk=v2%2F4c9f16b2-59bd-406a-945d-10a1fba1001b) - Linker Standard Library | EphemeralAllocator | Dyld Private Memory | PersistentAllocator | vm_allocate | vm_protect | _kernelrpc_mach_vm_allocate_trap | _kernelrpc_mach_vm_protect_trap 
  * &#9745; [DYLD — Do You Like Death? (VI)](https://karol-mazurek.medium.com/dyld-do-you-like-death-vi-1013a69118ff?sk=v2%2F37b3a61f-8483-4b38-977d-7f860944862b) - ProcessConfig | Process::Process | Process::Security | csr_check | CSR_ALLOW_APPLE_INTERNAL | csrctl | syscall_csr_check | AMFI | internalInstall | isRestricted | isFairPlayEncrypted | amfiFlags | amfi_check_dyld_policy_self | ___sandbox_ms | ___mac_syscall | mpo_policy_syscall_t | MAC policy | com.apple.driver.AppleMobileFileIntegrity | _policy_syscall | _check_dyld_policy_internal | macos_Dyld_policy_collect_state | logDyldPolicyData | DYLD_AMFI_FAKE | getAMFI | pruneEnvVars | com.apple.security.cs.allow-dyld-environment-variables
  * &#9744; [DYLD — Do You Like Death? (VII)]() - ProcessConfig::Logging::Logging
* &#9744; [VI. AMFI]()


## TOOLS
[CrimsonUroboros](#crimsonuroboros) • [MachOFileFinder](#machofilefinder) • [TrustCacheParser](#trustcacheparser) • [SignatureReader](#signaturereader) • [extract_cms.sh](#extract_cmssh) • [ModifyMachOFlags](#modifymachoflags) • [LCFinder](#lcfinder) • [MachODylibLoadCommandsFinder](#machodylibloadcommandsfinder)
***

### [CrimsonUroboros](tests/CrimsonUroboros.py)
![alt](img/CrimsonUroboros.jpg)
Core program resulting from the Snake&Apple article series for binary analysis. You may find older versions of this script in each article directory in this repository.
* Usage
```console
usage: CrimsonUroboros [-h] -p PATH [--file_type] [--header_flags] [--endian]
                       [--header] [--load_commands] [--has_cmd LC_MAIN]
                       [--segments] [--has_segment __SEGMENT] [--sections]
                       [--has_section __SEGMENT,__section] [--symbols]
                       [--imports] [--exports] [--imported_symbols]
                       [--chained_fixups] [--exports_trie] [--uuid] [--main]
                       [--encryption_info [(optional) save_path.bytes]]
                       [--strings_section] [--all_strings]
                       [--save_strings all_strings.txt] [--info]
                       [--dump_data [offset,size,output_path]]
                       [--calc_offset vm_offset] [--constructors]
                       [--verify_signature] [--cd_info] [--cd_requirements]
                       [--entitlements [human|xml|var]]
                       [--extract_cms cms_signature.der]
                       [--extract_certificates certificate_name]
                       [--remove_sig unsigned_binary]
                       [--sign_binary [adhoc|identity]] [--cs_offset]
                       [--cs_flags] [--has_pie] [--has_arc] [--is_stripped]
                       [--has_canary] [--has_nx_stack] [--has_nx_heap]
                       [--has_xn] [--is_notarized] [--is_encrypted]
                       [--is_restricted] [--is_hr] [--is_as] [--is_fort]
                       [--has_rpath] [--has_lv] [--checksec] [--dylibs]
                       [--rpaths] [--rpaths_u] [--dylibs_paths]
                       [--dylibs_paths_u] [--broken_relative_paths]
                       [--dylibtree [cache_path,output_path,is_extracted]]
                       [--dylib_id] [--reexport_paths] [--hijack_sec]
                       [--dylib_hijacking [(optional) cache_path]]
                       [--dylib_hijacking_a [cache_path]]
                       [--prepare_dylib [(optional) target_dylib_name]]
                       [--is_built_for_sim] [--get_dyld_env]
                       [--compiled_with_dyld_env] [--has_interposing]
                       [--interposing_symbols]
                       [--dump_prelink_info [(optional) out_name]]
                       [--dump_prelink_text [(optional) out_name]]
                       [--dump_prelink_kext [kext_name]]
                       [--kext_prelinkinfo [kext_name]]
                       [--kmod_info kext_name] [--kext_entry kext_name]
                       [--kext_exit kext_name] [--mig] [--has_suid]
                       [--has_sgid] [--has_sticky] [--injectable_dyld]
                       [--test_insert_dylib] [--test_prune_dyld]
                       [--test_dyld_print_to_file]

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
  --imported_symbols    Print symbols imported from external libraries with
                        dylib names
  --chained_fixups      Print Chained Fixups information
  --exports_trie        Print Export Trie information
  --uuid                Print UUID
  --main                Print entry point and stack size
  --encryption_info [(optional) save_path.bytes]
                        Print encryption info if any. Optionally specify an
                        output path to dump the encrypted data (if cryptid=0,
                        data will be in plain text)
  --strings_section     Print strings from __cstring section
  --all_strings         Print strings from all sections
  --save_strings all_strings.txt
                        Parse all sections, detect strings, and save them to a
                        file
  --info                Print header, load commands, segments, sections,
                        symbols, and strings
  --dump_data [offset,size,output_path]
                        Dump {size} bytes starting from {offset} to a given
                        {filename} (e.g. '0x1234,0x1000,out.bin')
  --calc_offset vm_offset
                        Calculate the real address (file on disk) of the given
                        Virtual Memory {vm_offset} (e.g. 0xfffffe000748f580)
  --constructors        Print binary constructors

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
                        each filename will be added an index at the end: _0
                        for signing, _1 for intermediate, and _2 for root CA
                        certificate
  --remove_sig unsigned_binary
                        Save the new file on a disk with removed signature
  --sign_binary [adhoc|identity]
                        Sign binary using specified identity - use : 'security
                        find-identity -v -p codesigning' to get the identity
                        (default: adhoc)
  --cs_offset           Print Code Signature file offset
  --cs_flags            Print Code Signature flags

CHECKSEC ARGS:
  --has_pie             Check if Position-Independent Executable (PIE) is set
  --has_arc             Check if Automatic Reference Counting (ARC) is in use
                        (can be false positive)
  --is_stripped         Check if binary is stripped
  --has_canary          Check if Stack Canary is in use (can be false
                        positive)
  --has_nx_stack        Check if stack is non-executable (NX stack)
  --has_nx_heap         Check if heap is non-executable (NX heap)
  --has_xn              Check if binary is protected by eXecute Never (XN) ARM
                        protection
  --is_notarized        Check if the application is notarized and can pass the
                        Gatekeeper verification
  --is_encrypted        Check if the application is encrypted (has
                        LC_ENCRYPTION_INFO(_64) and cryptid set to 1)
  --is_restricted       Check if binary has __RESTRICT segment or CS_RESTRICT
                        flag set
  --is_hr               Check if the Hardened Runtime is in use
  --is_as               Check if the App Sandbox is in use
  --is_fort             Check if the binary is fortified
  --has_rpath           Check if the binary utilise any @rpath variables
  --has_lv              Check if the binary has Library Validation (protection
                        against Dylib Hijacking)
  --checksec            Run all checksec module options on the binary

DYLIBS ARGS:
  --dylibs              Print shared libraries used by specified binary with
                        compatibility and the current version (loading paths
                        unresolved, like @rpath/example.dylib)
  --rpaths              Print all paths (resolved) that @rpath can be resolved
                        to
  --rpaths_u            Print all paths (unresolved) that @rpath can be
                        resolved to
  --dylibs_paths        Print absolute dylib loading paths (resolved
                        @rpath|@executable_path|@loader_path) in order they
                        are searched for
  --dylibs_paths_u      Print unresolved dylib loading paths.
  --broken_relative_paths
                        Print 'broken' relative paths from the binary (cases
                        where the dylib source is specified for an executable
                        directory without @executable_path)
  --dylibtree [cache_path,output_path,is_extracted]
                        Print the dynamic dependencies of a Mach-O binary
                        recursively. You can specify the Dyld Shared Cache
                        path in the first argument, the output directory as
                        the 2nd argument, and if you have already extracted
                        DSC in the 3rd argument (0 or 1). The output_path will
                        be used as a base for dylibtree. For example, to not
                        extract DSC, use: --dylibs ",,1", or to extract from
                        default to default use just --dylibs or --dylibs ",,0"
                        which will extract DSC to extracted_dyld_share_cache/
                        in the current directory
  --dylib_id            Print path from LC_ID_DYLIB
  --reexport_paths      Print paths from LC_REEXPORT_DLIB
  --hijack_sec          Check if binary is protected against Dylib Hijacking
  --dylib_hijacking [(optional) cache_path]
                        Check for possible Direct and Indirect Dylib Hijacking
                        loading paths. The output is printed to console and
                        saved in JSON format to
                        /tmp/dylib_hijacking_log.json(append mode).
                        Optionally, specify the path to the Dyld Shared Cache
  --dylib_hijacking_a [cache_path]
                        Like --dylib_hijacking, but shows only possible
                        vectors (without protected binaries)
  --prepare_dylib [(optional) target_dylib_name]
                        Compile rogue dylib. Optionally, specify
                        target_dylib_path, it will search for the imported
                        symbols from it in the dylib specified in the --path
                        argument and automatically add it to the source code
                        of the rogue lib. Example: --path lib1.dylib
                        --prepare_dylib /path/to/lib2.dylib

DYLD ARGS:
  --is_built_for_sim    Check if binary is built for simulator platform.
  --get_dyld_env        Extract Dyld environment variables from the loader
                        binary.
  --compiled_with_dyld_env
                        Check if binary was compiled with -dyld_env flag and
                        print the environment variables and its values.
  --has_interposing     Check if binary has interposing sections.
  --interposing_symbols
                        Print interposing symbols if any.

AMFI ARGS:
  --dump_prelink_info [(optional) out_name]
                        Dump "__PRELINK_INFO,__info" to a given file (default:
                        "PRELINK_info.txt")
  --dump_prelink_text [(optional) out_name]
                        Dump "__PRELINK_TEXT,__text" to a given file (default:
                        "PRELINK_text.txt")
  --dump_prelink_kext [kext_name]
                        Dump prelinked KEXT {kext_name} from decompressed
                        Kernel Cache PRELINK_TEXT segment to a file named:
                        prelinked_{kext_name}.bin
  --kext_prelinkinfo [kext_name]
                        Print _Prelink properties from PRELINK_INFO,__info for
                        a give {kext_name}
  --kmod_info kext_name
                        Parse kmod_info structure for the given {kext_name}
                        from Kernel Cache
  --kext_entry kext_name
                        Calculate the virtual memory address of the __start
                        (entrpoint) for the given {kext_name} Kernel Extension
  --kext_exit kext_name
                        Calculate the virtual memory address of the __stop
                        (exitpoint) for the given {kext_name} Kernel Extension
  --mig                 Search for MIG subsystem and prints message handlers
  --has_suid            Check if the file has SetUID bit set
  --has_sgid            Check if the file has SetGID bit set
  --has_sticky          Check if the file has sticky bit set
  --injectable_dyld     Check if the binary is injectable using
                        DYLD_INSERT_LIBRARIES
  --test_insert_dylib   Check if it is possible to inject dylib using
                        DYLD_INSERT_LIBRARIES (INVASIVE - the binary is
                        executed)
  --test_prune_dyld     Check if Dyld Environment Variables are cleared (using
                        DYLD_PRINT_INITIALIZERS=1) (INVASIVE - the binary is
                        executed)
  --test_dyld_print_to_file
                        Check if YLD_PRINT_TO_FILE Dyld Environment Variables
                        works (INVASIVE - the binary is executed)

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


## INSTALL
```
pip3 install -r requirements.txt
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64 -O /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache
xattr -d com.apple.quarantine /usr/local/bin/trustcache
brew install keith/formulae/dyld-shared-cache-extractor
brew install blacktop/tap/ipsw
```

## LIMITATIONS
* Codesigning module(codesign wrapper) works only on macOS.
* `--dylib_hijacking` needs [ipsw](https://github.com/blacktop/ipsw) to be installed.
* `--dylibtree` needs the [dyld-shared-cache-extractor](https://github.com/keith/dyld-shared-cache-extractor) to be installed.

## WHY UROBOROS? 
I will write the code for each article as a class SnakeX, where X will be the article number, to make it easier for the audience to follow. 
Each Snake class will be a child of the previous one and infinitely "eat itself" (inherit methods of the previous class), like Uroboros.

## ADDITIONAL LINKS
* [Apple Open Source](https://opensource.apple.com/releases/)
* [XNU](https://github.com/apple-oss-distributions/xnu)
* [dyld](https://github.com/apple-oss-distributions/dyld)

## TODO - IDEAS / IMPROVES
* DER Entitlements converter method - currently, only the `convert_xml_entitlements_to_dict()` method exists. I need to create a Python parser for DER-encoded entitlements.
* SuperBlob parser - to find other blobs in Code Signature.
* Entitlements Blob parser - to check if XML and DER blobs exist.
* Every method in the Snake class that use Entitlements should parse first XML > DER (currently, only XML parser exists)
* After making a SuperBlob parser and CodeDirectory blob parser, modify hasHardenedRuntime to check Runtime flag by using bitmask, instead of string.
* Build Dyld Shared Cache parser and extractor to make SnakeIV independant of dyld-shared-cache-extractor.
* Create `RottenApple.app` in another repository and use it for testing.
* Add Dyld Closure chapter to Snake&Apple V - Dyld
* Move `kext_prelinkinfo`, `dumpPrelink_info` and `dumpPrelink_text` to Snake & Apple chapter about Kernel Extensions when ready.
* Add kernelcache parser.
* Add `LC_FILESET_ENTRY` method to `dumpKernelExtension`.
* Consider moving methods like `removeNullBytesAlignment`, `calcTwoComplement64` etc. to `Utils` class.
* Move `--mig` option to Snake & Apple chapter about Mach Kernel when ready.
* Make Thread manager class and improve the Threading.thread with tracing methods and `kill()`.
