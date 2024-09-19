### [App Bundle Extension](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4?sk=v2%2F3ff105ad-f4f0-464d-b4d5-46b86c66fe14)
* Application Bundle
* App Bundle Structure
* Info.plist
  * CFBundleExecutable
  * plutil
  * __info_plist
* Gatekeeper Bypass (not)using Info.plist
* Resources
* Dirty NIB
* Frameworks
  * CFBundlePackageType
  * FMWK
* PlugIns
  * pluginkit
* _CodeSignature
  * CodeDirectory
  * CodeRequirements
  * CodeResources
  * CodeSignature
  * CodeEntitlements
* Inconsistency in codesign
* Re-signing apps
* Re-signing system applications
* make_bundle.sh
___
#### [Cracking macOS apps](https://karol-mazurek.medium.com/cracking-macos-apps-39575dd672e0?sk=v2%2F727dce55-53ee-45f6-b051-2979e62f2ba1)
Binary patching methods |Application patching methods |Resigning the app without losing entitlements |Resigning the app for debugging |Electron Apps | /Contents/Resources/app.asar
___
#### [Cracking Electron Integrity](https://karol-mazurek.medium.com/cracking-electron-integrity-0a10e0d5f239?sk=v2%2F7726b99c-c6c9-4d70-8c37-da9f2f0874e8)
getRawHeader | node:crypto | generateAsarIntegrity | electron_patcher | ElectronAsarIntegrity
___

### [I. Mach-O](https://karol-mazurek95.medium.com/snake-apple-i-mach-o-a8eda4b87263?sk=v2%2Ffc1cbfa4-e2d4-4387-9a82-b27191978b5b)
* Universal Binary (Fat Binary)
* Memory Pages
  * mprotect()
  * mmap()
* Mach-O structure
  * mach_header_64
    * Magic
    * cputype
    * cpusubtype
    * filetype
    * flags
  * load_command
  * segment_command_64
      * section_64
      * __PAGEZERO
      * __TEXT
      * __DATA_CONST
      * __DATA
      * __RESTRICT
      * __LINKEDIT
* Chained Fixups
  * Binding
  * Rebasing
  * LC_DYLD_CHAINED_FIXUPS
  * dyld_chained_fixups_header
  * LC_DYLD_CHAINED_FIXUPS
  * dyld_chained_starts_in_image 
  * dyld_chained_starts_in_segment
  * dyld_info
* LC_DYLD_EXPORTS_TRIE
* LC_SYMTAB
  * symtab_command
  * nlist_64
  * ntype
  * n_desc
  * REFERENCE_TYPE
    * REFERENCED_DYNAMICALLY
    * N_NO_DEAD_STRIP
    * N_DESC_DISCARDED
    * N_WEAK_REF 
    * N_WEAK_DEF
    * N_REF_TO_WEAK
  * LIBRARY_ORDINAL
* LC_DYSYMTAB
* DYNAMIC LINKER & ENVIRONMENT VARIABLES
  * LC_LOAD_DYLINKER
  * dylinker_command
  * LC_ID_DYLINKER
  * LC_DYLD_ENVIRONMENT
* UUID
  * uuid_command
  * uuidgen
* BUILD VERSION
  * LC_BUILD_VERSION
  * build_version_command
  * build_tool_version
  * build_version_command
* Source Version
  * LC_SOURCE_VERSION
  * source_version_command
* ENTRY POINT
  * LC_MAIN
  * entry_point_command
* Dynamic Libraries
  * dylib_command
* Function Addresses
  * LC_FUNCTION_STARTS
  * linkedit_data_command
*  DATA_IN_CODE
  * data_in_code_entry
* ENDIANESS
___

### [II. Code Signing](https://karol-mazurek95.medium.com/snake-apple-ii-code-signing-f0a9967b7f02?sk=v2%2Fbbc87007-89ca-4135-91d6-668b5d2fe9ae)
* CS_CodeDirectory
* CDHash 
* signature
* CMS
* Certificate Chain of Trust
* Ad hoc signing
* TrustCacheParser
* Notarization
* Code Signature
* LC_CODE_SIGNATURE
  * Super Blob
  * Code Directory
  * Requirement
  * Entitlements (XML and DER)
  * CMS Signature
* Info.plist
* cs_flags
* CodeResources
* ASN.1 and DER
* openssl
* RFC 5652–5.4. Message Digest Calculation Process.
* signedAttrs
___

### [III. Checksec](https://karol-mazurek95.medium.com/snake-apple-iii-checksec-ed64a4b766c1?sk=v2%2Fb4b8d637-e906-4b6b-8088-ca1f893cd787)
* PIE — Position-Independent Executable
  * -fno-pie
  * ModifyMachOFlags
  * MH_PIE
* ARC — Automatic Reference Counting
  * -fobjc-arc
  * _objc_release
* SS — Stripped Symbols
  * __mh_execute_header
* SC — Stack Canary / Stack Cookie
  * ___stack_chk_fail
  * ___stack_chk_guard
* NX stack
  * -allow_stack_execute
  * MH_ALLOW_STACK_EXECUTION
* NX heap
  * NO_HEAP_EXECUTION
* XN — Execute Never
  * mmap.PROT_READ
  * mmap.PROT_WRITE
  * mmap.PROT_EXEC
  * com.apple.security.cs.allow-jit
* Code Signature
* Notarization
  * notarytool
  * notary service’s REST API.
  * spctl
* Encryption
  * cryptid
  * ipatool
  * LC_ENCRYPTION_INFO
* Restrict
  * __RESTRICT
  * -sectcreate
* Hardened Runtime
* App Sandbox
  * com.apple.security.app-sandbox 
* Fortify
  * -D_FORTIFY_SOURCE
* RPath
___

### [IV. Dylibs](https://karol-mazurek.medium.com/snake-apple-iv-dylibs-2c955439b94e?sk=v2%2Fdef72b7a-121a-47a1-af89-7bf53aed1ea2)
* Libraries — Static vs Dynamic
* Frameworks
* Dylib Hijacking
  * com.apple.security.cs.disable-library-validation
  * com.apple.private.security.clear-library-validation
* DYLD_PRINT_SEARCHING
* libSystem.B.dylib
* Dyld Shared Cache
  * /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/
  * /System/Volumes/Preboot/Cryptexes/OS/System/DriverKit/System/Library/dyld/
  * ipsw
  * dyld-shared-cache-extractor
  * dyld_cache_format.h.
* Loading Process
  * dylibtree
  * MachOFile.cpp
  * Loader.cpp
  * Header.cpp
* MachODylibLoadCommandsFinder 
* Load Commands
  * LC_LOAD_DYLIB
  * LC_LOAD_WEAK_DYLIB
  * LC_REEXPORT_DYLIB
  * LC_LOAD_UPWARD_DYLIB
  * LC_ID_DYLIB
  * dylib_command 
  * loader_path
  * executable_path
* install_name_tool
* current_version
* compatibility_version
* enforceCompatVersion
* CVE-2023–26818
* dlopen
* DYLD_PRINT_APIS
* dtruss
* fs_usage
___

### [V. Dyld](https://karol-mazurek.medium.com/snake-apple-v-dyld-8b36b674cc44?sk=v2%2F4acb16f8-fa88-41f0-8d7c-1362f4060010)
* /usr/lib/dyld
* com.apple.darwin.ignition
* dylinker_command
* LC_DYLD_ENVIRONMENT
* dyldStartup.s
* __dyld_start
* dyldMain.cpp
* dyld_usage
* dyld_info
* vmmap
* lldb
* symbols
* Memory Layouts
* DYLD_IN_CACHE
* Interposing
* DYLD_PRINT_INTERPOSING
* DYLD_INSERT_LIBRARIES
___
#### [DYLD — Do You Like Death? (I)](https://karol-mazurek.medium.com/dyld-do-you-like-death-i-8199faad040e?sk=v2%2F359b081f-d944-409b-9e7c-95f7c171b969)
Startup | kernArgs | rebaseSelf | initializeLibc | task_self_trap | stack_guard | findArgv | findEnvp | findApple
___
#### [DYLD — Do You Like Death? (II)](https://karol-mazurek.medium.com/dyld-do-you-like-death-ii-b74360b8af47?sk=v2%2Ff0cff71c-5345-4228-a639-653325fc979d)
handleDyldInCache| isBuiltForSimulator | isTranslated | crossarch_trap | Calling Convention on ARM64v8 | __unused attribute | Dyld Shared Region | thisDyldUuid | hasExistingDyldCache | shared_region_check_np | Carry flag | dynamic data header | dyldInCacheMH
___
#### [DYLD — Do You Like Death? (III)](https://karol-mazurek.medium.com/dyld-do-you-like-death-iii-af77701a3034?sk=v2%2F06c92503-2db9-40e2-b139-c9ae0a35e7b3)
handleDyldInCache | DYLD_IN_CACHE | restartWithDyldInCache | dyld_all_image_infos | calculating offset for debugging Dyld in Cache
___
#### [DYLD — Do You Like Death? (IV)](https://karol-mazurek.medium.com/dyld-do-you-like-death-iv-ede6b157752c?sk=v2%2F87ebe38d-004c-41a6-bc1f-43898494a512)
RuntimeLocks | MemoryManager | dyld_hw_tpro | Lambda Capture | withWritableMemory | PAC | arm64e_preview_abi | __ptrauth_dyld_tpro0 | WriteProtectionState | previousState | os_compiler_barrier
___
#### [DYLD — Do You Like Death? (V)](https://karol-mazurek.medium.com/dyld-do-you-like-death-v-c40a267573cb?sk=v2%2F4c9f16b2-59bd-406a-945d-10a1fba1001b)
Linker Standard Library | EphemeralAllocator | Dyld Private Memory | PersistentAllocator | vm_allocate | vm_protect | _kernelrpc_mach_vm_allocate_trap | _kernelrpc_mach_vm_protect_trap 
___
#### [DYLD — Do You Like Death? (VI)](https://karol-mazurek.medium.com/dyld-do-you-like-death-vi-1013a69118ff?sk=v2%2F37b3a61f-8483-4b38-977d-7f860944862b)
ProcessConfig | Process::Process | Process::Security | csr_check | CSR_ALLOW_APPLE_INTERNAL | csrctl | syscall_csr_check | AMFI | internalInstall | isRestricted | isFairPlayEncrypted | amfiFlags | amfi_check_dyld_policy_self | ___sandbox_ms | ___mac_syscall | mpo_policy_syscall_t | MAC policy | com.apple.driver.AppleMobileFileIntegrity | _policy_syscall | _check_dyld_policy_internal | macos_Dyld_policy_collect_state | logDyldPolicyData | DYLD_AMFI_FAKE | getAMFI | pruneEnvVars | com.apple.security.cs.allow-dyld-environment-variables
___
#### [DYLD — Do You Like Death? (VII)](https://karol-mazurek.medium.com/dyld-do-you-like-death-vii-62c202f98610?sk=v2%2Fab26bfcf-ba56-493d-9af3-2d8790ca6208)
ProcessConfig | Process::Logging | Process::dyldCache | DYLD_PRINT_TO_STDERR | DYLD_PRINT_INTERPOSING | allowEnvVarsSharedCache | allowEnvVarsPrint | openLogFile | DYLD_PRINT_TO_FILE |  BSD open syscall | DYLD_SHARED_REGION | Shared Library Cache | DYLD_SHARED_CACHE_DIR | dyldCache | CacheFinder | Ignite | ignitionPayload | ignition | open_console | log_init | sysctlbyname | __sysctl | dyld_parse_boot_arg_int | dyld_parse_boot_arg_cstr | libignition | boot_init | stage_fire | getDyldCache | loadDyldCache | mapSplitCachePrivate | reuseExistingCache | mapSplitCacheSystemWide | jettison
___
#### [DYLD — Do You Like Death? (VIII)](https://karol-mazurek.medium.com/dyld-do-you-like-death-viii-327d7e7f3c0f?sk=v2%2F6c6b611d-fee4-4d9d-8a36-d59a05116e23)
ProcessConfig | Process::PathOverrides | Overrides and path fallbacks for Dylibs | security.allowEnvVarsPath | crashMsg | addEnvVar | DYLD_LIBRARY_PATH | DYLD_FRAMEWORK_PATH | DYLD_FALLBACK_FRAMEWORK_PATH | DYLD_FALLBACK_LIBRARY_PATH | DYLD_VERSIONED_FRAMEWORK_PATH | DYLD_VERSIONED_LIBRARY_PATH | DYLD_INSERT_LIBRARIES | DYLD_IMAGE_SUFFIX | DYLD_ROOT_PATH | _dylibPathOverridesExeLC | _dylibPathOverridesEnv | isLC_DYLD_ENV | CRSetCrashLogMessage2 | LC_DYLD_ENVIRONMENT | allowEmbeddedVars | _insertedDylibs | cryptexOSPath | VersionedPaths | processVersionedPaths | checkVersionedPath | LC_ID_DYLIB | sys.getDylibInfo | addPathOverride | dontUsePrebuiltForApp | adjustDevelopmentMode
___
#### [DYLD — Do You Like Death? (IX)](https://karol-mazurek.medium.com/dyld-do-you-like-death-ix-5052c865100e?sk=v2%2Fe078d739-ab30-4f2d-8a12-eefc63dd73b4)
RuntimeState | ProcessConfig | finalizeListTLV | FileManager | _fsUUIDMap | OrderedMap | UUIDs | PermanentRanges | state APIs
___
#### [DYLD — Do You Like Death? (X)](https://karol-mazurek.medium.com/dyld-do-you-like-death-x-76408570c357?sk=v2%2F8b69c2f1-ce13-4d05-bba1-e0164c3de381)
ExternallyViewableState | externallyViewable.init | dyld_all_image_info | exec_prefault_data | task_info | com.apple.security.get-task-allow | get_dyld_info | lsl:Vector | ProcessSnapshot | compact info | makeUnique | release | setDyldState | setInitialExternallyVisibleState | setShareCacheInfo | setDyld | inDyldCache | DYLD_IN_CACHE | recordFromInfo | FileRecord | Image | addImage | _snapshot | addImageInfo | setInitialImageCount | commit | compactInfoData | RemoteNotificationResponder
___
#### [DYLD — Do You Like Death? (XI)](https://karol-mazurek.medium.com/dyld-do-you-like-death-xi-cef76bc8dc14?sk=v2%2F0b88b392-ae94-43d0-9120-109306051e00)
prepare | APIs | isSimulatorPlatform | state.initializeClosureMode() | PrebuiltLoaders | JustInTimeLoader | PrebuilLoaderSet | dyld3 | dyld4 | Closures | initializeClosureMode | Loaders | validHeader | hasValidMagic | kmagic | dontUsePrebuiltForApp | findLaunchLoaderSet | cachePBLS | hasLaunchLoaderSetWithCDHash | findLaunchLoaderSetWithCDHash | findLaunchLoaderSet | allowOsProgramsToSaveUpdatedClosures | reserve | bit_ceil  | allowNonOsProgramsToSaveUpdatedClosures | DYLD_USE_CLOSURES | reserveExact | getOnDiskBinarySliceOffset | STACK_ALLOC_OVERFLOW_SAFE_ARRAY | topLevelLoaders | loadDependents | notifyDebuggerLoad | notifyDtrace | DOF | addPermamentRanges | STACK_ALLOC_ARRAY | weakDefMap | buildInterposingTables | handleStrongWeakDefOverrides | visibility | applyFixups | applyCachePatches | doSingletonPatching | applyInterposingToDyldCache | Libdyld.dylib | libdyld4Section | allImageInfos | storeProcessInfoPointer | __chkstk_darwin | partitionDelayLoads | DYLD_JUST_BUILD_CLOSURE | prewarming | notifyMonitorNeeded | LC_MAIN | LC_THREAD | getEntry | appMain | restorePreviousState | TPRO | libSystemHelpers | __exit
___

### [VI. AMFI](https://karol-mazurek.medium.com/snake-apple-vi-amfi-31c48fb92d33?sk=v2%2F8116bf86-e0a7-42be-ada9-5348447c01fd)
* Kernel Extension
  * AppleMobileFileIntegrity.kext
  * /System/Library/Extensions
  * Kext binary extraction
  * Kernelcache.
  * kextstat
  * Dependent kexts
  * KEXT_BUNDLE
* Mach-O analysis
* Kext Information Property List
* __PRELINK_INFO
* kmod_info
* _PrelinkKmodInfo
* AMFI Startup
* Entrypoint
  * OSBundleRequired
  * IOKitPersonalities
  * ioreg
  * kxld
  * OSKext::start
  * __realmain
  * initializeAppleMobileFileIntegrity
  * mac_policy_init
  * kernel_startup_initialize_upto
  * kernel_bootstrap_thread
  * mac_policy_initmach
  * load_security_extensions_function
  * load_security_extensions_function
  * bootstrapLoadSecurityExtensions
  * bootstrapLoadSecurityExtensions
  * loadSecurityExtensions
  * OSKext::loadKextWithIdentifier
  * register_kmod
  * OSRuntimeInitializeCPP
  * vftable
  * KEXT_NAME::start(IOService*)
* Turning off AMFI
  * amfi_get_out_of_my_way
  * nvram boot-args=""
* MAC policy syscall
  * __mac_syscall
  * mpo_cred_label_init_t
* PROTECTIONS
  * macos_dyld_policy_collect_state
  * DYLD_INSERT_LIBRARIES
  * cs.allow-relative-library-loads
  * policy_syscall
  * SUID GUID
* Signature Validation
  * vnode_check_signature
  * mpo_vnode_check_signature_t
  * cs_validate_page
  * com.apple.private.amfi.can-execute-cdhash
  * com.apple.rootless.storage.cvms
  * jit-codesigning
  * com.apple.security.get-task-allow
  * com.apple.private.oop-jit.loader
  * com.apple.private.amfi.can-execute-cdhash
  * com.apple.dyld_sim
  * com.apple.private.oop-jit.runner
* Launch Constraints
  * _proc_check_launch_constraints
* Amfid
  * /usr/libexec/amfid
  * verify_code_directory
  * _MIG_subsystem_1000
  * routine_descriptor
  * mach_msg
___
#### [Unexpected but expected behavior](https://karol-mazurek.medium.com/unexpected-but-expected-behavior-bf281cc21ee2?sk=v2%2Fda20f402-b7fa-4bb1-a160-83e758cdd513)
CS_RESTRICT (0x800) | pruneEnvVars | DYLD_PRINT_INITIALIZERS |  CS_REQUIRE_LV | com.apple.security.cs.allow-dyld-environment-variables | CS_RUNTIME | SetUID | SetGID
___

### [VII. Antivirus](https://karol-mazurek.medium.com/snake-apple-vii-antivirus-0a57acc10185?sk=v2%2F2c46d7ac-4435-41e6-bbda-2acb4eb78c76)
* GATEKEEPER
  * Application Whitelisting
  * Quarantine attribute
  * com.apple.quarantine
  * De-Quarantining
  * xattr
  * ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV*
  * LSQuarantine.h
* LAUNCH SERVICES
  * Reversing DSC
  * libquarantine.dylib
  * App Translocation
* QUARANTINE KEXT
  * Tracing hooks
  * hook_vnode_check_exec
  * sandbox_enforce
  * Double call mystery of apply_exec_quarantine
  * quarantine_get_flags
  * getxattr
  * Flags default values for quarantined volume
  * Quarantine flags logic
* SYSTEM POLICY
  * System Policy Database
  * System Policy Daemon
  * System Policy Manager (spctl)
* XProtect
  * gk.db
  * XProtect.meta.plist
  * XProtect.yara
  * XProtect.plist
  * Logging
  * CoreSerivcesUIAgent
  * Eicar test
  * Malware creator test
___
#### &#9745; [Apple Gatekeeper Bypass](https://karol-mazurek.medium.com/apple-gatekeeper-bypass-4315bbb33018?sk=v2%2F3c20fa28-1a3d-4bd0-9a25-79646f60c44f)
USB flash drive bypass | Network Shares bypass
___

### [VIII. Sandbox](https://karol-mazurek.medium.com/snake-apple-viii-app-sandbox-5aff081f07d5?sk=v2%2F5b65151b-d1f3-4f18-93da-4ad9aeacadb7)
com.apple.security.app-sandbox | Sandbox Operations | Sandbox Profiles | SBPL | /System/Library/Sandbox/Profiles/application.sb | SandboxProfileData | libsystem_sandbox.dylib | libsystem_sandbox.dylib | AppSandbox.framework | sandboxd | containermanagerd | sandbox_init | .com.apple.containermanagerd.metadata.plist | SandboxProfileDataValidationInfo | com.apple.MobileInstallation.ContentProtectionClass | com.apple.security.sandbox | AppleSystemPolicy.kext | CVE-2021–30853 | AppSandbox Framework | 
___
#### [SBPL Compilator](https://karol-mazurek.medium.com/sbpl-compilator-c05f5304d057?sk=v2%2F4ae3bf90-ff12-4fea-b0fc-0f2ef60d7b93)
.com.apple.containermanagerd.metadata.plist | SandboxProfileData | /System/Library/Sandbox/Profiles/ | sandbox_compile_file | com.apple.security.get-task-allow | sandbox-exec | Sandbox.kext
___
#### [Sandbox Detector](https://karol-mazurek.medium.com/sandbox-detector-4268ab3cd361?sk=v2%2F58fe49fb-1381-4db3-9db9-3f6309e4053a)
libsystem_sandbox.dylib | com.apple.security.app-sandbox | Activity Monitor.app | _sandbox_check | /usr/lib/libSystem.B.dylib | dyld-shared-cache-extractor | arm64e_preview_abi | kernel_task | sandbox_operation_fixup_0 | CTL_KERN | KERN_PROC | KERN_PROC_PID | struct kinfo_proc info | kinfo_getproc | sysctl | mib | sandbox_check_common_0 
___
#### [Sandbox Validator](https://karol-mazurek.medium.com/sandbox-validator-e760e5d88617?sk=v2%2F145ac2ef-ca06-41a0-b310-c96f4ce0037b)
SandBlaster | kernelcache | Decompiling Sandbox Profiles on Sonoma | _operation_is_forbidden | _syscall_check_sandbox_bulk | operation_names_3208 | sandbox_check | opainject | sandbox.h | sbtool | sandbox_filter_type | sandbox_validator
___
#### [App Sandbox startup](https://karol-mazurek.medium.com/app-sandbox-startup-71daf8f259d1?sk=v2%2F9f3b09a6-c7c0-445d-8613-8e25bf3f4e4d)
libsystem_secinit.dylib | _libsecinit_appsandbox | prepare() | com.apple.security.app-sandbox | _libsecinit_initializer | ___libsecinit_initializer_block_invoke | _libsecinit_appsandbox_check | xpc_pipe_create | xpc_pipe_routine | xpc_copy_description | xpc_object_t | SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY | SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY | SECINITD_REGISTRATION_MESSAGE_DYLD_VARIABLES_KEY | SECINITD_REGISTRATION_MESSAGE_VERSION_NUMBER_KEY | SECINITD_MESSAGE_TYPE_KEY | secinitd | SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY | SECINITD_REPLY_MESSAGE_REQUIRES_MIGRATION_KEY | SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY | SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY | SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY | SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_EXTENSION_KEY | SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY | SECINITD_MESSAGE_TYPE_KEY | SECINITD_REPLY_FAILURE_CODE | __sandbox_ms | hook_policy_syscall | sandbox_init
___

### [IX. TCC]()

___
### [X. NU]()

___
#### [Kernel Debugging Setup on MacOS](https://karol-mazurek.medium.com/kernel-debugging-setup-on-macos-07dd8c86cdb6?sk=v2%2F782bf539-a057-4f14-bbe7-f8e1ace26701)
* KDK
* sw_vers
* BuildVersion
* /Library/Developer/KDKs/
* /var/tmp/PanicDumps
* com.apple.kdumpd
* kdp_match_name
* DB_NMI_BTN_ENA
* DB_REBOOT_POST_CORE
* DB_ARP
* DB_NMI
* _panicd_ip
* DB_DBG_POST_CORE
* InstantPanic/build/InstantPanic.kext
