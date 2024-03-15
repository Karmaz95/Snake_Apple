// Initialization function for Apple's Mobile File Integrity (AMFI) system
initializeAppleMobileFileIntegrity() {

    // Allocating and locking mutex for thread safety
    lock = IOLockAlloc();
    lck_mtx_lock(lock);

    // Checking if driver lock is not already set
    if (OSCompareAndSwapPtr(0, lock, &driverLock))
        // Initializing AMFI lock group
        AMFILockGroup = lck_grp_alloc_init("AMFI", 0);

        // Initializing library constraints
        initLibraryConstraints();

        // Registering system control variable
        sysctl_register_oid(&sysctl__hw_features_allows_security_research);

        // Selecting personalized chip(pointer to img4_chip_t)
        chip = img4_chip_select_personalized_ap();

        // Instantiating chip and checking for errors
        chip_error = img4_chip_instantiate(chip);
        if (chip_error)
            panic("AMFI: No chip from IMG4? errno" + chip_error);

        // Checking chip properties to enable security research (Apple Security Research Device Program - https://security.apple.com/research-device/?)
        if (allow_security_reserach(chip))
            allows_security_research = 1;

        // Checking for boot-arg, e.g.:
        // sudo nvram boot-args="amfi_get_out_of_my_way=1"
        if (PE_parse_boot_argn("amfi_allow_research"))
            IOLog("AMFI: Allowing research due to amfi_allow_research boot-arg");
            allows_security_research = 1;

        // Without this boor-arg, the entitlements get-task-allow and task_for_pid-allow are required to use task_for_pid if binary is signed
        if (PE_parse_boot_argn("amfi_unrestrict_task_for_pid"))
            IOLog("unrestricted task_for_pid enabled by boot-arg");
            unrestricted_debugging = 1;
            boot_device = 1;

        if (PE_parse_boot_argn("amfi_dev_mode_policy"))
            IOLog("developer mode internal policy disabled by boot-arg");
            dev_mode = 1

        if (PE_parse_boot_argn("amfi_allow_any_signature" | "amfi_get_out_of_my_way"))
            IOLog("signature enforcement disabled by boot-arg");
            IOLog("library validation will not mark external binaries as platform"); // NOT SURE

        if (PE_parse_boot_argn("amfi_unrestricted_local_signing"))
            IOLog("unrestricted AMFI local signing enabled by boot-arg");

        if (PE_parse_boot_argn("amfi_ready_to_roll"))
            IOLog("practice a key roll");
            readyToRoll = true;
        
        // Disabling code signing enforcement based on the boot-arg
        if (PE_parse_boot_argn("cs_enforcement_disable"))
            IOLog("cs_enforcement disabled by boot-arg")
        
        // Finalizing initialization
        InitializeDenylist();
        _initializeCoreEntitlementsSupport(1); // Initialize support for entitlements and AMFI trust cache interface
        // Initialize UDID enforcement the exemption profile (define components allowed to execute despite AMFI
        precookExemptionProfile(); 
        jitHashCacheLock = IOLockAlloc()
        dyldSimCacheLock = IOLockAlloc()
        supplementalSigningInit(); // Another lock

        // Access device tree to get model name
        model_name = IORegistryEntry::fromPath("/")
        model_name = OSMetaClassBase::safeMetaCast(OSData::gMetaClass)
        IOLog("AMFI: queried model name from device tree:" + model_name);

        // Check if the model is iPhone
        // If true disable Swift Playgrounds JIT services && some CS features
        if (model_name == 'iPhone')
            IOLog("AMFI: disabling Swift Playgrounds JIT services on iPhone devices");
            _swiftPlaygroundsJIT == 0
            disable_code_signing_feature(0x10000000);
            disable_code_signing_feature(0x20000000);

        // For not iPhones - initialize function pointers to AMFI handlers for various security checks
        if (_swiftPlaygroundsJIT)
            pointers_list = {
                _cred_check_label_update_execve
                _cred_label_associate
                _cred_label_destroy
                _cred_label_init
                _cred_label_update_execve
                _proc_check_inherit_ipc_ports
                _vnode_check_signature          // Check Code Signature handler
                _file_check_library_validation  // Check validation of a library file
                _policy_initbsd                 // Final call from BSD for finalizing initialization of MACF ?
                _policy_syscall                 // MACF policy syscall handler
                _task_id_token_get_task
                _cred_label_associate_kernel
                _proc_check_launch_constraints  // Check launch constraints for a process
                amfi_exc_action_check_exception_send
                amfi_exc_action_label_associate
                amfi_exc_action_label_populate
                amfi_exc_action_label_destroy
                amfi_exc_action_label_init
                amfi_exc_action_label_update
                macos_task_get_movable_control_port
                hsp_proc_check_map_anon
                macos_task_policy
                macos_task_control_policy
                macos_proc_check_run_cs_invalid
                hook_vnode_check_setextattr
                hook_vnode_check_getextattr
                _file_check_mmap
                _vnode_notify_open
                core_dump_policy
            }

            // Register MAC policy
            mac_policy_register("AMFI", amfiPolicyHandle, 0)

            // Set security policies and constraints for AMFI
            configurationSettingsInit(); 

            // Initialize a lock for exception list
            hardeningInit()

        // Unlocking driver lock
        lck_mtx_unlock(driverLock);

    // Unlocking mutex and freeing memory
    lck_mtx_unlock(lock);
    IOLockFree(lock);
    lck_mtx_lock(driverLock);
}
