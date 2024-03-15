// Function to collect macOS dynamic linker (dyld) policy state
macos_dyld_policy_collect_state(calling_process, param_2, amfi_dyld_policy_state) {

    // Get process name & PID
    process_name = get_process_name(calling_process);
    process_ID = get_process_ID(calling_process);

    // Check if system integrity protection is enabled
    SIP_enabled = check_system_integrity_protection();

    // Check if CS_RESTRICT bit is ON
    has_CS_RESTRICT = check_cs_restrict_flag(calling_process);
    
    // Check if process has restrict segment 
    has_RESTRICT_segment = check_restricted_segment(calling_process);

    // Check if setuid/setgid behavior is enabled
    is_setUGid = check_setuid_setgid(calling_process);

    // Check if library validation is enabled
    has_LV = !has_entitlement(calling_process, "com.apple.security.cs.disable-library-validation");

    // Check if forced library validation is enabled (required by Hardened System Policy)
    has_CS_FORCED_LV = check_forced_library_validation(calling_process);

    // Check if binary is inside trust cache (CS_PLATFORM_BINARY == 0x4000000 | CS_DYLD_PLATFORM == 0x2000000) 
    platform = is_platform_binary();

    // Check if Hardened Runtime is enabled
    has_HR = check_hardened_runtime(calling_process);

    // Check entitlement for Allowing Relative Library loads
    has_ARL = has_entitlement(calling_process, "com.apple.security.cs.allow-relative-library-loads");

    // Check entitlement for allowing Dyld Environment Variables
    has_AEV = has_entitlement(calling_process, "com.apple.security.cs.allow-dyld-environment-variables");

    // Check entitlement for Getting Task Allow
    has_GTA = has_entitlement(calling_process, "com.apple.security.get-task-allow");

    // Check if the binary is built for simulator
    is_SIM = is_built_for_sim(calling_process);

    // Check if it is AppleInternal app
    is_AI = check_internal_test_app(calling_process);

    // Check if the application is masquerading mac App Store?
    is_mac_app_store = has_entitlement(calling_process,"com.apple.security.amfi.test.mac-app-store-test") && is_AI;

    // Not sure - checking Force Policy? (macOSPolicyConfig::forceDefaultDyldEnvVarsPolicy())
    is_fp = is_policy_forced()

    // Check if sandbox entitlement is present
    request_sandbox = has_entitlement(calling_process, "com.apple.security.app-sandbox");

    // Check if process is an iOS app:
    is_ios_app = is_iOS_app(calling_process);

    // Check if any of the below boot-args was used or process has GTA:
    is_AMFI_disabled = has_nvram_boot_arg('PE_i_can_has_debugger',
    'amfi_unrestrict_task_for_pid',
    'amfi_allow_any_signature',
    'amfi_get_out_of_my_way', 
    'cs_enforcement_disable', 
    'cs_debug') 
    unrestrict_task_for_pid = is_AMFI_disabled || has_GTA

    // Set the collected state according to the above functions.
    amfi_dyld_policy_state(process_name, process_ID, SIP_enabled, has_CS_RESTRICT, has_RESTRICT_segment, is_setUGid, \
    has_LV, has_CS_FORCED_LV, platform, has_HR, has_ARL, has_AEV, has_GTA, is_SIM, is_AI, is_mac_app_store, is_fp, \
    request_sandbox, is_ios_app, unrestrict_task_for_pid);

    // Log collected data
    log_dyld_policy_data(calling_process, param_2, amfi_dyld_policy_state);
}


