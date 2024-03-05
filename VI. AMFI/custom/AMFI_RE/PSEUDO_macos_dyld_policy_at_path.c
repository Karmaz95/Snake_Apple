// Set amfiFlags->allowEnvVarsPrint (AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS)
// RPL == Relative Path Loading
// HR == Hardening Runtime
// LV == Library Validation
// RP == Restricted Process
// RPP == Restricted Platform Process

macos_dyld_policy_at_path(proc *process, amfi_dyld_policy_state_t *policy_state) {
    uint flags = policy_state->flags;

    // Check if process is not restricted (CS_RUNTIME == 0x10000 and CS_RESTRICT == 0x800):
    if ((flags & 0x10800) == 0) {
        
        // Check if the process is not forcibly restricted
        int is_restricted = procIsDyldsRestricted(policy_state);
        if (is_restricted == 0) {

            // Check if the process does not use Library Validation (CS_FORCED_LV == 0x10):
            if ((flags & 0x10) == 0) {
                log("RPL: 0, HR: 0, RP: 0, LV: 0");
            }
        } else {
            // 0x40 == CS_EXECSEG_JIT used ?? (not sure aobut it)
            if ((flags & 0x40) != 0) {

                // (macOS Only) Page invalidation allowed by task port policy (CS_INVALID_ALLOWED == 0x20) not used
                if ((flags & 0x20) == 0) { 
                    
                    // Check if process does not use Library Validation
                    if ((flags & 0x10) == 0) {
                        log("RPL: 0, PPR: 1, LV: 0");
                    }
                } else {
                    log("RPL: 0, PPR: 1, LV: 0");
                }
            }
        }
        allowAtPaths == 0;
    }
    allowAtPaths == 1;
}
