intptr_t __fastcall apply_exec_quarantine(
        __int64 context,          // a1: context or structure with additional info
        struct vnode *file_vnode, // a2: vnode representing the file being executed
        __int64 reserved1,        // a3: reserved for future use
        __int64 reserved2,        // a4: reserved for future use
        __int64 reserved3,        // a5: reserved for future use
        __int64 reserved4,        // a6: reserved for future use
        __int64 reserved5,        // a7: reserved for future use
        __int64 reserved6)        // a8: reserved for future use
{
    int quarantine_flags;             // w0: quarantine flags
    int temp_flags;                   // w8: temporary storage for flags
    intptr_t result;                  // x0: return value
    struct mount *mount_info;         // x0: mount information
    char mount_flags;                 // w8: flags from mount info
    struct label *sec_label;          // x16: security label
    intptr_t label_result;            // x20: temporary storage for label result
    int label_flags;                  // w21: temporary storage for label flags
    const char *file_path;            // x0: file path
    const char *log_msg;              // x19: log message
    const char *quarantine_reason;    // x9: reason for quarantine
    __int64 reserved_context1;        // [xsp+0h] [xbp-160h]
    __int64 reserved_context2;        // [xsp+8h] [xbp-158h]
    unsigned int quarantine_flag_set; // [xsp+2Ch] [xbp-134h] BYREF
    __int128 additional_info[16];     // [xsp+30h] [xbp-130h] BYREF

    // Initialize additional info buffer and quarantine flag set
    memset(additional_info, 0, sizeof(additional_info));
    quarantine_flag_set = 0;

    // Retrieve quarantine flags for the vnode
    quarantine_flags, error_code = quarantine_get_flags(file_vnode, 0LL, (__int64)&quarantine_flag_set, (__int64)additional_info, reserved3, reserved4, reserved5, reserved6, reserved_context1, reserved_context2);

    // If any error during parsing in quarantine_get_flags, enforce quarantine.
    if (error_code) {
        temp_error_code= error_code;
        result = 0LL;
        if (temp_error_code == 0x5D)
            return result;
        return 1LL;
    }

    // Check quarantine flag set for specific conditions
    if ((quarantine_flag_set & 6) == 0)
        return 0LL;

    if ((quarantine_flag_set & 4) != 0) {
    LABEL_15:
        file_path = (const char *)getpath(file_vnode);
        log_msg = file_path;
        quarantine_reason = "created without user consent";
        if ((quarantine_flag_set & 4) == 0)
            quarantine_reason = "not approved by Gatekeeper";

        // Log the quarantine enforcement
        _os_log_internal(
            &dword_FFFFFE000792BD40,
            (os_log_t)&_os_log_default,
            OS_LOG_TYPE_ERROR,
            "exec of %s denied since it was quarantined by %s and %s, qtn-flags was 0x%08x",
            file_path,
            (const char *)additional_info,
            quarantine_reason,
            quarantine_flag_set);
        
        // Free the file path memory and return 1
        kfree_data_addr_external(log_msg);
        return 1LL;
    }

    result = 0LL;

    // Check if user-approved execution is required
    if (require_user_approved_exec) {
        if ((quarantine_flag_set & 0x40) == 0) {
            mount_info = vnode_mount(file_vnode);
            mount_flags = vfs_flags(mount_info);
            result = 0LL;

            if (context) {
                if ((mount_flags & 1) == 0) {
                    sec_label = *(struct label **)(context + 120);
                    if (sec_label) {
                        result = mac_label_get(sec_label, label_slot);
                        if (!result)
                            return result;
                        label_result = result;
                        os_ref_retain_internal((os_ref_atomic_t *)(result + 16), 0LL);
                        if (*(_QWORD *)label_result
                            && (os_ref_retain_internal((os_ref_atomic_t *)(*(_QWORD *)label_result + 60LL), 0LL), *(_QWORD *)label_result)) {
                            label_flags = *(_DWORD *)(*(_QWORD *)label_result + 56LL);
                            qtnstate_rele();
                            cred_label_rele(label_result);
                            if ((label_flags & 2) != 0)
                                goto LABEL_15;
                        } else {
                            cred_label_rele(label_result);
                        }
                    }
                    return 0LL;
                }
            }
        }
    }

    return result;
}