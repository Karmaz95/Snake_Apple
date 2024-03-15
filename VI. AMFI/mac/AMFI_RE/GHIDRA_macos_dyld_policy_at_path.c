
/* macos_dyld_policy_at_path(proc*, amfi_dyld_policy_state_t*) */

undefined8 macos_dyld_policy_at_path(proc *process,amfi_dyld_policy_state_t *policy_state)

{
  int is_restricted_fp;
  undefined8 allowAtPaths;
  char *log_message;
  uint flags;
  
  if ((*(uint *)policy_state & 0x10800) == 0) {
    is_restricted_fp = procIsDyldsRestricted(policy_state);
    if (is_restricted_fp == 0) {
check_CS_FORCED_LV:
      is_restricted_fp = procIsDyldsRestricted(policy_state);
      if ((is_restricted_fp == 0) || (((byte)*policy_state >> 4 & 1) != 0))
      goto set_allowAtPaths_to_1;
      log_message = "process is not hardened, restricted and does not use Library Validation";
    }
    else {
      flags = *(uint *)policy_state;
      if ((flags >> 6 & 1) == 0) goto check_CS_FORCED_LV;
      if ((flags >> 5 & 1) == 0) {
        if ((flags >> 4 & 1) != 0) goto set_allowAtPaths_to_1;
        log_message = "platform process is restricted and does not use Library Validation";
      }
      else {
        log_message = "platform process is restricted and is not signed with Library Validation";
      }
    }
    logDyldPolicyRejection(process,"relative path loading disallowed",log_message);
    allowAtPaths = 0;
  }
  else {
set_allowAtPaths_to_1:
    allowAtPaths = 1;
  }
  return allowAtPaths;
}

