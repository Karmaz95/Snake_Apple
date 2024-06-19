intptr_t __fastcall apply_exec_quarantine(__int64 a1, struct vnode *a2)
{
  int flags; // w0
  int v5; // w8
  intptr_t result; // x0
  struct mount *v7; // x0
  char v8; // w8
  struct label *v9; // x16
  intptr_t v10; // x20
  int v11; // w21
  const char *v12; // x0
  const char *v13; // x19
  const char *v14; // x9
  unsigned int v15; // [xsp+2Ch] [xbp-134h] BYREF
  __int128 v16[16]; // [xsp+30h] [xbp-130h] BYREF

  memset(v16, 0, sizeof(v16));
  v15 = 0;
  flags = quarantine_get_flags(a2, 0LL, &v15, v16);
  if ( flags )
  {
    v5 = flags;
    result = 0LL;
    if ( v5 == 93 )
      return result;
    return 1LL;
  }
  if ( (v15 & 6) == 0 )
    return 0LL;
  if ( (v15 & 4) != 0 )
  {
LABEL_15:
    v12 = (const char *)getpath(a2);
    v13 = v12;
    v14 = "created without user consent";
    if ( (v15 & 4) == 0 )
      v14 = "not approved by Gatekeeper";
    _os_log_internal(
      &dword_FFFFFE000792BD40,
      (os_log_t)&_os_log_default,
      OS_LOG_TYPE_ERROR,
      "exec of %s denied since it was quarantined by %s and %s, qtn-flags was 0x%08x",
      v12,
      (const char *)v16,
      v14,
      v15);
    kfree_data_addr_external(v13);
    return 1LL;
  }
  result = 0LL;
  if ( require_user_approved_exec )
  {
    if ( (v15 & 0x40) == 0 )
    {
      v7 = vnode_mount(a2);
      v8 = vfs_flags(v7);
      result = 0LL;
      if ( a1 )
      {
        if ( (v8 & 1) == 0 )
        {
          v9 = *(struct label **)(a1 + 120);
          if ( v9 )
          {
            result = mac_label_get(v9, label_slot);
            if ( !result )
              return result;
            v10 = result;
            os_ref_retain_internal((os_ref_atomic_t *)(result + 16), 0LL);
            if ( *(_QWORD *)v10
              && (os_ref_retain_internal((os_ref_atomic_t *)(*(_QWORD *)v10 + 60LL), 0LL), *(_QWORD *)v10) )
            {
              v11 = *(_DWORD *)(*(_QWORD *)v10 + 56LL);
              qtnstate_rele();
              cred_label_rele(v10);
              if ( (v11 & 2) != 0 )
                goto LABEL_15;
            }
            else
            {
              cred_label_rele(v10);
            }
          }
          return 0LL;
        }
      }
    }
  }
  return result;
}