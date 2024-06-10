bool __fastcall hook_vnode_check_setextattr(__int64 a1, __int64 a2, __int64 a3, const char *a4)
{
  _BOOL8 v4; // x20
  __int64 v5; // x16
  __int64 v7; // x0
  __int64 v8; // x19
  os_ref_atomic_t *v9; // x21
  __int64 v10; // x0
  __int64 v11; // x0
  __int64 v12; // x1
  __int64 v13; // x0
  __int64 v14; // x1

  v4 = 0LL;
  if ( a1 && sandbox_enforce )
  {
    v5 = *(_QWORD *)(a1 + 120);
    if ( v5 && (v7 = mac_label_get(v5, (unsigned int)label_slot)) != 0 )
    {
      v8 = v7;
      os_ref_retain_external((os_ref_atomic_t *)(v7 + 16), 0LL);
      if ( *(_QWORD *)v8
        && (os_ref_retain_external((os_ref_atomic_t *)(*(_QWORD *)v8 + 60LL), 0LL), (v9 = *(os_ref_atomic_t **)v8) != 0LL) )
      {
        v4 = (v9[14] & 2) != 0 && strcmp(a4, "com.apple.quarantine") == 0;
        if ( !os_ref_release_barrier_external(v9 + 15, 0LL) )
        {
          if ( *((_QWORD *)v9 + 6) )
            matchFree();
          v10 = *(_QWORD *)v9;
          *(_QWORD *)v9 = 0LL;
          kfree_data_addr(v10);
          v11 = *((_QWORD *)v9 + 2);
          v12 = *((_QWORD *)v9 + 3);
          *((_QWORD *)v9 + 2) = 0LL;
          kfree_data(v11, v12);
          v13 = *((_QWORD *)v9 + 4);
          v14 = *((_QWORD *)v9 + 5);
          *((_QWORD *)v9 + 4) = 0LL;
          kfree_data(v13, v14);
          kfree_type_impl(&qtnstate_destroy_kalloc_type_view_281, v9);
        }
      }
      else
      {
        v4 = 0LL;
      }
      cred_label_rele(v8);
    }
    else
    {
      return 0LL;
    }
  }
  return v4;
}