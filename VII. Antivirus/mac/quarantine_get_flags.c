__int64 __fastcall quarantine_get_flags(__int64 a1, __int64 a2, int a3, char *a4)
{
  __int64 v8; // x0
  char *v9; // x21
  __int64 v10; // x22
  int v11; // w1
  int v13[2]; // [xsp+8h] [xbp-38h] BYREF

  *(_QWORD *)v13 = 4096LL;
  v8 = kalloc_data(4097LL, 0LL);
  if ( !v8 )
    return 12LL;
  v9 = (char *)v8;
  v10 = quarantine_getinfo(a1, v8, v13, a2);
  v11 = v13[0];
  v9[*(_QWORD *)v13] = 0;
  if ( !(_DWORD)v10 )
    v10 = quarantine_info_parse(v9, v11, a3, a4);
  kfree_data(v9, 4097LL);
  return v10;
}