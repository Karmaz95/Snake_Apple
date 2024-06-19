__int64 __fastcall _spawn_via_launchd(const char *a1, __int64 a2, __int64 a3)
{
  xpc_object_t v4; // x20
  int v5; // w19
  int64_t int64; // x19
  __int64 v8; // x0
  xpc_object_t v9; // [xsp+8h] [xbp-18h] BYREF

  if ( a3 )
  {
    v8 = _xpc_asprintf("_spawn_via_launchd() no longer supports spawn_via_launchd_attr");
    _xpc_api_misuse(v8);
  }
  v4 = xpc_dictionary_create(0LL, 0LL, 0LL);
  xpc_dictionary_set_uint64(v4, "type", 7uLL);
  xpc_dictionary_set_uint64(v4, "handle", 0LL);
  xpc_dictionary_set_string(v4, "label", a1);
  v9 = 0LL;
  v5 = _xpc_domain_routine(817LL, v4, &v9);
  xpc_release(v4);
  if ( v5 )
  {
    *j____error() = v5;
    return 0xFFFFFFFFLL;
  }
  else
  {
    int64 = xpc_dictionary_get_int64(v9, "pid");
    xpc_release(v9);
  }
  return int64;
}