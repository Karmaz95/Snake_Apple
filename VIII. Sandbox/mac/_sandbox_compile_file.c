__int64 __fastcall sandbox_compile_file(const char *a1, __int64 a2, char **a3)
{
  FILE *v6; // x0
  FILE *v7; // x24
  char *v8; // x2
  const char *v9; // x8
  char **i; // x25
  FILE *v11; // x0
  char *v12; // t1
  int *v13; // x0
  __int64 v14; // x19
  char *v16; // [xsp+18h] [xbp-48h] BYREF

  v16 = 0LL;
  if ( *a1 )
  {
    if ( *a1 != 47 )
    {
      v9 = "/System/Library/Sandbox/Profiles";
      for ( i = &off_1E4D35420; ; ++i )
      {
        j__asprintf_11(&v16, "%s/%s.sb", v9, a1);
        if ( !v16 )
        {
          j__asprintf_11(a3, "out of memory");
          return 0LL;
        }
        v11 = j__fopen_15(v16, "r");
        v8 = v16;
        if ( v11 )
          break;
        j__free_34(v16);
        v12 = *i;
        v9 = v12;
        if ( !v12 )
        {
          j__asprintf_11(a3, "%s: profile not found");
          return 0LL;
        }
      }
      v7 = v11;
      goto LABEL_15;
    }
    v6 = j__fopen_15(a1, "r");
    if ( v6 )
    {
      v7 = v6;
      v8 = a1;
LABEL_15:
      v14 = compile(0LL, v7, v8, 0LL, a2, 0LL, a3);
      j__free_34(v16);
      j__fclose_16(v7);
      return v14;
    }
    v13 = j____error_27();
    j__strerror_15(*v13);
    j__asprintf_11(a3, "%s: %s");
  }
  else
  {
    j__asprintf_11(a3, "path is empty");
  }
  return 0LL;
}