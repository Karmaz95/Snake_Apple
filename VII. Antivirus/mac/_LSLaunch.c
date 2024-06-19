__int64 __fastcall _LSLaunch(
        LSContext *a1,
        __int64 a2,
        void *a3,
        unsigned int a4,
        void *a5,
        __int64 a6,
        __int64 a7,
        __int64 a8,
        __int64 a9,
        void *a10,
        __int64 a11,
        __int64 a12,
        _QWORD *a13,
        __int64 a14)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  v78 = a2;
  v21 = objc_retain(a3);
  v22 = objc_retain(a5);
  v23 = objc_retain(a10);
  v77 = 0LL;
  if ( !v22 )
    v22 = objc_retainAutoreleasedReturnValue(+[_LSOpen2Options defaultOptions](&OBJC_CLASS____LSOpen2Options, "defaultOptions"));
  v74 = a6;
  v75 = a7;
  v76 = a8;
  v24 = objc_retain(v21);
  v25 = v24;
  if ( !a1 || !a2 )
  {
    objc_release(v24);
LABEL_19:
    v37 = _LSLaunchWithRunningboard(a1, v25, a4, v74, v75, v76, a9, v23, a11, a2, a12, v22, &v77, a14);
    goto LABEL_38;
  }
  v26 = _LSBundleGet(a1->db, a2);
  if ( !v26 )
  {
    v38 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
    if ( j__os_log_type_enabled_3(v38, OS_LOG_TYPE_INFO) )
    {
      *v84 = 134349312;
      *&v84[4] = a1;
      *&v84[12] = 1026;
      *&v84[14] = a2;
      v39 = "LAUNCH: Bundle data is NULL so it must be re-registered before attempting launch, %{public}p %{public}d";
LABEL_24:
      j___os_log_impl_1(&dword_180981000, v38, OS_LOG_TYPE_INFO, v39, v84, 0x12u);
    }
LABEL_25:
    objc_release(v38);
    objc_release(v25);
    goto LABEL_32;
  }
  if ( !_LSBundleMeetsMinimumVersionRequirement(a1->db, a2, v26) )
  {
    v38 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
    if ( j__os_log_type_enabled_3(v38, OS_LOG_TYPE_INFO) )
    {
      *v84 = 134349312;
      *&v84[4] = a1;
      *&v84[12] = 1026;
      *&v84[14] = a2;
      v39 = "LAUNCH: Bundle needs to be re-registered before attempting launch to meet minimum version requirements, %{pu"
            "blic}p %{public}d";
      goto LABEL_24;
    }
    goto LABEL_25;
  }
  v82 = 0LL;
  v83 = 0.0;
  v27 = objc_msgSend(v25, "getContentModificationDate:error:", &v83, &v82);
  v28 = objc_retain(v82);
  if ( !v27 )
  {
    v40 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
    if ( j__os_log_type_enabled_3(v40, OS_LOG_TYPE_ERROR) )
    {
      v41 = objc_retainAutoreleasedReturnValue(objc_msgSend(v25, "URL"));
      *v84 = 134349827;
      *&v84[4] = a1;
      *&v84[12] = 1026;
      *&v84[14] = a2;
      v85 = 2113;
      v86 = v41;
      v87 = 2114;
      v88[0] = v28;
      j___os_log_impl_1(
        &dword_180981000,
        v40,
        OS_LOG_TYPE_ERROR,
        "LAUNCH: Unable to validate executable mod date inside bundle %{public}p %{public}d %{private}@, error=%{public}@",
        v84,
        0x26u);
      v42 = v41;
LABEL_30:
      objc_release(v42);
    }
LABEL_31:
    objc_release(v40);
    objc_release(v28);
    objc_release(v25);
    goto LABEL_32;
  }
  v29 = v83;
  if ( _LSBundleDataGetModTime(v26) != v29 )
  {
    v40 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
    if ( j__os_log_type_enabled_3(v40, OS_LOG_TYPE_INFO) )
    {
      v73 = objc_retainAutoreleasedReturnValue(objc_msgSend(v25, "URL"));
      v43 = v83;
      ModTime = _LSBundleDataGetModTime(v26);
      *v84 = 134350083;
      *&v84[4] = a1;
      *&v84[12] = 1026;
      *&v84[14] = a2;
      v85 = 2113;
      v86 = v73;
      v87 = 1026;
      LODWORD(v88[0]) = v43;
      WORD2(v88[0]) = 1026;
      *(v88 + 6) = ModTime;
      j___os_log_impl_1(
        &dword_180981000,
        v40,
        OS_LOG_TYPE_INFO,
        "LAUNCH: Forcing re-registration of bundle %{public}p %{public}d %{private}@ because the bundle mod date is chang"
        "ed, %{public}d vs %{public}d",
        v84,
        0x28u);
      v42 = v73;
      goto LABEL_30;
    }
    goto LABEL_31;
  }
  objc_release(v28);
  if ( (*(v26 + 158) & 0x80) != 0 )
  {
    objc_release(v25);
    goto LABEL_19;
  }
  v81 = 0LL;
  v30 = objc_retainAutoreleasedReturnValue(objc_msgSend(v25, "pathWithError:", &v81));
  v31 = objc_retain(v81);
  v72 = v30;
  if ( v30 )
  {
    v32 = objc_retainAutoreleasedReturnValue(constructExecutablePathFromBundleData(a1, a2, v26, v30, 0));
    if ( !v32 )
    {
      v36 = 0;
      goto LABEL_64;
    }
    v70 = v32;
    v80 = v31;
    v69 = -[FSNode initWithPath:flags:error:](
            objc_alloc(&OBJC_CLASS___FSNode),
            "initWithPath:flags:error:",
            v32,
            1LL,
            &v80);
    v68 = objc_retain(v80);
    objc_release(v31);
    v33 = v69;
    if ( v69 )
    {
      if ( -[FSNode isExecutableModeFile](v69, "isExecutableModeFile") )
      {
        if ( _LSBundleDataGetExecutableModTime(v26) >= 1 )
        {
          v83 = 0.0;
          v79 = v68;
          v67 = -[FSNode getContentModificationDate:error:](v69, "getContentModificationDate:error:", &v83, &v79);
          v34 = objc_retain(v79);
          objc_release(v68);
          if ( v67 )
          {
            v35 = v83;
            if ( _LSBundleDataGetExecutableModTime(v26) == v35 )
            {
              v36 = 0;
LABEL_73:
              v59 = v34;
              v33 = v69;
              goto LABEL_63;
            }
            v60 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
            if ( j__os_log_type_enabled_3(v60, OS_LOG_TYPE_INFO) )
            {
              v65 = v83;
              ExecutableModTime = _LSBundleDataGetExecutableModTime(v26);
              *v84 = 134350083;
              *&v84[4] = a1;
              *&v84[12] = 1026;
              *&v84[14] = a2;
              v85 = 2113;
              v86 = v70;
              v87 = 1026;
              LODWORD(v88[0]) = v65;
              WORD2(v88[0]) = 1026;
              *(v88 + 6) = ExecutableModTime;
              v61 = "LAUNCH: Forcing re-registration of bundle %{public}p %{public}d %{private}@ because the executable m"
                    "od date is changed, %{public}d vs %{public}d";
              v62 = v60;
              v63 = OS_LOG_TYPE_INFO;
              v64 = 40;
              goto LABEL_71;
            }
          }
          else
          {
            v60 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
            if ( j__os_log_type_enabled_3(v60, OS_LOG_TYPE_ERROR) )
            {
              *v84 = 134349827;
              *&v84[4] = a1;
              *&v84[12] = 1026;
              *&v84[14] = a2;
              v85 = 2113;
              v86 = v70;
              v87 = 2114;
              v88[0] = v34;
              v61 = "LAUNCH: Unable to validate executable mod date inside bundle %{public}p %{public}d %{private}@, error=%{public}@";
              v62 = v60;
              v63 = OS_LOG_TYPE_ERROR;
              v64 = 38;
LABEL_71:
              j___os_log_impl_1(&dword_180981000, v62, v63, v61, v84, v64);
            }
          }
          objc_release(v60);
          v36 = 1;
          goto LABEL_73;
        }
        v36 = 0;
LABEL_62:
        v59 = v68;
LABEL_63:
        objc_release(v33);
        v31 = v59;
        v32 = v70;
        goto LABEL_64;
      }
      v54 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
      if ( j__os_log_type_enabled_3(v54, OS_LOG_TYPE_INFO) )
      {
        *v84 = 134349571;
        *&v84[4] = a1;
        *&v84[12] = 1026;
        *&v84[14] = a2;
        v85 = 2113;
        v86 = v70;
        v55 = "LAUNCH: Forcing re-registration of bundle %{public}p %{public}d %{private}@ because the executable is not +x";
        v56 = v54;
        v57 = OS_LOG_TYPE_INFO;
        v58 = 28;
        goto LABEL_60;
      }
    }
    else
    {
      v54 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
      if ( j__os_log_type_enabled_3(v54, OS_LOG_TYPE_ERROR) )
      {
        *v84 = 134349827;
        *&v84[4] = a1;
        *&v84[12] = 1026;
        *&v84[14] = a2;
        v85 = 2113;
        v86 = v70;
        v87 = 2114;
        v88[0] = v68;
        v55 = "LAUNCH: Unable to make node to executable inside bundle %{public}p %{public}d %{private}@, error=%{public}@";
        v56 = v54;
        v57 = OS_LOG_TYPE_ERROR;
        v58 = 38;
LABEL_60:
        j___os_log_impl_1(&dword_180981000, v56, v57, v55, v84, v58);
      }
    }
    objc_release(v54);
    v36 = 1;
    goto LABEL_62;
  }
  v36 = 1;
  v52 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
  if ( j__os_log_type_enabled_3(v52, OS_LOG_TYPE_INFO) )
  {
    v53 = objc_retainAutoreleasedReturnValue(objc_msgSend(v25, "URL"));
    *v84 = 134349571;
    *&v84[4] = a1;
    *&v84[12] = 1026;
    *&v84[14] = a2;
    v85 = 2113;
    v86 = v53;
    v71 = v53;
    v36 = 1;
    j___os_log_impl_1(
      &dword_180981000,
      v52,
      OS_LOG_TYPE_INFO,
      "LAUNCH: Forcing re-registration of bundle %{public}p %{public}d %{private}@ because the node path cannot be created.",
      v84,
      0x1Cu);
    objc_release(v71);
  }
  v32 = v52;
LABEL_64:
  objc_release(v32);
  objc_release(v72);
  objc_release(v31);
  objc_release(v25);
  if ( !v36 )
    goto LABEL_19;
LABEL_32:
  *v84 = 0LL;
  if ( _LSContextInit(v84) )
  {
    v37 = 0LL;
  }
  else
  {
    v83 = 0.0;
    v37 = _LSFindOrRegisterBundleNode(v84, v25, 0LL, 33554433LL, 0LL, &v78, &v83);
    if ( !v37 )
      v37 = _LSLaunchWithRunningboard(v84, v25, a4, v74, v75, v76, a9, v23, a11, v78, a12, v22, &v77, a14);
    _LSContextDestroy(v84);
  }
  objc_release(*v84);
LABEL_38:
  if ( a13 )
    *a13 = v77;
  if ( v37 == -10652 )
  {
    v45 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
    if ( j__os_log_type_enabled_3(v45, OS_LOG_TYPE_INFO) )
    {
      *v84 = 138478339;
      *&v84[4] = v25;
      *&v84[12] = 1026;
      *&v84[14] = v77;
      v85 = 1026;
      LODWORD(v86) = HIDWORD(v77);
      v46 = "LAUNCH: Launch of %{private}@ matched already running application, 0x%{public}x-0x%{public}x";
      goto LABEL_46;
    }
  }
  else if ( v37 )
  {
    v45 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
    if ( j__os_log_type_enabled_3(v45, OS_LOG_TYPE_ERROR) )
    {
      MacOSStatusErrorString = GetMacOSStatusErrorString(v37);
      *v84 = 67240707;
      *&v84[4] = v37;
      *&v84[8] = 2082;
      *&v84[10] = MacOSStatusErrorString;
      v85 = 2113;
      v86 = v25;
      v46 = "LAUNCH: Launch failure with %{public}d/%{public}s %{private}@";
      v47 = v45;
      v48 = OS_LOG_TYPE_ERROR;
      v49 = 28;
      goto LABEL_49;
    }
  }
  else
  {
    v45 = objc_retainAutoreleasedReturnValue(_LSOpenLog());
    if ( j__os_log_type_enabled_3(v45, OS_LOG_TYPE_INFO) )
    {
      *v84 = 138478339;
      *&v84[4] = v25;
      *&v84[12] = 1026;
      *&v84[14] = v77;
      v85 = 1026;
      LODWORD(v86) = HIDWORD(v77);
      v46 = "LAUNCH: Launch of %{private}@ launched successfully, 0x%{public}x-0x%{public}x";
LABEL_46:
      v47 = v45;
      v48 = OS_LOG_TYPE_INFO;
      v49 = 24;
LABEL_49:
      j___os_log_impl_1(&dword_180981000, v47, v48, v46, v84, v49);
    }
  }
  objc_release(v45);
  objc_release(v23);
  objc_release(v22);
  objc_release(v25);
  return v37;
}