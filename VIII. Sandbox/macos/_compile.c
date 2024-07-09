char **compile()
{
  __int64 v0; // x0
  char **v1; // x6
  char **v2; // x21
  void *v3; // x5
  void *v4; // x23
  _QWORD *v5; // x4
  _QWORD *v6; // x24
  const char **v7; // x3
  const char **v8; // x27
  __int64 v9; // x2
  __int64 v10; // x25
  FILE *v11; // x1
  FILE *v12; // x22
  const char *v13; // x26
  _OWORD *v14; // x19
  _BYTE *v15; // x20
  const void *v16; // x0
  const void *v17; // x0
  char *v18; // x0
  char *v19; // x20
  size_t v20; // x22
  __int64 v21; // x0
  char v22; // w22
  __int64 v23; // x0
  xpc_object_t _14; // x22
  char **v25; // x23
  int v26; // w0
  int v27; // w26
  __int64 v28; // x26
  __int64 v29; // x27
  const char *v30; // x22
  const char **v31; // x28
  __int64 v32; // x26
  FILE *v33; // x0
  FILE *v34; // x27
  __int64 v35; // x26
  char v36; // w22
  const char *v37; // t1
  __int64 v38; // x0
  __int64 v39; // x0
  __int64 v40; // x0
  __int64 v41; // x25
  off_t v42; // x0
  unsigned __int64 v43; // x25
  const char **v44; // x8
  void *v45; // x0
  xpc_object_t value_11; // x0
  _QWORD *v47; // x23
  __int64 v48; // x24
  _DWORD *v49; // x0
  int v50; // w27
  int v51; // w26
  __int64 v52; // x28
  __int64 v53; // x0
  __int64 v54; // x25
  _QWORD *v55; // x0
  __int64 v56; // x0
  __int64 *v57; // x8
  __int64 v58; // x9
  int v59; // w24
  void *v60; // x26
  __int64 inited; // x0
  _QWORD *v62; // x25
  _DWORD *v63; // x0
  __int64 v64; // x27
  bool v65; // cf
  __int64 v66; // x24
  __int64 v67; // x28
  __int64 v68; // x26
  __int64 v69; // x0
  __int64 v70; // x0
  __int64 v71; // x0
  __int64 v72; // x0
  __int64 v73; // x0
  __int64 v74; // x0
  __int64 v75; // x0
  char v76; // w8
  unsigned __int64 v77; // x28
  __int64 *v78; // x24
  __int64 v79; // x0
  __int64 v80; // x0
  __int64 v81; // x0
  unsigned __int64 v82; // x28
  char v83; // w8
  unsigned __int64 v84; // x28
  __int64 *v85; // x24
  __int64 v86; // x28
  __int64 v87; // x0
  __int64 v88; // x0
  __int64 v89; // x0
  __int64 v90; // x0
  __int64 v91; // x0
  __int64 v92; // x0
  __int64 v93; // x0
  __int64 v94; // x0
  __int64 v95; // x0
  __int64 v96; // x0
  __int64 v97; // x0
  __int64 v98; // x0
  __int64 v99; // x0
  __int64 v100; // x0
  __int64 v101; // x0
  __int64 v102; // x0
  __int64 v103; // x0
  __int64 v104; // x0
  __int64 v105; // x0
  __int64 v106; // x26
  __int64 v107; // x0
  __int64 v108; // x8
  __int64 v109; // x26
  __int64 v110; // x24
  size_t v111; // x0
  __int64 *v112; // x0
  __int64 v113; // x0
  __int64 v114; // x0
  int v115; // w8
  int k; // w24
  __int64 v117; // x25
  __int64 v118; // x26
  _QWORD *v119; // x21
  _QWORD *v120; // x21
  __int64 v121; // t1
  __int64 v122; // x8
  _QWORD *v123; // x8
  __int64 v124; // x9
  __int64 v125; // t1
  __int64 v126; // x21
  FILE *v127; // x0
  FILE **v128; // x21
  FILE *v129; // t1
  __int64 v130; // x8
  void *v131; // x0
  void *v132; // x0
  __int64 v134; // x0
  __int64 v135; // x0
  __int64 v136; // x0
  __int64 v137; // x25
  __int64 v138; // x26
  __int64 v139; // x27
  void *v140; // x0
  void *v141; // x24
  __int64 v142; // x0
  char **v143; // x0
  __int64 v144; // x0
  __int64 v145; // x23
  int *v146; // x0
  char *v147; // x0
  __int64 v148; // x26
  const char *v149; // x28
  __int64 v150; // x0
  __int64 v151; // x26
  __int64 v152; // x0
  __int64 v153; // x26
  __int64 v154; // x0
  xpc_object_t v155; // x0
  __int64 v156; // x2
  __int64 v157; // x24
  __int64 v158; // x28
  unsigned __int64 i; // x25
  __int64 v160; // x24
  const char *v161; // x27
  FILE *v162; // x26
  int v163; // w0
  __int64 v164; // x0
  __int128 *v165; // x1
  char *v166; // x0
  __int64 v167; // x25
  char **v168; // x24
  __int64 v169; // x0
  __int64 v170; // x26
  __int64 v171; // x0
  __int64 v172; // x8
  __int64 v173; // x26
  __int64 v174; // x24
  void *v175; // x0
  char v176; // w24
  __int64 v177; // x0
  void *v178; // x0
  __int64 v179; // x25
  unsigned __int64 j; // x26
  __int64 v181; // x25
  __int64 *v182; // x27
  __int64 v183; // x9
  __int128 v184; // [xsp+0h] [xbp-1240h]
  const char *v185; // [xsp+0h] [xbp-1240h]
  double v186; // [xsp+0h] [xbp-1240h]
  const char *v187; // [xsp+0h] [xbp-1240h]
  _QWORD *v188; // [xsp+0h] [xbp-1240h]
  double v189; // [xsp+0h] [xbp-1240h]
  void *v190; // [xsp+38h] [xbp-1208h]
  __int64 v191; // [xsp+40h] [xbp-1200h]
  __int64 v192; // [xsp+40h] [xbp-1200h]
  __int64 v193; // [xsp+48h] [xbp-11F8h]
  char **v194; // [xsp+50h] [xbp-11F0h] BYREF
  _QWORD *v195; // [xsp+58h] [xbp-11E8h] BYREF
  __int64 immutable; // [xsp+60h] [xbp-11E0h] BYREF
  void *v197; // [xsp+68h] [xbp-11D8h] BYREF
  __int64 v198; // [xsp+70h] [xbp-11D0h] BYREF
  _QWORD *v199; // [xsp+78h] [xbp-11C8h] BYREF
  void *v200; // [xsp+80h] [xbp-11C0h] BYREF
  __int64 v201[5]; // [xsp+88h] [xbp-11B8h] BYREF
  __int64 v202[5]; // [xsp+B0h] [xbp-1190h] BYREF
  __int64 v203[6]; // [xsp+D8h] [xbp-1168h] BYREF
  __int64 v204[6]; // [xsp+108h] [xbp-1138h] BYREF
  __int64 v205[6]; // [xsp+138h] [xbp-1108h] BYREF
  __int64 v206[6]; // [xsp+168h] [xbp-10D8h] BYREF
  __int64 v207[6]; // [xsp+198h] [xbp-10A8h] BYREF
  __int64 v208[6]; // [xsp+1C8h] [xbp-1078h] BYREF
  __int64 v209[6]; // [xsp+1F8h] [xbp-1048h] BYREF
  __int64 v210[6]; // [xsp+228h] [xbp-1018h] BYREF
  __int64 v211[2]; // [xsp+258h] [xbp-FE8h] BYREF
  __int64 (__fastcall *v212)(); // [xsp+268h] [xbp-FD8h]
  void *v213; // [xsp+270h] [xbp-FD0h]
  __int64 v214; // [xsp+278h] [xbp-FC8h]
  __int64 v215[2]; // [xsp+280h] [xbp-FC0h] BYREF
  __int64 (__fastcall *v216)(); // [xsp+290h] [xbp-FB0h]
  void *v217; // [xsp+298h] [xbp-FA8h]
  __int64 v218; // [xsp+2A0h] [xbp-FA0h]
  __int64 v219[2]; // [xsp+2A8h] [xbp-F98h] BYREF
  __int64 (__fastcall *v220)(); // [xsp+2B8h] [xbp-F88h]
  void *v221; // [xsp+2C0h] [xbp-F80h]
  _QWORD *v222; // [xsp+2C8h] [xbp-F78h]
  __objc2_class *v223; // [xsp+2D0h] [xbp-F70h] BYREF
  __int64 v224; // [xsp+2D8h] [xbp-F68h]
  __int64 (__fastcall *v225)(); // [xsp+2E0h] [xbp-F60h]
  void *v226; // [xsp+2E8h] [xbp-F58h]
  __int64 v227; // [xsp+2F0h] [xbp-F50h]
  __objc2_class *v228; // [xsp+2F8h] [xbp-F48h] BYREF
  __int64 v229; // [xsp+300h] [xbp-F40h]
  __int64 (__fastcall *v230)(); // [xsp+308h] [xbp-F38h]
  void *v231; // [xsp+310h] [xbp-F30h]
  _QWORD *v232; // [xsp+318h] [xbp-F28h]
  __int64 v233; // [xsp+320h] [xbp-F20h]
  char ***v234; // [xsp+328h] [xbp-F18h]
  __int128 v235; // [xsp+330h] [xbp-F10h] BYREF
  __int128 v236; // [xsp+340h] [xbp-F00h] BYREF
  __int128 v237; // [xsp+350h] [xbp-EF0h]
  __int128 v238; // [xsp+360h] [xbp-EE0h]
  __int128 v239; // [xsp+370h] [xbp-ED0h]
  __int128 v240; // [xsp+380h] [xbp-EC0h]
  __int128 v241; // [xsp+390h] [xbp-EB0h]
  __int128 v242; // [xsp+3A0h] [xbp-EA0h]
  __int64 v243; // [xsp+3B0h] [xbp-E90h] BYREF
  char *v244; // [xsp+B50h] [xbp-6F0h]
  unsigned int v245; // [xsp+B58h] [xbp-6E8h]
  int v246; // [xsp+B5Ch] [xbp-6E4h] BYREF
  __int64 v247[11]; // [xsp+F60h] [xbp-2E0h] BYREF
  __int64 v248; // [xsp+FB8h] [xbp-288h] BYREF
  __int64 v249; // [xsp+11B8h] [xbp-88h]
  char **v250; // [xsp+11C8h] [xbp-78h]

  v0 = off_1ED3EBAC8();
  v2 = v1;
  v4 = v3;
  v6 = v5;
  v8 = v7;
  v10 = v9;
  v12 = v11;
  v13 = v0;
  v194 = 0LL;
  v14 = j__calloc_26(1uLL, 0x100uLL);
  *v14 = 1;
  v14[2] = 0u;
  v14[3] = 0u;
  *(v14 + 8) = 0LL;
  v15 = j__calloc_26(1uLL, 0x48uLL);
  *v15 = 1;
  v15[4] = 1;
  sb_context_retain(v14);
  *(v15 + 8) = v14;
  *(v14 + 9) = v15;
  *(v14 + 27) = 0LL;
  if ( *v14 != 2 )
    j____assert_rtn_18("sb_context_new", "context.c", 40, "context->refcnt == INTERNAL_REFERENCE_COUNT + 1");
  v195 = v14;
  v16 = *(v14 + 30);
  if ( v16 )
    j___Block_release_18(v16);
  *(v14 + 30) = j___Block_copy_18(&__block_literal_global_396);
  v17 = *(v14 + 31);
  if ( v17 )
    j___Block_release_18(v17);
  *(v14 + 31) = j___Block_copy_18(&__block_literal_global_8_5);
  v18 = j__calloc_26(1uLL, 0x30uLL);
  v19 = v18;
  if ( !v18 )
  {
    v23 = *(v14 + 30);
    if ( v23 )
      (*(v23 + 16))(v23, &sb_error_out_of_memory_oom_error);
    _14 = 0LL;
    goto LABEL_14;
  }
  *v18 = 1;
  sb_context_retain(v14);
  *(v19 + 2) = v14;
  v19[45] = 1;
  if ( !v13 )
  {
    if ( !v12 )
    {
      if ( v8 )
      {
        v30 = *v8;
        if ( *v8 )
        {
          v31 = v8 + 1;
          while ( 1 )
          {
            v32 = *(v19 + 2);
            v33 = j__fopen_15(v30, "r");
            if ( !v33 )
              break;
            v34 = v33;
            v35 = sb_buffer_with_contents_of_file(v32, v33, &v194);
            j__fclose_16(v34);
            *&v235 = v35;
            if ( !v35 )
              goto LABEL_106;
            v36 = sb_program_add_source_buffer(v19, v30, v35, &v194);
            sb_buffer_release(&v235);
            if ( (v36 & 1) == 0 )
              goto LABEL_106;
            v37 = *v31++;
            v30 = v37;
            if ( !v37 )
              goto LABEL_38;
          }
          v145 = *j____error_27();
          v146 = j____error_27();
          v147 = j__strerror_15(*v146);
          sb_error_set_with_format(v32, &v194, "failed to open \"%s\" for reading: (#%d) %s", v30, v145, v147);
          goto LABEL_106;
        }
      }
      goto LABEL_38;
    }
    j__flockfile(v12);
    v26 = j__fileno_5(v12);
    if ( v26 < 0 || (v27 = v26, j__bzero_30(&v235, 0x400uLL), j__fcntl_13(v27, 50, &v235)) )
    {
      if ( v10 )
      {
        v28 = 0LL;
LABEL_21:
        v29 = v28;
        v28 = sb_textbuf_with_string_copy(*(v19 + 2), v10, &v194);
        if ( !v28 )
        {
LABEL_103:
          if ( v29 )
          {
            *&v235 = v29;
            sb_buffer_release(&v235);
          }
          goto LABEL_105;
        }
LABEL_36:
        v40 = sb_program_source_alloc(v19, &v194);
        if ( v40 )
        {
          v41 = v40;
          v42 = j__ftello_0(v12);
          *(v41 + 40) = 0;
          *(v41 + 32) = v29;
          *v41 = v28;
          *(v41 + 8) = v12;
          *(v41 + 16) = v42;
          goto LABEL_38;
        }
        *&v235 = v28;
        sb_buffer_release(&v235);
        goto LABEL_103;
      }
      v38 = sb_buffer_alloc(*(v19 + 2), 0LL, &v194);
      if ( v38 )
      {
        v28 = v38;
        v29 = 0LL;
        *(v38 + 16) = *(v38 + 16) & 0xFD00000000000000LL | 0xD;
        *(v38 + 24) = "<input file>";
        goto LABEL_36;
      }
    }
    else
    {
      v39 = sb_textbuf_with_string_copy(*(v19 + 2), &v235, &v194);
      if ( v39 )
      {
        v28 = v39;
        if ( !v10 )
        {
          sb_buffer_retain(v39);
          v29 = v28;
          goto LABEL_36;
        }
        goto LABEL_21;
      }
    }
LABEL_105:
    j__funlockfile(v12);
LABEL_106:
    _14 = 0LL;
    goto LABEL_107;
  }
  v20 = j__strlen_31(v13);
  v21 = sb_buffer_alloc(v14, 0LL, &v194);
  if ( !v21 )
    goto LABEL_106;
  *(v21 + 16) = *(v21 + 16) & 0xFD00000000000000LL | v20 & 0xFFFFFFFFFFFFFFLL;
  *(v21 + 24) = v13;
  *&v235 = v21;
  v22 = sb_program_add_source_buffer(v19, v10, v21, &v194);
  sb_buffer_release(&v235);
  if ( (v22 & 1) == 0 )
    goto LABEL_106;
LABEL_38:
  if ( v6 )
  {
    _14 = j__xpc_dictionary_create_14(0LL, 0LL, 0LL);
    if ( v6[1] )
    {
      v43 = 0LL;
      do
      {
        v44 = (*v6 + 8 * v43);
        v43 += 2LL;
        j__xpc_dictionary_set_string_13(_14, *v44, v44[1]);
      }
      while ( v43 < v6[1] );
    }
    if ( v4 )
      j__xpc_dictionary_set_value_10(_14, "entitlements", v4);
    if ( !_14 )
    {
      v113 = *(v14 + 30);
      v25 = &sb_error_out_of_memory_oom_error;
      if ( v113 )
        (*(v113 + 16))(v113, &sb_error_out_of_memory_oom_error);
      _14 = 0LL;
      goto LABEL_15;
    }
    v45 = *(v19 + 4);
    if ( v45 )
      j__xpc_release_14(v45);
    *(v19 + 4) = j__xpc_retain_9(_14);
    v19[44] = 1;
    v19[45] = j__xpc_dictionary_get_value_11(_14, "NO_IMPLICIT_RULES") == 0LL;
    value_11 = j__xpc_dictionary_get_value_11(_14, "ENABLE_PATTERN_VARIABLES");
    v19[46] = value_11 != 0LL;
    v199 = 0LL;
    immutable = 0LL;
    v197 = 0LL;
    if ( !value_11 )
    {
      v47 = 0LL;
      goto LABEL_52;
    }
  }
  else
  {
    _14 = 0LL;
    *(v19 + 45) = 257;
    v199 = 0LL;
    immutable = 0LL;
    v197 = 0LL;
  }
  v48 = *(v19 + 2);
  v49 = j__calloc_26(1uLL, 0x28uLL);
  if ( v49 )
  {
    v47 = v49;
    *v49 = 1;
    sb_context_retain(v48);
    v47[1] = v48;
    v47[3] = 0LL;
    v47[4] = 0LL;
    v199 = v47;
LABEL_52:
    v50 = v19[45];
    v51 = v19[47];
    v52 = *(v19 + 2);
    v53 = sb_policy_new(v52, 0LL, 190LL, &v194);
    if ( !v53 )
      goto LABEL_147;
    v54 = v53;
    *&v235 = v53;
    v55 = j__calloc_26(1uLL, 0x38uLL);
    if ( !v55 )
    {
      v134 = *(v52 + 240);
      if ( v134 )
        (*(v134 + 16))(v134, &sb_error_out_of_memory_oom_error);
      v194 = &sb_error_out_of_memory_oom_error;
      sb_policy_release(&v235);
      goto LABEL_147;
    }
    *v55 = 1;
    v55[1] = v54;
    v193 = v55;
    v56 = sb_context_retain_modification(v52, v52 + 12);
    v57 = (v52 + 40);
    v58 = *(v52 + 40);
    *(v193 + 32) = v58;
    *(v193 + 24) = v52;
    if ( v58 )
      *(v58 + 40) = v193 + 32;
    *v57 = v193;
    *(v193 + 40) = v57;
    *(v193 + 48) = 0LL;
    v198 = v193;
    if ( v51 )
      v59 = (2 * (v50 != 0)) | 4;
    else
      v59 = 2 * (v50 != 0);
    v60 = *(v19 + 4);
    v200 = 0LL;
    inited = scheme_init_new(v56);
    if ( !inited )
    {
      v135 = *(v52 + 240);
      if ( v135 )
        (*(v135 + 16))(v135, &sb_error_out_of_memory_oom_error);
      v194 = &sb_error_out_of_memory_oom_error;
      goto LABEL_146;
    }
    v62 = inited;
    v63 = j__calloc_26(1uLL, 0x88uLL);
    if ( !v63 )
    {
      v136 = *(v52 + 240);
      if ( v136 )
        (*(v136 + 16))(v136, &sb_error_out_of_memory_oom_error);
      v194 = &sb_error_out_of_memory_oom_error;
      goto LABEL_145;
    }
    v64 = v63;
    v200 = v63;
    *v63 = 1LL;
    v63[3] = v59;
    sb_context_retain(v52);
    *(v64 + 24) = v52;
    v65 = __CFADD__((*v193)++, 1);
    if ( v65 )
      j____assert_rtn_18("sb_profile_retain", "profile.c", 91, "profile->refcnt > 0");
    *(v64 + 16) = v193;
    *(v64 + 48) = *(v193 + 8);
    v66 = v193;
    if ( v47 )
    {
      sb_pattern_varset_retain(v47);
      *(v64 + 32) = v47;
      sb_profile_set_pattern_variables(*(v64 + 16), v47);
      v66 = *(v64 + 16);
    }
    *(v64 + 56) = v62;
    scheme_set_external_data(v62, v64);
    if ( (*(v64 + 12) & 4) != 0 )
      scheme_enable_full_backtraces(v62, 1LL);
    scheme_set_output_port_string(v62, 0LL, 0LL, "<stdout>");
    if ( *(v64 + 64) )
      j____assert_rtn_18("define_type_symbols", "sbpl_parser.c", 288, "parser->sym_condition == NULL");
    if ( *(v64 + 72) )
      j____assert_rtn_18("define_type_symbols", "sbpl_parser.c", 289, "parser->sym_operation == NULL");
    if ( *(v64 + 80) )
      j____assert_rtn_18("define_type_symbols", "sbpl_parser.c", 290, "parser->sym_modifier == NULL");
    if ( *(v64 + 88) )
      j____assert_rtn_18("define_type_symbols", "sbpl_parser.c", 291, "parser->sym_msgfilter == NULL");
    if ( *(v64 + 96) )
      j____assert_rtn_18("define_type_symbols", "sbpl_parser.c", 292, "parser->sym_deprecated == NULL");
    v190 = v60;
    if ( *(v64 + 104) )
      j____assert_rtn_18("define_type_symbols", "sbpl_parser.c", 293, "parser->sym_nop == NULL");
    v191 = v66;
    v67 = *(v64 + 56);
    v68 = *(v67 + 4616);
    v69 = mk_symbol(v67, "condition");
    *(v64 + 64) = gc_protect(v67, 0LL, v69);
    v70 = mk_symbol(v67, "operation");
    *(v64 + 72) = gc_protect(v67, 0LL, v70);
    v71 = mk_symbol(v67, "modifier");
    *(v64 + 80) = gc_protect(v67, 0LL, v71);
    v72 = mk_symbol(v67, "message-filter");
    *(v64 + 88) = gc_protect(v67, 0LL, v72);
    v73 = mk_symbol(v67, "deprecated");
    *(v64 + 96) = gc_protect(v67, 0LL, v73);
    v74 = mk_symbol(v67, "no-op");
    *(v64 + 104) = gc_protect(v67, 0LL, v74);
    v184 = *(v64 + 64);
    _define_list(v67, "*sbpl-type-symbols*");
    gc_unprotect(v67, 6LL);
    if ( *(v67 + 4616) != v68 )
      j____assert_rtn_18("define_type_symbols", "sbpl_parser.c", 313, "sc->gc_protect_lst == initial_gc_protect_lst");
    v75 = mk_foreign_func(v62, version);
    _define_symbol(v62, "version", v75);
    define_action(v64, "allow", 1LL);
    define_action(v64, "deny", 0LL);
    define_action(v64, "delegate", 2LL);
    v76 = 0;
    v77 = 0LL;
    v219[0] = &OBJC_CLASS_____NSStackBlock__;
    v219[1] = 0x40000000LL;
    v220 = __sb_sbpl_parser_init_scheme_block_invoke;
    v221 = &__block_descriptor_tmp_22_3323;
    v222 = v62;
    LOBYTE(v235) = 0;
    v78 = &modifier_info;
    do
    {
      if ( *v78 )
      {
        (v220)(v219, *v78, v77, &v235);
        v76 = v235;
      }
      if ( v77 > 0x12 )
        break;
      ++v77;
      v78 += 4;
    }
    while ( (v76 & 1) == 0 );
    v228 = &OBJC_CLASS_____NSStackBlock__;
    v229 = 0x40000000LL;
    v230 = __sb_sbpl_parser_init_scheme_block_invoke_3;
    v231 = &__block_descriptor_tmp_27_3324;
    v232 = v62;
    v233 = v64;
    v79 = mk_foreign_block(v62, &v228);
    _define_symbol(v62, "with", v79);
    v80 = mk_foreign_func(v62, operation_expand);
    _define_symbol(v62, "operation-expand", v80);
    v81 = mk_foreign_func(v62, operations_allowed_by_default);
    _define_symbol(v62, "operations-allowed-by-default", v81);
    v82 = 0LL;
    v215[0] = &OBJC_CLASS_____NSStackBlock__;
    v215[1] = 0x40000000LL;
    v216 = __sb_sbpl_parser_init_scheme_block_invoke_4;
    v217 = &__block_descriptor_tmp_30_3328;
    v218 = v64;
    LOBYTE(v235) = 0;
    do
    {
      (v216)(v215, operation_names[v82], v82, &v235);
      if ( v235 )
        break;
      v65 = v82++ >= 0xC3;
    }
    while ( !v65 );
    v83 = 0;
    v84 = 0LL;
    v211[0] = &OBJC_CLASS_____NSStackBlock__;
    v211[1] = 0x40000000LL;
    v212 = __sb_sbpl_parser_init_scheme_block_invoke_5;
    v213 = &__block_descriptor_tmp_31_11;
    v214 = v64;
    LOBYTE(v235) = 0;
    v85 = &filter_info;
    do
    {
      if ( *v85 )
      {
        (v212)(v211, *v85, v84, &v235);
        v83 = v235;
      }
      if ( v84 > 0x5C )
        break;
      ++v84;
      v85 += 4;
    }
    while ( (v83 & 1) == 0 );
    define_combination_filter(v64, "require-all", sb_condition_conjunction);
    define_combination_filter(v64, "require-any", sb_condition_disjunction);
    v86 = *(v64 + 56);
    *&v235 = &OBJC_CLASS_____NSStackBlock__;
    *(&v235 + 1) = 0x40000000LL;
    *&v236 = __define_wrapper_filter_block_invoke;
    *(&v236 + 1) = &__block_descriptor_tmp_203_0;
    *&v237 = "require-not";
    *(&v237 + 1) = v64;
    *&v238 = sb_condition_negation;
    v87 = mk_foreign_block(v86, &v235);
    _define_symbol(v86, "require-not", v87);
    mk_foreign_func(v62, sbpl_enter_message_filter_context);
    _define_symbol(v62, "%sbpl-enter-message-filter-context", v184);
    mk_foreign_func(v62, sbpl_leave_message_filter_context);
    _define_symbol(v62, "%sbpl-leave-message-filter-context", v185);
    v210[0] = &OBJC_CLASS_____NSStackBlock__;
    v210[1] = 0x40000000LL;
    v210[2] = __sb_sbpl_parser_init_scheme_block_invoke_6;
    v210[3] = &__block_descriptor_tmp_38_3336;
    v210[4] = v191;
    v210[5] = v62;
    v88 = mk_foreign_block(v62, v210);
    _define_symbol(v62, "disable-callouts", v88);
    v209[0] = &OBJC_CLASS_____NSStackBlock__;
    v209[1] = 0x40000000LL;
    v209[2] = __sb_sbpl_parser_init_scheme_block_invoke_7;
    v209[3] = &__block_descriptor_tmp_40_3338;
    v209[4] = v191;
    v209[5] = v62;
    v89 = mk_foreign_block(v62, v209);
    _define_symbol(v62, "disable-full-symbolication", v89);
    v208[0] = &OBJC_CLASS_____NSStackBlock__;
    v208[1] = 0x40000000LL;
    v208[2] = __sb_sbpl_parser_init_scheme_block_invoke_8;
    v208[3] = &__block_descriptor_tmp_42_3340;
    v208[4] = v191;
    v208[5] = v62;
    mk_foreign_block(v62, v208);
    _define_symbol(v62, "%extends-protobox", v186);
    v90 = mk_foreign_func(v62, regex_quote);
    _define_symbol(v62, "regex-quote", v90);
    v91 = mk_foreign_func(v62, variable_quote);
    _define_symbol(v62, "variable-quote", v91);
    v207[0] = &OBJC_CLASS_____NSStackBlock__;
    v207[1] = 0x40000000LL;
    v207[2] = __sb_sbpl_parser_init_scheme_block_invoke_9;
    v207[3] = &__block_descriptor_tmp_48_3344;
    v207[4] = v62;
    v207[5] = v64;
    v92 = mk_foreign_block(v62, v207);
    _define_symbol(v62, "sbpl-filter?", v92);
    v206[0] = &OBJC_CLASS_____NSStackBlock__;
    v206[1] = 0x40000000LL;
    v206[2] = __sb_sbpl_parser_init_scheme_block_invoke_11;
    v206[3] = &__block_descriptor_tmp_51_15;
    v206[4] = v62;
    v206[5] = v64;
    v93 = mk_foreign_block(v62, v206);
    _define_symbol(v62, "sbpl-modifier?", v93);
    v205[0] = &OBJC_CLASS_____NSStackBlock__;
    v205[1] = 0x40000000LL;
    v205[2] = __sb_sbpl_parser_init_scheme_block_invoke_13;
    v205[3] = &__block_descriptor_tmp_54_3347;
    v205[4] = v62;
    v205[5] = v64;
    v94 = mk_foreign_block(v62, v205);
    _define_symbol(v62, "sbpl-operation?", v94);
    v204[0] = &OBJC_CLASS_____NSStackBlock__;
    v204[1] = 0x40000000LL;
    v204[2] = __sb_sbpl_parser_init_scheme_block_invoke_15;
    v204[3] = &__block_descriptor_tmp_57_6;
    v204[4] = v62;
    v204[5] = v64;
    v95 = mk_foreign_block(v62, v204);
    _define_symbol(v62, "sbpl-message-filter?", v95);
    v96 = mk_foreign_func(v62, sbpl_filter_eqv);
    _define_symbol(v62, "sbpl-filter-eqv?", v96);
    v97 = mk_foreign_func(v62, sbpl_filter_eqv);
    _define_symbol(v62, "sbpl-message-filter-eqv?", v97);
    v98 = mk_foreign_func(v62, sbpl_operation_eqv);
    _define_symbol(v62, "sbpl-operation-eqv?", v98);
    v203[0] = &OBJC_CLASS_____NSStackBlock__;
    v203[1] = 0x40000000LL;
    v203[2] = __sb_sbpl_parser_init_scheme_block_invoke_17;
    v203[3] = &__block_descriptor_tmp_62_3353;
    v203[4] = v64;
    v203[5] = v62;
    mk_foreign_block(v62, v203);
    _define_symbol(v62, "%sbpl-modifier-properties", v187);
    v202[0] = &OBJC_CLASS_____NSStackBlock__;
    v202[1] = 0x40000000LL;
    v202[2] = __sb_sbpl_parser_init_scheme_block_invoke_18;
    v202[3] = &__block_descriptor_tmp_64_8;
    v202[4] = v64;
    v99 = mk_foreign_block(v62, v202);
    _define_symbol(v62, "sbpl-operation-can-return?", v99);
    v201[0] = &OBJC_CLASS_____NSStackBlock__;
    v201[1] = 0x40000000LL;
    v201[2] = __sb_sbpl_parser_init_scheme_block_invoke_19;
    v201[3] = &__block_descriptor_tmp_67_9;
    v201[4] = v64;
    v100 = mk_foreign_block(v62, v201);
    _define_symbol(v62, "sbpl-version-compatible?", v100);
    v101 = mk_string(v62, "com.apple.sandbox.container");
    _define_symbol(v62, "*ios-sandbox-container*", v101);
    v102 = mk_string(v62, "com.apple.sandbox.application-group");
    _define_symbol(v62, "*ios-sandbox-application-group*", v102);
    v103 = mk_string(v62, "com.apple.sandbox.system-container");
    _define_symbol(v62, "*ios-sandbox-system-container*", v103);
    v104 = mk_string(v62, "com.apple.sandbox.system-group");
    _define_symbol(v62, "*ios-sandbox-system-group*", v104);
    v105 = mk_string(v62, "mac");
    _define_symbol(v62, "*target-platform*", v105);
    v106 = mk_string(v62, "/System/Library/Sandbox/Profiles");
    mk_string(v62, "/usr/share/sandbox");
    v188 = v106;
    _define_list(v62, "*default-import-search-paths*");
    v107 = mk_string(v62, "com.apple.sandbox.executable");
    _define_symbol(v62, "*sandbox-executable-bundle*", v107);
    v108 = 53LL;
    if ( (*(v64 + 12) & 2) == 0 )
      v108 = 59LL;
    _define_symbol(v62, "*apply-implicit-policy*", v62[v108]);
    v241 = 0u;
    v242 = 0u;
    v239 = 0u;
    v240 = 0u;
    v237 = 0u;
    v238 = 0u;
    v235 = 0u;
    v236 = 0u;
    v109 = v62[87];
    scheme_set_error_port_string(v62, &v235, &v243, "");
    if ( scheme_load_string(v62, init_scm, "<internal init prelude>")
      || scheme_load_string(v62, sbpl_scm, "<internal sbpl library>")
      || scheme_load_string(v62, policy_scm, "<implicit policy library>") )
    {
      v110 = *(v64 + 24);
      v111 = j__strspn_1(&v235, " -");
      sb_error_set_with_format(v110, &v194, "error loading standard libraries: %s", &v235 + v111);
      if ( !v194 )
        j____assert_rtn_18("sb_sbpl_parser_new", "sbpl_parser.c", 2566, "errorp == NULL || *errorp != NULL");
      if ( v200 )
      {
        v112 = &v200;
LABEL_95:
        sb_sbpl_parser_release(v112);
LABEL_146:
        sb_profile_release(&v198);
LABEL_147:
        if ( v47 )
          sb_pattern_varset_release(&v199);
        goto LABEL_149;
      }
LABEL_145:
      scheme_deinit(v62);
      j__free_34(v62);
      goto LABEL_146;
    }
    v62[87] = v109;
    v148 = *(v64 + 56);
    v149 = symname(*(v148 + 648));
    v223 = &OBJC_CLASS_____NSStackBlock__;
    v224 = 0x40000000LL;
    v225 = __define_error_handler_block_invoke;
    v226 = &__block_descriptor_tmp_229_1;
    v227 = v64;
    v150 = mk_foreign_block(v148, &v223);
    _define_symbol(v148, v149, v150);
    v151 = *(v64 + 56);
    v152 = mk_foreign_block(v151, &__block_literal_global_3380);
    _define_symbol(v151, "error", v152);
    v153 = *(v64 + 56);
    v223 = &OBJC_CLASS_____NSStackBlock__;
    v224 = 0x40000000LL;
    v225 = __define_on_open_handler_block_invoke;
    v226 = &__block_descriptor_tmp_254;
    v227 = v64;
    mk_foreign_block(v153, &v223);
    _define_symbol(v153, "%notify-file-open", v188);
    if ( v190 )
    {
      v154 = xpc2sc(v62, v190);
      _define_symbol(v62, "*params*", v154);
      if ( j__xpc_get_type_15(v190) == &OBJC_CLASS___OS_xpc_dictionary )
      {
        v155 = j__xpc_dictionary_get_value_11(v190, "entitlements");
        if ( v155 )
        {
          v156 = xpc2sc(v62, v155);
          _define_symbol(v62, "*entitlements*", v156);
        }
      }
    }
    else
    {
      _define_symbol(v62, "*params*", v62[47]);
    }
    v157 = v200;
    v197 = v200;
    if ( !v200 )
      goto LABEL_146;
    if ( v47 )
      sb_profile_set_pattern_variables(v193, v47);
    v192 = v157;
    if ( *(v19 + 1) )
    {
      v158 = 0LL;
      for ( i = 0LL; i < *(v19 + 1); ++i )
      {
        v160 = *(v19 + 1) + v158;
        v161 = *(*v160 + 24LL);
        j__fseeko_1(*(v160 + 8), *(v160 + 16), 0);
        v162 = *(v160 + 8);
        v157 = v192;
        if ( !v161 )
        {
          j__bzero_30(&v235, 0x400uLL);
          v163 = j__fileno_5(v162);
          if ( (v163 & 0x80000000) == 0 && !j__fcntl_13(v163, 50, &v235) )
          {
            v166 = j__strrchr_14(&v235, 47);
            if ( v166 )
              v165 = (v166 + 1);
            else
              v165 = &v235;
            v164 = v192;
            goto LABEL_182;
          }
          v161 = "<input file>";
        }
        v164 = v192;
        v165 = v161;
LABEL_182:
        if ( (_parse_file(v164, v165, v162, &v194) & 1) == 0 )
          goto LABEL_239;
        v158 += 48LL;
      }
    }
    if ( *(v157 + 10) )
    {
      v167 = *(v157 + 24);
      v168 = sb_error_new(v167, "parser already finalized", 0LL);
      v169 = *(v167 + 240);
      if ( v169 )
        (*(v169 + 16))(v169, v168);
      v194 = v168;
      goto LABEL_239;
    }
    v170 = *(v157 + 56);
    *(v157 + 112) = 0LL;
    v171 = scheme_global(v170, "%finalize", v189);
    scheme_call(v170, v171, *(v170 + 376));
    if ( *(v170 + 16) )
    {
      v194 = *(v157 + 112);
LABEL_239:
      v112 = &v197;
      goto LABEL_95;
    }
    *(v157 + 10) = 1;
    v172 = *(v19 + 3);
    v173 = *(v193 + 24);
    v228 = &OBJC_CLASS_____NSStackBlock__;
    v229 = 0x40000000LL;
    v230 = __sb_bytecode_output_profile_block_invoke;
    v231 = &__block_descriptor_tmp_100_7;
    v232 = v193;
    v233 = v172;
    v234 = &v194;
    j__bzero_30(&v236, 0xE90uLL);
    *&v235 = v173;
    *(&v235 + 1) = sb_mutable_buffer_new(v173, &v194);
    if ( !*(&v235 + 1) || (v247[0] = sb_condition_list_new(v173, &v194)) == 0 )
    {
      v176 = 0;
LABEL_218:
      if ( v236 )
        j__free_34(v236);
      v178 = v244;
      if ( v244 )
      {
        if ( !v245 )
          goto LABEL_225;
        v179 = 0LL;
        for ( j = 0LL; j < v245; ++j )
        {
          sb_buffer_release(&v244[v179]);
          v179 += 16LL;
        }
        v178 = v244;
        if ( v244 )
LABEL_225:
          j__free_34(v178);
        v245 = 0;
      }
      v181 = v249;
      if ( v249 )
      {
        v182 = &v248;
        do
        {
          v210[0] = *v182;
          *v182++ = 0LL;
          sb_buffer_release(v210);
          --v181;
        }
        while ( v181 );
      }
      if ( (v176 & 1) != 0 )
      {
        immutable = sb_mutable_buffer_make_immutable(&v235 + 8, &v194);
        if ( immutable )
        {
          v183 = *(v192 + 4);
          if ( v183 < *(v19 + 10) )
          {
            sb_error_set_with_format(
              *(v19 + 2),
              &v194,
              "SBPL version %u or greater is required (got version %u)",
              *(v19 + 10),
              v183);
            sb_buffer_release(&immutable);
          }
        }
      }
      else
      {
        if ( *(&v235 + 1) )
          sb_mutable_buffer_release(&v235 + 8);
        if ( v250 )
          v194 = v250;
        immutable = 0LL;
      }
      goto LABEL_239;
    }
    v174 = *(v173 + 28);
    if ( v174 )
    {
      v175 = j__calloc_26(*(v173 + 28), 0x18uLL);
      if ( !v175 )
      {
        v177 = *(v173 + 240);
        if ( v177 )
          (*(v177 + 16))(v177, &sb_error_out_of_memory_oom_error);
        v176 = 0;
        v194 = &sb_error_out_of_memory_oom_error;
        *&v236 = 0LL;
LABEL_217:
        sb_condition_list_release(v247);
        goto LABEL_218;
      }
      *&v236 = v175;
      *(&v236 + 1) = v174;
    }
    j__memset_24(&v246, 255, 0x400uLL);
    v176 = (v230)(&v228, &v235);
    if ( !v247[0] )
      goto LABEL_218;
    goto LABEL_217;
  }
  v114 = *(v48 + 240);
  if ( v114 )
    (*(v114 + 16))(v114, &sb_error_out_of_memory_oom_error);
  v194 = &sb_error_out_of_memory_oom_error;
LABEL_149:
  v137 = immutable;
  if ( !immutable )
    goto LABEL_107;
  *&v235 = immutable;
  if ( *immutable != 1 )
  {
    if ( !*immutable )
      j____assert_rtn_18("sb_buffer_convert_iovec", "buffer.c", 329, "buffer->refcnt > 0");
    v138 = *(immutable + 16);
    goto LABEL_154;
  }
  v138 = *(immutable + 16);
  if ( (v138 & 0x200000000000000LL) == 0 )
  {
LABEL_154:
    v139 = *(immutable + 8);
    v140 = j__malloc_34(v138 & 0xFFFFFFFFFFFFFFLL);
    if ( v140 )
    {
      v141 = v140;
      j__memcpy_31(v140, *(v137 + 24), v138 & 0xFFFFFFFFFFFFFFLL);
      v138 = *(v137 + 16);
      sb_buffer_release(&v235);
      goto LABEL_160;
    }
    v142 = *(v139 + 240);
    if ( v142 )
      (*(v142 + 16))(v142, &sb_error_out_of_memory_oom_error);
    v194 = &sb_error_out_of_memory_oom_error;
    sb_buffer_release(&v235);
LABEL_107:
    v25 = v194;
    if ( !v194 )
      goto LABEL_109;
    goto LABEL_108;
  }
  v141 = *(immutable + 24);
  *(immutable + 16) = v138 & 0xFDFFFFFFFFFFFFFFLL;
  sb_buffer_release(&v235);
  if ( !v141 )
    goto LABEL_107;
LABEL_160:
  v143 = j__malloc_34(0x18uLL);
  if ( !v143 )
  {
    j__free_34(v141);
    v14 = v195;
    v144 = v195[30];
    if ( v144 )
      (*(v144 + 16))(v144, &sb_error_out_of_memory_oom_error);
LABEL_14:
    v25 = &sb_error_out_of_memory_oom_error;
LABEL_15:
    v194 = &sb_error_out_of_memory_oom_error;
LABEL_108:
    j__asprintf_11(v2, "%s", *v25);
    v25 = 0LL;
    goto LABEL_109;
  }
  v25 = v143;
  *v143 = 0LL;
  v143[1] = v141;
  v143[2] = (v138 & 0xFFFFFFFFFFFFFFLL);
  if ( v194 )
    j____assert_rtn_18("compile", "compile.c", 137, "error == NULL");
LABEL_109:
  if ( _14 )
    j__xpc_release_14(_14);
  if ( v19 )
  {
    if ( !*v19 )
      j____assert_rtn_18("sb_program_release", "program.c", 175, "program->refcnt > 0");
    v115 = *v19 - 1;
    *v19 = v115;
    if ( !v115 )
    {
      sb_context_release(v19 + 16);
      for ( k = *(v19 + 1); k; *(v19 + 1) = k )
      {
        v117 = (k - 1);
        v118 = *(v19 + 1);
        v119 = (v118 + 48LL * v117);
        *&v235 = *v119;
        *v119 = 0LL;
        sb_buffer_release(&v235);
        v121 = v119[3];
        v120 = v119 + 3;
        if ( v121 )
          sb_buffer_release(v120);
        v122 = v118 + 48 * v117;
        v125 = *(v122 + 32);
        v123 = (v122 + 32);
        v124 = v125;
        if ( v125 )
        {
          *&v235 = v124;
          *v123 = 0LL;
          sb_buffer_release(&v235);
        }
        v126 = v118 + 48 * v117;
        v129 = *(v126 + 8);
        v128 = (v126 + 8);
        v127 = v129;
        if ( v129 )
        {
          j__funlockfile(v127);
          if ( *(v118 + 48 * v117 + 40) )
            j__fclose_16(*v128);
          *v128 = 0LL;
        }
        v130 = *(v19 + 1);
        if ( k != v130 )
        {
          j__memmove_25((*(v19 + 1) + 48 * v117), (*(v19 + 1) + 48 * v117 + 48), 48 * (v130 + ~v117));
          k = *(v19 + 1);
        }
        --k;
      }
      v131 = *(v19 + 1);
      if ( v131 )
        j__free_34(v131);
      if ( *(v19 + 3) )
        sb_condition_list_release(v19 + 24);
      v132 = *(v19 + 4);
      if ( v132 )
        j__xpc_release_14(v132);
      j__free_34(v19);
    }
  }
  if ( v14 )
    sb_context_release(&v195);
  return v25;
}