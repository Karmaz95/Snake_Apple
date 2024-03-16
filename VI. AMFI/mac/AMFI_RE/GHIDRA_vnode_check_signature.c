int _vnode_check_signature
          (vnode *vp,label *label,int cpu_type,cs_blob *cs_blob,uint *cs_flags,uint *signer_type,
          int flags,uint platform,char **fatal_failure_desc,ulong *fatal_failure_desc_len)

{
  uint uVar1;
  code *UNRECOVERED_JUMPTABLE;
  char cVar2;
  ipc_port *piVar3;
  bool bVar4;
  undefined uVar5;
  int iVar6;
  uint uVar11;
  uint uVar7;
  char ********ppppppppcVar12;
  char ********ppppppppcVar13;
  undefined8 uVar14;
  undefined8 uVar15;
  long lVar16;
  long *plVar17;
  long *plVar18;
  long *plVar19;
  long *plVar20;
  char ********ppppppppcVar21;
  int iVar8;
  int iVar9;
  uint uVar10;
  proc *ppVar22;
  ulong uVar23;
  char *pcVar24;
  uchar *puVar25;
  char *pcVar26;
  label *extraout_x1;
  undefined8 extraout_x1_00;
  undefined8 extraout_x1_01;
  undefined8 extraout_x1_02;
  undefined8 extraout_x1_03;
  undefined8 extraout_x1_04;
  undefined8 extraout_x1_05;
  undefined8 extraout_x1_06;
  undefined8 extraout_x1_07;
  undefined8 extraout_x1_08;
  undefined8 extraout_x1_09;
  undefined8 extraout_x1_10;
  undefined8 extraout_x1_11;
  undefined8 extraout_x1_12;
  undefined8 extraout_x1_13;
  undefined8 extraout_x1_14;
  undefined8 extraout_x1_15;
  undefined8 extraout_x1_16;
  undefined8 extraout_x1_17;
  undefined8 extraout_x1_18;
  undefined8 extraout_x1_19;
  undefined8 extraout_x1_20;
  undefined8 extraout_x1_21;
  undefined8 extraout_x1_22;
  undefined8 extraout_x1_23;
  undefined8 extraout_x1_24;
  label *extraout_x1_25;
  undefined8 extraout_x1_26;
  undefined8 extraout_x1_27;
  undefined8 extraout_x1_28;
  label *extraout_x1_29;
  label *plVar27;
  char ********ppppppppcVar28;
  ulong *puVar29;
  OSObject *pOVar30;
  ipc_port **ppiVar31;
  char *pcVar32;
  char ********ppppppppcVar33;
  char ********ppppppppcVar34;
  bool bVar35;
  uint uVar36;
  bool bVar37;
  char *******pppppppcVar38;
  cs_blob *pcVar39;
  char ********ppppppppcVar40;
  char ********ppppppppcVar41;
  char ********ppppppppcVar42;
  byte bVar43;
  char ********ppppppppcVar44;
  char ********ppppppppcVar45;
  char ********ppppppppcVar46;
  byte bVar47;
  char ********ppppppppcVar48;
  char ********ppppppppcVar49;
  undefined auVar50 [16];
  undefined auVar51 [16];
  char *in_stack_fffffffffffffd90;
  char ********in_stack_fffffffffffffd98;
  char ********local_208;
  char ********local_1f0;
  char ********local_1e8;
  undefined8 local_1e0;
  uint local_1d4;
  undefined8 local_1d0;
  ulong local_1c8;
  char ********local_1c0;
  uint local_1b4;
  char ********local_1b0;
  uint local_1a4;
  char ********local_1a0;
  char ********local_198;
  uint local_18c;
  undefined8 local_188;
  long *local_180;
  char ********local_178;
  long *local_170;
  char ********local_168;
  undefined local_15a [2];
  undefined8 local_158;
  char *******local_150;
  undefined local_148 [8];
  undefined local_140 [8];
  undefined8 local_138;
  char ********local_130;
  char ********ppppppppcStack_128;
  char *******local_120;
  undefined8 uStack_118;
  undefined8 local_108;
  char ********local_100;
  char ********ppppppppcStack_f8;
  char *******local_f0;
  undefined8 uStack_e8;
  undefined8 local_e0;
  undefined8 uStack_d8;
  undefined8 uStack_d0;
  undefined8 uStack_c8;
  long *local_c0;
  char ********local_b0;
  char ********ppppppppcStack_a8;
  char *******local_a0;
  undefined8 uStack_98;
  ipc_port *local_90;
  undefined8 uStack_88;
  undefined4 local_80;
  long local_78;
  
  ppppppppcVar46 = (char ********)(ulong)platform;
  ppppppppcVar42 = (char ********)(ulong)(uint)flags;
  local_78 = *(long *)PTR_DAT_fffffe0007e6ba68;
  ppppppppcVar33 = (char ********)cs_flags;
  ppppppppcVar34 = (char ********)signer_type;
  pcVar24 = (char *)ppppppppcVar46;
  if (*(int *)PTR_DAT_fffffe0007e6bae0 != 0) {
    in_stack_fffffffffffffd90 = (char *)ppppppppcVar46;
    func_0xfffffe0008c3c908("AMFI: vnode_check_signature called with platform %d\n");
    label = extraout_x1;
  }
  ppppppppcVar12 = (char ********)func_0xfffffe0008c3bd24(VnodeLazyPath::operator.new,label);
  ppppppppcVar41 = ppppppppcVar12 + 1;
  func_0xfffffe0008538b60(ppppppppcVar41,0x401);
  *ppppppppcVar12 = (char *******)&DAT_fffffe0007e75c28;
  ppppppppcVar12[0x82] = (char *******)vp;
  iVar6 = func_0xfffffe0008a49ecc(0x10);
  local_188 = (long *)CONCAT44(local_188._4_4_,cpu_type);
  if (iVar6 == 0) {
    local_100 = (char ********)0x0;
    ppppppppcVar33 = (char ********)&local_100;
    iVar6 = func_0xfffffe0008d8ef08(vp,"com.apple.root.installed",0,0);
    if ((iVar6 != 0x22) && (iVar6 != 0)) goto LAB_fffffe0009ac2498;
    if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
      uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
      *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
    }
    iVar6 = isVnodeQuarantined(vp);
    if (iVar6 != 0) {
      in_stack_fffffffffffffd90 = (char *)ppppppppcVar41;
      func_0xfffffe0008c3c908("com.apple.root.installed xattr disallowed on quarantined file: %s\n")
      ;
      goto LAB_fffffe0009ac2498;
    }
    in_stack_fffffffffffffd90 = (char *)ppppppppcVar41;
    func_0xfffffe0008c3c908("Allowing installed root as platform: %s\n");
    ppppppppcVar44 = (char ********)0x1;
  }
  else {
LAB_fffffe0009ac2498:
    ppppppppcVar44 = (char ********)0x0;
  }
  uVar7 = vnode_is_restricted(vp);
  uVar10 = (uint)ppppppppcVar44;
  ppppppppcVar21 = (char ********)cs_blob;
  local_180 = (long *)signer_type;
  if (platform == 2) {
    func_0xfffffe0008c3c908("Using iOS Platform policy\n");
    uVar7 = *cs_flags;
    ppppppppcVar46 = (char ********)(ulong)uVar7;
    *signer_type = 0;
    ppppppppcVar13 = (char ********)func_0xfffffe0008a47a1c(cs_blob);
    local_b0 = (char ********)0x0;
    local_90 = (ipc_port *)0x0;
    local_108 = (char ********)0x0;
    local_150 = (char *******)0x0;
    uVar14 = func_0xfffffe0008a4759c(cs_blob);
    uVar15 = func_0xfffffe0008a47590(cs_blob);
    ppppppppcVar28 = (char ********)0x0;
    pcVar32 = (char *)0xfade0c02;
    lVar16 = func_0xfffffe0008ad268c(uVar14,uVar15);
    uVar11 = *(uint *)(lVar16 + 8);
    plVar17 = (long *)func_0xfffffe0008a47c1c(cs_blob);
    local_198 = ppppppppcVar13;
    if (plVar17 != (long *)0x0) {
LAB_fffffe0009ac252c:
      local_100 = (char ********)((ulong)local_100 & 0xffffffff00000000);
      local_170 = plVar17;
      plVar18 = (long *)OSEntitlements::asDict();
      uVar11 = (uint)ppppppppcVar28;
      local_188 = plVar17;
      if (plVar18 != (long *)0x0) {
        plVar19 = (long *)func_0xfffffe0008bc6e1c();
        uVar11 = (uint)ppppppppcVar28;
        if (plVar19 != (long *)0x0) {
          local_1c8 = (ulong)uVar7;
          iVar6 = (**(code **)(*plVar18 + 0x150))(plVar18);
          uVar11 = (uint)ppppppppcVar28;
          if (iVar6 == 0) {
            local_18c = 0;
            pcVar39 = (cs_blob *)0x1;
            bVar35 = true;
            bVar4 = true;
          }
          else {
            plVar18 = (long *)(**(code **)(*plVar19 + 0x148))(plVar19);
            uVar11 = (uint)ppppppppcVar28;
            if (plVar18 == (long *)0x0) {
              local_18c = 0;
              pcVar39 = (cs_blob *)0x1;
              bVar4 = true;
              uVar36 = 0;
              iVar6 = 0;
            }
            else {
              local_1b0 = (char ********)fatal_failure_desc;
              local_18c = 0;
              local_1d4 = 0;
              local_1d0 = (long *)((ulong)local_1d0 & 0xffffffff00000000);
              uVar14 = *(undefined8 *)PTR_DAT_fffffe0007e6ba28;
              pcVar39 = (cs_blob *)0x1;
              do {
                plVar20 = (long *)func_0xfffffe0008bbdca0(plVar18,uVar14);
                if ((plVar20 == (long *)0x0) ||
                   (lVar16 = (**(code **)(*plVar20 + 0x168))(), lVar16 == 0)) {
                  (**(code **)(*plVar18 + 0x38))(plVar18);
                  in_stack_fffffffffffffd90 = (char *)func_0xfffffe0008bbe9f4();
                  func_0xfffffe0008c3c908("AMFI: skipping invalid entitlement of type \'%s\'\n");
                  pcVar39 = (cs_blob *)0x0;
                  local_18c = 1;
                }
                else {
                  *cs_flags = *cs_flags | 0x200;
                  iVar6 = func_0xfffffe00086abf28(lVar16,"get-task-allow");
                  if ((iVar6 == 0) &&
                     (iVar6 = OSEntitlementsHaveEntitlementBool
                                        ((OSEntitlements *)plVar17,"get-task-allow"), iVar6 != 0)) {
                    *cs_flags = *cs_flags | 4;
                  }
                  iVar6 = func_0xfffffe00086abf28(lVar16,"com.apple.private.oop-jit.loader");
                  if (iVar6 == 0) {
                    ppppppppcVar28 = (char ********)&local_100;
                    lVar16 = OSEntitlements::entitlementTypeFor
                                       ((OSEntitlements *)plVar17,"com.apple.private.oop-jit.loader"
                                        ,(CEType_t *)ppppppppcVar28);
                    if (lVar16 == 0x30000000e72a50) {
                      if ((int)local_100 != 4) {
                        pcVar32 = "OOP-JIT loader entitlement is an incorrect type";
LAB_fffffe0009ac40f0:
                        puVar29 = fatal_failure_desc_len;
                        fatal_error_fmt((LazyPath *)ppppppppcVar12,fatal_failure_desc,
                                        fatal_failure_desc_len,pcVar32);
                        uVar11 = (uint)puVar29;
                        bVar4 = false;
                        uVar36 = local_1d4;
                        local_1c0 = (char ********)cs_blob;
                        local_1b4 = uVar10;
                        iVar6 = (int)local_1d0;
                        goto LAB_fffffe0009ac3194;
                      }
                      local_1d0 = (long *)CONCAT44(local_1d0._4_4_,1);
                    }
                  }
                  else {
                    iVar6 = func_0xfffffe00086abf28(lVar16,"com.apple.private.oop-jit.runner");
                    if (iVar6 == 0) {
                      ppppppppcVar28 = (char ********)&local_100;
                      lVar16 = OSEntitlements::entitlementTypeFor
                                         ((OSEntitlements *)plVar17,
                                          "com.apple.private.oop-jit.runner",
                                          (CEType_t *)ppppppppcVar28);
                      if (lVar16 == 0x30000000e72a50) {
                        if (((int)local_100 != 4) && ((int)local_100 != 2)) {
                          pcVar32 = "OOP-JIT runner entitlement is an incorrect type";
                          goto LAB_fffffe0009ac40f0;
                        }
                        local_1d4 = 1;
                      }
                    }
                  }
                }
                plVar18 = (long *)(**(code **)(*plVar19 + 0x148))(plVar19);
                uVar11 = (uint)ppppppppcVar28;
              } while (plVar18 != (long *)0x0);
              bVar4 = true;
              uVar36 = local_1d4;
              local_1c0 = (char ********)cs_blob;
              local_1b4 = uVar10;
              iVar6 = (int)local_1d0;
            }
LAB_fffffe0009ac3194:
            bVar35 = iVar6 == 0 || uVar36 == 0;
          }
          (**(code **)(*plVar19 + 0x28))(plVar19);
          uVar36 = (uint)pcVar24;
          iVar6 = (int)ppppppppcVar42;
          if (!bVar35) {
            pcVar32 = "Cannot be both OOP-JIT loader and runner simultaneously";
            puVar29 = fatal_failure_desc_len;
            fatal_error_fmt((LazyPath *)ppppppppcVar12,fatal_failure_desc,fatal_failure_desc_len,
                            "Cannot be both OOP-JIT loader and runner simultaneously");
            uVar11 = (uint)puVar29;
            uVar14 = extraout_x1_04;
LAB_fffffe0009ac3210:
            ppppppppcVar40 = (char ********)0x0;
            ppppppppcVar46 = (char ********)(ulong)uVar7;
            fatal_failure_desc = (char **)ppppppppcVar44;
            local_1a4 = flags;
            goto LAB_fffffe0009ac4208;
          }
          uVar14 = extraout_x1_03;
          if (!bVar4) goto LAB_fffffe0009ac3210;
          ppppppppcVar44 = (char ********)0x4004000;
          local_1b0 = (char ********)fatal_failure_desc;
          goto LAB_fffffe0009ac2cc4;
        }
      }
      ppppppppcVar44 = (char ********)0x4004000;
LAB_fffffe0009ac2cc0:
      local_1b0 = (char ********)fatal_failure_desc;
      local_18c = 0;
      pcVar39 = (cs_blob *)0x1;
LAB_fffffe0009ac2cc4:
      uVar36 = (uint)pcVar24;
      iVar6 = (int)ppppppppcVar42;
      ppppppppcVar46 = (char ********)(ulong)uVar7;
      ppppppppcVar28 = (char ********)&local_100;
      if (ppppppppcVar13 == (char ********)0x0) {
        pcVar32 = "Internal Error: No cdhash found.";
      }
      else {
        iVar6 = _amfi_is_cdhash_in_trust_cache(ppppppppcVar13,1);
        ppppppppcVar45 = ppppppppcVar46;
        fatal_failure_desc = (char **)ppppppppcVar44;
        local_1b4 = uVar10;
        local_1a4 = flags;
        if (iVar6 == 0) goto LAB_fffffe0009ac2f60;
        *cs_flags = *cs_flags | (uint)ppppppppcVar44;
        setAndCheckValidationCategory(cs_blob,1,"trust-cache");
        if ((local_188 == (long *)0x0) || (lVar16 = OSEntitlements::asDict(), lVar16 == 0)) {
          pcVar32 = (char *)emptyDictionary()::empty;
          if (emptyDictionary()::empty == (char ********)0x0) {
            pcVar32 = (char *)func_0xfffffe0008bcc220(1);
            emptyDictionary()::empty = (char ********)pcVar32;
          }
        }
        else {
          pcVar32 = (char *)OSEntitlements::asDict();
        }
        uVar11 = *cs_flags;
        ppppppppcVar34 = (char ********)(ulong)(local_18c != 0);
        uVar36 = 0x74a2a3c;
        ppppppppcVar33 = (char ********)0x0;
        iVar6 = 2;
        in_stack_fffffffffffffd90 = (char *)local_1b0;
        in_stack_fffffffffffffd98 = (char ********)fatal_failure_desc_len;
        uVar7 = postValidation((LazyPath *)ppppppppcVar12,cs_blob,uVar11,(OSDictionary *)pcVar32,
                               '\0',local_18c != 0,2,"in-kernel",(char **)local_1b0,
                               fatal_failure_desc_len);
        uVar7 = uVar7 ^ 1;
        iVar9 = IsCDHashDenylisted((uchar *)ppppppppcVar13);
        if (iVar9 == 0) {
          ppppppppcVar42 = (char ********)0x0;
          ppppppppcVar40 = (char ********)0x0;
          fatal_failure_desc = (char **)0x1;
          uVar14 = extraout_x1_01;
          local_1f0 = (char ********)fatal_failure_desc_len;
          goto LAB_fffffe0009ac393c;
        }
        pcVar32 = "Bad things happened.";
      }
      puVar29 = fatal_failure_desc_len;
      fatal_error_fmt((LazyPath *)ppppppppcVar12,(char **)local_1b0,fatal_failure_desc_len,pcVar32);
      uVar11 = (uint)puVar29;
      ppppppppcVar40 = (char ********)0x0;
      uVar14 = extraout_x1_02;
      fatal_failure_desc = (char **)ppppppppcVar13;
      local_1b4 = uVar10;
      local_1a4 = flags;
      goto LAB_fffffe0009ac4208;
    }
    iVar9 = func_0xfffffe0008ad27ec(cs_blob,&local_b0,&local_90);
    uVar36 = (uint)pcVar24;
    iVar6 = (int)ppppppppcVar42;
    if (iVar9 == 0) {
      ppppppppcVar28 = &local_150;
      iVar9 = func_0xfffffe0008ad29a0(cs_blob,&local_108);
      ppppppppcVar40 = local_108;
      uVar36 = (uint)pcVar24;
      iVar6 = (int)ppppppppcVar42;
      if (iVar9 == 0) {
        if (((ulong)local_b0 | (ulong)local_108) == 0) {
LAB_fffffe0009ac32a0:
          pcVar26 = (char *)func_0xfffffe0008a479c4(cs_blob);
          plVar18 = (long *)OSEntitlements::makeInvalid(pcVar26);
        }
        else {
          uVar11 = (uVar11 & 0xff00ff00) >> 8 | (uVar11 & 0xff00ff) << 8;
          if ((0x203ff < (uVar11 >> 0x10 | uVar11 << 0x10)) && ((*(byte *)(lVar16 + 0x57) & 1) == 0)
             ) {
            if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
              uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
              *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
            }
            pcVar26 = "AMFI: constraint violation %s has entitlements but is not a main binary\n";
            in_stack_fffffffffffffd90 = (char *)ppppppppcVar41;
LAB_fffffe0009ac329c:
            func_0xfffffe0008c3c908(pcVar26);
            goto LAB_fffffe0009ac32a0;
          }
          if (local_108 == (char ********)0x0) {
            ppppppppcVar28 = &local_150;
            iVar9 = transmuteEntitlementsInDaemon
                              (cs_blob,(uchar **)&local_108,(ulong *)ppppppppcVar28);
            uVar36 = (uint)pcVar24;
            iVar6 = (int)ppppppppcVar42;
            if (iVar9 == 0) {
              in_stack_fffffffffffffd90 =
                   "entitlement validation failed, binary has XML entitlements but no DER slot is pr esent."
              ;
              goto LAB_fffffe0009ac2ea0;
            }
            if (local_108 == (char ********)0x0) {
              if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
                uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
                *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
              }
              in_stack_fffffffffffffd90 = (char *)ppppppppcVar41;
              func_0xfffffe0008c3c908
                        (
                        "Transmutation failed, but we will continue without attaching entitlements f or %s\n"
                        );
              func_0xfffffe0008c3c908("**** THIS IS A SERIOUS ISSUE ****\n");
              pcVar26 = "If you require entitlements you must resign your binary with DER\n";
              goto LAB_fffffe0009ac329c;
            }
            if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
              uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
              *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
            }
            in_stack_fffffffffffffd90 = (char *)ppppppppcVar41;
            func_0xfffffe0008c3c908
                      (
                      "AMFI: %s doesn\'t have DER entitlements and will not work in a future release \n"
                      );
          }
          else if (local_150 < &DAT_00000008) {
            in_stack_fffffffffffffd90 = "entitlements too small";
            goto LAB_fffffe0009ac2ea0;
          }
          uVar36 = (uint)pcVar24;
          iVar6 = (int)ppppppppcVar42;
          pppppppcVar38 = local_150 + -1;
          if ((char *******)0x20000 < pppppppcVar38) {
            in_stack_fffffffffffffd90 = "entitlements too large";
            local_150 = pppppppcVar38;
            local_108 = local_108 + 1;
            goto LAB_fffffe0009ac2ea0;
          }
          local_100 = (char ********)0x0;
          ppppppppcStack_f8 = (char ********)0x0;
          local_f0 = (char *******)0x0;
          pcVar32 = (char *)((long)local_108 + (long)local_150);
          local_150 = pppppppcVar38;
          local_108 = local_108 + 1;
          lVar16 = _CEValidate(0x10000000e70228,&local_100);
          uVar36 = (uint)pcVar24;
          iVar6 = (int)ppppppppcVar42;
          if (lVar16 != 0x30000000e72a50) {
            in_stack_fffffffffffffd90 = "failed parsing DER entitlements";
            goto LAB_fffffe0009ac2ea0;
          }
          ppppppppcVar28 = (char ********)(ulong)(ppppppppcVar40 == (char ********)0x0);
          ppppppppcStack_128 = ppppppppcStack_f8;
          local_130 = local_100;
          local_120 = local_f0;
          plVar18 = (long *)OSEntitlements::withValidationResult
                                      ((CEValidationResult)&local_130,cs_blob,
                                       ppppppppcVar40 == (char ********)0x0);
        }
        func_0xfffffe00085a8e38(_driverLock);
        plVar17 = (long *)func_0xfffffe0008a47c1c(cs_blob);
        if (plVar17 == (long *)0x0) {
          func_0xfffffe0008a47ba8(cs_blob,plVar18);
          plVar17 = plVar18;
        }
        else if (plVar18 != (long *)0x0) {
          (**(code **)(*plVar18 + 0x28))(plVar18);
        }
        func_0xfffffe00085aa2e4(_driverLock);
        uVar11 = (uint)ppppppppcVar28;
        if (plVar17 != (long *)0x0) goto LAB_fffffe0009ac252c;
        local_188 = (long *)0x0;
        ppppppppcVar44 = (char ********)0x4000000;
        local_170 = plVar17;
        goto LAB_fffffe0009ac2cc0;
      }
      in_stack_fffffffffffffd90 = "failed getting DER entitlements";
      pcVar24 = "Error getting DER\n";
    }
    else {
      in_stack_fffffffffffffd90 = "failed getting entitlements";
      pcVar24 = "Error getting XML\n";
    }
    func_0xfffffe0008c3c908(pcVar24);
    ppppppppcVar40 = ppppppppcVar41;
LAB_fffffe0009ac2ea0:
    local_170 = (long *)0x0;
    pcVar32 = 
    "The signature could not be validated because AMFI could not load its entitlements for validatio n: %s"
    ;
    puVar29 = fatal_failure_desc_len;
    auVar51 = fatal_error_fmt((LazyPath *)ppppppppcVar12,fatal_failure_desc,fatal_failure_desc_len,
                              "The signature could not be validated because AMFI could not load its entitlements for validation: %s"
                             );
    uVar11 = (uint)puVar29;
    ppppppppcVar28 = (char ********)0x1;
    local_1a4 = flags;
    goto LAB_fffffe0009ac4248;
  }
  uVar36 = *cs_flags;
  *signer_type = 0;
  puVar25 = (uchar *)func_0xfffffe0008a47a1c(cs_blob);
  local_178 = (char ********)0x0;
  local_170 = (long *)0x0;
  pcVar32 = (char *)&local_178;
  ppppppppcVar40 = ppppppppcVar12;
  uVar23 = StaticPlatformPolicy<>::loadEntitlementsFromSignature
                     ((OSEntitlements **)&local_170,cs_blob,(LazyPath *)ppppppppcVar12,
                      (char **)pcVar32);
  plVar17 = local_170;
  local_1d4 = uVar7;
  if ((uVar23 & 1) == 0) {
    pcVar32 = 
    "The signature could not be validated because AMFI could not load its entitlements for validatio n: %s"
    ;
    local_1a0 = local_178;
    goto LAB_fffffe0009ac2ef0;
  }
  local_198 = (char ********)(ulong)uVar36;
  local_1d0 = local_170;
  ppppppppcVar49 = (char ********)fatal_failure_desc;
  if (local_170 != (long *)0x0) {
    local_100 = (char ********)((ulong)local_100 & 0xffffffff00000000);
    plVar18 = (long *)OSEntitlements::asDict();
    if ((plVar18 == (long *)0x0) ||
       (ppppppppcVar21 = (char ********)func_0xfffffe0008bc6e1c(),
       ppppppppcVar21 == (char ********)0x0)) {
      local_18c = 0;
      uVar7 = 0;
      local_1c8 = 1;
      goto LAB_fffffe0009ac2dac;
    }
    iVar6 = (**(code **)(*plVar18 + 0x150))(plVar18);
    if (iVar6 == 0) {
      local_18c = 0;
      local_1c8 = 1;
      bVar35 = true;
      bVar4 = true;
    }
    else {
      plVar18 = (long *)(*(code *)(*ppppppppcVar21)[0x29])(ppppppppcVar21);
      if (plVar18 == (long *)0x0) {
        local_18c = 0;
        bVar35 = false;
        bVar37 = false;
        local_1c8 = 1;
        bVar4 = true;
      }
      else {
        local_18c = 0;
        bVar37 = false;
        bVar35 = false;
        local_1e0 = (undefined8 *)((ulong)local_1e0 & 0xffffffff00000000);
        bVar43 = 0;
        uVar7 = 0;
        bVar47 = 0;
        uVar14 = *(undefined8 *)PTR_DAT_fffffe0007e6ba28;
        local_1c8 = 1;
        do {
          plVar19 = (long *)func_0xfffffe0008bbdca0(plVar18,uVar14);
          if ((plVar19 == (long *)0x0) || (lVar16 = (**(code **)(*plVar19 + 0x168))(), lVar16 == 0))
          {
            (**(code **)(*plVar18 + 0x38))(plVar18);
            in_stack_fffffffffffffd90 = (char *)func_0xfffffe0008bbe9f4();
            func_0xfffffe0008c3c908("AMFI: skipping invalid entitlement of type \'%s\'\n");
            local_1c8 = 0;
            local_18c = 1;
            goto LAB_fffffe0009ac2974;
          }
          uVar23 = _matchIn(&_softRestrictedEntitlements,lVar16);
          if ((uVar23 & 1) == 0) {
            uVar23 = _matchIn(&_appSandboxEntitlements,lVar16);
            if ((uVar23 & 1) != 0) {
              uVar11 = 0x200;
LAB_fffffe0009ac29c8:
              *cs_flags = *cs_flags | uVar11;
              goto LAB_fffffe0009ac29e0;
            }
            uVar23 = _matchIn(&_unrestrictedEntitlements,lVar16);
            if ((uVar23 & 1) != 0) goto LAB_fffffe0009ac29e0;
            iVar6 = func_0xfffffe0008a49ecc(2);
            if ((iVar6 != 0) ||
               ((iVar6 = func_0xfffffe00086abf28("jit-codesigning",lVar16), iVar6 != 0 &&
                (iVar6 = func_0xfffffe00086abf28("com.apple.rootless.storage.cvms",lVar16),
                iVar6 != 0)))) {
              *cs_flags = *cs_flags | 0x200;
              uVar23 = _matchIn(&_restrictionExemptEntitlements,lVar16);
              if ((uVar23 & 1) == 0) {
                *cs_flags = *cs_flags | 0x800;
              }
              iVar6 = func_0xfffffe0008a49ecc(1);
              if ((iVar6 != 0) ||
                 (uVar23 = _matchIn(&_unrestrictedWhenSIPisOff,lVar16), (uVar23 & 1) == 0)) {
                iVar6 = ConfigurationSettings::enforceTCCEntitlementHardening();
                if (iVar6 == 0) {
                  local_1c8 = 0;
                  goto LAB_fffffe0009ac2918;
                }
                iVar6 = _matchIn(&_forceRuntimeAndLVEntitlements,lVar16);
                local_1c8 = 0;
                local_18c = 1;
                if (iVar6 != 0) {
                  uVar11 = 0x12000;
                  goto LAB_fffffe0009ac29c8;
                }
                goto LAB_fffffe0009ac29e0;
              }
            }
          }
          else {
LAB_fffffe0009ac2918:
            local_18c = 1;
LAB_fffffe0009ac29e0:
            iVar6 = func_0xfffffe00086abf28(lVar16,"com.apple.security.get-task-allow");
            if ((iVar6 == 0) &&
               (iVar6 = OSEntitlementsHaveEntitlementBool
                                  ((OSEntitlements *)plVar17,"com.apple.security.get-task-allow"),
               iVar6 != 0)) {
              *cs_flags = *cs_flags | 4;
            }
            iVar6 = _matchIn(&_systemExtensionEntitlements,lVar16);
            if (iVar6 != 0) {
              uVar11 = _matchIn(&_systemExtensionEntitlementsThatAllowJit,lVar16);
              uVar7 = uVar11 ^ 1 | uVar7;
              bVar47 = 1;
            }
            iVar6 = _matchIn(&_hardenedRuntimeEntitlements,lVar16);
            if (iVar6 != 0) {
              uVar11 = _matchIn(&_hardenedRuntimeJITEntitlement,lVar16);
              local_1e0 = (undefined8 *)CONCAT44(local_1e0._4_4_,uVar11 ^ 1 | (uint)local_1e0);
              bVar43 = 1;
            }
            if (((bool)(bVar47 & bVar43)) && (((uVar7 | (uint)local_1e0) & 1) != 0)) {
              pcVar32 = "Hardened Runtime relaxation entitlements disallowed on System Extensions";
LAB_fffffe0009ac366c:
              ppppppppcVar40 = (char ********)fatal_failure_desc_len;
              fatal_error_fmt((LazyPath *)ppppppppcVar12,fatal_failure_desc,fatal_failure_desc_len,
                              pcVar32);
              bVar4 = false;
              goto LAB_fffffe0009ac368c;
            }
            iVar6 = func_0xfffffe00086abf28(lVar16,"com.apple.private.oop-jit.loader");
            if (iVar6 == 0) {
              ppppppppcVar40 = (char ********)&local_100;
              lVar16 = OSEntitlements::entitlementTypeFor
                                 ((OSEntitlements *)plVar17,"com.apple.private.oop-jit.loader",
                                  (CEType_t *)ppppppppcVar40);
              if (lVar16 == 0x30000000e72a50) {
                if ((int)local_100 != 4) {
                  pcVar32 = "OOP-JIT loader entitlement is an incorrect type";
                  goto LAB_fffffe0009ac366c;
                }
                bVar35 = true;
              }
            }
            else {
              iVar6 = func_0xfffffe00086abf28(lVar16,"com.apple.private.oop-jit.runner");
              if (iVar6 == 0) {
                ppppppppcVar40 = (char ********)&local_100;
                lVar16 = OSEntitlements::entitlementTypeFor
                                   ((OSEntitlements *)plVar17,"com.apple.private.oop-jit.runner",
                                    (CEType_t *)ppppppppcVar40);
                if (lVar16 == 0x30000000e72a50) {
                  if (((int)local_100 != 4) && ((int)local_100 != 2)) {
                    pcVar32 = "OOP-JIT runner entitlement is an incorrect type";
                    goto LAB_fffffe0009ac366c;
                  }
                  bVar37 = true;
                }
              }
            }
          }
LAB_fffffe0009ac2974:
          plVar18 = (long *)(*(code *)(*ppppppppcVar21)[0x29])(ppppppppcVar21);
        } while (plVar18 != (long *)0x0);
        bVar4 = true;
LAB_fffffe0009ac368c:
        local_1b0 = (char ********)fatal_failure_desc;
        local_1f0 = (char ********)fatal_failure_desc_len;
        local_1e8 = (char ********)cs_flags;
        local_1b4 = uVar10;
      }
      bVar35 = !bVar35 || !bVar37;
    }
    (*(code *)(*ppppppppcVar21)[5])(ppppppppcVar21);
    if (bVar35) {
      uVar14 = extraout_x1_07;
      if (!bVar4) goto LAB_fffffe0009ac3708;
      uVar7 = (uint)(local_18c != 0) << 0xe;
      goto LAB_fffffe0009ac2dac;
    }
    pcVar32 = "Cannot be both OOP-JIT loader and runner simultaneously";
LAB_fffffe0009ac36f8:
    ppppppppcVar40 = (char ********)fatal_failure_desc_len;
    fatal_error_fmt((LazyPath *)ppppppppcVar12,fatal_failure_desc,fatal_failure_desc_len,pcVar32);
    uVar14 = extraout_x1_08;
LAB_fffffe0009ac3708:
    ppppppppcVar41 = (char ********)0x0;
    ppppppppcVar13 = ppppppppcVar44;
    ppppppppcVar48 = (char ********)fatal_failure_desc_len;
    local_1a0 = (char ********)in_stack_fffffffffffffd90;
    local_1c0 = (char ********)cs_blob;
    local_1a4 = flags;
    goto LAB_fffffe0009ac4084;
  }
  local_18c = 0;
  uVar7 = 0;
  local_1c8 = 1;
LAB_fffffe0009ac2dac:
  uVar14 = func_0xfffffe0008a4759c(cs_blob);
  uVar15 = func_0xfffffe0008a47590(cs_blob);
  uVar11 = 0;
  pcVar32 = (char *)0xfade0c02;
  ppppppppcVar21 = (char ********)func_0xfffffe0008ad268c(uVar14,uVar15);
  if (ppppppppcVar21 == (char ********)0x0) {
    ppppppppcVar28 = (char ********)0x0;
  }
  else {
    uVar1 = *(uint *)((long)ppppppppcVar21 + 4);
    ppppppppcVar28 = (char ********)(ulong)uVar1;
    uVar1 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
    pcVar39 = (cs_blob *)(ulong)uVar36;
    if (7 < (uVar1 >> 0x10 | uVar1 << 0x10)) {
      if (puVar25 == (uchar *)0x0) {
        pcVar32 = "Internal Error: No cdhash found.";
        ppppppppcVar41 = (char ********)0x0;
        local_1c0 = (char ********)cs_blob;
        local_1b4 = uVar10;
        local_1a4 = flags;
        goto LAB_fffffe0009ac40cc;
      }
      bVar43 = *(byte *)((long)ppppppppcVar21 + 0x26);
      ppppppppcVar13 = (char ********)(ulong)bVar43;
      iVar6 = _amfi_is_cdhash_in_trust_cache(puVar25,1);
      if (iVar6 != 0) {
        *cs_flags = uVar7 | *cs_flags | 0x4000000;
        setAndCheckValidationCategory(cs_blob,1,"trust-cache");
        if ((plVar17 == (long *)0x0) || (lVar16 = OSEntitlements::asDict(), lVar16 == 0)) {
          pcVar32 = (char *)emptyDictionary()::empty;
          if (emptyDictionary()::empty == (char ********)0x0) {
            pcVar32 = (char *)func_0xfffffe0008bcc220(plVar17,1);
            emptyDictionary()::empty = (char ********)pcVar32;
          }
        }
        else {
          pcVar32 = (char *)OSEntitlements::asDict();
        }
        ppppppppcVar40 = (char ********)(ulong)*cs_flags;
        ppppppppcVar34 = (char ********)(ulong)(local_18c != 0);
        pcVar24 = "in-kernel";
        ppppppppcVar33 = ppppppppcVar13;
        ppppppppcVar42 = ppppppppcVar46;
        in_stack_fffffffffffffd90 = (char *)fatal_failure_desc;
        in_stack_fffffffffffffd98 = (char ********)fatal_failure_desc_len;
        uVar7 = postValidation((LazyPath *)ppppppppcVar12,cs_blob,*cs_flags,(OSDictionary *)pcVar32,
                               bVar43,local_18c != 0,platform,"in-kernel",fatal_failure_desc,
                               fatal_failure_desc_len);
        uVar7 = uVar7 ^ 1;
        iVar6 = IsCDHashDenylisted(puVar25);
        if (iVar6 == 0) {
          ppppppppcVar28 = (char ********)0x0;
          ppppppppcVar41 = (char ********)0x0;
          ppppppppcVar44 = (char ********)0x1;
          uVar14 = extraout_x1_06;
          local_1c0 = (char ********)cs_blob;
          local_1b4 = uVar10;
          local_1a4 = flags;
          goto LAB_fffffe0009ac407c;
        }
        pcVar32 = "Bad things happened.";
        ppppppppcVar44 = ppppppppcVar13;
        ppppppppcVar21 = (char ********)cs_blob;
        local_1b4 = uVar10;
        goto LAB_fffffe0009ac36f8;
      }
      iVar9 = _codeDirectoryHashInCompilationServiceHash(puVar25);
      iVar6 = (int)ppppppppcVar42;
      if (iVar9 != 0) {
        iVar9 = noEntitlementsPresent(cs_blob);
        iVar6 = (int)ppppppppcVar42;
        if (iVar9 != 0) {
          if (plVar17 == (long *)0x0) {
LAB_fffffe0009ac3bc4:
            setAndCheckValidationCategory(cs_blob,10,"compilation-service");
            local_100 = (char ********)((ulong)local_100 & 0xffffffffffffff00);
            ppVar22 = (proc *)func_0xfffffe0008bbbe74();
            ppppppppcVar40 = (char ********)&local_100;
            AppleMobileFileIntegrity::AMFIEntitlementGetBool
                      (ppVar22,"com.apple.private.amfi.can-execute-cdhash",(bool *)ppppppppcVar40);
            if ((char)local_100 == '\0') {
              func_0xfffffe0008c3c908("AMFI: can-execute-cdhash code in non-entitled context.\n");
              uVar7 = 1;
              uVar14 = extraout_x1_20;
            }
            else {
              uVar7 = *cs_flags;
              ppppppppcVar40 = (char ********)(ulong)uVar7;
              if (emptyDictionary()::empty == (char ********)0x0) {
                emptyDictionary()::empty = (char ********)func_0xfffffe0008bcc220(1);
              }
              ppppppppcVar34 = (char ********)(ulong)(local_18c != 0);
              pcVar24 = "can-execute-cdhash";
              pcVar32 = (char *)emptyDictionary()::empty;
              ppppppppcVar42 = ppppppppcVar46;
              in_stack_fffffffffffffd90 = (char *)fatal_failure_desc;
              in_stack_fffffffffffffd98 = (char ********)fatal_failure_desc_len;
              uVar7 = postValidation((LazyPath *)ppppppppcVar12,cs_blob,uVar7,
                                     (OSDictionary *)emptyDictionary()::empty,bVar43,local_18c != 0,
                                     platform,"can-execute-cdhash",fatal_failure_desc,
                                     fatal_failure_desc_len);
              uVar7 = uVar7 ^ 1;
              uVar14 = extraout_x1_14;
              ppppppppcVar33 = ppppppppcVar13;
            }
            ppppppppcVar28 = (char ********)0x0;
            ppppppppcVar41 = (char ********)0x0;
            local_1c0 = (char ********)cs_blob;
            local_1b4 = uVar10;
            local_1a4 = flags;
            goto LAB_fffffe0009ac407c;
          }
          lVar16 = OSEntitlements::asDict();
          iVar6 = (int)ppppppppcVar42;
          if (lVar16 == 0) goto LAB_fffffe0009ac3bc4;
        }
      }
      ppppppppcVar40 =
           (char ********)
           func_0xfffffe0008c3bd24
                     (&StaticPlatformPolicy<>::
                       check_signature(LazyPath*,int,cs_blob*,unsigned_int*,unsigned_int*,int,bool,b ool,unsigned_int,char**,unsigned_long*)
                       ::kalloc_type_view_2630);
      local_15a = (undefined  [2])0x0;
      local_168 = (char ********)0x0;
      auVar51 = func_0xfffffe0008a47a1c(cs_blob);
      uVar36 = (uint)pcVar24;
      local_1e0 = auVar51._0_8_;
      if (local_1e0 == (undefined8 *)0x0) {
        _vnode_check_signature
                  ((vnode *)0x0,auVar51._8_8_,uVar11,(cs_blob *)pcVar32,(uint *)ppppppppcVar33,
                   (uint *)ppppppppcVar34,iVar6,uVar36,(char **)in_stack_fffffffffffffd90,
                   (ulong *)in_stack_fffffffffffffd98);
        local_1c0 = (char ********)cs_blob;
        local_1b4 = uVar10;
        local_1a4 = flags;
        goto LAB_fffffe0009ac5370;
      }
      local_f0 = (char *******)0x0;
      uStack_e8 = 0;
      uStack_d8 = 0;
      local_e0 = 0;
      uStack_c8 = 0;
      uStack_d0 = 0;
      local_c0 = plVar17;
      local_1b0 = (char ********)fatal_failure_desc;
      ppppppppcStack_f8 = (char ********)cs_blob;
      if ((flags & 1U) == 0) {
        local_100 = ppppppppcVar12;
        iVar6 = _codeDirectoryHashIsInJitHashCache((uchar *)local_1e0);
        if ((iVar6 != 0) && (iVar6 = noEntitlementsPresent(cs_blob), iVar6 != 0)) {
          *cs_flags = *cs_flags | 0x4004000;
          pcVar24 = "jit-hash-cache";
          local_1c0 = (char ********)cs_blob;
          local_1b4 = uVar10;
          local_1a4 = flags;
          goto LAB_fffffe0009ac3acc;
        }
      }
      else {
        local_100 = ppppppppcVar12;
        func_0xfffffe00085a8e38(dyldSimCacheLock);
        iVar6 = func_0xfffffe000853b798(local_1e0,&dyldSimCache,0x14);
        func_0xfffffe00085aa2e4(dyldSimCacheLock);
        if (iVar6 == 0) {
          uVar7 = 0x4004200;
          if (local_18c == 0) {
            uVar7 = 0x4004000;
          }
          *cs_flags = *cs_flags | uVar7;
          pcVar24 = "dyld_sim_cache";
          local_1c0 = (char ********)cs_blob;
          local_1b4 = uVar10;
          local_1a4 = flags;
          goto LAB_fffffe0009ac3acc;
        }
      }
      if (ppppppppcVar12 == (char ********)0x0) {
        ppppppppcVar44 = (char ********)0x0;
      }
      else {
        ppppppppcVar44 = ppppppppcVar41;
        if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
          uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
          *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
        }
      }
      ppppppppcVar45 = (char ********)"<null>";
      if (ppppppppcVar44 != (char ********)0x0) {
        ppppppppcVar45 = ppppppppcVar44;
      }
      if (((flags & 1U) == 0) && (uVar10 == 1)) {
        *cs_flags = *cs_flags | 0x4004000;
        pcVar24 = "platform-override";
        local_1c0 = (char ********)cs_blob;
        local_1b4 = uVar10;
        local_1a4 = flags;
        goto LAB_fffffe0009ac3acc;
      }
      uVar7 = (uint)bVar43;
      ppppppppcVar33 = (char ********)&local_168;
      ppppppppcVar34 = (char ********)(local_15a + 1);
      ppppppppcVar42 = (char ********)&local_100;
      _validateCoreTrust(cs_blob,(uchar *)local_1e0,(char *)ppppppppcVar45,(bool *)local_15a,
                         (ulonglong *)ppppppppcVar33,(bool *)ppppppppcVar34,
                         (ProfileValidationData *)ppppppppcVar42);
      local_1a0 = ppppppppcVar41;
      if (local_15a[0] == false) {
        in_stack_fffffffffffffd90 = (char *)ppppppppcVar45;
        func_0xfffffe0008c3c908("AMFI: \'%s\': Unrecoverable CT signature issue, bailing out.\n");
        uVar7 = 0;
        if (local_18c != 0 && (uint)local_1c8 == 0) {
          uVar7 = 2;
        }
        goto LAB_fffffe0009ac492c;
      }
      uVar11 = func_0xfffffe0008a478bc(cs_blob);
      if ((uVar11 >> 1 & 1) == 0) {
        iVar6 = 0;
      }
      else {
        iVar6 = _checkForOOPJit(cs_blob);
      }
      ppppppppcVar13 = (char ********)(ulong)uVar7;
      uVar23 = 0x100008;
      if (_readyToRoll != '\0') {
        uVar23 = 0x100000;
      }
      if ((flags & 1U) != 0) {
        lVar16 = func_0xfffffe0008a479c4(cs_blob);
        local_208 = local_168;
        if (((((ulong)local_168 & uVar23) != 0) && (lVar16 != 0)) &&
           (iVar6 = func_0xfffffe00086abf28(lVar16,"com.apple.dyld_sim"),
           local_1c0 = (char ********)cs_blob, local_1b4 = uVar10, local_1a4 = flags, iVar6 == 0))
        goto LAB_fffffe0009ac44e4;
        func_0xfffffe0008a49ecc(0x10);
LAB_fffffe0009ac3ec0:
        if (ppppppppcVar44 != (char ********)0x0) {
          if ((((flags & 1U) == 0) && (local_18c == 0)) &&
             (iVar6 = isAppleMagicDirectory((char *)ppppppppcVar44), iVar6 != 0)) {
            if (*(int *)PTR_DAT_fffffe0007e6bae0 != 0) {
              func_0xfffffe0008c3c908("AMFI: file %s matched magic path\n");
            }
            *cs_flags = *cs_flags | 0xc000000;
            pcVar24 = "magic-path";
            local_1c0 = (char ********)cs_blob;
            local_1b4 = uVar10;
            local_1a4 = flags;
            goto LAB_fffffe0009ac3acc;
          }
          *cs_flags = *cs_flags & 0xf3ffbfff;
          local_108 = (char ********)0x0;
          iVar6 = getDaemonPort((ipc_port **)&local_108);
          if (iVar6 != 0) {
            pcVar32 = "StaticPlatformPolicy<%d>: no registered daemon port\n";
            local_1c0 = (char ********)cs_blob;
            local_1b4 = uVar10;
            local_1a4 = flags;
            goto LAB_fffffe0009ac4620;
          }
          ppppppppcStack_128 = (char ********)0x0;
          local_130 = (char ********)0x0;
          uStack_118 = 0;
          local_120 = (char *******)0x0;
          local_140 = (undefined  [8])0x0;
          local_138 = (char *******)0x0;
          local_148 = (undefined  [8])0x0;
          local_90 = (ipc_port *)0x0;
          uStack_88 = 0;
          local_80 = 0;
          puVar25 = (uchar *)func_0xfffffe0008a47a1c(cs_blob);
          if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
            uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
            *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
          }
          ppppppppcVar28 = local_108;
          ppppppppcVar33 = (char ********)(ulong)(local_18c != 0);
          local_158 = 0;
          local_150 = (char *******)0x0;
          uVar14 = func_0xfffffe0008a47584(cs_blob);
          in_stack_fffffffffffffd98 = (char ********)local_140;
          in_stack_fffffffffffffd90 = local_140 + 4;
          pcVar24 = local_148 + 4;
          pcVar39 = (cs_blob *)(ulong)(uint)flags;
          ppppppppcVar34 = (char ********)(ulong)((uint)local_1c8 != 0);
          ppppppppcVar42 = (char ********)0x1;
          ppppppppcVar28 =
               (char ********)_verify_code_directory(ppppppppcVar28,ppppppppcVar41,uVar14);
          if (0x13 < *(int *)PTR_DAT_fffffe0007e6bae0) {
            in_stack_fffffffffffffd90 = "(restricted entitlements)";
            if (local_18c == 0) {
              in_stack_fffffffffffffd90 = "";
            }
            in_stack_fffffffffffffd98 = ppppppppcVar41;
            func_0xfffffe0008c3c908
                      ("callout out to amfid for %s %s, return %d valid: %d isApple: %d\n");
          }
          if ((int)ppppppppcVar28 != -0x134) {
            if ((int)ppppppppcVar28 != 0) {
              pcVar32 = "StaticPlatformPolicy<%d>: verify_code_directory returned 0x%x\n";
              in_stack_fffffffffffffd98 = ppppppppcVar28;
              local_1c0 = (char ********)cs_blob;
              local_1b4 = uVar10;
              local_1a4 = flags;
              goto LAB_fffffe0009ac4620;
            }
            ppppppppcStack_a8 = ppppppppcStack_128;
            local_b0 = local_130;
            uStack_98 = uStack_118;
            local_a0 = local_120;
            iVar6 = tokenIsTrusted((int)&stack0xfffffffffffffff0 - 0xa0);
            local_1c0 = (char ********)cs_blob;
            local_1b4 = uVar10;
            local_1a4 = flags;
            if (iVar6 == 0) goto LAB_fffffe0009ac50fc;
            if (local_140._4_4_ != 1) goto LAB_fffffe0009ac4624;
            ppiVar31 = &local_90;
            iVar9 = _identityMatch((char *)ppppppppcVar41,puVar25,(uchar *)ppiVar31);
            iVar6 = (int)ppiVar31;
            if (iVar9 == 0) {
              in_stack_fffffffffffffd90 = (char *)0x1;
              func_0xfffffe0008c3c908("StaticPlatformPolicy<%d>: Unable to match identity\n");
              *cs_flags = *cs_flags & 0xfffffffe;
              OSEntitlements::invalidate();
              goto LAB_fffffe0009ac4624;
            }
            if (local_138._4_4_ != 0) {
              *cs_flags = *cs_flags | 0x4000000;
              iVar6 = 0x74a4a42;
              setAndCheckValidationCategory(cs_blob,1,"amfid_made_platform");
            }
            if ((int)local_138 != 0) {
              *cs_flags = *cs_flags | 0x40000000;
            }
            if (local_140._0_4_ != 0) {
              *cs_flags = *cs_flags & 0xfffff7ff;
            }
            if (local_148._4_4_ != 0) {
              *cs_flags = *cs_flags | 0x4200;
            }
            ppppppppcVar28 = (char ********)(ulong)(local_148._0_4_ != 0);
            iVar9 = func_0xfffffe0008a47ac8(cs_blob);
            plVar27 = extraout_x1_25;
            if (iVar9 == 0) {
              uVar7 = (uint)local_208;
              if ((uVar7 >> 5 & 1) == 0) {
                if (((ulong)local_208 & 0x90) == 0) {
                  if ((uVar7 >> 0x10 & 1) == 0) {
                    if ((uVar7 >> 10 & 1) == 0) {
                      uVar7 = 10;
                      if (((ulong)local_208 & 0xc000) != 0) {
                        uVar7 = 2;
                      }
                    }
                    else {
                      in_stack_fffffffffffffd90 = (char *)ppppppppcVar41;
                      func_0xfffffe0008c3c908("%s: Signature meets iphone VPN Prod policy\n");
                      uVar7 = 10;
                    }
                  }
                  else {
                    uVar7 = 5;
                  }
                }
                else {
                  uVar7 = 3;
                }
              }
              else {
                uVar7 = 6;
              }
              iVar6 = 0x74a4a82;
              setAndCheckValidationCategory(cs_blob,uVar7,"amfid_validated");
              plVar27 = extraout_x1_29;
            }
            if ((flags & 1U) != 0) {
              uVar7 = 0x4004200;
              if (local_18c == 0) {
                uVar7 = 0x4004000;
              }
              if ((uVar7 & (*cs_flags ^ 0xffffffff)) != 0) {
                _vnode_check_signature
                          ((vnode *)cs_flags,plVar27,iVar6,pcVar39,(uint *)ppppppppcVar33,
                           (uint *)ppppppppcVar34,(int)ppppppppcVar42,(uint)pcVar24,
                           (char **)in_stack_fffffffffffffd90,(ulong *)in_stack_fffffffffffffd98);
                    /* WARNING: Treating indirect jump as call */
                UNRECOVERED_JUMPTABLE =
                     (code *)UndefinedInstructionException(0xc,0xfffffe0009ac5848);
                ppppppppcVar33 = (char ********)(*UNRECOVERED_JUMPTABLE)();
                return ppppppppcVar33;
              }
              func_0xfffffe00085a8e38(dyldSimCacheLock);
              uRamfffffe000be30880 = local_1e0[1];
              _dyldSimCache = *local_1e0;
              DAT_fffffe000be30888 = *(undefined4 *)(local_1e0 + 2);
              func_0xfffffe00085aa2e4(dyldSimCacheLock);
            }
            iVar6 = isAppleMagicDirectory((char *)ppppppppcVar44);
            if (iVar6 != 0) {
              *cs_flags = *cs_flags | 0xc000000;
              setAndCheckValidationCategory(cs_blob,1,"magic-path-entitlements");
            }
            uVar7 = 0;
            bVar4 = false;
            goto LAB_fffffe0009ac4648;
          }
          pcVar32 = "StaticPlatformPolicy<%d>: verify_code_directory server is dead\n";
          local_1c0 = (char ********)cs_blob;
          local_1b4 = uVar10;
          local_1a4 = flags;
          goto LAB_fffffe0009ac4620;
        }
        uVar7 = 0;
        ppppppppcVar45 = ppppppppcVar13;
        goto LAB_fffffe0009ac492c;
      }
      if (((ulong)local_168 & uVar23) != 0) {
        iVar6 = macOSPolicyConfig::platformIdentifierRequiresTrustCache();
        if (((uVar7 != 0) && (iVar6 != 0)) &&
           (iVar6 = macOSPolicyConfig::queryOverridableExecutionPolicyState(), iVar6 != 2)) {
          uVar14 = func_0xfffffe0008a479c4(cs_blob);
          uVar15 = func_0xfffffe000854a460("com.apple.InstallAssistant");
          iVar6 = func_0xfffffe000854a4f0("com.apple.InstallAssistant",uVar14,uVar15);
          if (((iVar6 != 0) &&
              ((iVar6 = func_0xfffffe0008a49ecc(0x10), iVar6 != 0 ||
               (uVar23 = _matchIn(&_appleInternalPPA,uVar14), (uVar23 & 1) == 0)))) &&
             (uVar23 = _matchIn(&_exactIdentifiersPPA,uVar14), (uVar23 & 1) == 0)) {
            in_stack_fffffffffffffd90 = (char *)ppppppppcVar45;
            func_0xfffffe0008c3c908
                      (
                      "AMFI: %s: Rejecting signature, binary has platform identifier but is not in t he trustcache\n"
                      );
            uVar7 = 1;
            ppppppppcVar45 = ppppppppcVar13;
            goto LAB_fffffe0009ac492c;
          }
        }
        uVar7 = 0x4004200;
        if (local_18c == 0) {
          uVar7 = 0x4004000;
        }
        *cs_flags = *cs_flags | uVar7;
        pcVar24 = "macos-platform";
        local_1c0 = (char ********)cs_blob;
        local_1b4 = uVar10;
        local_1a4 = flags;
        goto LAB_fffffe0009ac3acc;
      }
      if (local_15a[1] == '\0') {
        local_208 = local_168;
        if (iVar6 != 0) {
          iVar6 = _validateOOPJit(cs_blob,(OSEntitlements *)plVar17);
          if (iVar6 != 0) {
            func_0xfffffe0008c3c908("OOP-JIT Signed Fast Path -> %s\n");
            *cs_flags = *cs_flags | 0x4000;
            *signer_type = 9;
            pcVar24 = "macos-oopjit";
            uVar7 = 9;
            local_1c0 = (char ********)cs_blob;
            local_1b4 = uVar10;
            local_1a4 = flags;
            goto LAB_fffffe0009ac3ad4;
          }
          uVar7 = 4;
          ppppppppcVar45 = ppppppppcVar13;
          goto LAB_fffffe0009ac492c;
        }
        iVar6 = func_0xfffffe0008a49ecc(0x10);
        if (iVar6 == 0) {
          local_130 = (char ********)((ulong)local_130 & 0xffffffffffffff00);
          uVar14 = func_0xfffffe0008a4759c(cs_blob);
          uVar15 = func_0xfffffe0008a47590(cs_blob);
          iVar6 = _CMSValidateSignedVnode(uVar14,uVar15,local_1e0,&local_130);
          if (iVar6 == 0) {
            if ((char)local_130 == '\0') {
              uVar7 = 10;
            }
            else {
              func_0xfffffe0008c3c908("AMFI: \'%s\' passed old CMS code. (AMFITrustedKeys?)\n");
              uVar7 = 0x4004200;
              if (local_18c == 0) {
                uVar7 = 0x4004000;
              }
              *cs_flags = *cs_flags | uVar7;
              uVar7 = 1;
            }
            pcVar24 = "amfi-trusted-key";
            local_1c0 = (char ********)cs_blob;
            local_1b4 = uVar10;
            local_1a4 = flags;
            goto LAB_fffffe0009ac3ad4;
          }
        }
        goto LAB_fffffe0009ac3ec0;
      }
      uVar11 = AMFILocalSigningIsRestricted((uchar *)local_1e0);
      uVar14 = func_0xfffffe0008a4759c(cs_blob);
      uVar15 = func_0xfffffe0008a47590(cs_blob);
      lVar16 = func_0xfffffe0008ad268c(uVar14,uVar15,0,0xfade0c02);
      if (lVar16 == 0) {
        pcVar32 = "AMFI: \'%s\': unable to find code directory\n";
LAB_fffffe0009ac4924:
        func_0xfffffe0008c3c908(pcVar32);
        in_stack_fffffffffffffd90 = (char *)ppppppppcVar45;
      }
      else {
        uVar36 = (*(uint *)(lVar16 + 8) & 0xff00ff00) >> 8 | (*(uint *)(lVar16 + 8) & 0xff00ff) << 8
        ;
        if ((uVar36 >> 0x10 | uVar36 << 0x10) >> 10 < 0x81) {
          pcVar32 = 
          "AMFI: \'%s\': locally signed signatures need to be at least 0x%X signature version (0x%X) \n"
          ;
          in_stack_fffffffffffffd98 = (char ********)0x20400;
          goto LAB_fffffe0009ac4924;
        }
        uVar23 = *(ulong *)(lVar16 + 0x50);
        if ((uVar23 >> 0x38 & 1) != 0) {
          if (DAT_fffffe0007e7478c != '\0') {
            iVar6 = func_0xfffffe0008a49ecc(8);
            uVar11 = iVar6 != 0 & uVar11;
          }
          if (uVar11 != 0) {
            pcVar32 = "AMFI: \'%s\': verification failed since local signing is restricted\n";
            goto LAB_fffffe0009ac4924;
          }
          AMFIRestrictLocalSigning();
        }
        uVar11 = *(uint *)(lVar16 + 0x30);
        if (uVar11 == 0) {
          pcVar32 = "AMFI: \'%s\': local signed binary does not have a team identifier\n";
          goto LAB_fffffe0009ac4924;
        }
        uVar11 = (uVar11 & 0xff00ff00) >> 8 | (uVar11 & 0xff00ff) << 8;
        ppppppppcVar41 = (char ********)(lVar16 + (ulong)(uVar11 >> 0x10 | uVar11 << 0x10));
        iVar6 = func_0xfffffe00086abf28(ppppppppcVar41,"LOCALSPKEY");
        if (iVar6 != 0) {
          pcVar32 = "AMFI: \'%s\': local signed binary has an invalid team-identifier: %s\n";
          in_stack_fffffffffffffd98 = ppppppppcVar41;
          goto LAB_fffffe0009ac4924;
        }
        if ((plVar17 == (long *)0x0) || (lVar16 = OSEntitlements::asDict(), lVar16 == 0)) {
          ppppppppcVar13 = emptyDictionary()::empty;
          if (emptyDictionary()::empty == (char ********)0x0) {
            ppppppppcVar13 = (char ********)func_0xfffffe0008bcc220(1);
            emptyDictionary()::empty = ppppppppcVar13;
          }
        }
        else {
          ppppppppcVar13 = (char ********)OSEntitlements::asDict();
        }
        iVar6 = (*(code *)(*ppppppppcVar13)[0x2a])(ppppppppcVar13);
        if (iVar6 == 0) goto LAB_fffffe0009ac55f0;
        if ((uVar23 >> 0x38 & 1) == 0) {
          pcVar32 = "AMFI: \'%s\': disallowing locally signed library with entitlements";
          goto LAB_fffffe0009ac4924;
        }
        local_180 = (long *)func_0xfffffe0008bc6e1c(ppppppppcVar13);
        if (local_180 == (long *)0x0) {
LAB_fffffe0009ac55f0:
          func_0xfffffe0008c3c908("Locally Signed Fast Path -> %s\n");
          *cs_flags = *cs_flags | 0x4000;
          setAndCheckValidationCategory(cs_blob,7,"macos-local");
          ppppppppcVar13 = (char ********)(ulong)uVar7;
          local_1c0 = (char ********)cs_blob;
          local_1b4 = uVar10;
          local_1a4 = flags;
          goto LAB_fffffe0009ac3ad8;
        }
        iVar6 = (*(code *)(*ppppppppcVar13)[0x2a])(ppppppppcVar13);
        if (iVar6 == 0) {
LAB_fffffe0009ac55c8:
          (**(code **)(*local_180 + 0x28))();
          local_1b0 = (char ********)fatal_failure_desc;
          goto LAB_fffffe0009ac55f0;
        }
        local_1c8 = *(ulong *)PTR_DAT_fffffe0007e6ba28;
        do {
          plVar17 = (long *)(**(code **)(*local_180 + 0x148))();
          if (plVar17 == (long *)0x0) goto LAB_fffffe0009ac55c8;
          plVar18 = (long *)func_0xfffffe0008bbdca0(plVar17,local_1c8);
          if ((plVar18 == (long *)0x0) ||
             (pcVar32 = (char *)(**(code **)(*plVar18 + 0x168))(), pcVar32 == (char *)0x0)) {
            (**(code **)(*plVar17 + 0x38))(plVar17);
            in_stack_fffffffffffffd98 = (char ********)func_0xfffffe0008bbe9f4();
            func_0xfffffe0008c3c908
                      (
                      "AMFI: \'%s\':invalid entitlement of type \'%s\' disallowed in local signed co de\n"
                      );
            in_stack_fffffffffffffd90 = (char *)ppppppppcVar45;
            break;
          }
          pOVar30 = (OSObject *)(*(code *)(*ppppppppcVar13)[0x46])(ppppppppcVar13,plVar18);
          uVar23 = entitlementAllowedByConstraints
                             ((entitlement_constraint_t *)&_swiftPlaygrounds_macOS,pcVar32,pOVar30,
                              (char *)ppppppppcVar45);
        } while ((uVar23 & 1) != 0);
        (**(code **)(*local_180 + 0x28))();
        local_1b0 = (char ********)fatal_failure_desc;
      }
      uVar7 = 3;
      ppppppppcVar45 = ppppppppcVar13;
LAB_fffffe0009ac492c:
      ppppppppcVar28 = (char ********)0x0;
      ppppppppcVar13 = ppppppppcVar45;
      local_1c0 = (char ********)cs_blob;
      local_1b4 = uVar10;
      local_1a4 = flags;
      goto LAB_fffffe0009ac4930;
    }
  }
  pcVar32 = "Internal Error: No code directory found (code_dir_: %p, length: %d).";
  local_1a0 = ppppppppcVar21;
  in_stack_fffffffffffffd98 = ppppppppcVar28;
  local_1c0 = (char ********)cs_blob;
  local_1b4 = uVar10;
  local_1a4 = flags;
LAB_fffffe0009ac2ef0:
  pcVar39 = (cs_blob *)(ulong)uVar36;
  ppppppppcVar40 = (char ********)fatal_failure_desc_len;
  fatal_error_fmt((LazyPath *)ppppppppcVar12,fatal_failure_desc,fatal_failure_desc_len,pcVar32);
  ppppppppcVar41 = (char ********)0x0;
  uVar14 = extraout_x1_00;
  do {
    ppppppppcVar28 = (char ********)0x1;
    ppppppppcVar13 = ppppppppcVar44;
    ppppppppcVar45 = ppppppppcVar46;
LAB_fffffe0009ac2f0c:
    auVar50._8_8_ = uVar14;
    auVar50._0_8_ = local_170;
    uVar11 = (uint)ppppppppcVar40;
    in_stack_fffffffffffffd90 = (char *)local_1a0;
    if (local_170 != (long *)0x0) {
      auVar50 = (**(code **)(*local_170 + 0x28))();
      in_stack_fffffffffffffd90 = (char *)local_1a0;
    }
    if (ppppppppcVar41 != (char ********)0x0) {
      auVar50 = func_0xfffffe0008c3bf70
                          (&StaticPlatformPolicy<>::
                            check_signature(LazyPath*,int,cs_blob*,unsigned_int*,unsigned_int*,int,b ool,bool,unsigned_int,char**,unsigned_long*)
                            ::kalloc_type_view_2834,ppppppppcVar41);
    }
    if (((uint)pcVar39 & (*cs_flags ^ 0xffffffff) & 0xfffff7fe) == 0) goto LAB_fffffe0009ac4280;
    _vnode_check_signature
              (auVar50._0_8_,auVar50._8_8_,uVar11,(cs_blob *)pcVar32,(uint *)ppppppppcVar33,
               (uint *)ppppppppcVar34,(int)ppppppppcVar42,(uint)pcVar24,
               (char **)in_stack_fffffffffffffd90,(ulong *)in_stack_fffffffffffffd98);
LAB_fffffe0009ac2f60:
    cs_blob = pcVar39;
    iVar9 = (int)cs_blob;
    iVar6 = _codeDirectoryHashInCompilationServiceHash((uchar *)ppppppppcVar13);
    ppppppppcVar46 = ppppppppcVar45;
    local_1f0 = (char ********)fatal_failure_desc_len;
    if (iVar6 != 0) {
      iVar8 = noEntitlementsPresent((cs_blob *)ppppppppcVar21);
      uVar36 = (uint)pcVar24;
      iVar6 = (int)ppppppppcVar42;
      if (iVar8 == 0) goto LAB_fffffe0009ac2f8c;
      if (local_188 != (long *)0x0) {
        lVar16 = OSEntitlements::asDict();
        uVar36 = (uint)pcVar24;
        iVar6 = (int)ppppppppcVar42;
        if (lVar16 != 0) goto LAB_fffffe0009ac2f8c;
      }
      setAndCheckValidationCategory((cs_blob *)ppppppppcVar21,10,"compilation-service");
      local_100 = (char ********)((ulong)local_100 & 0xffffffffffffff00);
      ppVar22 = (proc *)func_0xfffffe0008bbbe74();
      ppppppppcVar42 = (char ********)&local_100;
      AppleMobileFileIntegrity::AMFIEntitlementGetBool
                (ppVar22,"com.apple.private.amfi.can-execute-cdhash",(bool *)ppppppppcVar42);
      uVar11 = (uint)ppppppppcVar42;
      if ((char)local_100 == '\0') {
        func_0xfffffe0008c3c908("AMFI: can-execute-cdhash code in non-entitled context.\n");
        uVar7 = 1;
        uVar14 = extraout_x1_12;
      }
      else {
        uVar11 = *cs_flags;
        if (emptyDictionary()::empty == (char ********)0x0) {
          emptyDictionary()::empty = (char ********)func_0xfffffe0008bcc220(1);
        }
        ppppppppcVar34 = (char ********)(ulong)(local_18c != 0);
        uVar36 = 0x74a2a5a;
        ppppppppcVar33 = (char ********)0x0;
        iVar6 = 2;
        pcVar32 = (char *)emptyDictionary()::empty;
        in_stack_fffffffffffffd90 = (char *)local_1b0;
        in_stack_fffffffffffffd98 = (char ********)fatal_failure_desc_len;
        uVar7 = postValidation((LazyPath *)ppppppppcVar12,(cs_blob *)ppppppppcVar21,uVar11,
                               (OSDictionary *)emptyDictionary()::empty,'\0',local_18c != 0,2,
                               "can-execute-cdhash",(char **)local_1b0,fatal_failure_desc_len);
        uVar7 = uVar7 ^ 1;
        uVar14 = extraout_x1_05;
      }
      fatal_failure_desc = (char **)(ulong)local_1b4;
      ppppppppcVar42 = (char ********)0x0;
      ppppppppcVar40 = (char ********)0x0;
      cs_blob = (cs_blob *)ppppppppcVar21;
LAB_fffffe0009ac393c:
      fatal_failure_desc_len = (ulong *)local_1f0;
      if (uVar7 == 0) goto LAB_fffffe0009ac41a4;
      ppppppppcVar28 = (char ********)0x1;
      plVar17 = local_188;
      goto LAB_fffffe0009ac420c;
    }
LAB_fffffe0009ac2f8c:
    ppppppppcVar40 =
         (char ********)
         func_0xfffffe0008c3bd24
                   (&StaticPlatformPolicy<>::
                     check_signature(LazyPath*,int,cs_blob*,unsigned_int*,unsigned_int*,int,bool,boo l,unsigned_int,char**,unsigned_long*)
                     ::kalloc_type_view_2630);
    local_148 = (undefined  [8])((ulong)local_148 & 0xffffffffffffff00);
    local_15a = (undefined  [2])((ushort)local_15a & 0xff);
    local_168 = (char ********)0x0;
    auVar51 = func_0xfffffe0008a47a1c(ppppppppcVar21);
    puVar25 = auVar51._0_8_;
    if (puVar25 == (uchar *)0x0) {
      _vnode_check_signature
                ((vnode *)0x0,auVar51._8_8_,uVar11,(cs_blob *)pcVar32,(uint *)ppppppppcVar33,
                 (uint *)ppppppppcVar34,(int)ppppppppcVar42,(uint)pcVar24,
                 (char **)in_stack_fffffffffffffd90,(ulong *)in_stack_fffffffffffffd98);
      cs_flags = (uint *)fatal_failure_desc_len;
      fatal_failure_desc_len = (ulong *)fatal_failure_desc;
      local_1a0 = ppppppppcVar41;
LAB_fffffe0009ac50fc:
      pcVar32 = "StaticPlatformPolicy<%d>: unable to verify audit token came from amfid\n";
LAB_fffffe0009ac4620:
      in_stack_fffffffffffffd90 = (char *)0x1;
      func_0xfffffe0008c3c908(pcVar32);
LAB_fffffe0009ac4624:
      ppppppppcVar28 = (char ********)0x0;
      uVar7 = 2;
      if ((uint)local_1c8 != 0 || (local_18c & 0xff) == 0) {
        uVar7 = 0;
      }
      bVar4 = true;
LAB_fffffe0009ac4648:
      if (((uint)local_208 >> 6 & 1) != 0) {
        *(uint *)local_180 = 6;
        setAndCheckValidationCategory((cs_blob *)local_1c0,4,"mac-app-store");
      }
      ppppppppcVar41 = ppppppppcVar40;
      if (!bVar4) goto LAB_fffffe0009ac3ae0;
LAB_fffffe0009ac4930:
      func_0xfffffe0008c3c908("AMFI: code signature validation failed.\n");
      ppppppppcVar41 = ppppppppcVar40;
      if (uVar7 < 5) {
        switch(uVar7) {
        default:
          setAndCheckValidationCategory((cs_blob *)local_1c0,10,"untrusted");
          goto LAB_fffffe0009ac4980;
        case 1:
          func_0xfffffe0008c3c908
                    ("AMFI: Platform binary with platform identifier not in trust cache\n");
          pcVar32 = "platform binary with platform identifier not in trust cache\n";
          break;
        case 2:
          func_0xfffffe0008c3c908("AMFI: bailing out because of restricted entitlements.\n");
          pcVar32 = 
          "Code has restricted entitlements, but the validation of its code signature failed.\nUnsat isfied Entitlements: %s"
          ;
          in_stack_fffffffffffffd90 = (char *)ppppppppcVar40;
          break;
        case 3:
          func_0xfffffe0008c3c908("AMFI: local signing validation was unsuccessful.\n");
          pcVar32 = "fatal error detected during local signing validation";
          break;
        case 4:
          func_0xfffffe0008c3c908("AMFI: OOP-JIT validation was unsuccessful.\n");
          pcVar32 = "fatal error detected during OOP-JIT signature validation";
        }
        ppppppppcVar40 = (char ********)fatal_failure_desc_len;
        fatal_error_fmt((LazyPath *)ppppppppcVar12,(char **)local_1b0,fatal_failure_desc_len,pcVar32
                       );
        uVar14 = extraout_x1_26;
        ppppppppcVar48 = (char ********)cs_flags;
        ppppppppcVar49 = (char ********)fatal_failure_desc_len;
        local_1a0 = (char ********)in_stack_fffffffffffffd90;
        goto LAB_fffffe0009ac4084;
      }
LAB_fffffe0009ac4980:
      uVar7 = (*(uint *)(ppppppppcVar21 + 1) & 0xff00ff00) >> 8 |
              (*(uint *)(ppppppppcVar21 + 1) & 0xff00ff) << 8;
      if ((uVar7 >> 0x10 | uVar7 << 0x10) < 0x20200) {
        bVar4 = false;
      }
      else {
        bVar4 = *(int *)(ppppppppcVar21 + 6) != 0;
      }
      pcVar39 = (cs_blob *)((ulong)local_198 & 0xffffffff);
      ppppppppcVar49 = local_1b0;
      if (DAT_fffffe0007e7478a == '\0') {
        if ((local_1a4 & 1) != 0) {
          pcVar32 = "Signature validation for dyld_sim failed. Your SDK may be damaged.";
          ppppppppcVar44 = ppppppppcVar13;
          fatal_failure_desc = (char **)(char ********)fatal_failure_desc_len;
          goto LAB_fffffe0009ac40cc;
        }
        if (bVar4) {
          uVar7 = *(uint *)(ppppppppcVar21 + 6);
          ppppppppcVar49 = (char ********)(ulong)uVar7;
          if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
            uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
            *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
          }
          local_90 = (ipc_port *)0x0;
          iVar6 = getDaemonPort(&local_90);
          ppppppppcVar46 = (char ********)cs_flags;
          ppppppppcVar48 = (char ********)fatal_failure_desc_len;
          if (iVar6 == 0) {
            uStack_e8 = 0;
            local_f0 = (char *******)0x0;
            ppppppppcStack_f8 = (char ********)0x0;
            local_100 = (char ********)0x0;
            puVar25 = (uchar *)func_0xfffffe0008a47a1c(local_1c0);
            local_b0 = (char ********)0x0;
            ppppppppcStack_a8 = (char ********)0x0;
            local_a0 = (char *******)((ulong)local_a0 & 0xffffffff00000000);
            if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
              uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
              *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
            }
            piVar3 = local_90;
            local_108 = (char ********)CONCAT44(local_108._4_4_,1);
            uVar14 = func_0xfffffe0008a47584(local_1c0);
            pcVar32 = (char *)&local_108;
            ppppppppcVar33 = (char ********)&local_b0;
            ppppppppcVar34 = (char ********)&local_100;
            ppppppppcVar44 =
                 (char ********)_check_broken_signature_with_teamid_fatal(piVar3,local_1a0,uVar14);
            if ((int)ppppppppcVar44 == -0x134) {
              pcVar32 = "%s: check_broken_signature_with_teamid_fatal server is dead\n";
              goto LAB_fffffe0009ac4ad4;
            }
            if ((int)ppppppppcVar44 != 0) {
              pcVar32 = "%s: check_broken_signature_with_teamid_fatal returned 0x%x\n";
              in_stack_fffffffffffffd98 = ppppppppcVar44;
              goto LAB_fffffe0009ac4ad4;
            }
            ppppppppcStack_128 = ppppppppcStack_f8;
            local_130 = local_100;
            uStack_118 = uStack_e8;
            local_120 = local_f0;
            uVar23 = tokenIsTrusted((audit_token_t)&local_130);
            if ((uVar23 & 1) == 0) {
              pcVar32 = "%s: unable to verify audit token came from amfid\n";
              goto LAB_fffffe0009ac4ad4;
            }
            ppppppppcVar40 = (char ********)&local_b0;
            uVar23 = _identityMatch((char *)local_1a0,puVar25,(uchar *)ppppppppcVar40);
            if (((uVar23 & 1) != 0) && ((int)local_108 == 0)) {
              uVar7 = (uVar7 & 0xff00ff00) >> 8 | (uVar7 & 0xff00ff) << 8;
              in_stack_fffffffffffffd98 =
                   (char ********)((long)ppppppppcVar21 + (ulong)(uVar7 >> 0x10 | uVar7 << 0x10));
              func_0xfffffe0008c3c908
                        (
                        "AMFI: Check-fix enabled for binary \'%s\' with TeamID \'%s\', identifier \' %s\': broken signature treated as unsigned without privileges. This workarou nd will not work for software built on or after 10.12.\n"
                        );
              uVar14 = extraout_x1_28;
              goto LAB_fffffe0009ac4084;
            }
          }
          else {
            pcVar32 = "%s: no registered daemon port for check_broken_signature_with_teamid_fatal\n"
            ;
LAB_fffffe0009ac4ad4:
            in_stack_fffffffffffffd90 =
                 "bool _checkBrokenSignatureWithTeamIDFatal(LazyPath *, struct cs_blob *)";
            func_0xfffffe0008c3c908(pcVar32);
          }
          pcVar32 = 
          "The code contains a Team ID, but validating its signature failed.\nPlease check your syst em log."
          ;
          ppppppppcVar40 = (char ********)fatal_failure_desc_len;
          fatal_error_fmt((LazyPath *)ppppppppcVar12,(char **)local_1b0,fatal_failure_desc_len,
                          "The code contains a Team ID, but validating its signature failed.\nPlease  check your system log."
                         );
          uVar14 = extraout_x1_27;
          local_1a0 = (char ********)in_stack_fffffffffffffd90;
          goto LAB_fffffe0009ac4084;
        }
      }
      ppppppppcVar44 = (char ********)(ulong)local_1b4;
      pcVar32 = (char *)ppppppppcVar28;
      goto LAB_fffffe0009ac4090;
    }
    local_f0 = (char *******)0x0;
    uStack_e8 = 0;
    ppppppppcVar28[5] = (char *******)0x0;
    ppppppppcVar28[4] = (char *******)0x0;
    ppppppppcVar28[7] = (char *******)0x0;
    ppppppppcVar28[6] = (char *******)0x0;
    local_c0 = local_188;
    local_100 = ppppppppcVar12;
    ppppppppcStack_f8 = ppppppppcVar21;
    iVar6 = _codeDirectoryHashIsInJitHashCache(puVar25);
    local_1e8 = (char ********)cs_flags;
    if ((iVar6 != 0) && (iVar6 = noEntitlementsPresent((cs_blob *)ppppppppcVar21), iVar6 != 0)) {
      *cs_flags = *cs_flags | 0x4004000;
      pcVar24 = "jit-hash-cache";
LAB_fffffe0009ac3878:
      setAndCheckValidationCategory((cs_blob *)ppppppppcVar21,1,pcVar24);
LAB_fffffe0009ac3888:
      ppppppppcVar42 = (char ********)0x0;
LAB_fffffe0009ac3890:
      if ((local_188 == (long *)0x0) || (lVar16 = OSEntitlements::asDict(), lVar16 == 0)) {
        pcVar32 = (char *)emptyDictionary()::empty;
        if (emptyDictionary()::empty == (char ********)0x0) {
          pcVar32 = (char *)func_0xfffffe0008bcc220(1);
          emptyDictionary()::empty = (char ********)pcVar32;
        }
      }
      else {
        pcVar32 = (char *)OSEntitlements::asDict();
      }
      fatal_failure_desc = (char **)(ulong)local_1b4;
      ppppppppcVar34 = (char ********)(ulong)(local_18c != 0);
      uVar11 = *(uint *)local_1e8;
      uVar36 = 0x74a2acb;
      ppppppppcVar33 = (char ********)0x0;
      iVar6 = 2;
      in_stack_fffffffffffffd90 = (char *)local_1b0;
      in_stack_fffffffffffffd98 = local_1f0;
      uVar7 = postValidation((LazyPath *)ppppppppcVar12,(cs_blob *)ppppppppcVar21,uVar11,
                             (OSDictionary *)pcVar32,'\0',local_18c != 0,2,"dynamic",
                             (char **)local_1b0,(ulong *)local_1f0);
      uVar7 = uVar7 ^ 1;
      uVar14 = extraout_x1_11;
      cs_flags = (uint *)local_1e8;
      cs_blob = (cs_blob *)ppppppppcVar21;
      goto LAB_fffffe0009ac393c;
    }
    if (ppppppppcVar12 == (char ********)0x0) {
      ppppppppcVar42 = (char ********)0x0;
    }
    else {
      ppppppppcVar42 = ppppppppcVar41;
      if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
        uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
        *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
      }
    }
    ppppppppcVar44 = (char ********)"<null>";
    if (ppppppppcVar42 != (char ********)0x0) {
      ppppppppcVar44 = ppppppppcVar42;
    }
    local_1c0 = ppppppppcVar21;
    if (local_1b4 != 0) {
      *cs_flags = *cs_flags | 0x4004000;
      pcVar24 = "platform-override";
      goto LAB_fffffe0009ac3878;
    }
    uVar7 = (uint)ppppppppcVar45;
    local_1c8 = (ulong)ppppppppcVar45 & 0xffffffff;
    pcVar32 = local_15a + 1;
    ppppppppcVar33 = (char ********)&local_168;
    ppppppppcVar34 = (char ********)local_148;
    ppppppppcVar28 = (char ********)&local_100;
    ppppppppcVar46 = ppppppppcVar44;
    _validateCoreTrust((cs_blob *)ppppppppcVar21,puVar25,(char *)ppppppppcVar44,(bool *)pcVar32,
                       (ulonglong *)ppppppppcVar33,(bool *)ppppppppcVar34,
                       (ProfileValidationData *)ppppppppcVar28);
    uVar36 = (uint)pcVar24;
    iVar6 = (int)ppppppppcVar28;
    uVar11 = (uint)ppppppppcVar46;
    if (local_15a[1] != '\0') {
      uVar10 = func_0xfffffe0008a478bc(ppppppppcVar21);
      if ((uVar10 >> 1 & 1) == 0) {
        uVar10 = 0;
      }
      else {
        uVar10 = _checkForOOPJit((cs_blob *)ppppppppcVar21);
      }
      ppppppppcVar13 = local_168;
      uVar36 = (uint)pcVar24;
      iVar6 = (int)ppppppppcVar28;
      ppppppppcVar46 = (char ********)((ulong)ppppppppcVar45 & 0xffffffff);
      if (((ulong)local_168 & 0x100008) != 0) {
        func_0xfffffe0008c3c908("AMFI: \'%s\' passed old-school CT policy.\n");
        uVar7 = 0x4004200;
        if (local_18c == 0) {
          uVar7 = 0x4004000;
        }
        *cs_flags = *cs_flags | uVar7;
        pcVar24 = "ct-platform";
        goto LAB_fffffe0009ac3878;
      }
      cVar2 = local_148[0];
      if (((uint)(((ulong)local_168 & 0x18000001ff80) != 0 || local_148[0] != '\0') | uVar10 & 1) ==
          0) {
        in_stack_fffffffffffffd98 = local_168;
        func_0xfffffe0008c3c908
                  (
                  "AMFI: \'%s\': unsuitable CT policy %#llx for this platform/device, rejecting sign ature.\n"
                  );
        in_stack_fffffffffffffd90 = (char *)ppppppppcVar44;
        goto LAB_fffffe0009ac3cd4;
      }
      local_198 = local_168;
      if ((((ulong)local_168 & 0x80000001100) != 0) &&
         (uVar23 = IsCDHashDenylisted(puVar25), (uVar23 & 1) == 0)) {
        func_0xfffffe0008c3c908("App Store Fast Path -> %s\n");
        *cs_flags = *cs_flags | 0x4000;
        pcVar24 = "fast-path-appstore";
LAB_fffffe0009ac449c:
        uVar7 = 4;
LAB_fffffe0009ac44a8:
        setAndCheckValidationCategory((cs_blob *)ppppppppcVar21,uVar7,pcVar24);
        ppppppppcVar46 = (char ********)((ulong)ppppppppcVar45 & 0xffffffff);
        goto LAB_fffffe0009ac3888;
      }
      iVar8 = func_0xfffffe0008a49ecc(8);
      uVar36 = (uint)pcVar24;
      iVar6 = (int)ppppppppcVar28;
      if ((iVar8 == 0) && (((ulong)ppppppppcVar13 & 0x100000002200) != 0)) {
        func_0xfffffe0008c3c908("QA Hierarchy used -> %s\n");
        *cs_flags = *cs_flags | 0x4000;
        pcVar24 = "qa-path-appstore";
        goto LAB_fffffe0009ac449c;
      }
      if (cVar2 != '\0') {
        uVar7 = AMFILocalSigningIsRestricted(puVar25);
        uVar14 = func_0xfffffe0008a4759c(ppppppppcVar21);
        uVar15 = func_0xfffffe0008a47590(ppppppppcVar21);
        pOVar30 = (OSObject *)0x0;
        pcVar32 = (char *)0xfade0c02;
        lVar16 = func_0xfffffe0008ad268c(uVar14,uVar15);
        uVar36 = (uint)pcVar24;
        iVar6 = (int)ppppppppcVar28;
        uVar11 = (uint)pOVar30;
        if (lVar16 == 0) {
          pcVar24 = "AMFI: \'%s\': unable to find code directory\n";
LAB_fffffe0009ac44c4:
          func_0xfffffe0008c3c908(pcVar24);
          uVar10 = 3;
          in_stack_fffffffffffffd90 = (char *)ppppppppcVar44;
          goto LAB_fffffe0009ac3cd8;
        }
        uVar10 = (*(uint *)(lVar16 + 8) & 0xff00ff00) >> 8 | (*(uint *)(lVar16 + 8) & 0xff00ff) << 8
        ;
        if ((uVar10 >> 0x10 | uVar10 << 0x10) >> 10 < 0x81) {
          pcVar24 = 
          "AMFI: \'%s\': locally signed signatures need to be at least 0x%X signature version (0x%X) \n"
          ;
          in_stack_fffffffffffffd98 = (char ********)0x20400;
          goto LAB_fffffe0009ac44c4;
        }
        uVar23 = *(ulong *)(lVar16 + 0x50);
        if ((uVar23 >> 0x38 & 1) != 0) {
          if (DAT_fffffe0007e7478c != '\0') {
            iVar6 = func_0xfffffe0008a49ecc(8);
            uVar7 = iVar6 != 0 & uVar7;
          }
          uVar36 = (uint)pcVar24;
          iVar6 = (int)ppppppppcVar28;
          uVar11 = (uint)pOVar30;
          if (uVar7 == 0) {
            AMFIRestrictLocalSigning();
            goto LAB_fffffe0009ac4c1c;
          }
          pcVar24 = "AMFI: \'%s\': verification failed since local signing is restricted\n";
LAB_fffffe0009ac4584:
          func_0xfffffe0008c3c908(pcVar24);
          in_stack_fffffffffffffd90 = (char *)ppppppppcVar44;
LAB_fffffe0009ac4588:
          uVar10 = 3;
          goto LAB_fffffe0009ac3cd8;
        }
LAB_fffffe0009ac4c1c:
        uVar36 = (uint)pcVar24;
        iVar6 = (int)ppppppppcVar28;
        uVar11 = (uint)pOVar30;
        uVar7 = *(uint *)(lVar16 + 0x30);
        if (uVar7 == 0) {
          pcVar24 = "AMFI: \'%s\': local signed binary does not have a team identifier\n";
          goto LAB_fffffe0009ac44c4;
        }
        uVar7 = (uVar7 & 0xff00ff00) >> 8 | (uVar7 & 0xff00ff) << 8;
        ppppppppcVar46 = (char ********)(lVar16 + (ulong)(uVar7 >> 0x10 | uVar7 << 0x10));
        iVar9 = func_0xfffffe00086abf28(ppppppppcVar46,"LOCALSPKEY");
        uVar36 = (uint)pcVar24;
        iVar6 = (int)ppppppppcVar28;
        uVar11 = (uint)pOVar30;
        if (iVar9 != 0) {
          pcVar24 = "AMFI: \'%s\': local signed binary has an invalid team-identifier: %s\n";
          in_stack_fffffffffffffd98 = ppppppppcVar46;
          goto LAB_fffffe0009ac44c4;
        }
        if ((local_188 == (long *)0x0) || (lVar16 = OSEntitlements::asDict(), lVar16 == 0)) {
          ppppppppcVar46 = emptyDictionary()::empty;
          if (emptyDictionary()::empty == (char ********)0x0) {
            ppppppppcVar46 = (char ********)func_0xfffffe0008bcc220(1);
            emptyDictionary()::empty = ppppppppcVar46;
          }
        }
        else {
          ppppppppcVar46 = (char ********)OSEntitlements::asDict();
        }
        iVar9 = (*(code *)(*ppppppppcVar46)[0x2a])(ppppppppcVar46);
        uVar36 = (uint)pcVar24;
        iVar6 = (int)ppppppppcVar28;
        uVar11 = (uint)pOVar30;
        if (iVar9 != 0) {
          if ((uVar23 >> 0x38 & 1) == 0) {
            pcVar24 = "AMFI: \'%s\': disallowing locally signed library with entitlements";
            goto LAB_fffffe0009ac4584;
          }
          plVar17 = (long *)func_0xfffffe0008bc6e1c(ppppppppcVar46);
          if (plVar17 != (long *)0x0) {
            iVar6 = (*(code *)(*ppppppppcVar46)[0x2a])(ppppppppcVar46);
            if (iVar6 != 0) {
              uVar14 = *(undefined8 *)PTR_DAT_fffffe0007e6ba28;
              do {
                uVar11 = (uint)pOVar30;
                plVar18 = (long *)(**(code **)(*plVar17 + 0x148))(plVar17);
                if (plVar18 == (long *)0x0) goto LAB_fffffe0009ac5500;
                plVar19 = (long *)func_0xfffffe0008bbdca0(plVar18,uVar14);
                uVar36 = (uint)pcVar24;
                iVar6 = (int)ppppppppcVar28;
                if (plVar19 == (long *)0x0) {
LAB_fffffe0009ac5560:
                  (**(code **)(*plVar18 + 0x38))(plVar18);
                  in_stack_fffffffffffffd98 = (char ********)func_0xfffffe0008bbe9f4();
                  func_0xfffffe0008c3c908
                            (
                            "AMFI: \'%s\':invalid entitlement of type \'%s\' disallowed in local sig ned code\n"
                            );
                  in_stack_fffffffffffffd90 = (char *)ppppppppcVar44;
                  break;
                }
                pcVar26 = (char *)(**(code **)(*plVar19 + 0x168))();
                uVar36 = (uint)pcVar24;
                iVar6 = (int)ppppppppcVar28;
                if (pcVar26 == (char *)0x0) goto LAB_fffffe0009ac5560;
                pOVar30 = (OSObject *)(*(code *)(*ppppppppcVar46)[0x46])(ppppppppcVar46,plVar19);
                pcVar32 = (char *)ppppppppcVar44;
                uVar23 = entitlementAllowedByConstraints
                                   ((entitlement_constraint_t *)&_swiftPlaygrounds_iOS,pcVar26,
                                    pOVar30,(char *)ppppppppcVar44);
                uVar36 = (uint)pcVar24;
                iVar6 = (int)ppppppppcVar28;
                uVar11 = (uint)pOVar30;
              } while ((uVar23 & 1) != 0);
              (**(code **)(*plVar17 + 0x28))(plVar17);
              goto LAB_fffffe0009ac4588;
            }
LAB_fffffe0009ac5500:
            (**(code **)(*plVar17 + 0x28))(plVar17);
          }
        }
        func_0xfffffe0008c3c908("Locally Signed Fast Path -> %s\n");
        *cs_flags = *cs_flags | 0x4000;
        pcVar24 = "fast-path-local";
        uVar7 = 7;
        goto LAB_fffffe0009ac44a8;
      }
      if (uVar10 != 0) {
        iVar9 = _validateOOPJit((cs_blob *)ppppppppcVar21,(OSEntitlements *)local_188);
        ppppppppcVar46 = (char ********)((ulong)ppppppppcVar45 & 0xffffffff);
        if (iVar9 == 0) {
          uVar10 = 4;
          goto LAB_fffffe0009ac3cd8;
        }
        func_0xfffffe0008c3c908("OOP-JIT Signed Fast Path -> %s\n");
        *cs_flags = *cs_flags | 0x4000;
        *(uint *)local_180 = 9;
        setAndCheckValidationCategory((cs_blob *)ppppppppcVar21,9,"oop-jit");
        goto LAB_fffffe0009ac3888;
      }
      if (ppppppppcVar42 == (char ********)0x0) goto LAB_fffffe0009ac3cd4;
      local_198 = ppppppppcVar13;
      *cs_flags = *cs_flags & 0xf3ffbfff;
      local_108 = (char ********)0x0;
      iVar8 = getDaemonPort((ipc_port **)&local_108);
      if (iVar8 == 0) {
        ppppppppcStack_128 = (char ********)0x0;
        local_130 = (char ********)0x0;
        uStack_118 = 0;
        local_120 = (char *******)0x0;
        local_178 = (char ********)((ulong)local_178 & 0xffffffff00000000);
        local_140 = (undefined  [8])0x0;
        local_138 = (char *******)0x0;
        local_148 = (undefined  [8])((ulong)local_148 & 0xffffffff);
        local_90 = (ipc_port *)0x0;
        uStack_88 = 0;
        local_80 = 0;
        puVar25 = (uchar *)func_0xfffffe0008a47a1c(ppppppppcVar21);
        if (*(char *)(ppppppppcVar12 + 0x81) == '\0') {
          uVar5 = (*(code *)(*ppppppppcVar12)[2])(ppppppppcVar12);
          *(undefined *)(ppppppppcVar12 + 0x81) = uVar5;
        }
        ppppppppcVar46 = local_108;
        ppppppppcVar34 = (char ********)(ulong)(iVar9 != 0);
        ppppppppcVar33 = (char ********)(ulong)(local_18c != 0);
        local_158 = 0;
        local_150 = (char *******)0x0;
        uVar11 = func_0xfffffe0008a47584(ppppppppcVar21);
        in_stack_fffffffffffffd98 = (char ********)(local_140 + 4);
        in_stack_fffffffffffffd90 = (char *)&local_138;
        uVar36 = (uint)local_140;
        pcVar32 = (char *)(ulong)local_1a4;
        iVar6 = 2;
        ppppppppcVar46 = (char ********)_verify_code_directory(ppppppppcVar46,ppppppppcVar41);
        if (0x13 < *(int *)PTR_DAT_fffffe0007e6bae0) {
          in_stack_fffffffffffffd90 = "(restricted entitlements)";
          if (local_18c == 0) {
            in_stack_fffffffffffffd90 = "";
          }
          in_stack_fffffffffffffd98 = ppppppppcVar41;
          func_0xfffffe0008c3c908
                    ("callout out to amfid for %s %s, return %d valid: %d isApple: %d\n");
        }
        if ((int)ppppppppcVar46 == -0x134) {
          pcVar24 = "StaticPlatformPolicy<%d>: verify_code_directory server is dead\n";
          goto LAB_fffffe0009ac45ec;
        }
        if ((int)ppppppppcVar46 != 0) {
          pcVar24 = "StaticPlatformPolicy<%d>: verify_code_directory returned 0x%x\n";
          in_stack_fffffffffffffd98 = ppppppppcVar46;
          goto LAB_fffffe0009ac45ec;
        }
        ppppppppcStack_a8 = ppppppppcStack_128;
        local_b0 = local_130;
        uStack_98 = uStack_118;
        local_a0 = local_120;
        iVar8 = tokenIsTrusted((int)&stack0xfffffffffffffff0 - 0xa0);
        if (iVar8 == 0) {
LAB_fffffe0009ac5370:
          iVar9 = (int)cs_blob;
          pcVar24 = "StaticPlatformPolicy<%d>: unable to verify audit token came from amfid\n";
          goto LAB_fffffe0009ac45ec;
        }
        if ((int)local_138 != 1) goto LAB_fffffe0009ac45f0;
        ppiVar31 = &local_90;
        iVar8 = _identityMatch((char *)ppppppppcVar41,puVar25,(uchar *)ppiVar31);
        uVar11 = (uint)ppiVar31;
        if (iVar8 == 0) {
          in_stack_fffffffffffffd90 = (char *)0x2;
          func_0xfffffe0008c3c908("StaticPlatformPolicy<%d>: Unable to match identity\n");
          *cs_flags = *cs_flags & 0xfffffffe;
          OSEntitlements::invalidate();
          goto LAB_fffffe0009ac45f0;
        }
        if ((int)local_178 != 0) {
          *cs_flags = *cs_flags | 0x4000000;
          uVar11 = 0x74a4a42;
          setAndCheckValidationCategory((cs_blob *)ppppppppcVar21,1,"amfid_made_platform");
        }
        if (local_138._4_4_ != 0) {
          *cs_flags = *cs_flags | 0x40000000;
        }
        if (local_140._4_4_ != 0) {
          *cs_flags = *cs_flags & 0xfffff7ff;
        }
        if (local_140._0_4_ != 0) {
          *cs_flags = *cs_flags | 0x4200;
        }
        ppppppppcVar42 = (char ********)(ulong)(local_148._4_4_ != 0);
        if (((ulong)ppppppppcVar13 & 0x10000001ee80) != 0) {
          local_f0 = local_150;
          uStack_e8 = local_158;
          iVar8 = validateAndRegisterProfile((ProfileValidationData *)&local_100);
          if (iVar8 == 0) goto LAB_fffffe0009ac4f70;
          goto LAB_fffffe0009ac45f4;
        }
LAB_fffffe0009ac4f70:
        iVar9 = func_0xfffffe0008a47ac8(ppppppppcVar21);
        if (iVar9 == 0) {
          uVar10 = (uint)ppppppppcVar13;
          if ((uVar10 >> 5 & 1) == 0) {
            if (((ulong)ppppppppcVar13 & 0x90) == 0) {
              if ((uVar10 >> 0x10 & 1) == 0) {
                if ((uVar10 >> 10 & 1) == 0) {
                  uVar10 = 10;
                  if (((ulong)ppppppppcVar13 & 0xc000) != 0) {
                    uVar10 = 2;
                  }
                }
                else {
                  func_0xfffffe0008c3c908("%s: Signature meets iphone VPN Prod policy\n");
                  uVar10 = 10;
                  in_stack_fffffffffffffd90 = (char *)ppppppppcVar41;
                }
              }
              else {
                uVar10 = 5;
              }
            }
            else {
              uVar10 = 3;
            }
          }
          else {
            uVar10 = 6;
          }
          uVar11 = 0x74a4a82;
          setAndCheckValidationCategory((cs_blob *)ppppppppcVar21,uVar10,"amfid_validated");
        }
        bVar4 = false;
        uVar10 = 0;
      }
      else {
        pcVar24 = "StaticPlatformPolicy<%d>: no registered daemon port\n";
LAB_fffffe0009ac45ec:
        in_stack_fffffffffffffd90 = (char *)0x2;
        func_0xfffffe0008c3c908(pcVar24);
LAB_fffffe0009ac45f0:
        ppppppppcVar42 = (char ********)0x0;
LAB_fffffe0009ac45f4:
        uVar10 = 2;
        if (iVar9 != 0 || local_18c == 0) {
          uVar10 = 0;
        }
        bVar4 = true;
        uVar7 = (uint)local_1c8;
      }
      ppppppppcVar46 = (char ********)(ulong)uVar7;
      if (((uint)local_198 >> 6 & 1) != 0) {
        *(uint *)local_180 = 6;
        uVar11 = 0x74a40b6;
        setAndCheckValidationCategory((cs_blob *)local_1c0,4,"mac-app-store");
      }
      ppppppppcVar21 = local_1c0;
      if (bVar4) goto LAB_fffffe0009ac3cdc;
      goto LAB_fffffe0009ac3890;
    }
    func_0xfffffe0008c3c908("AMFI: \'%s\': Unrecoverable CT signature issue, bailing out.\n");
    in_stack_fffffffffffffd90 = (char *)ppppppppcVar44;
LAB_fffffe0009ac3cd4:
    uVar10 = 0;
LAB_fffffe0009ac3cd8:
    ppppppppcVar46 = (char ********)((ulong)ppppppppcVar45 & 0xffffffff);
    ppppppppcVar42 = (char ********)0x0;
LAB_fffffe0009ac3cdc:
    func_0xfffffe0008c3c908("AMFI: code signature validation failed.\n");
    uVar14 = extraout_x1_15;
    cs_flags = (uint *)local_1e8;
    fatal_failure_desc_len = (ulong *)local_1f0;
    if (4 < uVar10) goto LAB_fffffe0009ac3db0;
    switch(uVar10) {
    default:
      uVar11 = 0x74a2afc;
      setAndCheckValidationCategory((cs_blob *)local_1c0,10,"untrusted");
      uVar14 = extraout_x1_16;
      goto LAB_fffffe0009ac3db0;
    case 1:
      func_0xfffffe0008c3c908("AMFI: Platform binary with platform identifier not in trust cache\n")
      ;
      pcVar32 = "platform binary with platform identifier not in trust cache\n";
      break;
    case 2:
      func_0xfffffe0008c3c908("AMFI: bailing out because of restricted entitlements.\n");
      pcVar32 = 
      "Code has restricted entitlements, but the validation of its code signature failed.\nUnsatisfi ed Entitlements: %s"
      ;
      in_stack_fffffffffffffd90 = (char *)ppppppppcVar40;
      break;
    case 3:
      func_0xfffffe0008c3c908("AMFI: local signing validation was unsuccessful.\n");
      uVar14 = extraout_x1_17;
LAB_fffffe0009ac3db0:
      if ((DAT_fffffe0007e7478a == '\0') ||
         (iVar9 = func_0xfffffe0008a49ecc(8), uVar14 = extraout_x1_18, iVar9 != 0))
      goto LAB_fffffe0009ac4208;
      func_0xfffffe0008c3c908("AMFI: Invalid signature but permitting execution\n");
      cs_blob = (cs_blob *)local_1c0;
      if (((*(byte *)((long)local_1e8 + 3) >> 2 & 1) == 0) && (DAT_fffffe0007e7478f == '\0')) {
        func_0xfffffe0008c3c908
                  (
                  "AMFI: Not from trust cache but marking as platform binary anyway (unless in 3rd p arty path).\n"
                  );
        *(uint *)local_1e8 = *(uint *)local_1e8 | (uint)fatal_failure_desc;
        setAndCheckValidationCategory((cs_blob *)local_1c0,1,"amfi_allow_any_signature");
        fatal_failure_desc = (char **)0x0;
      }
      else {
        fatal_failure_desc = (char **)0x0;
      }
LAB_fffffe0009ac41a4:
      pcVar32 = (char *)ppppppppcVar42;
      iVar9 = macOSPolicyConfig::executionRequiresTrustCache();
      if ((((ulong)fatal_failure_desc & 1) == 0) && (iVar9 != 0)) {
        pcVar32 = "The system only allows binaries in the trust cache.\n";
LAB_fffffe0009ac41f4:
        ppppppppcVar42 = (char ********)fatal_failure_desc_len;
        fatal_error_fmt((LazyPath *)ppppppppcVar12,(char **)local_1b0,fatal_failure_desc_len,pcVar32
                       );
        uVar11 = (uint)ppppppppcVar42;
        uVar14 = extraout_x1_22;
        goto LAB_fffffe0009ac4208;
      }
      iVar9 = macOSPolicyConfig::queryOverridableExecutionPolicyState();
      if (((uint)fatal_failure_desc & 1 | (uint)(iVar9 != 1)) == 0) {
        pcVar32 = 
        "The system only allows binaries in the trust cache. Running other software requires authent ication.\n"
        ;
        goto LAB_fffffe0009ac41f4;
      }
      uVar7 = *cs_flags;
      if ((uVar7 >> 0x1a & 1) == 0) {
        uVar23 = macOSPolicyConfig::allowOnlyPlatformCode();
        if ((uVar23 & 1) != 0) {
          pcVar32 = 
          "The system only allows platform binaries, and the code is not a platform binary\n";
          goto LAB_fffffe0009ac41f4;
        }
        uVar7 = *cs_flags;
      }
      *cs_flags = uVar7 | 0x20000000;
      checkDebuggerStatus((OSEntitlements **)&local_170,cs_flags,cs_blob,SUB81(pcVar32,0));
      uVar11 = (uint)cs_blob;
      ppppppppcVar28 = (char ********)0x0;
      plVar17 = local_170;
      uVar14 = extraout_x1_23;
      if (((*(byte *)((long)cs_flags + 3) >> 2 & 1) != 0) && (local_170 != (long *)0x0)) {
        OSEntitlements::markAsCSPlatform();
        ppppppppcVar28 = (char ********)0x0;
        plVar17 = local_170;
        uVar14 = extraout_x1_24;
      }
      goto LAB_fffffe0009ac420c;
    case 4:
      func_0xfffffe0008c3c908("AMFI: OOP-JIT validation was unsuccessful.\n");
      pcVar32 = "fatal error detected during OOP-JIT signature validation";
    }
    ppppppppcVar42 = local_1f0;
    fatal_error_fmt((LazyPath *)ppppppppcVar12,(char **)local_1b0,(ulong *)local_1f0,pcVar32);
    uVar11 = (uint)ppppppppcVar42;
    uVar14 = extraout_x1_19;
LAB_fffffe0009ac4208:
    ppppppppcVar28 = (char ********)0x1;
    plVar17 = local_188;
LAB_fffffe0009ac420c:
    auVar51._8_8_ = uVar14;
    auVar51._0_8_ = plVar17;
    if (plVar17 != (long *)0x0) {
      auVar51 = (**(code **)(*plVar17 + 0x28))();
    }
    ppppppppcVar44 = (char ********)fatal_failure_desc;
    if (ppppppppcVar40 != (char ********)0x0) {
      auVar51 = func_0xfffffe0008c3bf70
                          (&StaticPlatformPolicy<>::
                            check_signature(LazyPath*,int,cs_blob*,unsigned_int*,unsigned_int*,int,b ool,bool,unsigned_int,char**,unsigned_long*)
                            ::kalloc_type_view_2834,ppppppppcVar40);
    }
LAB_fffffe0009ac4248:
    ppppppppcVar13 = ppppppppcVar44;
    if (((uint)ppppppppcVar46 & (*cs_flags ^ 0xffffffff) & 0xfffff7fe) == 0) {
      *cs_flags = *cs_flags | 0x3300;
LAB_fffffe0009ac4280:
      if (ppppppppcVar12 != (char ********)0x0) {
        (*(code *)(*ppppppppcVar12)[1])(ppppppppcVar12);
      }
      if (*(long *)PTR_DAT_fffffe0007e6ba68 != local_78) {
        ppppppppcVar33 = (char ********)func_0xfffffe000854c1ec();
        return ppppppppcVar33;
      }
      return ppppppppcVar28;
    }
    _vnode_check_signature
              (auVar51._0_8_,auVar51._8_8_,uVar11,(cs_blob *)pcVar32,(uint *)ppppppppcVar33,
               (uint *)ppppppppcVar34,iVar6,uVar36,(char **)in_stack_fffffffffffffd90,
               (ulong *)in_stack_fffffffffffffd98);
LAB_fffffe0009ac44e4:
    func_0xfffffe00085a8e38(dyldSimCacheLock);
    uRamfffffe000be30880 = local_1e0[1];
    _dyldSimCache = *local_1e0;
    DAT_fffffe000be30888 = *(undefined4 *)(local_1e0 + 2);
    func_0xfffffe00085aa2e4(dyldSimCacheLock);
    uVar7 = 0x4004200;
    if ((local_18c & 0xff) == 0) {
      uVar7 = 0x4004000;
    }
    *cs_flags = *cs_flags | uVar7;
    pcVar24 = "macos-dyld_sim";
LAB_fffffe0009ac3acc:
    uVar7 = 1;
LAB_fffffe0009ac3ad4:
    setAndCheckValidationCategory((cs_blob *)local_1c0,uVar7,pcVar24);
LAB_fffffe0009ac3ad8:
    ppppppppcVar28 = (char ********)0x0;
    ppppppppcVar41 = ppppppppcVar40;
LAB_fffffe0009ac3ae0:
    ppppppppcVar33 = ppppppppcVar13;
    if ((local_1d0 == (long *)0x0) || (lVar16 = OSEntitlements::asDict(), lVar16 == 0)) {
      pcVar32 = (char *)emptyDictionary()::empty;
      if (emptyDictionary()::empty == (char ********)0x0) {
        pcVar32 = (char *)func_0xfffffe0008bcc220(local_1d0,1);
        emptyDictionary()::empty = (char ********)pcVar32;
      }
    }
    else {
      pcVar32 = (char *)OSEntitlements::asDict();
    }
    bVar4 = (local_18c & 0xff) != 0;
    ppppppppcVar34 = (char ********)(ulong)bVar4;
    ppppppppcVar40 = (char ********)(ulong)*cs_flags;
    pcVar24 = "dynamic";
    ppppppppcVar42 = ppppppppcVar46;
    in_stack_fffffffffffffd90 = (char *)local_1b0;
    in_stack_fffffffffffffd98 = (char ********)fatal_failure_desc_len;
    uVar7 = postValidation((LazyPath *)ppppppppcVar12,(cs_blob *)local_1c0,*cs_flags,
                           (OSDictionary *)pcVar32,(uchar)ppppppppcVar33,bVar4,(uint)ppppppppcVar46,
                           "dynamic",(char **)local_1b0,fatal_failure_desc_len);
    uVar7 = uVar7 ^ 1;
    ppppppppcVar44 = (char ********)(ulong)local_1b4;
    uVar14 = extraout_x1_13;
    ppppppppcVar49 = local_1b0;
LAB_fffffe0009ac407c:
    ppppppppcVar13 = ppppppppcVar44;
    ppppppppcVar48 = (char ********)fatal_failure_desc_len;
    ppppppppcVar21 = local_1c0;
    local_1a0 = (char ********)in_stack_fffffffffffffd90;
    if (uVar7 != 0) {
LAB_fffffe0009ac4084:
      ppppppppcVar28 = (char ********)0x1;
      pcVar39 = (cs_blob *)((ulong)local_198 & 0xffffffff);
      ppppppppcVar45 = ppppppppcVar46;
      fatal_failure_desc_len = (ulong *)ppppppppcVar48;
      fatal_failure_desc = (char **)ppppppppcVar49;
      goto LAB_fffffe0009ac2f0c;
    }
    pcVar39 = (cs_blob *)((ulong)local_198 & 0xffffffff);
    pcVar32 = (char *)ppppppppcVar28;
LAB_fffffe0009ac4090:
    iVar6 = macOSPolicyConfig::executionRequiresTrustCache();
    fatal_failure_desc = (char **)ppppppppcVar49;
    ppppppppcVar21 = local_1c0;
    if ((((ulong)ppppppppcVar44 & 1) == 0) && (iVar6 != 0)) {
      pcVar32 = "The system only allows binaries in the trust cache.\n";
      goto LAB_fffffe0009ac40cc;
    }
    iVar6 = macOSPolicyConfig::queryOverridableExecutionPolicyState();
    if (((uint)ppppppppcVar44 & 1 | (uint)(iVar6 != 1)) != 0) {
      uVar7 = *cs_flags;
      local_1a0 = (char ********)in_stack_fffffffffffffd90;
      if ((uVar7 >> 0x1a & 1) == 0) {
        uVar23 = macOSPolicyConfig::allowOnlyPlatformCode();
        if ((uVar23 & 1) != 0) {
          pcVar32 = 
          "The system only allows platform binaries, and the code is not a platform binary\n";
          goto LAB_fffffe0009ac40cc;
        }
        uVar7 = *cs_flags;
        local_1a0 = (char ********)in_stack_fffffffffffffd90;
      }
      *cs_flags = uVar7 | 0x20000000;
      ppppppppcVar33 = (char ********)(ulong)local_1d4;
      ppppppppcVar34 = (char ********)cs_flags;
      platformHardenFlagsIfNeeded
                ((LazyPath *)ppppppppcVar12,(int)local_188,(cs_blob *)local_1c0,
                 (OSEntitlements *)local_1d0,SUB41(local_1d4,0),cs_flags);
      ppppppppcVar40 = local_1c0;
      checkDebuggerStatus((OSEntitlements **)&local_170,cs_flags,(cs_blob *)local_1c0,
                          SUB81(pcVar32,0));
      ppppppppcVar28 = (char ********)0x0;
      uVar14 = extraout_x1_09;
      ppppppppcVar13 = ppppppppcVar44;
      ppppppppcVar45 = ppppppppcVar46;
      if (((*(byte *)((long)cs_flags + 3) >> 2 & 1) != 0) && (local_170 != (long *)0x0)) {
        OSEntitlements::markAsCSPlatform();
        ppppppppcVar28 = (char ********)0x0;
        uVar14 = extraout_x1_10;
      }
      goto LAB_fffffe0009ac2f0c;
    }
    pcVar32 = 
    "The system only allows binaries in the trust cache. Running other software requires authenticat ion.\n"
    ;
LAB_fffffe0009ac40cc:
    ppppppppcVar40 = (char ********)fatal_failure_desc_len;
    fatal_error_fmt((LazyPath *)ppppppppcVar12,(char **)ppppppppcVar49,fatal_failure_desc_len,
                    pcVar32);
    uVar14 = extraout_x1_21;
    local_1a0 = (char ********)in_stack_fffffffffffffd90;
  } while( true );
}

