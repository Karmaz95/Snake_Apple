void _initializeAppleMobileFileIntegrity(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  ulong uVar5;
  long *plVar6;
  long lVar7;
  uint local_d4;
  ulong local_d0;
  undefined8 uStack_c8;
  undefined8 uStack_c0;
  undefined8 uStack_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 uStack_88;
  undefined8 uStack_80;
  undefined8 uStack_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 uStack_60;
  undefined8 uStack_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_38;
  
  local_38 = *(undefined8 *)PTR_DAT_fffffe0007e6ba68;
  uVar4 = func_0xfffffe0008c3cf30();
  func_0xfffffe00085a8e38();
  uVar5 = func_0xfffffe0008bbcd34(0,uVar4,&_driverLock);
  if ((uVar5 & 1) == 0) {
    return;
  }
  _AMFILockGroup = func_0xfffffe00085a8478("AMFI",0);
  initLibraryConstraints();
  _overrideUnrestrictedDebugging = 0;
  func_0xfffffe0008aa1474(&_sysctl__hw_features_allows_security_research);
  _allows_security_research = 0;
  uStack_48 = 0;
  local_50 = 0;
  uStack_68 = 0;
  local_70 = 0;
  uStack_58 = 0;
  uStack_60 = 0;
  uStack_88 = 0;
  local_90 = 0;
  uStack_78 = 0;
  uStack_80 = 0;
  uStack_a8 = 0;
  local_b0 = 0;
  local_98 = 0;
  uStack_a0 = 0;
  uStack_c8 = 0;
  local_d0 = 0;
  uStack_b8 = 0;
  uStack_c0 = 0;
  uVar4 = func_0xfffffe0009915f8c();
  iVar2 = func_0xfffffe0009910330(uVar4,&local_d0);
  if (iVar2 != 0) {
    func_0xfffffe0008da4510("\"AMFI: No chip from IMG4? errno: %d\" @%s:%d");
    return;
  }
  if ((uStack_a0._5_1_ != '\0') || ((int)local_98 == 1)) {
    _allows_security_research = 1;
  }
  local_d4 = 0;
  iVar2 = func_0xfffffe0008d70830("amfi_allow_research",&local_d4,4);
  if ((iVar2 != 0) && (local_d4 != 0)) {
    func_0xfffffe0008c3c908("AMFI: Allowing research due to amfi_allow_research boot arg");
    _allows_security_research = 1;
  }
  local_d0 = local_d0 & 0xffffffff00000000;
  iVar2 = func_0xfffffe0008a49ecc(8);
  if (iVar2 == 0) {
    local_d4 = 0;
    func_0xfffffe0008d70830("amfi",&local_d4,4);
    iVar2 = func_0xfffffe0008d70830("amfi_unrestrict_task_for_pid",&local_d0,4);
    if (((iVar2 != 0) && ((int)local_d0 != 0)) || ((local_d4 & 1) != 0)) {
      func_0xfffffe0008c3c908("%s: unrestricted task_for_pid enabled by boot-arg\n");
      _overrideUnrestrictedDebugging = 1;
      _BootedDevice = 1;
    }
    iVar2 = func_0xfffffe0008d70830("amfi_dev_mode_policy",&local_d0,4);
    if ((iVar2 != 0) && ((int)local_d0 != 0)) {
      func_0xfffffe0008c3c908("%s: developer mode internal policy disabled by boot-arg\n");
      DAT_fffffe0007e74790 = 1;
    }
    iVar2 = func_0xfffffe0008d70830("amfi_allow_any_signature",&local_d0,4);
    if (((iVar2 != 0) && ((int)local_d0 != 0)) || (((byte)local_d4 >> 1 & 1) != 0)) {
      func_0xfffffe0008c3c908("%s: signature enforcement disabled by boot-arg\n");
                    /* WARNING: Read-only address (ram,0xfffffe0007e7478b) is written */
      _DAT_fffffe0007e7478a = CONCAT11(DAT_fffffe0007e7478b,1);
    }
    iVar2 = func_0xfffffe0008d70830("amfi_get_out_of_my_way",&local_d0,4);
    if (((iVar2 != 0) && ((int)local_d0 != 0)) || ((local_d4 >> 7 & 1) != 0)) {
      func_0xfffffe0008c3c908("%s: signature enforcement disabled by boot-arg\n");
      _DAT_fffffe0007e7478a = 0x101;
    }
    if ((local_d4 >> 2 & 1) != 0) {
      func_0xfffffe0008c3c908
                ("%s: library validation will not mark external binaries as platform\n");
      DAT_fffffe0007e7478f = 1;
    }
    iVar2 = func_0xfffffe0008d70830("amfi_unrestricted_local_signing",&local_d0,4);
    if ((iVar2 != 0) && ((int)local_d0 != 0)) {
      func_0xfffffe0008c3c908("%s: unrestricted AMFI local signing enabled by boot-arg\n");
      DAT_fffffe0007e7478c = 1;
    }
  }
  iVar2 = func_0xfffffe0008d70830("amfi_ready_to_roll",&local_d0,4);
  if ((iVar2 != 0) && ((int)local_d0 != 0)) {
    func_0xfffffe0008c3c908("%s: practice a key roll\n");
    _readyToRoll = 1;
  }
  iVar2 = func_0xfffffe0008d70830("cs_enforcement_disable",&local_d0,4);
  bVar1 = (int)local_d0 != 0;
  if (iVar2 != 0 && bVar1) {
    func_0xfffffe0008c3c908("%s: cs_enforcement disabled by boot-arg\n");
    iVar3 = func_0xfffffe0008a49ecc(8);
    if (iVar3 != 0) goto LAB_fffffe0009ac1ba8;
  }
  DAT_fffffe0007e7478e = iVar2 != 0 && bVar1;
  InitializeDenylist();
  _initializeCoreEntitlementsSupport(1);
  precookExemptionProfile();
  numJitHashCacheEntries = 0;
  jitHashCache = 0;
  jitHashCacheLock = func_0xfffffe0008c3cf30();
  dyldSimCacheLock = func_0xfffffe0008c3cf30();
  supplementalSigningInit();
  _swiftPlaygroundsJIT = '\x01';
  plVar6 = (long *)func_0xfffffe0008c45154("/",*(undefined8 *)PTR_DAT_fffffe0007e6bb00,0,0,0);
  if (plVar6 == (long *)0x0) {
    _initializeAppleMobileFileIntegrity();
LAB_fffffe0009ac1ba0:
    _initializeAppleMobileFileIntegrity();
  }
  else {
    uVar4 = (**(code **)(*plVar6 + 0x2d8))(plVar6,"model");
    plVar6 = (long *)func_0xfffffe0008bbdca0(uVar4,*(undefined8 *)PTR_DAT_fffffe0007e6ba08);
    if (plVar6 == (long *)0x0) goto LAB_fffffe0009ac1ba0;
    uVar4 = (**(code **)(*plVar6 + 0x198))();
    func_0xfffffe0008c3c908("AMFI: queried model name from device tree: %s\n");
    lVar7 = func_0xfffffe00086ac444(uVar4,"iPhone",6);
    if (lVar7 == 0) {
      if (_swiftPlaygroundsJIT == '\0') goto LAB_fffffe0009ac17f4;
    }
    else {
      func_0xfffffe0008c3c908("AMFI: disabling Swift Playgrounds JIT services on iPhone devices\n");
      _swiftPlaygroundsJIT = '\0';
LAB_fffffe0009ac17f4:
      func_0xfffffe0008ab4fe8(0x10000000);
      func_0xfffffe0008ab4fe8(0x20000000);
    }
    _unrestrictedCDHashLock = func_0xfffffe0008c3cf30();
    initTrustCacheAccess();
    DAT_fffffe0007e747d0 = _cred_check_label_update_execve;
    DAT_fffffe0007e747f8 = _cred_label_associate;
    DAT_fffffe0007e74808 = _cred_label_destroy;
    DAT_fffffe0007e74820 = _cred_label_init;
    DAT_fffffe0007e74830 = _cred_label_update_execve;
    DAT_fffffe0007e74b58 = _proc_check_inherit_ipc_ports;
    DAT_fffffe0007e75120 = _vnode_check_signature;
    DAT_fffffe0007e749a0 = _file_check_library_validation;
    DAT_fffffe0007e74b40 = _policy_initbsd;
    DAT_fffffe0007e74b48 = _policy_syscall;
    DAT_fffffe0007e74ab8 = _task_id_token_get_task;
    DAT_fffffe0007e747f0 = _cred_label_associate_kernel;
    DAT_fffffe0007e748f8 = _proc_check_launch_constraints;
    DAT_fffffe0007e74ba0 = amfi_exc_action_check_exception_send;
    DAT_fffffe0007e74ba8 = amfi_exc_action_label_associate;
    DAT_fffffe0007e74bb0 = amfi_exc_action_label_populate;
    DAT_fffffe0007e74bb8 = amfi_exc_action_label_destroy;
    DAT_fffffe0007e74bc0 = amfi_exc_action_label_init;
    DAT_fffffe0007e74bc8 = amfi_exc_action_label_update;
    DAT_fffffe0007e74d88 = macos_task_get_movable_control_port;
    DAT_fffffe0007e75178 = hsp_proc_check_map_anon;
    DAT_fffffe0007e74aa8 = macos_task_policy;
    DAT_fffffe0007e74ab0 = macos_task_policy;
    DAT_fffffe0007e74c88 = macos_task_control_policy;
    DAT_fffffe0007e75138 = macos_proc_check_run_cs_invalid;
    DAT_fffffe0007e75040 = hook_vnode_check_setextattr;
    DAT_fffffe0007e74fc0 = hook_vnode_check_getextattr;
    DAT_fffffe0007e748c0 = _file_check_mmap;
    DAT_fffffe0007e751c0 = _vnode_notify_open;
    DAT_fffffe0007e74cf8 = core_dump_policy;
    DAT_fffffe0007e75158 = supplementalVnodeCheckSignature;
    mac_policy = "AMFI";
    DAT_fffffe0007e75220 = "Apple Mobile File Integrity";
    DAT_fffffe0007e75228 = &_initializeAppleMobileFileIntegrity()::labelnamespaces;
    DAT_fffffe0007e75230 = 1;
    DAT_fffffe0007e75238 = &mac_ops;
    DAT_fffffe0007e75240 = 0;
    DAT_fffffe0007e75248 = &_amfi_mac_slot;
    DAT_fffffe0007e75250 = 0;
    iVar2 = func_0xfffffe0008d75b64(&mac_policy,&amfiPolicyHandle,0);
    if (iVar2 == 0) {
      configurationSettingsInit();
      hardeningInit();
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  _initializeAppleMobileFileIntegrity();
LAB_fffffe0009ac1ba8:
  _initializeAppleMobileFileIntegrity();
  func_0xfffffe0008c3c908("%s\n");
  func_0xfffffe0008da4510("\"Cannot unload AMFI - policy is not dynamic\\n\" @%s:%d");
  return;
}