
/* macos_dyld_policy_collect_state(proc*, unsigned long long, amfi_dyld_policy_state_t*) */

void macos_dyld_policy_collect_state
               (proc *param_1,ulonglong param_2,amfi_dyld_policy_state_t *param_3)

{
  code *UNRECOVERED_JUMPTABLE;
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  long lVar4;
  uint uVar5;
  ulong unaff_x30;
  
  iVar1 = func_0xfffffe0008a49ecc(2);
  *(uint *)param_3 = *(uint *)param_3 & 0xfffffffe | (uint)(iVar1 != 0);
  uVar2 = func_0xfffffe0008a49850(param_1);
  uVar5 = (uint)param_2;
  *(uint *)param_3 = (uVar5 & 2 | uVar2 & 1) << 1 | *(uint *)param_3 & 0xfffffff9;
  uVar2 = func_0xfffffe0008a8d2a0(param_1);
  *(uint *)param_3 = *(uint *)param_3 & 0xfffffff0 | *(uint *)param_3 & 7 | (uVar2 & 1) << 3;
  uVar2 = func_0xfffffe0008a474c8(param_1);
  *(uint *)param_3 = *(uint *)param_3 & 0xffffffe0 | *(uint *)param_3 & 0xf | (uVar2 & 1) << 4;
  uVar2 = func_0xfffffe0008a47520(param_1);
  *(uint *)param_3 = *(uint *)param_3 & 0xffffffc0 | *(uint *)param_3 & 0x1f | (uVar2 & 1) << 5;
  uVar2 = func_0xfffffe0008a47fb0(param_1);
  *(uint *)param_3 = *(uint *)param_3 & 0xffffff80 | *(uint *)param_3 & 0x3f | (uVar2 & 1) << 6;
  iVar1 = func_0xfffffe0008a4986c(param_1);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = macOSPolicyConfig::hardeningEnabled();
    uVar2 = 0x80;
    if (iVar1 == 0) {
      uVar2 = 0;
    }
  }
  *(uint *)param_3 = *(uint *)param_3 & 0xffffff7f | uVar2;
  iVar1 = proc_has_entitlement(param_1,"com.apple.security.cs.allow-relative-library-loads");
  uVar2 = 0x100;
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  *(uint *)param_3 = *(uint *)param_3 & 0xfffffeff | uVar2;
  iVar1 = proc_has_entitlement(param_1,"com.apple.security.cs.allow-dyld-environment-variables");
  uVar2 = 0x200;
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  *(uint *)param_3 = *(uint *)param_3 & 0xfffffdff | uVar2;
  iVar1 = proc_has_get_task_allow(param_1);
  uVar2 = 0x400;
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  *(uint *)param_3 = uVar2 | (uVar5 & 1) << 0xb | *(uint *)param_3 & 0xfffff3ff;
  iVar1 = func_0xfffffe0008a49ecc(0x10);
  *(uint *)param_3 = (uVar5 & 4) << 0xb | (uint)(iVar1 == 0) << 0xc | *(uint *)param_3 & 0xffffcfff;
  iVar1 = proc_has_entitlement(param_1,"com.apple.security.app-sandbox");
  uVar2 = 0x4000;
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  *(uint *)param_3 = *(uint *)param_3 & 0xffffbfff | uVar2;
  lVar4 = func_0xfffffe0008a478e4(param_1);
  if (lVar4 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = func_0xfffffe0008a47a28();
    uVar2 = (uint)(iVar1 == 6) << 0xf;
  }
  *(uint *)param_3 = *(uint *)param_3 & 0xffff7fff | uVar2;
  iVar1 = func_0xfffffe0008a84714(param_1);
  *(uint *)param_3 =
       *(uint *)param_3 & 0xfffc0000 | *(uint *)param_3 & 0xffff | (uint)(iVar1 == 2) << 0x10;
  uVar2 = func_0xfffffe0008a473e4(param_1);
  *(uint *)param_3 =
       *(uint *)param_3 & 0xfff80000 | *(uint *)param_3 & 0x3ffff | (uVar2 & 1) << 0x12;
  iVar1 = func_0xfffffe0008a49ecc(4);
  *(uint *)param_3 =
       *(uint *)param_3 & 0xfff00000 | *(uint *)param_3 & 0x7ffff | (uint)(iVar1 == 0) << 0x13;
  lVar4 = func_0xfffffe0008a478e4(param_1);
  if (lVar4 == 0) {
    uVar2 = *(uint *)param_3 & 0xffefffff;
    *(uint *)param_3 = uVar2;
    uVar3 = 0;
  }
  else {
    *(uint *)param_3 = *(uint *)param_3 | 0x100000;
    uVar3 = func_0xfffffe0008a47ac8();
    uVar2 = *(uint *)param_3;
  }
  *(undefined4 *)(param_3 + 4) = uVar3;
  if ((uVar2 >> 0xc & 1) != 0) {
    iVar1 = proc_has_entitlement(param_1,"com.apple.security.amfi.test.mac-app-store-test");
    if (iVar1 != 0) {
      func_0xfffffe0008c3c908
                (
                "dyldPolicy: AppleInternal and com.apple.security.amfi.test.mac_app_store_test, masq uerading as app store\n"
                );
      *(uint *)param_3 = *(uint *)param_3 | 0x8000;
    }
    if (_BootedDevice != '\0') {
      *(uint *)param_3 = *(uint *)param_3 | 0x80000;
    }
  }
  if (((unaff_x30 ^ unaff_x30 << 1) >> 0x3e & 1) == 0) {
    logDyldPolicyData(param_1,param_2,param_3);
    return;
  }
                    /* WARNING: Treating indirect jump as call */
  UNRECOVERED_JUMPTABLE = (code *)SoftwareBreakpoint(0xc471,0xfffffe0009aca2c0);
  (*UNRECOVERED_JUMPTABLE)();
  return;
}

/* 
logDyldPolicyData():
  "dyldPolicy: (%d) (%s) in(%08llx) sip(%d) cs_restrict(%d) restrict_segment(%d) setugid (%d) lv(%d) forced_lv(%d) platform(%d) hardened(%d) arl(%d) aev(%d) gta(%d) sim(%d) ai (%d) fp(%d) request_sandbox(%d) is_mac_app_store(%d) is_ios_app(%d) unrestrict_task_for_pid(%d)\n");
*/