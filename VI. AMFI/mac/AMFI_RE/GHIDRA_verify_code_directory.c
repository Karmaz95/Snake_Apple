
ulong _verify_code_directory
                (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
                undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 *param_8,
                undefined4 *param_9,undefined4 *param_10,undefined4 *param_11,undefined4 *param_12,
                undefined4 *param_13_00,undefined4 *param_13,undefined8 param_15_00,
                undefined8 *param_14,undefined8 *param_17,undefined4 *param_15,undefined8 *param_19)

{
  ulong uVar1;
  ulong uVar2;
  ulong uVar3;
  uint uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined auVar8 [16];
  int local_1128 [2];
  long local_1120;
  undefined local_1118 [8];
  undefined local_1110 [8];
  int local_1108;
  undefined4 uStack_1104;
  uint local_1100;
  undefined4 uStack_10fc;
  undefined8 local_10f8;
  undefined4 auStack_10f0 [7];
  undefined4 local_10d4;
  uint local_10cc;
  undefined8 auStack_10c8 [2];
  int aiStack_10b8 [1044];
  long local_68;
  
  auVar8 = (*DAT_fffffe0007e6bb38)();
  local_68 = *(long *)PTR_DAT_fffffe0007e6ba68;
  func_0xfffffe0008538b60(local_1128,0x10bc);
  local_1108 = (int)*(undefined8 *)PTR_DAT_fffffe0007e6b9d8;
  uStack_1104 = (undefined4)((ulong)*(undefined8 *)PTR_DAT_fffffe0007e6b9d8 >> 0x20);
  if (DAT_fffffe0007e6bb40 == 0) {
    uStack_10fc = func_0xfffffe0008599ccc(&local_10f8,auVar8._8_8_,0x400);
  }
  else {
    uStack_10fc = func_0xfffffe0008599d30(&local_10f8,auVar8._8_8_,0x400);
  }
  local_1100 = 0;
  uVar4 = uStack_10fc + 3U & 0xfffffffc;
  uVar2 = (ulong)uVar4;
  *(undefined8 *)((long)&local_10f8 + uVar2) = param_3;
  *(undefined4 *)((long)auStack_10f0 + uVar2) = param_4;
  *(undefined4 *)((long)auStack_10f0 + uVar2 + 4) = param_5;
  *(undefined4 *)((long)auStack_10f0 + uVar2 + 8) = param_6;
  *(undefined4 *)((long)auStack_10f0 + uVar2 + 0xc) = param_7;
  local_1118 = (undefined  [8])func_0xfffffe0008599cb0();
  local_1128[0] = 0x1513;
  local_1110 = (undefined  [8])0x3e800000000;
  local_1120 = auVar8._0_8_;
  uVar2 = func_0xfffffe0008599758(local_1128,uVar4 + 0x48,0x10bc);
  uVar4 = (int)uVar2 + 0xeffffffe;
  if ((uVar4 < 0xf) && ((1 << (ulong)(uVar4 & 0x1f) & 0x4003U) != 0)) {
    func_0xfffffe0008599cc4(local_1118);
    goto LAB_fffffe0009acbbc8;
  }
  if ((int)uVar2 != 0) {
    func_0xfffffe0008599cbc(local_1118);
    goto LAB_fffffe0009acbbc8;
  }
  if (local_1110._4_4_ == 0x47) {
    uVar2 = 0xfffffecc;
  }
  else if (local_1110._4_4_ == 0x44c) {
    if (local_1128[0] < 0) {
      uVar2 = 0xfffffed4;
      if ((((local_1108 == 1) && (0x77 < (uint)local_1128[1])) && ((uint)local_1128[1] < 0x1079)) &&
         (local_1120 == 0)) {
        if ((uStack_10fc._3_1_ == '\x01') && (local_10cc < 0x1001)) {
          uVar2 = 0xfffffed4;
          if ((local_1128[1] - 0x78U < local_10cc) ||
             (uVar4 = local_10cc + 3 & 0xfffffffc, local_1128[1] != uVar4 + 0x78))
          goto LAB_fffffe0009acbbc0;
          uVar1 = (ulong)uVar4;
          if ((int)local_10f8 == *(int *)((long)aiStack_10b8 + uVar1 + 4)) {
            uVar3 = (ulong)(uint)local_1128[1] + 3 & 0x1fffffffc;
            if ((*(int *)((long)local_1128 + uVar3) == 0) &&
               (0x1f < *(uint *)((long)local_1128 + uVar3 + 4))) {
              *param_8 = auStack_10f0[1];
              *param_9 = auStack_10f0[2];
              *param_10 = auStack_10f0[3];
              *param_11 = auStack_10f0[4];
              *param_12 = auStack_10f0[5];
              *param_13_00 = auStack_10f0[6];
              *param_13 = local_10d4;
              func_0xfffffe0008599ccc(param_15_00,auStack_10c8,0x1000);
              uVar2 = 0;
              uVar6 = *(undefined8 *)((long)auStack_10c8 + uVar1 + 8);
              uVar5 = *(undefined8 *)((long)auStack_10c8 + uVar1);
              *(undefined4 *)(param_14 + 2) = *(undefined4 *)((long)aiStack_10b8 + uVar1);
              param_14[1] = uVar6;
              *param_14 = uVar5;
              *param_17 = CONCAT44(local_1100,uStack_1104);
              *param_15 = *(undefined4 *)((long)aiStack_10b8 + uVar1 + 4);
              uVar6 = *(undefined8 *)((long)&uStack_10fc + uVar3);
              uVar5 = *(undefined8 *)((long)&uStack_1104 + uVar3);
              uVar7 = *(undefined8 *)(local_1118 + uVar3 + 4);
              param_19[1] = *(undefined8 *)(local_1110 + uVar3 + 4);
              *param_19 = uVar7;
              param_19[3] = uVar6;
              param_19[2] = uVar5;
            }
            else {
              uVar2 = 0xfffffecb;
            }
            goto LAB_fffffe0009acbbc8;
          }
        }
LAB_fffffe0009acbbbc:
        uVar2 = 0xfffffed4;
      }
    }
    else {
      if (local_1128[1] != 0x2c) goto LAB_fffffe0009acbbbc;
      uVar2 = 0xfffffed4;
      if (local_1100 != 0) {
        uVar4 = local_1100;
        if (local_1120 != 0) {
          uVar4 = 0xfffffed4;
        }
        uVar2 = (ulong)uVar4;
      }
    }
  }
  else {
    uVar2 = 0xfffffed3;
  }
LAB_fffffe0009acbbc0:
  func_0xfffffe0008599b4c(local_1128);
LAB_fffffe0009acbbc8:
  if (*(long *)PTR_DAT_fffffe0007e6ba68 == local_68) {
    return uVar2;
  }
  uVar2 = func_0xfffffe000854c1ec();
  return uVar2;
}

