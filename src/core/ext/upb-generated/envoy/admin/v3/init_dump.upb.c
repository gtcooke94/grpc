/* This file was generated by upbc (the upb compiler) from the input
 * file:
 *
 *     envoy/admin/v3/init_dump.proto
 *
 * Do not edit -- your changes will be discarded when the file is
 * regenerated. */

#include <stddef.h>
#include "upb/generated_code_support.h"
#include "envoy/admin/v3/init_dump.upb.h"
#include "udpa/annotations/status.upb.h"

// Must be last.
#include "upb/port/def.inc"

static const upb_MiniTableSub envoy_admin_v3_UnreadyTargetsDumps_submsgs[1] = {
  {.submsg = &envoy_admin_v3_UnreadyTargetsDumps_UnreadyTargetsDump_msg_init},
};

static const upb_MiniTableField envoy_admin_v3_UnreadyTargetsDumps__fields[1] = {
  {1, 0, 0, 0, 11, (int)kUpb_FieldMode_Array | ((int)UPB_SIZE(kUpb_FieldRep_4Byte, kUpb_FieldRep_8Byte) << kUpb_FieldRep_Shift)},
};

const upb_MiniTable envoy_admin_v3_UnreadyTargetsDumps_msg_init = {
  &envoy_admin_v3_UnreadyTargetsDumps_submsgs[0],
  &envoy_admin_v3_UnreadyTargetsDumps__fields[0],
  8, 1, kUpb_ExtMode_NonExtendable, 1, UPB_FASTTABLE_MASK(8), 0,
  UPB_FASTTABLE_INIT({
    {0x0000000000000000, &_upb_FastDecoder_DecodeGeneric},
    {0x000000003f00000a, &upb_prm_1bt_max64b},
  })
};

static const upb_MiniTableField envoy_admin_v3_UnreadyTargetsDumps_UnreadyTargetsDump__fields[2] = {
  {1, UPB_SIZE(4, 0), 0, kUpb_NoSub, 9, (int)kUpb_FieldMode_Scalar | ((int)kUpb_FieldRep_StringView << kUpb_FieldRep_Shift)},
  {2, UPB_SIZE(0, 16), 0, kUpb_NoSub, 9, (int)kUpb_FieldMode_Array | ((int)UPB_SIZE(kUpb_FieldRep_4Byte, kUpb_FieldRep_8Byte) << kUpb_FieldRep_Shift)},
};

const upb_MiniTable envoy_admin_v3_UnreadyTargetsDumps_UnreadyTargetsDump_msg_init = {
  NULL,
  &envoy_admin_v3_UnreadyTargetsDumps_UnreadyTargetsDump__fields[0],
  UPB_SIZE(16, 24), 2, kUpb_ExtMode_NonExtendable, 2, UPB_FASTTABLE_MASK(24), 0,
  UPB_FASTTABLE_INIT({
    {0x0000000000000000, &_upb_FastDecoder_DecodeGeneric},
    {0x000000003f00000a, &upb_pss_1bt},
    {0x001000003f000012, &upb_prs_1bt},
    {0x0000000000000000, &_upb_FastDecoder_DecodeGeneric},
  })
};

static const upb_MiniTable *messages_layout[2] = {
  &envoy_admin_v3_UnreadyTargetsDumps_msg_init,
  &envoy_admin_v3_UnreadyTargetsDumps_UnreadyTargetsDump_msg_init,
};

const upb_MiniTableFile envoy_admin_v3_init_dump_proto_upb_file_layout = {
  messages_layout,
  NULL,
  NULL,
  2,
  0,
  0,
};

#include "upb/port/undef.inc"

