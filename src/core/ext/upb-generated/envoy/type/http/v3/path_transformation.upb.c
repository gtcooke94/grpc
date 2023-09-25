/* This file was generated by upbc (the upb compiler) from the input
 * file:
 *
 *     envoy/type/http/v3/path_transformation.proto
 *
 * Do not edit -- your changes will be discarded when the file is
 * regenerated. */

#include <stddef.h>
#include "upb/generated_code_support.h"
#include "envoy/type/http/v3/path_transformation.upb.h"
#include "udpa/annotations/status.upb.h"
#include "validate/validate.upb.h"

// Must be last.
#include "upb/port/def.inc"

static const upb_MiniTableSub envoy_type_http_v3_PathTransformation_submsgs[1] = {
  {.submsg = &envoy_type_http_v3_PathTransformation_Operation_msg_init},
};

static const upb_MiniTableField envoy_type_http_v3_PathTransformation__fields[1] = {
  {1, 0, 0, 0, 11, (int)kUpb_FieldMode_Array | ((int)UPB_SIZE(kUpb_FieldRep_4Byte, kUpb_FieldRep_8Byte) << kUpb_FieldRep_Shift)},
};

const upb_MiniTable envoy_type_http_v3_PathTransformation_msg_init = {
  &envoy_type_http_v3_PathTransformation_submsgs[0],
  &envoy_type_http_v3_PathTransformation__fields[0],
  8, 1, kUpb_ExtMode_NonExtendable, 1, UPB_FASTTABLE_MASK(8), 0,
  UPB_FASTTABLE_INIT({
    {0x0000000000000000, &_upb_FastDecoder_DecodeGeneric},
    {0x000000003f00000a, &upb_prm_1bt_max64b},
  })
};

static const upb_MiniTableSub envoy_type_http_v3_PathTransformation_Operation_submsgs[2] = {
  {.submsg = &envoy_type_http_v3_PathTransformation_Operation_NormalizePathRFC3986_msg_init},
  {.submsg = &envoy_type_http_v3_PathTransformation_Operation_MergeSlashes_msg_init},
};

static const upb_MiniTableField envoy_type_http_v3_PathTransformation_Operation__fields[2] = {
  {2, UPB_SIZE(4, 8), -1, 0, 11, (int)kUpb_FieldMode_Scalar | ((int)UPB_SIZE(kUpb_FieldRep_4Byte, kUpb_FieldRep_8Byte) << kUpb_FieldRep_Shift)},
  {3, UPB_SIZE(4, 8), -1, 1, 11, (int)kUpb_FieldMode_Scalar | ((int)UPB_SIZE(kUpb_FieldRep_4Byte, kUpb_FieldRep_8Byte) << kUpb_FieldRep_Shift)},
};

const upb_MiniTable envoy_type_http_v3_PathTransformation_Operation_msg_init = {
  &envoy_type_http_v3_PathTransformation_Operation_submsgs[0],
  &envoy_type_http_v3_PathTransformation_Operation__fields[0],
  UPB_SIZE(8, 16), 2, kUpb_ExtMode_NonExtendable, 0, UPB_FASTTABLE_MASK(24), 0,
  UPB_FASTTABLE_INIT({
    {0x0000000000000000, &_upb_FastDecoder_DecodeGeneric},
    {0x0000000000000000, &_upb_FastDecoder_DecodeGeneric},
    {0x0008000002000012, &upb_pom_1bt_max64b},
    {0x000800000301001a, &upb_pom_1bt_max64b},
  })
};

const upb_MiniTable envoy_type_http_v3_PathTransformation_Operation_NormalizePathRFC3986_msg_init = {
  NULL,
  NULL,
  0, 0, kUpb_ExtMode_NonExtendable, 0, UPB_FASTTABLE_MASK(255), 0,
};

const upb_MiniTable envoy_type_http_v3_PathTransformation_Operation_MergeSlashes_msg_init = {
  NULL,
  NULL,
  0, 0, kUpb_ExtMode_NonExtendable, 0, UPB_FASTTABLE_MASK(255), 0,
};

static const upb_MiniTable *messages_layout[4] = {
  &envoy_type_http_v3_PathTransformation_msg_init,
  &envoy_type_http_v3_PathTransformation_Operation_msg_init,
  &envoy_type_http_v3_PathTransformation_Operation_NormalizePathRFC3986_msg_init,
  &envoy_type_http_v3_PathTransformation_Operation_MergeSlashes_msg_init,
};

const upb_MiniTableFile envoy_type_http_v3_path_transformation_proto_upb_file_layout = {
  messages_layout,
  NULL,
  NULL,
  4,
  0,
  0,
};

#include "upb/port/undef.inc"

