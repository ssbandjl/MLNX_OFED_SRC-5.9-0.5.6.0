# csv record types that can be parsed, same enum as in rdma-core providers/mlx5/dr_dbg.c
DR_DUMP_REC_TYPE_DOMAIN_OBJS = "30"
DR_DUMP_REC_TYPE_DOMAIN = "3000"
DR_DUMP_REC_TYPE_DOMAIN_INFO_FLEX_PARSER = "3001"
DR_DUMP_REC_TYPE_DOMAIN_INFO_DEV_ATTR = "3002"
DR_DUMP_REC_TYPE_DOMAIN_INFO_VPORT = "3003"
DR_DUMP_REC_TYPE_DOMAIN_INFO_CAPS = "3004"
DR_DUMP_REC_TYPE_DOMAIN_SEND_RING = "3005"

DR_DUMP_REC_TYPE_TABLE_OBJS = "31"
DR_DUMP_REC_TYPE_TABLE = "3100"
DR_DUMP_REC_TYPE_TABLE_RX = "3101"
DR_DUMP_REC_TYPE_TABLE_TX = "3102"

DR_DUMP_REC_TYPE_MATCHER_OBJS = "32"
DR_DUMP_REC_TYPE_MATCHER = "3200"
DR_DUMP_REC_TYPE_MATCHER_MASK = "3201"
DR_DUMP_REC_TYPE_MATCHER_RX = "3202"
DR_DUMP_REC_TYPE_MATCHER_TX = "3203"
DR_DUMP_REC_TYPE_MATCHER_BUILDER = "3204"
DR_DUMP_REC_TYPE_MATCHER_MASK_WITH_RESERVED = "3205"

DR_DUMP_REC_TYPE_RULE_OBJS = "33"
DR_DUMP_REC_TYPE_RULE = "3300"
DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V0 = "3301"
DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V0 = "3302"
DR_DUMP_REC_TYPE_RULE_RX_ENTRY_V1 = "3303"
DR_DUMP_REC_TYPE_RULE_TX_ENTRY_V1 = "3304"

DR_DUMP_REC_TYPE_ACTION_OBJS = "34"
DR_DUMP_REC_TYPE_ACTION_ENCAP_L2 = "3400"
DR_DUMP_REC_TYPE_ACTION_ENCAP_L3 = "3401"
DR_DUMP_REC_TYPE_ACTION_MODIFY_HDR = "3402"
DR_DUMP_REC_TYPE_ACTION_DROP = "3403"
DR_DUMP_REC_TYPE_ACTION_QP = "3404"
DR_DUMP_REC_TYPE_ACTION_FT = "3405"
DR_DUMP_REC_TYPE_ACTION_CTR = "3406"
DR_DUMP_REC_TYPE_ACTION_TAG = "3407"
DR_DUMP_REC_TYPE_ACTION_VPORT = "3408"
DR_DUMP_REC_TYPE_ACTION_DECAP_L2 = "3409"
DR_DUMP_REC_TYPE_ACTION_DECAP_L3 = "3410"
DR_DUMP_REC_TYPE_ACTION_DEVX_TIR = "3411"
DR_DUMP_REC_TYPE_ACTION_PUSH_VLAN = "3412"
DR_DUMP_REC_TYPE_ACTION_POP_VLAN = "3413"
DR_DUMP_REC_TYPE_ACTION_METER = "3414"
DR_DUMP_REC_TYPE_ACTION_SAMPLER = "3415"
DR_DUMP_REC_TYPE_ACTION_DEST_ARRAY = "3416"
DR_DUMP_REC_TYPE_ACTION_ASO_FIRST_HIT = "3417"
DR_DUMP_REC_TYPE_ACTION_ASO_FLOW_METER = "3418"
DR_DUMP_REC_TYPE_ACTION_ASO_CT = "3419"
DR_DUMP_REC_TYPE_ACTION_MISS = "3423"
DR_DUMP_REC_TYPE_ACTION_ROOT_FT = "3424"
DR_DUMP_REC_TYPE_ACTION_MATCH_RANGE = "3425"

DR_DUMP_REC_TYPE_PMD_ACTION_PKT_REFORMAT = "4410"
DR_DUMP_REC_TYPE_PMD_ACTION_MODIFY_HDR = "4420"
DR_DUMP_REC_TYPE_PMD_ACTION_COUNTER = "4430"

# View mode
DR_DUMP_VIEW_RULE = 0,
DR_DUMP_VIEW_TREE = 1,

# steering format version
MLX5_HW_CONNECTX_5 = 0x0
MLX5_HW_CONNECTX_6DX = 0x1

# STE V1 format
DR_STE_TYPE_BWC_BYTE = 0x0
DR_STE_TYPE_BWC_DW = 0x1
DR_STE_TYPE_MATCH = 0x4
DR_STE_TYPE_MATCH_RANGES = 0x7
DR_STE_TYPE_MATCH_OLD = 0x2

# STE V1 Lookup type is built from 2B: [ Definer mode 1B ][ Definer index 1B ]
DR_STE_V1_LU_TYPE_DONT_CARE = 0x000f
DR_STE_V1_LU_TYPE_ETHL2_HEADERS_I = 0x0106
DR_STE_V1_LU_TYPE_ETHL2_HEADERS_O = 0x0105
DR_STE_V1_LU_TYPE_ETHL2_I = 0x0004
DR_STE_V1_LU_TYPE_ETHL2_O = 0x0003
DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_I = 0x000c
DR_STE_V1_LU_TYPE_ETHL2_SRC_DST_O = 0x000b
DR_STE_V1_LU_TYPE_ETHL2_SRC_I = 0x0006
DR_STE_V1_LU_TYPE_ETHL2_SRC_O = 0x0005
DR_STE_V1_LU_TYPE_ETHL2_TNL = 0x0002
DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_I = 0x0008
DR_STE_V1_LU_TYPE_ETHL3_IPV4_5_TUPLE_O = 0x0007
DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_I = 0x000f
DR_STE_V1_LU_TYPE_ETHL3_IPV4_MISC_O = 0x000d
DR_STE_V1_LU_TYPE_ETHL4_I = 0x000a
DR_STE_V1_LU_TYPE_ETHL4_MISC_I = 0x0114
DR_STE_V1_LU_TYPE_ETHL4_MISC_O = 0x0113
DR_STE_V1_LU_TYPE_ETHL4_O = 0x0009
DR_STE_V1_LU_TYPE_FLEX_PARSER_0 = 0x0111
DR_STE_V1_LU_TYPE_FLEX_PARSER_1 = 0x0112
DR_STE_V1_LU_TYPE_FLEX_PARSER_TNL_HEADER = 0x000e
DR_STE_V1_LU_TYPE_GENERAL_PURPOSE = 0x010e
DR_STE_V1_LU_TYPE_GRE = 0x010d
DR_STE_V1_LU_TYPE_IBL3_EXT = 0x0102
DR_STE_V1_LU_TYPE_IBL4 = 0x0103
DR_STE_V1_LU_TYPE_INVALID = 0x00ff
DR_STE_V1_LU_TYPE_IPV6_DES_I = 0x0108
DR_STE_V1_LU_TYPE_IPV6_DES_O = 0x0107
DR_STE_V1_LU_TYPE_IPV6_SRC_I = 0x010a
DR_STE_V1_LU_TYPE_IPV6_SRC_O = 0x0109
DR_STE_V1_LU_TYPE_MPLS_I = 0x010c
DR_STE_V1_LU_TYPE_MPLS_O = 0x010b
DR_STE_V1_LU_TYPE_NOP = 0x0000
DR_STE_V1_LU_TYPE_SRC_QP_GVMI = 0x0104
DR_STE_V1_LU_TYPE_STEERING_REGISTERS_0 = 0x010f
DR_STE_V1_LU_TYPE_STEERING_REGISTERS_1 = 0x0110
DR_STE_V1_LU_TYPE_TNL_HEADER = 0x0117