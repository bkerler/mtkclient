#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License

# DXCC = Discretix CryptoCell

import logging
import hashlib
from struct import pack
from Cryptodome.Util.number import bytes_to_long
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from mtkclient.Library.gui_utils import LogBase, logsetup

Lcs = 0xA
KceSet = 0xB
Kce = 0xC  # CodeEncryptionKey
SASI_SB_HASH_BOOT_KEY_256B = 2  # 0x10
SASI_SB_HASH_BOOT_KEY_1_128B = 1  # 0x14
SASI_SW_VERSION_COUNTER1 = 1  # 0x18
SASI_SW_VERSION_COUNTER2 = 2  # 0x19

oem_pubk = "DACD8B5FDA8A766FB7BCAA43F0B16915" + \
           "CE7B47714F1395FDEBCF12A2D41155B0" + \
           "FB587A51FECCCB4DDA1C8E5EB9EB69B8" + \
           "6DAF2C620F6C2735215A5F22C0B6CE37" + \
           "7AA0D07EB38ED340B5629FC2890494B0" + \
           "78A63D6D07FDEACDBE3E7F27FDE4B143" + \
           "F49DB4971437E6D00D9E18B56F02DABE" + \
           "B0000B6E79516D0C8074B5A42569FD0D" + \
           "9196655D2A4030D42DFE05E9F64883E6" + \
           "D5F79A5BFA3E7014C9A62853DC1F21D5" + \
           "D626F4D0846DB16452187DD776E8886B" + \
           "48C210C9E208059E7CAFC997FD2CA210" + \
           "775C1A5D9AA261252FB975268D970C62" + \
           "733871D57814098A453DF92BC6CA1902" + \
           "5CD9D430F02EE46F80DE6C63EA802BEF" + \
           "90673AAC4C6667F2883FB4501FA77455"

huawei_med_lx9 = "C1A9D3E65C7EAEB31932E9DD224C07C0" + \
                 "70D879FB4FE518C64E92C24B79DC1EE1" + \
                 "535D91D38DD34D7E32A22DEED60F0727" + \
                 "FF8F8747E2598ACB5DDC73C61D2434A9" + \
                 "1D568FE3E773BD0D17AA46B0364E0DCF" + \
                 "3B41E0034605D572B6CD7DD8A816E7D6" + \
                 "84181B1646628576D1E22F55071687B9" + \
                 "E5B2F9C9536167B7EDCF10F1F85BE57B" + \
                 "6EE873BFE952BB33F0001140E0E46AF2" + \
                 "D64D39C568D8E372BCE3609BCACA5316" + \
                 "E4EBDDE5721B33611E064DF41A4BCF0A" + \
                 "3A395791D3203BF220DC71F4267093CE" + \
                 "B78E30A844D4631DE8CE6D0514202BB5" + \
                 "8AD2024B16558C2AD9B30CE05043FF67" + \
                 "C4D265A3D5F3275D93AFDC1A39625C2C" + \
                 "5BD6FDCDBD75E76E6D9E74E9672B5897"

buffer = bytearray(b"\x00" * 0x20C)
buffer[0:4] = pack("<I", 3)
buffer[4:8] = pack("<I", 256)
buffer[12:15] = b"\x01\x00\x01"
buffer[0x10C:0x20C] = bytes.fromhex(huawei_med_lx9)
huawei_oem_key = bytearray(hashlib.sha256(buffer).digest())

regval = {
    "DXCC_CON": 0x0000,
}

INT32_MAX = 0x7FFFFFFF

SB_AXI_ID = 0
AXI_SECURE = 0

HASH_MD5_DIGEST_SIZE_IN_BYTES = 16
HASH_SHA1_DIGEST_SIZE_IN_BYTES = 20
HASH_SHA224_DIGEST_SIZE_IN_BYTES = 28
HASH_SHA256_DIGEST_SIZE_IN_BYTES = 32
HASH_SHA384_DIGEST_SIZE_IN_BYTES = 48
HASH_SHA512_DIGEST_SIZE_IN_BYTES = 64

HASH_MD5_BLOCK_SIZE_IN_BYTES = 64
HASH_SHA1_BLOCK_SIZE_IN_BYTES = 64
HASH_SHA224_BLOCK_SIZE_IN_BYTES = 64
HASH_SHA256_BLOCK_SIZE_IN_BYTES = 64
HASH_SHA384_BLOCK_SIZE_IN_BYTES = 128
HASH_SHA512_BLOCK_SIZE_IN_BYTES = 128

AES_BLOCK_SIZE_IN_BYTES = 16

AES_IV_SIZE_IN_BYTES = AES_BLOCK_SIZE_IN_BYTES

AES_CCM_NONCE_LENGTH_MIN = 7
AES_CCM_NONCE_LENGTH_MAX = 13

AES_CCM_TAG_LENGTH_MIN = 4
AES_CCM_TAG_LENGTH_MAX = 16
DES_IV_SIZE_IN_BYTES = 8

# Use constant counter ID and AXI ID
SB_COUNTER_ID = 0

# The AES block size in words and in bytes
AES_BLOCK_SIZE_IN_WORDS = 4

# The size of the IV or counter buffer
AES_IV_COUNTER_SIZE_IN_WORDS = AES_BLOCK_SIZE_IN_WORDS
AES_IV_COUNTER_SIZE_IN_BYTES = (AES_IV_COUNTER_SIZE_IN_WORDS * 4)

# The size of the AES KEY in words and bytes
AES_KEY_SIZE_IN_WORDS = AES_BLOCK_SIZE_IN_WORDS
AES_KEY_SIZE_IN_BYTES = (AES_KEY_SIZE_IN_WORDS * 4)

AES_Key128Bits_SIZE_IN_WORDS = AES_BLOCK_SIZE_IN_WORDS
AES_Key128Bits_SIZE_IN_BYTES = AES_BLOCK_SIZE_IN_BYTES
AES_Key256Bits_SIZE_IN_WORDS = 8
AES_Key256Bits_SIZE_IN_BYTES = (AES_Key256Bits_SIZE_IN_WORDS * 4)

# Hash IV+Length
HASH_DIGEST_SIZE_IN_WORDS = 8
HASH_DIGEST_SIZE_IN_BYTES = (HASH_DIGEST_SIZE_IN_WORDS * 4)
HASH_LENGTH_SIZE_IN_WORDS = 4
HASH_LENGTH_SIZE_IN_BYTES = (HASH_LENGTH_SIZE_IN_WORDS * 4)

# Offset, shift, size
AES_t = {
    "KEY_0_0": [0x400, 0x0, 0x20],
    "KEY_0_1": [0x404, 0x0, 0x20],
    "KEY_0_2": [0x408, 0x0, 0x20],
    "KEY_0_3": [0x40C, 0x0, 0x20],
    "KEY_0_4": [0x410, 0x0, 0x20],
    "KEY_0_5": [0x414, 0x0, 0x20],
    "KEY_0_6": [0x418, 0x0, 0x20],
    "KEY_0_7": [0x41C, 0x0, 0x20],
    "IV_0_0": [0x440, 0x0, 0x20],
    "IV_0_1": [0x444, 0x0, 0x20],
    "IV_0_2": [0x448, 0x0, 0x20],
    "IV_0_3": [0x44C, 0x0, 0x20],
    "CTR_0_0": [0x460, 0x0, 0x20],
    "CTR_0_1": [0x464, 0x0, 0x20],
    "CTR_0_2": [0x468, 0x0, 0x20],
    "CTR_0_3": [0x46C, 0x0, 0x20],
    "BUSY": [0x470, 0x0, 0x1],
    "SK": [0x478, 0x0, 0x1],
    "CMAC_INIT": [0x47C, 0x0, 0x1],
    "PREV_IV_0_0": [0x490, 0x0, 0x20],
    "PREV_IV_0_1": [0x494, 0x0, 0x20],
    "PREV_IV_0_2": [0x498, 0x0, 0x20],
    "PREV_IV_0_3": [0x49C, 0x0, 0x20],
    "REMAINING_BYTES": [0x4BC, 0x0, 0x20],
    "CONTROL": [0x4C0,
                {"DEC_KEY0": [0x0, 0x1],
                 "MODE0_IS_CBC_CTS": [0x1, 0x1],
                 "MODE_KEY0": [0x2, 0x3],
                 "MODE_KEY1": [0x5, 0x3],
                 "AES_TUNNEL_IS_ON": [0xa, 0x1],
                 "NK_KEY0": [0xc, 0x2],
                 "NK_KEY1": [0xe, 0x2],
                 "AES_TUNNEL1_DECRYPT": [0x16, 0x1],
                 "AES_TUN_B1_USES_PADDED_DATA_IN": [0x17, 0x1],
                 "AES_TUNNEL0_ENCRYPT": [0x18, 0x1],
                 "AES_OUTPUT_MID_TUNNEL_DATA": [0x19, 0x1],
                 "AES_TUNNEL_B1_PAD_EN": [0x1a, 0x1],
                 "AES_OUT_MID_TUN_TO_HASH": [0x1c, 0x1],
                 "AES_XOR_CRYPTOKEY": [0x1d, 0x1],
                 "DIRECT_ACCESS": [0x1f, 0x1]}
                ],
    "HW_FLAGS": [0x4C8,
                 {"SUPPORT_256_192_KEY": [0x0, 0x1],
                  "AES_LARGE_RKEK": [0x1, 0x1],
                  "DPA_CNTRMSR_EXIST": [0x2, 0x1],
                  "CTR_EXIST": [0x3, 0x1],
                  "ONLY_ENCRYPT": [0x4, 0x1],
                  "USE_SBOX_TABLE": [0x5, 0x1],
                  "USE_5_SBOXES": [0x8, 0x1],
                  "AES_SUPPORT_PREV_IV": [0x9, 0x1],
                  "AES_TUNNEL_EXISTS": [0xa, 0x1],
                  "SECOND_REGS_SET_EXIST": [0xb, 0x1],
                  "DFA_CNTRMSR_EXIST": [0xc, 0x1]}
                 ],
    "XEX_HW_T_CALC_KICK": [0x4cc, 0x0, 0x1],
    "XEX_HW_T_CALC_IS_ON": [0x4d4, 0x0, 0x2],
    "CTR_NO_INCREMENT": [0x4d8, 0x0, 0x1],
    "SW_RESET": [0x4f4, 0x0, 0x1],
    "XEX_HW_T_CALC_KEY_0": [0x500, 0x0, 0x20],
    "XEX_HW_T_CALC_KEY_1": [0x504, 0x0, 0x20],
    "XEX_HW_T_CALC_KEY_2": [0x508, 0x0, 0x20],
    "XEX_HW_T_CALC_KEY_3": [0x50c, 0x0, 0x20],
    "XEX_HW_T_CALC_KEY_4": [0x510, 0x0, 0x20],
    "XEX_HW_T_CALC_KEY_5": [0x514, 0x0, 0x20],
    "XEX_HW_T_CALC_KEY_6": [0x518, 0x0, 0x20],
    "XEX_HW_T_CALC_KEY_7": [0x51c, 0x0, 0x20],
    "DATA_UNIT": [0x520, 0x0, 0x20],
    "AES_CMAC_SIZE0_KICK": [0x524, 0x0, 0x1],
}

MISC = {
    "AES_CLK_ENABLE": [0x810, 0x0, 0x1],
    "DES_CLK_ENABLE": [0x814, 0x0, 0x1],
    "HASH_CLK_ENABLE": [0x818, 0x0, 0x1],
    "PKA_CLK_ENABLE": [0x81c, 0x0, 0x1],
    "DMA_CLK_ENABLE": [0x820, 0x0, 0x1],
    "CLK_STATUS": [0x824,
                   {"AES_CLK_STATUS": [0x0, 0x1],
                    "DES_CLK_STATUS": [0x1, 0x1],
                    "HASH_CLK_STATUS": [0x2, 0x1],
                    "PKA_CLK_STATUS": [0x3, 0x1],
                    "RC4_CLK_STATUS": [0x4, 0x1],
                    "C2_CLK_STATUS": [0x7, 0x1],
                    "DMA_CLK_STATUS": [0x8, 0x1]}
                   ],
    "RC4_CLK_ENABLE": [0x854, 0x0, 0x1],
    "MTI2_CLK_ENABLE": [0x858, 0x0, 0x1],
}

CC_CTL = {
    "CRYPTO_CTL": [0x900, 0x0, 0x5],
    "CRYPTO_BUSY": [0x910, 0x0, 0x1],
    "HASH_BUSY": [0x91c, 0x0, 0x1],
    "VERSION": [0x928, 0x0, 0x20],
    "CONTEXT_ID": [0x930, 0x0, 0x8],
    "HASH_COMPARE_ERR_ID_FIFO0": [0x940, 0x0, 0x1a],
    "HASH_COMPARE_ERR_ID_FIFO1": [0x944, 0x0, 0x1a],
    "HASH_COMPARE_ERR_ID_FIFO2": [0x948, 0x0, 0x1a],
    "HASH_COMPARE_ERR_ID_FIFO3": [0x94c, 0x0, 0x1a]
}

DIN = {
    "DIN_BUFFER": [0xc00, 0x0, 0x20],
    "DIN_MEM_DMA_BUSY": [0xc20, 0x0, 0x1],
    "SRC_LLI_SRAM_ADDR": [0xc24, 0x0, 0xf],
    "SRC_LLI_WORD0": [0xc28, 0x0, 0x20],
    "SRC_LLI_WORD1": [0xC2C,
                      {"BYTES_NUM": [0x0, 0x1e],
                       "FIRST": [0x1e, 0x1],
                       "LAST": [0x1f, 0x1]}
                      ],
    "SRAM_SRC_ADDR": [0xc30, 0x0, 0x20],
    "DIN_SRAM_BYTES_LEN": [0xc34, 0x0, 0x20],
    "DIN_SRAM_DMA_BUSY": [0xc38, 0x0, 0x1],
    "DIN_SRAM_ENDIANNESS": [0xc3c, 0x0, 0x1],
    "AXI_CPU_DIN_PARAMS": [0xC40,
                           {"RDID": [0x0, 0x4],
                            "PROT": [0x8, 0x2]}
                           ],
    "DIN_SW_RESET": [0xc44, 0x0, 0x1],
    "DIN_CPU_DATA_SIZE": [0xc48, 0x0, 0x10],
    "WRITE_ALIGN_LAST": [0xc4c, 0x0, 0x1],
    "FIFO_IN_EMPTY": [0xc50, 0x0, 0x1],
    "DISABLE_OUTSTD_REQ": [0xc54, 0x0, 0x1],
    "DIN_FIFO_RST_PNTR": [0xc58, 0x0, 0x1],
}

DOUT = {
    "DOUT_BUFFER": [0xd00, 0x0, 0x20],
    "DOUT_MEM_DMA_BUSY": [0xd20, 0x0, 0x1],
    "DST_LLI_SRAM_ADDR": [0xd24, 0x0, 0xf],
    "DST_LLI_WORD0": [0xd28, 0x0, 0x20],
    "DST_LLI_WORD1": [0xD2C,
                      {"BYTES_NUM": [0x0, 0x1e],
                       "FIRST": [0x1e, 0x1],
                       "LAST": [0x1f, 0x1]}
                      ],
    "DOUT_SRAM_BYTES_LEN": [0xd34, 0x0, 0x20],
    "DOUT_SRAM_DMA_BUSY": [0xd38, 0x0, 0x1],
    "DOUT_SRAM_ENDIANNESS": [0xd3c, 0x0, 0x1],
    "READ_ALIGN_LAST": [0xd44, 0x0, 0x1],
    "FIFO_MODE": [0xd48, 0x0, 0x1],
    "DOUT_FIFO_EMPTY": [0xd50, 0x0, 0x1],
    "AXI_CPU_DOUT_PARAMS": [0xD54,
                            {"CACHE_TYPE": [0x0, 0x4],
                             "WRID": [0xc, 0x4],
                             "PROT": [0x10, 0x2],
                             "FORCE_CPU_PARAMS": [0x12, 0x1]}
                            ],
    "DOUT_SW_RESET": [0xd58, 0x0, 0x1]
}

DES = {
    "SRAM_DEST_ADDR": [0xd30, 0x0, 0x20],
    "DES_KEY_0": [0x208, 0x0, 0x20],
    "DES_KEY_1": [0x20c, 0x0, 0x20],
    "DES_KEY_2": [0x210, 0x0, 0x20],
    "DES_KEY_3": [0x214, 0x0, 0x20],
    "DES_KEY_4": [0x218, 0x0, 0x20],
    "DES_KEY_5": [0x21c, 0x0, 0x20],
    "DES_CONTROL_0": [0x220,
                      {"ENC": [0x0, 0x1],
                       "KEY_NUM": [0x1, 0x2],
                       "MODE": [0x3, 0x2]}
                      ],
    "DES_CONTROL_1": [0x224, 0x0, 0x20],
    "DES_IV_0": [0x228, 0x0, 0x20],
    "DES_IV_1": [0x22c, 0x0, 0x20],
    "DES_VERSION": [0x230,
                    {"FIXES": [0x0, 0x8],
                     "MINOR": [0x8, 0x4],
                     "MAJOR": [0xc, 0x4]}
                    ],
    "DES_RBG_INIT_VAL": [0x248, 0x0, 0x8],
    "DES_RBG_READY": [0x24c, 0x0, 0x1],
    "DES_BUSY": [0x270, 0x0, 0x1],
    "DES_SW_RESET": [0x280, 0x0, 0x1]
}

DSCRPTR = {
    "DSCRPTR_COMPLETION_COUNTER0": [0xE00,
                                    {"COMPLETION_COUNTER": [0x0, 0x6],
                                     "OVERFLOW_COUNTER": [0x6, 0x1]}
                                    ],
    "DSCRPTR_COMPLETION_COUNTER1": [0xE04,
                                    {"COMPLETION_COUNTER": [0x0, 0x6],
                                     "OVERFLOW_COUNTER": [0x6, 0x1]}
                                    ],
    "DSCRPTR_COMPLETION_STATUS": [0xe3c, 0x0, 0x2],
    "DSCRPTR_SW_RESET": [0xe40, 0x0, 0x1],
    "DSCRPTR_CNTX_SWITCH_COUNTER_VAL": [0xe44, 0x0, 0x20],
    "DSCRPTR_DISABLE_CNTX_SWITCH": [0xe48, 0x0, 0x1],
    "DSCRPTR_DEBUG_MODE": [0xe4c, 0x0, 0x1],
    "DSCRPTR_FILTER_DROPPED_CNT": [0xe50, 0x0, 0x20],
    "DSCRPTR_FILTER_DROPPED_MEM_CNT": [0xe54, 0x0, 0x20],
    "DSCRPTR_FILTER_DEBUG": [0xe58, 0x0, 0x8],
    "DSCRPTR_FILTER_DROPPED_ADDRESS": [0xe5c, 0x0, 0x20],
    "DSCRPTR_QUEUE_SRAM_SIZE": [0xe60, 0x0, 0xa],
    "DSCRPTR_SINGLE_ADDR_EN": [0xe64, 0x0, 0x1],
    "DSCRPTR_MEASURE_CNTR": [0xe68, 0x0, 0x20],
    "DSCRPTR_FILTER_DROPPED_ADDRESS_HIGH": [0xe6c, 0x0, 0x10],
    "DSCRPTR_QUEUE0_WORD0": [0xe80, 0x0, 0x20],
    "DSCRPTR_QUEUE0_WORD1": [0xE84,
                             {"DIN_DMA_MODE": [0x0, 0x2],
                              "DIN_SIZE": [0x2, 0x18],
                              "NS_BIT": [0x1a, 0x1],
                              "DIN_CONST_VALUE": [0x1b, 0x1],
                              "NOT_LAST": [0x1c, 0x1],
                              "LOCK_QUEUE": [0x1d, 0x1],
                              "DIN_VIRTUAL_HOST": [0x1e, 0x2]}
                             ],
    "DSCRPTR_QUEUE0_WORD2": [0xe88, 0x0, 0x20],
    "DSCRPTR_QUEUE0_WORD3": [0xE8C,
                             {"DOUT_DMA_MODE": [0x0, 0x2],
                              "DOUT_SIZE": [0x2, 0x18],
                              "NS_BIT": [0x1a, 0x1],
                              "DOUT_LAST_IND": [0x1b, 0x1],
                              "HASH_XOR_BIT": [0x1d, 0x1],
                              "DOUT_VIRTUAL_HOST": [0x1e, 0x2]}
                             ],
    "DSCRPTR_QUEUE0_WORD4": [0xE90,
                             {"DATA_FLOW_MODE": [0x0, 0x6],
                              "AES_SEL_N_HASH": [0x6, 0x1],
                              "AES_XOR_CRYPTO_KEY": [0x7, 0x1],
                              "ACK_NEEDED": [0x8, 0x2],
                              "CIPHER_MODE": [0xa, 0x4],
                              "CMAC_SIZE0": [0xe, 0x1],
                              "CIPHER_DO": [0xf, 0x2],
                              "CIPHER_CONF0": [0x11, 0x2],
                              "CIPHER_CONF1": [0x13, 0x1],
                              "CIPHER_CONF2": [0x14, 0x2],
                              "KEY_SIZE": [0x16, 0x2],
                              "SETUP_OPERATION": [0x18, 0x4],
                              "DIN_SRAM_ENDIANNESS": [0x1c, 0x1],
                              "DOUT_SRAM_ENDIANNESS": [0x1d, 0x1],
                              "WORD_SWAP": [0x1e, 0x1],
                              "BYTES_SWAP": [0x1f, 0x1]}
                             ],
    "DSCRPTR_QUEUE0_WORD5": [0xE94,
                             {"DIN_ADDR_HIGH": [0x0, 0x10],
                              "DOUT_ADDR_HIGH": [0x10, 0x10]}
                             ],
    "DSCRPTR_QUEUE0_WATERMARK": [0xe98, 0x0, 0xa],
    "DSCRPTR_QUEUE0_CONTENT": [0xe9c, 0x0, 0xa],
    "DSCRPTR_QUEUE1_WORD0": [0xea0, 0x0, 0x20],
    "DSCRPTR_QUEUE1_WORD1": [0xEA4,
                             {"DIN_DMA_MODE": [0x0, 0x2],
                              "DIN_SIZE": [0x2, 0x18],
                              "NS_BIT": [0x1a, 0x1],
                              "DIN_CONST": [0x1b, 0x1],
                              "NOT_LAST": [0x1c, 0x1],
                              "LOCK_QUEUE": [0x1d, 0x1],
                              "DIN_VIRTUAL_HOST": [0x1e, 0x2]}
                             ],
    "DSCRPTR_QUEUE1_WORD2": [0xea8, 0x0, 0x20],
    "DSCRPTR_QUEUE1_WORD3": [0xEAC,
                             {"DOUT_DMA_MODE": [0x0, 0x2],
                              "DOUT_SIZE": [0x2, 0x18],
                              "NS_BIT": [0x1a, 0x1],
                              "DOUT_LAST_IND": [0x1b, 0x1],
                              "HASH_XOR_BIT": [0x1d, 0x1],
                              "DOUT_VIRTUAL_HOST": [0x1e, 0x2]}
                             ],
    "DSCRPTR_QUEUE1_WORD4": [0xEB0,
                             {"DATA_FLOW_MODE": [0x0, 0x6],
                              "AES_SEL_N_HASH": [0x6, 0x1],
                              "AES_XOR_CRYPTO_KEY": [0x7, 0x1],
                              "ACK_NEEDED": [0x8, 0x2],
                              "CIPHER_MODE": [0xa, 0x4],
                              "CMAC_SIZE0": [0xe, 0x1],
                              "CIPHER_DO": [0xf, 0x2],
                              "CIPHER_CONF0": [0x11, 0x2],
                              "CIPHER_CONF1": [0x13, 0x1],
                              "CIPHER_CONF2": [0x14, 0x2],
                              "KEY_SIZE": [0x16, 0x2],
                              "SETUP_OPERATION": [0x18, 0x4],
                              "DIN_SRAM_ENDIANNESS": [0x1c, 0x1],
                              "DOUT_SRAM_ENDIANNESS": [0x1d, 0x1],
                              "WORD_SWAP": [0x1e, 0x1],
                              "BYTES_SWAP": [0x1f, 0x1]}
                             ],
    "DSCRPTR_QUEUE1_WORD5": [0xEB4,
                             {"DIN_ADDR_HIGH": [0x0, 0x10],
                              "DOUT_ADDR_HIGH": [0x10, 0x10]}
                             ],
    "DSCRPTR_QUEUE1_WATERMARK": [0xeb8, 0x0, 0xa],
    "DSCRPTR_QUEUE1_CONTENT": [0xebc, 0x0, 0xa]
}

HASH = {
    "HASH_H0": [0x640, 0x0, 0x20],
    "HASH_H1": [0x644, 0x0, 0x20],
    "HASH_H2": [0x648, 0x0, 0x20],
    "HASH_H3": [0x64c, 0x0, 0x20],
    "HASH_H4": [0x650, 0x0, 0x20],
    "HASH_H5": [0x654, 0x0, 0x20],
    "HASH_H6": [0x658, 0x0, 0x20],
    "HASH_H7": [0x65c, 0x0, 0x20],
    "HASH_H8": [0x660, 0x0, 0x20],
    "FLUSH_AES_MAC_BUF": [0x680, 0x0, 0x1],
    "AUTO_HW_PADDING": [0x684, 0x0, 0x1],
    "LOAD_INIT_STATE": [0x694, 0x0, 0x1],
    "TRUNC_OUTPUT": [0x698, 0x0, 0x2],
    "DUMP_COMPARE_REST": [0x69c, 0x0, 0x1],
    "DUMP_TO_DOUT": [0x6a0, 0x0, 0x1],
    "HASH_SEL_AES_MAC": [0x6a4, 0x0, 0x1],
    "HASH_H0_SAVED": [0x740, 0x0, 0x20],
    "HASH_H1_SAVED": [0x744, 0x0, 0x20],
    "HASH_H2_SAVED": [0x748, 0x0, 0x20],
    "HASH_H3_SAVED": [0x74c, 0x0, 0x20],
    "HASH_H4_SAVED": [0x750, 0x0, 0x20],
    "HASH_H5_SAVED": [0x754, 0x0, 0x20],
    "HASH_H6_SAVED": [0x758, 0x0, 0x20],
    "HASH_H7_SAVED": [0x75c, 0x0, 0x20],
    "HASH_H8_SAVED": [0x760, 0x0, 0x20],
    "HASH_VERSION": [0x7B0,
                     {"FIXES": [0x0, 0x8],
                      "MINOR_VERSION_NUMBER": [0x8, 0x4],
                      "MAJOR_VERSION_NUMBER": [0xc, 0x4]}
                     ],
    "HASH_CONTROL": [0x7C0,
                     {"MODE_0_1": [0x0, 0x2],
                      "MODE_3": [0x3, 0x1]}
                     ],
    "HASH_PAD_EN": [0x7c4, 0x0, 0x1],
    "HASH_PAD_CFG": [0x7c8, 0x2, 0x1],
    "HASH_CUR_LEN_0": [0x7cc, 0x0, 0x20],
    "HASH_CUR_LEN_1": [0x7d0, 0x0, 0x20],
    "HASH_PARAM": [0x7DC,
                   {"CW": [0x0, 0x4],
                    "CH": [0x4, 0x4],
                    "DW": [0x8, 0x4],
                    "SHA_512_EXISTS": [0xc, 0x1],
                    "PAD_EXISTS": [0xd, 0x1],
                    "MD5_EXISTS": [0xe, 0x1],
                    "HMAC_EXISTS": [0xf, 0x1],
                    "SHA_256_EXISTS": [0x10, 0x1],
                    "HASH_COMPARE_EXISTS": [0x11, 0x1],
                    "DUMP_HASH_TO_DOUT_EXISTS": [0x12, 0x1]}
                   ],
    "HASH_AES_SW_RESET": [0x7e4, 0x0, 0x1],
    "HASH_ENDIANESS": [0x7e8, 0x0, 0x1],
    "HASH_LOAD_DIGEST": [0x7fc, 0x0, 0x1]
}

AXI = {
    "AXIM_MON_INFLIGHT0": [0xb00, 0x0, 0x8],
    "AXIM_MON_INFLIGHT1": [0xb04, 0x0, 0x8],
    "AXIM_MON_INFLIGHT2": [0xb08, 0x0, 0x8],
    "AXIM_MON_INFLIGHT3": [0xb0c, 0x0, 0x8],
    "AXIM_MON_INFLIGHT4": [0xb10, 0x0, 0x8],
    "AXIM_MON_INFLIGHT5": [0xb14, 0x0, 0x8],
    "AXIM_MON_INFLIGHT8": [0xb20, 0x0, 0x8],
    "AXIM_MON_INFLIGHT9": [0xb24, 0x0, 0x8],
    "AXIM_MON_INFLIGHT10": [0xb28, 0x0, 0x8],
    "AXIM_MON_INFLIGHT11": [0xb2c, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST0": [0xb40, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST1": [0xb44, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST2": [0xb48, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST3": [0xb4c, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST4": [0xb50, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST5": [0xb54, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST8": [0xb60, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST9": [0xb64, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST10": [0xb68, 0x0, 0x8],
    "AXIM_MON_INFLIGHTLAST11": [0xb6c, 0x0, 0x8],
    "AXIM_PIDTABLE0": [0xB70,
                       {"PID_BROKEN1": [0x0, 0x1],
                        "PID_BROKEN2": [0x1, 0x1],
                        "PID_OSCNTR": [0x2, 0x8],
                        "PID_ID": [0xa, 0x5]}
                       ],
    "AXIM_PIDTABLE1": [0xB74,
                       {"PID_BROKEN1": [0x0, 0x1],
                        "PID_BROKEN2": [0x1, 0x1],
                        "PID_OSCNTR": [0x2, 0x8],
                        "PID_ID": [0xa, 0x5]}
                       ],
    "AXIM_PIDTABLE2": [0xB78,
                       {"PID_BROKEN1": [0x0, 0x1],
                        "PID_BROKEN2": [0x1, 0x1],
                        "PID_OSCNTR": [0x2, 0x8],
                        "PID_ID": [0xa, 0x5]}
                       ],
    "AXIM_PIDTABLE3": [0xB7C,
                       {"PID_BROKEN1": [0x0, 0x1],
                        "PID_BROKEN2": [0x1, 0x1],
                        "PID_OSCNTR": [0x2, 0x8],
                        "PID_ID": [0xa, 0x5]}
                       ],
    "AXIM_MON_COMP0": [0xb80, 0x0, 0x10],
    "AXIM_MON_COMP1": [0xb84, 0x0, 0x10],
    "AXIM_MON_COMP2": [0xb88, 0x0, 0x10],
    "AXIM_MON_COMP3": [0xb8c, 0x0, 0x10],
    "AXIM_MON_COMP4": [0xb90, 0x0, 0x10],
    "AXIM_MON_COMP5": [0xb94, 0x0, 0x10],
    "AXIM_MON_COMP8": [0xba0, 0x0, 0x10],
    "AXIM_MON_COMP9": [0xba4, 0x0, 0x10],
    "AXIM_MON_COMP10": [0xba8, 0x0, 0x10],
    "AXIM_MON_COMP11": [0xbac, 0x0, 0x10],
    "AXIM_MON_RMAX": [0xbb4, 0x0, 0x20],
    "AXIM_MON_RMIN": [0xbb8, 0x0, 0x20],
    "AXIM_MON_WMAX": [0xbbc, 0x0, 0x20],
    "AXIM_MON_WMIN": [0xbc0, 0x0, 0x20],
    "AXIM_MON_ERR": [0xBC4,
                     {"BRESP": [0x0, 0x2],
                      "BID": [0x2, 0x4],
                      "RRESP": [0x10, 0x2],
                      "RID": [0x12, 0x4]}
                     ],
    "AXIM_RDSTAT": [0xbc8, 0x0, 0x4],
    "AXIM_RLATENCY": [0xbd0, 0x0, 0x20],
    "AXIM_RBURST": [0xbd4, 0x0, 0x20],
    "AXIM_WLATENCY": [0xbd8, 0x0, 0x20],
    "AXIM_WBURST": [0xbdc, 0x0, 0x20],
    "AXIM_CACHETYPE_CFG": [0xBE0,
                           {"ICACHE_ARCACHE": [0x0, 0x4],
                            "DCACHE_ARCACHE": [0x4, 0x4],
                            "DD_ARCACHE": [0x8, 0x4],
                            "NOT_USED0": [0xc, 0x4],
                            "ICACHE_AWCACHE": [0x10, 0x4],
                            "DCACHE_AWCACHE": [0x14, 0x4],
                            "DD_AWCACHE": [0x18, 0x4],
                            "NOT_USED1": [0x1c, 0x4]}
                           ],
    "AXIM_PROT_CFG": [0xBE4,
                      {"ICACHE_ARPROT": [0x0, 0x2],
                       "DCACHE_ARPROT": [0x2, 0x2],
                       "DD_ARPROT": [0x4, 0x1],
                       "NOT_USED0": [0x5, 0x3],
                       "ICACHE_AWPROT": [0x8, 0x2],
                       "DCACHE_AWPROT": [0xa, 0x2],
                       "DD_AWPROT": [0xc, 0x1],
                       "NOT_USED1": [0xd, 0x3]}
                      ],
    "AXIM_CFG1": [0xBE8,
                  {"RD_AFTER_WR_STALL": [0x0, 0x4],
                   "BRESPMASK": [0x4, 0x1],
                   "RRESPMASK": [0x5, 0x1],
                   "INFLTMASK": [0x6, 0x1],
                   "COMPMASK": [0x7, 0x1],
                   "ACCUM_LIMIT": [0x10, 0x5]}
                  ],
    "AXIM_ACE_CONST": [0xBEC,
                       {"ARDOMAIN": [0x0, 0x2],
                        "AWDOMAIN": [0x2, 0x2],
                        "ARBAR": [0x4, 0x2],
                        "AWBAR": [0x6, 0x2],
                        "ARSNOOP": [0x8, 0x4],
                        "AWSNOOP_NOT_ALIGNED": [0xc, 0x3],
                        "AWSNOOP_ALIGNED": [0xf, 0x3],
                        "AWADDR_NOT_MASKED": [0x12, 0x7],
                        "AWLEN_VAL": [0x19, 0x4]}
                       ],
    "AXIM_CACHE_PARAMS": [0xBF0,
                          {"AWCACHE_LAST": [0x0, 0x4],
                           "AWCACHE": [0x4, 0x4],
                           "ARCACHE": [0x8, 0x4]}
                          ]
}


class DescDirection:
    DESC_DIRECTION_ILLEGAL = 0xFFFFFFFF
    DESC_DIRECTION_ENCRYPT_ENCRYPT = 0
    DESC_DIRECTION_DECRYPT_DECRYPT = 1
    DESC_DIRECTION_DECRYPT_ENCRYPT = 3
    DESC_DIRECTION_END = INT32_MAX


class SepEngineType:
    SEP_ENGINE_NULL = 0
    SEP_ENGINE_AES = 1
    SEP_ENGINE_DES = 2
    SEP_ENGINE_HASH = 3
    SEP_ENGINE_RC4 = 4
    SEP_ENGINE_DOUT = 5


class SepCryptoAlg:
    SEP_CRYPTO_ALG_NULL = 0xFFFFFFFF
    SEP_CRYPTO_ALG_AES = 0
    SEP_CRYPTO_ALG_DES = 1
    SEP_CRYPTO_ALG_HASH = 2
    SEP_CRYPTO_ALG_RC4 = 3
    SEP_CRYPTO_ALG_C2 = 4
    SEP_CRYPTO_ALG_HMAC = 5
    SEP_CRYPTO_ALG_AEAD = 6
    SEP_CRYPTO_ALG_BYPASS = 7
    SEP_CRYPTO_ALG_COMBINED = 8
    SEP_CRYPTO_ALG_NUM = 9
    SEP_CRYPTO_ALG_RESERVE32B = INT32_MAX


class SepCryptoDirection:
    SEP_CRYPTO_DIRECTION_NULL = 0xFFFFFFFF
    SEP_CRYPTO_DIRECTION_ENCRYPT = 0
    SEP_CRYPTO_DIRECTION_DECRYPT = 1
    SEP_CRYPTO_DIRECTION_DECRYPT_ENCRYPT = 3
    SEP_CRYPTO_DIRECTION_RESERVE32B = INT32_MAX


class SepCipherMode:
    SEP_CIPHER_NULL_MODE = 0xFFFFFFFF
    SEP_CIPHER_ECB = 0
    SEP_CIPHER_CBC = 1
    SEP_CIPHER_CTR = 2
    SEP_CIPHER_CBC_MAC = 3
    SEP_CIPHER_XTS = 4
    SEP_CIPHER_XCBC_MAC = 5
    SEP_CIPHER_OFB = 6
    SEP_CIPHER_CMAC = 7
    SEP_CIPHER_CCM = 8
    SEP_CIPHER_CBC_CTS = 11
    SEP_CIPHER_GCTR = 12
    SEP_CIPHER_RESERVE32B = INT32_MAX


class SepHashMode:
    SEP_HASH_NULL = 0xFFFFFFFF
    SEP_HASH_SHA1 = 0
    SEP_HASH_SHA256 = 1
    SEP_HASH_SHA224 = 2
    SEP_HASH_SHA512 = 3
    SEP_HASH_SHA384 = 4
    SEP_HASH_MD5 = 5
    SEP_HASH_CBC_MAC = 6
    SEP_HASH_XCBC_MAC = 7
    SEP_HASH_CMAC = 8
    SEP_HASH_MODE_NUM = 9
    SEP_HASH_RESERVE32B = INT32_MAX


class SepHashHwMode:
    SEP_HASH_HW_MD5 = 0
    SEP_HASH_HW_SHA1 = 1
    SEP_HASH_HW_SHA256 = 2
    SEP_HASH_HW_SHA224 = 10
    SEP_HASH_HW_SHA512 = 4
    SEP_HASH_HW_SHA384 = 12
    SEP_HASH_HW_GHASH = 6
    SEP_HASH_HW_RESERVE32B = INT32_MAX


class SepC2Mode:
    SEP_C2_NULL = 0xFFFFFFFF
    SEP_C2_ECB = 0
    SEP_C2_CBC = 1
    SEP_C2_RESERVE32B = INT32_MAX


class SepMulti2Mode:
    SEP_MULTI2_NULL = 0xFFFFFFFF
    SEP_MULTI2_ECB = 0
    SEP_MULTI2_CBC = 1
    SEP_MULTI2_OFB = 2
    SEP_MULTI2_RESERVE32B = INT32_MAX


class SepCryptoKeyType:
    SEP_USER_KEY = 0
    SEP_ROOT_KEY = 1
    SEP_PROVISIONING_KEY = 2
    SEP_SESSION_KEY = 3
    SEP_APPLET_KEY = 4
    SEP_END_OF_KEYS = INT32_MAX


class DmaMode:
    DMA_MODE_NULL = 0xFFFFFFFF
    NO_DMA = 0
    DMA_SRAM = 1
    DMA_DLLI = 2
    DMA_MLLI = 3


class FlowMode:
    FLOW_MODE_NULL = -1
    BYPASS = 0
    DIN_AES_DOUT = 1
    AES_to_HASH = 2
    AES_and_HASH = 3
    DIN_DES_DOUT = 4
    DES_to_HASH = 5
    DES_and_HASH = 6
    DIN_HASH = 7
    DIN_HASH_and_BYPASS = 8
    AESMAC_and_BYPASS = 9
    AES_to_HASH_and_DOUT = 10
    DIN_RC4_DOUT = 11
    DES_to_HASH_and_DOUT = 12
    AES_to_AES_to_HASH_and_DOUT = 13
    AES_to_AES_to_HASH = 14
    AES_to_HASH_and_AES = 15
    DIN_MULTI2_DOUT = 16
    DIN_AES_AESMAC = 17
    HASH_to_DOUT = 18
    S_DIN_to_AES = 32
    S_DIN_to_AES2 = 33
    S_DIN_to_DES = 34
    S_DIN_to_RC4 = 35
    S_DIN_to_MULTI2 = 36
    S_DIN_to_HASH = 37
    S_AES_to_DOUT = 38
    S_AES2_to_DOUT = 39
    S_RC4_to_DOUT = 41
    S_DES_to_DOUT = 42
    S_HASH_to_DOUT = 43
    SET_FLOW_ID = 44


class SetupOp:
    SETUP_LOAD_NOP = 0
    SETUP_LOAD_STATE0 = 1
    SETUP_LOAD_STATE1 = 2
    SETUP_LOAD_STATE2 = 3
    SETUP_LOAD_KEY0 = 4
    SETUP_LOAD_XEX_KEY = 5
    SETUP_WRITE_STATE0 = 8
    SETUP_WRITE_STATE1 = 9
    SETUP_WRITE_STATE2 = 10
    SETUP_WRITE_STATE3 = 11


class AesMacSelector:
    AES_SK = 1
    AES_CMAC_INIT = 2
    AES_CMAC_SIZE0 = 3


class HwCryptoKey:
    USER_KEY = 0
    ROOT_KEY = 1
    PROVISIONING_KEY = 2
    SESSION_KEY = 3
    RESERVED_KEY = 4
    PLATFORM_KEY = 5
    CUSTOMER_KEY = 6
    KFDE0_KEY = 7
    KFDE1_KEY = 9
    KFDE2_KEY = 10
    KFDE3_KEY = 11


class HwAesKeySize:
    AES_128_KEY = 0
    AES_192_KEY = 1
    AES_256_KEY = 2


class HwDesKeySize:
    DES_ONE_KEY = 0
    DES_TWO_KEYS = 1
    DES_THREE_KEYS = 2


"""

/* SeP context size */
#ifndef SEP_CTX_SIZE_LOG2
#if (SEP_SUPPORT_SHA > 256)
SEP_CTX_SIZE_LOG2 8
#else
SEP_CTX_SIZE_LOG2 7
#endif
#endif
SEP_CTX_SIZE (1<<SEP_CTX_SIZE_LOG2)
SEP_CTX_SIZE_WORDS (SEP_CTX_SIZE >> 2)

SEP_DES_IV_SIZE 8
SEP_DES_BLOCK_SIZE 8

SEP_DES_ONE_KEY_SIZE 8
SEP_DES_DOUBLE_KEY_SIZE 16
SEP_DES_TRIPLE_KEY_SIZE 24
SEP_DES_KEY_SIZE_MAX SEP_DES_TRIPLE_KEY_SIZE

SEP_AES_IV_SIZE 16
SEP_AES_IV_SIZE_WORDS (SEP_AES_IV_SIZE >> 2)

SEP_AES_BLOCK_SIZE 16
SEP_AES_BLOCK_SIZE_WORDS 4

SEP_AES_128_BIT_KEY_SIZE 16
SEP_AES_128_BIT_KEY_SIZE_WORDS	(SEP_AES_128_BIT_KEY_SIZE >> 2)
SEP_AES_192_BIT_KEY_SIZE 24
SEP_AES_192_BIT_KEY_SIZE_WORDS	(SEP_AES_192_BIT_KEY_SIZE >> 2)
SEP_AES_256_BIT_KEY_SIZE 32
SEP_AES_256_BIT_KEY_SIZE_WORDS	(SEP_AES_256_BIT_KEY_SIZE >> 2)
SEP_AES_KEY_SIZE_MAX			SEP_AES_256_BIT_KEY_SIZE
SEP_AES_KEY_SIZE_WORDS_MAX		(SEP_AES_KEY_SIZE_MAX >> 2)

SEP_MD5_DIGEST_SIZE 16
SEP_SHA1_DIGEST_SIZE 20
SEP_SHA224_DIGEST_SIZE 28
SEP_SHA256_DIGEST_SIZE 32
SEP_SHA256_DIGEST_SIZE_IN_WORDS 8
SEP_SHA384_DIGEST_SIZE 48
SEP_SHA512_DIGEST_SIZE 64

SEP_SHA1_BLOCK_SIZE 64
SEP_SHA1_BLOCK_SIZE_IN_WORDS 16
SEP_MD5_BLOCK_SIZE 64
SEP_MD5_BLOCK_SIZE_IN_WORDS 16
SEP_SHA224_BLOCK_SIZE 64
SEP_SHA256_BLOCK_SIZE 64
SEP_SHA256_BLOCK_SIZE_IN_WORDS 16
SEP_SHA1_224_256_BLOCK_SIZE 64
SEP_SHA384_BLOCK_SIZE 128
SEP_SHA512_BLOCK_SIZE 128

#if (SEP_SUPPORT_SHA > 256)
SEP_DIGEST_SIZE_MAX SEP_SHA512_DIGEST_SIZE
SEP_HASH_BLOCK_SIZE_MAX SEP_SHA512_BLOCK_SIZE /*1024b*/
#else /* Only up to SHA256 */
SEP_DIGEST_SIZE_MAX SEP_SHA256_DIGEST_SIZE
SEP_HASH_BLOCK_SIZE_MAX SEP_SHA256_BLOCK_SIZE /*512b*/
#endif

SEP_HMAC_BLOCK_SIZE_MAX SEP_HASH_BLOCK_SIZE_MAX

SEP_RC4_KEY_SIZE_MIN 1
SEP_RC4_KEY_SIZE_MAX 20
SEP_RC4_STATE_SIZE 264

SEP_C2_KEY_SIZE_MAX 16
SEP_C2_BLOCK_SIZE 8

SEP_MULTI2_SYSTEM_KEY_SIZE 		32
SEP_MULTI2_DATA_KEY_SIZE 		8
SEP_MULTI2_SYSTEM_N_DATA_KEY_SIZE 	(SEP_MULTI2_SYSTEM_KEY_SIZE + SEP_MULTI2_DATA_KEY_SIZE)
#define	SEP_MULTI2_BLOCK_SIZE					8
#define	SEP_MULTI2_IV_SIZE					8
#define	SEP_MULTI2_MIN_NUM_ROUNDS				8
#define	SEP_MULTI2_MAX_NUM_ROUNDS				128


SEP_ALG_MAX_BLOCK_SIZE SEP_HASH_BLOCK_SIZE_MAX

SEP_MAX_COMBINED_ENGINES 4

SEP_MAX_CTX_SIZE (max(sizeof(struct sep_ctx_rc4), sizeof(struct sep_ctx_cache_entry)))
"""


def hw_desc_init():
    return [0, 0, 0, 0, 0, 0]


def bitmask(mask_size):
    if mask_size < 32:
        return (1 << mask_size) - 1
    else:
        return 0xFFFFFFFF


def tovalue(value, bitsize, shift):
    v = value & (1 << bitsize) - 1
    return v << shift


def hw_desc_set_cipher_mode(p_desc, cipher_mode):
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD4"][1]["CIPHER_MODE"]
    p_desc[4] |= tovalue(cipher_mode, bitsize, shift)
    return p_desc


def hw_desc_set_cipher_config0(p_desc, cipher_config):
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD4"][1]["CIPHER_CONF0"]
    p_desc[4] |= tovalue(cipher_config, bitsize, shift)
    return p_desc


def hw_desc_set_cipher_config1(p_desc, cipher_config):
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD4"][1]["CIPHER_CONF1"]
    p_desc[4] |= tovalue(cipher_config, bitsize, shift)
    return p_desc


def hw_desc_set_setup_mode(p_desc, setup_mode):
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD4"][1]["SETUP_OPERATION"]
    p_desc[4] |= tovalue(setup_mode, bitsize, shift)
    return p_desc


def hw_desc_set_flow_mode(p_desc, flow_mode):
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD4"][1]["DATA_FLOW_MODE"]
    p_desc[4] |= tovalue(flow_mode, bitsize, shift)
    return p_desc


def hw_desc_set_dout_sram(p_desc, dout_adr, dout_size):
    v = DSCRPTR["DSCRPTR_QUEUE0_WORD2"]
    shift, bitsize = v[1], v[2]
    p_desc[2] |= tovalue((dout_adr & 0xFFFFFFFF), bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD3"][1]["DOUT_DMA_MODE"]
    p_desc[3] |= tovalue(DmaMode.DMA_SRAM, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD3"][1]["DOUT_SIZE"]
    p_desc[3] |= tovalue(dout_size, bitsize, shift)
    return p_desc


def hw_desc_set_dout_dlli(p_desc, dout_adr, dout_size, axi_ns, lastind):
    v = DSCRPTR["DSCRPTR_QUEUE0_WORD2"]
    shift, bitsize = v[1], v[2]
    p_desc[2] |= tovalue((dout_adr & 0xFFFFFFFF), bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD5"][1]["DOUT_ADDR_HIGH"]
    p_desc[5] |= tovalue((dout_adr >> 32 & 0xFFFFFFFF) << 16, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD3"][1]["DOUT_DMA_MODE"]
    p_desc[3] |= tovalue(DmaMode.DMA_DLLI, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD3"][1]["DOUT_SIZE"]
    p_desc[3] |= tovalue(dout_size, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD3"][1]["DOUT_LAST_IND"]
    p_desc[3] |= tovalue(lastind, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD3"][1]["NS_BIT"]
    p_desc[3] |= tovalue(lastind, bitsize, shift)
    return p_desc


def hw_desc_set_key_size_aes(p_desc, key_size):
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD4"][1]["KEY_SIZE"]
    p_desc[4] |= tovalue(((key_size >> 3) - 2), bitsize, shift)
    return p_desc


def hw_desc_set_din_sram(p_desc, din_adr, din_size):
    v = DSCRPTR["DSCRPTR_QUEUE0_WORD0"]
    shift, bitsize = v[1], v[2]
    p_desc[0] |= tovalue(din_adr & 0xFFFFFFFF, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_DMA_MODE"]
    p_desc[1] |= tovalue(DmaMode.DMA_SRAM, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_SIZE"]
    p_desc[1] |= tovalue(din_size, bitsize, shift)
    return p_desc


def hw_desc_set_din_const(p_desc, val, din_size):
    v = DSCRPTR["DSCRPTR_QUEUE0_WORD0"]
    shift, bitsize = v[1], v[2]
    p_desc[0] |= tovalue(val & 0xFFFFFFFF, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_CONST_VALUE"]
    p_desc[1] |= tovalue(1, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_DMA_MODE"]
    p_desc[1] |= tovalue(DmaMode.DMA_SRAM, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_SIZE"]
    p_desc[1] |= tovalue(din_size, bitsize, shift)
    return p_desc


def hw_desc_set_cipher_do(p_desc, cipher_do):
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD4"][1]["CIPHER_DO"]
    p_desc[4] |= tovalue(cipher_do, bitsize, shift)
    return p_desc


def hw_desc_set_din_nodma(p_desc, din_adr, din_size):
    v = DSCRPTR["DSCRPTR_QUEUE0_WORD0"]
    shift, bitsize = v[1], v[2]
    p_desc[0] |= tovalue(din_adr & 0xFFFFFFFF, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_DMA_MODE"]
    p_desc[1] |= tovalue(DmaMode.NO_DMA, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_SIZE"]
    p_desc[1] |= tovalue(din_size, bitsize, shift)
    return p_desc


def hw_desc_set_din_type(p_desc, dma_mode, din_adr, din_size, axi_id, axi_ns):
    v = DSCRPTR["DSCRPTR_QUEUE0_WORD0"]
    shift, bitsize = v[1], v[2]
    p_desc[0] |= tovalue(din_adr & 0xFFFFFFFF, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD5"][1]["DIN_ADDR_HIGH"]
    p_desc[5] |= tovalue(din_adr >> 32 & 0xFFFF, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_DMA_MODE"]
    p_desc[1] |= tovalue(dma_mode, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_SIZE"]
    p_desc[1] |= tovalue(din_size, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["DIN_VIRTUAL_HOST"]
    p_desc[1] |= tovalue(axi_id, bitsize, shift)
    shift, bitsize = DSCRPTR["DSCRPTR_QUEUE0_WORD1"][1]["NS_BIT"]
    p_desc[1] |= tovalue(axi_ns, bitsize, shift)
    return p_desc


class DxccReg:
    def __init__(self, setup):
        self.dxcc_base = setup.dxcc_base
        self.read32 = setup.read32
        self.write32 = setup.write32

    def __setattr__(self, key, value):
        if key in ("sej_base", "read32", "write32", "regval"):
            return super(DxccReg, self).__setattr__(key, value)
        if key in regval:
            addr = regval[key] + self.sej_base
            return self.write32(addr, value)
        else:
            return super(DxccReg, self).__setattr__(key, value)

    def __getattribute__(self, item):
        if item in ("sej_base", "read32", "write32", "regval"):
            return super(DxccReg, self).__getattribute__(item)
        if item in regval:
            addr = regval[item] + self.sej_base
            return self.read32(addr)
        else:
            return super(DxccReg, self).__getattribute__(item)


class Dxcc(metaclass=LogBase):
    DX_HOST_IRR = 0xA00
    DX_HOST_ICR = 0xA08  # DX_CC = (HOST_RGF, HOST_ICR)
    DX_DSCRPTR_QUEUE0_WORD0 = 0xE80
    DX_DSCRPTR_QUEUE0_WORD1 = 0xE84
    DX_DSCRPTR_QUEUE0_WORD2 = 0xE88
    DX_DSCRPTR_QUEUE0_WORD3 = 0xE8C
    DX_DSCRPTR_QUEUE0_WORD4 = 0xE90
    DX_DSCRPTR_QUEUE0_WORD5 = 0xE94
    DX_DSCRPTR_QUEUE0_CONTENT = 0xE9C
    DX_HOST_SEP_HOST_GPR0 = 0xA80  # DX_HOST_SEP_HOST_GPR0_REG_OFFSET
    DX_HOST_SEP_HOST_GPR1 = 0xA88
    DX_HOST_SEP_HOST_GPR2 = 0xA90
    DX_HOST_SEP_HOST_GPR3 = 0xA9C
    DX_HOST_SEP_HOST_GPR4 = 0xAA0

    def sb_hal_clear_interrupt_bit(self):
        self.write32(self.dxcc_base + self.DX_HOST_ICR, 4)

    def sb_crypto_wait(self):
        while True:
            value = self.read32(self.dxcc_base + self.DX_HOST_IRR)
            if value != 0:
                return value

    def sasi_paldmaunmap(self, value1):
        return

    @staticmethod
    def sasi_paldmamap(value1):
        # value2=value1
        return value1

    def sasi_sb_adddescsequence(self, data):
        while True:
            if self.read32(self.dxcc_base + self.DX_DSCRPTR_QUEUE0_CONTENT) << 0x1C != 0:
                break
        self.write32(self.dxcc_base + self.DX_DSCRPTR_QUEUE0_WORD0, data[0])
        self.write32(self.dxcc_base + self.DX_DSCRPTR_QUEUE0_WORD1, data[1])
        self.write32(self.dxcc_base + self.DX_DSCRPTR_QUEUE0_WORD2, data[2])
        self.write32(self.dxcc_base + self.DX_DSCRPTR_QUEUE0_WORD3, data[3])
        self.write32(self.dxcc_base + self.DX_DSCRPTR_QUEUE0_WORD4, data[4])
        self.write32(self.dxcc_base + self.DX_DSCRPTR_QUEUE0_WORD5, data[5])

    def __init__(self, setup, loglevel=logging.INFO, gui: bool = False):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger, loglevel, gui)
        self.hwcode = setup.hwcode
        self.dxcc_base = setup.dxcc_base
        self.read32 = setup.read32
        self.write32 = setup.write32
        self.writemem = setup.writemem
        self.da_payload_addr = setup.da_payload_addr

        self.reg = DxccReg(setup)

    def tzcc_clk(self, value):
        if value:
            if self.hwcode in [0x1209]:
                res = self.write32(0x10001084, 0x600)
            else:
                res = self.write32(0x1000108C, 0x18000000)
        else:
            if self.hwcode in [0x1209]:
                res = self.write32(0x10001080, 0x200)
            else:
                res = self.write32(0x10001088, 0x8000000)
        return res

    def generate_itrustee_fbe(self, key_sz=32, appid: bytes = b""):
        salt = b"TrustedCorekeymaster" + b"\x07" * 0x10 + appid
        return self.generate_aes_cmac(key_sz=key_sz, salt=salt)

    def generate_aes_cmac(self, key_sz=32, salt: bytes = b""):
        fdekey = b""
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        self.tzcc_clk(1)
        for ctr in range(0, key_sz // 16):
            seed = salt + pack("<B", ctr)
            paddr = self.sbrom_aes_cmac(1, 0x0, seed, 0x0, len(seed), dstaddr)
            for field in self.read32(paddr, 4):
                fdekey += pack("<I", field)
        self.tzcc_clk(0)
        return fdekey

    def generate_moto_rpmb(self):
        rpmb_ikey = bytearray(b"CCUSTOMM")
        rpmb_salt = bytearray(b"MOTO")
        for i in range(len(rpmb_ikey)):
            rpmb_ikey[i] = rpmb_ikey[i]
        for i in range(len(rpmb_salt)):
            rpmb_salt[i] = rpmb_salt[i]

        keylength = 0x10
        self.tzcc_clk(1)
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        rpmbkey = self.sbrom_key_derivation(1, rpmb_ikey, rpmb_salt, keylength, dstaddr)
        self.tzcc_clk(0)
        return rpmbkey

    def generate_rpmb(self, level=0):
        rpmb_ikey = bytearray(b"RPMB KEY")
        rpmb_salt = bytearray(b"SASI")
        for i in range(len(rpmb_ikey)):
            rpmb_ikey[i] = rpmb_ikey[i] + level
        for i in range(len(rpmb_salt)):
            rpmb_salt[i] = rpmb_salt[i] + level

        keylength = 0x20
        if level > 0:
            keylength = 0x10
        self.tzcc_clk(1)
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        rpmbkey = self.sbrom_key_derivation(1, rpmb_ikey, rpmb_salt, keylength, dstaddr)
        self.tzcc_clk(0)
        return rpmbkey

    def sasi_bsv_socid_compute(self):
        key = bytes.fromhex("49")
        salt = b"\x00" * 32
        keylength = 0x10
        self.tzcc_clk(1)
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        pubkey = self.sasi_bsv_pub_key_hash_get(SASI_SB_HASH_BOOT_KEY_256B)
        derivedkey = self.sbrom_key_derivation(1, key, salt, keylength, dstaddr)
        hash = hashlib.sha256(pubkey + derivedkey).digest()
        self.tzcc_clk(0)
        return hash

    def generate_rpmb_mitee(self):
        rpmb_ikey = bytes.fromhex("AD1AC6B4BDF4EDB7")
        rpmb_salt = bytes.fromhex("69EF6584")
        keylength = 0x10
        self.tzcc_clk(1)
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        rpmbkey = self.sbrom_key_derivation(1, rpmb_ikey, rpmb_salt, keylength, dstaddr)
        self.tzcc_clk(0)
        return rpmbkey

    def sasi_bsv_otp_word_read(self, otpAddress):
        if otpAddress > 0x24:
            return None
        while True:
            val = self.read32(self.dxcc_base + (0x2AF * 4)) & 1
            if val != 0:
                break
        self.write32(self.dxcc_base + (0x2A9 * 4), (4 * otpAddress) | 0x10000)
        while True:
            val = self.read32(self.dxcc_base + (0x2AD * 4)) & 1
            if val != 0:
                break
        res = self.read32(self.dxcc_base + (0x2AB * 4))
        return res

    def sasi_bsv_lcs_get(self):
        while True:
            val = self.read32(self.dxcc_base + (0x2AF * 4)) & 1
            if val != 0:
                break
        lcs = self.read32(self.dxcc_base + (0x2B5 * 4))
        if lcs != 1:
            if lcs != 5:
                return 0
            if self.read32(self.dxcc_base + (0x2B5 * 4)) & 0x100 != 0:
                return 0xB000002
            otp_word = self.sasi_bsv_otp_word_read(0xA)
            if self.read32(self.dxcc_base + (0x2B5 * 4)) & 0x100 != 0:
                if otp_word & 0xF0000 != 0x30000:
                    return 0xB000080
        if self.read32(self.dxcc_base + (0x2B5 * 4)) & 0x200 == 0:
            return 0
        return 0xB000003

    def sasi_bsv_pub_key_hash_get(self, keyindex=SASI_SB_HASH_BOOT_KEY_256B):
        if keyindex == SASI_SB_HASH_BOOT_KEY_256B:
            start = 0x10
            length = 0x8
        elif keyindex == SASI_SB_HASH_BOOT_KEY_1_128B:
            start = 0x14
            length = 0x4
        else:
            return None
        hashval = bytearray()
        for idx in range(start, start + length, 0x1):
            hashval.extend(int.to_bytes(self.sasi_bsv_otp_word_read(idx), 4, 'little'))
        return hashval

    def sbrom_decrypt_kcst(self):
        pdesc = hw_desc_init()
        pdesc[0] = 0
        pdesc[1] = 0x3FFC000
        pdesc[2] = 0
        pdesc[3] = 0
        pdesc[4] = 0
        pdesc[5] = 0
        self.sasi_sb_adddescsequence(pdesc)
        self.sb_hal_wait_desc_completion()

    def sbrom_aeslockenginekey(self):
        pdesc = hw_desc_init()
        pdesc[0] = 0
        pdesc[1] = 0x8000081
        pdesc[2] = 0
        pdesc[3] = 0
        pdesc[4] = 0x4801C20
        pdesc[5] = 0
        self.sasi_sb_adddescsequence(pdesc)
        self.sb_hal_wait_desc_completion()

    def sasi_bsv_customer_key_decrypt(self):
        plat_key = b"KEY PLAT"
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        salt = self.sasi_bsv_pub_key_hash_get(keyindex=SASI_SB_HASH_BOOT_KEY_256B)
        platkey = self.sbrom_key_derivation(HwCryptoKey.PLATFORM_KEY, plat_key, salt, 0x10, dstaddr)
        _ = platkey
        while True:
            val = self.read32(self.dxcc_base + 0xAF4) & 1
            if val != 0:
                break
        self.sbrom_decrypt_kcst()
        while True:
            val = self.read32(self.dxcc_base + 0xAF0) & 1
            if val != 0:
                break
        self.write32(self.dxcc_base + 0xAC0, 0)
        self.write32(self.dxcc_base + 0xAC4, 0)
        self.write32(self.dxcc_base + 0xAC8, 0)
        self.write32(self.dxcc_base + 0xACC, 0)
        self.sbrom_aeslockenginekey()

    def sasi_bsv_security_disable(self):
        lcs = self.sasi_bsv_lcs_get()
        if lcs == 7:
            return
        self.write32(self.dxcc_base + 0xAC0, 0)
        self.write32(self.dxcc_base + 0xAC4, 0)
        self.write32(self.dxcc_base + 0xAC8, 0)
        self.write32(self.dxcc_base + 0xACC, 0)
        self.write32(self.dxcc_base + 0xAD8, 1)

    def generate_provision_key(self):
        plat_key = b"KEY PLAT"
        prov_key = b"PROVISION KEY"
        self.tzcc_clk(1)
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        lcs = self.sasi_bsv_lcs_get()
        _ = lcs
        # salt = hashlib.sha256(bytes.fromhex(oem_pubk)).digest()
        salt = self.sasi_bsv_pub_key_hash_get(keyindex=SASI_SB_HASH_BOOT_KEY_256B)
        platkey = self.sbrom_key_derivation(HwCryptoKey.PLATFORM_KEY, plat_key, salt, 0x10, dstaddr)
        while True:
            val = self.read32(self.dxcc_base + 0xAF4) & 1
            if val != 0:
                break
        provkey = self.sbrom_key_derivation(HwCryptoKey.PROVISIONING_KEY, prov_key, salt, 0x10, dstaddr)
        self.write32(self.dxcc_base + 0xAC0, 0)
        self.write32(self.dxcc_base + 0xAC4, 0)
        self.write32(self.dxcc_base + 0xAC8, 0)
        self.write32(self.dxcc_base + 0xACC, 0)
        pdesc = hw_desc_init()
        pdesc[0] = 0
        pdesc[1] = 0x8000081
        pdesc[2] = 0
        pdesc[3] = 0
        pdesc[4] = 0x4801C20
        pdesc[5] = 0
        self.sasi_sb_adddescsequence(pdesc)
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        self.sb_hal_wait_desc_completion()
        # data=self.read32(0x200D90)
        self.tzcc_clk(0)
        return platkey, provkey

    def generate_sha256(self, data):
        dstaddr = self.da_payload_addr - 0x300
        if self.hwcode == 0x1129:
            dstaddr = 0x20F1000
        self.sbrom_sha256(_buffer=data, destaddr=dstaddr)
        result = bytearray()
        for field in self.read32(dstaddr, 8):
            result.extend(pack("<I", field))
        return result

    def sbrom_key_derivation(self, aeskeytype, label, salt, requestedlen, destaddr):
        result = bytearray()
        if aeskeytype > HwCryptoKey.PLATFORM_KEY or (1 << (aeskeytype - 1) & 0x17) == 0:
            return 0xF2000002
        if requestedlen > 0xFF or (requestedlen << 28) & 0xFFFFFFFF:
            return 0xF2000003
        if 0x0 >= len(label) > 0x20:
            return 0xF2000003
        bufferlen = len(salt) + 3 + len(label)
        iterlength = (requestedlen + 0xF) >> 4
        for i in range(0, iterlength):
            _buffer = pack("<B", i + 1) + label + b"\x00" + salt + pack("<B", (8 * requestedlen) & 0xFF)
            dstaddr = self.sbrom_aes_cmac(aeskeytype, 0x0, _buffer[:bufferlen], 0, bufferlen, destaddr)
            if dstaddr != 0:
                for field in self.read32(dstaddr, 4):
                    result.extend(pack("<I", field))
        return result

    def sbrom_aes_cmac(self, aes_key_type, internal_key, data_in, dma_mode, bufferlen, destaddr):
        sram_addr = destaddr
        iv_sram_addr = sram_addr
        input_sram_addr = iv_sram_addr + AES_IV_COUNTER_SIZE_IN_BYTES
        block_size = len(data_in) // 0x20 * 0x20
        output_sram_addr = input_sram_addr + block_size
        key_sram_addr = output_sram_addr + block_size
        p_internal_key = key_sram_addr
        if internal_key != 0:
            self.writemem(key_sram_addr, internal_key)
        if dma_mode != 0:
            dma_mode = dma_mode
        self.writemem(input_sram_addr, data_in[:bufferlen])
        if self.sbrom_aes_cmac_driver(aes_key_type, p_internal_key, input_sram_addr, dma_mode, bufferlen, sram_addr):
            return sram_addr
        return 0

    def sb_hal_init(self):
        return self.sb_hal_clear_interrupt_bit()

    def sb_hal_wait_desc_completion(self, destptr=0):
        data = []
        self.sb_hal_clear_interrupt_bit()
        val = self.sasi_paldmamap(0)
        data.append(0x0)  # 0
        data.append(0x8000011)  # 1 #DIN_DMA|DOUT_DMA|DIN_CONST
        data.append(destptr)  # 2
        data.append(0x8000012)  # 3
        data.append(0x100)  # 4
        data.append((destptr >> 32) << 16)  # 5
        self.sasi_sb_adddescsequence(data)
        while True:
            if self.sb_crypto_wait() & 4 != 0:
                break
        while True:
            value = self.read32(self.dxcc_base + 0xBA0)
            if value != 0:
                break
        if value == 1:
            self.sb_hal_clear_interrupt_bit()
            self.sasi_paldmaunmap(val)
            return 0
        else:
            return 0xF6000001

    def sbrom_aes_cmac_driver(self, aes_key_type, p_internal_key, p_data_in, dma_mode, block_size, p_data_out):
        iv_sram_addr = 0
        if aes_key_type == HwCryptoKey.ROOT_KEY:
            if (self.read32(self.dxcc_base + self.DX_HOST_SEP_HOST_GPR4) >> 1) & 1 == 1:
                key_size_in_bytes = 0x20  # SEP_AES_256_BIT_KEY_SIZE
            else:
                key_size_in_bytes = 0x10  # SEP_AES_128_BIT_KEY_SIZE
        else:
            key_size_in_bytes = 0x10  # SEP_AES_128_BIT_KEY_SIZE
        self.sb_hal_init()

        pdesc = hw_desc_init()
        pdesc = hw_desc_set_cipher_mode(pdesc, SepCipherMode.SEP_CIPHER_CMAC)  # desc[4]=0x1C00
        pdesc = hw_desc_set_cipher_config0(pdesc, DescDirection.DESC_DIRECTION_ENCRYPT_ENCRYPT)
        pdesc = hw_desc_set_key_size_aes(pdesc, key_size_in_bytes)  # desc[4]=0x801C00
        pdesc = hw_desc_set_din_sram(pdesc, iv_sram_addr, AES_IV_COUNTER_SIZE_IN_BYTES)
        pdesc = hw_desc_set_din_const(pdesc, 0, AES_IV_COUNTER_SIZE_IN_BYTES)  # desc[1]=0x8000041
        pdesc = hw_desc_set_flow_mode(pdesc, FlowMode.S_DIN_to_AES)  # desc[4]=0x801C20
        pdesc = hw_desc_set_setup_mode(pdesc, SetupOp.SETUP_LOAD_STATE0)  # desc[4]=0x1801C20
        # pdesc[1] |= 0x8000000 #
        self.sasi_sb_adddescsequence(pdesc)

        # Load key
        mdesc = hw_desc_init()
        if aes_key_type == HwCryptoKey.USER_KEY:
            key_sram_addr = p_internal_key
            mdesc = hw_desc_set_din_sram(mdesc, key_sram_addr, AES_Key128Bits_SIZE_IN_BYTES)
        mdesc = hw_desc_set_cipher_do(mdesc, aes_key_type)  # desc[4]=0x8000
        mdesc = hw_desc_set_cipher_mode(mdesc, SepCipherMode.SEP_CIPHER_CMAC)  # desc[4]=0x9C00
        mdesc = hw_desc_set_cipher_config0(mdesc, DescDirection.DESC_DIRECTION_ENCRYPT_ENCRYPT)
        mdesc = hw_desc_set_key_size_aes(mdesc, key_size_in_bytes)  # desc[4]=0x809C00
        mdesc = hw_desc_set_flow_mode(mdesc, FlowMode.S_DIN_to_AES)  # desc[4]=0x809C20
        mdesc = hw_desc_set_setup_mode(mdesc, SetupOp.SETUP_LOAD_KEY0)  # desc[4]=0x4809C20
        mdesc[4] |= ((aes_key_type >> 2) & 3) << 20
        self.sasi_sb_adddescsequence(mdesc)

        # Process input data
        rdesc = hw_desc_init()
        if dma_mode == DmaMode.DMA_SRAM:
            rdesc = hw_desc_set_din_sram(rdesc, p_data_in, block_size)
        else:
            rdesc = hw_desc_set_din_type(rdesc, DmaMode.DMA_DLLI, p_data_in, block_size, SB_AXI_ID,
                                         AXI_SECURE)  # desc[1]=0x3E, desc[0]=0x200E18
        rdesc = hw_desc_set_flow_mode(rdesc, FlowMode.DIN_AES_DOUT)  # desc[4]=1
        self.sasi_sb_adddescsequence(rdesc)

        if aes_key_type != HwCryptoKey.PROVISIONING_KEY:
            xdesc = hw_desc_init()
            xdesc = hw_desc_set_cipher_mode(xdesc, SepCipherMode.SEP_CIPHER_CMAC)  # desc[4]=0x1C00
            xdesc = hw_desc_set_cipher_config0(xdesc, DescDirection.DESC_DIRECTION_ENCRYPT_ENCRYPT)
            xdesc = hw_desc_set_setup_mode(xdesc, SetupOp.SETUP_WRITE_STATE0)  # desc[4]=0x8001C00
            xdesc = hw_desc_set_flow_mode(xdesc, FlowMode.S_AES_to_DOUT)  # desc[4]=0x8001C26
            if dma_mode == DmaMode.DMA_SRAM:
                xdesc = hw_desc_set_dout_sram(xdesc, p_data_out, AES_BLOCK_SIZE_IN_BYTES)
            else:
                xdesc = hw_desc_set_dout_dlli(xdesc, p_data_out, AES_BLOCK_SIZE_IN_BYTES, SB_AXI_ID,
                                              0)  # desc[2]=0x200E08, desc[3]=0x42
            # xdesc = hw_desc_set_din_sram(xdesc, 0, 0)
            xdesc = hw_desc_set_din_nodma(xdesc, 0, 0)
            self.sasi_sb_adddescsequence(xdesc)
        return self.sb_hal_wait_desc_completion() == 0

    @staticmethod
    def mtee_decrypt(data):
        key = bytes.fromhex("B936C14D95A99585073E5607784A51F7444B60D6BFD6110F76D004CCB7E1950E")
        skey = hashlib.sha256(key).digest()
        return AES.new(key=skey[:16], iv=skey[16:], mode=AES.MODE_CBC).decrypt(data)

    @staticmethod
    def descramble(data):
        key = bytes.fromhex("5C0E349A27DC46034C7B6744A378BD17")
        iv = bytes.fromhex("A0B0924686447109F2D51DCDDC93458A")
        ctr = Counter.new(128, initial_value=bytes_to_long(iv))
        return AES.new(key=key, counter=ctr, mode=AES.MODE_CTR).decrypt(data)

    def sbrom_sha256(self, _buffer, destaddr):  # TZCC_SHA256_Init
        dataptr = destaddr + 0x40
        ivptr = destaddr + 0x20
        outptr = destaddr
        self.writemem(0x1000108C, pack("<I", 0x18000000))
        iv = bytes.fromhex("19CDE05BABD9831F8C68059B7F520E513AF54FA572F36E3C85AE67BB67E6096A")
        self.writemem(ivptr, iv)
        self.writemem(dataptr, _buffer)
        self.sbrom_cryptoinitdriver(aesivptr=ivptr, cryptodrivermode=0)
        self.sbrom_cryptoupdate(inputptr=dataptr, outputptr=outptr, block_size=len(_buffer), islastblock=1,
                                cryptodrivermode=0, waitforcrypto=0)
        self.sbrom_cryptofinishdriver(outptr)
        self.writemem(0x10001088, pack("<I", 0x8000000))
        return 0

    def sbrom_cryptoinitdriver(self, aesivptr, cryptodrivermode):
        if cryptodrivermode & 0xFFFFFFFD == 0:
            # 0=v9
            # 1=0x820
            # 2=0
            # 3=0
            # 4=0x1000825
            # 5=v9>>32
            pdesc = hw_desc_init()
            pdesc = hw_desc_set_din_type(pdesc, DmaMode.DMA_DLLI, aesivptr, 0x20, SB_AXI_ID, AXI_SECURE)
            pdesc = hw_desc_set_flow_mode(pdesc, FlowMode.S_DIN_to_HASH)
            pdesc = hw_desc_set_cipher_mode(pdesc, SepHashHwMode.SEP_HASH_HW_SHA256)
            pdesc = hw_desc_set_setup_mode(pdesc, SetupOp.SETUP_LOAD_STATE0)
            self.sasi_sb_adddescsequence(pdesc)
            # 0=0
            # 1=0x8000041
            # 2=0
            # 3=0
            # 4=0x4000825
            # 5=0
            tdesc = hw_desc_init()
            tdesc = hw_desc_set_flow_mode(tdesc, FlowMode.S_DIN_to_HASH)
            tdesc = hw_desc_set_cipher_mode(tdesc, SepHashHwMode.SEP_HASH_HW_SHA256)
            tdesc = hw_desc_set_setup_mode(tdesc, SetupOp.SETUP_LOAD_KEY0)
            tdesc = hw_desc_set_din_const(tdesc, 0, 0x10)
            self.sasi_sb_adddescsequence(tdesc)
        if cryptodrivermode >= 1:
            mdesc = hw_desc_init()
            mdesc = hw_desc_set_cipher_mode(mdesc, SepCipherMode.SEP_CIPHER_CTR)
            mdesc = hw_desc_set_setup_mode(mdesc, SetupOp.SETUP_LOAD_STATE1)
            mdesc = hw_desc_set_flow_mode(mdesc, FlowMode.S_DIN_to_AES)
            mdesc = hw_desc_set_dout_dlli(mdesc, 0, AES_BLOCK_SIZE_IN_BYTES, SB_AXI_ID,
                                          0)
            self.sasi_sb_adddescsequence(mdesc)

            mdesc2 = hw_desc_init()
            mdesc2 = hw_desc_set_cipher_mode(mdesc2, SepCipherMode.SEP_CIPHER_CTR)
            mdesc2 = hw_desc_set_setup_mode(mdesc2, SetupOp.SETUP_LOAD_KEY0)
            mdesc2 = hw_desc_set_flow_mode(mdesc2, FlowMode.S_DIN_to_AES)
            mdesc2 = hw_desc_set_dout_dlli(mdesc2, 0, AES_BLOCK_SIZE_IN_BYTES, SB_AXI_ID,
                                           0)
            self.sasi_sb_adddescsequence(mdesc2)

    def sbrom_cryptoupdate(self, inputptr, outputptr, block_size, islastblock, cryptodrivermode, waitforcrypto):
        if waitforcrypto == 2:
            if self.sb_hal_wait_desc_completion() == 1:
                return True
        if islastblock == 1 and (cryptodrivermode & 0xFFFFFFFD) == 0:
            # 0=0
            # 1=0
            # 2=outputptr
            # 3=0x42
            # 4=0x908082B
            # 5=outputptr>>32<<16
            ydesc = hw_desc_init()
            ydesc = hw_desc_set_dout_dlli(ydesc, outputptr, 0x10, SB_AXI_ID, 0)
            ydesc = hw_desc_set_flow_mode(ydesc, FlowMode.S_HASH_to_DOUT)
            ydesc = hw_desc_set_cipher_mode(ydesc, SepHashHwMode.SEP_HASH_HW_SHA256)
            ydesc = hw_desc_set_cipher_config1(ydesc, SepHashMode.SEP_HASH_SHA256)
            ydesc = hw_desc_set_setup_mode(ydesc, SetupOp.SETUP_WRITE_STATE1)
            self.sasi_sb_adddescsequence(ydesc)
        udesc = hw_desc_init()
        udesc = hw_desc_set_din_type(udesc, DmaMode.DMA_DLLI, inputptr, block_size, SB_AXI_ID, AXI_SECURE)
        if not cryptodrivermode:
            udesc = hw_desc_set_flow_mode(udesc, FlowMode.DIN_HASH)
        self.sasi_sb_adddescsequence(udesc)
        if (waitforcrypto == 2 and not islastblock) or waitforcrypto == 3:
            self.sb_hal_wait_desc_completion()
        elif waitforcrypto == 0:
            return 0
        else:
            return 0xF2000001

    def sbrom_cryptofinishdriver(self, outputptr):
        fdesc = hw_desc_init()
        fdesc = hw_desc_set_dout_dlli(fdesc, outputptr, 0x20, SB_AXI_ID, 0)
        fdesc = hw_desc_set_flow_mode(fdesc, FlowMode.S_HASH_to_DOUT)
        fdesc = hw_desc_set_cipher_mode(fdesc, SepHashHwMode.SEP_HASH_HW_SHA256)
        fdesc = hw_desc_set_cipher_config0(fdesc, SepHashHwMode.SEP_HASH_HW_SHA256)
        fdesc = hw_desc_set_cipher_config1(fdesc, SepHashMode.SEP_HASH_SHA256)
        fdesc = hw_desc_set_setup_mode(fdesc, SetupOp.SETUP_WRITE_STATE0)
        # 0 = 0
        # 1 = 0
        # 2 = outputptr
        # 3 = 0x82
        # 4 = 0x80C082B
        # 5 = outputptr>>32<<16
        self.sasi_sb_adddescsequence(fdesc)
        return self.sb_hal_wait_desc_completion()


if __name__ == "__main__":
    # 0=0
    # 1=0
    # 2=outputptr
    # 3=0x42
    # 4=0x908082B
    # 5=outputptr>>32<<16
    desc = hw_desc_init()
    desc = hw_desc_set_dout_dlli(desc, 0, 0x10, SB_AXI_ID, 0)
    desc = hw_desc_set_flow_mode(desc, FlowMode.S_HASH_to_DOUT)
    desc = hw_desc_set_cipher_mode(desc, SepHashHwMode.SEP_HASH_HW_SHA256)
    desc = hw_desc_set_cipher_config1(desc, SepHashMode.SEP_HASH_SHA256)
    desc = hw_desc_set_setup_mode(desc, SetupOp.SETUP_WRITE_STATE1)
    print(desc)
