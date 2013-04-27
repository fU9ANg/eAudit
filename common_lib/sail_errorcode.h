/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef SAIL_ERRORCODE_H
#define SAIL_ERRORCODE_H

#include "sail_basetype.h"

#define SAIL_OK		0x00

/*算法模块返回代码起始位置0x80；*/
#define SAIL_ALLOC_MEM							0x00000080
#define SAIL_ALGOR_PARA_ERROR					0x00000081
#define SAIL_ALGORID_ERROR						0x00000082
#define SAIL_ERR_LEN							0x00000083
#define SAIL_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH	0x00000084
#define SAIL_WRONG_FINAL_BLOCK_LENGTH			0x00000085
#define SAIL_BAD_DECRYPT						0x00000086
#define SAIL_INIT_KEY_FAIL						0x00000087
#define SAIL_HASH_LEN_ERR						0x00000088
#define SAIL_VERIFY_HASH_FAIL					0x00000089
#define SAIL_BUFFER_TOO_SMALL					0x0000008A
#define SAIL_INVALID_RSA_KEY_TYPE               0x0000008B
#define SAIL_INVALID_PRIVATE_KEY                0x0000008C
#define SAIL_CONSTRUCT_PRIKEY_FAIL              0x0000008D
#define SAIL_INVALID_PASSWORD                   0x0000008E
#define SAIL_INVALID_CERTIFICATE                0x0000008F
#define SAIL_SIGN_FAIL                          0x00000090
#define SAIL_VERIFY_FAIL                        0x00000091
#define SAIL_PRIVATEKEY_ENC_FAIL                0x00000092
#define SAIL_PRIVATEKEY_DEC_FAIL                0x00000093
#define SAIL_PUBLICKEY_ENC_FAIL                 0x00000094
#define SAIL_PUBLICKEY_DEC_FAIL                 0x00000095
#define SAIL_GENERATE_X509_FAIL                 0x00000096
#define SAIL_GENERATE_EVP_PKEY_FAIL             0x00000097
#define SAIL_PKEY_ASSIGN_RSA_FAIL               0x00000098
#define SAIL_X509_REQ_SET_VER_FAIL              0x00000099
#define SAIL_X509_REQ_SET_PUBKEY_FAIL           0x0000009A
#define SAIL_GENERATE_X509_NAME_FAIL            0x0000009B
#define SAIL_INVALID_PARAMETER                  0x0000009C
#define SAIL_INVALID_RSA_KEY_LENGTH             0x0000009D
#define SAIL_GENERATE_X509_NAME_ENTRY_FAIL      0x0000009E
#define SAIL_ADD_X509_NAME_ENTRY_FAIL           0x0000009F
#define SAIL_X509_REQ_SET_SUBNAME_FAIL          0x000000A0
#define SAIL_MEM_TO_BIO_FAIL                    0x000000A1
#define SAIL_ENCODE_DER_REQ_FAIL                0x000000A2
#define SAIL_ENCODE_PEM_REQ_FAIL                0x000000A3
#define SAIL_ENCODE_DER_PRI_FAIL                0x000000A4
#define SAIL_ENCODE_PEM_PRI_FAIL                0x000000A5
#define SAIL_ENC_PRIKEY_FAIL                    0x000000A6
#define SAIL_GENERATE_RSA_KEY_FAIL              0x000000A7
#define SAIL_X509_REQ_SIGN_FAIL                 0x000000A8
#define SAIL_GET_RANDOM_FAIL                    0x000000A9
#define SAIL_ENCODE_FAIL                        0x000000AA
#define SAIL_VERIFY_MAC_FAIL                    0x000000AB
#define SAIL_READ_BIO_X509_FAIL                 0x000000AC
#define SAIL_READ_X509_REQ_FAIL                 0x000000AD
#define SAIL_X509_GET_PUBKEY_FAIL               0x000000AE
#define SAIL_X509_REQ_GET_PUBKEY_FAIL           0x000000AF
#define SAIL_RSA_NOT_PAIR                       0x000000B0
#define SAIL_EVP_GET_DIGEST_FAIL                0x000000B1
#define SAIL_X509_NEW_FAIL                      0x000000B2
#define SAIL_SERIAL_TO_BN_FAIL                  0x000000B3
#define SAIL_BN_TO_ASN1_INTEGER_FAIL            0x000000B4
#define SAIL_X509_SIGN_FAIL                     0x000000B5
#define SAIL_X509_SET_PUBKEY_FAIL               0x000000B6
#define SAIL_X509_SET_ISSUER_NAME_FAIL          0x000000B7
#define SAIL_X509_SET_SUBJECT_NAME_FAIL         0x000000B8
#define SAIL_PEM_WRITE_BIO_FAIL                 0x000000B9
#define SAIL_X509_GMTIME_ADJ_FAIL               0x000000BA
#define SAIL_DEFLATEINIT_FAIL                   0x000000BB
#define SAIL_INVALID_SESSION_HANDLE             0x000000BC
#define SAIL_DEFLATE_FAIL                       0x000000BD
#define SAIL_INFLATEINIT_FAIL                   0x000000BE
#define SAIL_INFLATE_FAIL                       0x000000BF
#define SAIL_CONFIG_FILE_ERROR                  0x000000C0
#define SAIL_X509V3_EXT_ADD_CONF_FAIL           0x000000C1
#define SAIL_ASN1_STR_SET_MASK_ASC_FAIL         0x000000C2
#define SAIL_X509_SET_VER_FAIL                  0x000000C3
#define SAIL_X509_REQ_GET_SUB_NAME_FAIL         0x000000C4
#define SAIL_X509_GET_SN_FAIL                   0x000000C5
#define SAIL_PEM_WRITE_X509_REQ_FAIL            0x000000C6

/*启动器模块返回代码起始位置*/
#define CTL_ALLOC_MEM                           0x00000800

/*具体error coe*/
#define CTL_PAR_ERR                             0x00000801
#define CTL_FILE_NOT_EXIST                      0x00000802
#define CTL_FILE_OPEN_FAIL                      0x00000803
#define CTL_FILE_IS_NULL                        0x00000804
#define CTL_CRT_SHM_FAIL                        0x00000805
#define CTL_GET_SHM_FAIL                        0x00000806
#define CTL_ATTACH_SHM_FAIL         0x00000807
#define CTL_DEL_SHM_FAIL            0x00000808
#define CTL_AUDIT_DIRECT_ERR        0x00000809
#define CTL_READ_FILE_TO_MEM_FAIL   0x00000810
#define CTL_MALLOC_FAIL             0x00000811
#define CTL_CALLOC_FAIL             0x00000812

#define CTL_LSEEK_FILE_FAIL         0x00000813
#define CTL_RD_FILE_FAIL            0x00000814
#define CTL_SUPPORT_PRO_FILE_ERR    0x00000815

/*过滤分类模块返回代码起始位置*/
#define FILTER_ALLOC_MEM    0x00000850
/*具体error coe*/
#define FILTER_PAR_ERR_OFFSET           1
#define FILTER_PAR_ERR                  (FILTER_ALLOC_MEM+1)
#define FILTER_OPEN_FILE_FAIL_OFFSET    2
#define FILTER_F_LSEEK_FAIL_OFFSET      3
#define FILTER_F_WRITE_FAIL_OFFSET      4  
#define FILTER_MMAP_FAIL_OFFSET         5
#define FILTER_FILE_HAS_CNT_OFFSET      6  

#define FILTER_GET_SHM_FAIL_OFFSET      7
#define FILTER_GET_SHM_FAIL             (FILTER_ALLOC_MEM + 7)

#define FILTER_ATTACH_SHM_FAIL_OFFSET   8
#define FILTER_ATTACH_SHM_FAIL          (FILTER_ALLOC_MEM + 8)

#endif
