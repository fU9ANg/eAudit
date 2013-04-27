/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_PUB_H
#define _EAUDIT_PUB_H

#define STR(s) #s

#define MAX_DIR_SIZE       256
#define MAX_PID_STR_SIZE   10
#define MAX_SYS_CMD_SIZE   256
#define MAX_FILE_PATH_SIZE 512
#define MAX_BLK_SIZE       1600
#define MAX_LOG_CNT_SIZE   256
#define U_LONG_SIZE  32

#define MAX_PORT 65535         /*the max port now*/
#define MAX_PRO_NAME_SIZE 16  /*the protocol name size*/

#define NICNAMESIZE 16  

#define LOG_DIR_PATH       "/log"

#define OK  0
#define ERR -1

#define SAIL_TRUE  1
#define SAIL_FALSE 0

#define DEF_FILE_DES_VAL -1
#define DEF_PID_VAL      -1
#define DEF_KEY_VAL      0
#define DEF_SHM_ID_VAL -1
#define DEF_SEM_ID_VAL -1

#ifndef IPV6
#define DEF_SNAPLEN  68	/* ether + IPv4 + TCP + 14 */
#else
#define DEF_SNAPLEN  96	/* ether + IPv6 + TCP + 22 */
#endif

#define SNAPLEN 1580

#endif
