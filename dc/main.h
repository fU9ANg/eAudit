
/*
 * file: main.h
 * Written 2009-2013 by fU9ANg
 * bb.newlife@gmail.com
 *
 */

#ifndef _DC_MAIN_H
#define _DC_MAIN_H

#define RECV_BYTES_LEN 256
#define REGISTER_INFO   0x01
#define UNREGISTER_INFO   0x02
#define REGISTER_RESPONSE_CODE 0x81
#define UNREGISTER_RESPONSE_CODE 0x82

#define DC_USR_NUM 4000

/* 接收消息结构体 */
typedef struct tag_SET
{
    unsigned char flag;
    unsigned char length;
    unsigned char message[RECV_BYTES_LEN];
    struct sockaddr_in addr;
}   MESSAGE_QUEUE;

/* 通信头部定义 */
typedef struct tag_SRTA_HDR
{
    unsigned char   flag[4];
    unsigned short  version;
    unsigned char   opt_code;
    unsigned long   param_length;
}   PSRTA_HDR,*PSRTA_HDR_ID;            
#define PSRTA_HDR_SIZE sizeof(PSRTA_HDR)

/* 用户注册信息列表定义 */
typedef struct tag_DCUSR_INFO
{
    int dc_usr_id;
    char dc_usr_name[256];
    unsigned char dc_usr_mac[6];
    char dc_usr_ip[20];
    char dc_usr_os_info[256];
    char dc_usr_hostname[256];
    unsigned char dc_usr_lock_status;
    char dc_usr_reg_detail[256];
    char dc_usr_real_ip[20];
}   DCUSR_INFO,*DCUSR_INFO_ID;            
#define DCUSR_INFO_SIZE sizeof(DCUSR_INFO)

#endif // _DC_MAIN_H
