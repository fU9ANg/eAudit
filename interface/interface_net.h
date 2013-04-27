
/*
 * file: interface_net.h
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#ifndef _INTERFACE_NET_H
#define  _INTERFACE_NET_H

#include "interface_pub.h"

#define NET_MSG_FLAG_SIZE 4

#define NET_MSG_CRC 0xFFFFFFFF
#define NOW_NET_PKT_VERSION 1

/*���ݰ�ͷ��ʽ*/
#pragma pack(1)

typedef struct tagNET_MSG_HDR
{
    char flag[NET_MSG_FLAG_SIZE];
    unsigned short version;
    unsigned long seq_no;
    unsigned char protect_mode;
    int msg_type;
    unsigned long msg_body_len;   /*��Ϣ�峤��,��������Ϣͷ��*/ 
    unsigned long reserved;
    unsigned long check_val;
    char filename[256];
}NET_MSG_HDR,*NET_MSG_HDR_ID;
#define NET_MSG_HDR_SIZE sizeof(NET_MSG_HDR)

#pragma pack()

/*����ģʽȡֵ*/
typedef enum
{
    EXPRESS_MODE = 0,
    ZIP_MODE,
    ENCRYPT_MODE
}EN_PROTECT_MODE;

#endif
