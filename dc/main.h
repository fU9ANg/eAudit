
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

#endif // _DC_MAIN_H
