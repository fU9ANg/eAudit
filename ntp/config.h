
/*
 * file: config.h
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#ifndef _NTP_CONFIG_H
#define _NTP_CONFIG_H

#define NTP_SERVER_STR_LEN  128
#define DEFAULT_BASIC_TIME  3600

#define LIST_COMMON_KEY     "COMMON"
#define LIST_NUM_KEY        "LIST_NUM"
#define TIMESYN_NUM         "TIMESYN_NUM"
#define LIST_MODE_GETE_KEY  "MODE_GETE"
#define NTP_SERVER_NUM      "NTP_SERVER_NUM"
#define NET_SEG_NUM         "NET_SEG_NUM"

#define LIST_INFO_KEY       "LIST_INFO"
#define SYS_NET_SEG         "SYS_NET_SEG"
#define LIST_RESOURCE_KEY   "INFO"
#define SYN_TIMEVAL         "SYN_TIMEVAL"
#define SYN_TIMEVALS        "Syn_timevals"

#define _DEBUG
#undef  _DEBUG

/* 1.主时间服务器定义 */

/* 定义NTP服务器地址结构 */
typedef struct tagNTP_SERVER_ADDRESS
{
    char ntp_server_str[NTP_SERVER_STR_LEN];
}   NTP_SERVER_ADDRESS, *NTP_SERVER_ADDRESS_ID;
#define NTP_SERVER_ADDRESS_SIZE sizeof(NTP_SERVER_ADDRESS)

/* 定义NTP服务器可以允许时间同步网段 */
typedef struct tagNTP_SERVER_NETSEG
{
    char ip[NTP_SERVER_STR_LEN];
    char mask[NTP_SERVER_STR_LEN];
}   NTP_SERVER_NETSEG, *NTP_SERVER_NETSEG_ID;
#define NTP_SERVER_NETSEG_SIZE sizeof(NTP_SERVER_NETSEG)

/* 定义NTP主时间同步数据结构 */
typedef struct tagNTP_TIMERSYN_SERVER
{
    NTP_SERVER_ADDRESS_ID ntp_server_address_id;
    NTP_SERVER_NETSEG_ID ntp_server_netseg_id;
    int ntp_server_num;
    int ntp_netseg_num;
    int timer_time;
}   NTP_TIMERSYN_SERVER, *NTP_TIMERSYN_SERVER_ID;
#define NTP_TIMERSYN_SERVER_SIZE sizeof(NTP_TIMERSYN_SERVER)

/* 2.从时间服务器定义 */

/* 从时间服务器IP数据结构地址定义 */
typedef struct tagSECEND_TIMERSYN_SERVER_ADDRESS
{
    char second_timersyn_str[NTP_SERVER_STR_LEN];
}   SECEND_TIMERSYN_SERVER_ADDRESS, *SECEND_TIMERSYN_SERVER_ADDRESS_ID;
#define SECEND_TIMERSYN_SERVER_ADDRESS_SIZE sizeof(SECEND_TIMERSYN_SERVER_ADDRESS)

/* 从时间服务器结构体定义 */
typedef struct tagSECOND_TIMERSYN_SERVER
{
    SECEND_TIMERSYN_SERVER_ADDRESS_ID second_timersyn_server_address_id;
    int second_ntp_server_num;
    int timer_time;
}   SECOND_TIMERSYN_SERVER, *SECOND_TIMERSYN_SERVER_ID;
#define SECOND_TIMERSYN_SERVER_SIZE sizeof(SECOND_TIMERSYN_SERVER)

#endif  // _NTP_CONFIG_H
