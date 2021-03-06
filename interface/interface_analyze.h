
/*
 * file: interface_analyze.h
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#ifndef _INTERFACE_ANALYZE_H
#define _INTERFACE_ANALYZE_H

#include    <sys/types.h>
#include    "interface_pub.h"

/*packets file path suffix*/
#define PKT_FILE_SUFFIX     ".pdat"
#define PKT_FILE_TMP_SUFFIX ".tmp"

/*the par to the analyze process*/
typedef struct tagPAR_ITF_ANALYZE
{
    int pro_id;
    key_t pro_tbl_shm_key;
    CFG_FILE_SET cfg_file_set;
    FUNC_SWITCH func_switch;
    key_t rule_pool_key;
    unsigned long rule_num;
    char pkt_file_dir[MAX_DIR_SIZE + 1];
    long deposit_ivl_sec;
    key_t usr_list_key;
    unsigned long usr_num;

    key_t authorize_network_key;
    unsigned long authorize_network_num;

    key_t authorize_account_key;
    unsigned long authorize_account_num;

    key_t authorize_cmd_key;
    unsigned long authorize_cmd_num;

    key_t authorize_custom_key;
    unsigned long authorize_custom_num;

    key_t authorize_feature_key;
    unsigned long authorize_feature_num;

}   PAR_ITF_ANALYZE,*PAR_ITF_ANALYZE_ID;
#define PAR_ITF_ANALYZE_SIZE sizeof(PAR_ITF_ANALYZE)

/*the interface between filter and analyze*/
/*pkt file flag*/
typedef enum
{
    NO_CNT = 1,
    HAS_CNT     
}   EN_PKT_FILE_STATUS;

/*the packets file header*/
typedef struct tagRULE_ID_ST
{
    unsigned long rule_id; 
    unsigned long authorize_id;
    unsigned long usr_id;   
    unsigned long res_index;
    unsigned long net_index;
    unsigned char hit_direct;

}   RULE_ID_ST,*RULE_ID_ST_ID;
#define RULE_ID_ST_SIZE sizeof(RULE_ID_ST)

/*the packets file header*/
typedef struct tagPKT_USR_HDR
{
    struct timeval ts;          /*time stamp*/
    unsigned long cap_len;      /*the porsion len*/
    unsigned long pkt_size;     /*ip pkt all len*/

}   PKT_USR_HDR,*PKT_USR_HDR_ID;
#define PKT_USR_HDR_SIZE sizeof(PKT_USR_HDR)

/*pkt file header*/
/*pkt file usrt head*/
typedef struct tagPKT_FILE_USR_HDR
{
    int file_flag;
    unsigned long all_packets_num;
    unsigned long all_packets_size;
    unsigned long crc_num;
    unsigned long reseaved;

}   PKT_FILE_USR_HDR,*PKT_FILE_USR_HDR_ID;
#define PKT_FILE_USR_HDR_SIZE sizeof(PKT_FILE_USR_HDR)

typedef struct tagPKT_FILE_PCAP_HDR
{
    unsigned long magic;
    unsigned version_major;
    unsigned version_minor;
    unsigned long thiszone;    /*gmt to local correction*/
    unsigned long sigfigs;     /*accuracy of timestamps */
    unsigned long snaplen;     /* max length saved portion of each pkt */
    unsigned long linktype;    /* data link type (LINKTYPE_*) */

}   PKT_FILE_PCAP_HDR,*PKT_FILE_PCAP_HDR_ID;
#define PKT_FILE_PCAP_HDR_SIZE sizeof(PKT_FILE_PCAP_HDR)

typedef struct tagPKT_FILE_HDR
{
    PKT_FILE_USR_HDR usr_hdr;
    PKT_FILE_PCAP_HDR pcap_hdr;

}   PKT_FILE_HDR,*PKT_FILE_HDR_ID;
#define PKT_FILE_HDR_SIZE sizeof(PKT_FILE_HDR)

#endif
