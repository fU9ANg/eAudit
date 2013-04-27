
/*
 * file: interface_filter.h
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#ifndef _INTERFACE_FILTER_H
#define _INTERFACE_FILTER_H

#include "interface_pub.h"

#define DEF_PKT_FILE_WAIT_SENCONDS 15

/*filter 写文件增加的时间*/
#define INCREASE_FILTER_IVL  5

/*the par between the main_process and the filter model*/
typedef struct tagPAR_ITF_FILTER
{
    int nic_no;
    int pro_num;
    int que_num;
    CFG_FILE_SET cfg_file_set;
    FUNC_SWITCH func_switch;
    key_t protected_resources_key;
    key_t run_cfg_shm_key;
    unsigned long protected_resources_num;
    key_t pro_table_shm_key;
    long deposit_ivl_sec;
    char pkt_file_dir[MAX_DIR_SIZE + 1];
    char nic_name[NICNAMESIZE+1];
     key_t authorize_network_key;
    unsigned long authorize_network_num;
     key_t redirect_port_key;
    unsigned long dynamic_protect_resource_num;
    key_t usr_list_key;
   unsigned long usr_num;
   /*2009 05 02 阻断功能*/
   key_t ipqueque_sem_key;
   key_t tcpclosequeptr_key;
   key_t tcpclosefirstque_key;
   unsigned long fst_block_queque_num;
#ifdef MULTITASK_FILTER
    key_t pkt_wr_info_key;
#endif
} __attribute__ ((packed)) PAR_ITF_FILTER, *PAR_ITF_FILTER_ID;
#define PAR_ITF_FILTER_SIZE sizeof(PAR_ITF_FILTER)

/*the audit direct*/
typedef enum
{
    UP_DIRECT = 0,      /*DST*/
    DN_DIRECT,            /*SRC*/
    ALL_DIRECT            /*DST AND SRC*/
}   EN_EAUDIT_DIRECT;

#define AUDIT_DIRECT_NUM 3

/*the rule node index*/
typedef struct tagRULE_NODE_IDX
{
    unsigned long node_no;
}   RULE_NODE_IDX,*RULE_NODE_IDX_ID;
#define RULE_NODE_IDX_SIZE sizeof(RULE_NODE_IDX)

/*the direct index structure of deque*/
typedef struct tagDIRECT_INDEX_RULE
{
    unsigned char direct;    
    int rule_num;               
    key_t shm_key;              
}   DIRECT_INDEX_RULE,*DIRECT_INDEX_RULE_ID;
#define DIRECT_INDEX_RULE_SIZE sizeof(DIRECT_INDEX_RULE)

/*the main index structure of deque*/
typedef struct tagPORT_INDEX_RULE
{
    unsigned short port;    /*port*/
    key_t shm_key;          /*the shm key of this rule list about the port*/ 
}   PORT_INDEX_RULE,*PORT_INDEX_RULE_ID;
#define PORT_INDEX_RULE_SIZE sizeof(PORT_INDEX_RULE)

typedef struct tagDIRECT_MAP
{
    int rule_num;
    RULE_NODE_IDX_ID rule_addr;
}   DIRECT_MAP,*DIRECT_MAP_ID;
#define DIRECT_MAP_SIZE sizeof(DIRECT_MAP)

typedef struct tagPORT_MAP
{
    DIRECT_MAP_ID direct_addr;
}   PORT_MAP,*PORT_MAP_ID;
#define PORT_MAP_SIZE sizeof(PORT_MAP)

/*equal to the function switch*/
typedef struct tagFUNC_SWITCH_FILTER
{
    int iAlarmSwitch;
    int iErrSwitch;
    int iStatSwitch;
}   FUNC_SWITCH_FILTER,*FUNC_SWITCH_FILTER_ID;
#define FUNC_SWITCH_FILTER_SIZE sizeof(FUNC_SWITCH_FILTER)

/*the file info of every pro READ INFO*/
typedef struct tagPKT_FILE_PROC_INFO
{
    int pro_id;
    key_t sem_key;
}   PKT_FILE_PROC_INFO,*PKT_FILE_PROC_INFO_ID;
#define PKT_FILE_PROC_INFO_SIZE sizeof(PKT_FILE_PROC_INFO)

#endif
