
#ifndef _CTL_PROTECT_RULE_H
#define _CTL_PROTECT_RULE_H

#include "interface_filter.h"

/*the DEF_SHM_KEY_VAL*/
#define DEF_SHM_KEY_VAL  0

/*del rules shm mode*/
#define DEL_MAIN_SHM     1
#define NOT_DEL_MAIN_SHN 2

/*the char middle the rule items*/
#define RULE_ITEMS_IVL_ASC     43              /*THE CHAR:space*/
#define RILE_ITEMS_DELIM       "+"
#define RILE_ITEMS_DELIM_CHAR  '+'

#define RULE_ID_DELIM           ":"
#define RULE_ID_DELIM_CHAR      ':'

/*the rule line end char*/
#define RULE_LINE_END_ASC       59             /*';'*/
#define OTR_RULE_LINE_END_ASC   10       /*'\n'*/
#define RULE_LINE_DELIM         ";"

/*has or no rule flag*/
typedef enum{
    HAS_RULE = 0,
    NO_RULE
}EN_RULE_FLG;

/*the filter rule structure*/
typedef struct tagFILTER_RULE
{
    unsigned long rule_id;
    unsigned long id;
    unsigned long ip_addr;
    unsigned long net_mask;
    int pro_id;
    unsigned short port;
    unsigned char direct;       /*value is:EN_DIRECT*/
    short sq_class;     //授权审计级别
    short wsq_class;    //未授权审计级别
    int rule_group_id;  //资源组I
}FILTER_RULE,*FILTER_RULE_ID;
#define FILTER_RULE_BLK_SIZE sizeof(FILTER_RULE)

/*per rules items number*/
#define RULE_ITEMS_NUM 8

/*the declaration of global function and var*/
/*global var*/
extern key_t g_max_shm_key;
extern key_t g_max_sem_key;

/*global function*/
extern int open_rules_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);

extern unsigned long get_rules_num(char *file_cnt_buf);
extern void copy_item(FILTER_RULE_ID filter_rule_id,int item_no,char *item);
extern int set_rules_item(FILTER_RULE_ID filter_rule_id,char *buf);
extern int set_rules_buf(FILTER_RULE_ID filter_rule_id,char *file_cnt_buf,unsigned long buf_num);

extern void qsort_by_port(FILTER_RULE_ID filter_rule_id,unsigned long buf_num);

extern PORT_INDEX_RULE_ID create_port_index(key_t *port_idx_shm_key,int *port_idx_shm_id);
//extern RULE_NODE_ID create_rule_items_pool(unsigned long items_num,key_t *shm_pool_key,int *pool_shm_id);
//extern int create_rule_tbl(PORT_INDEX_RULE_ID port_index_rule_id,RULE_NODE_ID rule_pool_id,\
                      FILTER_RULE_ID filter_rule_id,unsigned long rule_num);

extern int del_shm_deque(key_t shm_key,int flag);

extern int get_pro_num(FILTER_RULE_ID filter_rule_id,unsigned long rule_num);

extern int callback_rule_shm(PORT_INDEX_RULE_ID port_index_rule_id,int shmid);

#endif
