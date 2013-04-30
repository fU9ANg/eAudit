
#ifndef _CTL_SUPPORT_PRO_H
#define _CTL_SUPPORT_PRO_H

#define SUPPORT_PRO_ITEMS_DELIM      ";" 
#define SUPPORT_PRO_ITEMS_DELIM_CHAR ';' 

typedef struct tagSUPPORT_PRO_HEAD
{
    int pro_num;
}SUPPORT_PRO_HEAD,*SUPPORT_PRO_HEAD_ID;
#define SUPPORT_PRO_HEAD_SIZE sizeof(SUPPORT_PRO_HEAD)

/*global function*/
extern int open_support_pro_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
extern void close_support_pro_file(int fd);
extern int get_support_pro_num(int fd);
extern void get_support_pro(SUPPORT_PRO_NODE_ID support_pro_id,char *file_cnt_buf,int pro_num);
extern int chk_support_pro(SUPPORT_PRO_NODE_ID support_pro_id,int pro_num);
extern SUPPORT_PRO_NODE_ID create_pro_table(key_t shm_key,int *tbl_shm_id,SUPPORT_PRO_NODE_ID support_pro_id,int pro_num);

#endif
