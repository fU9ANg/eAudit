
#ifndef _CTL_PKT_FILE_INFO_H
#define _CTL_PKT_FILE_INFO_H

/*RESERVED*/
typedef struct tagPRO_SHM_INFO
{
    int shm_id;
    int sem_id;
}PRO_SHM_INFO,*PRO_SHM_INFO_ID;
#define PRO_SHM_INFO_SIZE sizeof(PRO_SHM_INFO)

extern int create_file_no_file(char *file_name, SUPPORT_PRO_NODE_ID pro_tbl_shm_addr ,char *base_dir,int pro_num);
extern PKT_FILE_PROC_INFO_ID create_pkt_file_proc_info(key_t *shm_key_ptr,int *shm_id,int pro_num);

extern int callback_pro_sem(int pro_no,PKT_FILE_PROC_INFO_ID shm_addr);

#endif

