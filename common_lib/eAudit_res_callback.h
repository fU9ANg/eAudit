/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_RES_CALLBACK_H
#define _EAUDIT_RES_CALLBACK_H

#define RES_REG_DIR "./tmp_res_reg"

#define REG_SHM_ITEM_NUM 2
#define REG_SEM_ITEM_NUM 1

typedef struct tagREG_BASIC_INFO
{
    int heap_num;
    int shm_num;
    int sem_num;
}   REG_BASIC_INFO;

extern char *get_reg_file_path(char *file_path,char *dir_path,pid_t pid);
extern int reg_proc(char *file_path,int proc_class);
extern int callback_reg_sys_res(FILE *fp);

#endif
