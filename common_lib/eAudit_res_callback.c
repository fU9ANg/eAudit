/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "eAudit_pub.h"
#include "eAudit_shm.h"
#include "eAudit_sem.h"
#include "eAudit_res_callback.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
char *get_reg_file_path(char *file_path,char *dir_path,pid_t pid)
{
    char *addr = file_path;

    if (strlen(dir_path) > MAX_DIR_SIZE)
        return NULL;

    sprintf(file_path,"%s/%d.reg",dir_path,pid);

    return addr;        
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int reg_proc(char *file_path,int proc_class)
{
    char str[10];
    
    FILE *fp = NULL;

    if (NULL == (fp = fopen(file_path,"w+")))
        return ERR;

    memset(&str,0x00,10);
    sprintf(str,"%d",proc_class);
    fputs(str,fp);
    fclose(fp);

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int callback_reg_sys_res(FILE *fp)
{
    int i;
    REG_BASIC_INFO reg_info;
    char str[U_LONG_SIZE + 1];
    unsigned long addr;
    int shm_id;
    int sem_id;

    fseek(fp,0,SEEK_SET);

    memset(&reg_info,0x00,sizeof(REG_BASIC_INFO));

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    reg_info.heap_num = atoi(str);
    for (i = 0;i < reg_info.heap_num;i++)
    {
        memset(str,0x00,U_LONG_SIZE + 1);
        fgets(str,U_LONG_SIZE + 1,fp);
        addr = strtoul(str,NULL,10);
        free((void *)addr);
    }

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    reg_info.shm_num = atoi(str);
    for (i = 0;i < reg_info.shm_num;i++)
    {
        memset(str,0x00,U_LONG_SIZE + 1);
        fgets(str,U_LONG_SIZE + 1,fp);
        addr = strtoul(str,NULL,10);
        if (detach_shm((char *)addr) < 0)
            return ERR;

        memset(str,0x00,U_LONG_SIZE + 1);
        fgets(str,U_LONG_SIZE + 1,fp);
        shm_id = atoi(str);
        if (-1 != shm_id)
        {
            if (del_shm(shm_id) < 0)
                return ERR;
        }
    }
    
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    reg_info.sem_num = atoi(str);
    for (i = 0;i < reg_info.sem_num;i++)
    {
        memset(str,0x00,U_LONG_SIZE + 1);
        fgets(str,U_LONG_SIZE + 1,fp);
        sem_id = atoi(str);
        if (del_sem(sem_id) < 0)
            return ERR;
    }

    return OK;
}
