
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include <stdarg.h> 
#include <time.h>

#include <sys/param.h>
#include <syslog.h>

#include "eAudit_pub.h"
#include "eAudit_log.h"
#include "eAudit_sem.h"
#include "eAudit_shm.h"
#include "eAudit_mem.h"
#include "eAudit_dir.h"
#include "eAudit_shm_que.h"
#include "eAudit_single_run.h"
#include "eAudit_res_callback.h"

#include "interface_pub.h"
#include "interface_filter.h"
#include "ctl_pub.h"
#include "ctl_debug.h"
#include "ctl_pkt_shm_que.h"
#include "ctl_pkt_file_info.h"
#include "ctl_filter_rule.h"
#include "ctl_res_callback.h"

/*global var*/
RES_MAP_ID g_res_map_id = NULL;
int g_mem_num = 0;
int g_shm_num = 0;
int g_sem_num = 0;
int g_file_num = 0;

/*static function declaration*/
/*no*/

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
RES_MAP_ID create_res_map(int num)
{
    size_t len;
    RES_MAP_ID map_id = NULL;
    
    len = num * RES_MAP_SIZE;
    map_id = malloc(num * RES_MAP_SIZE);
    
    return map_id;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_max_res_num(int res_type)
{
    int max_num = 0;
    
    switch(res_type)
    {
        case MEM_RES:
            max_num = MAX_MEM_NUM;
            break;
            
        case SHM_RES:
            max_num = MAX_SHM_NUM;
            break;
            
        case SEM_RES:
            max_num = MAX_SEM_NUM;
            break;
            
        case FILE_RES:
            max_num = MAX_FILE_NUM;
            break;
            
        default:
            break;
    }
    
    return max_num;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_res_no(int res_type)
{
    int res_no = 0;
    
    switch(res_type)
    {
        case MEM_RES:
            break;
            res_no = g_mem_num;
        case SHM_RES:
            res_no = g_shm_num;
            break;
        case SEM_RES:
            res_no = g_sem_num;
            break;
        case FILE_RES:
            res_no = g_file_num;
            break;
        default:
            break;
    }
    
    return res_no;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_res_no(int res_type)
{
    switch(res_type)
    {
        case MEM_RES:
            g_mem_num++;
            break;
            
        case SHM_RES:
            g_shm_num++;
            break;
            
        case SEM_RES:
            g_sem_num++;
            break;
            
        case FILE_RES:
            g_file_num++;
            break;
            
        default:
            break;
    }
    
    return;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void reg_res(int res_type,void *res)
{
    void **res_lst_id = NULL;
    int res_no;
    
    res_no = get_res_no(res_type);
    if (res_no > get_max_res_num(res_type))
    {
        DEBUG("[ERR]reg res err:num > max res num.");
        return;
    }
    
    res_lst_id = (g_res_map_id + res_type)->res_lst_id;
    *(res_lst_id + res_no) = res;
    
    set_res_no(res_type);
    
    return;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int callback_res(RES_MAP_ID map_id)
{
    register int i;
    register int j;
    register void **res_lst_id = NULL;
    
    for (i = 0;i < MAX_RES_TYPE_NUM;i++)
    {
        if (0 == 1)
        {
            for (j = 0;j < MAX_MEM_NUM;j++)
            {
                if (NULL != map_id)
                {
                    res_lst_id = (g_res_map_id + i)->res_lst_id; 
                    if (NULL != res_lst_id + j)
                    {
                        SAIL_free((void **)(res_lst_id + j));
                    }
                }
            }
        }
         /*not ok*/
        
    } 
    
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
char *get_res_reg_file_path(char *file_path,char *file_name,char *model_name)
{
    char *addr = file_path;

    sprintf(file_path,"%s/%s/%s.reg",RES_REG_DIR,model_name,file_name);

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
int callback_reg_mem_res(FILE *fp)
{
    register int i;
    REG_BASIC_INFO reg_info;
    char str[U_LONG_SIZE + 1];
    unsigned long addr;

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
int callback_reg_shm_res(FILE *fp)
{
    int shm_num;
    char str[U_LONG_SIZE + 1];
    unsigned long addr;
    int shm_id;
    QUE_ID cfg_que_info = NULL;
    PORT_INDEX_RULE_ID port_index_rule_id = NULL;

    fseek(fp,0,SEEK_SET);
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_num = atoi(str);

    if (7 != shm_num)
    {
    	 DEBUG("SHM NUM ERR.");
        return ERR;
    }

    /*1*/
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    cfg_que_info = (QUE_ID)strtoul(str,NULL,10);

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_id = atoi(str);

    (void)callback_shm_que(cfg_que_info,shm_id);

    /*2*/
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    addr = strtoul(str,NULL,10);
    if (NULL == (char *)addr)
    {
        if (detach_shm((char *)addr) < 0)
            return ERR;
    }
	
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_id = atoi(str);
    if (-1 != shm_id)
    {
        if (del_shm(shm_id) < 0)
            return ERR;
    }

    /*3*/
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    addr = strtoul(str,NULL,10);
    if (NULL == (char *)addr)
    {
        if (detach_shm((char *)addr) < 0)
            return ERR;
    }
	
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_id = atoi(str);
    if (-1 != shm_id)
    {
        if (del_shm(shm_id) < 0)
            return ERR;
    }	

    /*4*/
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    addr = strtoul(str,NULL,10);
    if (NULL == (char *)addr)
    {
        if (detach_shm((char *)addr) < 0)
            return ERR;
    }
	
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_id = atoi(str);
    if (-1 != shm_id)
    {
        if (del_shm(shm_id) < 0)
            return ERR;
    }

    /*5*/
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    port_index_rule_id = (PORT_INDEX_RULE_ID)strtoul(str,NULL,10);

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_id = atoi(str);

    (void)callback_rule_shm(port_index_rule_id,shm_id);

    /*6*/
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_id = atoi(str);
    if (-1 != shm_id)
    {
        if (del_shm(shm_id) < 0)
            return ERR;
    }

    /*7*/
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_id = atoi(str);
    if (-1 != shm_id)
    {
        if (del_shm(shm_id) < 0)
            return ERR;
    }

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
int callback_last_reg_shm_res(FILE *fp)
{
    int num;
    int shm_id;
    key_t shm_key;
    char str[U_LONG_SIZE + 1];
    QUE_ID cfg_que_info = NULL;
    PORT_INDEX_RULE_ID port_index_rule_id = NULL;

    fseek(fp,0,SEEK_SET);
    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    num = atoi(str);

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_key = atol(str);
    DEBUG("shm key = %ld\n",shm_key);

    shm_id = shmget(shm_key,0,IPC_CREAT);
    if (shm_id >= 0)
    {
        cfg_que_info = (QUE_ID)shmat(shm_id,NULL,SHM_RDONLY);
        if (!cfg_que_info)
        {
            info("[Warning]Attach shm fail.\n");
        }
        else
        {
            (void)callback_shm_que(cfg_que_info,shm_id);
        }
    }

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_key = atol(str);
    DEBUG("shm key = %ld\n",shm_key);
    shm_id = shmget(shm_key,0,IPC_CREAT);
    if (shm_id >= 0)
    {	
        (void)del_shm(shm_id);
    }

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_key = atol(str);
    DEBUG("shm key = %ld\n",shm_key);
    shm_id = shmget(shm_key,0,IPC_CREAT);
    if (shm_id >= 0)
    {
        (void)del_shm(shm_id);
    }

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_key = atol(str);
    DEBUG("shm key = %ld\n",shm_key);
    shm_id = shmget(shm_key,0,IPC_CREAT);
    if (shm_id >= 0)
    {
        (void)del_shm(shm_id);
    }

    memset(str,0x00,U_LONG_SIZE + 1);
    fgets(str,U_LONG_SIZE + 1,fp);
    shm_key = atol(str);
    DEBUG("shm key = %ld\n",shm_key);
    shm_id = shmget(shm_key,0,IPC_CREAT);
    if (shm_id >= 0)
    {
        port_index_rule_id = (PORT_INDEX_RULE_ID)shmat(shm_id,NULL,SHM_RDONLY);
        if (!port_index_rule_id)
        {
            info("[Warning]Attach shm fail.\n");
        }
	 else
	 {
	     (void)callback_rule_shm(port_index_rule_id,shm_id);
	 }
    }

    return OK;
}
