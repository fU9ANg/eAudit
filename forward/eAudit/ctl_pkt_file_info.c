
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include <stdarg.h>
#include <time.h>

#include <syslog.h>

#include "eAudit_log.h"
#include "eAudit_mem.h"
#include "eAudit_config.h"
#include "eAudit_string.h"
#include "eAudit_sem.h"
#include "eAudit_shm.h"

#include "ctl_pub.h"
#include "interface_filter.h"
#include "interface_analyze.h"
#include "ctl_debug.h"
#include "ctl_filter_rule.h"
#include "ctl_support_pro.h"
#include "ctl_pkt_file_info.h"

/*static function declaration*/

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int create_file_no_file(char *file_name, SUPPORT_PRO_NODE_ID pro_tbl_shm_addr ,char *base_dir,int pro_num)
{
    register int i;
    unsigned long file_no;
    char file_path[MAX_FILE_PATH_SIZE+1];
    int fd = DEF_FILE_DES_VAL;
    char buf[U_LONG_SIZE+1];
	
    for (i = 0;i < pro_num;i++)
    {
        memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
        sprintf(file_path,"%s/%s/%s",base_dir,(pro_tbl_shm_addr + i)->pro_name,file_name);
       printf("%s  \n",file_path);
        if (IS_EXIST == file_is_exist(file_path))  
        {
            continue;
        }
		
        if ((fd = open(file_path,O_RDWR | O_CREAT)) < 0)
        {
            DEBUG("open file no file Fail.[in ctl main]");     
            return ERR;
        }

        memset(buf,0x00,U_LONG_SIZE+1); 
        file_no = 1;
        sprintf(buf,"%ld",file_no);

        if (-1 == write(fd,buf,strlen(buf)))
        { 
            DEBUG("write file no file fail.[in ctl main]");
	     close(fd);
	     fd = DEF_FILE_DES_VAL; 
	     return ERR;
        }

	close(fd);
	fd = DEF_FILE_DES_VAL;
    }
	
    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
PKT_FILE_PROC_INFO_ID create_pkt_file_proc_info(key_t *shm_key_ptr,int *shm_id,int pro_num)
{
    register int i;
    int shmid;
    int sem_id;
    key_t shm_key;
    key_t sem_key;
    unsigned long shm_size;
    PKT_FILE_PROC_INFO_ID shm_addr = NULL;
    
    g_max_shm_key += SHM_KEY_IVL;
    shm_key = g_max_shm_key;
    *shm_key_ptr = shm_key;
    shm_size = PKT_FILE_PROC_INFO_SIZE * pro_num;
    
    shmid = shmget(shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shmid < 0)
    {
        error("[Err]Create pkt files proc info head fail.");
        return NULL;
    }
    
    shm_addr = (PKT_FILE_PROC_INFO_ID)shmat(shmid,NULL,0);
    if (!shm_addr)
    {
        error("[Err]Attatch pkt files proc info head fail.");
        return NULL;
    }
    
    for (i = 0;i < pro_num;i++)
    {
        (shm_addr + i)->pro_id = i;
        (shm_addr + i)->sem_key = DEF_KEY_VAL;
		
        g_max_sem_key += SEM_KEY_IVL;
	sem_key = g_max_sem_key; 
	if ((sem_id = create_sem(sem_key)) < 0)
        {
            error("[Err]Create pkt files proc sem fail.");
            (void)callback_pro_sem(i,shm_addr);
            return NULL;
        }
        
        (shm_addr + i)->sem_key = sem_key;
    }

    *shm_id = shmid;
    
    return shm_addr;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
#if 0
unsigned long search_pro_file_start_no(char *pro_name,unsigned long file_num,PKT_FILE_RD_INFO_ID pkt_rd_info_id)
{
    register int i;
    DIR *dir = NULL;
    struct dirent *ptr = NULL;
    unsigned long num = 0;
    char dir_path[MAX_DIR_SIZE+1];
    char file_path[MAX_FILE_PATH_SIZE+1];
    FILE *fp = NULL;
    PKT_FILE_HDR pkt_file_hdr;
   int is_get_wr_no = 0;
   int is_get_rd_no = 0;
    
    memset(dir_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(pro_dir,%s/%s,PKT_FILE_DIR,pro_name);
    
    dir =opendir(dir_path);
    while(dir)
    {
        if ((ptr = readdir(dir)) != NULL)
        {
            if ((strcmp(ptr->d_name,".")) && (strcmp(ptr->d_name,"..")))
            {
                num++;
            }
        }
        else
        {
            break;
        }
    }
    
    if (num < file_num)
    {
        num++;
	 for (i = 0;i < num;i++)
        {
            memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
            sprintf(file_path,"%s/%s_%d.%s",dir_path,pro_name,i,PKT_FILE_TYPE);
            fp = fopen(file_path,"r");
            if (NULL == fp)
            {
                DEBUG("open the file fail.")
                return -1;
            }
            
            memset(&pkt_file_hdr,0x00,PKT_FILE_HDR_SIZE);
            if (PKT_FILE_HDR_SIZE != fread(&pkt_file_hdr,PKT_FILE_HDR_SIZE,1,fp))
            {
                DEBUG("PKT file err.");
                return -1;
            }
			
            if (HAS_CNT == pkt_file_hdr.file_flag) 
            {
                 (pkt_rd_info_id + i)->file_start_rd_no= i;
		   break;
            }
        }
	 
        return num;
    }
     
    if (num == file_num)
    {
        for (i = 0;i < num;i++)
        {
            memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
            sprintf(file_path,"%s/%s_%d.%s",dir_path,pro_name,i,PKT_FILE_TYPE);
            fp = fopen(file_path,"r");
            if (NULL == fp)
            {
                DEBUG("open the file fail.")
                return -1;
            }
            
            memset(&pkt_file_hdr,0x00,PKT_FILE_HDR_SIZE);
            if (PKT_FILE_HDR_SIZE != fread(&pkt_file_hdr,PKT_FILE_HDR_SIZE,1,fp))
            {
                DEBUG("PKT file err.");
                return -1;
            }
            
            if ((NO_CNT == pkt_file_hdr.file_flag) && (0 == is_get_wr_no))
            {
                is_get_wr_no = 1;
            }
			
            if ((HAS_CNT == pkt_file_hdr.file_flag) && (0 == is_get_rd_no))
            {
                 is_get_rd_no = 1;
                 (pkt_rd_info_id + i)->file_start_rd_no= i;
            }

	     if ((1 == is_get_rd_no) && (1 == is_get_wr_no))
		    break;
        }
        
        if (i == file_num - 1)
        {
            num = 0;
        }
        else
        {
            num = i + 1;
        }
    }
    
    return num;
}
#endif

/****************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
#if 0
int callback_pro_shm(int pro_no,PKT_FILE_PROC_INFO_ID *shm_addr)
{
    register int i;
    int ret;
    key_t shm_key;
    int shm_id;

    for (i = 0;i < pro_no;i++)
    {
        shm_key =  (shm_addr + i)->shm_key;
        shm_id = shmget(shm_key,0,IPC_CREAT);
        if (shm_id < 0)
        {
            DEBUG("GT PRO SHM FAIL.");
            return ERR;
        }  
          
        ret = del_shm(shm_id);
        if (ret < 0)
            return ERR;
    }

    return OK;
}
#endif

/****************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int callback_pro_sem(int pro_no,PKT_FILE_PROC_INFO_ID shm_addr)
{
    register int i;
    int ret;
    key_t sem_key;
    int sem_id;

    for (i = 0;i < pro_no;i++)
    {
        sem_key = (shm_addr + i)->sem_key;
        sem_id = semget(sem_key,0,0666);
        if (sem_id < 0)
        {
            DEBUG("get pro sem id fail.");
            return ERR;
        } 
        
        ret = del_sem(sem_id);
	    if (ret < 0)
            return ERR;
    }

    return OK;
}
