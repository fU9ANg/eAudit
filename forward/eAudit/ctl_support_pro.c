
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
int open_support_pro_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        printf("[Err]Support protocols list file don't exist.\n");
        return(CTL_FILE_NOT_EXIST);
    }

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        printf("[Err]Open support protocols list file Fail.\n");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        printf("[Err]Support protocols list file all size is 0.\n");
        close(fd);
        return(CTL_FILE_IS_NULL);
    }

    *fd_ptr = fd;
    *file_size_ptr = file_size;
    //printf("###filesize = %d\n",file_size);
	
    return(SAIL_OK); 
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void close_support_pro_file(int fd)
{
    if (DEF_FILE_DES_VAL != fd)
        close(fd);
        
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
int get_support_pro_num(int fd)
{
    register int i;
    int num = 0;
    int len = 0;
    char buf[MAX_PRO_NUM_SIZE];
    
    if (DEF_FILE_DES_VAL == fd)
        return(CTL_PAR_ERR);
    
    if (lseek(fd,0,SEEK_SET) < 0)
    {
        error("[Err]Lseek to support protocols list file head err.\n");
        return 0;
    }

    memset(buf,0x00,MAX_PRO_NUM_SIZE);
    if (read(fd,buf,MAX_PRO_NUM_SIZE) < 0)
    {
        error("[Err]Read support protocols list file err.\n");
        return 0;
    }
    
    len = strlen(buf);
    
    for (i = len - 1;i >= 0;i--)
    {
        if ((buf[i] == SUPPORT_PRO_ITEMS_DELIM_CHAR) 
	      || (buf[i] == '\n') || (buf[i] == '\r'))
        {
            buf[i] = '\0';
            break;
        }
    }
    
    num = atoi(buf);

#ifdef _DEBUG
  //  info("[Info]The sys support protocols number is:%d\n",num);
#endif 
   
    return num;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_support_pro(SUPPORT_PRO_NODE_ID support_pro_id,char *file_cnt_buf,int pro_num)
{
    register int i = 0;
    char *s = file_cnt_buf;
    char *p = NULL;
        
    strtok(s,SUPPORT_PRO_ITEMS_DELIM);  /*all protocols num*/
    
    while((p = strtok(NULL,SUPPORT_PRO_ITEMS_DELIM)) != NULL)
    {
        i++;
        if (i > pro_num)
            break;
        
        trim(p);
        
        (support_pro_id + i - 1)->pro_no = i - 1;
        strcpy((support_pro_id + i - 1)->pro_name,p);

#ifdef _DEBUG
 //       info("[Info]p = %s\n",p);
#endif  
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
int chk_support_pro(SUPPORT_PRO_NODE_ID support_pro_id,int pro_num)
{
    register int i;
    register int j;
    
    for (i = 0;i < pro_num;i++)
    {
        for (j = i + 1;j < pro_num;j++)
        {
            if (0 == strcmp((support_pro_id + i)->pro_name,(support_pro_id + j)->pro_name))
                return CTL_SUPPORT_PRO_FILE_ERR;

	     if ((support_pro_id + i)->pro_no == (support_pro_id + j)->pro_no)
	         return CTL_SUPPORT_PRO_FILE_ERR;
        } 
    }
    
    return SAIL_OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
SUPPORT_PRO_NODE_ID create_pro_table(key_t shm_key,int *tbl_shm_id,SUPPORT_PRO_NODE_ID support_pro_id,int pro_num)
{
    int shm_id;
    int shm_size;
    SUPPORT_PRO_NODE_ID shm_addr = NULL;
    
    shm_size = pro_num*SUPPORT_PRO_NODE_SIZE;
    
    shm_id = shmget(shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shm_id < 0)
    {
    	 	shm_id = get_shm(shm_key);
		if(shm_id<0){
			error("[Err]Create protocols table shm fail.\n");
        		return NULL;
		}
		DEL_SHM(shm_id);
	       shm_id = shmget(shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       if(shm_id <0){
		   	error("[Err]Create protocols table shm fail.\n");
        		return NULL;
	       }
    }
    
    shm_addr = (SUPPORT_PRO_NODE_ID)shmat(shm_id,NULL,0);
    if (!shm_addr)
    {
        error("[Err]Attatch protocols table shm fail.\n");
        return NULL;
    }
    
    memcpy(shm_addr,support_pro_id,shm_size);
    
    *tbl_shm_id = shm_id;
    
    return shm_addr;
}
