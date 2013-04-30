
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <stdarg.h>
#include <time.h>
#include <syslog.h>

#include "eAudit_lib_Head.h"

#include "ctl_pub.h"
#include "ctl_debug.h"
#include "interface_pub.h"
#include "interface_pmc.h"
#include "ctl_sys_info.h"
#include "ctl_config.h"
#include "ctl_filter_rule.h"
#include "ctl_sq_list.h"

/*static function declaration*/
static int open_sq_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
static unsigned long get_sq_list_num(char *file_cnt_buf);
static int set_sq_list_buf(SQ_LIST_MEM_ID list_id,char *file_cnt_buf,unsigned long buf_num);
static int set_sq_list_item(SQ_LIST_MEM_ID list_id,char *buf);
static void copy_sq_list_item(SQ_LIST_MEM_ID list_id,int item_no,char *item);

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_sq_list(int *shm_list_id,key_t *shm_list_key,unsigned long *num)
{
    int fd;
    unsigned long file_size = 0;
    char file_path[MAX_FILE_PATH_SIZE+1];
    char *file_cnt_buf = NULL;
    unsigned long line_num = 0;

    int shm_id;
    unsigned long shm_size;

    SQ_LIST_MEM_ID list_id = NULL;
    
    memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
   // sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_SQ_FILE_NAME);

    if (SAIL_OK != open_sq_list_file(file_path,&fd,&file_size))
    {
        error("[Err]Open usr list file error.\n");

        return ERR;
    }

    file_cnt_buf = (char *)malloc(file_size + 1);
    if (NULL == file_cnt_buf)
    {
        error("[Err]Malloc for usr list file fail.\n");
        close(fd);
        return ERR;
    }

    if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
    {
        error("[Err]Get usr list file content fail.\n");
        free(file_cnt_buf);
        close(fd);
        return ERR;
    }
    file_cnt_buf[file_size] = '\0';  
    close(fd);

    line_num = get_sq_list_num(file_cnt_buf);
    *num = line_num;

     g_max_shm_key += SHM_KEY_IVL;
     shm_size = SQ_LIST_MEM_SIZE*line_num;

    shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shm_id < 0)
    {
        error("create usr list shm fail.");
        free(file_cnt_buf);
        return ERR;
    }

    *shm_list_id = shm_id;
    *shm_list_key = g_max_shm_key;

    list_id = (SQ_LIST_MEM_ID)shmat(shm_id,NULL,0);
    if (!list_id)
    {
        error("attach usr list shm fail.");
        free(file_cnt_buf);
        DEL_SHM(shm_id);
        return ERR;
    }

    (void)set_sq_list_buf(list_id,file_cnt_buf,line_num);

    free(file_cnt_buf);
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
static int open_sq_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        error("[Err]Protect rules file don't exist.");
        return(CTL_FILE_NOT_EXIST);
    }

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        error("[Err]Open protect rules file fail.");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        error("[Err]Protect rules file no content.");
        close(fd);
        return(CTL_FILE_IS_NULL);
    }

    *fd_ptr = fd;
    *file_size_ptr = file_size;
	
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
static unsigned long get_sq_list_num(char *file_cnt_buf)
{
    register unsigned long i = 0;
    register int num = 0;
    register char *str = file_cnt_buf;
    
    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    
    while (str[i] != '\0')
    {
        if (LIST_LINE_END_ASC == str[i])
            num++;
        i++;
    }    
    
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
static int set_sq_list_buf(SQ_LIST_MEM_ID list_id,char *file_cnt_buf,unsigned long buf_num)
{
    unsigned long i = 0;
    char *p = NULL;
    char *s = file_cnt_buf;
    SQ_LIST_MEM_ID d = list_id;
    
    if ((NULL == list_id) || (NULL == file_cnt_buf))
        return(CTL_PAR_ERR);

    strtok(s,LIST_LINE_DELIM);

    trim(s);
    set_sq_list_item(d,s);
    i++;
    
    while((p = strtok(NULL,LIST_LINE_DELIM)) != NULL)
    {
          i++;
          if (i > buf_num)
              break;
       
          if (i <= buf_num)
          {
              trim(p);
              d++;
    	      set_sq_list_item(d,p);
    	  }
    }
    
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
static int set_sq_list_item(SQ_LIST_MEM_ID list_id,char *buf)
{
    register int i = 0;
    register char *s = buf;
    register char *p = NULL;
    
    if ((NULL == list_id) || (NULL == buf))
        return(CTL_PAR_ERR);
    
    p = s;
    while (*s != '\0')
    {
        if (LIST_ITEMS_DELIM_CHAR == *s)
        {
            i++;
            if (i > SQ_LIST_ITEMS_NUM)
                break;

            *s = '\0';
            trim(p);          
            copy_sq_list_item(list_id,i,p);
            p = s + sizeof(char);       
        }
        
        s++;
    }
    
    i++;
    trim(p);
    copy_sq_list_item(list_id,i,p);
    
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
static void copy_sq_list_item(SQ_LIST_MEM_ID list_id,int item_no,char *item)
{
    register char *p = item;

    switch(item_no)
    {
        case 1:
            list_id->iUsrGId = atoi(p);
            break;
        case 2:
            list_id->iRuleGId = atoi(p);
            break;         
        default:  
            break;  
    }
  
    return;
}
