
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
#include "ctl_monitor_sysinfo_list.h"


/*static function declaration*/
static int open_monitor_sysinfo_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
static unsigned long get_monitor_sysinfo_list_num(unsigned char *file_cnt_buf);
static int set_monitor_sysinfo_list_buf(MONITOR_SYSINFO_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num);
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_monitor_sysinfo_list(MONITOR_SYSINFO_ID monitor_sysinfo_id)
{
    int fd;
    unsigned long file_size = 0;
    char file_path[MAX_FILE_PATH_SIZE+1];
    unsigned char *file_cnt_buf = NULL;
    unsigned long line_num = 0;
    unsigned long read_num=0;

    if(monitor_sysinfo_id ==NULL)
		return ERR;
    memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_MONITOR_SYS_INFO_FILE_NAME);

    monitor_sysinfo_id->cpu_use_rate = 80;
    monitor_sysinfo_id->mem_use_rate = 80;
    monitor_sysinfo_id->hd_use_rate = 80;

    if (SAIL_OK != open_monitor_sysinfo_list_file(file_path,&fd,&file_size))
    {
        error("[Err]Open monitor sysinfo  list file error.\n");
        return ERR;
    }
    file_cnt_buf = (unsigned char *)malloc(file_size + 1);
    if (NULL == file_cnt_buf)
    {
        error("[Err]Malloc for authorize account list file fail.\n");
        close(fd);
        return ERR;
    }

    if (NULL == cfg_get_file_cnt(fd,(char *)file_cnt_buf,file_size))
    {
        error("[Err]Get authorize account list file content fail.\n");
        free(file_cnt_buf);
        close(fd);
        return ERR;
    }
    file_cnt_buf[file_size] = '\0';  
    close(fd);
    printf("file_cnt_buf =%s\n",file_cnt_buf);	
  
    line_num = get_monitor_sysinfo_list_num(file_cnt_buf);
   if(line_num == 0){
		free(file_cnt_buf);
		return ERR;
   }
    if(CTL_PAR_ERR == set_monitor_sysinfo_list_buf(monitor_sysinfo_id,file_cnt_buf,line_num,&read_num))
		return ERR;
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
static int open_monitor_sysinfo_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        error("[Err]monitor sysinfo file don't exist.");
        return(CTL_FILE_NOT_EXIST);
    }

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        error("[Err]monitor sysinfo rules file fail.");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        error("[Err]monitor sysinfo  file no content.");
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
static unsigned long get_monitor_sysinfo_list_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = (char *)file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_NUM_KEY,key_val))
   {
            	  error("get monitor sysinfo  list num  err.\n");
                return 0;
   }
    num = atoi(key_val);
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
static int set_monitor_sysinfo_list_buf(MONITOR_SYSINFO_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num)
{
    unsigned long i = 0;
    unsigned long j =0;
    char *s = (char *)file_cnt_buf;
    unsigned char key_val[512];
    char info_str[32];
    if ((NULL == list_id) || (NULL == file_cnt_buf)||(0==buf_num))
        return(CTL_PAR_ERR);
	
    for(i=0;i<buf_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,(char *)key_val))
   	{
            	  error("get monitor sysinfo  line  err.\n");
                continue;
   	}
       if(i==0)
	   	list_id->cpu_use_rate = atoi((char *)key_val);
	else if(i==1)
		list_id->mem_use_rate= atoi((char *)key_val);
		else
			list_id->hd_use_rate= atoi((char *)key_val);
	++j;
	printf("line %ld ok\n",i);
    }
    *real_list_num = j;
    if(j == buf_num)
    	return(SAIL_OK);
    else
	return(CTL_PAR_ERR);
}

