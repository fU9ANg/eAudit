
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
#include "ctl_usr_list.h"

/*static function declaration*/
static int open_usr_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
static unsigned long get_usr_list_num(unsigned char *file_cnt_buf);
static unsigned long get_usr_list_mode_switch(unsigned char *file_cnt_buf);
static int set_usr_list_buf(USR_LIST_MEM_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num);
static int analysis_usr_list_line(unsigned char *p,unsigned long index,USR_LIST_MEM_ID q,unsigned char mode_switch);
static void chk_half_chinese_code(unsigned char *p);
static int compar_usrid(const void *a,const void *b);
static int com_usr_list_id(const void* a,const void *b);
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_usr_list(int *shm_list_id,key_t *shm_list_key,unsigned long *num,int usr_num)
{
    int fd;
    unsigned long file_size = 0;
    char file_path[MAX_FILE_PATH_SIZE+1];
    unsigned char *file_cnt_buf = NULL;
    unsigned long line_num = 0;
    unsigned char mode_switch=0;
    unsigned long read_num=0;
    int shm_id;
    unsigned long shm_size;
    USR_LIST_MEM_ID list_id = NULL;
    int usrid =0;
    USR_LIST_MEM_ID list_id0 = NULL;
	
    
    memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_USR_LIST_FILE_NAME);

    if (SAIL_OK != open_usr_list_file(file_path,&fd,&file_size))
    {
        error("[Err]Open usr list file error.\n");
        return ERR;
    }
   //printf("file_size = %d\n",file_size);
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
    mode_switch = get_usr_list_mode_switch(file_cnt_buf);
    line_num = get_usr_list_num(file_cnt_buf);
    if(line_num>= usr_num)
		line_num = usr_num;
   if(line_num == 0){
		free(file_cnt_buf);
		return ERR;
   }
    g_max_shm_key += SHM_KEY_IVL;
    shm_size = USR_LIST_MEM_SIZE*line_num;

    shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shm_id < 0)
    {
    		shm_id = get_shm(g_max_shm_key);
		if(shm_id<0){
			 error("create usr list shm fail.");
        		free(file_cnt_buf);
        		return ERR;
		}
		DEL_SHM(shm_id);
	       shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       if(shm_id <0){
		   	 error("create usr list shm fail.");
       		 free(file_cnt_buf);
        		return ERR;
	       }
    }

    *shm_list_key = g_max_shm_key;
    *shm_list_id = shm_id;

    list_id = (USR_LIST_MEM_ID)shmat(shm_id,NULL,0);
    if (!list_id)
    {
        error("attach usr list shm fail.");
        free(file_cnt_buf);
        DEL_SHM(shm_id);
        return ERR;
    }

    (void)set_usr_list_buf(list_id,file_cnt_buf,line_num,mode_switch,&read_num);
   
   *num = read_num;
   read_num--;
    free(file_cnt_buf);
    qsort(list_id,read_num,USR_LIST_MEM_SIZE,compar_usrid);
#if 0
   /*test test 2009 0505*/
   //printf("usr info len =%d \n",sizeof(USR_LIST_MEM));
   usrid = 9490;
   list_id0 = (USR_LIST_MEM_ID) bsearch((const void*)usrid,(void*)list_id,read_num,USR_LIST_MEM_SIZE,com_usr_list_id);
   if(list_id0!=NULL){
		printf("find ok usrid = %d\n",list_id0->iUsrId);	
   }
   usrid = 1034;
   list_id0 = (USR_LIST_MEM_ID) bsearch((const void*)usrid,(void*)list_id,read_num,USR_LIST_MEM_SIZE,com_usr_list_id);
   if(list_id0!=NULL){
		printf("find ok usrid = %d\n",list_id0->iUsrId);	
   }
   usrid = 4690;
   list_id0 = (USR_LIST_MEM_ID) bsearch((const void*)usrid,(void*)list_id,read_num,USR_LIST_MEM_SIZE,com_usr_list_id);
   if(list_id0!=NULL){
		printf("find ok usrid = %d\n",list_id0->iUsrId);	
   }

 #endif
    return OK;

}


static int com_usr_list_id(const void* a,const void *b){
	if((unsigned long )a==((USR_LIST_MEM*)b)->iUsrId)
		return 0;
	else if((unsigned long )a > ((USR_LIST_MEM*)b)->iUsrId)
		return 1;
	else 
		return -1;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int open_usr_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
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
static unsigned long get_usr_list_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_NUM_KEY,key_val))
   {
            	  error("get usr list num  err.\n");
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
static unsigned long get_usr_list_mode_switch(unsigned char *file_cnt_buf)
{
    register char *str = file_cnt_buf;
    char key_val[64];
    
    if (NULL == file_cnt_buf)
        return 1;
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_MODE_GETE_KEY,key_val))
   {
            	  error("get list mode switch  err.\n");
                return 1;
   }
   if(strlen(key_val)<2)
   	return 1;
    if(strncmp(key_val, "ON", 2) ==0)
    		return 1;
   return 0;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int set_usr_list_buf(USR_LIST_MEM_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num)
{
    unsigned long i = 0;
    unsigned long j =0;
    char *p = NULL;
    char *s = file_cnt_buf;
    USR_LIST_MEM_ID d = list_id;
    unsigned char key_val[512];
    char info_str[32];
    if ((NULL == list_id) || (NULL == file_cnt_buf)||(0==buf_num))
        return(CTL_PAR_ERR);
	
    for(i=0;i<buf_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%d",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,key_val))
   	{
            	  error("get list mode switch  err.\n");
                continue;
   	}
	if(0 == analysis_usr_list_line(key_val,j,list_id,mode_switch_type)){
  		printf("LINE %d error \n",i);
		continue;
        }
	++j;
	printf("user info line %d ok\n",i);
    }
    *real_list_num = j;
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
static int analysis_usr_list_line(unsigned char *p,unsigned long index,USR_LIST_MEM_ID q,unsigned char mode_switch){
	unsigned char *s =p;
	unsigned char *t=NULL;
	unsigned long i, len =0;
	unsigned char *ip = NULL;
	unsigned char *haddr = NULL;
	int centifymethod;
	
	if(p==NULL)
		return 0;
	/*get usr id*/
	t = strtok(s,LIST_ITEMS_DELIM);
	if(t==NULL)
		return 0;
#if 0
	len = strlen(t);
	for(i=0;i<len;i++)
	{
		if(isdigit(t[i]))
			continue;
		return 0;
	}
#endif
	q[index].iUsrId = atoi(t);
	/*get usr ip */
	t = NULL;
	t = strtok(NULL,LIST_ITEMS_DELIM);
	if(t == NULL)
		return 0;
	ip = t;

	q[index].ip = inet_addr(t);
	/*get usr mac*/
	t =NULL;
	t = strtok(NULL,LIST_ITEMS_DELIM);
	if(t == NULL)
		return 0;
//	len = strlen(t)>32?32:strlen(t);

	haddr = t;
	strcpy(q[index].strMac,t);
	/*get usr name*/
	t =NULL;
	t = strtok(NULL,LIST_ITEMS_DELIM);
	if(t == NULL)
		return 0;
//	len = strlen(t)>256?256:strlen(t);
	//chk_half_chinese_code(t);
	strcpy(q[index].strUsrName,t);
        //printf("strUsrName = %s\n",q[index].strUsrName);
	/*get usr mode switch*/
	t =NULL;
	t = strtok(NULL,LIST_ITEMS_DELIM);
	if(t == NULL)
		return 0;
#if 0
	len = strlen(t);
	for(i=0;i<len;i++)
	{
		if(isdigit(t[i]))
			continue;
		return 0;
	}
#endif
	centifymethod = atoi(t);

	switch(centifymethod)
	{
		case 0:
			if(!is_valid_ip(ip))
			{
				return 0;
			}
			
			break;

		case 1:
			if(!is_valid_haddr(haddr))
			{
				return 0;
			}
			break;

		case 2:
			if(!is_valid_ip(ip) || !is_valid_haddr(haddr))
			{
				return 0;
			}
			break;

	}

	q[index].iUsrCertifyMethod = centifymethod;
	q[index].Mode_Switch = mode_switch;
	return 1;
}

int is_valid_ip(const unsigned char* ip)
{
	char* p = ip;
	int i;
	char c = 0;

	if(p == NULL)
	{
		return 0;
	}
	
	while( *p != NULL)
	{
		if(*p == '.')
		{
			c++;
		}else
		{
			if(!isdigit(*p))
			{
				return 0;
			}
		}
		p++;
	}
	if(c == 3)
	{
		return 1;
	}
}

int is_valid_haddr(const unsigned char* haddr)
{
	char* ha = haddr;
	if(ha == NULL || strlen(ha) != 12)
	{
		return 0;
	}
	while(*ha != NULL)
	{
		if(!isdigit(*ha)&& !isupper(*ha))
		{
			return 0;
		}

		ha++;
	}
	return 1;

}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void chk_half_chinese_code(unsigned char *p)
{
    int i;
    int size = 0;
    int len = 0;

    if (NULL == p)
       return;

    len = strlen(p);
    if (0 == len)
       return;

    for(i = 0;i < len;i++)
    {
        if( p[i] > 0 && p[i] <= 127)   
        {     
        }
        else
        {
            size++;
        }
    }    
    if (size%2 == 0)
        return;
 
    p[len - 1] = '\0';   
}
/**********************************
*func name:比较两个用户信息 用户ID
*function:
*parameters:2009/04/24
*call:
*called:
*return:返回成功与否
*/
static int compar_usrid(const void *a,const void *b){
	if(((USR_LIST_MEM*)a)->iUsrId==((USR_LIST_MEM*)b)->iUsrId)
		return 0;
	else  if(((USR_LIST_MEM*)a)->iUsrId> ((USR_LIST_MEM*)b)->iUsrId)
		return 1;
	else 
		return -1;
}
