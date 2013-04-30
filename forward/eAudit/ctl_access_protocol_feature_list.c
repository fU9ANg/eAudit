
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
#include "ctl_access_protocol_feature_list.h"

/*static function declaration*/
static int open_authorize_protocol_feature_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
static unsigned long get_authorize_protocol_feature_list_num(unsigned char *file_cnt_buf);
static unsigned long get_authorize_protocol_feature_list_mode_switch(unsigned char *file_cnt_buf);
static int set_authorize_protocol_feature_list_buf(AUTHORIZE_PROTOCOL_FEATURE_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num);
static int analysis_authorize_protocol_feature_list_line(unsigned char *p,unsigned long index,AUTHORIZE_PROTOCOL_FEATURE_ID q,unsigned char mode_switch);
static void chk_half_chinese_code(unsigned char *p);
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_authorize_protocol_feature_list(int *shm_list_id,key_t *shm_list_key,unsigned long *num,char *pro_name)
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

    AUTHORIZE_PROTOCOL_FEATURE_ID list_id = NULL;
    
    memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(file_path,"%s/%s%s%s",SNAM_CFG_DIR,"eAudit_Authorize_access_",pro_name,"_feature.conf");
   // printf("protocol config file path = %s\n",file_path);
    if (SAIL_OK != open_authorize_protocol_feature_list_file(file_path,&fd,&file_size))
    {
        error("[Err]Open authorize protocol feature list file error.\n");
        return ERR;
    }
   //printf("file_size = %d\n",file_size);
    file_cnt_buf = (char *)malloc(file_size + 1);
    if (NULL == file_cnt_buf)
    {
        error("[Err]Malloc for authorize protocol feature list file fail.\n");
        close(fd);
        return ERR;
    }

    if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
    {
        error("[Err]Get authorize protocol feature list file content fail.\n");
        free(file_cnt_buf);
        close(fd);
        return ERR;
    }
    file_cnt_buf[file_size] = '\0';  
    close(fd);
    //printf("file_cnt_buf =%s\n",file_cnt_buf);	
    mode_switch = get_authorize_protocol_feature_list_mode_switch(file_cnt_buf);
    //printf("mode switch = %d\n",mode_switch);
    line_num = get_authorize_protocol_feature_list_num(file_cnt_buf);
    if(line_num == 0){
		free(file_cnt_buf);
		return ERR;
	}
   
    g_max_shm_key += SHM_KEY_IVL;
    shm_size = authorize_protocol_feature_size*line_num;
  //  printf("profeature key = %u \n",g_max_shm_key);
    shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shm_id < 0)
    {
    		shm_id = get_shm(g_max_shm_key);
		if(shm_id<0){
			 error("create authorize protocol feature list shm fail.");
        		free(file_cnt_buf);
        		return ERR;
		}
		DEL_SHM(shm_id);
	       shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       if(shm_id <0){
		   	error("create authorize protocol feature list shm fail.");
       		 free(file_cnt_buf);
        		return ERR;
	       }
    }

    *shm_list_key = g_max_shm_key;
    *shm_list_id = shm_id;

    list_id = (AUTHORIZE_PROTOCOL_FEATURE_ID)shmat(shm_id,NULL,0);
    if (!list_id)
    {
        error("attach authorize protocol feature  list shm fail.");
        free(file_cnt_buf);
        DEL_SHM(shm_id);
        return ERR;
    }

    (void)set_authorize_protocol_feature_list_buf(list_id,file_cnt_buf,line_num,mode_switch,&read_num);
   
    *num = read_num;
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
static int open_authorize_protocol_feature_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        error("[Err]authorize protocol feature  file don't exist.");
        return(CTL_FILE_NOT_EXIST);
    }

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        error("[Err]authorize protocol featurerules file fail.");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        error("[Err]authorize protocol feature file no content.");
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
static unsigned long get_authorize_protocol_feature_list_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_NUM_KEY,key_val))
   {
            	  error("get authorize protocol feature list num  err.\n");
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
static unsigned long get_authorize_protocol_feature_list_mode_switch(unsigned char *file_cnt_buf)
{
    register char *str = file_cnt_buf;
    char key_val[64];
    
    if (NULL == file_cnt_buf)
        return 1;
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_MODE_GETE_KEY,key_val))
   {
            	  error("getauthorize protocol feature mode switch  err.\n");
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
static int set_authorize_protocol_feature_list_buf(AUTHORIZE_PROTOCOL_FEATURE_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num)
{
    unsigned long i = 0;
    unsigned long j =0;
    char *p = NULL;
    char *s = file_cnt_buf;
    AUTHORIZE_PROTOCOL_FEATURE_ID d = list_id;
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
            	  error("get authorize protocol feature line  err.\n");
                continue;
   	}
	if(0 == analysis_authorize_protocol_feature_list_line(key_val,j,list_id,mode_switch_type)){
  		printf("LINE %d error \n",i);
		
		continue;
        }
	++j;
	//printf("line %d ok\n",i);
	
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
static int analysis_authorize_protocol_feature_list_line(unsigned char *p,unsigned long index,AUTHORIZE_PROTOCOL_FEATURE_ID q,unsigned char mode_switch){
	unsigned char *s=p;
	unsigned char *t=NULL;
	unsigned char *tmp_addr = NULL;
	unsigned char *not_authorize=NULL;
	unsigned char *t1=NULL;
	unsigned long i,j,k,shm_size,len =0;
	AUTHORIZE_PROTOCOL_FEATURE_CONTENT_ID content_id = NULL;
	AUTHORIZE_PROTOCOL_FEATURE_TYPE_ID pro_feature_content_type_id=NULL;
	unsigned long feature_type_num =0;
	unsigned long feature_content_num=0;
	int shm_id = -1;
	
	if(p==NULL)
		return 0;
	/* 1  get authorize  id*/
	t = strtok(s,LIST_ITEMS_INDER);
       not_authorize = strtok(NULL,LIST_ITEMS_INDER);
       t1 = strtok(NULL,LIST_ITEMS_INDER);  
	if(t==NULL||not_authorize==NULL||t1==NULL)
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
	q[index].authorize_id = atoi(t);
       tmp_addr = strtok(not_authorize,LIST_ITEMS_DELIM);
	if(tmp_addr == NULL)
		return 0;
#if 0
	len = strlen(tmp_addr);
	for(i=0;i<len;i++)
	{
		if(isdigit(tmp_addr[i]))
			continue;
		return 0;
	}
#endif
       q[index].against_authorize_event.block_flag = atoi(tmp_addr);
	//DEBUG("q[%d].against_authorize_event.block_flag =%d",index,q[index].against_authorize_event.block_flag);
        tmp_addr = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr == NULL)
		return 0;
#if 0
	len = strlen(tmp_addr);
	for(i=0;i<len;i++)
	{
		if(isdigit(tmp_addr[i]))
			continue;
		return 0;
	}
#endif
       q[index].against_authorize_event.warn_flag = atoi(tmp_addr);
	//DEBUG("q[%d].against_authorize_event.block_flag =%d",index,q[index].against_authorize_event.warn_flag);
	 tmp_addr = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr == NULL)
		return 0;
#if 0
	len = strlen(tmp_addr);
	for(i=0;i<len;i++)
	{
		if(isdigit(tmp_addr[i]))
			continue;
		return 0;
	}
#endif
       q[index].against_authorize_event.log_flag = atoi(tmp_addr);
	//DEBUG("q[%d].against_authorize_event.block_flag =%d",index,q[index].against_authorize_event.log_flag);
	
      t = t1;
	/*2 get authorize pro feature type num  ,alloc memory for pro feature type num*/
	tmp_addr = strtok(t,LIST_ITEMS_DELIM);
	if(tmp_addr == NULL)
		return 0;
#if 0
	len = strlen(tmp_addr);
	for(i=0;i<len;i++)
	{
		if(isdigit(tmp_addr[i]))
			continue;
		return 0;
	}
#endif
	q[index].pro_feature_num= atoi(tmp_addr);
	if(q[index].pro_feature_num==0)
		return 0;
	feature_type_num = q[index].pro_feature_num;
     /*分配共享内存，以便于存储协议特征类别值*/
	 g_max_shm_key += SHM_KEY_IVL;
    	shm_size = authorize_protocol_feature_type_size*q[index].pro_feature_num;
	//printf("pro feature jfdks g_max_shm_key = %u\n",g_max_shm_key);
       shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    	if (shm_id < 0)
    	{
    		shm_id = get_shm(g_max_shm_key);
		if(shm_id<0){
			 error("create authorize protocol feature list shm fail.");
        		return ERR;
		}
		DEL_SHM(shm_id);
	       shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       if(shm_id <0){
		   	error("create authorize protocol feature list shm fail.");
        		return ERR;
	       }
    	}
    	pro_feature_content_type_id = (AUTHORIZE_PROTOCOL_FEATURE_TYPE_ID)shmat(shm_id,NULL,0);
    	if (!pro_feature_content_type_id)
    	{
      	  	error("attach authorize protocol feature  type list shm fail.");
        	DEL_SHM(shm_id);
        	return ERR;
   	 }
	q[index].authorize_protocol_feature_key= g_max_shm_key;
      for(j=0;j<feature_type_num;j++){
		tmp_addr = strtok(NULL,LIST_ITEMS_DELIM);
		if(tmp_addr == NULL)
			return 0;
	#if 0
		len = strlen(tmp_addr);
		for(i=0;i<len;i++)
		{
			if(isdigit(tmp_addr[i]))
				continue;
			return 0;
		}
	#endif
		pro_feature_content_type_id[j].authorize_type = atoi(tmp_addr);
		//printf("authorize type = %d\n",pro_feature_content_type_id[j].authorize_type);
		
		tmp_addr = strtok(NULL,LIST_ITEMS_DELIM);
		if(tmp_addr == NULL)
			return 0;
	#if 0
		len = strlen(tmp_addr);
		for(i=0;i<len;i++)
		{
			if(isdigit(tmp_addr[i]))
				continue;
			return 0;
		}
	#endif
		feature_content_num = atoi(tmp_addr);
		if(feature_content_num==0)
			return 0;
		pro_feature_content_type_id[j].authorize_feature_content_num = feature_content_num;
		//printf("feature content num = %d\n",feature_content_num);
              /*创建协议特征内容共享内存区域*/
              g_max_shm_key += SHM_KEY_IVL;
    		shm_size = authorize_protocol_feature_content_size*feature_content_num;
    		shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    		if (shm_id < 0)
    		{
    			shm_id = get_shm(g_max_shm_key);
			if(shm_id<0){
			 	error("create authorize protocol feature list shm fail.");
        			return ERR;
			}
			DEL_SHM(shm_id);
	       	shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	      		if(shm_id <0){
		   		error("create authorize protocol feature list shm fail.");
        			return ERR;
	       	}
    		}
    		content_id = (AUTHORIZE_PROTOCOL_FEATURE_CONTENT_ID)shmat(shm_id,NULL,0);
    		if (!content_id)
    		{
      	  		error("attach authorize protocol feature  list shm fail.");
        		DEL_SHM(shm_id);
        		return ERR;
   	 	}
		pro_feature_content_type_id[j].authorize_protocol_feature_content_key = g_max_shm_key;
		/*解析填充相应数据到内存地址*/
		for(k=0;k<feature_content_num;k++){
			tmp_addr = strtok(NULL,LIST_ITEMS_DELIM);
			if(tmp_addr == NULL)
				return 0;
			len = strlen(tmp_addr)>255?255:strlen(tmp_addr);
			memcpy(content_id[k].pro_feature_content,tmp_addr,len);
			//printf("pro_feature_content = %s\n",content_id[k].pro_feature_content);
		}
	}
	q[index].mode_switch = mode_switch;
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

