
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
#include "ctl_access_network_list.h"

/*static function declaration*/
static int open_authorize_network_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
static unsigned long get_authorize_network_list_num(unsigned char *file_cnt_buf);
static unsigned long get_authorize_network_list_mode_switch(unsigned char *file_cnt_buf);
static int set_authorize_network_list_buf(AUTHORIZE_ACCESS_NETWORK_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num);
static int analysis_authorize_network_list_line(unsigned char *p,unsigned long index,AUTHORIZE_ACCESS_NETWORK_ID q,unsigned char mode_switch);
static void chk_half_chinese_code(unsigned char *p);
static int compar_network_authorize_resid(const void *a,const void *b);
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_authorize_network_list(int *shm_list_id,key_t *shm_list_key,unsigned long *num)
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

    AUTHORIZE_ACCESS_NETWORK_ID list_id = NULL;
    
    memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_NETWORK_FILE_NAME);

    if (SAIL_OK != open_authorize_network_list_file(file_path,&fd,&file_size))
    {
        error("[Err]Open authorize network  file error.\n");
        return ERR;
    }
   //printf("file_size = %d\n",file_size);
    file_cnt_buf = (char *)malloc(file_size + 1);
    if (NULL == file_cnt_buf)
    {
        error("[Err]Malloc for authorize network list file fail.\n");
        close(fd);
        return ERR;
    }

    if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
    {
        error("[Err]Get authorize network list file content fail.\n");
        free(file_cnt_buf);
        close(fd);
        return ERR;
    }
    file_cnt_buf[file_size] = '\0';  
    close(fd);
    //printf("file_cnt_buf =%s\n",file_cnt_buf);	
    mode_switch = get_authorize_network_list_mode_switch(file_cnt_buf);
    //printf("mode switch = %d\n",mode_switch);
    line_num = get_authorize_network_list_num(file_cnt_buf);
    if(line_num == 0){
		free(file_cnt_buf);
		return ERR;
	}
    g_max_shm_key += SHM_KEY_IVL;
    shm_size = authorize_access_network_size*line_num;

    shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shm_id < 0)
    {
		shm_id = get_shm(g_max_shm_key);
		if(shm_id<0){
			 error("create authorize network list shm fail.");
			free(file_cnt_buf);
        		return ERR;
		}
		DEL_SHM(shm_id);
	       shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       if(shm_id <0){
		   	 error("create authorize network list shm fail.");
		   	free(file_cnt_buf);
        		return ERR;
	       }
    }

    *shm_list_key = g_max_shm_key;
    *shm_list_id = shm_id;

    list_id = (AUTHORIZE_ACCESS_NETWORK_ID)shmat(shm_id,NULL,0);
    if (!list_id)
    {
        error("attach authorize network list shm fail.");
        free(file_cnt_buf);
        DEL_SHM(shm_id);
        return ERR;
    }

    (void)set_authorize_network_list_buf(list_id,file_cnt_buf,line_num,mode_switch,&read_num);
    
    *num = read_num;
   // read_num--;
    free(file_cnt_buf);
   // qsort(list_id,read_num,authorize_access_network_size,compar_network_authorize_resid);
    return OK;
}
/**********************************
*func name:比较两个用户信息 用户ID
*function:
*parameters:2009/04/24
*call:
*called:
*return:返回成功与否
*/
static int compar_network_authorize_resid(const void *a,const void *b){
	if(((AUTHORIZE_ACCESS_NETWORK*)a)->protect_resource_id==((AUTHORIZE_ACCESS_NETWORK*)b)->protect_resource_id)
		return 0;
	else  if(((AUTHORIZE_ACCESS_NETWORK*)a)->protect_resource_id> ((AUTHORIZE_ACCESS_NETWORK*)b)->protect_resource_id)
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
static int open_authorize_network_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        error("[Err]authorize network file don't exist.");
        return(CTL_FILE_NOT_EXIST);
    }

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        error("[Err]Open authorize network file fail.");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        error("[Err]authorize network file no content.");
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
static unsigned long get_authorize_network_list_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_NUM_KEY,key_val))
   {
            	  error("get authorize network list num  err.\n");
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
static unsigned long get_authorize_network_list_mode_switch(unsigned char *file_cnt_buf)
{
    register char *str = file_cnt_buf;
    char key_val[64];
    
    if (NULL == file_cnt_buf)
        return 1;
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_MODE_GETE_KEY,key_val))
   {
            	  error("get authorize network list mode switch  err.\n");
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
static int set_authorize_network_list_buf(AUTHORIZE_ACCESS_NETWORK_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num)
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
	if(0 == analysis_authorize_network_list_line(key_val,j,list_id,mode_switch_type)){
  		printf("LINE %d error \n",i);
		continue;
        }
	++j;
	printf("network access line %d ok\n",i);
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
static int analysis_authorize_network_list_line(unsigned char *p,unsigned long index,AUTHORIZE_ACCESS_NETWORK_ID q,unsigned char mode_switch){
	unsigned char *s=p;
	unsigned char *t=NULL;
	unsigned char *k=NULL;
	unsigned char *tmp_addr1=NULL;
	unsigned char *tmp_addr2=NULL;
	unsigned long i, len =0;
	
	if(p==NULL)
		return 0;
	/* get authorize id*/
	t = strtok(s,LIST_ITEMS_INDER);
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

	q[index].authorize_id = atoi(t);
	//printf("network authorize id = %d\n",q[index].authorize_id);
	/*get usr id */
	t = strtok(NULL,LIST_ITEMS_INDER);
	if(t == NULL)
		return 0;
#if 0
	len = strlen(t);
	for(i=0;i<len;i++){
		if(isdigit(t[i]))
			continue;
		return 0;
	}
#endif
	q[index].usr_id = atoi(t);
	//printf("network usr id = %d\n",q[index].usr_id);
	/*get protected resource id */
	t = strtok(NULL,LIST_ITEMS_INDER);
	if(t == NULL)
		return 0;
#if 0
	len = strlen(t);
	for(i=0;i<len;i++){
		if(isdigit(t[i]))
			continue;
		return 0;
	}
#endif
	q[index].protect_resource_id= atoi(t);
	printf("network protect resoure id = %d\n",q[index].protect_resource_id);
	/*get eaudit level*/
	t = strtok(NULL,LIST_ITEMS_INDER);
	if(t == NULL)
		return 0;
	len = strlen(t)>256?256:strlen(t);
	tmp_addr1 = t;
	//printf("len = %d eaudit level str = %s\n",len,tmp_addr1);
        t = strtok(NULL,LIST_ITEMS_INDER);
	if(t == NULL)
		return 0;
	tmp_addr2 = t;
       // printf("authorize level = %s\n",t);
        
   	/*in eaudit level , get eaudit direction */

	/*得到审计方向控制值*/
	k = strtok(tmp_addr1,LIST_ITEMS_DELIM);
	if(k==NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.eaudit_direction = atoi(k);
       // printf("network eaudit level direction = %d\n",q[index].eaudit_level.eaudit_direction);
	/*得到会话级审计控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k==NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.session_level = atoi(k);
 	/*得到记录级审计控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k==NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.record_level= atoi(k);
	/*得到事件级审计控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k==NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.event_level= atoi(k);
	/*得到分析级审计控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k==NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif 
	q[index].eaudit_level.analysis_level= atoi(k);
      /*得到综合分析审计控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k==NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.total_analysis_level = atoi(k);
      /*得到自定义审计控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k==NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.custom_made_level = atoi(k);
      /*得到管理级审计控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k==NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.manage_level= atoi(k);
	
	/*get authorize level */
       /*在授权模式下，得到命令授权审计控制值*/
	k = strtok(tmp_addr2,LIST_ITEMS_DELIM);
	if(k == NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].authorize_level.authorize_cmd = atoi(k);
	/*在授权模式下，得到网络帐号授权审计控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k == NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].authorize_level.authorize_account= atoi(k);
      /*在授权模式下，得到网络自定义通用授权控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k == NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].authorize_level.authorize_custom_made= atoi(k);
	/*在授权模式下，得到网络自定义协议特征授权控制值*/
	k = strtok(NULL,LIST_ITEMS_DELIM);
	if(k == NULL)
		return 0;
#if 0
	len = strlen(k);
	for(i=0;i<len;i++)
	{
		if(isdigit(k[i]))
			continue;
		return 0;
	}
#endif
	q[index].authorize_level.authorize_pro_feature_made= atoi(k);
        //printf("authorize_pro_feature_made = %d\n",q[index].authorize_level.authorize_pro_feature_made);
	/*得到轮询模式开关控制值*/
	q[index].mode_switch= mode_switch;
       // printf("mode_switch = %d\n",mode_switch);
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

