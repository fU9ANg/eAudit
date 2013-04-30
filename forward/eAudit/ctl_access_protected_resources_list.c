
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
#include "ctl_access_protected_resources_list.h"

/*static function declaration*/
static int open_protects_resources_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
static unsigned long get_protects_resources_list_num(unsigned char *file_cnt_buf);
static unsigned long get_protects_resources_list_mode_switch(unsigned char *file_cnt_buf);
static int set_protects_resources_list_buf(PROTECTED_RESOURCE_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num,int *Line);
static int analysis_protects_resources_list_line(unsigned char *p,unsigned long index,PROTECTED_RESOURCE_ID q,unsigned char mode_switch);
static void chk_half_chinese_code(unsigned char *p);
static int src_port_analysis(unsigned char  port_mode,unsigned char *str,unsigned long index,PROTECTED_RESOURCE_ID q);
static int dst_port_analysis(unsigned char  port_mode,unsigned char *str,unsigned long index,PROTECTED_RESOURCE_ID q);
static int unauthorize_event_dispose_analysis(unsigned char *str ,unsigned long index,PROTECTED_RESOURCE_ID q);
static int eaudit_level_dispose_analysis(unsigned char *str ,unsigned long index,PROTECTED_RESOURCE_ID q);
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_protected_resources_list(int *shm_list_id,key_t *shm_list_key,unsigned long *num,int res_num,int *Line)
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

    PROTECTED_RESOURCE_ID list_id = NULL;
    int log_pri = FILE_LOG;	
    write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"########################fjasdj!\n");
    memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_PROTECT_RESOURCE_FILE_NAME);

    if (SAIL_OK != open_protects_resources_list_file(file_path,&fd,&file_size))
    {
        error("[Err]Open protected resources list file error.\n");
        return ERR;
    }
   //printf("file_size = %d\n",file_size);
    file_cnt_buf = (char *)malloc(file_size + 1);
    if (NULL == file_cnt_buf)
    {
        error("[Err]Malloc for protected resources list file fail.\n");
        close(fd);
        return ERR;
    }

    if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
    {
        error("[Err]Get protected resources list file content fail.\n");
        free(file_cnt_buf);
        close(fd);
        return ERR;
    }
    file_cnt_buf[file_size] = '\0';  
    close(fd);
    //printf("file content = %s\n",file_cnt_buf);	
    mode_switch = get_protects_resources_list_mode_switch(file_cnt_buf);
    //printf("mode switch = %d\n",mode_switch);
    line_num = get_protects_resources_list_num(file_cnt_buf);
   if(line_num>=res_num)
   	line_num = res_num;
    //printf("line num = %d\n",line_num);
   // *num = line_num;
    if(line_num == 0){
		free(file_cnt_buf);
		return ERR;
	}
    g_max_shm_key += SHM_KEY_IVL;
    shm_size = protected_resource_size*line_num;

    shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shm_id < 0)
    {
    		shm_id = get_shm(g_max_shm_key);
		if(shm_id<0){
			error("create protected resources list shm fail.");
			free(file_cnt_buf);
        		return ERR;
		}
		DEL_SHM(shm_id);
	       shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       if(shm_id <0){
		   	error("create protected resources list shm fail.");
		   	free(file_cnt_buf);
        		return ERR;
	       }
    }
   // printf("alloc shm ok\n");
    *shm_list_key = g_max_shm_key;
    *shm_list_id = shm_id;
    //printf("start get list_id\n");
    list_id = (PROTECTED_RESOURCE_ID)shmat(shm_id,NULL,0);
    if (!list_id)
    {
        error("attach protected resources  list shm fail.");
        free(file_cnt_buf);
        DEL_SHM(shm_id);
        return ERR;
    }
     //printf("start .....\n");
     memset((char *)list_id,0x00,shm_size);
     //printf("start 1 ......\n");
    (void)set_protects_resources_list_buf(list_id,file_cnt_buf,line_num,mode_switch,&read_num,Line);
   
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
static int open_protects_resources_list_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        error("[Err]protects_resources file don't exist.");
        return(CTL_FILE_NOT_EXIST);
    }

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        error("[Err]protects_resources rules file fail.");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        error("[Err]protects_resources file no content.");
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
static unsigned long get_protects_resources_list_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_NUM_KEY,key_val))
   {
            	  error("get authorize cmd list num  err.\n");
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
static unsigned long get_protects_resources_list_mode_switch(unsigned char *file_cnt_buf)
{
    register char *str = file_cnt_buf;
    char key_val[64];
    
    if (NULL == file_cnt_buf)
        return 1;
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_MODE_GETE_KEY,key_val))
   {
            	  error("get protected resources  mode switch  err.\n");
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
static int set_protects_resources_list_buf(PROTECTED_RESOURCE_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num,int * Line)
{
    unsigned long i = 0;
    unsigned long j =0;
    char *p = NULL;
    char *s = file_cnt_buf;
    PROTECTED_RESOURCE_ID d = list_id;
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
            	  error("get protected resources  line  err.\n");
                continue;
   	}
	//printf("read line str = %s\n",key_val);
	if(0 == analysis_protects_resources_list_line(key_val,j,list_id,mode_switch_type)){
  		printf("LINE %d error \n",i);
		memset((char*)list_id,0x00,protected_resource_size);
		if(buf_num == 1)
			*Line = 1;
		continue;
        }
	++j;
	printf("res line %d ok\n",i);
	
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
static int analysis_protects_resources_list_line(unsigned char *p,unsigned long index,PROTECTED_RESOURCE_ID q,unsigned char mode_switch){
	unsigned char *s=p;
	unsigned char *t=NULL;
	unsigned char *tmp_protect_resource_addr=NULL;
	unsigned char *tmp_not_authorize_info_addr = NULL;
	unsigned char *tmp_eaudit_level_info_addr = NULL;
	unsigned char *tmp_addr = NULL;
	unsigned char *tmp_addr1=NULL;
	unsigned char *tmp_addr2=NULL;
	unsigned char *tmp_addr3=NULL;
	unsigned char *tmp_addr4=NULL;
	unsigned char *tmp_addr5=NULL;
	unsigned char *tmp_addr6=NULL;
	int i, j,k,len =0;
	unsigned char dispose_byte=0;
	char ip_str[20];
	unsigned char str[1024];
	struct in_addr ip;
	unsigned long shm_size = 0;
	int shm_id;
	INTERVAL_PORT_ID port_id=NULL;
	CONTINUE_PORT_ID continue_port_id=NULL;
	unsigned long port_tatol_num=0;
	 unsigned int port_mode = 0;
	unsigned int src_port_mode=0;
	unsigned int dst_port_mode = 0;
	unsigned char src_str[1024];
	unsigned char dst_str[1024];
	
	if(s==NULL)
		return 0;
	tmp_protect_resource_addr = strtok(s,LIST_ITEMS_INDER);
	if(tmp_protect_resource_addr==NULL)
		return 0;
        tmp_not_authorize_info_addr= strtok(NULL,LIST_ITEMS_INDER);
	if(tmp_not_authorize_info_addr==NULL)
		return 0;
	tmp_eaudit_level_info_addr = strtok(NULL,LIST_ITEMS_INDER);
        if(tmp_eaudit_level_info_addr == NULL)
	   	return 0;
       
	/* 1 解析保护资源列表*/
	/*得到协议名字*/
	len = strlen(tmp_protect_resource_addr);
	j=0;
	for(i=len-1;i>=0;i--){
		if(tmp_protect_resource_addr[i]=='+'){
			tmp_protect_resource_addr[i] = '\0';
			break;
		}
		str[j]=tmp_protect_resource_addr[i];
		j++;
	}
	str[j]='\0';
	k=0;
	for(i=j-1;i>=0;i--){
		q[index].pro_name[k]= str[i];
		k++;
	}
	q[index].pro_name[k] = '\0';
	//printf("pro_name = %s\n",q[index].pro_name);
        /*get protected resource name */
       t = strtok(tmp_protect_resource_addr,LIST_ITEMS_DELIM);
	if(NULL == t)
		return 0;
	len = strlen(t)>255?255:strlen(t);
	memcpy(q[index].rule_name,t,len);
       
	/*得到保护资源ID*/
	t = strtok(NULL,LIST_ITEMS_DELIM);
	if(NULL == t)
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
       q[index].rule_id = atoi(t);
	//printf("resoures id = %d\n",q[index].rule_id);
	/*得到以太网类型*/
	t = strtok(NULL,LIST_ITEMS_DELIM);
#if 0
	len = strlen(t);
	for(i=0;i<len;i++)
	{
		if(isdigit(t[i]))
			continue;
		return 0;
	}
#endif
	q[index].ethernet_type = atoi(t);
	//printf("get ethernet type = %d\n",q[index].ethernet_type);
	if(q[index].ethernet_type == ARP)
		goto not_authorize_analysis;
	/*得到传输层类型*/
	t = strtok(NULL,LIST_ITEMS_DELIM);
#if 0
	len = strlen(t);
	for(i=0;i<len;i++)
	{
		if(isdigit(t[i]))
			continue;
		return 0;
	}
#endif
	q[index].transfer_type = atoi(t);
	//printf("transfer type = %d\n",q[index].transfer_type);
	/*得到处理字节*/
	t = strtok(NULL,LIST_ITEMS_DELIM);
#if 0
	len = strlen(t);
	for(i=0;i<len;i++)
	{
		if(isdigit(t[i]))
			continue;
		return 0;
	}
#endif
	dispose_byte = atoi(t);
        //printf("dispose byte = %d\n",dispose_byte); 
	/*get mac combine */
	if(dispose_byte&0x01)
		q[index].use_mac_flag =SMAC;
	else
		q[index].use_mac_flag =NO_USE;
	if(dispose_byte&0x02){
		if(q[index].use_mac_flag)
			q[index].use_mac_flag = SMAC_DMAC;
		else
		       q[index].use_mac_flag = DMAC;
	}
	//printf("q[index].use_mac_flag  =%d\n",q[index].use_mac_flag );
      /*get ip combine*/
	if(dispose_byte&0x04)
		q[index].use_ip_flag =SIP;
	else
		q[index].use_ip_flag = NO_USE;
	if(dispose_byte&0x08){
		if(q[index].use_ip_flag)
			q[index].use_ip_flag = SIP_DIP;
		else
			q[index].use_ip_flag = DIP;
	}
	/*get port combine*/
	if(dispose_byte&0x20)
		q[index].use_port_flag=SPORT;
	else
		q[index].use_port_flag= NO_USE;
	if(dispose_byte&0x40){
		if(q[index].use_port_flag)
			q[index].use_port_flag = SPORT_DPORT;
		else
			q[index].use_port_flag = DPORT;
	}
       if(dispose_byte&0x80)
	   	q[index].dispose_object_relation = OR;
	else
		q[index].dispose_object_relation = AND;
      //  printf("ip = %d port =%d mac = %d object relation = %d\n",q[index].use_ip_flag,q[index].use_port_flag,\
q[index].use_mac_flag,q[index].dispose_object_relation);
	/*dispose combine object*/
	switch(q[index].use_ip_flag){
		case SIP:
			/*get src ip */
			//t =NULL;
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len =strlen(t)>20?20:strlen(t);
			memset(ip_str,0,20);
			memcpy(ip_str,t,len);
            		if (0 == strncmp(ip_str,"255.255.255.255",15))
            			q[index].sip.ip = 0xFFFFFFFF;
            		else
            		{
                		inet_aton(ip_str,&ip);
                		q[index].sip.ip = ip.s_addr;
            		}
			/*get src mask*/
			//t =NULL;
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len =strlen(t)>20?20:strlen(t);
			memset(ip_str,0,20);
			memcpy(ip_str,t,len);
            		if (0 == strncmp(ip_str,"255.255.255.255",15))
            			q[index].sip.mask =htonl(4294967295);
            		else
            		{
                		inet_aton(ip_str,&ip);
                		q[index].sip.mask = ip.s_addr;
            		}
			break;
		case DIP:
			/*get dst  ip */
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len =strlen(t)>20?20:strlen(t);
			memset(ip_str,0,20);
			memcpy(ip_str,t,len);
            		if (0 == strncmp(ip_str,"255.255.255.255",15))
            			q[index].dip.ip = htonl(4294967295);
            		else
            		{
                		inet_aton(ip_str,&ip);
                		q[index].dip.ip = ip.s_addr;
            		}
			/*get src mask*/
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len =strlen(t)>20?20:strlen(t);
			memcpy(ip_str,0,20);
			memcpy(ip_str,t,len);
            		if (0 == strncmp(ip_str,"255.255.255.255",15))
            			q[index].dip.mask =htonl(4294967295);
            		else
            		{
                		inet_aton(ip_str,&ip);
                		q[index].dip.mask = ip.s_addr;
            		}
			break;
		case SIP_DIP:
			/*get src ip */
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len =strlen(t)>20?20:strlen(t);
                        memset(ip_str,0,20);
			memcpy(ip_str,t,len);
                        //printf("src -ip = %s\n",ip_str);
            		if (0 == strncmp(ip_str,"255.255.255.255",15))
            			q[index].sip.ip = htonl(4294967295);
            		else
            		{
                		inet_aton(ip_str,&ip);
                		q[index].sip.ip = ip.s_addr;
            		}
			/*get src mask*/
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len =strlen(t)>20?20:strlen(t);
			memset(ip_str,0,20);
			memcpy(ip_str,t,len);
                       // printf("src -mask = %s\n",ip_str);
            		if (0 == strncmp(ip_str,"255.255.255.255",15)){
            			q[index].sip.mask =htonl(4294967295);
                               // printf("src mask ok \n");
			}
            		else
            		{
                		inet_aton(ip_str,&ip);
                		q[index].sip.mask = ip.s_addr;
            		}
                      //  printf("src ip = %u mask = %u\n",q[index].sip.ip,q[index].sip.mask);
			/*get dst  ip */
			t =NULL;
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len =strlen(t)>20?20:strlen(t);
                        memset(ip_str,0x00,20);
			memcpy(ip_str,t,len);
                       // printf("dst -ip = %s\n",ip_str);
            		if (0 == strncmp(ip_str,"255.255.255.255",15))
            			q[index].dip.ip = htonl(4294967295);
            		else
            		{
                		inet_aton(ip_str,&ip);
                		q[index].dip.ip = ip.s_addr;
                              //  printf("dip ip = %s\n",inet_ntoa(ip));
            		}
			/*get src mask*/
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len =strlen(t)>20?20:strlen(t);
			memset(ip_str,0,20);
			memcpy(ip_str,t,len);
                       // printf("dst -mask = %s\n",ip_str);
            		if (0 == strncmp(ip_str,"255.255.255.255",15))
            			q[index].dip.mask =htonl(4294967295);
            		else
            		{
                		inet_aton(ip_str,&ip);
                		q[index].dip.mask = ip.s_addr;
            		}
			//printf("dst ip = %u mask = %u\n",q[index].dip.ip,q[index].dip.mask);
			break;
		case NO_USE:
		default:
			break;
	}
	/*get mac info*/
	switch(q[index].use_mac_flag){
		case SMAC:
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
                        len = strlen(t);
			if(len >17)
				return 0;
			memcpy(q[index].smac,t,len);
			//printf("smac = %s\n",q[index].smac);
			break;
		case DMAC:
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len = strlen(t);
			if(len>17)
				return 0;
			memcpy(q[index].dmac,t,len);
			//printf("dmac = %s\n",q[index].dmac);
			break;
		case SMAC_DMAC:
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len = strlen(t);
                        if(len >17)
				return 0;
			memcpy(q[index].smac,t,len);
			//printf("smac = %s\n",q[index].smac);
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
				return 0;
			len = strlen(t);
			if(len >17)
				return 0;
			memcpy(q[index].dmac,t,len);
                      //  printf("dmac = %s\n",q[index].dmac);
			break;
		case NO_USE:
		default:
			break;
	}


	/*inportance port info */
	/*get port info*/
	switch(q[index].use_port_flag){
		case SPORT:
			/*得到端口表示方法*/
			 t = strtok(NULL,LIST_ITEMS_DELIM);
			 if(NULL == t)
			 	return 0;
	#if 0
			len = strlen(t);
			for(i=0;i<len;i++){
				if(isdigit(t[i]))
					continue;
				return 0;
			}
	#endif
			src_port_mode = atoi(t);
			
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
			 	return 0;
			len = strlen(t);
			if(len >1024)
				return 0;
			memset(src_str,0x00,1024);
			strcpy(src_str,t);
		#if 0
			t = strtok(NULL,LIST_ITEMS_DELIM);
	 		if(NULL == t)
				return 0;
			len = strlen(t);
			if(len >31)
				return 0;
			strcpy(q[index].pro_name,t);
			printf("pro name = %s\n",q[index].pro_name);
		#endif
                     	if(0== src_port_analysis(src_port_mode,src_str,index,q))
				return 0;
			break;
		case DPORT:
			/*得到端口表示方法*/
			 t = strtok(NULL,LIST_ITEMS_DELIM);
			 if(NULL == t)
			 	return 0;
	#if 0
			len = strlen(t);
			for(i=0;i<len;i++){
				if(isdigit(t[i]))
					continue;
				return 0;
			}
	#endif
			dst_port_mode = atoi(t);
			
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
			 	return 0;
			len = strlen(t);
			if(len >1024)
				return;
			memset(dst_str,0x00,1024);
			strcpy(dst_str,t);
		#if 0
			t = strtok(NULL,LIST_ITEMS_DELIM);
	 		if(NULL == t)
				return 0;
			len = strlen(t);
			if(len >31)
				return 0;
			strcpy(q[index].pro_name,t);
			printf("pro name = %s\n",q[index].pro_name);
		#endif
                     	if(0== dst_port_analysis(dst_port_mode,dst_str,index,q))
				return 0;
			break;
		case SPORT_DPORT:
			/*得到端口表示方法*/
			 /*得到端口表示方法*/
			 t = strtok(NULL,LIST_ITEMS_DELIM);
			 if(NULL == t)
			 	return 0;
	#if 0
			len = strlen(t);
			for(i=0;i<len;i++){
				if(isdigit(t[i]))
					continue;
				return 0;
			}
	#endif
			src_port_mode = atoi(t);
			//printf("src_port_mode  = %d\n",src_port_mode );
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
			 	return 0;
			len = strlen(t);
			if(len >1024)
				return;
			memset(src_str,0x00,1024);
			strcpy(src_str,t);
			//printf("src_port_str=%s\n",src_str);
			 t = strtok(NULL,LIST_ITEMS_DELIM);
			 if(NULL == t)
			 	return 0;
	#if 0
			len = strlen(t);
			for(i=0;i<len;i++){
				if(isdigit(t[i]))
					continue;
				return 0;
			}
	#endif
			dst_port_mode = atoi(t);
			//printf("dst_port_mode = %d\n",dst_port_mode);
			t = strtok(NULL,LIST_ITEMS_DELIM);
			if(NULL == t)
			 	return 0;
			len = strlen(t);
			if(len >1024)
				return;
			memset(dst_str,0x00,1024);
			strcpy(dst_str,t);
			//printf("dst_port_str = %s\n",dst_str);
		#if 0
                        t = strtok(NULL,LIST_ITEMS_DELIM);
	 		if(NULL == t)
				return 0;
			len = strlen(t);
			if(len >31)
				return 0;
			strcpy(q[index].pro_name,t);
			printf("pro name = %s\n",q[index].pro_name);
	       #endif
                     if(0== src_port_analysis(src_port_mode,src_str,index,q))
				return 0;
                   //  printf("src port analysis over\n");
                     if(0== dst_port_analysis(dst_port_mode,dst_str,index,q))
				return 0; 
		    //printf("dst port analysis over\n");
		 
			
			break;
		case NO_USE:
		default:
			break;
	}
not_authorize_analysis:
	/*得到未授权事件*/
	len=strlen(tmp_not_authorize_info_addr);
	if(len >1023)
		return 0;
	memset(str,0x00,1024);
	strcpy(str,tmp_not_authorize_info_addr);
	if(0==unauthorize_event_dispose_analysis(str,index,q))
		return 0;
	//printf("unauthorize event analysis over\n");
	/*得到审计级别*/
	len = strlen(tmp_eaudit_level_info_addr);
	if(len >1023)
		return 0;
	memset(str,0x00,1024);
	strcpy(str,tmp_eaudit_level_info_addr);
	if(0==eaudit_level_dispose_analysis(str,index,q))
		return 0;
	//printf("eaudit_level_analysis over\n");
     	q[index].mode_switch = mode_switch;
        q[index].res_index = index;
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
static int eaudit_level_dispose_analysis(unsigned char *str ,unsigned long index,PROTECTED_RESOURCE_ID q){
	unsigned char *tmp_addr0 = str;
	unsigned char *tmp_addr1=NULL;
	unsigned long i, len =0;

	
	tmp_addr1 = strtok(tmp_addr0,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.eaudit_direction = atoi(tmp_addr1);
	//printf("eAudit direction val = %d\n",q[index].eaudit_level.eaudit_direction);

	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.session_level= atoi(tmp_addr1);
	//printf("session level val  = %d\n",q[index].eaudit_level.session_level);

	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.record_level= atoi(tmp_addr1);
	//printf("record level val  = %d\n",q[index].eaudit_level.record_level);

	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.event_level= atoi(tmp_addr1);
	//printf("event level val  = %d\n",q[index].eaudit_level.event_level);

	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.analysis_level= atoi(tmp_addr1);
	//printf("analysis level val  = %d\n",q[index].eaudit_level.analysis_level);

	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.total_analysis_level= atoi(tmp_addr1);
	//printf("total analysis level val  = %d\n",q[index].eaudit_level.total_analysis_level);

	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.custom_made_level= atoi(tmp_addr1);
	//printf("custom_made_level val  = %d\n",q[index].eaudit_level.custom_made_level);

	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].eaudit_level.manage_level= atoi(tmp_addr1);
	//printf("custom_made_level val  = %d\n",q[index].eaudit_level.manage_level);
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
static int unauthorize_event_dispose_analysis(unsigned char *str ,unsigned long index,PROTECTED_RESOURCE_ID q){
	unsigned char *tmp_addr0 = str;
	unsigned char *tmp_addr1=NULL;
	unsigned long i, len =0;
	
	tmp_addr1 = strtok(tmp_addr0,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].unauthorize_event.block_flag = atoi(tmp_addr1);
	//printf("block flag =%d\n",q[index].unauthorize_event.block_flag);
	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].unauthorize_event.warn_flag= atoi(tmp_addr1);
	//printf("warn flag =%d\n",q[index].unauthorize_event.warn_flag);
	tmp_addr1 = strtok(NULL,LIST_ITEMS_DELIM);
	if(tmp_addr1 ==NULL)
		return 0;
#if 0
	len = strlen(tmp_addr1);
	for(i=0;i<len;i++){
		if(isdigit(tmp_addr1[i]))
			continue;
		return 0;
	}
#endif
	q[index].unauthorize_event.log_flag= atoi(tmp_addr1);
	//printf("log  flag =%d\n",q[index].unauthorize_event.log_flag);
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
static int src_port_analysis(unsigned char  port_mode,unsigned char *str ,unsigned long index,PROTECTED_RESOURCE_ID q){
	unsigned char *tmp_addr0 = NULL;
	unsigned char *tmp_addr1=NULL;
	unsigned char *tmp_addr2=NULL;
	unsigned char *tmp_addr3=NULL;
	unsigned char *tmp_addr4=NULL;
	unsigned char *tmp_addr5=NULL;
	unsigned char *tmp_addr6=NULL;
	unsigned long i, j,len =0;
	unsigned long shm_size = 0;
	int shm_id;
	INTERVAL_PORT_ID port_id=NULL;
	CONTINUE_PORT_ID continue_port_id=NULL;
	SAVE_STRING_ID str_id =NULL;
	unsigned long port_tatol_num=0;
	q[index].sip.src_port_express = port_mode;
	switch(port_mode){
		case SINGLE:
						tmp_addr0  = strtok(str,"#");
						if(NULL == tmp_addr0)
							return 0;
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_tatol_num = atoi(tmp_addr0);
						if(port_tatol_num == 0)
							return 0;
						tmp_addr0 =strtok(NULL,"#");
						if(NULL == tmp_addr0)
							return 0;
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						q[index].sip.single_port = atoi(tmp_addr0);
						break;
		case CONTINUE_PORT:
						tmp_addr0  = strtok(str,"#");
						if(NULL == tmp_addr0)
							return 0;
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_tatol_num = atoi(tmp_addr0);
						if(port_tatol_num == 0)
							return 0;
						g_max_shm_key += SHM_KEY_IVL;
						q[index].sip.continue_port_shm_key = g_max_shm_key;
						q[index].sip.continue_port_num = port_tatol_num;
						shm_size = port_tatol_num*continue_port_size;
						shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    						if (shm_id < 0)
    						{
    							shm_id = get_shm(g_max_shm_key);
							if(shm_id<0){
								error("create protected resources port  list shm fail.1");
        							return 0;
								}
							DEL_SHM(shm_id);
	       					shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       					if(shm_id <0){
		   						error("create protected resources port  list shm fail.1");
        							return 0;
	       					}
    						}
						continue_port_id = (CONTINUE_PORT_ID)shmat(shm_id,NULL,0);
						if (!continue_port_id)
    						{
        						error("attach protected resources port  list shm fail.");
        						DEL_SHM(shm_id);
        						return 0;
    						}
						 str_id = (SAVE_STRING_ID)calloc(save_string_size,port_tatol_num);
						if(str_id ==NULL)
							return 0;
						tmp_addr0  = strtok(NULL,"#");
						if(NULL == tmp_addr0){
							free(str_id);
							return 0;
						}
						tmp_addr1  = strtok(tmp_addr0,",");
						if(NULL == tmp_addr1){
							free(str_id);
							return 0;
						}
						len = strlen(tmp_addr1)>512?512:strlen(tmp_addr1);
						strcpy(str_id[0].str,tmp_addr1);
						for(i=1;i<port_tatol_num;i++){
							tmp_addr1 = strtok(NULL,",");
							if(NULL == tmp_addr1){
								free(str_id);
								return 0;
							}
							len = strlen(tmp_addr1)>512?512:strlen(tmp_addr1);
							strcpy(str_id[i].str,tmp_addr1);
						}
						for(i=0;i<port_tatol_num;i++){
							/*得到最小端口*/
							tmp_addr0 = str_id[i].str;
							tmp_addr1 = strtok(tmp_addr0,"-");
							if(tmp_addr1==NULL){
								free(str_id);
								return 0;
							}
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								free(str_id);
								return 0;
							}
						#endif
							continue_port_id[i].min_port = atoi(tmp_addr1);
                                                       // printf("src minport = %d\n",continue_port_id[i].min_port);
							/*得到最大端口*/
							tmp_addr1 = strtok(NULL,"-");
							if(tmp_addr1==NULL){
								free(str_id);
								return 0;
							}
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								free(str_id);
								return 0;
							}
						#endif
							continue_port_id[i].max_port = atoi(tmp_addr1);
                                                       // printf("src maxport = %d\n",continue_port_id[i].max_port);
						}
						break;
		case INTERVAL_PORT:
						tmp_addr0  = strtok(str,"#");
						if(NULL == tmp_addr0)
							return 0;
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_tatol_num = atoi(tmp_addr0);
						if(port_tatol_num == 0)
							return 0;
						g_max_shm_key += SHM_KEY_IVL;
						q[index].sip.interval_port_num = port_tatol_num;
						q[index].sip.interval_port_shm_key = g_max_shm_key;
						shm_size = port_tatol_num*interval_port_size;
						shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    						if (shm_id < 0)
    						{
    							shm_id = get_shm(g_max_shm_key);
							if(shm_id<0){
								error("create protected resources port  list shm fail.2");
        							return 0;
								}
							DEL_SHM(shm_id);
	       					shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       					if(shm_id <0){
		   						error("create protected resources port  list shm fail.2");
        							return 0;
	       					}
    						}
						port_id = (INTERVAL_PORT_ID)shmat(shm_id,NULL,0);
						if (!port_id)
    						{
        						error("attach protected resources port  list shm fail.");
        						DEL_SHM(shm_id);
        						return 0;
    						}
						tmp_addr0  = strtok(NULL,"#");
						if(NULL == tmp_addr0)
							return 0;
						tmp_addr1 = strtok(tmp_addr0,",");
						if(NULL == tmp_addr1)
							return 0;
					#if 0
						len = strlen(tmp_addr1);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr1[i]))
								continue;
							return 0;
						}
					#endif
						port_id[0].port = atoi(tmp_addr1);
						for(i=1;i<port_tatol_num;i++){
							tmp_addr1 = strtok(NULL,",");
							if(tmp_addr1==NULL)
								return 0;
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								return 0;
							}
						#endif
							port_id[i].port = atoi(tmp_addr1);
						}
						break;
		case CONTINUE_INTERVAL_PORT:
						tmp_addr0  = strtok(str,"#");
						if(NULL == tmp_addr0)
							return 0;
						tmp_addr1  = strtok(NULL,"#");
						if(NULL == tmp_addr1)
							return 0;
						tmp_addr2  = strtok(NULL,"#");
						if(NULL == tmp_addr2)
							return 0;
						//printf("str0 = %s\n",tmp_addr0);
						//printf("str1 = %s\n",tmp_addr1);
						//printf("str2= %s\n",tmp_addr2);
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						q[index].sip.interval_port_num = atoi(tmp_addr0);
						port_tatol_num = q[index].sip.interval_port_num;
						g_max_shm_key += SHM_KEY_IVL;
						q[index].sip.interval_port_shm_key = g_max_shm_key;
						shm_size = port_tatol_num*interval_port_size;
						shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    						if (shm_id < 0)
    						{
    							shm_id = get_shm(g_max_shm_key);
							if(shm_id<0){
								error("create protected resources port  list shm fail.2");
        							return 0;
								}
							DEL_SHM(shm_id);
	       					shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       					if(shm_id <0){
		   						error("create protected resources port  list shm fail.2");
        							return 0;
	       					}
        						
    						}
						port_id = (INTERVAL_PORT_ID)shmat(shm_id,NULL,0);
						if (!port_id)
    						{
        						error("attach protected resources port  list shm fail.");
        						DEL_SHM(shm_id);
        						return 0;
    						}
						//printf("port_tatol_num = %d\n",port_tatol_num);
						tmp_addr0 = strtok(tmp_addr1,",");
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_id[0].port = atoi(tmp_addr0);
						//printf("interval port1 = %d\n",port_id[0].port);
						for(i=1;i<port_tatol_num;i++){
								tmp_addr0 = strtok(NULL,",");
							#if 0
								len = strlen(tmp_addr0);
								for(j=0;j<len;j++){
									if(isdigit(tmp_addr0[j]))
										continue;
									return 0;
								}
							#endif
								port_id[i].port = atoi(tmp_addr0);
                                                               // printf("interval port[%d] = %d\n",i,port_id[i].port);
						}
						/*得到联系端口段数*/
						tmp_addr0 = strtok(NULL,",");
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_tatol_num = atoi(tmp_addr0);
						//printf("##port_tatol_num = %d\n",port_tatol_num);
						if(port_tatol_num == 0)
							return 0;
						g_max_shm_key += SHM_KEY_IVL;
						q[index].sip.continue_port_shm_key = g_max_shm_key;
						q[index].sip.continue_port_num = port_tatol_num;
						shm_size = port_tatol_num*continue_port_size;
						shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    						if (shm_id < 0)
    						{
    							shm_id = get_shm(g_max_shm_key);
							if(shm_id<0){
								error("create protected resources port  list shm fail.2");
        							return 0;
								}
							DEL_SHM(shm_id);
	       					shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       					if(shm_id <0){
		   						error("create protected resources port  list shm fail.2");
        							return 0;
	       					}
    						}
						continue_port_id = (CONTINUE_PORT_ID)shmat(shm_id,NULL,0);
						if (!continue_port_id)
    						{
        						error("attach protected resources port  list shm fail.");
        						DEL_SHM(shm_id);
        						return 0;
    						}
						 str_id = (SAVE_STRING_ID)calloc(save_string_size,port_tatol_num);
						if(str_id ==NULL)
							return 0;
						tmp_addr0  = strtok(tmp_addr2,",");
						if(NULL == tmp_addr0){
							free(str_id);
							return 0;
						}
						//len = strlen(tmp_addr0)>512?512:strlen(tmp_addr0);
						strcpy(str_id[0].str,tmp_addr0);
                                             //  printf("str_id[0].str = %s\n",str_id[0].str);
						for(i=1;i<port_tatol_num;i++){
							tmp_addr1 = strtok(NULL,",");
							if(NULL == tmp_addr1){
								free(str_id);
								return 0;
							}
							//len = strlen(tmp_addr1)>512?512:strlen(tmp_addr1);
							strcpy(str_id[i].str,tmp_addr1);
							//printf("str_id[%d].str = %s\n",i,str_id[i].str);
						}
                               
						for(i=0;i<port_tatol_num;i++){
							/*得到最小端口*/
							tmp_addr0 = str_id[i].str;
							//printf("tmp_addr0 = %s\n",tmp_addr0);
							
							tmp_addr1 = strtok(tmp_addr0,"-");
							if(tmp_addr1==NULL){
								free(str_id);
								return 0;
							}
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								free(str_id);
								return 0;
							}
						#endif
							continue_port_id[i].min_port = atoi(tmp_addr1);
							/*得到最大端口*/
							tmp_addr1 = strtok(NULL,"-");
							if(tmp_addr1==NULL){
								free(str_id);
								return 0;
							}
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								free(str_id);
								return 0;
							}
						#endif
							continue_port_id[i].max_port = atoi(tmp_addr1);
						}
					break;
		default:
					return 0;
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
static int dst_port_analysis(unsigned char  port_mode,unsigned char *str ,unsigned long index,PROTECTED_RESOURCE_ID q){
	unsigned char *tmp_addr0 = NULL;
	unsigned char *tmp_addr1=NULL;
	unsigned char *tmp_addr2=NULL;
	unsigned char *tmp_addr3=NULL;
	unsigned char *tmp_addr4=NULL;
	unsigned char *tmp_addr5=NULL;
	unsigned char *tmp_addr6=NULL;
	unsigned long i, j,len =0;
	unsigned long shm_size = 0;
	int shm_id;
	INTERVAL_PORT_ID port_id=NULL;
	CONTINUE_PORT_ID continue_port_id=NULL;
	SAVE_STRING_ID str_id =NULL;
	unsigned long port_tatol_num=0;
	q[index].dip.dst_port_express = port_mode;
	switch(port_mode){
		case SINGLE:
						tmp_addr0  = strtok(str,"#");
						if(NULL == tmp_addr0)
							return 0;
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_tatol_num = atoi(tmp_addr0);
						if(port_tatol_num == 0)
							return 0;
						tmp_addr0 =strtok(NULL,"#");
						if(NULL == tmp_addr0)
							return 0;
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
						q[index].dip.single_port = atoi(tmp_addr0);
						break;
		case CONTINUE_PORT:
						tmp_addr0  = strtok(str,"#");
						if(NULL == tmp_addr0)
							return 0;
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_tatol_num = atoi(tmp_addr0);
						if(port_tatol_num == 0)
							return 0;
						g_max_shm_key += SHM_KEY_IVL;
						q[index].dip.continue_port_shm_key = g_max_shm_key;
						q[index].dip.continue_port_num = port_tatol_num;
						shm_size = port_tatol_num*continue_port_size;
						shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    						if (shm_id < 0)
    						{
    							shm_id = get_shm(g_max_shm_key);
							if(shm_id<0){
								error("create protected resources port  list shm fail.2");
        							return 0;
								}
							DEL_SHM(shm_id);
	       					shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       					if(shm_id <0){
		   						error("create protected resources port  list shm fail.2");
        							return 0;
	       					}
    						}
						continue_port_id = (CONTINUE_PORT_ID)shmat(shm_id,NULL,0);
						if (!continue_port_id)
    						{
        						error("attach protected resources port  list shm fail.");
        						DEL_SHM(shm_id);
        						return 0;
    						}
					        str_id = (SAVE_STRING_ID)calloc(save_string_size,port_tatol_num);
						if(str_id ==NULL)
							return 0;
						tmp_addr0  = strtok(NULL,"#");
						if(NULL == tmp_addr0){
							free(str_id);
							return 0;
						}
						tmp_addr1  = strtok(tmp_addr0,",");
						if(NULL == tmp_addr1){
							free(str_id);
							return 0;
						}
						len = strlen(tmp_addr1)>512?512:strlen(tmp_addr1);
						strcpy(str_id[0].str,tmp_addr1);
						for(i=1;i<port_tatol_num;i++){
							tmp_addr1 = strtok(NULL,",");
							if(NULL == tmp_addr1){
								free(str_id);
								return 0;
							}
							len = strlen(tmp_addr1)>512?512:strlen(tmp_addr1);
							strcpy(str_id[i].str,tmp_addr1);
						}
						for(i=0;i<port_tatol_num;i++){
							/*得到最小端口*/
							tmp_addr0 = str_id[i].str;
							tmp_addr1 = strtok(tmp_addr0,"-");
							if(tmp_addr1==NULL){
								free(str_id);
								return 0;
							}
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								free(str_id);
								return 0;
							}
						#endif
							continue_port_id[i].min_port = atoi(tmp_addr1);
							/*得到最大端口*/
							tmp_addr1 = strtok(NULL,"-");
							if(tmp_addr1==NULL){
								free(str_id);
								return 0;
							}
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								free(str_id);
								return 0;
							}
						#endif
							continue_port_id[i].max_port = atoi(tmp_addr1);
						}
						break;
		case INTERVAL_PORT:
						tmp_addr0  = strtok(str,"#");
						if(NULL == tmp_addr0)
							return 0;
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_tatol_num = atoi(tmp_addr0);
						if(port_tatol_num == 0)
							return 0;
						g_max_shm_key += SHM_KEY_IVL;
						q[index].dip.interval_port_num = port_tatol_num;
						q[index].dip.interval_port_shm_key = g_max_shm_key;
						shm_size = port_tatol_num*interval_port_size;
						shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    						if (shm_id < 0)
    						{
    							shm_id = get_shm(g_max_shm_key);
							if(shm_id<0){
								error("create protected resources port  list shm fail.2");
        							return 0;
								}
							DEL_SHM(shm_id);
	       					shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       					if(shm_id <0){
		   						error("create protected resources port  list shm fail.2");
        							return 0;
	       					}
        						
    						}
						port_id = (INTERVAL_PORT_ID)shmat(shm_id,NULL,0);
						if (!port_id)
    						{
        						error("attach protected resources port  list shm fail.");
        						DEL_SHM(shm_id);
        						return 0;
    						}
						tmp_addr0  = strtok(NULL,"#");
						if(NULL == tmp_addr0)
							return 0;
						tmp_addr1 = strtok(tmp_addr0,",");
						if(NULL == tmp_addr1)
							return 0;
					#if 0
						len = strlen(tmp_addr1);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr1[i]))
								continue;
							return 0;
						}
					#endif
						port_id[0].port = atoi(tmp_addr1);
						for(i=1;i<port_tatol_num;i++){
							tmp_addr1 = strtok(NULL,",");
							if(tmp_addr1==NULL)
								return 0;
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								return 0;
							}
						#endif
							port_id[i].port = atoi(tmp_addr1);
						}
						break;
		case CONTINUE_INTERVAL_PORT:
						tmp_addr0  = strtok(str,"#");
						if(NULL == tmp_addr0)
							return 0;
						tmp_addr1  = strtok(NULL,"#");
						if(NULL == tmp_addr1)
							return 0;
						tmp_addr2  = strtok(NULL,"#");
						if(NULL == tmp_addr2)
							return 0;
						//printf("str0 = %s\n",tmp_addr0);
						//printf("str1 = %s\n",tmp_addr1);
						//printf("str2= %s\n",tmp_addr2);
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						q[index].dip.interval_port_num = atoi(tmp_addr0);
						port_tatol_num = q[index].dip.interval_port_num;
						g_max_shm_key += SHM_KEY_IVL;
						q[index].dip.interval_port_shm_key = g_max_shm_key;
						shm_size = port_tatol_num*interval_port_size;
						shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    						if (shm_id < 0)
    						{
    							shm_id = get_shm(g_max_shm_key);
							if(shm_id<0){
								error("create protected resources port  list shm fail.2");
        							return 0;
								}
							DEL_SHM(shm_id);
	       					shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       					if(shm_id <0){
		   						error("create protected resources port  list shm fail.2");
        							return 0;
	       					}
        						
    						}
						port_id = (INTERVAL_PORT_ID)shmat(shm_id,NULL,0);
						if (!port_id)
    						{
        						error("attach protected resources port  list shm fail.");
        						DEL_SHM(shm_id);
        						return 0;
    						}
						//printf("port_tatol_num = %d\n",port_tatol_num);
						tmp_addr0 = strtok(tmp_addr1,",");
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_id[0].port = atoi(tmp_addr0);
						//printf("interval port1 = %d\n",port_id[0].port);
						for(i=1;i<port_tatol_num;i++){
								tmp_addr0 = strtok(NULL,",");
							#if 0
								len = strlen(tmp_addr0);
								for(j=0;j<len;j++){
									if(isdigit(tmp_addr0[j]))
										continue;
									return 0;
								}
							#endif
								port_id[i].port = atoi(tmp_addr0);
                                                             //   printf("interval port[%d] = %d\n",i,port_id[i].port);
						}
						/*得到联系端口段数*/
						tmp_addr0 = strtok(NULL,",");
					#if 0
						len = strlen(tmp_addr0);
						for(i=0;i<len;i++){
							if(isdigit(tmp_addr0[i]))
								continue;
							return 0;
						}
					#endif
						port_tatol_num = atoi(tmp_addr0);
						//printf("##port_tatol_num = %d\n",port_tatol_num);
						if(port_tatol_num == 0)
							return 0;
						g_max_shm_key += SHM_KEY_IVL;
						q[index].dip.continue_port_shm_key = g_max_shm_key;
						q[index].dip.continue_port_num = port_tatol_num;
						shm_size = port_tatol_num*continue_port_size;
						shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    						if (shm_id < 0)
    						{
        						shm_id = get_shm(g_max_shm_key);
							if(shm_id<0){
								error("create protected resources port  list shm fail.2");
        							return 0;
								}
							DEL_SHM(shm_id);
	       					shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       					if(shm_id <0){
		   						error("create protected resources port  list shm fail.2");
        							return 0;
	       					}
    						}
						continue_port_id = (CONTINUE_PORT_ID)shmat(shm_id,NULL,0);
						if (!continue_port_id)
    						{
        						error("attach protected resources port  list shm fail.");
        						DEL_SHM(shm_id);
        						return 0;
    						}
						 str_id = (SAVE_STRING_ID)calloc(save_string_size,port_tatol_num);
						if(str_id ==NULL)
							return 0;
						tmp_addr0  = strtok(tmp_addr2,",");
						if(NULL == tmp_addr0){
							free(str_id);
							return 0;
						}
						//len = strlen(tmp_addr0)>512?512:strlen(tmp_addr0);
						strcpy(str_id[0].str,tmp_addr0);
                                              // printf("str_id[0].str = %s\n",str_id[0].str);
						for(i=1;i<port_tatol_num;i++){
							tmp_addr1 = strtok(NULL,",");
							if(NULL == tmp_addr1){
								free(str_id);
								return 0;
							}
							//len = strlen(tmp_addr1)>512?512:strlen(tmp_addr1);
							strcpy(str_id[i].str,tmp_addr1);
							//printf("str_id[%d].str = %s\n",i,str_id[i].str);
						}
                               
						for(i=0;i<port_tatol_num;i++){
							/*得到最小端口*/
							tmp_addr0 = str_id[i].str;
							//printf("tmp_addr0 = %s\n",tmp_addr0);
							
							tmp_addr1 = strtok(tmp_addr0,"-");
							if(tmp_addr1==NULL){
								free(str_id);
								return 0;
							}
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								free(str_id);
								return 0;
							}
						#endif
							continue_port_id[i].min_port = atoi(tmp_addr1);
							/*得到最大端口*/
							tmp_addr1 = strtok(NULL,"-");
							if(tmp_addr1==NULL){
								free(str_id);
								return 0;
							}
						#if 0
							len = strlen(tmp_addr1);
							for(j=0;j<len;j++){
								if(isdigit(tmp_addr1[j]))
									continue;
								free(str_id);
								return 0;
							}
						#endif
							continue_port_id[i].max_port = atoi(tmp_addr1);
						}	
					break;
		default:
					return 0;
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

