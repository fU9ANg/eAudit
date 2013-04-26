
/*
 * file: config.c
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include <locale.h>
#include <limits.h>

#include <stdarg.h> 
#include <time.h>

#include <sys/param.h>
#include <pcap.h>
#include <syslog.h>

#include <assert.h>
#include <errno.h>

#include "eAudit_lib_Head.h"

#include "interface_manage.h"
#include "interface_capture.h"
#include "interface_filter.h"
#include "interface_analyze.h"
#include "interface_monitor.h"
#include "interface_flow.h"
#include "config.h"


void DEBUG(const char *fmt, ...);
static unsigned long get_nettimesyn_conf_file_netseg_num(unsigned char *file_cnt_buf);
static int open_conf_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);
static unsigned long get_handnettime_conf_file_num(unsigned char *file_cnt_buf);
static int set_handnettime_list_buf(unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num);
static int set_secondtimesyn_list_buf(unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num);
static unsigned long get_secondtimesyn_conf_file_num(unsigned char *file_cnt_buf);
static unsigned long get_secondtimesyn_conf_file_num(unsigned char *file_cnt_buf);
static unsigned long get_secondtimesyn_conf_file_timervals(unsigned char *file_cnt_buf);
static int set_nettimesyn_server_list_buf(unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num);
static int set_nettimesyn_netseg_list_buf(unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num);
static unsigned long get_nettimesyn_conf_file_server_num(unsigned char *file_cnt_buf);

/*******************************************
*func name:检测手工修改时间服务器配置文件正确性
*function:
*parameters:
*call:
*called:
*return:
*/
int cfg_get_key_val0(char *src,char *seckey, char *key,char *dest)
{
    long i = 0;
    int iRet = GET_CFG_VAL_FAIL;
    char *secAddr = NULL;
    char *keyAddr = NULL;
    char *p= NULL;
    char *ps= NULL;

    secAddr = strstr(src,seckey);
    if (NULL == secAddr)
    {
        return iRet;
    }

    p = secAddr + strlen(seckey);
    keyAddr = strstr(p,key);
    if (NULL == keyAddr)
    {
        return iRet;
    }
    p = keyAddr;
    while(*p++ != '=');
   // p++;
    
    i = 0;
    ps = dest;
    while( (*p != '\n') && (*p != '\r') && (*p != '\0')
        //   && (*p != CFG_NOTE_SIGN1) && (*p != CFG_NOTE_SIGN2))
	&& (*p != CFG_NOTE_SIGN1))
    {
    //    if (!isspace(*p))
    //    {
            *ps = *p;
            ps++;
            i++;
    //    }

        p++;
    }

    if (i > 0)
    {
        *ps = '\0';
	iRet = GET_CFG_VAL_OK;
    }
	
    return iRet;
}
/*1 手动修改时间服务器动作*/

int Check_HandNetTime_ConfFile(int *fd,unsigned long *file_size)
{
    char file_path[MAX_FILE_PATH_SIZE+1];
    sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_HANDNETTIME_FILE_NAME);
    if (SAIL_OK != open_conf_file(file_path,fd,file_size))
    {
        DEBUG("[Err]Open handnetime config file error.\n");
        return ERR;
    }
    return OK;
}

/*******************************************
*func name:检测手工修改时间服务器配置文件正确性
*function:
*parameters:
*call:
*called:
*return:
*/
/*1 手动修改时间服务器动作*/
int Check_HandNetTime_conf_file(int fd,unsigned long file_size,unsigned long *num,  unsigned char *file_cnt_buf )
{
    char file_path[MAX_FILE_PATH_SIZE+1];
    char new_file_path[MAX_FILE_PATH_SIZE+1];
    unsigned long line_num = 0;
    unsigned long read_num=0;
    memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
    memset(new_file_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_HANDNETTIME_FILE_NAME);
    sprintf(new_file_path,"%s/%s_last",SNAM_CFG_DIR,PMC_HANDNETTIME_FILE_NAME);
    DEBUG("file path = %s\n",file_path);

    if (NULL == cfg_get_file_cnt(fd,(char *)file_cnt_buf,(int)file_size))
    {
        DEBUG("[Err]Get handnettime conf  file content fail.");
        free(file_cnt_buf);
        close(fd);
        return ERR;
    }
    file_cnt_buf[file_size] = '\0';  
    close(fd);
    DEBUG("file_cnt_buf =%s",file_cnt_buf);	
    line_num = get_handnettime_conf_file_num(file_cnt_buf);
   	if(line_num == 0)
    {
        free(file_cnt_buf);
        return ERR;
	}
    DEBUG("line_num = %d",line_num);
    set_handnettime_list_buf(file_cnt_buf,line_num,&read_num);
    if(read_num >0 )
    {
        *num = read_num;
        rename(file_path,new_file_path);
        return OK;
    }
	else
    {
        free(file_cnt_buf);
        return ERR;
	}
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int open_conf_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
    DEBUG("start");	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        DEBUG("[Err]authorize accont  file don't exist.");
        return(CTL_FILE_NOT_EXIST);
    }
    DEBUG("START1");
    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        DEBUG("[Err]authorize account rules file fail.");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        DEBUG("[Err]authorize account  file no content.");
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
static unsigned long get_handnettime_conf_file_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = (char *)file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
    if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_NUM_KEY,key_val))
   {
        DEBUG("ERROR: get handnettime config number.");
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
static int set_handnettime_list_buf(unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num)
{
    unsigned long i = 0;
    unsigned long j =0;
    char *s = (char *)file_cnt_buf;
    unsigned char key_val[512];
    char info_str[32];
    if ( (NULL == file_cnt_buf)||(0==buf_num))
        return(CTL_PAR_ERR);
	
    for(i=0;i<buf_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,(char *)key_val))
   	{
        DEBUG("ERROR: get handnettime config file line.");
        continue;
   	}
	++j;
	DEBUG("line %d ok",i);
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
int Dispose_HandNetTime_Conf_Content(unsigned char *file_cnt_buf,unsigned long real_num,HANDMODIFYTIME_SERVER_ID p){
    unsigned long i = 0;
    char *s = (char *)file_cnt_buf;
    unsigned char key_val[512];
    char info_str[32];
    int len=0;
    DEBUG("real_num = %d",real_num);
    DEBUG("file_ctn_buf = %s",file_cnt_buf);
    if ( (NULL == file_cnt_buf)||(0==real_num)||(p==NULL))
        return(CTL_PAR_ERR);
    DEBUG("OK");
    for(i=0;i<real_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val0(s,LIST_INFO_KEY,info_str,(char *)key_val))
   	{
            	  DEBUG("get handnettime conf file line  err.");
                continue;
   	}
	p[i].handmodifytime_num = real_num;
	len = strlen((const char *)key_val)>127?127:strlen((const char *)key_val);
	memcpy(p[i].handmodifytime_str,key_val,len);
	DEBUG("p[%d].handmodifytime_str=%s",i,p[i].handmodifytime_str);
    }
    free(file_cnt_buf);
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
void DEBUG(const char *fmt, ...)
{
#ifdef _DEBUG
	va_list ap;
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if(*fmt)
	{	
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
#endif

	return;
}

/*2 从时间服务器解析*/
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int Check_SecondTimeSyn_ConfFile(int *fd,unsigned long *file_size){
	 char file_path[MAX_FILE_PATH_SIZE+1];
	 sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_SECONDTIMESYN_FILE_NAME);
	if (SAIL_OK != open_conf_file(file_path,fd,file_size))
    	{
        	DEBUG("[Err]Open handnetime conf  file error.");
        	return ERR;
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
static int set_secondtimesyn_list_buf(unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num)
{
    unsigned long i = 0;
    unsigned long j =0;
    char *s = (char *)file_cnt_buf;
    unsigned char key_val[512];
    char info_str[32];
    if ( (NULL == file_cnt_buf)||(0==buf_num))
        return(CTL_PAR_ERR);
	
    for(i=0;i<buf_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,(char *)key_val))
   	{
            	  DEBUG("get handnettime conf file line  err.");
                continue;
   	}
	++j;
	DEBUG("line %d ok",i);
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
static unsigned long get_secondtimesyn_conf_file_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = (char *)file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,TIMESYN_NUM,key_val))
   {
            	  DEBUG("get secondtimesyn conf  num  err.");
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
static unsigned long get_secondtimesyn_conf_file_timervals(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = (char *)file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,SYN_TIMEVAL,SYN_TIMEVALS,key_val))
   {
            	  DEBUG("get secondtimesyn conf  timevals num  err.");
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
int Check_SecondTimeSyn_conf_file(int fd,unsigned long file_size,unsigned long *num,  unsigned char *file_cnt_buf ,unsigned long *timevals){

    	char file_path[MAX_FILE_PATH_SIZE+1];
	char new_file_path[MAX_FILE_PATH_SIZE+1];
    	unsigned long line_num = 0;
    	unsigned long read_num=0;
	memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
	memset(new_file_path,0x00,MAX_FILE_PATH_SIZE+1);
       sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_SECONDTIMESYN_FILE_NAME);
	sprintf(new_file_path,"%s/%s_last",SNAM_CFG_DIR,PMC_SECONDTIMESYN_FILE_NAME); 
	

    	if (NULL == cfg_get_file_cnt(fd,(char *)file_cnt_buf,(int)file_size))
    	{
        	DEBUG("[Err]Get secondnettimesyn conf  file content fail.");
       	 free(file_cnt_buf);
        	close(fd);
        	return ERR;
    	}
    	file_cnt_buf[file_size] = '\0';  
   	close(fd);
    	DEBUG("file_cnt_buf =%s",file_cnt_buf);	
    	line_num = get_secondtimesyn_conf_file_num(file_cnt_buf);
   	if(line_num == 0){
		free(file_cnt_buf);
		return ERR;
	}
   	DEBUG("line_num = %d",line_num);
       set_secondtimesyn_list_buf(file_cnt_buf,line_num,&read_num);
       if(read_num >0 ){
              *num = read_num;
	       *timevals = get_secondtimesyn_conf_file_timervals(file_cnt_buf);
		if(*timevals>0){
			rename(file_path,new_file_path);
			return OK;
		}
		else{
			free(file_cnt_buf);
	       	return ERR;
		}
       }
	else{
		free(file_cnt_buf);
	       return ERR;
	}
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int Dispose_SecondTimeSyn_Conf_Content(unsigned char *file_cnt_buf,unsigned long real_num,SECOND_TIMERSYN_SERVER_ID p){
    unsigned long i = 0;
    char *s = (char *)file_cnt_buf;
    unsigned char key_val[512];
    char info_str[32];
    int len=0;
    if ( (NULL == file_cnt_buf)||(0==real_num)||(p==NULL))
        return(CTL_PAR_ERR);
	
    for(i=0;i<real_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,(char *)key_val))
   	{
            	  DEBUG("get handnettime conf file line  err.");
                continue;
   	}
	len = strlen((const char *)key_val)>127?127:strlen((const char *)key_val);
	memcpy(p->second_timersyn_server_address_id[i].second_timersyn_str,key_val,len);
	DEBUG("p[%d].secondtimesyn_str=%s",i,p->second_timersyn_server_address_id[i].second_timersyn_str);
    }
   p->second_ntp_server_num = real_num;
    free(file_cnt_buf);
    return(SAIL_OK);
}

/*3 主时间服务器修改操作*/
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int Check_NetTimeSyn_ConfFile(int *fd,unsigned long *file_size){
	 char file_path[MAX_FILE_PATH_SIZE+1];
	 sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_NETTIMESYN_FILE_NAME);
	if (SAIL_OK != open_conf_file(file_path,fd,file_size))
    	{
        	DEBUG("[Err]Open handnetime conf  file error.");
        	return ERR;
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
static int set_nettimesyn_server_list_buf(unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num)
{
    unsigned long i = 0;
    unsigned long j =0;
    char *s = (char *)file_cnt_buf;
    unsigned char key_val[512];
    char info_str[32];
    if ( (NULL == file_cnt_buf)||(0==buf_num))
        return(CTL_PAR_ERR);
	
    for(i=0;i<buf_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,(char *)key_val))
   	{
            	  DEBUG("get handnettime conf file line  err.");
                continue;
   	}
	++j;
	DEBUG("line %d ok",i);
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
static int set_nettimesyn_netseg_list_buf(unsigned char *file_cnt_buf,unsigned long buf_num,unsigned long *real_list_num)
{
    unsigned long i = 0;
    unsigned long j =0;
    char *s = (char *)file_cnt_buf;
    unsigned char key_val[512];
    char info_str[32];
    if ( (NULL == file_cnt_buf)||(0==buf_num))
        return(CTL_PAR_ERR);
	
    for(i=0;i<buf_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,SYS_NET_SEG,info_str,(char *)key_val))
   	{
            	  DEBUG("get handnettime conf file line  err.");
                continue;
   	}
	++j;
	DEBUG("line %d ok",i);
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
static unsigned long get_nettimesyn_conf_file_server_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str =(char *)file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,NTP_SERVER_NUM,key_val))
   {
            	  DEBUG("get nettimesyn conf  net server num  err.");
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
static unsigned long get_nettimesyn_conf_file_netseg_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = (char *)file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,NET_SEG_NUM,key_val))
   {
            	  DEBUG("get nettimesyn conf  netseg num  err.");
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
int Check_NetTimeSyn_conf_file(int fd,unsigned long file_size,unsigned long *num,  unsigned long *netseg_num, unsigned char *file_cnt_buf ,unsigned long *timevals){
    
    	char file_path[MAX_FILE_PATH_SIZE+1];
	char new_file_path[MAX_FILE_PATH_SIZE+1];
    	unsigned long line_num = 0;
	unsigned long net_seg_num =0;
    	unsigned long read_num=0;
	unsigned long real_net_seg_num =0;
	memset(file_path,0x00,MAX_FILE_PATH_SIZE+1);
	memset(new_file_path,0x00,MAX_FILE_PATH_SIZE+1);
       sprintf(file_path,"%s/%s",SNAM_CFG_DIR,PMC_NETTIMESYN_FILE_NAME);
	sprintf(new_file_path,"%s/%s_last",SNAM_CFG_DIR,PMC_NETTIMESYN_FILE_NAME);
	

    	if (NULL == cfg_get_file_cnt(fd,(char *)file_cnt_buf,(int)file_size))
    	{
        	DEBUG("[Err]Get nettimesyn conf  file content fail.");
       	 free(file_cnt_buf);
        	close(fd);
        	return ERR;
    	}
    	file_cnt_buf[file_size] = '\0';  
   	close(fd);
    	DEBUG("file_cnt_buf =%s",file_cnt_buf);	
    	line_num = get_nettimesyn_conf_file_server_num(file_cnt_buf);
	net_seg_num = get_nettimesyn_conf_file_netseg_num(file_cnt_buf);
   	if((line_num == 0)||(net_seg_num ==0)){
		free(file_cnt_buf);
		return ERR;
	}
   	DEBUG("line_num = %d",line_num);
	DEBUG("net_seg_num = %d",net_seg_num);
       set_nettimesyn_server_list_buf(file_cnt_buf,line_num,&read_num);
	set_nettimesyn_netseg_list_buf(file_cnt_buf,net_seg_num,&real_net_seg_num);
       if((read_num >0)&&(real_net_seg_num>0) ){
              *num = read_num;
		 *netseg_num = real_net_seg_num;
	       *timevals = get_secondtimesyn_conf_file_timervals(file_cnt_buf);
		if(*timevals>0){
			rename(file_path,new_file_path);
			return OK;
		}
		else{
			free(file_cnt_buf);
	       	return ERR;
		}
       }
	else{
		free(file_cnt_buf);
	       return ERR;
	}
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int Dispose_NetTimeSyn_Conf_Content(unsigned char *file_cnt_buf,unsigned long real_num,unsigned long real_netseg_num,NTP_TIMERSYN_SERVER_ID p){
    unsigned long i = 0;
    char *s = (char *)file_cnt_buf;
    unsigned char key_val[512];
    char info_str[32];
    char info_tmp_str[512];
    char* p0=NULL;
    int len=0;
    unsigned long tmp_seg_num =0;
    if ( (NULL == file_cnt_buf)||(0==real_num)||(p==NULL)||(real_netseg_num ==0))
        return(CTL_PAR_ERR);
	
    for(i=0;i<real_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,(char *)key_val))
   	{
            	  DEBUG("get nettimesyn conf file line  err.");
                continue;
   	}
	len = strlen((const char *)key_val)>127?127:strlen((const char *)key_val);
	memcpy(p->ntp_server_address_id[i].ntp_server_str,key_val,len);
	DEBUG("p[%d].nettimesyn_str=%s",i,p->ntp_server_address_id[i].ntp_server_str);
    }
    p->ntp_server_num = real_num;
   tmp_seg_num = real_netseg_num;
    for(i=0;i<real_netseg_num;i++){
	memset(info_str,0x00,32);
	memset(key_val,0x00,512);
	sprintf(info_str,"%s%ld",LIST_RESOURCE_KEY,i);
	if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,SYS_NET_SEG,info_str,(char *)key_val))
   	{
            	  DEBUG("get nettimesyn conf file line  err.");
                continue;
   	}
	DEBUG("NET SEG STR = %s",key_val);
	len = strlen((const char *)key_val)>511?511:strlen((const char *)key_val);
	memcpy(info_tmp_str,key_val,len);
	p0 = strtok(info_tmp_str,"+");
	if(p0==NULL){
		tmp_seg_num--;
		continue;
	}
	len = strlen(p0)>128?128:strlen(p0);
	memcpy(p->ntp_server_netseg_id[i].ip,p0,len);
	p0 = strtok(NULL,"+");
	if(p0==NULL){
		tmp_seg_num--;
		continue;
	}
	len = strlen(p0)>128?128:strlen(p0);
	memcpy(p->ntp_server_netseg_id[i].mask,p0,len);
    }
    p->ntp_netseg_num = tmp_seg_num;
    free(file_cnt_buf);
    if(real_netseg_num>0)	
		return(SAIL_OK);
    else
		return(CTL_PAR_ERR); 
}
