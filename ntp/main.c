
/*
 * file: main.c
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 *
 * 修改写cron/root文件的函数，以防止在末尾写入多行相同的配置
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

HANDMODIFYTIME_SERVER_ID g_handmodify_server_id = NULL;
SECOND_TIMERSYN_SERVER_ID g_second_timersyn_server_id = NULL;
NTP_TIMERSYN_SERVER_ID g_ntp_timersyn_server_id = NULL;
unsigned char ntptimesyn_flag = 0;

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int Write_Ntpconf_file(){
	int i,fd=-1;
	char ntpconf_file_path[NTP_SERVER_STR_LEN]={0};
	char buf[NTP_SERVER_STR_LEN]={0};
	sprintf(ntpconf_file_path,"%s","/etc/ntp.conf");
	fd = open(ntpconf_file_path,O_RDWR |O_CREAT | O_TRUNC);
	if(fd<0){
		DEBUG("OPEN ntpconf file fail!");
		return ERR;
	}
	for(i=0;i<g_second_timersyn_server_id->second_ntp_server_num;i++){
	 	sprintf(buf,"server  %s\n",g_second_timersyn_server_id->second_timersyn_server_address_id[i].second_timersyn_str);
    		if (-1 == write(fd,buf,strlen(buf))){
			close(fd);
			return ERR;
		}
	}
	close(fd);
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
int Write_Ntp_StepTickers_file(){
	int i,fd=-1;
	char ntpconf_file_path[NTP_SERVER_STR_LEN]={0};
	char buf[NTP_SERVER_STR_LEN]={0};
	sprintf(ntpconf_file_path,"%s","/etc/ntp/step-tickers");
	fd = open(ntpconf_file_path,O_RDWR |O_CREAT | O_TRUNC);
	if(fd<0){
		DEBUG("OPEN step-tickers file fail!");
		return ERR;
	}
	for(i=0;i<g_second_timersyn_server_id->second_ntp_server_num;i++){
	 	sprintf(buf,"%s\n",g_second_timersyn_server_id->second_timersyn_server_address_id[i].second_timersyn_str);
    		if (-1 == write(fd,buf,strlen(buf))){
			close(fd);
			return ERR;
		}
	}
	close(fd);
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
int Write_NtpTimeSynconf_file(){
	int i,fd=-1;
	char ntpconf_file_path[NTP_SERVER_STR_LEN]={0};
	char buf[NTP_SERVER_STR_LEN]={0};
	sprintf(ntpconf_file_path,"%s","/etc/ntp.conf");
	fd = open(ntpconf_file_path,O_RDWR |O_CREAT | O_TRUNC);
	if(fd<0){
		DEBUG("OPEN ntpconf file fail!");
		return ERR;
	}
	for(i=0;i<g_ntp_timersyn_server_id->ntp_server_num;i++){
	 	sprintf(buf,"server %s\n",g_ntp_timersyn_server_id->ntp_server_address_id[i].ntp_server_str);
    		if (-1 == write(fd,buf,strlen(buf))){
			close(fd);
			return ERR;
		}
	}
       for(i=0;i<g_ntp_timersyn_server_id->ntp_server_num;i++){
	 	sprintf(buf,"restrict %s mask 255.255.255.255 nomodify notrap noquery\n",g_ntp_timersyn_server_id->ntp_server_address_id[i].ntp_server_str);
    		if (-1 == write(fd,buf,strlen(buf))){
			close(fd);
			return ERR;
		}
	}
	DEBUG("NTP NETSEG NUM = %d",g_ntp_timersyn_server_id->ntp_netseg_num);
	for(i=0;i<g_ntp_timersyn_server_id->ntp_netseg_num;i++){
		sprintf(buf,"restrict %s mask %s\n",g_ntp_timersyn_server_id->ntp_server_netseg_id[i].ip,g_ntp_timersyn_server_id->ntp_server_netseg_id[i].mask);
		if (-1 == write(fd,buf,strlen(buf))){
			close(fd);
			return ERR;
		}
	}
	close(fd);
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
int Write_NtpTimeSYN_StepTickers_file(){
	int i,fd=-1;
	char ntpconf_file_path[NTP_SERVER_STR_LEN]={0};
	char buf[NTP_SERVER_STR_LEN]={0};
	sprintf(ntpconf_file_path,"%s","/etc/ntp/step-tickers");
	fd = open(ntpconf_file_path,O_RDWR |O_CREAT | O_TRUNC);
	if(fd<0){
		DEBUG("OPEN step-tickers file fail!");
		return ERR;
	}
	for(i=0;i<g_ntp_timersyn_server_id->ntp_server_num;i++){
	 	sprintf(buf,"%s\n",g_ntp_timersyn_server_id->ntp_server_address_id[i].ntp_server_str);
    		if (-1 == write(fd,buf,strlen(buf))){
			close(fd);
			return ERR;
		}
	}
	close(fd);
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
int Write_Linux_Crontab_file(){
	int fd=-1;
	char ntpconf_file_path[NTP_SERVER_STR_LEN]={0};
	char ntp_schedule[NTP_SERVER_STR_LEN];
	int ntp_schedule_len = 0;
	char* file_ptr = NULL;
	int filesize = 0;
	char* p;
	int find_len;
	struct stat statbuf;

	
	sprintf(ntpconf_file_path,"%s","/var/spool/cron/root");
	fd = open(ntpconf_file_path,O_RDWR |O_CREAT);
	if(fd<0)
	{
		DEBUG("OPEN ROOT file fail!");
		return ERR;
	}
	if(fstat(fd, &statbuf) < 0)
	{
		DEBUG("fstat file fail!");
		close(fd);
		return ERR;
	}
	filesize = statbuf.st_size;
	
	ntp_schedule_len= sprintf(ntp_schedule,"0 */%u * * * /usr/sbin/ntpdate %s\n",g_second_timersyn_server_id->timer_time, g_second_timersyn_server_id->second_timersyn_server_address_id[0].second_timersyn_str);

	if((file_ptr = malloc( filesize + ntp_schedule_len + 1)) == NULL)
	{
		DEBUG("Malloc file buf fail!");
		close(fd);
		return ERR;
	}
	
	if(-1 == read(fd, file_ptr, filesize))
	{
		close(fd);
		free(file_ptr);
		return ERR;
	}
	file_ptr[filesize] = '\0';
	p = strstr(file_ptr, "/usr/sbin/ntpdate");
	
	while(p != NULL)
	{
		p--;
		while(*p != '\n' && p > file_ptr)
		{
			p--;
		}
		
		if(*p == '\n')
			p++;
		find_len = 0;
		while(p[find_len] != '\n')
		{
			find_len++;
		}
		find_len++;
		filesize-=find_len;
		memcpy(p, p+find_len, filesize- (p-file_ptr));
		file_ptr[filesize] = '\0';
		p = strstr(p, "/usr/sbin/ntpdate");
	}
	memcpy(file_ptr+filesize, ntp_schedule, ntp_schedule_len);
	filesize+=ntp_schedule_len;

	if(ftruncate(fd, 0L) < 0)
	{
		DEBUG("truncate file fail!");
		free(file_ptr);
		close(fd);
		return ERR;
	}
	if(lseek(fd, 0L, SEEK_SET) < 0)
	{
		DEBUG("lseek file fail!");
		free(file_ptr);
		close(fd);
		return ERR;
	}
    	if (-1 == write(fd,file_ptr,filesize))
	{
		close(fd);
		free(file_ptr);
		return ERR;
	}
	close(fd);
	free(file_ptr);
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
static void NtpTimeSyn_Time_over(int sig_no){
	if(SIGALRM == sig_no){
		ntptimesyn_flag =1;
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
int main(void){
	int i,fd;
        unsigned long file_size, unit_num =0;
	unsigned char *file_cnt_buf =NULL;
	char cmd[NTP_SERVER_STR_LEN] ={0};
	unsigned long net_seg_num,timevals= 0;

	SECEND_TIMERSYN_SERVER_ADDRESS_ID second_timesyn_address_id =NULL;
	NTP_SERVER_ADDRESS_ID ntp_server_address_id =NULL;
	NTP_SERVER_NETSEG_ID ntp_server_netseg_id = NULL;
	DEBUG("1");
	signal(SIGALRM,NtpTimeSyn_Time_over);
        DEBUG("2");
	/*1 修改手动时间服务器操作*/
	if(OK == Check_HandNetTime_ConfFile(&fd,&file_size)){
		file_cnt_buf = (unsigned char *)malloc(file_size + 1);
    		if (NULL == file_cnt_buf)
    		{
        		DEBUG("[Err]Malloc for handnettime conf  file fail.");
       			 close(fd);
        		goto next2;
    		}
		if(OK == Check_HandNetTime_conf_file(fd,file_size,&unit_num,file_cnt_buf)){
			g_handmodify_server_id = (HANDMODIFYTIME_SERVER_ID)calloc(HANDMODIFYTIME_SERVER_SIZE,unit_num);
			if(NULL ==g_handmodify_server_id )
				DEBUG("alloc handnettime conf file mem space fail!");
			else
				if(SAIL_OK != Dispose_HandNetTime_Conf_Content(file_cnt_buf,unit_num,g_handmodify_server_id))
					DEBUG("dispose handnettime conf content fail !");
				else{
					for(i=0;i<g_handmodify_server_id->handmodifytime_num;i++){
						sprintf(cmd,"%s '%s'","date -s",g_handmodify_server_id[i].handmodifytime_str);
						system(cmd);
						sleep(1);
						memset(cmd,0,NTP_SERVER_STR_LEN);
						sprintf(cmd,"%s","hwclock -w");
						system(cmd);
						sleep(1);
					}
				}		
		}
	}
next2:
       DEBUG("3");
	/* 2 修改从时间服务器操作*/
	if(OK == Check_SecondTimeSyn_ConfFile(&fd,&file_size)){
		file_cnt_buf = (unsigned char *)malloc(file_size + 1);
    		if (NULL == file_cnt_buf)
    		{
        		DEBUG("[Err]Malloc for handnettime conf  file fail.\n");
       			 close(fd);
        		goto next;
    		}
      if(OK == Check_SecondTimeSyn_conf_file(fd,file_size,&unit_num, file_cnt_buf ,&timevals)){
	  	second_timesyn_address_id = (SECEND_TIMERSYN_SERVER_ADDRESS_ID)calloc(SECEND_TIMERSYN_SERVER_ADDRESS_SIZE,unit_num);
		if(NULL == second_timesyn_address_id)
			goto next;
		g_second_timersyn_server_id = (SECOND_TIMERSYN_SERVER_ID)calloc(SECOND_TIMERSYN_SERVER_SIZE,1);
		if(NULL ==g_second_timersyn_server_id )
			DEBUG("alloc secondtimesyn conf file mem space fail!");
		else{
			g_second_timersyn_server_id->timer_time = timevals;
			g_second_timersyn_server_id->second_timersyn_server_address_id = second_timesyn_address_id;
			if( SAIL_OK !=Dispose_SecondTimeSyn_Conf_Content(file_cnt_buf,unit_num,g_second_timersyn_server_id))
				DEBUG("dispose secondtimesyn  conf content fail !");
			else{
				if(OK == Write_Ntpconf_file())
					if(OK ==Write_Ntp_StepTickers_file())
						if(OK == Write_Linux_Crontab_file()){
							sprintf(cmd,"%s","service ntpd restart");
							system(cmd);
							sleep(5);
						}
			}		
		}
	}
  }
	DEBUG("4");
next:
     /*3 修改主时间服务器操作*/
	if(OK == Check_NetTimeSyn_ConfFile(&fd,&file_size)){
		file_cnt_buf = (unsigned char *)malloc(file_size + 1);
    		if (NULL == file_cnt_buf)
    		{
        		DEBUG("[Err]Malloc for handnettime conf  file fail.\n");
       		close(fd);
        		goto next0;
    		}
		if(OK == Check_NetTimeSyn_conf_file(fd,file_size,&unit_num, &net_seg_num, file_cnt_buf ,&timevals)){
			ntp_server_address_id = (NTP_SERVER_ADDRESS_ID)calloc(NTP_SERVER_ADDRESS_SIZE,unit_num);
		if(NULL == ntp_server_address_id)
			goto next0;
		ntp_server_netseg_id = (NTP_SERVER_NETSEG_ID)calloc(NTP_SERVER_NETSEG_SIZE,net_seg_num);
		if(NULL ==ntp_server_netseg_id )
			goto next0;
      		g_ntp_timersyn_server_id = (NTP_TIMERSYN_SERVER_ID)calloc(NTP_TIMERSYN_SERVER_SIZE,1);
      		if(NULL == g_ntp_timersyn_server_id)
	  		goto next0;
      		g_ntp_timersyn_server_id->timer_time = timevals;
      		g_ntp_timersyn_server_id->ntp_server_address_id = ntp_server_address_id;
      		g_ntp_timersyn_server_id->ntp_server_netseg_id = ntp_server_netseg_id;
      		if(SAIL_OK != Dispose_NetTimeSyn_Conf_Content(file_cnt_buf,unit_num,net_seg_num,g_ntp_timersyn_server_id))
			goto next0;
      		if(OK ==Write_NtpTimeSynconf_file())
	  		if(OK ==Write_NtpTimeSYN_StepTickers_file()){
				sprintf(cmd,"%s","service ntpd restart");
				system(cmd);
				alarm(timevals*DEFAULT_BASIC_TIME);
	  		}
	}
 }
next0:
	while(1){
		if(ntptimesyn_flag==1){
			ntptimesyn_flag =0;
			sprintf(cmd,"%s","service ntpd restart");
			system(cmd);
			alarm(g_ntp_timersyn_server_id->timer_time*DEFAULT_BASIC_TIME);
		}
	}
}
