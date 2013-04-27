
/*
 * file: main.c
 * Written 2009-2013 by fU9ANg
 * bb.newlife@gmail.com
 * content:增加了流量监测和连接次数配置文件格式定义；也修改了数据库连接配置文件问题
 * 增加了NTP配置文件和监控系统信息配置文件
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
#include <syslog.h>

#include <assert.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "eAudit_lib_Head.h"
#include "interface_pmc.h"
#include "model_ctl.h"
#include "debug.h"
#include "main.h"

/*static global var*/
static char g_comm_nic_name[NICNAMESIZE+1];
static char s_pid_file[MAX_FILE_PATH_SIZE];
static char *g_progname;
static int g_can_comm = SAIL_TRUE;
static long g_snam_pid = -1;
static int g_dev_type = 0;

/*static function declare*/
static int get_dev_type();
static void set_pmc_thread_arg(PTHREAD_ARGS_ID p_args,unsigned long ip,int fd);
static void *pmc_server_proc(void *arg);
static int pmc_analysis_pkt(int skt_fd,unsigned char *pbuf,int *pstatus,char *filename,int *filesize);
static int pmc_analysis_status(int skt_fd,unsigned char *pbuf,int len,int *pstatus,int *filesize,char *filename);
static int check_pkt_flg(char *name);
static int check_flag(unsigned char *pbuf);

static int socket_write(int sock_fd,void *buffer,int length);
static int socket_read(int sock_fd,void *buffer,int length);

static void proc_heart_msg();
static int put_jc_pars(int fd);
static int put_sj_pars(int fd);
static int put_sj_def(int fd);
static int put_jc_def(int fd);
static int get_cfg_sj_jc(void *buf);

static int modify_jc_ip(void *buf);
static int change_db_ip(char *ip);

static void make_net_msg_hdr(NET_MSG_HDR_ID hdr_id,unsigned long seq_no,
		             unsigned char msg_type,unsigned long msg_body_len);

static int get_dev_id(char *dev_id);
static unsigned long get_msg_body_len(void *buf);

static int refresh_db_cfg_info(void *pbuf,unsigned long len);

static int backup_cfg_file(char *path);
static int copy_cfg_file(char *src_path,char *dst_path);
static int send_response(int fd,int ret);

static int check_if_cmd(int len);
static int reboot_dev();

static void stop_server(void);
static void server_stop_signal_handler(int signo);
static int is_file_exist (char * filename);
static void daemonize(int skt_fd);

static char *last_dir_separator(const char *dir);
static char *get_prog_name(const char *argv0);
static int create_pid_file(char *path);
static int reg_pid_to_file(long pid);
static void pmc_svr_stop(char *argv0);
static int modify_nic_ip(char *path,char *ip);
static int modify_nic_mask(char *path,char *ip);
static int modify_nic_gateway(char *path,char *ip);

static int SYSTEM(const char * cmdstring);
static void reboot_sys();
static void stop_eAudit();
static void sys_delay(long delaytimes);

static void prevent_cps_process();
static void get_snam_pid();
static void Read_Protocols_Name(char *input_str,char *out_str);
int listen_sockfd;
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int main(int argc, char **argv)
{
   // int listen_sockfd;
    int com_sockfd = -1;
    int sin_size; 
    struct sockaddr_in server_addr; 
    struct sockaddr_in client_addr;
    struct in_addr ip;
    int flag;
    char command[248];

    PTHREAD_ARGS pthread_arg;
    pthread_t pmc_thread_t;
    pthread_attr_t attr;
    unsigned long peer_ip;
    
   // INFO("************Start Dev PMC Server Process***********\n");

    /*1:only one paremters*/
    if (1 == argc)
    {
        /*1:the system user is root*/
        if (getuid() != 0)
        {
            error("[Err]You must be root user to run the system.\n");
            exit(EXIT_FAILURE);
        }

        /*2:make sure that real and effective uids are the same*/
        if (getuid() != geteuid())
        {
            error("%s: real and effective user IDs must equal\n",argv[0]);
            exit(EXIT_FAILURE);
        }

        /*3:make the proccess only run one times*/
        //proc_is_run(WITH_FILE_LOCK,SNAM_LOCK_FILE);
    }
	
    /*2:set local for isprint*/
    setlocale(LC_ALL, "");

    /*3:get program par */
    if (argc > 1)
    {
        if (strcmp(argv[1], "stop") == 0)
        {
            /*the system user is root*/
            if (getuid() != 0)
            {
                error("[Err]You must be root user to run the system.\n");
                exit(EXIT_FAILURE);
            }
            pmc_svr_stop(argv[0]);
            exit(EXIT_SUCCESS);
        }

        if (argc > 1)
        {
            if (strcmp(argv[1], "start") == 0)
            {
                INFO("Start......");
            }
        }
    }

    /*4:取得程序名称*/
   // g_progname = get_prog_name(argv[0]);
      g_progname = (char *)malloc(32+1);
      strcpy(g_progname,"pmc_server");

    /*5:安装信号处理程序*/
    signal(SIGINT,SIG_IGN);
    signal(SIGKILL, server_stop_signal_handler);
    signal(SIGTERM, server_stop_signal_handler);
    /*8:获取通信网卡的名称*/
    memset(g_comm_nic_name,0x00,NICNAMESIZE+1);
    if (0 == strncmp(argv[0],".",1))
    {
        if (NULL == argv[1])
        {
            error("Please set the name of comm NIC!");
            exit(EXIT_FAILURE);
        }    
        strcpy(g_comm_nic_name,argv[1]);
    }
    else
    {
        strcpy(g_comm_nic_name,"eth0");
    }

   // get_snam_pid();
    g_dev_type = get_dev_type();

    /*9:创建socket描述符*/
    if((listen_sockfd = socket(PF_INET,SOCK_STREAM,0))== -1)
    { 
        error("[Err]Create monitor server socket err."); 
        FREE(g_progname);
        unlink(s_pid_file);
        exit(EXIT_FAILURE); 
    }

    /*10:设置socket选项*/
    flag = 1;
    if (setsockopt(listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
    {
        error("[Err]setsockopt SO_REUSEADDR err."); 
        FREE(g_progname);
        unlink(s_pid_file);
        exit(EXIT_FAILURE); 
    }

#ifndef _WITH_TCP_NODELAY
    flag = 1;
    if (setsockopt(listen_sockfd, IPPROTO_TCP,TCP_NODELAY, (char *)&flag, sizeof(flag)) == -1)
    {
        error("[Err]setsockopt TCP_NODELAY err."); 
        FREE(g_progname);
        unlink(s_pid_file);
        exit(EXIT_FAILURE); 
    }
#endif

    /*11:绑定SOCKET*/
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(PMC_SEVER_PORT); 
    server_addr.sin_addr.s_addr =htonl(INADDR_ANY); 
    ip.s_addr = server_addr.sin_addr.s_addr;
   // printf("server ip = %s\n",inet_ntoa(ip));
    if(bind(listen_sockfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr)) == -1)
    { 
        error("[Err]Bind sever socket err."); 
	 error(errno);
        close(listen_sockfd);
        FREE(g_progname);
        unlink(s_pid_file);
        exit(EXIT_FAILURE); 
    }

    /*12:监听*/
    if(listen(listen_sockfd,MAX_PMC_REQURE_NUM)== -1)
    { 
        error("[Err]Listen sever socket err."); 
        close(listen_sockfd);
        FREE(g_progname);
        unlink(s_pid_file);
        exit(EXIT_FAILURE); 
    } 
    sin_size = sizeof(struct sockaddr_in);

    //daemonize(listen_sockfd);

    /*13:是否有新的连接*/
    while(g_can_comm)
    {
        /*1.1:接受连接*/
        com_sockfd = accept(listen_sockfd,(struct sockaddr *)(&client_addr),&sin_size);
        if (-1 == com_sockfd)
        {
            if (errno == EINTR)
                continue;
            continue;
        }

        /*2.2:获得对方IP*/
        peer_ip = client_addr.sin_addr.s_addr;

        /*3.3:设置线程参数*/
        set_pmc_thread_arg(&pthread_arg,peer_ip,com_sockfd);

        /*4.4:创建线程*/
        if (0 == pthread_attr_init(&attr))
        {
	    if (0 == pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
	    {
		  if (pthread_create(&pmc_thread_t,&attr,pmc_server_proc,(void*)&pthread_arg) != 0)
                    error("[PMC]: Create thread failed.\n");
                  else
                    DEBUG("Create thread OK.\n");
	     }
        }
        else
        {
            DEBUG("Init thread attr Fail.\n");
        }
    }

    close(listen_sockfd);
    close(com_sockfd);
    
    FREE(g_progname);
    unlink(s_pid_file);
    exit(EXIT_SUCCESS);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int get_dev_type()
{
    FILE *fp = NULL;
    char buf[1024];
    char *p = NULL;
    char *s = buf;

    fp = fopen("/var/lib/eAudit/data/SNAM_DEV_ID.conf","r+");
    if (NULL == fp)
        return 0;

    memset(buf,0x00,1024);
    if (NULL == fgets(buf,1024,fp))
        return 0;


    strtok(s,"-");
    p = strtok(NULL,"-");
    p = strtok(NULL,"-");
    if ('I' == p[0])
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
static void set_pmc_thread_arg(PTHREAD_ARGS_ID p_args,unsigned long ip,int fd)
{
    if (NULL == p_args)
        return;

    p_args->ip = ip;
    p_args->conn_fd = fd;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void *pmc_server_proc(void *arg)
{
    PTHREAD_ARGS pthread_arg;
    unsigned char buf[MAX_PMC_RW_SIZE];
    int bytes_read;
    int status = STATUS_UNKNOW;
     char filename[256]={0};
    unsigned long filesize=0;

    if (NULL == arg)
        error("[PMC]The thread parameters error.\n");

    pthread_arg = *(PTHREAD_ARGS_ID)arg;

    for(;;)
    {
        memset(buf,0x00,MAX_PMC_RW_SIZE);

        bytes_read = recv(pthread_arg.conn_fd,buf,sizeof(buf),0); 
        if (bytes_read <= 0) 
            continue; 

        if (OK == check_if_cmd(bytes_read))
        {
            DEBUG("Pkt size = cmd size.\n");
            if (OK == check_flag(buf))
            {
            	DEBUG("This is cmd.\n");
            	if (1 == pmc_analysis_pkt(pthread_arg.conn_fd,buf,&status,filename,&filesize))
                    break;
            }
            else
            {
		DEBUG("@@@@@@@@@@@@@@@@@filname = %s filesize = %d",filename,filesize);
		if (1 == pmc_analysis_status(pthread_arg.conn_fd,buf,bytes_read,&status,&filesize,filename))
                    break;
            }
        }
        else
        {
	    DEBUG("#################filname = %s filesize = %d",filename,filesize);
            if (1 == pmc_analysis_status(pthread_arg.conn_fd,buf,bytes_read,&status,&filesize,filename))
                break;
        }
    }
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int pmc_analysis_pkt(int skt_fd,unsigned char *pbuf,int *pstatus,char *filename,int *filesize)
{
    NET_MSG_HDR_ID pkt_id = (NET_MSG_HDR_ID)pbuf;
    int ret;
    char cfg_file_path[MAX_FILE_PATH_SIZE+1];
    char dst_path[MAX_FILE_PATH_SIZE+1];
    int fd;

    assert(pbuf!=NULL);

    DEBUG("Cmd Pkt Analysis.");
    DEBUG("pkt_id->msg_type = %d ",pkt_id->msg_type);
    strcpy(filename,pkt_id->filename);
    *filesize = pkt_id->msg_body_len;
    switch (pkt_id->msg_type)
    {
			case MSG_DEV_HEART:
            			proc_heart_msg();  /*心跳*/
            			*pstatus = STATUS_UNKNOW;
            			break;          
        		case CMD_GET_JC_PARS:
            			put_jc_pars(skt_fd);     /*发送监测当前参数*/
            			*pstatus = STATUS_UNKNOW;
            			return 1;
            			break;        
        		case CMD_GET_SJ_PARS:
            			put_sj_pars(skt_fd);     /*发送审计当前参数*/
            			*pstatus = STATUS_UNKNOW;
            			return 1;
            			break;          
        		case CMD_GET_SJ_DEF:
            			put_sj_def(skt_fd);       /*发送审计缺省参数*/
            			*pstatus = STATUS_UNKNOW;
            			return 1;
            			break;          
        		case CMD_GET_JC_DEF:
            			put_jc_def(skt_fd);       /*发送监测缺省参数*/
            			*pstatus = STATUS_UNKNOW;
            			return 1;
            			break;      
        		case CMD_CFG_SJ_JC: /*发送监测审计关系列表*/
            			DEBUG("sj_jc");
        			#if 0
            			ret = RESPONSE_OK;
            			if (ERR == get_cfg_sj_jc(pbuf))
            			{
                			DEBUG("err");
                			ret = RESPONSE_ERR;
            			}
            			send_response(fd,ret);
        			#endif
            			*pstatus = STATUS_CFG_SJ_JC;
            			break;    


		  	case MSB_CMD_TRANSFER_FILE_OVER:/*重新启动设备*/
				  ret = MSB_CMD_TRANSFER_FILE_OVER;
				  send_response(skt_fd,ret);
                                  close(skt_fd);
				  close(listen_sockfd);
				  reboot_dev();
				  break;
                      
			case MSG_CMD_DEV_IP:   /*更改设备IP*/
				       DEBUG("MSG_CMD_DEV_IP OK");
            				*pstatus = STATUS_MD_IP;
            				break;
	       		case MSG_CMD_FLOWCONTROL:
					DEBUG("MSG_CMD_FLOWCONTROL OK");
            				ret = MSG_CMD_FLOWCONTROL;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_FLOWCONTROL;  
            				break;   
			case MSG_CMD_MODIFY_SWITCHDEV_IP:
					DEBUG("MSG_CMD_MODIFY_SWITCHDEV_IP OK");
            				ret = MSG_CMD_MODIFY_SWITCHDEV_IP;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_MODIFY_SWITCHDEV_IP;  
            				break;
			case MSG_CMD_ARP:
					DEBUG("MSG_CMD_ARP OK");
            				ret = MSG_CMD_ARP;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_ARP;  
            				break;
        		case MSG_CMD_USR_INFO_LIST:    /*用户列表*/
					DEBUG("CMD_CFG_USR_LIST OK");
            				ret = MSG_CMD_USR_INFO_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_USR_INFO;  
            				break; 
			case MSG_CMD_PROTECT_RESOURCE_LIST:
					DEBUG("MSG_CMD_PROTECT_RESOURCE_LIST OK");
            				ret = MSG_CMD_PROTECT_RESOURCE_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_PROTECT_RESOURCE;  
            				break; 
			case MSG_CMD_NETWORK_AUTHORIZE_LIST:
					DEBUG("MSG_CMD_NETWORK_AUTHORIZE_LIST OK");
            				ret = MSG_CMD_NETWORK_AUTHORIZE_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_NETWORK_AUTHORIZE;  
            				break; 
			case MSG_CMD_CMD_AUTHORIZE_LIST:
					DEBUG("MSG_CMD_CMD_AUTHORIZE_LIST OK");
            				ret = MSG_CMD_CMD_AUTHORIZE_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_CMD_AUTHORIZE;  
            				break; 
			case MSG_CMD_ACCOUNT_AUTHORIZE_LIST:
					DEBUG("MSG_CMD_ACCOUNT_AUTHORIZE_LIST OK");
            				ret = MSG_CMD_ACCOUNT_AUTHORIZE_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_ACCOUNT_AUTHORIZE;  
            				break; 
			case MSG_CMD_PROTOCOL_ACUSTOM_AUTHORIZE_LIST:
					DEBUG("MSG_CMD_PROTOCOL_ACUSTOM_AUTHORIZE_LIST OK");
            				ret = MSG_CMD_PROTOCOL_ACUSTOM_AUTHORIZE_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_PROTOCOL_ACUSTOM_AUTHORIZE;  
            				break; 
			case MSG_CMD_PROTOCOL_FEATURE_AUTHORIZE_LIST:
					DEBUG("MSG_CMD_PROTOCOL_FEATURE_AUTHORIZE_LIST OK");
            				ret = MSG_CMD_PROTOCOL_FEATURE_AUTHORIZE_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_PROTOCOL_FEATURE_AUTHORIZE;  
            				break; 
			case MSG_CMD_LINK_FLUX_MONITOR_LIST:
					DEBUG("MSG_CMD_LINK_FLUX_MONITOR_LIST OK");
            				ret = MSG_CMD_LINK_FLUX_MONITOR_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_LINK_FLUX_MONITOR;  
            				break; 


							
			case MSG_CMD_NETTIMESYN_LIST:
					DEBUG("MSG_CMD_NETTIMESYN_LIST OK");
            				ret = MSG_CMD_NETTIMESYN_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_NETTIMESYN;  
            				break; 
			case MSG_CMD_SECONDTIMESYN_LIST:
					DEBUG("MSG_CMD_SECONDTIMESYN_LIST OK");
            				ret = MSG_CMD_SECONDTIMESYN_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_SECONDTIMESYN;  
            				break; 
			case MSG_CMD_HANDNETTIME_LIST:
					DEBUG("MSG_CMD_HANDNETTIME_LIST OK");
            				ret = MSG_CMD_HANDNETTIME_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_HANDNETTIME;  
            				break; 
			case MSG_CMD_MONITOR_SYS_INFO_LIST:
					DEBUG("MSG_CMD_MONITOR_SYS_INFO_LIST OK");
            				ret = MSG_CMD_MONITOR_SYS_INFO_LIST;
            				if (OK == send_response(skt_fd,ret))
                				*pstatus = STATUS_MONITOR_SYS_INFO;  
            				break; 
			default:
					*pstatus  = STATUS_UNKNOW;
					break;
    }
    return 0;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int pmc_analysis_status(int skt_fd,unsigned char *pbuf,int len,int *pstatus,int *filesize,char *filename)
{
    int fd;
    int status = *pstatus;
    char cfg_file_path[MAX_FILE_PATH_SIZE+1];
    char cfg_newfile_path[MAX_FILE_PATH_SIZE+1];
    int ret;
    char cmd[512];
    char pro_name[256];

    assert(pbuf!=NULL);
   
    DEBUG("pbuf = %s\n",pbuf);	
    DEBUG("STATUS = %d\n",status);
    switch (status)
    {
	 case STATUS_CFG_SJ_JC:
            ret = RESPONSE_OK;
            if (ERR == get_cfg_sj_jc(pbuf))
                ret = RESPONSE_ERR;
            DEBUG("status cfg sj jc send ret = %d\n",ret);
            send_response(skt_fd,ret);
            return 1;
    	case STATUS_MD_IP:
		   	modify_jc_ip(pbuf);
            		ret = RESPONSE_OK;
            		send_response(skt_fd,ret);
            		memset(cmd,0x00,512);
			strcpy(cmd,"service network restart");
			system(cmd);
			sleep(3);
			break;
	case STATUS_FLOWCONTROL:
			DEBUG("ENTER INTO STATUS_FLOWCONTROL_CONF");
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_FLOWCTRL_FILE_NAME);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_FLOWCTRL_FILE_NAME);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
			DEBUG("pbuf = %s\n",pbuf);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
			break;
	case STATUS_MODIFY_SWITCHDEV_IP:
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
                        memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
                        sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_FLOWCTRL_SWITCH_IP);
                        sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_FLOWCTRL_SWITCH_IP);
                        fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
                        if (fd < 0)
                                return 1;
                         if (-1 == write(fd,pbuf,len))
                        {
                                error("Write cfg content error.\n");
                                close(fd);
                                return 1;
                        }
                        close(fd);
                        if((*filesize =*filesize-len)<=0){
                                rename(cfg_newfile_path,cfg_file_path);
                        }
                        break;
						
    	 case STATUS_ARP:
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
                        memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
                        sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_ARP_FILE_NAME);
                        sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_ARP_FILE_NAME);
                        fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
                        if (fd < 0)
                                return 1;
                         if (-1 == write(fd,pbuf,len))
                        {
                                error("Write cfg content error.\n");
                                close(fd);
                                return 1;
                        }
                        close(fd);
                        if((*filesize =*filesize-len)<=0){
                                rename(cfg_newfile_path,cfg_file_path);
                        }
			   break;
			
        case STATUS_USR_INFO:
			DEBUG("STATUS_CFG_USR_LIST RECEIVE");
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_USR_LIST_FILE_NAME);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_USR_LIST_FILE_NAME);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
		      break;
	  case STATUS_PROTECT_RESOURCE:
	  	    	DEBUG("STATUS_PROTECT_RESOURCE RECEIVE");
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_PROTECT_RESOURCE_FILE_NAME);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_PROTECT_RESOURCE_FILE_NAME);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
		      break;

	 case STATUS_NETWORK_AUTHORIZE:
	  	    DEBUG("STATUS_NETWORK_AUTHORIZE RECEIVE");
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_NETWORK_FILE_NAME);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_NETWORK_FILE_NAME);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
		      break;
	 case STATUS_CMD_AUTHORIZE:
	  	    DEBUG("STATUS_CMD_AUTHORIZE RECEIVE");
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_CMD_FILE_NAME);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_CMD_FILE_NAME);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
		      break;

	case STATUS_ACCOUNT_AUTHORIZE:
	  	    DEBUG("STATUS_ACCOUNT_AUTHORIZE RECEIVE");
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_ACCOUNT_FILE_NAME);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_ACCOUNT_FILE_NAME);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
		      break;

	case STATUS_PROTOCOL_ACUSTOM_AUTHORIZE:
	  	    DEBUG("STATUS_PROTOCOL_ACUSTOM_AUTHORIZE RECEIVE");
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_CUSTOM_FILE_NAME);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,PMC_AUTHORIZE_ACCESS_CUSTOM_FILE_NAME);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
		      break;
  
	  case STATUS_PROTOCOL_FEATURE_AUTHORIZE:
	  	    	DEBUG("STATUS_PROTOCOL_FEATURE_AUTHORIZE RECEIVE");
		   	DEBUG("FILENAME = %s",filename);
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,filename);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,filename);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
				memset(pro_name,0x00,256);
				Read_Protocols_Name(filename,pro_name);
			}
		      break;
	case STATUS_LINK_FLUX_MONITOR:
		    	DEBUG("STATUS_LINK_FLUX_MONITOR RECEIVE");
		   	DEBUG("FILENAME = %s",filename);
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,filename);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,filename);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
			break;
	case STATUS_NETTIMESYN:
		    	DEBUG("STATUS_NETTIMESYN RECEIVE");
		   	DEBUG("FILENAME = %s",filename);
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,filename);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,filename);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
			break;
	case STATUS_SECONDTIMESYN:
		    	DEBUG("STATUS_SECONDTIMESYN RECEIVE");
		   	DEBUG("FILENAME = %s",filename);
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,filename);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,filename);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
			break;
	case STATUS_HANDNETTIME:
		    	DEBUG("STATUS_HANDNETTIME RECEIVE");
		   	DEBUG("FILENAME = %s",filename);
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,filename);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,filename);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
			break;
	 case STATUS_MONITOR_SYS_INFO:
		    	DEBUG("STATUS_MONITOR_SYS_INFO RECEIVE");
		   	DEBUG("FILENAME = %s",filename);
			memset(cfg_file_path,0x00,MAX_FILE_PATH_SIZE+1);
	     		memset(cfg_newfile_path,0x00,MAX_FILE_PATH_SIZE+1);
            		sprintf(cfg_newfile_path,"%s/%s_tmp",SNAM_CFG_DIR,filename);
            		sprintf(cfg_file_path,"%s/%s",SNAM_CFG_DIR,filename);
            		fd = open(cfg_newfile_path, O_RDWR |O_CREAT | O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            		if (fd < 0)
                		return 1;
           		 if (-1 == write(fd,pbuf,len))
            		{
                		error("Write cfg content error.\n");
                		close(fd);
                		return 1;
            		}
           		close(fd);
	  		if((*filesize =*filesize-len)<=0){
	  		 	rename(cfg_newfile_path,cfg_file_path);
			}
			break;
        default:
            break;
    }

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
static int socket_write(int sock_fd,void *buffer,int length) 
{ 
    int senden_bytes = -1; 
    int times = 5;
   
    errno = 0;

    while (times--)
    {
        senden_bytes = send(sock_fd,buffer,length,0); 
        if(senden_bytes <= 0) 
        {    
            if(errno == EINTR)  /* 中断错误 继续写*/ 
                continue;
            else            
                return -1; 
        }
        else
        {
            break;
        }
    } 
	
    return senden_bytes; 
} 

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int socket_read(int sock_fd,void *buffer,int length) 
{ 
    int bytes_left = length;; 
    int bytes_recv = 0; 
    char *ptr = NULL; 

    errno = 0;   

    while (bytes_left >0) 
    { 
        bytes_recv = recv(sock_fd,ptr,bytes_recv,0); 
        if (bytes_recv < 0) 
        { 
            if(errno==EINTR) 
                bytes_recv = 0; 
            else 
                return ERR; 
        } 
        else if(bytes_recv == 0) 
            break; 
        
        bytes_left -= bytes_recv; 
        ptr += bytes_recv; 
    }
    
    return(length - bytes_left); 
} 

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int check_if_cmd(int len)
{
    if (len == sizeof(NET_MSG_HDR))
        return OK;
    
    return ERR;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int check_flag(unsigned char *pbuf)
{
    NET_MSG_HDR_ID pkt_id = (NET_MSG_HDR_ID)pbuf;
    
    return check_pkt_flg(pkt_id->flag);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int check_pkt_flg(char *name)
{
    assert(name!=NULL);

    if (0 == strncmp(name,PMC_NET_PKT_FLAG,NET_MSG_FLAG_SIZE))
        return OK;
    
    return ERR;  
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void proc_heart_msg()
{
    return;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int put_jc_pars(int fd)
{
    JDEVPARS_PKT pkt;
    int len = 0;

    memset(&pkt,0x00,JDEVPARS_PKT_SIZE);
    if (ERR == get_dev_id(pkt.body.strJDevSeq))
        error("[Err]Get DEV ID Fail.\n");

    len = strlen(pkt.body.strJDevSeq);
    make_net_msg_hdr(&(pkt.hdr),0,RET_GET_JC_PARS,len);

    len += NET_MSG_HDR_SIZE;
    DEBUG("Len = %d\n",len);
    if (-1 == socket_write(fd,(void *)(&pkt),len))
    {
        error("[Err]Send JDEV Pars to PMC Centor Error.\n");
        return ERR;
    }

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int put_sj_pars(int fd)
{
    SDEVPARS_PKT pkt;
    int len = 0;

    memset(&pkt,0x00,SDEVDEFCFG_PKT_SIZE);
    if (ERR == get_dev_id(pkt.body.strSDevSeq))
        error("[Err]Get DEV ID Fail.\n");

    len = strlen(pkt.body.strSDevSeq);
    make_net_msg_hdr(&(pkt.hdr),0,RET_GET_SJ_PARS,len);

    len += NET_MSG_HDR_SIZE;
    if (-1 == socket_write(fd,(void *)(&pkt),len))
    {
        error("[Err]Send SDEV pars to PMC Centor Error.\n");
        return ERR;
    }

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int put_sj_def(int fd)
{
    SDEVDEFCFG_PKT pkt;
    int len = 0;

    memset(&pkt,0x00,SDEVDEFCFG_PKT_SIZE);
    if (ERR == get_dev_id(pkt.body.strSDevSeq))
        error("[Err]Get DEV ID Fail.\n");

    len = strlen(pkt.body.strSDevSeq);
    make_net_msg_hdr(&(pkt.hdr),0,RET_GET_SJ_DEF,len);

    pkt.body.port = PMC_SEVER_PORT;

    len += NET_MSG_HDR_SIZE + sizeof(unsigned short) + 64;
    if (-1 == socket_write(fd,(void *)(&pkt),len))
    {
        error("[Err]Send to PMC Centor Error.\n");
        return ERR;
    }

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int put_jc_def(int fd)
{
    JDEVDEFCFG_PKT pkt;
    int len = 0;

    memset(&pkt,0x00,JDEVDEFCFG_PKT_SIZE);
    if (ERR == get_dev_id(pkt.body.strJDevSeq))
        error("[Err]Get DEV ID Fail.\n");

    len = strlen(pkt.body.strJDevSeq);
    make_net_msg_hdr(&(pkt.hdr),0,RET_GET_JC_DEF,len);

    pkt.body.port = PMC_SEVER_PORT;

    len += NET_MSG_HDR_SIZE + sizeof(unsigned short) + 64;
    if (-1 == socket_write(fd,(void *)(&pkt),len))
    {
        error("[Err]Send to PMC Centor Error.\n");
        return ERR;
    }

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int get_cfg_sj_jc(void *buf)
{
    SDBCONNINFO_ID body_id = NULL;
    unsigned long body_len = 0;

    body_id = (SDBCONNINFO_ID)buf;

    /*写入对应的配置文件*/
    return refresh_db_cfg_info((void *)body_id,body_len);
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int modify_jc_ip(void *buf)
{
    char ip[64];
    char *body_id = NULL;
	
    char *strMask_id = NULL;
    char *strGageway_id = NULL;
	
    unsigned long body_len = 0;
    unsigned long strMask_len = 0;
    unsigned long strGateWay_len = 0;
    char command[512];
    char path[512+1];

    char strMask[32];
    char strGateWay[32];
    memset(strMask,0x00,32);
    memset(strGateWay,0x00,32);

    body_id = strtok((char *)buf,"+");
    body_len = strlen(body_id);
    memcpy(ip,body_id,body_len);
    ip[body_len] = '\0';
	
    strMask_id = strtok(NULL,"+");
    strMask_len = strlen(strMask_id);
    memcpy(strMask,strMask_id,strMask_len);
    strMask[strMask_len]= '\0';
	
    strGageway_id = strtok(NULL,"+");
    strGateWay_len = strlen(strGageway_id);
    memcpy(strGateWay,strGageway_id,strGateWay_len);
    strGateWay[strGateWay_len]= '\0';
    sprintf(path,"%s%s","/etc/sysconfig/network-scripts/ifcfg-",g_comm_nic_name);	
    modify_nic_ip(path,ip);
    if (1 == g_dev_type)
    {
      change_db_ip(ip);
    }
    modify_nic_mask(path,strMask);
    modify_nic_gateway(path,strGateWay);
    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int change_db_ip(char *ip)
{
    char buf[1024];
    char db_cfg_path[MAX_FILE_PATH_SIZE+1];
    int fd;
        
    /*写入对应的配置文件*/
    memset(db_cfg_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(db_cfg_path,"%s/%s",SNAM_CFG_DIR,PMC_DB_CONN_CFG_FILE_NAME);

    if (IS_EXIST == file_is_exist(db_cfg_path)) 
    {
        if (ERR == backup_cfg_file(db_cfg_path))
        {
            error("[Err]Backup Cfg File error.\n");
        }
    }
    
    fd = open(db_cfg_path, O_RDWR |O_CREAT | O_TRUNC );
    if (fd < 0)
        return ERR;

    write(fd,PMC_DB_CONN_CFG_SECT,11);
    write(fd,"\n",1);

    sprintf(buf,"%s = %s\n",PMC_CONN_IP_KEY,ip);
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

    sprintf(buf,"%s = %d\n",PMC_CONN_PORT_KEY,5432);
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

    sprintf(buf,"%s = %s\n",PMC_CONN_DB_NAME_KEY,"eAudit");
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

     sprintf(buf,"%s = %s\n",PMC_CONN_USR_NAME_KEY,"snamdb_super_user");
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

	 sprintf(buf,"%s = %s\n",PMC_CONN_DB_PASSWORD_KEY,"Sailing-gfdDSR3425-d55fdgDFf");
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

    close(fd);
    return OK;
    
ErrProc:
    close(fd);  
    return ERR;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int send_response(int fd,int ret)
{
    NET_MSG_HDR hdr;

    memset(&hdr,0x00,sizeof hdr);
    make_net_msg_hdr(&hdr,0,ret,0);

    if (ERR == socket_write(fd,(void *)(&hdr),sizeof hdr))
    {
        error("[Err]Send Reaponse Pkt Error.\n");
        return ERR;
    }

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void make_net_msg_hdr(NET_MSG_HDR_ID hdr_id,unsigned long seq_no,
                                                       unsigned char msg_type,unsigned long msg_body_len)
{
    memcpy(hdr_id->flag,PMC_NET_PKT_FLAG,NET_MSG_FLAG_SIZE);
    hdr_id->protect_mode = EXPRESS_MODE;
    hdr_id->msg_type = msg_type;
    hdr_id->msg_body_len = msg_body_len;
    hdr_id->check_val = NET_MSG_CRC;
    hdr_id->seq_no = seq_no;
    hdr_id->reserved = 0;
    hdr_id->version = NOW_NET_PKT_VERSION;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int get_dev_id(char *dev_id)
{
    char file_path[MAX_FILE_PATH_SIZE+1];
    int fd = DEF_FILE_DES_VAL;
    char buf[MAX_PMC_DEV_ID_SIZE];
    int size;

    sprintf(file_path,"%s/%s",DEV_ID_SET_PATH ,DEV_ID_FILE_NAME );

    if ((fd = open(file_path,O_RDONLY)) < 0)
    {
        error("[Err]Open Dev ID File(%s) Fail.",file_path);
        return ERR;
    }

    size = read(fd,buf,MAX_PMC_DEV_ID_SIZE);
    if (size <= 0)
    {
        error("[Err]Read DEV ID File error.\n");
        close(fd);
        return ERR;
    }

    if (size >= MAX_PMC_DEV_ID_SIZE)
    {
        error("[Err]The DEV ID file content is error.\n");
        close(fd);
        return ERR;
    }
   
    buf[size] = '\0';

    strcpy(dev_id,buf);
    DEBUG("dev id = %s\n",dev_id);

    close(fd);
    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static unsigned long get_msg_body_len(void *buf)
{
    NET_MSG_HDR_ID hdr_id = (NET_MSG_HDR_ID)buf;

    if (NULL == buf)
        return 0;

    return(hdr_id->msg_body_len);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int refresh_db_cfg_info(void *pbuf,unsigned long len)
{
    SDBCONNINFO_ID pkt = NULL;
    char db_cfg_path[MAX_FILE_PATH_SIZE+1];
    int fd;
    char buf[1024];
        
    /*写入对应的配置文件*/
    memset(db_cfg_path,0x00,MAX_FILE_PATH_SIZE+1);
    sprintf(db_cfg_path,"%s/%s",SNAM_CFG_DIR,PMC_DB_CONN_CFG_FILE_NAME);

    if (IS_EXIST == file_is_exist(db_cfg_path)) 
    {
        if (ERR == backup_cfg_file(db_cfg_path))
        {
            error("[Err]Backup Cfg File error.\n");
        }
    }
    
    fd = open(db_cfg_path, O_RDWR |O_CREAT | O_TRUNC );
    if (fd < 0)
        return ERR;

    pkt = (SDBCONNINFO_ID)pbuf;
    write(fd,PMC_DB_CONN_CFG_SECT,11);
    write(fd,"\n",1);

    sprintf(buf,"%s = %s\n",PMC_CONN_IP_KEY,pkt->strIP);
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

    sprintf(buf,"%s = %d\n",PMC_CONN_PORT_KEY,5432);
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

    sprintf(buf,"%s = %s\n",PMC_CONN_DB_NAME_KEY,pkt->strDbName);
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

   
     sprintf(buf,"%s = %s\n",PMC_CONN_USR_NAME_KEY,"snamdb_super_user");
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;

	 sprintf(buf,"%s = %s\n",PMC_CONN_DB_PASSWORD_KEY,"Sailing-gfdDSR3425-d55fdgDFf");
    if (-1 == write(fd,buf,strlen(buf)))
        goto ErrProc;
   
    close(fd);
    DEBUG("dB Info Set OK.");
    return OK;
    
ErrProc:
    close(fd);  
    return ERR;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int backup_cfg_file(char *path)
{
    char file_path[MAX_FILE_PATH_SIZE+1+7];
    unsigned char block[1024];
    int in;
    int out;
    long read_len = 0;

    sprintf(file_path,"%s_backup",path);
    if (ERR == is_file_exist(file_path))
        return OK;

    out = open(file_path, O_RDWR |O_CREAT);
    if (out < 0)
        return ERR;

    in = open(file_path, O_RDONLY );
    if (in < 0)
        return ERR;
    
    while((read_len = read(in,block,sizeof(block))) > 0)
        write(out,block,read_len);

    close(out);
    close(in);

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int copy_cfg_file(char *src_path,char *dst_path)
{
    unsigned char block[1024];
    int in;
    int out;
    long read_len = 0;

    out = open(dst_path, O_RDWR | O_CREAT | O_TRUNC);
    if (out < 0)
        return ERR;

    in = open(src_path, O_RDONLY);
    if (in < 0)
        return ERR;
    
    while((read_len = read(in,block,sizeof(block))) > 0)
        write(out,block,read_len);

    close(out);
    close(in);

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int reboot_dev()
{
    char cmd[MAX_SYS_CMD_SIZE];

    memset(cmd,0x00,MAX_SYS_CMD_SIZE);
    strcpy(cmd, "/eAudit/bin/eAudit restart");
    system(cmd);

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void stop_server(void)
{
    g_can_comm = SAIL_FALSE;
    exit(EXIT_SUCCESS);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void server_stop_signal_handler(int signo)
{
    stop_server();
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int is_file_exist (char * filename)
{
    if (NULL == filename)
        return ERR;

    if (0 == access(filename, F_OK))
        return OK;
    else
        return ERR;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void daemonize(int skt_fd)
{
    pid_t pid = DEF_PID_VAL;
    int fd;
    int fdtablesiaze;

    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTSTP,SIG_IGN);
 
    if (pid==fork())
        exit(0);
    else if(pid< 0)
        exit(1);

    setsid();
    signal(SIGHUP,SIG_IGN);

    if ((pid = fork())!=0)
        exit(0);

    for(fd = 0,fdtablesiaze = getdtablesize();fd < fdtablesiaze;fd++)
    {
        if (fd!=skt_fd)
            close(fd);
    }

    chdir("/");
    umask(0);

    return;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void pmc_svr_stop(char *argv0)
{
    FILE *fp = NULL;
    long pid;
    char *progname;
    char pid_file[MAX_FILE_PATH_SIZE];
    char command[248];

    progname = get_prog_name(argv0);
    snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,progname);
    if (NOT_EXIST == file_is_exist(pid_file)) 
    {
        INFO("The eAudit not start up.\n");
        return;
    }

    INFO("The pid file name = %s\n",pid_file);

    fp = fopen(pid_file,"rb");
    if (NULL == fp)
    {
        warning("fopen pid file fail.\n");
        return;
    }

    while(0 == feof(fp))
    {
         fscanf(fp, "%ld", &pid);
         if (kill((pid_t)pid, SIGTERM) != 0)
	 {
            warning(_("%s: could not send stop signal (PID: %ld),maybe stoped.\n"), progname, pid);
	 }
    }

    fclose(fp);
    FREE(progname);

    strcpy(command,"/eAudit/bin/eAudit restart");
    system(command);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static char *last_dir_separator(const char *dir)
{
    const char *p,*ret = NULL;

    for (p = dir; *p; p++){
        if (IS_DIR_SEP(*p))
            ret = p;
    }
	
    return (char *) ret;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static char *get_prog_name(const char *argv0)
{
    const char  *nodir_name;
    char *prog_name;

    nodir_name = last_dir_separator(argv0);
    if (nodir_name)
        nodir_name++;

    prog_name = strdup(nodir_name);
    if (prog_name == NULL)
    {
        error("[Err]%s: out of memory\n", nodir_name);
        exit(EXIT_FAILURE);
    }

    return prog_name;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int create_pid_file(char *path)
{
    FILE *fp = NULL;    

    assert(path != NULL);

    fp = fopen(path,"w+");
    if (NULL == fp)
        return ERR;

    fclose(fp);

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int reg_pid_to_file(long pid)
{
    FILE *fp = NULL;
    char buf[U_LONG_SIZE+1];

    fp = fopen(s_pid_file,"a+b");
    if (NULL == fp)
        return ERR;
    
    sprintf(buf,"%ld",pid);
    fputs(buf,fp);
    fputc('\n',fp);

    fflush(fp);
    fclose(fp);
    
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
static int modify_nic_ip(char *path,char *ip)
{
    FILE *fp = NULL;
    FILE *tfp = NULL;
    char buf[1024];
    char pbuf[1024];
    char *keyAddr = NULL;
    int ret = ERR;
    char tmp_path[512];

    if (NULL == path)
        return ERR;

    sprintf(tmp_path,"/etc/sysconfig/network-scripts/%s","tmp");
    copy_cfg_file(path,tmp_path);

    fp = fopen(tmp_path,"r+");
    if (NULL == fp)
        return ERR;

    tfp = fopen(path,"w+");
    if (NULL == tfp){
          fclose(fp);
           return ERR;
	}
    while (!feof(fp))
    {
        memset(buf,0x00,1024);
        if (NULL == fgets(buf,1024,fp))
            continue;

        if ('#' == buf[0])
        {
            fwrite(buf,sizeof(char),strlen(buf),tfp);
            continue;
        }

        keyAddr = strstr(buf,"IPADDR");
        if (NULL == keyAddr)
        {
            fwrite(buf,sizeof(char),strlen(buf),tfp);
            continue;
        }

        sprintf(pbuf,"%s%s\n","IPADDR=",ip);

        if (fwrite(pbuf,sizeof(char),strlen(pbuf),tfp) <= 0){
            fclose(fp);
    		fclose(tfp);
	    return ERR;
        }
        ret = OK;
    }

    fclose(fp);
    fclose(tfp);

    return ret;
}

static int modify_nic_mask(char *path,char *ip)
{
    FILE *fp = NULL;
    FILE *tfp = NULL;
    char buf[1024];
    char pbuf[1024];
    char *keyAddr = NULL;
    int ret = ERR;
    char tmp_path[512];

    if (NULL == path)
        return ERR;

    sprintf(tmp_path,"/etc/sysconfig/network-scripts/%s","tmp");
    copy_cfg_file(path,tmp_path);

    fp = fopen(tmp_path,"r+");
    if (NULL == fp)
        return ERR;

    tfp = fopen(path,"w+");
    if (NULL == tfp){
	 fclose(fp);
        return ERR;
    	}
    while (!feof(fp))
    {
        memset(buf,0x00,1024);
        if (NULL == fgets(buf,1024,fp))
            continue;

        if ('#' == buf[0])
        {
            fwrite(buf,sizeof(char),strlen(buf),tfp);
            continue;
        }

        keyAddr = strstr(buf,"NETMASK");
        if (NULL == keyAddr)
        {
            fwrite(buf,sizeof(char),strlen(buf),tfp);
            continue;
        }

        sprintf(pbuf,"%s%s\n","NETMASK=",ip);

        if (fwrite(pbuf,sizeof(char),strlen(pbuf),tfp) <= 0){
			fclose(fp);
   			 fclose(tfp);
			return ERR;
        	}
        ret = OK;
    }

    fclose(fp);
    fclose(tfp);

    return ret;
}

static int modify_nic_gateway(char *path,char *ip)
{
    FILE *fp = NULL;
    FILE *tfp = NULL;
    char buf[1024];
    char pbuf[1024];
    char *keyAddr = NULL;
    int ret = ERR;
    char tmp_path[512];

    if (NULL == path)
        return ERR;

    sprintf(tmp_path,"/etc/sysconfig/network-scripts/%s","tmp");
    copy_cfg_file(path,tmp_path);

    fp = fopen(tmp_path,"r+");
    if (NULL == fp)
        return ERR;

    tfp = fopen(path,"w+");
    if (NULL == tfp){
	 fclose(fp);
        return ERR;
    	}
    while (!feof(fp))
    {
        memset(buf,0x00,1024);
        if (NULL == fgets(buf,1024,fp))
            continue;

        if ('#' == buf[0])
        {
            fwrite(buf,sizeof(char),strlen(buf),tfp);
            continue;
        }

        keyAddr = strstr(buf,"GATEWAY");
        if (NULL == keyAddr)
        {
            fwrite(buf,sizeof(char),strlen(buf),tfp);
            continue;
        }

        sprintf(pbuf,"%s%s\n","GATEWAY=",ip);

        if (fwrite(pbuf,sizeof(char),strlen(pbuf),tfp) <= 0){
			fclose(fp);
    			fclose(tfp);
			return ERR;
        	}
        ret = OK;
    }

    fclose(fp);
    fclose(tfp);

    return ret;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int SYSTEM(const char *cmdstring)
{
    pid_t pid;
    int status = 0;

    if(cmdstring == NULL)
    {
         return (1);
    }

    if((pid = fork()) < 0)
    {
        status = -1;
    }
    else if(pid == 0)
    {
        //execl(cmdstring, (char *)0,(char *)0);
        system(cmdstring);
        _exit(127);
    }

    return status;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void reboot_sys()
{   
    pid_t pid,t_pid;
    char command[248];
    int num = 100000;

    strcpy(command,"/eAudit/bin/eAudit restart");
    system(command);

    //stop_eAudit();
    //while (num--)
    //    sys_delay(1000000);    
    sleep(4);

    DEBUG("########eAudit Stop OK.\n");

    kill((pid_t)g_snam_pid,SIG_STOP_SNAM_MSG);   

#if 0
    pid = fork();
    switch (pid){
        case -1:
            warning("[Err]Create eAudit processes fail.\n");
            break;
        case 0:
            DEBUG("Start eAudit processes");
            execl("/bin/sh", "sh", "-c","/eAudit/bin/eAudit", (char *)0);
            error("[Err]Start eAudit processes Fail.\n");
            exit(EXIT_FAILURE);
            break;
        default:
            break;
   }
#endif

#if 0
    pid = fork();
    if (0 == pid)
    {
       #if 0
        t_pid = fork();   
        switch (t_pid){
            case -1:
            warning("[Err]Create eAudit processes fail.\n");
            break;
            case 0:
            DEBUG("Start eAudit processes");
            execl("/bin/sh", "sh", "-c","/eAudit/bin/eAudit", (char *)0);
            //execl("/eAudit/bin/eAudit",(char *)0,(char *)0);
            error("[Err]Start eAudit processes Fail.\n");
            exit(EXIT_FAILURE);
            break;
            default:
            break;
        }
        waitpid(t_pid,NULL,0);
       #endif
       DEBUG("########Begin start eAudit.\n");
       system("/eAudit/bin/eAudit");
    }
#endif
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void stop_eAudit()
{
    FILE *fp = NULL;
    long pid;
    char pid_file[MAX_FILE_PATH_SIZE];
    char cmd[248];

    snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,"eAudit");
    if (NOT_EXIST == file_is_exist(pid_file)) 
    {
        INFO("The eAudit not start up.\n");
        return;
    }

    INFO("The pid file name = %s\n",pid_file);

    fp = fopen(pid_file,"rb");
    if (NULL == fp)
    {
        warning("fopen pid file fail.\n");
        return;
    }

    while(0 == feof(fp))
    {
         fscanf(fp, "%ld", &pid);
         if (kill((pid_t)pid, SIGTERM) != 0)
	 {
            warning("%s: could not send stop signal (PID: %ld),maybe stoped.\n", "eAudit", pid);
	 }
         sleep(2);
         strcpy(cmd,"kill -9 pid");
         system(cmd);
    }

    fclose(fp);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void sys_delay(long delaytimes)
{
    while(delaytimes--);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void prevent_cps_process()
{
    pid_t pid;
    int stat;

    while((pid = waitpid(-1,&stat,WNOHANG)) < 0);

    return;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void get_snam_pid()
{
    FILE *fp = NULL;
    long pid;
    char pid_file[MAX_FILE_PATH_SIZE];

    memset(pid_file,0x00,MAX_FILE_PATH_SIZE);
    snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,"SNAM");
    if (NOT_EXIST == file_is_exist(pid_file)) 
        return;

    if (NULL == (fp = fopen(pid_file,"rb")))
        return;

    fseek(fp,0,SEEK_SET);
    fscanf(fp, "%ld", &pid);
    g_snam_pid = pid;
    fclose(fp);
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void Read_Protocols_Name(char *input_str,char *out_str){
	int i,len,j=0;
	int k =0;
	len = strlen(input_str);
	DEBUG("input str len = %d",len);
	for(i=0;i<len;i++){
		if((input_str[i]=='_')&&(j==3))
			break;
		if(input_str[i]=='_'){
			++j;
			continue;
		}
		out_str[k] = input_str[i];
		++k;	
	}
	out_str[k]='\0';
	DEBUG("protocols name = %s",out_str);
}
