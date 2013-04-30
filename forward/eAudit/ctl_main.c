
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
#include "interface_block.h"
//#include "interface_authorize.h"    /*add authorize file define */

#include "ctl_pub.h"
#include "ctl_debug.h"
#include "ctl_sys_info.h"
#include "ctl_version_info.h"
#include "ctl_config.h"
#include "ctl_filter_rule.h"
#include "ctl_support_pro.h"
#include "ctl_pkt_file_info.h"
#include "ctl_pkt_shm_que.h"
#include "ctl_res_callback.h"
#include "ctl_cmd.h"
#include "ctl_socket.h"
#include "ctl_usr_list.h"
#include "ctl_access_cmd_list.h"
#include "ctl_access_custom_list.h"
#include "ctl_access_protected_resources_list.h"
#include "ctl_access_protocol_feature_list.h"
#include "ctl_monitor_sysinfo_list.h"
#include "ctl_sq_list.h"
#include "ctl_main.h"
#include "ctl_monitor.h"
#include "ctl_db.h"
#include "ctl_crc32.h"
#include <sail_auth.h>

/*extern globa var define*/
char *g_progname;
long g_us_err_no = 0;
PID_INFO_ID g_pid_info = NULL;
int g_all_process_num;
int g_sys_msg_que_id = -1;

/*static var define*/
static char s_pid_file[MAX_FILE_PATH_SIZE];
//static int s_stop_signo = SIGTERM;	
static int s_stop_signo = SIGKILL;
/*static function declaration*/
static void sys_help(void);
static void sys_stop(char *arv0);
static void sys_status(char *argv0);
static void sys_delay(long delaytimes);
static void Stop_eAudit();
static char *last_dir_separator(const char *dir);
static char *get_progname(const char *argv0);
static void report_err_to_net(int sock_fd,char *wk_info_file);

static int make_sys_log_dir(int log_tool,char *dir_path);
static int check_dir(char *dir_path);
static int is_base_dir(char *dir);
static int chk_support_pro_dir(char *dir_path);
static int chk_cfg_dir(char *dir_path);
static int make_sys_dir(char *dir);
static long  Read_eAudit_Pid();
static int create_pid_file(char *path);

static SUPPORT_PRO_NODE_ID get_support_protocol_list(char** proto_list, int pro_num);
static int make_protocol_pkt_dir(int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,char *pkt_file_dir);
static int make_protocol_data_dir(int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,char *base_data_dir);
static int make_res_reg_dir(char *dir);
static int make_protocol_log_dir(int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,char *base_data_dir);
static int get_shm_max_key(int cfg_que_buf_num,int cfg_mode,CFG_HEAD_ID cfg_hdr_id, char *file_cnt_buf );
static int get_sem_max_key(int cfg_que_buf_num,int cfg_mode,CFG_HEAD_ID cfg_hdr_id, char *file_cnt_buf );

static void rm_file(char *path);
static void rm_res_reg_file(void);
static void res_callback(FILTER_RULE_ID *filter_rule,CFG_NIC_BASIC_ID *nic_basic_buf_id,\
                         char **program_name,char **file_buf,SUPPORT_PRO_NODE_ID *pro_items_id);

static int mp_reg_heap(CFG_NIC_BASIC_ID nic_basic_buf_id,PID_INFO_ID pid_info_id);
static int mp_reg_shm_num(int shm_num);
static int mp_reg_shm(void *shm_addr,int shm_id);
static int mp_reg_shm_key_num(int shm_num);
static int mp_reg_shm_key(key_t shm_key);
static int reg_pid_to_shm(PID_INFO_ID pid_info_id,int idx,long pid,char *path,char *par);
//static int reg_pid_to_shm(PID_INFO_ID pid_info_id,int idx,long pid,int pid_type);
static int reg_pid_to_file(long pid);

static void quick_die(int sig_no);
static void die(int sig_no);
static void prevent_cps_process();
static void swait_child_process();
static void callback_last_res();

static void print_que_info(QUE_ID que_id,int nic_num,int que_num);
static void print_proc_stop_info(const char *format,...);

static void get_proc_name_by_type(int type,char *proc_name);
static int open_dir_set_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);

#ifdef WITH_DAEMON_MODEL
static void init_daemon(void);
#endif

static int pipe_write_key_to_net(key_t pid_info_key,int pipe_fd);
static int wait_child_process(PID_INFO_ID pid_info_id);
static int make_res_dir();
static int create_redirect_port_shm_mem(int *shm_list_id,key_t *shm_list_key,unsigned long *num);
static int set_support_protocol_list_buf(SUPPORT_PRO_NODE_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num);
static unsigned char get_support_protocol_list_num(unsigned char *file_cnt_buf);
static unsigned char get_support_protocol_mode_switch(unsigned char *file_cnt_buf);
/*2009 06 09 */
static int Create_File(char **argv,char *wk_info_file);
static void Stop_Process_Restart(char **argv);
static void Stop_Process(char **argv);
static int Judge_Mutex_Run(char **argv);
static int ReadeAuditSysConf(int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,EAUDIT_SYS_CONF *eAuditSysConf);
static int ReadCaptureNIC(CAPTURE_NIC_CONF *CaptureNicConf,EAUDIT_SYS_CONF *eAuditSysConf,CONFIG_KEY *conf_key,NIC_QUE_INFO_ID nic_que_info_id);
static int Read_ConfigFile_Mem(int serv_num,int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,CONFIG_KEY *conf_key, MONITOR_SYSINFO *monitor_sysinfo,EAUDIT_SYS_CONF *eAuditSysConf,CAPTURE_NIC_CONF *CaptureNicConf);
int Start_ProAnalysis_Server(EAUDIT_SYS_CONF *eAuditSysConf,CAPTURE_NIC_CONF *CaptureNicConf,CONFIG_KEY *conf_key,int fail_proc_num,int *pid_index,char *wk_info_file,int pro_num,int may_proc_num);
static int set_support_server_list_buf(BASIC_SERV_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num);
static BASIC_SERV_ID get_support_server_list(int *serv_num);
static int Start_Basic_Server(BASIC_SERV_ID basic_serv_id,int serv_num,EAUDIT_SYS_CONF *eAuditSysConf,CAPTURE_NIC_CONF *CaptureNicConf,CONFIG_KEY *conf_key,int fail_proc_num,int *pid_index,char *wk_info_file,int pro_num,int may_proc_num);
static long  Read_Connect_Pid();
static int reg_connect_pid_to_file(long pid);
static int Socket_Commulication(char *serv_ip,unsigned short serv_port,int cmd,int wmode);
static int socket_write(int sock_fd,void *buffer,int length);
static int GetConnectServerIpPort(char ip[],unsigned long *port,unsigned long *WorkMode,char child_process_ip[]);
static int eAudit_Exit_Inform_Connect(unsigned long wmode);
static int Socket_NonBlockCommulication(char *serv_ip,unsigned short serv_port,int cmd,int wmode);
static int ReadeAuditSysConfForeAudit(EAUDIT_SYS_CONF *eAuditSysConf);
static int Start_eAudit_Basic_Server(BASIC_SERV_ID basic_serv_id,int serv_num,EAUDIT_SYS_CONF *eAuditSysConf,int *pid_index);
static int Create_eAudit_File(char **argv);
static int eAudit_to_Auth_Shake_Socket();
static int handle_auth_request(int new_fd,const char *addr);
static int Socket_Inform_Child_Process();
static void ResBack_ConnectServer(int sig_no);
static void die1(int sig_no);
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int main(int argc, char **argv)
{
	 char wk_info_file[MAX_FILE_PATH_SIZE];
        CFG_NIC_BASIC_ID nic_basic_buf = NULL;
        int pid_index=0;
	 register int i,j;
    	 int log_pri = LOG_DEBUG;	 
    	 int log_filter_mode = LOG_NOT_FILTER;
    	 int log_tool = LOG_TOOL;
    	 int pro_num = 0;
	char* proto_list[] = {"HTTP", "FTP", "SMTP", "POP3", "TELNET", "MSN", "EMULE", "X11", "RDP",
						"RLOGIN", "NETBIOS", "SYBASE", "SQLSERVER", "ORACLE", "INFORMIX", 
						"DB2", "ARP", "SKYPE","QQ","THUNDER","BT", "FETION"};
	
    	 SUPPORT_PRO_NODE_ID pro_items_id = NULL;
		
	 SUPPORT_PRO_NODE_ID now_pro_items_id =NULL;
	 int now_pro_num =0;
        int fail_proc_num = 0;
    	 int may_proc_num = 0;
        PRO_FEATURE_PARA_ID pro_feature_id = NULL;
    	 key_t pro_tbl_shm_key;
    	 SUPPORT_PRO_NODE_ID pro_tbl_shm_addr = NULL;
   	 int cfg_que_buf_num;
        QUE_ID cfg_que_info = NULL;
    	 key_t run_cfg_shm_key; 
        unsigned long run_cfg_shm_size;
	
    	 key_t rule_que_shm_key;
       

        unsigned long filter_rules_num;
        FILTER_RULE_ID filter_rule_id = NULL;
        PORT_INDEX_RULE_ID port_index_id = NULL;
    
    	 key_t shm_pool_key;
    	 unsigned long pool_size = 0;
    	 key_t pool_sem_key;

	 NIC_QUE_INFO_ID nic_que_info_id = NULL;
    
	key_t pid_info_shm_key;
       unsigned long pid_info_shm_size = 0;

       char protocol_name[32];
       int protocol_name_len =0;

       /*系统监控信息结构体声明*/
       MONITOR_SYSINFO monitor_sysinfo;
       /*2009 06 09*/
   	EAUDIT_SYS_CONF eAuditSysConf;
       CAPTURE_NIC_CONF CaptureNicConf;
       CONFIG_KEY conf_key;
       PROTECTED_RESOURCE_ID protect_res_addr0=NULL;
	PROTECTED_RESOURCE_ID protect_res_addr1=NULL;
       BASIC_SERV_ID basic_serv_id =NULL;
       int serv_num = 0;
       char *file_cnt_buf = NULL;
	int fd =-1;
	SAIL_AUTH pData_auth;
	SAIL_Analysis_AUTH *pData_analysis=NULL;
	SAIL_Function_AUTH *pData_function=NULL;
	char serv_ip1[20],child_ip[20];
	unsigned long serv_port,work_mode;
	unsigned long wmode=0;

       memset((char *)&monitor_sysinfo,0,sizeof(monitor_sysinfo));
	memset((char *)&eAuditSysConf,0,sizeof(eAuditSysConf));
	memset((char *)&CaptureNicConf,0,sizeof(CaptureNicConf));

	memset((char *)&conf_key,0,sizeof(conf_key));

	memset((char *)&pData_auth,0,sizeof(pData_auth));
	
    /*1 only one paremters*/
    if ((1 == argc) &&(ERR == Judge_Mutex_Run(argv)))
    	exit(EXIT_FAILURE);
    /*2:set local for isprint*/
    setlocale(LC_ALL, "");
    signal(SIG_STOP_SNAM_MSG, Stop_eAudit);
    signal(SIGINT,SIG_IGN);
    signal(SIGKILL,quick_die);
    signal(SIGTERM, die);	
    signal(SIGCHLD,prevent_cps_process);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCONT,ResBack_ConnectServer);
	
     /*20090813 add */
    GetConnectServerIpPort(serv_ip1,&serv_port,&work_mode,child_ip);	
    wmode = work_mode;
   // printf("wmode = %d \n",wmode);
    /*3:get program par */
    if (argc > 1)
    {
        if(strcmp(argv[1], "restart") == 0)
        {   
             if(wmode !=3 )
              	eAudit_Exit_Inform_Connect(wmode);
	      Stop_Process_Restart(argv);
	      exit(EXIT_SUCCESS);
        }
        if (strcmp(argv[1], "stop") == 0)
        {
             if(wmode !=3 )
			eAudit_Exit_Inform_Connect(wmode);
		Stop_Process(argv);
		exit(EXIT_SUCCESS);
        }
	 DEBUG("Please renew input para ,input para err   ");
	 exit(EXIT_SUCCESS);
    }
    
  //if((wmode &0x00000001 ==0x01) ||((wmode &0x00000001 ==0x00) &&(wmode &0x02 ==0x00000000)))	{
   if((wmode ==0)||(wmode == 1)){
   /*add authorize info manage tool*/
   pData_analysis = (SAIL_Analysis_AUTH*)calloc(sizeof(SAIL_Analysis_AUTH),100);
   if(pData_analysis ==NULL)
		exit(EXIT_FAILURE);
    pData_function = (SAIL_Function_AUTH *)calloc(sizeof(SAIL_Function_AUTH),30);
   if(pData_function ==NULL)
		exit(EXIT_FAILURE);
  
    /*4 create pid file and check sys dir*/
    memset(wk_info_file,0x00,MAX_FILE_PATH_SIZE);
    sprintf(wk_info_file,"%s/%s",SYS_WORK_INFO_DIR_PATH,SYS_WORK_INFO_FILE_NAME);
    if(ERR ==  Create_File(argv,wk_info_file))
    		exit(EXIT_FAILURE);
    while(0x00 != sail_read_authdata(1,&pData_auth,pData_analysis,pData_function)){
		sleep(20);
   }
   /*5:make the sys log dir*/
  if (ERR == make_sys_log_dir(log_tool,LOG_DIR_PATH))
  {
        error("[Err]Create us log dir fail.\n");
        (void)record_sys_work_info(wk_info_file,"Create us log dir fail.",\
                                                      RECORD_INC_TIME); 
        goto SYS_ERROR;
  }
  init_log(SYS_NAME,LOG_TOOL,log_filter_mode);
  
  /*6:get sys free mem size etc.*/
  if (ERR == get_sys_mem_size(&(g_sys_hw_info.mem_info)))
  {
        error("[Err]Get sys mem info err.\n");
        (void)record_sys_work_info(wk_info_file,"Get sys mem info err.",\
                                                      RECORD_INC_TIME); 
        goto SYS_ERROR;
  }
    /*14:check sys support protocol dir and file*/
    if (ERR == chk_support_pro_dir(SUPPORT_PRO_DIR_PATH))
    {
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Support protocols list dir err!\n");
        goto SYS_ERROR;
    }

    /*7:read system support protocols*/
	pro_num = sizeof(proto_list)/sizeof(char*);
	
   pro_items_id = get_support_protocol_list(proto_list, pro_num);
   // printf("pro_num = %d\n",pro_num);
    if (NULL == pro_items_id)
    {
        error("[Err]Get support protocols fail.");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get support protocols list file content fail!\n");
        pro_num =0;
    }

    //DEBUG("Get support protocols list OK.");

    /*16:check system support protocols items*/
    if (SAIL_OK != chk_support_pro(pro_items_id,pro_num))
    {
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Set support protocols list file items err!\n");
        goto SYS_ERROR;
    }
    (void)record_sys_work_info(wk_info_file,"Get support protocols list  OK.",RECORD_INC_TIME);
    /*add basic server into system */
    basic_serv_id = get_support_server_list(&serv_num);
    if(NULL == basic_serv_id){
		error("[Err]get support server list err .\n");
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get support server list err!");
		serv_num = 0;
    }
   /*compare pro tbl*/
    now_pro_num = pData_auth.auth_num;
    now_pro_items_id = (SUPPORT_PRO_NODE_ID)calloc(SUPPORT_PRO_NODE_SIZE,now_pro_num);
    if(now_pro_items_id ==NULL)
	 exit(EXIT_FAILURE);
    for(i=0;i<now_pro_num;i++){
		strcpy(now_pro_items_id[i].pro_name,(pro_items_id+pData_analysis[i].flag-1)->pro_name);
		now_pro_items_id[i].pro_no = i;
   }
   FREE(pro_items_id);

    if(ERR == ReadeAuditSysConf(now_pro_num,now_pro_items_id,&eAuditSysConf))
		goto SYS_ERROR;


    /*32:check protect rules num*/
    if (eAuditSysConf.MaxProtectRulesNum* protected_resource_size >(g_sys_hw_info.mem_info.free_mem_size)*1024*\
        CAPTURE_FILTER_PROPORTION*RULE_PROPORTION/2)
    {
        error("[Err]Rules num too big.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Rules num too big!");
        goto SYS_ERROR;
    }

    /*33:make res reg dir*/
#ifdef WITH_FILE_REG_RES
    if (ERR == make_res_reg_dir(RES_REG_DIR))
    {
        error("[Err]Make system resource reg dir fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make system resource reg dir fail!\n");
        goto SYS_ERROR;
    }
#endif
    
    /*35:callback last res*/
#ifdef WITH_SHM_KEY_FILE
    callback_last_res();
#endif
       /*read capture NIC FILE */
	if(ERR == ReadCaptureNIC(&CaptureNicConf,&eAuditSysConf,&conf_key,nic_que_info_id))
		goto SYS_ERROR;
	conf_key.ProResNum =  pData_auth.CSV_Num;
	conf_key.UsrNum =  pData_auth.userNum;
   	/*read and analysis authorize config information  */
      if(ERR == Read_ConfigFile_Mem(serv_num,now_pro_num,now_pro_items_id,&conf_key,&monitor_sysinfo,&eAuditSysConf,&CaptureNicConf))
	  	goto SYS_ERROR;
	/*res callback use */  
	protect_res_addr0 = (PROTECTED_RESOURCE_ID)calloc(protected_resource_size,conf_key.protected_resources_num);
   	if(protect_res_addr0 ==NULL){
		error("alloc protect res mem fail");
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"alloc protect res mem fail!");
		goto SYS_ERROR;
   	}
    	PROTECTED_RESOURCE_ID list_id0 = (PROTECTED_RESOURCE_ID)shmat(conf_key.protected_resource_list_id0,NULL,SHM_RDONLY);
    	if(list_id0 == NULL){
		error("alloc protect res SHM  fail");
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"alloc protect res SHM fail!");
		goto SYS_ERROR;
    	}
    	memcpy((char *)protect_res_addr0,(char *)list_id0,conf_key.protected_resources_num*protected_resource_size); 
       protect_res_addr1 = (PROTECTED_RESOURCE_ID)calloc(protected_resource_size,conf_key.protected_resources_num);
   	if(protect_res_addr1 ==NULL){
		error("alloc protect res mem fail");
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"alloc protect res mem fail!");
		goto SYS_ERROR;
   	}
    	PROTECTED_RESOURCE_ID list_id1 = (PROTECTED_RESOURCE_ID)shmat(conf_key.protected_resource_list_id1,NULL,SHM_RDONLY);
    	if(list_id1 == NULL){
		error("alloc protect res SHM  fail");
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"alloc protect res SHM fail!");
		goto SYS_ERROR;
    	}
    	memcpy((char *)protect_res_addr1,(char *)list_id1,conf_key.protected_resources_num*protected_resource_size); 
		
      if(ERR == Start_ProAnalysis_Server(&eAuditSysConf,&CaptureNicConf,&conf_key, fail_proc_num, &pid_index,wk_info_file,now_pro_num,may_proc_num))
		goto SYS_ERROR;
      if(ERR == Start_Basic_Server(basic_serv_id, serv_num,&eAuditSysConf,&CaptureNicConf,&conf_key, fail_proc_num,&pid_index,wk_info_file,now_pro_num, may_proc_num))
		goto SYS_ERROR;	
	//DEBUG("Start analysis process and Server Success.........................................................................................");
	//DEBUG("pid_index = %d \n",pid_index);
	if(fork()==0){
		//printf("进入握手子进程\n");
		sleep(8);
		eAudit_to_Auth_Shake_Socket();
		exit(EXIT_SUCCESS);
	}
  	if(-1 ==eAudit_Monitor(g_pid_info,++pid_index,s_pid_file,eAuditSysConf.MonitorTimeIntervals,&monitor_sysinfo,eAuditSysConf.MonitorNum,now_pro_items_id,now_pro_num))
   		goto SYS_EXIT; 
  }
 // else if((wmode &0x00000001 ==0x00) &&(wmode &0x00000002 ==0x02)){
    else if(wmode==2 || wmode==3){
		printf("进入动态身份eAudit 模式\n");
		//read eAudit sys file info */
        if(ERR == Create_eAudit_File(argv))
			goto SYS_ERROR;
	 if(ERR == ReadeAuditSysConfForeAudit(&eAuditSysConf))
		goto SYS_ERROR;
	  /*get basic NTP PMC CONNECT server */
	 basic_serv_id = get_support_server_list(&serv_num);
   	 if(NULL == basic_serv_id){
		error("[Err]get support server list err .\n");
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get support server list err!");
		serv_num = 0;
    	}
	 g_pid_info =(PID_INFO_ID)calloc(serv_num,PID_INFO_SIZE);
	 if(g_pid_info ==NULL)
	 	goto SYS_ERROR;
	/*动态身份认证基本服务 */
       if(ERR == Start_eAudit_Basic_Server(basic_serv_id, serv_num,&eAuditSysConf,&pid_index))
		goto SYS_ERROR;	
	monitor_sysinfo.cpu_use_rate = 80;
	monitor_sysinfo.hd_use_rate = 80;
	monitor_sysinfo.mem_use_rate = 80;
	now_pro_items_id =NULL;
	now_pro_num =0;
       if(-1 ==eAudit_Monitor(g_pid_info,pid_index,s_pid_file,eAuditSysConf.MonitorTimeIntervals,&monitor_sysinfo,eAuditSysConf.MonitorNum,now_pro_items_id,now_pro_num))
   		goto SYS_EXIT; 

}else
	printf("没有进入任何模式\n");
SYS_ERROR:
SYS_EXIT:
 if((wmode  ==1) ||((wmode ==0) ||(wmode ==3)))	{ 
 //二合一或者单独检测服务器
   // printf("回收资源\n");
    FREE(pro_items_id);
    Sem_Ip_Queque_Destroy(conf_key.ip_queque_sem_id0);
    Sem_Ip_Queque_Destroy(conf_key.ip_queque_sem_id1);
    die1(SIGTERM);
//    FREE(nic_que_info_id);
    DEL_SHM(conf_key.run_cfg_shm_id);
    DEL_SHM(conf_key.pro_tbl_shm_id);
    DEL_SHM(conf_key.pid_info_shm_id); 
    DEL_SHM(conf_key.redirect_port_shm_id);
    callback_shm_pretected_resource(protect_res_addr0,conf_key.protected_resource_list_id0,conf_key.protected_resources_num,conf_key.Pro_Real_Line);
    callback_shm_pretected_resource(protect_res_addr1,conf_key.protected_resource_list_id1,conf_key.protected_resources_num,conf_key.Pro_Real_Line);
    DEL_SHM(conf_key.usr_list_id);
    DEL_SHM(conf_key.authorize_network_id);
    callback_shm_account(conf_key.authorize_account_id,conf_key.authorize_account_num);
    callback_shm_cmd(conf_key.authorize_cmd_id,conf_key.authorize_cmd_num);
    callback_shm_custom(conf_key.authorize_custom_id,conf_key.authorize_custom_num);
    for(i=0;i<now_pro_num;i++){
	 	if(conf_key.pro_feature_id[i].pro_feature_key>0)
	 		 callback_shm_protocol_feature(conf_key.pro_feature_id[i].shm_id,conf_key.pro_feature_id[i].pro_feature_num);
    }

    DEL_SHM(conf_key.tcpclosequequeptr_shmid0);
    DEL_SHM(conf_key.tcpclosefirstque_shmid0);
    DEL_SHM(conf_key.tcpclosesecondque_shmid0);
    DEL_SHM(conf_key.ipque_shmid0);
    DEL_SHM(conf_key.snd_check_block_shmid0);
    DEL_SHM(conf_key.tcpclosequequeptr_shmid1);
    DEL_SHM(conf_key.tcpclosefirstque_shmid1);
    DEL_SHM(conf_key.tcpclosesecondque_shmid1);
    DEL_SHM(conf_key.ipque_shmid1);
    DEL_SHM(conf_key.snd_check_block_shmid1);
    DEL_SYS_MSG_QUE(g_sys_msg_que_id);
    rm_res_reg_file();
    unlink(s_pid_file);
    del_dir_and_file(RES_REG_DIR);
 }else{
	unlink(s_pid_file);
      if(g_pid_info!=NULL)
       	free(g_pid_info);
 	}
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
static int make_sys_log_dir(int log_tool,char *dir_path)
{
    int ret = OK;
	
    if (SYS_LOG != log_tool)
    {
        ret = make_dir(LOG_DIR_PATH,S_IRWXU);
    }

    return ret;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int check_dir(char *dir_path)
{
	DIR *dirptr;
	struct dirent *entry;
	int result = DIR_IS_EMPTY;

	errno = 0;

       // info("dir = %s\n",dir_path);
	dirptr = opendir(dir_path);

	if (NULL == dirptr)
		return (errno == ENOENT) ? DIR_IS_NOEXISTS : OPEN_DIR_ERR;

	while ((entry = readdir(dirptr)) != NULL)
	{
		if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
		{
			continue;
		}
		else
		{
			result = DIR_IS_NOEMPTY;			/* not empty */
			break;
		}
	}

	closedir(dirptr);

	if (errno != 0)
	    result = OPEN_DIR_ERR;			      /* some kind of I/O error? */

	return result;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int chk_support_pro_dir(char *dir_path)
{
    int ret = OK;
    int log_pri = LOG_DEBUG;	
	
    switch (check_dir(dir_path))
    {
        case DIR_IS_NOEXISTS:
	      //  info("[Info]Creating directory %s ... ",dir_path);
	        if (ERR == make_dir(dir_path,S_IRWXU))
                {
                    error("[Err]Create support protocols list dir fail.\n");
                    return ERR;
                }

	        error("[Err]Please Create support protocols list file in the %s dir.\n",dir_path);
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"No support protocols list file!\n");
	        ret = ERR;
	        break;
	    case DIR_IS_EMPTY:
	        error("[Err]Please Create support protocols list file in the %s dir.\n",dir_path);
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"No support protocols list file!\n");
	        ret = ERR;
	        break;
	    case DIR_IS_NOEMPTY:
	        break;
	    case OPEN_DIR_ERR:
	        error("[Err]Open the support protocols list dir[%s] err.\n",dir_path);
	        ret = ERR;
	        break;
	    default:
	        error("[Err]Check dir[%s] happen call err.\n",dir_path);
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Open support protocols list dir happen call err!\n");
	        ret = ERR;
	        break;
    }

    return ret;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int chk_cfg_dir(char *dir_path)
{
    int ret = OK;
    int log_pri = LOG_DEBUG;	
	
    switch (check_dir(dir_path))
    {
        case DIR_IS_NOEXISTS:
	        //info("[Info]Creating directory %s ... ",dir_path);
	        if (ERR == make_dir(dir_path,S_IRWXU))
               {
                    error("[Err]Create sys config dir fail.\n");
                    return ERR;
               }

	        error("[Err]Please Create sys config file in the %s dir.\n",dir_path);
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"No sys config file!\n");
	        ret = ERR;
	        break;
	    case DIR_IS_EMPTY:
	        error("[Err]Please Create sys config file in the %s dir.\n",dir_path);
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"No sys config file!\n");
	        ret = ERR;
	        break;
	    case DIR_IS_NOEMPTY:
	        break;
	    case OPEN_DIR_ERR:
	        error("[Err]Open the sys config dir[%s] err.\n",dir_path);
	        ret = ERR;
	        break;
	    default:
	        error("[Err]Check dir[%s] happen call err.\n",dir_path);
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Open support protocols list dir happen call err!\n");
	        ret = ERR;
	        break;
    }

    return ret;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int is_base_dir(char *dir)
{
    int num = 0;
    char *p = dir;

    ++p;
	
    while (*p != '\0')
    {
        if ('/' == *p)
	    ++num;

        ++p;
    }

    if (num == strlen(dir))
        return SAIL_TRUE;

    return SAIL_FALSE;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int make_sys_dir(char *dir)
{
    int last;
    int ret = OK;
    struct stat sb;
    char tmp_dir[MAX_DIR_SIZE+1];
    register char *p = NULL;

    if (strlen(dir) > MAX_DIR_SIZE)
    {
        error("[Err]Dir path too long.\n");
        return ERR;
    }

    strcpy(tmp_dir,dir);
    p = tmp_dir;

    if (SAIL_TRUE == is_base_dir(p))
    {
        error("[Err]The '/' dir don't be allowed.\n");
        return ERR;
    }

    if ('.' == p[0])
        ++p;

    if ('/' == p[0])
        ++p;

    ++p;
    for (last = 0;!last;++p)
    {
           if (EOS == p[0])
	        last = 1;
	    else if(p[0] != '/')
	        continue;

	    *p = '\0';
	    if (!last && p[1] == EOS)
	    {
                last = 1;
	    }
	
	    if (stat(tmp_dir, &sb) == 0)
	    {
	        if (!S_ISDIR(sb.st_mode))
	        {
	            if (last)
	                errno = EEXIST;
	            else
	                errno = ENOTDIR;

		    ret = ERR;
		    error("[Err]The %s dir is exists but not a dir.\n");
		    break;
	        }
	    }
            else if (mkdir(tmp_dir, S_IRWXU|S_IRWXG|S_IRWXO) < 0)
	    {
                //printf("dir = %s\n",tmp_dir);
                error("[Err]mkdir error.\n");
	        ret = ERR;
	        break;
            }

	     if (!last)
	        *p = '/';
   }

   return ret;
}


/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static BASIC_SERV_ID get_support_server_list(int *serv_num)
{
	int fd = DEF_FILE_DES_VAL;
	char *file_cnt_buf = NULL;
	BASIC_SERV_ID addr = NULL;
	char file_name[MAX_FILE_PATH_SIZE+1];
	unsigned long file_size = 0;
	int ret;
	int have_read;
	unsigned char mode_switch = 0;
	unsigned long line_num = 0;
	unsigned long read_num=0;
	
	memset(file_name,0x00,MAX_FILE_PATH_SIZE+1);
	sprintf(file_name,"%s/%s",SUPPORT_PRO_DIR_PATH,SUPPORT_SERV_FILE_NAME);
	if (SAIL_OK != open_support_pro_file(file_name,&fd, &file_size))
	{
		write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Open support server list file fail!");
		return NULL;
	}
	
	file_cnt_buf = (char *)malloc(file_size + 1);
	if (NULL == file_cnt_buf)
	{
		error("[Err]Malloc for support server list file fail.\n");
		close(fd);
		return ERR;
	}

	if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
	{
		FREE(file_cnt_buf);
		close(fd);
		fd = DEF_FILE_DES_VAL;
		error("[Err]Get support server list file content fail[PPP]!\n");
		write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get support server list file content fail!");
		return NULL;
	}
	file_cnt_buf[file_size] = '\0';
	//printf("file_cnt_buf = %s \n",file_cnt_buf);
	close(fd);


   	mode_switch = get_support_protocol_mode_switch(file_cnt_buf);

	line_num = get_support_protocol_list_num(file_cnt_buf);

	if(line_num == 0)
	{
		free(file_cnt_buf);
		return ERR;
	}
	addr = (BASIC_SERV_ID)calloc(BASIC_SERV_SIZE,line_num);
	if (NULL == addr)
	{
		error("[Err]Calloc for all support server items fail!\n");
		FREE(file_cnt_buf);
		write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Calloc for all support server items fail!");
		return NULL;
	}
    	set_support_server_list_buf(addr, file_cnt_buf,line_num,mode_switch,&read_num);
	FREE(file_cnt_buf);
	*serv_num = read_num;
	return addr;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static SUPPORT_PRO_NODE_ID get_support_protocol_list(char** proto_list, int pro_num)
{
/*	int fd = DEF_FILE_DES_VAL;
	char *file_cnt_buf = NULL;
	SUPPORT_PRO_NODE_ID addr = NULL;
	char file_name[MAX_FILE_PATH_SIZE+1];
	unsigned long file_size = 0;
	int ret;
	int have_read;
	unsigned char mode_switch = 0;
	unsigned long line_num = 0;
	unsigned long read_num=0;
	
	memset(file_name,0x00,MAX_FILE_PATH_SIZE+1);
	sprintf(file_name,"%s/%s",SUPPORT_PRO_DIR_PATH,SUPPORT_PRO_FILE_NAME);
	if (SAIL_OK != open_support_pro_file(file_name,&fd, &file_size))
	{
		write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Open support protocols list file fail!");
		return NULL;
	}
	printf("#################file_size = %d fd = %d\n",file_size, fd);
	printf("file_size = %d\n",file_size);
	file_cnt_buf = (char *)malloc(file_size + 1);
	if (NULL == file_cnt_buf)
	{
		error("[Err]Malloc for authorize custom list file fail.\n");
		close(fd);
		return ERR;
	}

	if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
	{
		FREE(file_cnt_buf);
		close(fd);
		fd = DEF_FILE_DES_VAL;
		error("[Err]Get support protocols list file content fail[PPP]!\n");
		write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get support protocols list file content fail!");
		return NULL;
	}
	file_cnt_buf[file_size] = '\0';
	printf("sys file content = %s\n",file_cnt_buf);
	close(fd);


   	mode_switch = get_support_protocol_mode_switch(file_cnt_buf);

	line_num = get_support_protocol_list_num(file_cnt_buf);

	if(line_num == 0)
	{
		free(file_cnt_buf);
		return ERR;
	}
	addr = (SUPPORT_PRO_NODE_ID)calloc(SUPPORT_PRO_NODE_SIZE,line_num);
	if (NULL == addr)
	{
		error("[Err]Calloc for all support protocols items fail!\n");
		FREE(file_cnt_buf);
		write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Calloc for all support protocols items fail!");
		return NULL;
	}
    	set_support_protocol_list_buf(addr, file_cnt_buf,line_num,mode_switch,&read_num);
	FREE(file_cnt_buf);
	*pro_num = read_num;
	return addr;*/
	int i;
	SUPPORT_PRO_NODE_ID addr = NULL;
	if(pro_num == 0)
	{
		return NULL;
	}
	if((addr = (SUPPORT_PRO_NODE_ID)calloc(pro_num, SUPPORT_PRO_NODE_SIZE)) == NULL)
	{
		return NULL;
	}
	for(i = 0; i< pro_num; i++)
	{
		addr[i].pro_no = i;
		strcpy(addr[i].pro_name, proto_list[i]);
	}
	return addr;
}


static unsigned char get_support_protocol_mode_switch(unsigned char *file_cnt_buf)
{
    register char *str = file_cnt_buf;
    char key_val[64];
    
    if (NULL == file_cnt_buf)
        return 1;
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_MODE_GETE_KEY,key_val))
   {
            	  error("getauthorize support protocol switch  err.\n");
                return 1;
   }
   if(strlen(key_val)<2)
   	return 1;
    if(strncmp(key_val, "ON", 2) ==0)
    		return 1;
   return 0;
}

static unsigned char get_support_protocol_list_num(unsigned char *file_cnt_buf)
{
    register int num = 0;
    register char *str = file_cnt_buf;
    char key_val[64];

    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    memset(key_val,0x00,64);
   if (GET_CFG_VAL_FAIL == cfg_get_key_val(str,LIST_COMMON_KEY,LIST_NUM_KEY,key_val))
   {
            	  error("get support protocol list num  err.\n");
                return 0;
   }
    num = atoi(key_val);
    return num;
}

static int set_support_protocol_list_buf(SUPPORT_PRO_NODE_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num)
{
	unsigned long i = 0;
	unsigned long j =0;
	char *p = NULL;
	char *s = file_cnt_buf;
//	USR_LIST_MEM_ID d = list_id;
	unsigned char key_val[512];
	char info_str[32];
	if ((NULL == list_id) || (NULL == file_cnt_buf)||(0==buf_num))
		return(CTL_PAR_ERR);

	for(i=0;i<buf_num;i++)
	{
		memset(info_str,0x00,32);
		memset(key_val,0x00,512);
		sprintf(info_str,"%s%d",LIST_RESOURCE_KEY,i);
		if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,key_val))
		{
			error("get support protocol  line  err.\n");
			continue;
		}
		list_id[j].pro_no = j;
		strcpy(list_id[j].pro_name, key_val);
		j++;
	}
	*real_list_num = j;
	return(SAIL_OK);
}

static int set_support_server_list_buf(BASIC_SERV_ID list_id,unsigned char *file_cnt_buf,unsigned long buf_num,unsigned char mode_switch_type,unsigned long *real_list_num)
{
	unsigned long i = 0;
	unsigned long j =0;
	char *p = NULL;
	char *s = file_cnt_buf;
//	USR_LIST_MEM_ID d = list_id;
	unsigned char key_val[512];
	char info_str[32];
	if ((NULL == list_id) || (NULL == file_cnt_buf)||(0==buf_num))
		return(CTL_PAR_ERR);

	for(i=0;i<buf_num;i++)
	{
		memset(info_str,0x00,32);
		memset(key_val,0x00,512);
		sprintf(info_str,"%s%d",LIST_RESOURCE_KEY,i);
		if (GET_CFG_VAL_FAIL == cfg_get_key_val(s,LIST_INFO_KEY,info_str,key_val))
		{
			error("get support server  line  err.\n");
			continue;
		}
		strcpy(list_id[j].serv_name, key_val);
		j++;
	}
	*real_list_num = j;
	return(SAIL_OK);
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int get_shm_max_key(int cfg_que_buf_num,int cfg_mode,CFG_HEAD_ID cfg_hdr_id, char *file_cnt_buf )
{
    key_t *shm_key_array = NULL;
		
    switch (cfg_mode)
    {
        case READ_FILE:            
            shm_key_array = (key_t * )calloc(sizeof(key_t),cfg_que_buf_num);
            if (NULL == shm_key_array)
            {
    	        error("[Err]Calloc shm key array fail.\n");
                return ERR;
            }
            
            if (ERR == get_shm_key_array(shm_key_array,cfg_hdr_id->iNICNum,cfg_hdr_id->iPerNICQueNum,file_cnt_buf))
            {
	            error("[Err]Get shm key array fail.\n");
		        FREE(shm_key_array);		  
                return ERR;
	        }
	          
	        g_max_shm_key = get_max_shm_key(shm_key_array,cfg_que_buf_num);
		 printf("g_max_shm_key = %ld \n",g_max_shm_key);
		 

	        FREE(shm_key_array);
            break;		
        case DEF_MODE:
        default:
	        g_max_shm_key = DEF_QUE_SHM_KEY + (cfg_que_buf_num - 1)*SHM_KEY_IVL;
            break;
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
static int get_sem_max_key(int cfg_que_buf_num,int cfg_mode,CFG_HEAD_ID cfg_hdr_id, char *file_cnt_buf )
{
    key_t *sem_key_array = NULL;
		
    switch (cfg_mode)
    {
        case READ_FILE:
            sem_key_array = (key_t * )calloc(sizeof(key_t),cfg_que_buf_num);
            if (NULL == sem_key_array)
            {
                error("[Err]calloc sem key array fail.\n");
                return ERR;
            }

            if (ERR == get_sem_key_array(sem_key_array,cfg_hdr_id->iNICNum,cfg_hdr_id->iPerNICQueNum,file_cnt_buf))
            {
                error("[Err]Get sem key array fail.\n");
		        FREE(sem_key_array);
                return ERR;
            }

            g_max_sem_key = get_max_sem_key(sem_key_array,cfg_que_buf_num);

            FREE(sem_key_array);
            break;			
        case DEF_MODE:
        default:
            g_max_sem_key = DEF_QUE_SEM_KEY + (cfg_que_buf_num - 1)*SEM_KEY_IVL;
            break;
    }

    g_max_shm_key += EMPTY_SEM_IVL;
	
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
static int make_protocol_pkt_dir(int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,char *pkt_file_dir)
{
    register int i;
    char pro_dir[MAX_DIR_SIZE + 1];

    for (i = 0;i < pro_num;i++)
    {
        memset(pro_dir,0x00,MAX_DIR_SIZE+1);
        sprintf(pro_dir,"%s/%s",pkt_file_dir,(pro_items_id+i)->pro_name);
		
       // DEBUG("PROTOCOL PKT FILE DIR[%d] = %s\n",i,pro_dir);
	
        if (ERR == make_dir(pro_dir,S_IRWXU))
        {
            error("[Err]Make %s protocol packets files dir fail.\n",(pro_items_id+i)->pro_name);
            return ERR;
        }    
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
static int make_protocol_data_dir(int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,char *base_data_dir)
{
    register int i;
    char pro_dir[MAX_DIR_SIZE + 1];

    for (i = 0;i < pro_num;i++)
    {
        memset(pro_dir,0x00,MAX_DIR_SIZE+1);
        sprintf(pro_dir,"%s/%s",base_data_dir,(pro_items_id+i)->pro_name);
		
      //  DEBUG("PROTOCOL PKT FILE DIR[%d] = %s\n",i,pro_dir);
	
        if (ERR == make_dir(pro_dir,S_IRWXU))
        {
            error("[Err]Make %s protocol packets files dir fail.\n",(pro_items_id+i)->pro_name);
            return ERR;
        }    
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
static int make_protocol_log_dir(int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,char *base_data_dir)
{
    register int i;
    char pro_dir[MAX_DIR_SIZE + 1];

    for (i = 0;i < pro_num;i++)
    {
        memset(pro_dir,0x00,MAX_DIR_SIZE+1);
        sprintf(pro_dir,"%s/%s",base_data_dir,(pro_items_id+i)->pro_name);
		
      //  DEBUG("PROTOCOL PKT FILE DIR[%d] = %s\n",i,pro_dir);
	
        if (ERR == make_dir(pro_dir,S_IRWXU))
        {
            error("[Err]Make %s protocol log dir fail.\n",(pro_items_id+i)->pro_name);
            return ERR;
        }    
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
static int make_res_reg_dir(char *dir)
{
    char res_dir[MAX_DIR_SIZE + 1];

    if (ERR == make_dir(dir,S_IRWXU))
    {
        error("[Err]Make res reg dir fail.\n");
        return ERR;
    }

    memset(res_dir,0x00,MAX_DIR_SIZE+1);
    sprintf(res_dir,"%s/%s",dir,START_MODEL_NAME);	
    if (ERR == make_dir(res_dir,S_IRWXU))
    {
        error("[Err]Make start res reg dir fail.\n");
        return ERR;
    }    
 
    memset(res_dir,0x00,MAX_DIR_SIZE+1);
    sprintf(res_dir,"%s/%s",dir,CAPTURE_MODEL_NAME);	
    if (ERR == make_dir(res_dir,S_IRWXU))
    {
        error("[Err]Make capture res reg dir fail.\n");
        return ERR;
    } 

    memset(res_dir,0x00,MAX_DIR_SIZE+1);
    sprintf(res_dir,"%s/%s",dir,FILTER_MODEL_NAME);	
    if (ERR == make_dir(res_dir,S_IRWXU))
    {
        error("[Err]Make filter res reg dir fail.\n");
        return ERR;
    } 

    memset(res_dir,0x00,MAX_DIR_SIZE+1);
    sprintf(res_dir,"%s/%s",dir,ANALYZE_MODEL_NAME);	
    if (ERR == make_dir(res_dir,S_IRWXU))
    {
        error("[Err]Make analysis res reg dir fail.\n");
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
static void res_callback(FILTER_RULE_ID *filter_rule,CFG_NIC_BASIC_ID *nic_basic_buf_id,
                         char **program_name,char **file_buf,SUPPORT_PRO_NODE_ID *pro_items_id)
{
    //if (NULL != filter_rule)
    //{
     //   SAIL_free((void **)filter_rule);
    //}

    if (NULL != nic_basic_buf_id)
    {
        SAIL_free((void **)nic_basic_buf_id);  
    }

    if (NULL != program_name)
    {
        SAIL_free((void **)program_name);  
    }

    //if (NULL != file_buf)
    //{
    //    SAIL_free((void **)file_buf);
    //}
    
    if (NULL != pro_items_id)
    {
        SAIL_free((void **)pro_items_id);
    }

    del_dir_and_file(EAUDIT_LOCK_FILE);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int mp_reg_heap(CFG_NIC_BASIC_ID nic_basic_buf_id,PID_INFO_ID pid_info_id)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];
   
    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    get_res_reg_file_path(file_path,MEM_RES_FILE_NAME,START_MODEL_NAME);

   // printf("file path =%s\n",file_path);
    if (NULL == (fp = fopen(file_path,"a+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",2);
    fputs(buf,fp);
    fputc('\n',fp);

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%ld",(unsigned long)nic_basic_buf_id);
    fputs(buf,fp);
    fputc('\n',fp);

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%ld",(unsigned long)pid_info_id);
    fputs(buf,fp); 
    fputc('\n',fp);  

    fflush(fp); 
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
static int mp_reg_shm_num(int shm_num)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];
  
    memset(file_path,0x00,MAX_FILE_PATH_SIZE);

    get_res_reg_file_path(file_path,SHM_RES_FILE_NAME,START_MODEL_NAME);              

    if (NULL == (fp = fopen(file_path,"w+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",shm_num);
    fputs(buf,fp);
    fputc('\n',fp);

    fflush(fp);
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
static int mp_reg_shm(void *shm_addr,int shm_id)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];

    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    get_res_reg_file_path(file_path,SHM_RES_FILE_NAME,START_MODEL_NAME);       
    if (NULL == (fp = fopen(file_path,"a+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%u",(unsigned long)shm_addr);
    fputs(buf,fp);
    fputc('\n',fp);
    
    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",shm_id);
    fputs(buf,fp);
    fputc('\n',fp);

    fflush(fp);
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
static int mp_reg_shm_key_num(int shm_num)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];
  
    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    get_res_reg_file_path(file_path,SHM_KEY_RES_FILE_NAME,START_MODEL_NAME);               

    if (NULL == (fp = fopen(file_path,"w+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",shm_num);
    fputs(buf,fp);
    fputc('\n',fp);

    fflush(fp);
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
static int mp_reg_shm_key(key_t shm_key)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];

    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    get_res_reg_file_path(file_path,SHM_KEY_RES_FILE_NAME,START_MODEL_NAME);       
    if (NULL == (fp = fopen(file_path,"a+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%u",(unsigned long)shm_key);
    fputs(buf,fp);
    fputc('\n',fp);

    fflush(fp);
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
static void callback_last_res()
{
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];;

    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    get_res_reg_file_path(file_path,SHM_KEY_RES_FILE_NAME,START_MODEL_NAME);          
    if (IS_EXIST == file_is_exist(file_path))
    {
        //INFO("The shm key reg file exist.");
        if (NULL == (fp = fopen(file_path,"r")))
            return;

        (void)callback_last_reg_shm_res(fp);

        fclose(fp);
        unlink(file_path);
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
static void quick_die(int sig_no)
{
    register int i;
    pid_t pid;
    long ret;
    int stat;
	
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];
    int num = 0;

    if ((SIGINT == sig_no) || (SIGKILL == sig_no))
    { 
        memset(file_path,0x00,MAX_FILE_PATH_SIZE);
        for (i = 0;i < g_all_process_num;i++)
        {
            pid = (g_pid_info + i)->pid;
            if (pid <= 0)
            {
                continue;
            }

            num = 0;
            while(num < 2000)
            {
                ret = waitpid(pid,&stat,WNOHANG);
                //printf("pid = %ld,ret = %ld\n",pid,ret);
                if (pid == ret)
                {
                    if (WIFEXITED(stat) > 0)
                        break;

                    break;
                }

                if (-1 == ret)
                    break;

                if (0 == ret)
                    num++;
            }
        }

        //DEL_SYS_MSG_QUE(g_sys_msg_que_id);
        if (g_sys_msg_que_id >= 0)
        {
            //INFO("[Callback resources]msg que id = %d\n",g_sys_msg_que_id);
            if (-1 == delete_sys_msg_que(g_sys_msg_que_id))
                error("[Err]Delete sys msg que fail.\n");
	}
	
        (void)get_res_reg_file_path(file_path,MEM_RES_FILE_NAME,START_MODEL_NAME);       
       // info("[Callback resources]mem reg file path = %s\n",file_path); /*会重入*/
        unlink(file_path);

        get_res_reg_file_path(file_path,SHM_RES_FILE_NAME,START_MODEL_NAME);       
       // info("[Callback resources]shm reg file path = %s\n",file_path);
		
        if (NULL == (fp = fopen(file_path,"r")))
            exit(EXIT_SUCCESS);;

        if (ERR == callback_reg_shm_res(fp))
        {
            error("[Err]Callback Shm res fail.\n");
        }

        fclose(fp);
        unlink(file_path);

        unlink(s_pid_file);

        if (SAIL_TRUE == dir_is_empty(RES_REG_DIR))
        {
            del_dir_and_file(RES_REG_DIR);
        }

        if (IS_EXIST == file_is_exist(EAUDIT_LOCK_FILE))
        {
            unlink(EAUDIT_LOCK_FILE);
        }

       // INFO("Callback eAudit ctl process resources OK.\n"); 
        exit(EXIT_SUCCESS);
    }
}

static void ResBack_ConnectServer(int sig_no){
	if(SIGCONT ==sig_no){
		unlink("/var/lib/eAudit/data/CONNECT_SERVER.pid");
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
static void die(int sig_no)
{
    register int i;
    pid_t pid;
    int stat;
    long ret;

    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];
    int num = 0;

    if (SIGTERM == sig_no)
    {
       // info("*******************************\n");
        //info("RES Callback\n");
       // info("*******************************\n");
       unlink("/var/lib/eAudit/data/CONNECT_SERVER.pid");
        memset(file_path,0x00,MAX_FILE_PATH_SIZE);
        for (i = 0;i < g_all_process_num;i++)
        {
            pid = (g_pid_info + i)->pid;
            if (pid <= 0)
                continue;

            num = 0;
            while(num < 2000)
            {
                ret = waitpid(pid,&stat,WNOHANG);
                if (pid == ret)
                {
                    if (WIFEXITED(stat) > 0)
                        break;

                    break;
                }

                if (0 == ret)
                    num++;

                if (-1 == waitpid(pid,&stat,WNOHANG))
                    break;
            }
        }
        
       // info("**Child Res Callback Ok.\n");
        if (g_sys_msg_que_id >= 0)
        {
            //INFO("msg que id = %d\n",g_sys_msg_que_id);
            //DEL_SYS_MSG_QUE(g_sys_msg_que_id);
            if (-1 == delete_sys_msg_que(g_sys_msg_que_id))
                error("[Err]Delete sys msg que fail.\n");
            //INFO("Delete sys msg que OK!");
        }

        (void)get_res_reg_file_path(file_path,MEM_RES_FILE_NAME,START_MODEL_NAME);       
       // info("mem reg file path = %s\n",file_path); /*会重入*/
        unlink(file_path);

        get_res_reg_file_path(file_path,SHM_RES_FILE_NAME,START_MODEL_NAME);       
        //info("shm reg file path = %s\n",file_path);/*会重入*/
		
        if (NULL == (fp = fopen(file_path,"r")))
            exit(EXIT_SUCCESS);;

        if (ERR == callback_reg_shm_res(fp))
        {
            error("[Err]Callback Shm res fail.\n");
        }

        fclose(fp);
        unlink(file_path);

        unlink(s_pid_file);
       

        if (SAIL_TRUE == dir_is_empty(RES_REG_DIR))
        {
            INFO("Delete res reg dir OK.\n");
            del_dir_and_file(RES_REG_DIR);
        }

        if (IS_EXIST == file_is_exist(EAUDIT_LOCK_FILE))
        {
            INFO("Delete lock file OK.\n");
            unlink(EAUDIT_LOCK_FILE);
        }

       // INFO("Callback eAudit ctl process resources OK.\n");
    //    exit(EXIT_SUCCESS);
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
static void die1(int sig_no)
{
    register int i;
    pid_t pid;
    int stat;
    long ret;

    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];
    int num = 0;

    if (SIGTERM == sig_no)
    {
       // info("*******************************\n");
        //info("RES Callback\n");
       // info("*******************************\n");
      
        memset(file_path,0x00,MAX_FILE_PATH_SIZE);
        for (i = 0;i < g_all_process_num;i++)
        {
            pid = (g_pid_info + i)->pid;
            if (pid <= 0)
                continue;

            num = 0;
            while(num < 2000)
            {
                ret = waitpid(pid,&stat,WNOHANG);
                if (pid == ret)
                {
                    if (WIFEXITED(stat) > 0)
                        break;

                    break;
                }

                if (0 == ret)
                    num++;

                if (-1 == waitpid(pid,&stat,WNOHANG))
                    break;
            }
        }
        
       // info("**Child Res Callback Ok.\n");
        if (g_sys_msg_que_id >= 0)
        {
            //INFO("msg que id = %d\n",g_sys_msg_que_id);
            //DEL_SYS_MSG_QUE(g_sys_msg_que_id);
            if (-1 == delete_sys_msg_que(g_sys_msg_que_id))
                error("[Err]Delete sys msg que fail.\n");
            //INFO("Delete sys msg que OK!");
        }

        (void)get_res_reg_file_path(file_path,MEM_RES_FILE_NAME,START_MODEL_NAME);       
       // info("mem reg file path = %s\n",file_path); /*会重入*/
        unlink(file_path);

        get_res_reg_file_path(file_path,SHM_RES_FILE_NAME,START_MODEL_NAME);       
        //info("shm reg file path = %s\n",file_path);/*会重入*/
		
        if (NULL == (fp = fopen(file_path,"r")))
            exit(EXIT_SUCCESS);;

        if (ERR == callback_reg_shm_res(fp))
        {
            error("[Err]Callback Shm res fail.\n");
        }

        fclose(fp);
        unlink(file_path);

        unlink(s_pid_file);
       

        if (SAIL_TRUE == dir_is_empty(RES_REG_DIR))
        {
            INFO("Delete res reg dir OK.\n");
            del_dir_and_file(RES_REG_DIR);
        }

        if (IS_EXIST == file_is_exist(EAUDIT_LOCK_FILE))
        {
            INFO("Delete lock file OK.\n");
            unlink(EAUDIT_LOCK_FILE);
        }

       // INFO("Callback eAudit ctl process resources OK.\n");
    //    exit(EXIT_SUCCESS);
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
static void print_que_info(QUE_ID que_id,int nic_num,int que_num)
{
    register int i;
    register int j;

    for (i = 0;i < nic_num;i++)
    {
        for(j = 0;j < que_num;j++)
        {
            printf("blk num[%d] = %d\n",i*que_num+j,(que_id+i*nic_num+j)->iQueBlkNum);
            printf("blk size[%d] = %d\n",i*que_num+j,(que_id+i*nic_num+j)->iQueBlkSize); 
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
static void swait_child_process()
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
static void print_proc_stop_info(const char *format,...)
{
    char buf[1024];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, 1024, format, args);
    va_end(args);

    fprintf(stderr, "Info: %s [Stop].\n", buf);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void get_proc_name_by_type(int type,char *proc_name)
{
    strcpy(proc_name,STR(NO_PROCESS));
	
    switch(type)
    {
        case NO_PROCESS:  
            break;
	    case CTL_PROCESS:
	        strcpy(proc_name,STR(CTL_PROCESS));
	        break;
	    case NET_DAEMON_PROCESS:
	        strcpy(proc_name,STR(NET_DAEMON_PROCESS));
	        break;
	    case CAPTURE_CHILD_PROCESS:
	        strcpy(proc_name,STR(CAPTURE_CHILD_PROCESS));		 
	        break;
	    case FILTER_CHILD_PROCESS:
	        strcpy(proc_name,STR(FILTER_CHILD_PROCESS));
	        break;
	    case ANALYZE_CHILD_PROCESS:
	        strcpy(proc_name,STR(ANALYZE_CHILD_PROCESS));
	        break;
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
static int open_dir_set_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        DEBUG("dir set  file not exist.");
        return(CTL_FILE_NOT_EXIST);
    }

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        DEBUG("open dir set  file Fail.");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        DEBUG("dir set  file size is 0.");
        close(fd);
        return(CTL_FILE_IS_NULL);
    }

    *fd_ptr = fd;
    *file_size_ptr = file_size;
	
    return(SAIL_OK); 
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
#if 0
static int reg_pid_to_shm(PID_INFO_ID pid_info_id,int idx,long pid,int pid_type)
{
    register int i = idx;

    (pid_info_id + i)->pid = (long)pid;
    (pid_info_id + i)->pid_type = pid_type;

    return OK;
}
#endif

static int reg_pid_to_shm(PID_INFO_ID pid_info_id,int idx,long pid,char *path,char *par)
{
    register int i = idx;
    if(path ==NULL||pid_info_id ==NULL)
		return ERR;
    (pid_info_id + i)->pid = (long)pid;
    strcpy((pid_info_id + i)->exec_path,path);
    if(par ==NULL)
		 (pid_info_id + i)->para_flag = 0;
    else {
	 	 (pid_info_id + i)->para_flag = 1;
		  strcpy((pid_info_id + i)->parameter,par);
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

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int pipe_write_key_to_net(key_t pid_info_key,int pipe_fd)
{
    int len;
    char buf[64];
    long key = (long)pid_info_key;
    unsigned char hdr[4];

    sprintf(buf,"%ld",key);
    len = strlen(buf);
    hdr[0] = PIPE_PID_KEY_INFO;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >> 8) & 0xFF;
    hdr[3] = (len >> 0) & 0xFF;

    if (-1 == write(pipe_fd,hdr,sizeof hdr))
        return ERR;

    if (-1 == write(pipe_fd,buf,len))
        return ERR;

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
#ifdef RUN_WITH_DAEMON_MODEL
static void init_daemon(void)
{
    int i;
    pid_t pid = DEF_PID_VAL;
 
    if (pid == fork())
        exit(0);
    else if(pid< 0)
        exit(1);

    setsid();

    if (pid == fork())
        exit(0);
    else if(pid< 0)
        exit(1);

    for(i=0;i< NOFILE;++i)
        close(i);

    chdir("/tmp");
    umask(0);

    return;
}
#endif

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
static void Stop_eAudit(){
        //printf("eAudit OVER ########################################################\n");
	g_Exit_eAudit_flag=1;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static char *get_progname(const char *argv0)
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
static void report_err_to_net(int sock_fd,char *wk_info_file)
{
#ifdef INC_NET_REPOERT_MODEL
    char report_buf[MAX_REPORT_MSG_SIZE+1];

    if (-1 == sock_fd)
    {
        sock_fd = monitor_acting_client();
        if (-1 == sock_fd)
        {
            (void)record_sys_work_info(wk_info_file,"Connect to monitor sever fail.",\
                                                          RECORD_INC_TIME); 
            return;
        }
    }

    ++g_us_err_no;
    sprintf(report_buf,"%d%ld",RPT_ERR_MSG,g_us_err_no);
	
    if (ERR == skt_send(sock_fd,report_buf,strlen(report_buf)))
    {
        close(sock_fd);
        (void)record_sys_work_info(wk_info_file,"Cnnect to monitor sever fail.",\
                                                          RECORD_INC_TIME); 
        return;
    }

    if (sock_fd > 0)
        close(sock_fd);
#endif

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
static void rm_file(char *path)
{
    int flag = NOT_EXIST;

    flag = file_is_exist(path);   
    if (IS_EXIST == flag)
        unlink(path);

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
static void rm_res_reg_file(void)
{
    char file_path[MAX_FILE_PATH_SIZE];

    (void)get_res_reg_file_path(file_path,MEM_RES_FILE_NAME,START_MODEL_NAME);
    rm_file(file_path);
    (void)get_res_reg_file_path(file_path,SHM_RES_FILE_NAME,START_MODEL_NAME);
    rm_file(file_path);
    (void)get_res_reg_file_path(file_path,SEM_RES_FILE_NAME,START_MODEL_NAME);
    rm_file(file_path);
    (void)get_res_reg_file_path(file_path,FILE_RES_FILE_NAME,START_MODEL_NAME);
    rm_file(file_path);
    (void)get_res_reg_file_path(file_path,ALL_RES_FILE_NAME,START_MODEL_NAME);
    rm_file(file_path);

    (void)get_res_reg_file_path(file_path,SHM_KEY_RES_FILE_NAME,START_MODEL_NAME);
    rm_file(file_path);

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
static int wait_child_process(PID_INFO_ID pid_info_id)
{
    register int i;
    int status = 0;
    char proc_name[MAX_PROC_NAME_SIZE+1];
    int end_proc_num = 0;
    pid_t ret_pid = DEF_PID_VAL;
    char log_cnt[MAX_LOG_CNT_SIZE + 1];
 
    errno = 0;

    waitpid(-1,NULL,0);
    return OK;

#if 0
    for(i = 0;i < g_all_process_num;i++)
    {
       // printf("###pid = %ld\n",(pid_info_id+i)->pid);
        if ((pid_info_id+i)->pid <= 0)
            continue;

        ret_pid = waitpid((pid_info_id+i)->pid,&status,0);
        if (ret_pid == (pid_info_id+i)->pid)
        {
            ++end_proc_num;
            memset(log_cnt,0x00,MAX_LOG_CNT_SIZE + 1);
            memset(proc_name,0x00,MAX_PROC_NAME_SIZE + 1);
            get_proc_name_by_type((pid_info_id+i)->pid_type,proc_name);
	
           // printf("##Status = %d\n",status);				
            if (WIFEXITED(status))
            {
                sprintf(log_cnt,"[%s] %s",proc_name,"process end Ok");
            }
            else
            {
                sprintf(log_cnt,"[%s] %s",proc_name,"process end Err");
            }
					
            print_proc_stop_info("%s",log_cnt);
            //write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,MULTITASK,log_cnt);
        }

        if (-1 == ret_pid)
        {
            if (errno == ECHILD)
            {
                end_proc_num++;
                error("Child Process has already quitted.\n");
            }

            if (errno == EINTR)
                error("WNOHANG don't be set.\n");

            if (errno == EINVAL)
                error("Option error.");

            error("[Err]Waitpid Error.\n");
            return OK;
        }

        if (end_proc_num == g_all_process_num)
            return OK;   
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
static void sys_help(void)
{
    printf(_("********************************\n"));
    printf(_("*eAudit System help information*\n"));
    printf(_("********************************\n"));

    printf(_("***************************************\n"));
    printf(_("*1:eAudit System configure information*\n"));
    printf(_("***************************************\n"));

    printf(_("(1)support protocoles file dir:%s\n"),SUPPORT_PRO_DIR_PATH);
    printf(_("(2)support protocoles file name:%s\n"),SUPPORT_PRO_FILE_NAME);
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
static void sys_stop(char *argv0)
{
    FILE *fp = NULL;
    long pid;
    char *progname;
    char pid_file[MAX_FILE_PATH_SIZE];

    progname = get_progname(argv0);
    snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,progname);
   
    if (NOT_EXIST == file_is_exist(pid_file)) 
    {
        INFO("The eAudit not start up.\n");
        return;
    }

    fp = fopen(pid_file,"rb");
    if (NULL == fp)
    {
        warning("fopen pid file fail.\n");
        return;
    }

    while(0 == feof(fp))
    {
         fscanf(fp, "%ld", &pid); 
         if (kill((pid_t)pid, s_stop_signo) != 0)
	 {
            warning(_("%s: could not send stop signal (PID: %ld),maybe stoped.\n"), progname, pid);
	     continue;    //add 2009 07 30
         }
#if 0
	usleep(10);
	/*add 2009 07 30 解决不能杀CAPTURE进程*/
	while (kill((pid_t)pid, SIGNAL_ZERO) == SIGNAL_ZERO){
		
		printf("没有杀死CAPTURE ,进入第二次杀\n");
		usleep(10);
		kill((pid_t)pid, s_stop_signo);
	}
#endif
    }

    fclose(fp);
    FREE(progname);
    unlink(pid_file);
   // snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,"EAUDIT");
  //  unlink(pid_file);
}
/***get eAudit  pid *********************************************/
static long  Read_eAudit_Pid()
{
    FILE *fp = NULL;
    long pid;
    char pid_file[MAX_FILE_PATH_SIZE];

     snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,"EAUDIT");
   
    if (NOT_EXIST == file_is_exist(pid_file)) 
    {
        INFO("The eAudit not start up.\n");
        return 0;
    }

    fp = fopen(pid_file,"rb");
    if (NULL == fp)
    {
        warning("fopen pid file fail.\n");
        return 0;
    }

    while(0 == feof(fp))
    {
         fscanf(fp, "%ld", &pid);
         break;
    }

    fclose(fp);
    unlink(pid_file);
    return pid;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
/*
static void sys_status(char *argv0)
{
    FILE *fp = NULL;
    long pid;
    char *progname;
    char pid_file[MAX_FILE_PATH_SIZE];

    progname = get_progname(argv0);
    snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,progname);
    if (NOT_EXIST == file_is_exist(pid_file)) 
    {
        INFO("The eAudit not start up.\n");
        return;
    }

    fp = fopen(pid_file,"rb");
    if (NULL == fp)
    {
        warning("fopen pid file fail.\n");
        return;
    }

    while(0 == feof(fp))
    {
         fscanf(fp, "%ld", &pid);
         if (kill((pid_t)pid, 0) != 0)
	 {
            warning(_("%ld: process stoped.\n"), pid);
	 }
    }

    fclose(fp);
    FREE(progname);
}
*/
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
static int make_res_dir()
{
    char pro_dir[MAX_DIR_SIZE + 1];

    if (ERR == make_dir(RES_REG_DIR,S_IRWXU))
        return ERR; 

    memset(pro_dir,0x00,MAX_DIR_SIZE+1);
    sprintf(pro_dir,"%s/%s",RES_REG_DIR,START_MODEL_NAME);
    if (ERR == make_dir(RES_REG_DIR,S_IRWXU))
        return ERR;

    memset(pro_dir,0x00,MAX_DIR_SIZE+1);
    sprintf(pro_dir,"%s/%s",RES_REG_DIR,CAPTURE_MODEL_NAME);
    if (ERR == make_dir(RES_REG_DIR,S_IRWXU))
        return ERR;

    memset(pro_dir,0x00,MAX_DIR_SIZE+1);
    sprintf(pro_dir,"%s/%s",RES_REG_DIR,FILTER_MODEL_NAME);
    if (ERR == make_dir(RES_REG_DIR,S_IRWXU))
        return ERR;

    memset(pro_dir,0x00,MAX_DIR_SIZE+1);
    sprintf(pro_dir,"%s/%s",RES_REG_DIR,ANALYZE_MODEL_NAME);
    if (ERR == make_dir(RES_REG_DIR,S_IRWXU))
        return ERR;

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
static int create_redirect_port_shm_mem(int *shm_list_id,key_t *shm_list_key,unsigned long *num)
{
    int shm_id;
    unsigned long shm_size;
    g_max_shm_key += SHM_KEY_IVL;
    shm_size = REDIRECTION_PORT_INFO_SIZE*(*num);
    //printf("UUUUUUUUUUU   key = %ld\n",g_max_shm_key);
    shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shm_id < 0)
    {
    		shm_id = get_shm(g_max_shm_key);
		if(shm_id<0){
			 error("create create_redirect_port_shm_memshm fail.");
        		return ERR;
		}
		DEL_SHM(shm_id);
	       shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
	       if(shm_id <0){
		   	   error("create create_redirect_port_shm_mem list shm fail.");
        		return ERR;
	       }
       
    }
    *shm_list_key = g_max_shm_key;
    // printf("redirect port shm mem key = %u \n",g_max_shm_key);
    *shm_list_id = shm_id;
    return OK;
}
/*2009 06 09 add eAudit authorize manage tool*/
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int Create_File(char **argv,char *wk_info_file){
       int log_pri = LOG_DEBUG;	 
    	 int log_filter_mode = LOG_NOT_FILTER;
    	 int log_tool = LOG_TOOL;
    g_progname = get_progname(argv[0]);
    make_res_dir();
    if (ERR == make_sys_dir(SYS_CFG_SET_PATH))
    {
        error("[Err]Make system config data dir fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make system config data dir fail!");
        return ERR;
    }
 //   DEBUG("make the sys cfg path for save pid etc ok!");
   /*add 2008/07/29*/
    snprintf(s_pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,"EAUDIT");
    if (ERR == create_pid_file(s_pid_file))
    {
        error("[Err]Create SNAM CTL system pid file fail.\n");
        FREE(g_progname);
	 return ERR;
    }   

    if (ERR == reg_pid_to_file(getpid()))
    {
        error("[Err]Reg SNAM CTL process info to pid file fail.\n");
        FREE(g_progname);
        return ERR;
    }
  //  printf("create eAudit pid file ok\n");
  /*add 2008/07/29*/
    /*make the work err risk too small*/
    /*6:make the sys run info dir*/
    if (ERR == make_dir(SYS_WORK_INFO_DIR_PATH,S_IRWXU))
    {
        error("[Err]Create sys main process run info dir fail.\n");
        FREE(g_progname);
        return ERR;
    }  
  //  printf("make the sys run info dir ok\n");
    /*7:make the sys run info file*/
   
    if (ERR == create_sys_work_info_file(wk_info_file))
    {
        error("[Err]Create sys main process run info file fail.\n");
	 FREE(g_progname);
        return ERR;
    }
    (void)record_sys_work_info(wk_info_file,"Create sys main process run info file OK.",RECORD_INC_TIME);   
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
static int Judge_Mutex_Run(char **argv){
/*1:the system user is root*/
        if (getuid() != 0)
        {
            error("[Err]You must be root user to run the system.\n");
            return ERR;
        }

        /*2:make sure that real and effective uids are the same*/
        if (getuid() != geteuid())
        {
            error("%s: real and effective user IDs must equal\n",argv[0]);
            return ERR;
        }

        /*3:make the proccess only run one times*/
        proc_is_run(WITH_FILE_LOCK,EAUDIT_LOCK_FILE);
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
static void Stop_Process_Restart(char **argv){
	pid_t pid =-1;
 	/*the system user is root*/
       if (getuid() != 0)
       {
                error("[Err]You must be root user to run the system.\n");
                exit(EXIT_FAILURE);
        }
        sys_stop(argv[0]);
	 pid =Read_eAudit_Pid();
        if(pid!=0)
	    kill((pid_t)pid,SIG_STOP_SNAM_MSG);
	 sleep(15);
	 pid = fork();
    	 switch (pid){
        	case -1:
            		warning("[Err]Create eAudit processes fail.\n");
            	break;
        	case 0:
           		 //DEBUG("Start eAudit processes");
            		execl("/bin/sh", "sh", "-c","/eAudit/bin/eAudit", (char *)0);
            		error("[Err]Start eAudit processes Fail.\n");
            		exit(EXIT_FAILURE);
            		break;
        	default:
            	break;
   	}
       usleep(100);
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void Stop_Process(char **argv){
	pid_t pid=-1;
	/*the system user is root*/
       if (getuid() != 0)	
       {
                error("[Err]You must be root user to run the system.\n");
                exit(EXIT_FAILURE);
       }
	sys_stop(argv[0]);
	pid =Read_eAudit_Pid();
       if(pid!=0)
              kill((pid_t)pid,SIG_STOP_SNAM_MSG);   
}
/**********************************
*func name:read eAudit_sys.conf 
*function:
*parameters:
*call:
*called:
*return:
*/
static int ReadeAuditSysConf(int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,EAUDIT_SYS_CONF *eAuditSysConf){
	char file_name[MAX_FILE_PATH_SIZE];
	int cfg_mode,fd,file_size;
       char *file_cnt_buf=NULL;
       int log_pri = LOG_DEBUG;	 
    	 int log_filter_mode = LOG_NOT_FILTER;
    	 int log_tool = LOG_TOOL,i;
	char tmpchar[256];
	
    	if (ERR == chk_cfg_dir(CFG_DIR_PATH))
    	{
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Sys config dir err!\n");
        	return ERR;
    	}
    	//DEBUG("Check cfg dir OK.");

    	/*read eAudit sys cfg file*/
    	memset(file_name,0x00,MAX_FILE_PATH_SIZE);
    	sprintf(file_name,"%s/%s",CFG_DIR_PATH,SYS_CFG_FILE_NAME);
    	cfg_mode = get_read_cfg_mode(file_name,&fd,&file_size);
	memset(&(eAuditSysConf->PacketsFilesDir),0,256);
	/*1 read pkt data dir and protect rules dir */
    	switch (cfg_mode)
    	{
        	case READ_FILE:
            		file_cnt_buf = (char *)malloc(file_size + 1);
            		if (NULL == file_cnt_buf)
            		{
                		error("[Err]Malloc for sys cfg file fail!\n");
                		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Malloc for sys cfg file fail.");
                		return ERR;
            		}

            		if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
	     		{
	         		error("[Err]Get sys cfg file content fail!\n");
	         		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get sys cfg file content fail!");
		  		return ERR;
	     		}
	     		file_cnt_buf[file_size] = '\0';
            		CLOSE_FILE(fd);

            		if (ERR == get_sys_dir_by_file(eAuditSysConf->PacketsFilesDir,eAuditSysConf->ProtectRulesFileDir,file_cnt_buf))
            		{
                		error("[Err]Get sys dir info err.\n");
                		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get sys dir info err.");
                		return ERR;
            		}
			//DEBUG("PKT DATA DIR = %s protect rule dir = %s ",eAuditSysConf->PacketsFilesDir,eAuditSysConf->ProtectRulesFileDir);		
            		break;			
        	case DEF_MODE:
        	default:		 
            		get_sys_dir_by_def(eAuditSysConf->PacketsFilesDir,eAuditSysConf->ProtectRulesFileDir);
	     		break;
    }
   for(i=1;i<3;i++){     //add 2010 4 14 
   	 sprintf(tmpchar,"%s%d",eAuditSysConf->PacketsFilesDir,i);
    /*make the packets files dir*/
    	//if (ERR == make_sys_dir(eAuditSysConf->PacketsFilesDir))
    	if (ERR == make_sys_dir(tmpchar))
    {
        error("[Err]Make packets files dir fail.\n");  
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make packets files dir fail!\n");
	 return ERR;
    }
   } //add 2010 4 14 
    //DEBUG("Make pkt files dir OK.");

    /*:get packets files dir HDD info*/
    if (ERR == get_sys_fs_info(&(g_sys_hw_info.fs_info),eAuditSysConf->PacketsFilesDir))
    {
        error("[Err]Get system packets file sys info fail.\n");
	 write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get system packets file sys info fail!\n");
	 return ERR;
    }
   for(i=1;i<3;i++){     //add 2010 4 14 
   	 sprintf(tmpchar,"%s%d",eAuditSysConf->PacketsFilesDir,i);
    /*:make the protocol pkt file dir*/
    if (ERR == make_protocol_pkt_dir(pro_num,pro_items_id,tmpchar))
    {
        error("[Err]Make protocols packets files dir fail.\n");
	 write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make protocol packets files dir fail!\n");
        return ERR;
    }
   	}
   // DEBUG("Make protocols packets files Dir OK.");
     if (ERR == make_sys_dir(SNAM_DATA_DIR))
    {
        error("[Err]Make pro data  dir fail.\n");  
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make pro data  dir fail!\n");
	 return ERR;
    }
    if (ERR == make_protocol_data_dir(pro_num,pro_items_id,SNAM_DATA_DIR))
    {
        error("[Err]Make protocols data files dir fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make protocol data files dir fail!\n");
        return ERR;
    }
   //DEBUG("Make protocols data files Dir OK.");

    /*23:create per protocols read and write no file*/	
   for(i=1;i<3;i++){
   	 sprintf(tmpchar,"%s%d",eAuditSysConf->PacketsFilesDir,i);
    if (ERR == create_file_no_file(PKT_WR_NO_FILE_NAME,pro_items_id,tmpchar,pro_num))
    {
        error("[Err]Create file write no file fail!\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"CREATE file write no file fail!");
        return ERR;
    }

    if (ERR == create_file_no_file(PKT_RD_NO_FILE_NAME,pro_items_id,tmpchar,pro_num))
    {
        error("[Err]Create file read no file fail!\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"CREATE file read no file fail!");
        return ERR;
    }
   	}
    //DEBUG("Create write and read file no file OK.");
	
    if(ERR ==  make_protocol_log_dir(pro_num,pro_items_id,LOG_DIR_PATH)){
	error("[Err]Make protocols log dir fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make protocol log dir fail!\n");
        return ERR;
    }
   //DEBUG("make protocol log dir ok\n");
   

    /*2:get management NIC name*/
    memset(&(eAuditSysConf->NicForManagement),0,16);
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_manage_nic_name(eAuditSysConf->NicForManagement,file_cnt_buf))
            {
                error("[Err]Get management NIC name fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get management NIC name fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            strcpy(&(eAuditSysConf->NicForManagement),DEF_MAN_NIC_NAME);
	     break;
    }
    
    //DEBUG("Begin Check management NIC Name.");
     /*:check management NIC name*/
    if (ERR == check_manage_nic(eAuditSysConf->NicForManagement))
    {
        error("[Err]The management NIC err.\n");
	 write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"The management NIC err!\n");
	 return ERR;
    }
  //  DEBUG("End Check management NIC Name.");
    
    /*3 :get deposit interval seconds*/
	
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_deposit_ivl_sec(&eAuditSysConf->DepositIntervalSeconds,file_cnt_buf))
            {
                error("[Err]The deposit interval seconds set err.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"The Deposit interval seconds set err!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->DepositIntervalSeconds = DEF_DEPOSIT_IVL_SEC;
	     break;
    }
   // DEBUG("DepositIntervalSeconds = %d",eAuditSysConf->DepositIntervalSeconds);
      /*4 :get monitor interval seconds*/
	
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_monitor_ivl_sec(&eAuditSysConf->MonitorTimeIntervals,file_cnt_buf))
            {
                error("[Err]The monitor interval seconds set err.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"The monitor interval seconds set err!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->MonitorTimeIntervals = DEF_MONITOR_IVL_SEC;
	     break;
    }
    //DEBUG("MonitorTimeIntervals = %d ",eAuditSysConf->MonitorTimeIntervals);

    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_monitor_num(&eAuditSysConf->MonitorNum,file_cnt_buf))
            {
                error("[Err]The monitor interval seconds set err.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"The monitor interval seconds set err!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->MonitorNum= DEF_MONITOR_NUM;
	     break;
    }
    //DEBUG("monitor num = %d\n",eAuditSysConf->MonitorNum);
    
     /*5 :get_dynamic_protect_resource_num*/
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dynamic_protect_resource_num(&eAuditSysConf->DynamicProtectResNum,file_cnt_buf))
            {
                error("[Err]get_dynamic_protect_resource_num set err.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get_dynamic_protect_resource_num set err!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->DynamicProtectResNum = DEF_DYNAMIC_PROTECT_RESOURCE_NUM;
	     break;
    }
   /*get block queque num config value*/
  // DEBUG("DynamicProtectResNum = %d ",eAuditSysConf->DynamicProtectResNum);
     /*6 :get block para set info */
	
     switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_block_queque_conf_num((BLOCK_QUEQUE_NUM_ID)&(eAuditSysConf->BlockInfo),file_cnt_buf))
            {
                error("[Err]get_block_queque_conf_num set err.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get_block_queque_conf_num set err!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:	
	   	eAuditSysConf->BlockInfo.fst_block_queque_num= DEF_MAX_FST_BLOCK_QUEQUE_NUM;
	   	eAuditSysConf->BlockInfo.snd_block_queque_num=DEF_MAX_SND_BLOCK_QUEQUE_NUM;
		eAuditSysConf->BlockInfo.block_ip_queque_num= DEF_MAX_BLOCK_IP_QUEQUE_NUM;
		eAuditSysConf->BlockInfo.snd_check_block_queque_num=DEF_MAX_SND_CHECK_BLOCK_QUEQUE_NUM;
	     	break;
     	}
     
    /*7:get packets files set config info*/
	
    memset(&(eAuditSysConf->cfg_file_set),0x00,CFG_FILE_SET_SIZE);
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_file_set_by_file(&(eAuditSysConf->cfg_file_set),file_cnt_buf))
            {
                error("[Err]Get packets file pool set err.\n");
                write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get packets file pool set err!");
                return ERR;
            }
            break;
        case DEF_MODE:
        default:
            get_file_set_by_def(&(eAuditSysConf->cfg_file_set));
            break;
    }

    /*8:get function switch*/
    memset(&(eAuditSysConf->func_switch),0x00,FUNC_SWITCH_SIZE);
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_func_switch_by_file(&(eAuditSysConf->func_switch),file_cnt_buf))
            {
                error("[Err]Get function switch set fail.\n");
                write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get function switch set fail!");
                return ERR;
            }
            break;
        case DEF_MODE:
        default:
            get_func_switch_by_def(&(eAuditSysConf->func_switch));
            break;
    }

    /*9 get flow stat switch*/
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_flow_switch_by_file(&(eAuditSysConf->FlowSwitch),file_cnt_buf))
            {
                error("[Err]Get flow stat switch set fail.\n");
                write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get flow stat switch set fail!");
                return ERR;
            }
            break;
        case DEF_MODE:
        default:
            get_flow_switch_by_def(&(eAuditSysConf->FlowSwitch));
            break;
    }

    if (ON == eAuditSysConf->func_switch.iStatSwitch)
    {
        if (ERR == make_dir(PKT_STAT_FILE_DIR,S_IRWXU))
        {
            error("[Err]Make packets stat dir fail.\n");	   
	     write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make packets stat dir fail.");
            return ERR;
        }
    }
 /*10 get MAX PROTECT RULE NUM*/

    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_rulenum_set_by_file(&eAuditSysConf->MaxProtectRulesNum,file_cnt_buf))
            {
                error("[Err]Get rule num fail.\n");
                write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get rule num fail!");
                return ERR;
            }
            break;
        case DEF_MODE:
        default:
            get_rulenum_set_by_def(&eAuditSysConf->MaxProtectRulesNum);
            break;
    }
   //DEBUG("MaxProtectNum = %d ",eAuditSysConf->MaxProtectRulesNum);
   /*11*/
   
   /*2:get DcAuthServIp */
    memset(&(eAuditSysConf->DcAuthServIp),0,20);
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_serv_ip(eAuditSysConf->DcAuthServIp,file_cnt_buf))
            {
                error("[Err]Get DcAuthServIp fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get DcAuthServIp name fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            strcpy(&(eAuditSysConf->DcAuthServIp),DEF_DC_SERV_IP);
	     break;
    }
   // printf("DcAuthServIp = %s \n",eAuditSysConf->DcAuthServIp);
	
 /*12*/
   /*2:get DcAuthServPort*/
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_serv_port(&eAuditSysConf->DcAuthServPort,file_cnt_buf))
            {
                error("[Err]GetDcAuthServPort fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"DcAuthServPort fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->DcAuthServPort = DEF_DC_SERV_PORT;
	     break;
    }
    /*13:get Dcwork mode*/
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_work_mode(&eAuditSysConf->work_mode,file_cnt_buf))
            {
                error("[Err]get WORK_MODE  fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get WORK_MODE  fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->work_mode = DEF_WORK_MODE;
	     break;
    }
   FREE(file_cnt_buf);
   return OK;
}
/**********************************
*func name:read eAudit_sys.conf 
*function:
*parameters:
*call:
*called:
*return:
*/
static int ReadeAuditSysConfForeAudit(EAUDIT_SYS_CONF *eAuditSysConf){
	char file_name[MAX_FILE_PATH_SIZE];
	int cfg_mode,fd,file_size;
       char *file_cnt_buf=NULL;
       int log_pri = LOG_DEBUG;	 
    	 int log_filter_mode = LOG_NOT_FILTER;
    	 int log_tool = LOG_TOOL;
	
    	if (ERR == chk_cfg_dir(CFG_DIR_PATH))
    	{
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Sys config dir err!\n");
        	return ERR;
    	}
    
    	/*read eAudit sys cfg file*/
    	memset(file_name,0x00,MAX_FILE_PATH_SIZE);
    	sprintf(file_name,"%s/%s",CFG_DIR_PATH,SYS_CFG_FILE_NAME);
    	cfg_mode = get_read_cfg_mode(file_name,&fd,&file_size);
	/*1 read pkt data dir and protect rules dir */
    	switch (cfg_mode)
    	{
        	case READ_FILE:
            		file_cnt_buf = (char *)malloc(file_size + 1);
            		if (NULL == file_cnt_buf)
            		{
                		error("[Err]Malloc for sys cfg file fail!\n");
                		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Malloc for sys cfg file fail.");
                		return ERR;
            		}

            		if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
	     		{
	         		error("[Err]Get sys cfg file content fail!\n");
	         		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get sys cfg file content fail!");
		  		return ERR;
	     		}
	     		file_cnt_buf[file_size] = '\0';
            		CLOSE_FILE(fd);		
            		break;			
        	default:		 
	     		break;
    }
    /*2:get management NIC name*/
    memset(&(eAuditSysConf->NicForManagement),0,16);
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_manage_nic_name(eAuditSysConf->NicForManagement,file_cnt_buf))
            {
                error("[Err]Get management NIC name fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get management NIC name fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            strcpy(&(eAuditSysConf->NicForManagement),DEF_MAN_NIC_NAME);
	     break;
    }
    
   // DEBUG("Begin Check management NIC Name.");
     /*:check management NIC name*/
    if (ERR == check_manage_nic(eAuditSysConf->NicForManagement))
    {
        error("[Err]The management NIC err.\n");
	 write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"The management NIC err!\n");
	 return ERR;
    }
  //  DEBUG("End Check management NIC Name.");
    
    /*3 :get deposit interval seconds*/
	
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_deposit_ivl_sec(&eAuditSysConf->DepositIntervalSeconds,file_cnt_buf))
            {
                error("[Err]The deposit interval seconds set err.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"The Deposit interval seconds set err!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->DepositIntervalSeconds = DEF_DEPOSIT_IVL_SEC;
	     break;
    }
    //DEBUG("DepositIntervalSeconds = %d",eAuditSysConf->DepositIntervalSeconds);
      /*4 :get monitor interval seconds*/
	
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_monitor_ivl_sec(&eAuditSysConf->MonitorTimeIntervals,file_cnt_buf))
            {
                error("[Err]The monitor interval seconds set err.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"The monitor interval seconds set err!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->MonitorTimeIntervals = DEF_MONITOR_IVL_SEC;
	     break;
    }
	
  //  DEBUG("MonitorTimeIntervals = %d ",eAuditSysConf->MonitorTimeIntervals);

    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_monitor_num(&eAuditSysConf->MonitorNum,file_cnt_buf))
            {
                error("[Err]The monitor interval seconds set err.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"The monitor interval seconds set err!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->MonitorNum= DEF_MONITOR_NUM;
	     break;
    }
   // DEBUG("monitor num = %d\n",eAuditSysConf->MonitorNum);
    
   
   /*2:get DcAuthServIp */
    memset(&(eAuditSysConf->DcAuthServIp),0,20);
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_serv_ip(eAuditSysConf->DcAuthServIp,file_cnt_buf))
            {
                error("[Err]Get DcAuthServIp fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get DcAuthServIp name fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            strcpy(&(eAuditSysConf->DcAuthServIp),DEF_DC_SERV_IP);
	     break;
    }
  //  printf("DcAuthServIp = %s \n",eAuditSysConf->DcAuthServIp);
	
 /*12*/
   /*2:get DcAuthServPort*/
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_serv_port(&eAuditSysConf->DcAuthServPort,file_cnt_buf))
            {
                error("[Err]GetDcAuthServPort fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"DcAuthServPort fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->DcAuthServPort = DEF_DC_SERV_PORT;
	     break;
    }
    /*13:get Dcwork mode*/
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_work_mode(&eAuditSysConf->work_mode,file_cnt_buf))
            {
                error("[Err]get WORK_MODE  fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get WORK_MODE  fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            eAuditSysConf->work_mode = DEF_WORK_MODE;
	     break;
    }
   FREE(file_cnt_buf);
   return OK;
}
/**********************************
*func name:read Capture_NIC.conf 
*function:
*parameters:
*call:
*called:
*return:
*/
static int ReadCaptureNIC(CAPTURE_NIC_CONF *CaptureNicConf,EAUDIT_SYS_CONF *eAuditSysConf,CONFIG_KEY *conf_key,NIC_QUE_INFO_ID nic_que_info_id){
	
   	char file_name[MAX_FILE_PATH_SIZE];
   	int fd,file_size,cfg_mode;
	char *file_cnt_buf = NULL;
	int cfg_que_buf_num =0;
	int run_cfg_shm_size;
       int log_pri = LOG_DEBUG;	 
    	 int log_filter_mode = LOG_NOT_FILTER;
    	 int log_tool = LOG_TOOL;
		 
    	memset(file_name,0x00,MAX_FILE_PATH_SIZE);
    	sprintf(file_name,"%s/%s",CFG_DIR_PATH,CAPTURE_NIC_CFG_NAME);
    	cfg_mode = get_read_cfg_mode(file_name,&fd,&file_size);
    
    	/*1 :read the header of the run config file*/
    	switch (cfg_mode)
    	{
        	case READ_FILE:
            			file_cnt_buf = (char *)malloc(file_size + 1);
           			 if (NULL == file_cnt_buf)
            			{
               			 error("[Err]Malloc for capture NIC cfg file content fail!\n");
                			write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Malloc for capture NIC cfg file content fail.");
               			return ERR;
            			}

            			if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
	     			{
	         			error("[Err]Get capture NIC cfg file fail!\n");
	         			write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get capture NIC cfg file  fail!");
		  			return ERR;
	     			}
	     			file_cnt_buf[file_size] = '\0';
            			CLOSE_FILE(fd);
			       //得到网卡个数及其每个网卡对应的抓包队列数
            			if (ERR == get_cfg_hdr_by_file(&(CaptureNicConf->cfg_hdr),file_cnt_buf))
            			{
                			error("[Err]Get capture NIC cfg file header info err.\n");
                			write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get capture NIC cfg file header info err.");
                			return ERR;
            			}
            			break;			
        	case DEF_MODE:
        	default:		 
	     			get_cfg_hdr_by_def(&(CaptureNicConf->cfg_hdr));
            			break; 
    	}
   	//DEBUG("Get capture NIC cfg file header info OK.");
  
    /*2 :check capture NIC cfg file header info*/
    if (CaptureNicConf->cfg_hdr.iNICNum > MAX_NIC_NUM)
        CaptureNicConf->cfg_hdr.iNICNum = MAX_NIC_NUM;
    
    if (CaptureNicConf->cfg_hdr.iPerNICQueNum < MIN_QUE_NUM)
    {
        error("[Err]the que number must > 1.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"[Err]que number <= 1!");
        return ERR;
    }

    if (CaptureNicConf->cfg_hdr.iPerNICQueNum > MAX_QUE_NUM)
    {
        error("[Err]the que number can't > MAX_QUE_NUM.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"[Err]que number > MAX_QUE_NUM!");
        return ERR;
    }
   
    /*2 :get NIC basic info*/
    CaptureNicConf->nic_basic_buf = (CFG_NIC_BASIC_ID)calloc(CFG_NIC_BASIC_SIZE,CaptureNicConf->cfg_hdr.iNICNum);
    if (NULL == CaptureNicConf->nic_basic_buf)
    {
        error("[Err]Calloc for capture nic basic cfg info fail!\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Calloc for capture nic basic cfg info fail!");
        return ERR;
    }
    
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_nic_basic_info_by_file(CaptureNicConf->nic_basic_buf,CaptureNicConf->cfg_hdr.iNICNum,file_cnt_buf))
            {
                error("[Err]Get capture nic basic cfg info err.\n");
                write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get capture nic basic cfg info err!");
                return ERR;
            }
            break;
        case DEF_MODE:
        default:
            get_nic_basic_info_by_def(CaptureNicConf->nic_basic_buf,CaptureNicConf->cfg_hdr.iNICNum);
            break;         
    }  

    /*3 :check nic basic info if READ_FILE or not*/
    if (ERR == check_nic_basic_info(CaptureNicConf->nic_basic_buf,CaptureNicConf->cfg_hdr.iNICNum,eAuditSysConf->NicForManagement))
    {
        error("[Err]Capture nic basic info set err.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Capture nic basic info set err.!");
        return ERR;
    }   
   // DEBUG("Get capture nic basic info OK.");
 
    /*4:Get the shm max key */
    cfg_que_buf_num = (CaptureNicConf->cfg_hdr.iNICNum) * (CaptureNicConf->cfg_hdr.iPerNICQueNum); 
    if (ERR == get_shm_max_key(cfg_que_buf_num,cfg_mode,&(CaptureNicConf->cfg_hdr),file_cnt_buf))
    {
        error("[Err]Get max shm key fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get max shm key fail!");
        return ERR;   
    }
   
    g_max_shm_key += SHM_KEY_IVL;
    conf_key->run_cfg_shm_key = g_max_shm_key;

    g_res_info.que_num = cfg_que_buf_num;

    /*42:get the sem max key*/
    if (ERR == get_sem_max_key(cfg_que_buf_num,cfg_mode,&(CaptureNicConf->cfg_hdr),file_cnt_buf))
    {
        error("[Err]Get max sem key fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get max sem key fail!");
        return ERR; 
    }
    
    g_max_sem_key += SEM_KEY_IVL;
   // conf_key->pool_sem_key = g_max_sem_key;

   // INFO("Get max shm key and max sem key OK.");
    //(void)record_sys_work_info(wk_info_file,"Get max shm key and max sem key OK.",RECORD_INC_TIME);

    /*43:assign que config shm*/
    run_cfg_shm_size = cfg_que_buf_num * QUE_INFO_SIZE;
    if ((conf_key->run_cfg_shm_id = shmget(conf_key->run_cfg_shm_key,run_cfg_shm_size,IPC_CREAT|IPC_EXCL)) < 0)
    {
      		conf_key->run_cfg_shm_id = get_shm(conf_key->run_cfg_shm_key);
		if(conf_key->run_cfg_shm_id<0){
			  error("[Err]Create shm for capture NIC cfg info fail.\n");
			  write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create shm for capture NIC cfg info fail!");
        		return ERR;
		}
		DEL_SHM(conf_key->run_cfg_shm_id );
	       conf_key->run_cfg_shm_id = shmget(conf_key->run_cfg_shm_key,run_cfg_shm_size,IPC_CREAT|IPC_EXCL);
	       if(conf_key->run_cfg_shm_id <0){
		   	  error("[Err]Create shm for capture NIC cfg info fail.\n");
			  write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create shm for capture NIC cfg info fail!");
        		return ERR;
	       }
    }

   
    CaptureNicConf->cfg_que_info = (QUE_ID)shmat(conf_key->run_cfg_shm_id,NULL,0);
    if (NULL == CaptureNicConf->cfg_que_info)
    {
        error("[Err]Attatch shm for capture NIC cfg info fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Attatch shm for capture NIC cfg info fail!");
        return ERR;
    }
	
    /*5 :get que config info*/
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_que_info_by_file(CaptureNicConf->cfg_que_info,CaptureNicConf->cfg_hdr.iNICNum,CaptureNicConf->cfg_hdr.iPerNICQueNum,file_cnt_buf))
            {
                error("[Err]Get capture NIC cfg info by file fail.\n");
                write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get capture NIC cfg info by file fail!");
                return ERR;
            }
            break;
        case DEF_MODE:
	 default:
	     get_que_info_by_def(CaptureNicConf->cfg_que_info,CaptureNicConf->cfg_hdr.iNICNum,CaptureNicConf->cfg_hdr.iPerNICQueNum);
            break;
    }
   // DEBUG("Get capture NIC cfg que info OK.");
    //(void)record_sys_work_info(wk_info_file,"Get capture NIC cfg que info OK.",RECORD_INC_TIME);
  
    /*45:check que config info*/
    if (ERR == check_que_info(CaptureNicConf->cfg_que_info,cfg_que_buf_num))
    {
        error("[Err]Capture NIC cfg info Set Err.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Capture NIC cfg info Set Err!");
        return ERR;
    }

//#ifdef _DEBUG
 //   print_que_info(CaptureNicConf->cfg_que_info,CaptureNicConf->cfg_hdr.iNICNum,CaptureNicConf->cfg_hdr.iPerNICQueNum);
//#endif

    /*46:create pkt shm que and sem*/
    nic_que_info_id = (NIC_QUE_INFO_ID)malloc(NIC_QUE_INFO_SIZE * cfg_que_buf_num);
    if (NULL == nic_que_info_id)
    {
        error("[Err]Malloc for nic que shm and sem info fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Malloc for nic que shm and sem info fail.");
        return ERR;
    }

    init_nic_que_info(cfg_que_buf_num,nic_que_info_id);

    if (ERR == create_per_nic_shm(cfg_que_buf_num,CaptureNicConf->cfg_que_info,nic_que_info_id))
    {
        error("[Err]Create Per Nic Que Shm Err.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create Per Nic Que Shm Err!");
        return ERR;
    }

    //DEBUG("Create packets shm que OK.");

    if (ERR == create_per_nic_sem(cfg_que_buf_num,CaptureNicConf->cfg_que_info,nic_que_info_id))
    {
        (void)del_per_nic_shm(cfg_que_buf_num,nic_que_info_id);
        error("[Err]Create packets shm que Sem Err.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create packets shm que Err!");
        return ERR;
    }

    //DEBUG("Create Per Nic Que Shm and Sem OK.");
    FREE(nic_que_info_id);
	
    /*47:callback cfg file mem*/
    FREE(file_cnt_buf);
    return OK;
}

/**********************************
*func name:read Capture_NIC.conf 
*function:
*parameters:
*call:
*called:
*return:
*/
static int Read_ConfigFile_Mem(int serv_num,int pro_num,SUPPORT_PRO_NODE_ID pro_items_id,CONFIG_KEY *conf_key,
	MONITOR_SYSINFO *monitor_sysinfo,EAUDIT_SYS_CONF *eAuditSysConf,CAPTURE_NIC_CONF *CaptureNicConf){
	
	int i,j,protocol_name_len;
	key_t authorize_protocol_feature_key;
	int authorize_protocol_feature_num;
	char protocol_name[32];
	int authorize_protocol_feature_id=-1;
	int pid_info_shm_size=0;
	PID_INFO_ID pid_info_id = NULL;
	int log_pri = LOG_DEBUG;	 
    	int log_filter_mode = LOG_NOT_FILTER;
    	int log_tool = LOG_TOOL;
	SUPPORT_PRO_NODE_ID pro_tbl_shm_addr=NULL;
 	/*1 :create protocols table*/
    	if(pro_num >0)
    	{
    	   
	    g_max_shm_key += SHM_KEY_IVL;
	    conf_key->pro_tbl_shm_key = g_max_shm_key;
	    pro_tbl_shm_addr = create_pro_table(g_max_shm_key,&(conf_key->pro_tbl_shm_id),pro_items_id,pro_num);
	    if (!pro_tbl_shm_addr)
	    {
	        error("[Err]Create protocols table fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create protocols table fail!");
	        return ERR;
	    }
	    conf_key->pro_num= pro_num;
	    conf_key->pro_tbl_shm_addr = pro_tbl_shm_addr;
	    //FREE(pro_items_id);
   	}
    	//DEBUG("Start protect rules file......\n");
    
   /*2008 11 19*/
   if(ERR == get_protected_resources_list(&(conf_key->protected_resource_list_id0), &(conf_key->protected_resources_list_key0),&(conf_key->protected_resources_num),conf_key->ProResNum,&conf_key->Pro_Real_Line))
   	warning("get 0000protected resources list Info Fail.\n");
     if(ERR == get_protected_resources_list(&(conf_key->protected_resource_list_id1), &(conf_key->protected_resources_list_key1),&(conf_key->protected_resources_num),conf_key->ProResNum,&conf_key->Pro_Real_Line))
   	warning("get 11111 protected resources list Info Fail.\n");
/*Begin 20080528*/
    /*60:读取用户列表文件并存入共享内存*/
    if (ERR == get_usr_list(&(conf_key->usr_list_id),&(conf_key->usr_list_key),&(conf_key->usr_all_num),conf_key->UsrNum))
        DEBUG("Get usr list Info Fail.\n");
   
  /*读取授权账号列表文件并存入共享内存*/
   if(ERR ==  get_authorize_account_list(&(conf_key->authorize_account_id),&(conf_key->authorize_account_list_key),&(conf_key->authorize_account_num)))
   		warning("Get authorize account list INFO fail.\n");

    /*读取授权命令列表文件并存入共享内存*/
    if(ERR == get_authorize_cmd_list(&(conf_key->authorize_cmd_id),&(conf_key->authorize_cmd_list_key),&(conf_key->authorize_cmd_num)))
		warning("Get authorize cmd list INFO fail.\n");
    /*读取授权通用文件列表并存入共享内存*/
    if(ERR == get_authorize_custom_list(&(conf_key->authorize_custom_id),&(conf_key->authorize_custom_list_key),&(conf_key->authorize_custom_num)))
		warning("Get authorize custom list fail.\n");

     /*读取授权协议特征文件列表并存入共享内存*/
    if(pro_num>0){
   	 conf_key->pro_feature_id = (PRO_FEATURE_PARA_ID)calloc(pro_feature_para_size,pro_num);
   	if(NULL == conf_key->pro_feature_id)
   	{
		warning("alloc protocol feature parameter fail.\n");
	       return ERR;
   	}
    }
    for(i=0;i<pro_num;i++){
		authorize_protocol_feature_key = 0;
   		authorize_protocol_feature_id = DEF_SHM_ID_VAL;
   		authorize_protocol_feature_num = 0;
		memset(protocol_name,0x00,32);
		protocol_name_len = strlen(pro_tbl_shm_addr[i].pro_name);
		for(j=0;j<protocol_name_len;j++){
			protocol_name[j] = tolower(pro_tbl_shm_addr[i].pro_name[j]);
		}
		protocol_name[j] = '\0';
	       if(ERR ==get_authorize_protocol_feature_list(&authorize_protocol_feature_id,&authorize_protocol_feature_key,&authorize_protocol_feature_num,protocol_name) ){
			warning("Get authorize protocol feature list fail.\n");
			continue;
		}
		conf_key->pro_feature_id[i].shm_id = authorize_protocol_feature_id;
		conf_key->pro_feature_id[i].pro_feature_key = authorize_protocol_feature_key;
		conf_key->pro_feature_id[i].pro_feature_num = authorize_protocol_feature_num;
   }
  // DEBUG("enter start network file analysis\n");
  /*网络授权信息文件读取并存入内存*/
    if(ERR == get_authorize_network_list(&(conf_key->authorize_network_id),&(conf_key->authorize_network_key),&(conf_key->authorize_network_num)))
   		warning("Get authorize network list file fail.\n");
    conf_key->redirect_port_list_num =1;

  if(ERR == create_redirect_port_shm_mem(&(conf_key->redirect_port_shm_id),&(conf_key->redirect_port_key),&(conf_key->redirect_port_list_num)))
		warning("create_redirect_port_shm_mem fail.\n");
    /*得到配置系统信息报警*/
    if(ERR==get_monitor_sysinfo_list(monitor_sysinfo))
		DEBUG("GET MONITOR SYSINFO LIST FAIL !");

   // DEBUG("cpu_use_rate:%d,  mem_use_rate:%d,  hd_use_rate:%d\n", monitor_sysinfo->cpu_use_rate, monitor_sysinfo->mem_use_rate, monitor_sysinfo->hd_use_rate);
    /*增加阻断功能共享内存模块*/

  /*第一个网卡阻断队列定义*/
    /*1 tcpclose hdr ptr */
     g_max_shm_key += SHM_KEY_IVL;
    conf_key->tcpclosequeptr_key0= g_max_shm_key;
   printf("tcpclosequeptr_key0 = %ld \n",conf_key->tcpclosequeptr_key0);
  
     int tcpclosequequeptr_shm_size = 1*1;
     conf_key->tcpclosequequeptr_shmid0 = Get_TcpCloseQueque_shm(conf_key->tcpclosequeptr_key0,tcpclosequequeptr_shm_size);
     if(conf_key->tcpclosequequeptr_shmid0 == -1){
		 error("[Err]Create block tcpclosequequeptr shm queque fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create block tcpclosequequeptr shm queque fail!");
	        return ERR;
     }
    // printf("conf_key->tcpclosequeptr_key = %u\n",conf_key->tcpclosequeptr_key);

     /*2 first tcpclose queque ptr */
	 
     g_max_shm_key += SHM_KEY_IVL;
     conf_key->tcpclosefirstque_key0= g_max_shm_key;
     printf("conf_key->tcpclosefirstque_key = %u  block num = %d\n",conf_key->tcpclosefirstque_key0,eAuditSysConf->BlockInfo.fst_block_queque_num);
	 
     int tcpclosefirstque_shm_size = eAuditSysConf->BlockInfo.fst_block_queque_num*TCP_CLOSE_INFO_SIZE;
     conf_key->tcpclosefirstque_shmid0 = Get_TcpCloseQueque_shm(conf_key->tcpclosefirstque_key0,tcpclosefirstque_shm_size);
     if(conf_key->tcpclosefirstque_shmid0 == -1){
		 error("[Err]Create block  tcpclosefirstquequeptr shm queque fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create block tcpclosefirstquequeptr shm queque fail!");
	        return ERR;
     }
      /*3  second  tcpclose queque ptr */
     g_max_shm_key += SHM_KEY_IVL;
     conf_key->tcpclosesecondque_key0 = g_max_shm_key;
   // printf("conf_key->tcpclosesecondque_key= %u snd num = %d \n",conf_key->tcpclosesecondque_key,eAuditSysConf->BlockInfo.snd_block_queque_num);
     int tcpclosesecondque_shm_size = eAuditSysConf->BlockInfo.snd_block_queque_num*TCP_CLOSE_INFO_SIZE;
     conf_key->tcpclosesecondque_shmid0 = Get_TcpCloseQueque_shm(conf_key->tcpclosesecondque_key0,tcpclosesecondque_shm_size);
     if(conf_key->tcpclosesecondque_shmid0 == -1){
		 error("[Err]Create block  tcpclosesecondquequeptr shm queque fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create block tcpclosesecondquequeptr shm queque fail!");
	        return ERR;
     }
      /*4  ip queque ptr */
     g_max_shm_key += SHM_KEY_IVL;
     conf_key->ipque_key0 = g_max_shm_key;
     int ipque_shm_size = eAuditSysConf->BlockInfo.block_ip_queque_num*IP_PACKET_SIZE;
    // printf("conf_key->ipque_key= %u\n",conf_key->ipque_key);
     conf_key->ipque_shmid0 = Get_TcpCloseQueque_shm(conf_key->ipque_key0,ipque_shm_size);
     if(conf_key->ipque_shmid0 == -1){
		 error("[Err]Create block  ipque_key shm queque fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create block ipqueptr shm queque fail!");
	        return ERR;
     }
    /*5  snd check ip queque ptr */
     g_max_shm_key += SHM_KEY_IVL;
     conf_key->snd_check_block_key0= g_max_shm_key;
     int snd_check_ip_shm_size = eAuditSysConf->BlockInfo.snd_check_block_queque_num*TCP_CLOSE_INFO_SIZE;
    // printf("conf_key->snd_check_block_key = %u\n",conf_key->snd_check_block_key);
     conf_key->snd_check_block_shmid0= Get_TcpCloseQueque_shm(conf_key->snd_check_block_key0,snd_check_ip_shm_size);
     if(conf_key->snd_check_block_shmid0 == -1){
		 error("[Err]Create snd check block share memory fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create snd check block share memory fail!");
	        return ERR;
     }

  /*第二张网卡阻断队列定义*/
    /*1 tcpclose hdr ptr */
     g_max_shm_key += SHM_KEY_IVL;
    conf_key->tcpclosequeptr_key1= g_max_shm_key;
     int tcpclosequequeptr_shm_size0 = 1*1;
     conf_key->tcpclosequequeptr_shmid1 = Get_TcpCloseQueque_shm(conf_key->tcpclosequeptr_key1,tcpclosequequeptr_shm_size0);
     if(conf_key->tcpclosequequeptr_shmid1== -1){
		 error("[Err]Create block tcpclosequequeptr shm queque fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create block tcpclosequequeptr shm queque fail!");
	        return ERR;
     }
    // printf("conf_key->tcpclosequeptr_key = %u\n",conf_key->tcpclosequeptr_key);

     /*2 first tcpclose queque ptr */
	 
     g_max_shm_key += SHM_KEY_IVL;
     conf_key->tcpclosefirstque_key1= g_max_shm_key;
     printf("conf_key->tcpclosefirstque_key = %u  block num = %d\n",conf_key->tcpclosefirstque_key1,eAuditSysConf->BlockInfo.fst_block_queque_num);
     int tcpclosefirstque_shm_size0 = eAuditSysConf->BlockInfo.fst_block_queque_num*TCP_CLOSE_INFO_SIZE;
     conf_key->tcpclosefirstque_shmid1 = Get_TcpCloseQueque_shm(conf_key->tcpclosefirstque_key1,tcpclosefirstque_shm_size0);
     if(conf_key->tcpclosefirstque_shmid1 == -1){
		 error("[Err]Create block  tcpclosefirstquequeptr shm queque fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create block tcpclosefirstquequeptr shm queque fail!");
	        return ERR;
     }
      /*3  second  tcpclose queque ptr */
     g_max_shm_key += SHM_KEY_IVL;
     conf_key->tcpclosesecondque_key1 = g_max_shm_key;
   // printf("conf_key->tcpclosesecondque_key= %u snd num = %d \n",conf_key->tcpclosesecondque_key,eAuditSysConf->BlockInfo.snd_block_queque_num);
     int tcpclosesecondque_shm_size0 = eAuditSysConf->BlockInfo.snd_block_queque_num*TCP_CLOSE_INFO_SIZE;
     conf_key->tcpclosesecondque_shmid1 = Get_TcpCloseQueque_shm(conf_key->tcpclosesecondque_key1,tcpclosesecondque_shm_size0);
     if(conf_key->tcpclosesecondque_shmid1 == -1){
		 error("[Err]Create block  tcpclosesecondquequeptr shm queque fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create block tcpclosesecondquequeptr shm queque fail!");
	        return ERR;
     }
      /*4  ip queque ptr */
     g_max_shm_key += SHM_KEY_IVL;
     conf_key->ipque_key1 = g_max_shm_key;
     int ipque_shm_size0 = eAuditSysConf->BlockInfo.block_ip_queque_num*IP_PACKET_SIZE;
    // printf("conf_key->ipque_key= %u\n",conf_key->ipque_key);
     conf_key->ipque_shmid1 = Get_TcpCloseQueque_shm(conf_key->ipque_key1,ipque_shm_size0);
     if(conf_key->ipque_shmid1 == -1){
		 error("[Err]Create block  ipque_key shm queque fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create block ipqueptr shm queque fail!");
	        return ERR;
     }
    /*5  snd check ip queque ptr */
     g_max_shm_key += SHM_KEY_IVL;
     conf_key->snd_check_block_key1= g_max_shm_key;
     int snd_check_ip_shm_size0 = eAuditSysConf->BlockInfo.snd_check_block_queque_num*TCP_CLOSE_INFO_SIZE;
    // printf("conf_key->snd_check_block_key = %u\n",conf_key->snd_check_block_key);
     conf_key->snd_check_block_shmid1= Get_TcpCloseQueque_shm(conf_key->snd_check_block_key1,snd_check_ip_shm_size0);
     if(conf_key->snd_check_block_shmid1 == -1){
		 error("[Err]Create snd check block share memory fail.\n");
	        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create snd check block share memory fail!");
	        return ERR;
     }



    /*62:get the all process num*/
#ifdef INC_CAPTURE_MODEL
    g_all_process_num = CaptureNicConf->cfg_hdr.iNICNum;
#endif

#ifdef INC_FILTER_MODEL
    g_all_process_num += CaptureNicConf->cfg_hdr.iNICNum;
#endif

#ifdef INC_ANALYZE_MODEL
    g_all_process_num += pro_num*CaptureNicConf->cfg_hdr.iNICNum;
#endif
g_all_process_num += serv_num;

    printf("########################################all_process_num = %d\n",g_all_process_num);
    
    /*63:pid and nicname response*/
    g_max_shm_key += SEM_KEY_IVL;
    conf_key->pid_info_shm_key = g_max_shm_key;
    pid_info_shm_size = g_all_process_num * PID_INFO_SIZE;
    if ((conf_key->pid_info_shm_id = shmget(conf_key->pid_info_shm_key,pid_info_shm_size,IPC_CREAT|IPC_EXCL)) < 0)
    {

		conf_key->pid_info_shm_id = get_shm(conf_key->pid_info_shm_key);
		if(conf_key->pid_info_shm_id<0){
			 error("[Err]Create shm for pid info fail.\n");
			 write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create shm for pid info fail!");
        		return ERR;
		}
		DEL_SHM(conf_key->pid_info_shm_id);
	      conf_key->pid_info_shm_id = shmget(conf_key->pid_info_shm_key,pid_info_shm_size,IPC_CREAT|IPC_EXCL);
	       if(conf_key->pid_info_shm_id <0){
		   	 error("[Err]Create shm for pid info fail.\n");
		   	 write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create shm for pid info fail!");
        		return ERR;
	       }
    }

    pid_info_id = (PID_INFO_ID)shmat(conf_key->pid_info_shm_id,NULL,0);
    if (NULL == pid_info_id)
    {
        error("[Err]Attatch shm for pid info fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Attatch shm for pid info fail!");
        return ERR;
    }

    g_pid_info = pid_info_id;


    /*:start the capture child process*/
#ifdef WITH_FILE_REG_RES
    (void)mp_reg_heap(CaptureNicConf->nic_basic_buf,pid_info_id);
    (void)mp_reg_shm_num(7);
    (void)mp_reg_shm((void *)CaptureNicConf->cfg_que_info,conf_key->run_cfg_shm_id);
    //(void)mp_reg_shm((void *)pool_id,shm_pool_id);
    (void)mp_reg_shm((void *)pid_info_id,conf_key->pid_info_shm_id);
    (void)mp_reg_shm((void *)pro_tbl_shm_addr,conf_key->pro_tbl_shm_id);
   // (void)mp_reg_shm((void *)port_index_id,port_idx_shm_id);
   
    (void)mp_reg_shm(NULL,conf_key->usr_list_id);
    (void)mp_reg_shm(NULL,conf_key->protected_resource_list_id0);
    (void)mp_reg_shm(NULL,conf_key->protected_resource_list_id1);
    (void)mp_reg_shm(NULL,conf_key->authorize_account_id);
    (void)mp_reg_shm(NULL,conf_key->authorize_cmd_id);
    (void)mp_reg_shm(NULL,conf_key->authorize_custom_id);
    (void)mp_reg_shm(NULL,conf_key->authorize_network_id);
    (void)mp_reg_shm(NULL,conf_key->redirect_port_shm_id);

    (void)mp_reg_shm(NULL,conf_key->snd_check_block_shmid0);
    (void)mp_reg_shm(NULL,conf_key->tcpclosequequeptr_shmid0);
    (void)mp_reg_shm(NULL,conf_key->tcpclosefirstque_shmid0);
    (void)mp_reg_shm(NULL,conf_key->tcpclosesecondque_shmid0);
    (void)mp_reg_shm(NULL,conf_key->ipque_shmid0);
    (void)mp_reg_shm(NULL,conf_key->snd_check_block_shmid1);
     (void)mp_reg_shm(NULL,conf_key->tcpclosequequeptr_shmid1);
    (void)mp_reg_shm(NULL,conf_key->tcpclosefirstque_shmid1);
    (void)mp_reg_shm(NULL,conf_key->tcpclosesecondque_shmid1);
    (void)mp_reg_shm(NULL,conf_key->ipque_shmid1);
     for(i=0;i<pro_num;i++){
	 	if(conf_key->pro_feature_id[i].shm_id >0)
	 		(void)mp_reg_shm(NULL,conf_key->pro_feature_id[i].shm_id);
    }
  
    #ifdef WITH_SHM_KEY_FILE
        /*for check res at sys starting*/
        (void)mp_reg_shm_key_num(5);
        (void)mp_reg_shm_key(conf_key->run_cfg_shm_key);
        (void)mp_reg_shm_key(conf_key->shm_pool_key);
        (void)mp_reg_shm_key(conf_key->pid_info_shm_key);
        (void)mp_reg_shm_key(conf_key->pro_tbl_shm_key);
        (void)mp_reg_shm_key(conf_key->rule_que_shm_key);
	(void)mp_reg_shm_key(conf_key->protected_resources_list_key0);
	(void)mp_reg_shm_key(conf_key->protected_resources_list_key1);
        (void)mp_reg_shm_key(conf_key->usr_list_key);
	(void)mp_reg_shm_key(conf_key->authorize_account_list_key);
	(void)mp_reg_shm_key(conf_key->authorize_cmd_list_key);
	(void)mp_reg_shm_key(conf_key->authorize_custom_list_key);
	(void)mp_reg_shm_key(conf_key->authorize_network_key);
	(void)mp_reg_shm_key(conf_key->redirect_port_key);
	
       (void)mp_reg_shm_key(conf_key->snd_check_block_key0);
	(void)mp_reg_shm_key(conf_key->tcpclosequeptr_key0);
	(void)mp_reg_shm_key(conf_key->tcpclosefirstque_key0);
	(void)mp_reg_shm_key(conf_key->tcpclosesecondque_key0);
	(void)mp_reg_shm_key(conf_key->ipque_key0);
	  (void)mp_reg_shm_key(conf_key->snd_check_block_key1);
	(void)mp_reg_shm_key(conf_key->tcpclosequeptr_key1);
	(void)mp_reg_shm_key(conf_key->tcpclosefirstque_key1);
	(void)mp_reg_shm_key(conf_key->tcpclosesecondque_key1);
	(void)mp_reg_shm_key(conf_key->ipque_key1);
	for(i=0;i<pro_num;i++){
	 if(conf_key->pro_feature_id[i].pro_feature_key>0)
	 	(void)mp_reg_shm_key(conf_key->pro_feature_id[i].pro_feature_key);
    }
    #endif
#endif

    /*66:create pid file*/
    snprintf(s_pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,g_progname);
    if (ERR == create_pid_file(s_pid_file))
    {
        error("[Err]Create system pid file fail.\n");
	 write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create system pid file fail!\n");
	 return ERR;
    }  
   
  conf_key->ip_queque_sem_key0 = g_max_sem_key + 10000;;
    
   if((conf_key->ip_queque_sem_id0 = Sem_Ip_Queque_Create(conf_key->ip_queque_sem_key0))==-1){
		error("[Err]Create ip queque sem  fail.\n");
	 	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create ip queque sem  fail!\n");
	 	return ERR;
    }
    if(-1 == Init_Sem_Ip_Queue(conf_key->ip_queque_sem_id0)){
		error("[Err]init  ip queque sem  fail.\n");
	 	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"init ip queque sem  fail!\n");
	 	return ERR;
     }	 
     conf_key->ip_queque_sem_key1 = g_max_sem_key + 50000;;
    
   if((conf_key->ip_queque_sem_id1 = Sem_Ip_Queque_Create(conf_key->ip_queque_sem_key1))==-1){
		error("[Err]Create ip queque sem  fail.\n");
	 	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create ip queque sem  fail!\n");
	 	return ERR;
    }
    if(-1 == Init_Sem_Ip_Queue(conf_key->ip_queque_sem_id1)){
		error("[Err]init  ip queque sem  fail.\n");
	 	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"init ip queque sem  fail!\n");
	 	return ERR;
     }	 
     sleep(4);
     Sem_V(0,conf_key->ip_queque_sem_id0);
     Sem_V(1,conf_key->ip_queque_sem_id0);
     Sem_Unlock(0,conf_key->ip_queque_sem_id0);
     Sem_Unlock(1,conf_key->ip_queque_sem_id0);
    Sem_V(0,conf_key->ip_queque_sem_id1);
     Sem_V(1,conf_key->ip_queque_sem_id1);
     Sem_Unlock(0,conf_key->ip_queque_sem_id1);
     Sem_Unlock(1,conf_key->ip_queque_sem_id1);
     return OK;
}
/**********************************
*func name:开始启动数据引擎和协议分析进程
*function:
*parameters:
*call:
*called:
*return:
*/
int Start_ProAnalysis_Server(EAUDIT_SYS_CONF *eAuditSysConf,CAPTURE_NIC_CONF *CaptureNicConf,CONFIG_KEY *conf_key,int fail_proc_num,int *pid_index,char *wk_info_file,int pro_num,int may_proc_num){

	char par[MAX_PAR_SIZE],exec_path[MAX_PAR_SIZE],pro_ans_model[MAX_ANS_MODEL_NAME+1];
	char ipsemkey[256],tcpclosefirstquekey[256],sndcheckquekey[256],tcpclosesecondquekey[256],ipquekey[256];
	int i,k;
       pid_t pid =-1;
       int log_pri = LOG_DEBUG;	 
    	 int log_filter_mode = LOG_NOT_FILTER;
    	 int log_tool = LOG_TOOL;
#ifdef INC_CAPTURE_MODEL
	//for (i = 0;i < cfg_hdr.iNICNum;i++)
	printf("cfg_hdr.iNICNum = %d \n",CaptureNicConf->cfg_hdr.iNICNum);
     	for (i = 0;i < CaptureNicConf->cfg_hdr.iNICNum;i++)
    	{ 
        	memset(&par,0x00,MAX_PAR_SIZE);
		if(i==0)
        	sprintf(par,"%s+%d+%d+%d+%d+%d+%ld+%d+%ld+%d+%s+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld",\
	          (CaptureNicConf->nic_basic_buf + i)->NICName,i, CaptureNicConf->cfg_hdr.iPerNICQueNum,\
                 eAuditSysConf->func_switch.iAlarmSwitch,eAuditSysConf->func_switch.iErrSwitch,eAuditSysConf->func_switch.iStatSwitch,\
                 (unsigned long)conf_key->run_cfg_shm_key,CaptureNicConf->cfg_hdr.iNICNum,eAuditSysConf->DepositIntervalSeconds,eAuditSysConf->FlowSwitch,(char *)&(eAuditSysConf->NicForManagement),\
                  (unsigned long)conf_key->ip_queque_sem_key0,(unsigned long)conf_key->tcpclosefirstque_key0,(unsigned long)eAuditSysConf->BlockInfo.fst_block_queque_num,(unsigned long)conf_key->snd_check_block_key0,\
                  (unsigned long)eAuditSysConf->BlockInfo.snd_check_block_queque_num,(unsigned long)conf_key->tcpclosesecondque_key0,(unsigned long)eAuditSysConf->BlockInfo.snd_block_queque_num,\
                  (unsigned long)conf_key->ipque_key0,(unsigned long)eAuditSysConf->BlockInfo.block_ip_queque_num,(unsigned long)conf_key->protected_resources_list_key0,\
                  (unsigned long)conf_key->protected_resources_num,(unsigned long)conf_key->usr_list_key,(unsigned long)conf_key->usr_all_num,\
                  (unsigned long)conf_key->authorize_network_key,(unsigned long)conf_key->authorize_network_num);
              else
		   sprintf(par,"%s+%d+%d+%d+%d+%d+%ld+%d+%ld+%d+%s+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld",\
	          (CaptureNicConf->nic_basic_buf + i)->NICName,i, CaptureNicConf->cfg_hdr.iPerNICQueNum,\
                 eAuditSysConf->func_switch.iAlarmSwitch,eAuditSysConf->func_switch.iErrSwitch,eAuditSysConf->func_switch.iStatSwitch,\
                 (unsigned long)conf_key->run_cfg_shm_key,CaptureNicConf->cfg_hdr.iNICNum,eAuditSysConf->DepositIntervalSeconds,eAuditSysConf->FlowSwitch,(char *)&(eAuditSysConf->NicForManagement),\
                  (unsigned long)conf_key->ip_queque_sem_key1,(unsigned long)conf_key->tcpclosefirstque_key1,(unsigned long)eAuditSysConf->BlockInfo.fst_block_queque_num,(unsigned long)conf_key->snd_check_block_key1,\
                  (unsigned long)eAuditSysConf->BlockInfo.snd_check_block_queque_num,(unsigned long)conf_key->tcpclosesecondque_key1,(unsigned long)eAuditSysConf->BlockInfo.snd_block_queque_num,\
                  (unsigned long)conf_key->ipque_key1,(unsigned long)eAuditSysConf->BlockInfo.block_ip_queque_num,(unsigned long)conf_key->protected_resources_list_key1,\
                  (unsigned long)conf_key->protected_resources_num,(unsigned long)conf_key->usr_list_key,(unsigned long)conf_key->usr_all_num,\
                  (unsigned long)conf_key->authorize_network_key,(unsigned long)conf_key->authorize_network_num);
		DEBUG("capture par = %s",par);

        	pid = fork();         
        	switch (pid){
            		case -1:
                		++fail_proc_num;
                		break;
            		case 0: 
		  		//DEBUG("Capture on NIC %s Ok !",(CaptureNicConf->nic_basic_buf + i)->NICName);
                		execl(CAPTURE_MODEL_PATH,(char *)&par,(char *)0);
                		error("[Err]Start capture process Fail.\n");
                		(void)record_sys_work_info(wk_info_file,"Start capture process Fail",RECORD_INC_TIME);
                		exit(EXIT_FAILURE);
               		break;
            		default:
				memset(exec_path,0,MAX_PAR_SIZE);
		  		sprintf(exec_path,"%s",CAPTURE_MODEL_PATH);
                		if (ERR == reg_pid_to_shm(g_pid_info,*pid_index,pid,exec_path,&par))
                		{
                    			error("[Err]Reg capture process info fail.\n");
                    			return ERR;
                		}
                
                		if (ERR == reg_pid_to_file(pid))
                		{
                    			error("[Err]Reg capture process info to pid file fail.\n");
                    			return ERR;
                		}
                		break;
        	}

    	#ifdef INC_FILTER_MODEL
        	//DEBUG("Start the filter process......"); 
        	(void)record_sys_work_info(wk_info_file,"Start the filter process......",RECORD_INC_TIME);
			
		memset(&par,0x00,MAX_PAR_SIZE);
		if(i==0)
         	sprintf(par,"%d+%d+%d+%ld+%ld+%d+%d+%d+%ld+%ld+%ld+%ld+%ld+%s%d+%s+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld\
		 	+%ld",i,pro_num,CaptureNicConf->cfg_hdr.iPerNICQueNum, eAuditSysConf->cfg_file_set.maxPktFileSize, eAuditSysConf->cfg_file_set.maxPktFileNum,\
                   eAuditSysConf->func_switch.iAlarmSwitch, eAuditSysConf->func_switch.iErrSwitch, eAuditSysConf->func_switch.iStatSwitch,(unsigned long)conf_key->protected_resources_num,\
                  (unsigned long)conf_key->run_cfg_shm_key,(unsigned long)conf_key->protected_resources_list_key0,\
                  (unsigned long)conf_key->pro_tbl_shm_key,eAuditSysConf->DepositIntervalSeconds,eAuditSysConf->PacketsFilesDir,i+1,(CaptureNicConf->nic_basic_buf  + i)->NICName,\
		  (unsigned long)conf_key->authorize_network_key,(unsigned long)conf_key->authorize_network_num,(unsigned long)conf_key->redirect_port_key,\
		  (unsigned long)eAuditSysConf->DynamicProtectResNum,(unsigned long)conf_key->usr_list_key,(unsigned long)conf_key->usr_all_num,\
		  (unsigned long)conf_key->ip_queque_sem_key0,(unsigned long)conf_key->tcpclosequeptr_key0,(unsigned long)conf_key->tcpclosefirstque_key0,\
		  (unsigned long)(eAuditSysConf->BlockInfo.fst_block_queque_num));
		else
   			sprintf(par,"%d+%d+%d+%ld+%ld+%d+%d+%d+%ld+%ld+%ld+%ld+%ld+%s%d+%s+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld\
		 	+%ld",i,pro_num,CaptureNicConf->cfg_hdr.iPerNICQueNum, eAuditSysConf->cfg_file_set.maxPktFileSize, eAuditSysConf->cfg_file_set.maxPktFileNum,\
                   eAuditSysConf->func_switch.iAlarmSwitch, eAuditSysConf->func_switch.iErrSwitch, eAuditSysConf->func_switch.iStatSwitch,(unsigned long)conf_key->protected_resources_num,\
                  (unsigned long)conf_key->run_cfg_shm_key,(unsigned long)conf_key->protected_resources_list_key1,\
                  (unsigned long)conf_key->pro_tbl_shm_key,eAuditSysConf->DepositIntervalSeconds,eAuditSysConf->PacketsFilesDir,i+1,(CaptureNicConf->nic_basic_buf  + i)->NICName,\
		  (unsigned long)conf_key->authorize_network_key,(unsigned long)conf_key->authorize_network_num,(unsigned long)conf_key->redirect_port_key,\
		  (unsigned long)eAuditSysConf->DynamicProtectResNum,(unsigned long)conf_key->usr_list_key,(unsigned long)conf_key->usr_all_num,\
		  (unsigned long)conf_key->ip_queque_sem_key0,(unsigned long)conf_key->tcpclosequeptr_key0,(unsigned long)conf_key->tcpclosefirstque_key0,\
		  (unsigned long)(eAuditSysConf->BlockInfo.fst_block_queque_num));
       	//DEBUG("filter par = %s\n",par);
        	pid = fork();        
        	switch (pid){
            		case -1:
               	 	++fail_proc_num;
                		break;
            		case 0:
                		//DEBUG("Filter on NIC %s OK",(CaptureNicConf->nic_basic_buf + i)->NICName);
                		execl(FILTER_MODEL_PATH,(char *)&par,(char *)0);                
                		error("[Err]Start filter process Fail.\n");
                		(void)record_sys_work_info(wk_info_file,"Start filter process Fail",RECORD_INC_TIME);
                		exit(EXIT_FAILURE);
                		break;
            		default:
				(*pid_index)++;
				memset(exec_path,0,MAX_PAR_SIZE);
				sprintf(exec_path,"%s",FILTER_MODEL_PATH);
                		if (ERR == reg_pid_to_shm(g_pid_info,*pid_index,pid,exec_path,&par))
                		{
                    			error("[Err]Reg filter process info fail.\n");
                    			return ERR;
                		}  
                     
               	 	if (ERR == reg_pid_to_file(pid))
                		{
                    			error("[Err]Reg filter process info to pid file fail.\n");
                    			return ERR;
                		}
		  		conf_key->filter_pid = pid;
                		break;
        		}
    	#endif	
    	} 
#endif

     /*69:check if all capture and filter processes start fail*/
#ifdef INC_CAPTURE_MODEL
    may_proc_num = CaptureNicConf->cfg_hdr.iNICNum;
#endif

#ifdef INC_FILTER_MODEL
    may_proc_num = CaptureNicConf->cfg_hdr.iNICNum<<1;
#endif

    if (may_proc_num > 0 
        && fail_proc_num == may_proc_num)
    {
        error("[Err]All capture and filter Processes start Fail.\n");	  
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"All capture and filter Processes start Fail!");
        return ERR;
    }

    if (fail_proc_num > 0)
    {
        error("[Err]Some process start fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Some process start fail!");
        return ERR;
    }
	
    /*start the analysis child process*/
#ifdef INC_ANALYZE_MODEL

   // DEBUG("Start the all analysis processes......"); 
   for (k= 0;k < CaptureNicConf->cfg_hdr.iNICNum;k++)
//	for (k= 0;k < 19;k++)
	{
//    for (i = 0 ; i < 1;i++)
	for (i = 0 ; i < pro_num;i++)
    {
        memset(pro_ans_model,0x00,MAX_ANS_MODEL_NAME+1);
        sprintf(pro_ans_model,"%s%s%s",ANALYZE_MODEL_BASE_PATH,\
                 (conf_key->pro_tbl_shm_addr + i)->pro_name,ANALYZE_MODEL_PATH_SUFFIX);
    
        //printf("analysis process path = %s\n",pro_ans_model);
        memset(&par,0x00,MAX_PAR_SIZE);
	
	 if((strncmp((conf_key->pro_tbl_shm_addr + i)->pro_name,"ORACLE",6)==0)||(strncmp((conf_key->pro_tbl_shm_addr + i)->pro_name,"BT",2)==0)||(strncmp((conf_key->pro_tbl_shm_addr + i)->pro_name,"SKYPE",5)==0)){
         	sprintf(par,"%d+%ld+%ld+%ld+%d+%d+%d+%ld+%ld+%s%d+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld",\
                (conf_key->pro_tbl_shm_addr + i)->pro_no,(unsigned long)conf_key->pro_tbl_shm_key,eAuditSysConf->cfg_file_set.maxPktFileSize,\
		eAuditSysConf->cfg_file_set.maxPktFileNum,eAuditSysConf->func_switch.iAlarmSwitch,eAuditSysConf->func_switch.iErrSwitch,eAuditSysConf->func_switch.iStatSwitch,\
                (unsigned long)conf_key->protected_resources_list_key0,(unsigned long)conf_key->protected_resources_num,eAuditSysConf->PacketsFilesDir,k+1,eAuditSysConf->DepositIntervalSeconds,\
                (unsigned long)conf_key->usr_list_key,(unsigned long)conf_key->usr_all_num,(unsigned long)conf_key->authorize_network_key,\
		(unsigned long)conf_key->authorize_network_num,(unsigned long)conf_key->authorize_account_list_key,\
		(unsigned long)conf_key->authorize_account_num,(unsigned long)conf_key->authorize_cmd_list_key,\
		(unsigned long)conf_key->authorize_cmd_num,(unsigned long)conf_key->authorize_custom_list_key,(unsigned long)conf_key->authorize_custom_num,\
		(unsigned long)conf_key->pro_feature_id[i].pro_feature_key,(unsigned long)conf_key->pro_feature_id[i].pro_feature_num,(unsigned long)conf_key->redirect_port_key,\
		(unsigned long)conf_key->filter_pid,(unsigned long)conf_key->ip_queque_sem_key0);
         }else{
			sprintf(par,"%d+%ld+%ld+%ld+%d+%d+%d+%ld+%ld+%s%d+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld",\
                (conf_key->pro_tbl_shm_addr + i)->pro_no,(unsigned long)conf_key->pro_tbl_shm_key,eAuditSysConf->cfg_file_set.maxPktFileSize,\
		  eAuditSysConf->cfg_file_set.maxPktFileNum,eAuditSysConf->func_switch.iAlarmSwitch,eAuditSysConf->func_switch.iErrSwitch,eAuditSysConf->func_switch.iStatSwitch,\
                (unsigned long)conf_key->protected_resources_list_key0,(unsigned long)conf_key->protected_resources_num,eAuditSysConf->PacketsFilesDir,k+1,eAuditSysConf->DepositIntervalSeconds,\
                (unsigned long)conf_key->usr_list_key,(unsigned long)conf_key->usr_all_num,(unsigned long)conf_key->authorize_network_key,\
		(unsigned long)conf_key->authorize_network_num,(unsigned long)conf_key->authorize_account_list_key,\
		(unsigned long)conf_key->authorize_account_num,(unsigned long)conf_key->authorize_cmd_list_key,\
		(unsigned long)conf_key->authorize_cmd_num,(unsigned long)conf_key->authorize_custom_list_key,(unsigned long)conf_key->authorize_custom_num,\
		(unsigned long)conf_key->pro_feature_id[i].pro_feature_key,(unsigned long)conf_key->pro_feature_id[i].pro_feature_num);
	}
		
        DEBUG("PAR = %s",par);      
        pid = fork();
        switch (pid)
        {
            case -1:
	         ++fail_proc_num;
                break;
            case 0:	
//				while(1);
               if(-1 == execl(pro_ans_model,(char *)&par,(char *)0))
			   	error("execl error\n");
		  error("[Err]Start analysis process Fail.\n");
                (void)record_sys_work_info(wk_info_file,"Start analysis process Fail",RECORD_INC_TIME);
                exit(EXIT_FAILURE);
                break;
            default:
#if 1
		 (*pid_index)++;

              if (ERR == reg_pid_to_shm(g_pid_info,*pid_index,\
                                                            pid,pro_ans_model,&par))
               {
                    error("[Err]Reg analysis process info fail.\n");
                    return ERR;
               }  

               if (ERR == reg_pid_to_file(pid))
               {
                    error("[Err]Reg analysis process info to pid file fail.\n");
                    return ERR;
               }
  #endif
                break;

        }	
    }
   }
#endif
}
/**********************************
*func name:START BASIC SERVER PROCESS DESCRIBE
*function:
*parameters:
*call:
*called:
*return:
*/
static int Start_Basic_Server(BASIC_SERV_ID basic_serv_id,int serv_num,EAUDIT_SYS_CONF *eAuditSysConf,CAPTURE_NIC_CONF *CaptureNicConf,CONFIG_KEY *conf_key,int fail_proc_num,int *pid_index,char *wk_info_file,int pro_num,int may_proc_num){

		pid_t pid;
		char par[MAX_PAR_SIZE],exec_path[MAX_PAR_SIZE],serv_model[MAX_ANS_MODEL_NAME+1];
		int i;
		unsigned long wmode =0;
		int log_pri = LOG_DEBUG;	 
    	 	int log_filter_mode = LOG_NOT_FILTER;
    	 	int log_tool = LOG_TOOL;
              if(basic_serv_id==NULL)
			  	return ERR;
		wmode = eAuditSysConf->work_mode;
		for(i=0;i<serv_num;i++){
			memset(serv_model,0x00,MAX_ANS_MODEL_NAME+1);
        		sprintf(serv_model,"%s%s%s",ANALYZE_MODEL_BASE_PATH,(basic_serv_id + i)->serv_name,SERVER_MODEL_PAHT_SUFFIX);
        		//DEBUG("server process path = %s",serv_model);
        		memset(&par,0x00,MAX_PAR_SIZE);
			if(strncmp((basic_serv_id + i)->serv_name,"PMC",3)==0)
				sprintf(&par,"%s",eAuditSysConf->NicForManagement);
			else if(strncmp((basic_serv_id + i)->serv_name,"DC",2)==0)
					sprintf(&par,"%ld+%ld",(unsigned long)conf_key->usr_list_key,(unsigned long)conf_key->usr_all_num);
				else if(strncmp((basic_serv_id + i)->serv_name,"BLOCK",5)==0)

						//sprintf(par,"%ld+%ld+%ld+%ld+%ld+%ld+%ld+%ld",(unsigned long)conf_key->ip_queque_sem_key,(unsigned long)conf_key->tcpclosequeptr_key,\
						//(unsigned long)conf_key->tcpclosefirstque_key,(unsigned long)(eAuditSysConf->BlockInfo.fst_block_queque_num),\
						//(unsigned long)conf_key->tcpclosesecondque_key,(unsigned long)(eAuditSysConf->BlockInfo.snd_block_queque_num),\
						//(unsigned long)conf_key->ipque_key,(unsigned long)(eAuditSysConf->BlockInfo.block_ip_queque_num));
						;
					else if((strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)==0)&&(wmode ==0x01)){
						
						//printf("##########################jinru connnect server############\n");
						if((pid =Read_Connect_Pid())>0){
							if (kill((pid_t)pid, SIGNAL_ZERO) == SIGNAL_ZERO){   //存在进程
								/*add socket server commulication*/
								//printf("*************************connect server exist ok \n");
next1:
								//printf("*************************connect server have exist#### ok \n");
								Socket_Commulication(eAuditSysConf->DcAuthServIp,eAuditSysConf->DcAuthServPort,0x04,wmode);
								//printf("commulication success \n");
								sprintf(exec_path,"%s",serv_model);
                        					(*pid_index)++;
			 					if (ERR == reg_pid_to_shm(g_pid_info,*pid_index,pid,exec_path,&par))
            							{
                							error("[Err]##########connect server precess register connect server  fail.\n");
                							return ERR;
            							}
								continue;
							}else{
							     // printf("########connect server \n");
								eAudit_Exit_Inform_Connect(wmode);
								if((pid =Read_Connect_Pid())>0){
									if (kill((pid_t)pid, SIGNAL_ZERO) == SIGNAL_ZERO)
										goto next1;
								}
							}	
						}
						system("killall -9 CONNECT_server");
					}
					else if((strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)==0)&&(wmode ==0x00))
							continue;
						else
							;
				
			pid = fork();
   			switch (pid){
        				case -1:
			 				++fail_proc_num;
            						break;
        				case 0:  
            						execl(serv_model,(char *)&par,(char *)0);
            						error("[SNAM][Err]Start basic sever process Fail.\n");
            						exit(EXIT_FAILURE);
            						break;
        				default:
							sprintf(exec_path,"%s",serv_model);
                        				(*pid_index)++;
							 if((strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)==0)&&(wmode==0x01))
							 	g_pid_info[*pid_index].conect_flag =1;
			 				if (ERR == reg_pid_to_shm(g_pid_info,*pid_index,pid,exec_path,&par))
            						{
                						error("[Err]start basic server  fail.\n");
                						return ERR;
            						}
							
						
                                                 if(strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)!=0){
            							if (ERR == reg_pid_to_file(pid))
            							{
                							error("[Err]basic serverprocess info to pid file fail.\n");
                							return ERR;
            							}
                                                 }else{
                                                  	     if((strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)==0)&&(wmode==0x01)){
                                                             // printf("#########唐清友带connect server 进程起来\n");
									if(ERR ==  reg_connect_pid_to_file(pid))
									{
                								error("[Err]basic connect server info to pid file fail.\n");
                								return ERR;
            								}
                                                  	    }
                                                 }
						
            						break;
    			}
		}
		/*2009 08 13 add*/
		if(wmode ==0x00)  //表示是动态身份认真和监控器分开
			Socket_Commulication(eAuditSysConf->DcAuthServIp,eAuditSysConf->DcAuthServPort,0x04,wmode);
		//有可能出现挂起状态
		if(basic_serv_id !=NULL){
			free(basic_serv_id);
			basic_serv_id = NULL;
		}
    /*:check if all processes start fail*/
	#ifdef INC_CAPTURE_MODEL
    		may_proc_num = CaptureNicConf->cfg_hdr.iNICNum;
	#endif

	#ifdef INC_FILTER_MODEL
    		may_proc_num = CaptureNicConf->cfg_hdr.iNICNum<<1;
	#endif

	#ifdef INC_ANALYZE_MODEL
    		may_proc_num = (CaptureNicConf->cfg_hdr.iNICNum<<1) + pro_num;
	#endif

	#ifdef INC_FLOW_STAT_ANALYSIS_MODEL
    		++may_proc_num;
	#endif

	#ifdef INC_HW_MOT_MODEL
    		++may_proc_num;
	#endif

    if (fail_proc_num == may_proc_num)
    {
        error("[Err]All Processes start Fail.\n");	  
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"All Processes start Fail!");
        return ERR;
    }

    if (fail_proc_num > 0)
    {
        error("[Err]Some analysis process start fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Some analysis process start fail!");
        return ERR;
    }
    return OK;
}

/**********************************
*func name:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@2009 08 13
*function:
*parameters:
*call:
*called:
*return:
*/
static int Start_eAudit_Basic_Server(BASIC_SERV_ID basic_serv_id,int serv_num,EAUDIT_SYS_CONF *eAuditSysConf,int *pid_index){

		pid_t pid;
		char par[MAX_PAR_SIZE],exec_path[MAX_PAR_SIZE],serv_model[MAX_ANS_MODEL_NAME+1];
		int i;
		unsigned long wmode =0;
		int log_pri = LOG_DEBUG;	 
    	 	int log_filter_mode = LOG_NOT_FILTER;
    	 	int log_tool = LOG_TOOL;
              if(basic_serv_id==NULL)
			  	return ERR;
		wmode = eAuditSysConf->work_mode;
		for(i=0;i<serv_num;i++){
			memset(serv_model,0x00,MAX_ANS_MODEL_NAME+1);
        		sprintf(serv_model,"%s%s%s",ANALYZE_MODEL_BASE_PATH,(basic_serv_id + i)->serv_name,SERVER_MODEL_PAHT_SUFFIX);
        		//DEBUG("server process path = %s",serv_model);
        		memset(&par,0x00,MAX_PAR_SIZE);
			if(strncmp((basic_serv_id + i)->serv_name,"PMC",3)==0)
				sprintf(&par,"%s",eAuditSysConf->NicForManagement);
			else if((strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)==0)&&(wmode==2)){
						
						//printf("##########################jfasdjf############\n");
						if((pid =Read_Connect_Pid())>0){
							if (kill((pid_t)pid, SIGNAL_ZERO) == SIGNAL_ZERO){   //存在进程
								/*add socket server commulication*/
								//printf("*************************connect server exist ok \n");
next1:
								//printf("*************************connect server have exist#### ok \n");
								Socket_Commulication(eAuditSysConf->DcAuthServIp,eAuditSysConf->DcAuthServPort,0x04,wmode);
								//printf("commulication success \n");
								sprintf(exec_path,"%s",serv_model);
                        					
			 					if (ERR == reg_pid_to_shm(g_pid_info,*pid_index,pid,exec_path,&par))
            							{
                							error("[Err]##########connect server precess register connect server  fail.\n");
                							return ERR;
            							}
								(*pid_index)++;
								continue;
							}else{
								eAudit_Exit_Inform_Connect(wmode);
								if((pid =Read_Connect_Pid())>0){
									if (kill((pid_t)pid, SIGNAL_ZERO) == SIGNAL_ZERO)
										goto next1;
								}
							}	
						}
					}
					else if((strncmp((basic_serv_id + i)->serv_name,"DC",2)==0)&&(wmode ==0x02)||(strncmp((basic_serv_id + i)->serv_name,"DC",2)==0)&&(wmode ==0x03))
							continue;
					else if((strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)==0)&&(wmode==3))
							continue;
					       else
							;
				
			pid = fork();
   			switch (pid){
        				case -1:
            						break;
        				case 0:  
            						execl(serv_model,(char *)&par,(char *)0);
            						error("[SNAM][Err]Start basic sever process Fail.\n");
            						exit(EXIT_FAILURE);
            						break;
        				default:
							sprintf(exec_path,"%s",serv_model);
							if((strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)==0)&&(wmode==0x02))
								g_pid_info[*pid_index].conect_flag =1;
			 				if (ERR == reg_pid_to_shm(g_pid_info,*pid_index,pid,exec_path,&par))
            						{
                						error("[Err]start basic server  fail.\n");
                						return ERR;
            						}
							(*pid_index)++;
						
                                                 if(strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)!=0){
            							if (ERR == reg_pid_to_file(pid))
            							{
                							error("[Err]basic serverprocess info to pid file fail.\n");
                							return ERR;
            							}
                                                 }else{
                                                  	     if((strncmp((basic_serv_id + i)->serv_name,"CONNECT",7)==0)&&(wmode==0x02)){
                                                              //printf("#########唐清友带connect server 进程起来\n");
									if(ERR ==  reg_connect_pid_to_file(pid))
									{
                								error("[Err]basic connect server info to pid file fail.\n");
                								return ERR;
            								}
                                                  	    }
                                                 }
						
            						break;
    			}
		}
		//有可能出现挂起状态
		if(basic_serv_id !=NULL){
			free(basic_serv_id);
			basic_serv_id = NULL;
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
/***get CONNECT  pid *********************************************/
static long  Read_Connect_Pid()
{
    FILE *fp = NULL;
    long pid;
    char pid_file[MAX_FILE_PATH_SIZE];

     snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,"CONNECT_SERVER");
   
    if (NOT_EXIST == file_is_exist(pid_file)) 
    {
        INFO("CONNECT_SERVER CONFIG FILE is not exist.\n");
        return 0;
    }

    fp = fopen(pid_file,"rb");
    if (NULL == fp)
    {
        warning("fopen CONNECT SERVER FILE pid file fail.\n");
        return 0;
    }

    while(0 == feof(fp))
    {
         fscanf(fp, "%ld", &pid);
         break;
    }

    fclose(fp);
   // unlink(pid_file);
//   printf("connect server pid = %u\n",pid);
    return pid;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int reg_connect_pid_to_file(long pid)
{
    FILE *fp = NULL;
    char pid_file[MAX_FILE_PATH_SIZE];

    snprintf(pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,"CONNECT_SERVER");
    char buf[U_LONG_SIZE+1];
    unlink(pid_file);
    fp = fopen(pid_file,"a+b");
    if (NULL == fp)
        return ERR;
    sprintf(buf,"%ld",pid);
    fputs(buf,fp);
    fputc('\n',fp);

    fflush(fp);
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
            if(errno == EINTR)  
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

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int Socket_Commulication(char *serv_ip,unsigned short serv_port,int cmd,int wmode){

    int i,sockfd,bytes_read=0;
    PSESSION_HDR pd_data,*pd_data_p=NULL;
    pid_t pid =-1;
    int flag,j,serials,pserials=NULL;
    unsigned short num0,*pNum0=NULL; 
    struct sockaddr_in server_addr; 
    unsigned char szBuf[256];
    unsigned char *pBuf=NULL;
    char *sflag = "STRA";
    char *sflag0 = "12345678";
    char protect_mode,*ppro_mode=NULL;
    pNum0 = &num0;
    num0 = 0x0100;
    pserials = &serials;
    serials = 0;
    ppro_mode = &protect_mode;
    protect_mode =0;
    
	
    if((sockfd = socket(PF_INET,SOCK_STREAM,0))== -1)
    { 
        error("[Err]Create connect client  socket server  err."); 
        return -1;
    }
 
    flag = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
    {
        error("[Err]setsockopt SO_REUSEADDR err.");
	 close(sockfd);
       return -1;
    }
 //  printf("  #################serv_ip = %s serv_port = %d \n",serv_ip,serv_port);
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET; 
    if(serv_port == 0)
    	server_addr.sin_port = htons(5799); 
    else 
	server_addr.sin_port = htons(serv_port);
  

    if(serv_ip ==NULL)
    	server_addr.sin_addr.s_addr =inet_addr("127.0.0.1");
    else 
	server_addr.sin_addr.s_addr =inet_addr(serv_ip);
   // printf("11111111\n");
    if(connect(sockfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr)) != 0)
    { 
        error("[Err]Socket_Commulication connect  sever socket err."); 
	//error(errno);
	printf("lian jie err  work mode = %d serv ip = %s serv port = %d \n",wmode,serv_ip,serv_port);
        close(sockfd);
        return -1;
    }
    //printf("22222222\n");
    memset(szBuf,0,256);
    memset((char *)&pd_data,0,sizeof(PSESSION_HDR));
    pBuf =(char *)&pd_data;
    memcpy((char *)(&pd_data.flag),"SRTA",4);
    pd_data.version = 0x100;
    pd_data.serial=0;
    pd_data.mode = 0;
    pd_data.opt_code = cmd;
    pd_data.param_length = 8;
    pd_data.reserved =0;
    	
	
    //printf("hdr crc32 = %u\n",crc32(0,pBuf,sizeof(PSESSION_HDR)-4));
	
    pd_data.prt_crc = crc32(0,pBuf,sizeof(PSESSION_HDR)-4);
    memcpy(szBuf,pBuf,sizeof(PSESSION_HDR));

    memcpy(szBuf+sizeof(PSESSION_HDR),"12345678",8);
	
  //  printf("all data crc32 = %u \n",crc32(0,szBuf,sizeof(PSESSION_HDR)+8));
	
    serials =crc32(0,szBuf,sizeof(PSESSION_HDR)+8);
	
    pd_data.version = htons(0x100);
    pd_data.param_length = htonl(8);
    pd_data.prt_crc = htonl(pd_data.prt_crc);

    memset(szBuf,0,256);
    memcpy(szBuf,pBuf,sizeof(PSESSION_HDR));
    memcpy(szBuf+sizeof(PSESSION_HDR),"12345678",8);
    memcpy(szBuf+sizeof(PSESSION_HDR)+8,&serials,4);
    //printf("33333333333333333\n");
   /*发送通知*/
    if(-1 == socket_write(sockfd,szBuf,sizeof(PSESSION_HDR)+8+4)){
		error("[Err]Bind sever socket err."); 
	 	//error(errno);
		printf("lian jie err  work mode = %d serv ip = %s serv port = %d \n",wmode,serv_ip,serv_port);
        	close(sockfd);
        	return -1;
   }
  // printf("send yangzheng reboot inform success ok \n");
/*接收确认报文*/
    j=5;
    while(j)
    {
        memset(szBuf,0x00,256);
       //printf("wait for rev data \n");
        bytes_read = recv(sockfd,szBuf,sizeof(szBuf),0); 
        if (bytes_read <= 0) {
			j--;
			continue; 
        }
	 pd_data_p = szBuf;
	 pBuf = szBuf;
	 flag =pd_data_p->opt_code;
	// printf("pd_data_p->opt_code=%.2x\n",pd_data_p->opt_code);
       pBuf +=sizeof(PSESSION_HDR);
	memcpy(&serials,pBuf,4);
	//printf("serials = %u \n",serials);
	 if(serials == 0){
	 	//printf("ok ok \n");
	 	if(flag == 0x85){
			pBuf+=4;
			memcpy(&serials,pBuf,4);
			//for(i=0;i<8;i++) printf("%.2x \n",*pd_data_p++);
			//printf("revc yangzhang pid = %d \n",serials);
			pid = Read_Connect_Pid();
			//printf("conect server pid = %d \n",pid);
			if(pid !=serials){
				//printf("###restart write connect server pid = %d \n",serials);
				reg_connect_pid_to_file(serials);
				}
			
				
		}
	 		
	 	break;
	 }
	 j--;
}
close(sockfd);
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
int setnonblocking(int sockfd)
{
	if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1) {
		return -1;
	}
	return 0;
}
static int Socket_NonBlockCommulication(char *serv_ip,unsigned short serv_port,int cmd,int wmode){

    int i,sockfd,bytes_read=0;
    PSESSION_HDR pd_data,*pd_data_p=NULL;
    pid_t pid =-1;
    int flag,j,serials,pserials=NULL;
    unsigned short num0,*pNum0=NULL; 
    struct sockaddr_in server_addr; 
    unsigned char szBuf[256];
    unsigned char *pBuf=NULL;
    char *sflag = "STRA";
    char *sflag0 = "12345678";
    char protect_mode,*ppro_mode=NULL;
    pNum0 = &num0;
    num0 = 0x0100;
    pserials = &serials;
    serials = 0;
    ppro_mode = &protect_mode;
    protect_mode =0;

	
    if((sockfd = socket(PF_INET,SOCK_STREAM,0))== -1)
    { 
        error("[Err]Create connect client  socket server  err."); 
        return -1;
    }
    
    flag = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
    {
        error("[Err]setsockopt SO_REUSEADDR err.");
	 close(sockfd);
       return -1;
    }
       
 //  printf(" serv_ip = %s serv_port = %d \n",serv_ip,serv_port);
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET; 
    if(serv_port == 0)
    	server_addr.sin_port = htons(5800); 
    else 
	server_addr.sin_port = htons(serv_port);
  

    if(serv_ip ==NULL)
    	server_addr.sin_addr.s_addr =inet_addr("192.168.10.161");
    else 
	server_addr.sin_addr.s_addr =inet_addr(serv_ip);
    // printf("serv_ip = %s  serv_port = %d\n",serv_ip, serv_port );
    if(connect(sockfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr)) != 0)
    { 
        error("[Err]connect  sever socket err."); 
	// error(errno);
        close(sockfd);
        return -1;
    }
   // setnonblocking(sockfd);
    memset(szBuf,0,256);
    memset((char *)&pd_data,0,sizeof(PSESSION_HDR));
    pBuf =(char *)&pd_data;
    memcpy((char *)(&pd_data.flag),"SRTA",4);
    pd_data.version = 0x100;
    pd_data.serial=0;
    pd_data.mode = 0;
    pd_data.opt_code = cmd;
    pd_data.param_length = 8;
    pd_data.reserved =0;
    	
	
    //printf("hdr crc32 = %u\n",crc32(0,pBuf,sizeof(PSESSION_HDR)-4));
	
    pd_data.prt_crc = crc32(0,pBuf,sizeof(PSESSION_HDR)-4);
    memcpy(szBuf,pBuf,sizeof(PSESSION_HDR));

    memcpy(szBuf+sizeof(PSESSION_HDR),"12345678",8);
	
  //  printf("all data crc32 = %u \n",crc32(0,szBuf,sizeof(PSESSION_HDR)+8));
	
    serials =crc32(0,szBuf,sizeof(PSESSION_HDR)+8);
	
    pd_data.version = htons(0x100);
    pd_data.param_length = htonl(8);
    pd_data.prt_crc = htonl(pd_data.prt_crc);

    memset(szBuf,0,256);
    memcpy(szBuf,pBuf,sizeof(PSESSION_HDR));
    memcpy(szBuf+sizeof(PSESSION_HDR),"12345678",8);
    memcpy(szBuf+sizeof(PSESSION_HDR)+8,&serials,4);

   /*发送通知*/
    if(-1 == socket_write(sockfd,szBuf,sizeof(PSESSION_HDR)+8+4)){
		error("[Err]Bind sever socket err."); 
	 	//error(errno);
        	close(sockfd);
        	return -1;
   }
   //printf("send success ok \n");
/*接收确认报文*/
    j=5;
    while(j)
    {
        memset(szBuf,0x00,256);
       //printf("wait for rev data \n");
        bytes_read = recv(sockfd,szBuf,sizeof(szBuf),0); 
        if (bytes_read <= 0) {
			j--;
			continue; 
        }
	 pd_data_p = szBuf;
	 pBuf = szBuf;
	 flag =pd_data_p->opt_code;
	// printf("pd_data_p->opt_code=%.2x\n",pd_data_p->opt_code);
       pBuf +=sizeof(PSESSION_HDR);
	memcpy(&serials,pBuf,4);
	//printf("serials = %u \n",serials);
	 if(serials == 0){
	 	//printf("ok ok \n");
	 	if(flag == 0x85){
			pBuf+=4;
			memcpy(&serials,pBuf,4);
			//for(i=0;i<8;i++) printf("%.2x \n",*pd_data_p++);
			
			pid = Read_Connect_Pid();
			//printf("conect server pid = %d \n",pid);
			if(pid !=serials){
				//printf("###restart write connect server pid = %d \n",serials);
				reg_connect_pid_to_file(serials);
				}
				
		}
	 		
	 	break;
	 }
	 j--;
}
close(sockfd);
return 0;
}
/**********************************
*func name:read from eAudit_sys.conf,get connect server ip and port 
*function:
*parameters:
*call:
*called:
*return:
*/
static int GetConnectServerIpPort(char ip[],unsigned long *port,unsigned long *WorkMode,char child_process_ip[]){
	char file_name[MAX_FILE_PATH_SIZE];
	int cfg_mode,fd,file_size;
       char *file_cnt_buf=NULL;
       int log_pri = LOG_DEBUG;	 
    	 int log_filter_mode = LOG_NOT_FILTER;
    	 int log_tool = LOG_TOOL;
	
    	if (ERR == chk_cfg_dir(CFG_DIR_PATH))
    	{
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Sys config dir err!\n");
        	return ERR;
    	}

    	/*read eAudit sys cfg file*/
    	memset(file_name,0x00,MAX_FILE_PATH_SIZE);
    	sprintf(file_name,"%s/%s",CFG_DIR_PATH,SYS_CFG_FILE_NAME);
    	cfg_mode = get_read_cfg_mode(file_name,&fd,&file_size);
	/*1 read pkt data dir and protect rules dir */
    	switch (cfg_mode)
    	{
        	case READ_FILE:
            		file_cnt_buf = (char *)malloc(file_size + 1);
            		if (NULL == file_cnt_buf)
            		{
                		error("[Err]Malloc for sys cfg file fail!\n");
                		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Malloc for sys cfg file fail.");
                		return ERR;
            		}

            		if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
	     		{
	         		error("[Err]Get sys cfg file content fail!\n");
	         		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get sys cfg file content fail!");
		  		return ERR;
	     		}
	     		file_cnt_buf[file_size] = '\0';
            		CLOSE_FILE(fd);
            		break;			
        	case DEF_MODE:
        	default:		 
	     		break;
    }

   /*2:get DcAuthServIp */
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_serv_ip(ip,file_cnt_buf))
            {
                error("[Err]Get DcAuthServIp fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get DcAuthServIp name fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            strcpy(ip,DEF_DC_SERV_IP);
	     break;
    }
 //   printf("DcAuthServIp1 = %s \n",ip);
	
   /*3:get DcAuthServPort*/
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_serv_port(port,file_cnt_buf))
            {
                error("[Err]GetDcAuthServPort fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"DcAuthServPort fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            *port= DEF_DC_SERV_PORT;
	     break;
    }
    //printf("port = %d \n ",*port);
    /*get dc work mode */
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_dc_work_mode(WorkMode,file_cnt_buf))
            {
                error("[Err]GetDcWorkMode fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"GetDcWorkMode  fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            *WorkMode= DEF_DC_SERV_PORT;
	     break;
    }
   // printf("get dc work mode = %d \n",*WorkMode);


      /*2:get DcAuthServIp */
    switch (cfg_mode)
    {
        case READ_FILE:
            if (ERR == get_child_process_serv_ip(child_process_ip,file_cnt_buf))
            {
                error("[Err]Get DcAuthServIp fail.\n");
	         write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Get DcAuthServIp name fail!\n");
	         return ERR;
            }
            break;			
        case DEF_MODE:
        default:		 
            strcpy(child_process_ip,DEF_DC_SERV_IP);
	     break;
    }
   FREE(file_cnt_buf);
   return OK;
}
/**********************************
*func name:eAudit exit inform CONNECT_server 
*function:
*parameters:
*call:
*called:
*return:
*/
static int eAudit_Exit_Inform_Connect(unsigned long wmode){
	   char serv_ip1[20],child_ip[20];
	   unsigned long serv_port,work_mode;
	pid_t pid;
	GetConnectServerIpPort(serv_ip1,&serv_port,&work_mode,child_ip);
	if(wmode == 0){   //二合一或者认证模式
	       //printf("exit inform 0x05 \n");
		Socket_Commulication(serv_ip1,serv_port,0x05,wmode);
  		Socket_Inform_Child_Process();
		return OK;
	}
	if(((pid =Read_Connect_Pid())>0)&&((wmode == 1)||(wmode == 2))){
		if (kill((pid_t)pid, SIGNAL_ZERO) == SIGNAL_ZERO){   //存在进程
			/*add socket server commulication*/
		     Socket_Commulication(serv_ip1,serv_port,0x05,wmode);
		}else{
		       Socket_NonBlockCommulication(serv_ip1,serv_port,0x05,wmode);
		}
		if(wmode!=2)
			Socket_Inform_Child_Process();
	}
	return OK;
}
/**********************************
*func name:eAudit exit inform CONNECT_server 
*function:
*parameters:
*call:
*called:
*return:
*/
static int Create_eAudit_File(char **argv){
       int log_pri = LOG_DEBUG;	 
    	 int log_filter_mode = LOG_NOT_FILTER;
    	 int log_tool = LOG_TOOL;
    g_progname = get_progname(argv[0]);
    make_res_dir();
    if (ERR == make_sys_dir(SYS_CFG_SET_PATH))
    {
        error("[Err]Make system config data dir fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Make system config data dir fail!");
        return ERR;
    }
    //DEBUG("make the sys cfg path for save pid etc ok!");
   /*add 2008/07/29*/
    snprintf(s_pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,"EAUDIT");
    if (ERR == create_pid_file(s_pid_file))
    {
        error("[Err]Create SNAM CTL system pid file fail.\n");
        FREE(g_progname);
	 return ERR;
    }   

    if (ERR == reg_pid_to_file(getpid()))
    {
        error("[Err]Reg SNAM CTL process info to pid file fail.\n");
        FREE(g_progname);
        return ERR;
    }
    //printf("create eAudit pid file ok\n");
 
   
    snprintf(s_pid_file,MAX_FILE_PATH_SIZE,"%s/%s.pid",SYS_CFG_SET_PATH,g_progname);
    if (ERR == create_pid_file(s_pid_file))
    {
        error("[Err]Create system pid file fail.\n");
	 write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"Create system pid file fail!\n");
	 return ERR;
    }  
    return OK;
}

/*动态身份认证和监测服务器握手TCP连接*/
/****************************************************************
*******************************************************************
						2009 08 15 
*******************************************************************/
static int eAudit_to_Auth_Shake_Socket()
{
  int sockfd, new_fd;
  socklen_t len;
  struct sockaddr_in my_addr, their_addr;
  unsigned int  listen_num,optval;
  struct linger optval1;
  char serv_ip1[20],child_ip[20];
  unsigned long serv_port,work_mode;
  char addr[16];

  if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
	perror("shake 5799 socket server socket err ");
	exit(1);
  }
  else printf("new socket for 5799 created\n");
  GetConnectServerIpPort(serv_ip1,&serv_port,&work_mode,child_ip);
 //设置SO_REUSEADDR选项(服务器快速重起)
  optval = 0x1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, 4);

  //设置SO_LINGER选项(防范CLOSE_WAIT挂住所有套接字)
  optval1.l_onoff = 1;
  optval1.l_linger = 5;    
  setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &optval1, sizeof(struct linger));

  bzero(&my_addr, sizeof(my_addr));
  my_addr.sin_family = PF_INET;
  my_addr.sin_port = htons(serv_port-1);  

  my_addr.sin_addr.s_addr = inet_addr(child_ip);
 // printf("port = %d serv_ip1= %s \n",serv_port,child_ip);

  
  if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1) {
	printf("shake 5799 socket server bind err \n");
	printf("errno = %d \n",errno);
	exit(1);
  }
  else 
	DEBUG("5798 binded\n");

//设置SO_REUSEADDR选项(服务器快速重起)
//  optval = 0x1;
// setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, 4);

  //设置SO_LINGER选项(防范CLOSE_WAIT挂住所有套接字)
  //optval1.l_onoff = 1;
 // optval1.l_linger = 5;    
//  setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &optval1, sizeof(struct linger));
 
  if (listen(sockfd, listen_num) == -1) {
	printf("shake 5799 socket server listen  err");
	exit(1);
  }
  else 
	DEBUG("begin listen 5799\n");

  while(1) {
	len = sizeof(struct sockaddr);
	if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &len)) == -1) {
	  printf("shake 5799 socket server accept err");
	  exit(errno);
	}
	else
	{
	  bzero(addr,16);
	  memcpy(addr,inet_ntoa(their_addr.sin_addr),16);

	  if(-1 == handle_auth_request(new_fd,addr))
	  	{
	  		close(new_fd);
	  		break;
	  	}
	  close(new_fd);
	}
  }

  close(sockfd);
  return 0;
}

static int  handle_auth_request(int new_fd,const char *addr)
{
  unsigned char buf[MAXBUF],bufx[256];

  int i,len;
  unsigned long crcnum1,crcnum2, tail_crc;
  PSESSION_HDR_ID ps;
  unsigned long * lp;


  /* 开始处理每个新连接上的数据收发 */
  bzero(buf, MAXBUF);
  /* 接收客户端的消息 */
  len = recv(new_fd, buf, MAXBUF, 0);
  if (len > 0)
	DEBUG
	("%d接收消息成功:'%s'，共%d个字节的数据\n", new_fd, buf, len);
  else {
	if (len < 0)
	  DEBUG
	  ("SELF: 消息接收失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
	close(new_fd);
	return 0;
  }
  ps=(PSESSION_HDR_ID)buf;
  if ((ps->opt_code==0x84)||(ps->opt_code==0x85))
	printf("this is my send message %x\n",ps->opt_code);

  ps->version      =  ntohs(ps->version);
  ps->serial       =  ntohl(ps->serial);
  ps->param_length =  ntohl(ps->param_length);
  ps->prt_crc      =  ntohl(ps->prt_crc);


  //printf("flag=%s  version=%d  serial=%d  length=%d opt_code=%x reserv=%x \n",ps->flag, ps->version,ps->serial,ps->param_length,ps->opt_code,ps->reserved);


  // printf("sizeof=%d\n",sizeof(PSESSION_HDR));

  bzero(bufx, 50);
  memcpy(bufx,(char *)ps,sizeof(PSESSION_HDR)-4);

  crcnum1=crc32(0,bufx,sizeof(PSESSION_HDR)-4);

  //printf("crcnum1=%u,  prt_crc=%u\n",crcnum1,ps->prt_crc);

  // printf("ps->parmlength=%d\n",ps->param_length);

  bzero(bufx, 256);
  memcpy(bufx,(char *)ps,sizeof(PSESSION_HDR));

  memcpy((bufx+sizeof(PSESSION_HDR)),(buf+sizeof(PSESSION_HDR)),ps->param_length);

  crcnum2=crc32(0,bufx,sizeof(PSESSION_HDR)+ps->param_length);

  bzero(bufx,4);
  memcpy(bufx,(buf+len-4),4);
  lp=(unsigned long *)&bufx;
  tail_crc=*lp;   

//  printf("crcnum2=%u,  tail_crc=%u\n",crcnum2,tail_crc);

  if ( crcnum1==ps->prt_crc  && crcnum2==tail_crc )
  {
	if  ( !strncmp((char *)ps->flag,"SRTA",4) )
	{  
	  if ( (ps->opt_code==0x04) && (ps->version==0x0100) )
	  {
		//printf("recev tongzi------------------------------\n");
		ps->version=ntohs(ps->version);
		ps->serial=ntohl(ps->serial);
		ps->param_length=4;
		ps->opt_code=0x84;

		bzero(bufx, 50);
		memcpy(bufx,ps,sizeof(PSESSION_HDR)-4);

		crcnum1=crc32(0,bufx,sizeof(PSESSION_HDR)-4);

		ps->prt_crc=crcnum1;

		bzero(bufx, 256);
		memcpy(bufx,ps,sizeof(PSESSION_HDR));

		bzero(buf,10);
		memcpy(bufx+sizeof(PSESSION_HDR),buf,ps->param_length);

		crcnum2=crc32(0,bufx,sizeof(PSESSION_HDR)+ps->param_length);

		memcpy(bufx+sizeof(PSESSION_HDR)+ps->param_length,&crcnum2,4);

		send(new_fd,bufx,sizeof(PSESSION_HDR)+ps->param_length+4,0);

	  }
	  } 
	  if  ( !strncmp((char *)ps->flag,"SRTA",4) )
	  		if ( (ps->opt_code==0x05) && (ps->version==0x0100) ){
				//printf("收到子进程退出命名\n");
				return -1;
				//exit(EXIT_SUCCESS);
	  		}
  	
	  		
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
static int Socket_Inform_Child_Process(){

    int i,sockfd,bytes_read=0;
    PSESSION_HDR pd_data,*pd_data_p=NULL;
    pid_t pid =-1;
    int flag,j,serials,pserials=NULL;
    unsigned short num0,*pNum0=NULL; 
    struct sockaddr_in server_addr; 
    unsigned char szBuf[256];
    unsigned char *pBuf=NULL;
    char *sflag = "STRA";
    char *sflag0 = "12345678";
    char protect_mode,*ppro_mode=NULL;
    char serv_ip1[20],child_ip[20];
   unsigned long serv_port,work_mode;
    pNum0 = &num0;
    num0 = 0x0100;
    pserials = &serials;
    serials = 0;
    ppro_mode = &protect_mode;
    protect_mode =0;

	
    if((sockfd = socket(PF_INET,SOCK_STREAM,0))== -1)
    { 
        error("[Err]Create  inform child process connect client  socket server  err."); 
        return -1;
    }
 
    flag = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
    {
        error("[Err]setsockopt SO_REUSEADDR err.");
	 close(sockfd);
       return -1;
    }
    GetConnectServerIpPort(serv_ip1,&serv_port,&work_mode,child_ip);
  // printf(" inform child process serv_ip = %s  inform child process  serv_port = %d \n",child_ip,serv_port);
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET; 
    if(serv_port == 0)
    	server_addr.sin_port = htons(5798); 
    else 
	server_addr.sin_port = htons(serv_port-1);
  

    if(child_ip ==NULL)
    	server_addr.sin_addr.s_addr =inet_addr("127.0.0.1");
    else 
	server_addr.sin_addr.s_addr =inet_addr(child_ip);

    if(connect(sockfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr)) != 0)
    { 
        error("[Err]connect   inform child process  sever socket err."); 
        close(sockfd);
        return -1;
    }
    memset(szBuf,0,256);
    memset((char *)&pd_data,0,sizeof(PSESSION_HDR));
    pBuf =(char *)&pd_data;
    memcpy((char *)(&pd_data.flag),"SRTA",4);
    pd_data.version = 0x100;
    pd_data.serial=0;
    pd_data.mode = 0;
    pd_data.opt_code = 0x05;
    pd_data.param_length = 8;
    pd_data.reserved =0;
    	
	
    //printf("hdr crc32 = %u\n",crc32(0,pBuf,sizeof(PSESSION_HDR)-4));
	
    pd_data.prt_crc = crc32(0,pBuf,sizeof(PSESSION_HDR)-4);
    memcpy(szBuf,pBuf,sizeof(PSESSION_HDR));

    memcpy(szBuf+sizeof(PSESSION_HDR),"12345678",8);
	
  //  printf("all data crc32 = %u \n",crc32(0,szBuf,sizeof(PSESSION_HDR)+8));
	
    serials =crc32(0,szBuf,sizeof(PSESSION_HDR)+8);
	
    pd_data.version = htons(0x100);
    pd_data.param_length = htonl(8);
    pd_data.prt_crc = htonl(pd_data.prt_crc);

    memset(szBuf,0,256);
    memcpy(szBuf,pBuf,sizeof(PSESSION_HDR));
    memcpy(szBuf+sizeof(PSESSION_HDR),"12345678",8);
    memcpy(szBuf+sizeof(PSESSION_HDR)+8,&serials,4);

   /*发送通知*/
    if(-1 == socket_write(sockfd,szBuf,sizeof(PSESSION_HDR)+8+4)){
		error("[Err]Bind sever socket err."); 
        	close(sockfd);
        	return -1;
   }
close(sockfd);
return 0;
}

