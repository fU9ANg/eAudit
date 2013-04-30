
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
#include <sys/statfs.h>
#include <locale.h>
#include <limits.h>
#include <sys/time.h>
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
#include <netinet/in.h>
#include  <net/if_arp.h>    
#include  <sys/ioctl.h>
#include  <net/if.h>
#include  <netinet/in.h>

#include <sail_auth.h>
#include "ctl_monitor.h"
#include "interface_monitor.h"
#include "interface_pub.h"
#include "ctl_db.h"
#include "ctl_config.h"
#include "ctl_sys_info.h"

static void DEBUG(const char *fmt, ...);
static int file_is_exist(char* filename);
static int run_chect_process_state(PID_INFO_ID p,int pid_num);
static void boot_chect_process_state(PID_INFO_ID p,int pid_num);
//void get_now_time(char *str_time);
void cal_occupy(struct occupy *, struct occupy *);  
void get_occupy(struct occupy *);    
void get_syscpu_occupy_ratio(); 
int eAudit_Monitor(PID_INFO_ID p,int pid_num,char *pid_file,long monitor_times,MONITOR_SYSINFO_ID monitor_sysinfo_id,long monitor_number,SUPPORT_PRO_NODE_ID pro_items_id1,int pro_num1);
/*define grobal variable */
unsigned char g_Exit_eAudit_flag = 0;
unsigned char g_read_authorize;
unsigned char boot_des_info[MAX_DES_INFO_SIZE];
unsigned char db_des_info[MAX_DES_INFO_SIZE];

unsigned char mem_des_info[MAX_DES_INFO_SIZE];
unsigned char hd_des_info[MAX_DES_INFO_SIZE];
unsigned char cpu_des_info[MAX_DES_INFO_SIZE];
unsigned char log_des_info[MAX_DES_INFO_SIZE];

unsigned char mem_alarm_des_info[MAX_DES_INFO_SIZE];
unsigned char hd_alarm_des_info[MAX_DES_INFO_SIZE];
unsigned char cpu_alarm_des_info[MAX_DES_INFO_SIZE];
unsigned char log_alarm_des_info[MAX_DES_INFO_SIZE];

float g_cpu_used;           
int cpu_num;

long monitor_time;
long tmp_times;

PID_INFO_ID p0;
int pid_num0;
char *pid_file0;
long hd_percent_num =0;
long mem_percent_num =0;
long cpu_percent_num = 0;
long monitor_val= 0;
//int capture_pid =0;
unsigned char timer_time_over_flag = 0;
unsigned char mem_over_flag =0;
unsigned char hd_over_flag= 0;
unsigned char log_over_flag =0 ;
unsigned char cpu_over_flag =0;
#undef _DEBUG
/*log */
#define RECORD_INC_TIME 2


static char *skip_token(const char *p)
{
    while (isspace(*p)) p++;
    while (*p && !isspace(*p)) p++;
    return (char *)p;
}

void check_sys_info(){
    int len;
    int fd;
    unsigned long mem_free_vol = 0;
    unsigned long mem_total_vol = 0;
    unsigned char tmp_info[128];
    unsigned long hw_total_vol=0;
    unsigned long log_total_vol = 0;
    float log_percent_rate = 0.0;
	
    float hd_percent_rate = 0.0;
    struct statfs sb,buf;
    char buffer[MAX_PROC_FILE_SIZE+1];
    char *p;
    float mem_percent_used = 0.0;
    float hw_percent_used = 0.0;
    float log_percent_used = 0.0;

    if (statfs(PROCFS, &sb) < 0 || sb.f_type != PROC_SUPER_MAGIC)
    {
        error("proc filesystem not mounted on PROC");
        return ;
    }

    fd = open(PROC_MEMINFO_FILE, O_RDONLY);
    if (fd < 0)
    {
        error("[ERR]Open proc file fail.\n");
        return ;
    }

    len = read(fd, buffer, sizeof(buffer)-1);
    if (len < 0)
    {
         error("[ERR]Read proc file fail.\n");
         close(fd);
        return ;
    }
    close(fd);
    buffer[len] = '\0';

    p = buffer;
    p = skip_token(p);
    mem_total_vol = strtoul(p, &p, 10);
    p = strchr(p, '\n');
    p = skip_token(p);
    mem_free_vol = strtoul(p, &p, 10);
    mem_percent_used =((float)(mem_total_vol-mem_free_vol))*100/(float)mem_total_vol;
    sprintf((unsigned char *)mem_des_info,"内存总容量:%uKB ,已使用: %.2f %%",mem_total_vol, mem_percent_used);
    if(mem_percent_used>=mem_percent_num)
    {
   		sprintf((unsigned char *)mem_alarm_des_info, "内存已使用: %.2f %, 超过限定值: %d %", mem_percent_used, mem_percent_num);
		mem_over_flag =1;
    }
//////////////////////
    if (statfs("/data",&buf) != 0)
    {
        error("[Err]Can't read the packets files dir HDD info!\n");
        return ;
    }

    hw_total_vol =((float)(buf.f_blocks*4))/(1024*1024);
    hw_percent_used = ((float)(buf.f_blocks - buf.f_bfree)) / (float)buf.f_blocks * 100;
    sprintf((unsigned char *)hd_des_info, "业务日志空间总容量: %dG, 已使用: %.2f %%", hw_total_vol, hw_percent_used);

    hd_percent_rate = hd_percent_num;
    if(hw_percent_used>=hd_percent_rate)
    {
		sprintf((unsigned char *)hd_alarm_des_info, "业务日志空间已使用: %.2f %, 超过限定值: %ld %", hw_percent_used, hd_percent_num);
		hd_over_flag = 1;
    }
    sprintf((unsigned char *)db_des_info,"数据库数据表项空间已使用 %.2f %%",hw_percent_used);

////////////////////////
    if (statfs("/log",&buf) != 0)
    {
        error("[Err]Can't read the log dir HDD info!\n");
        return ;
    }
    log_total_vol =((float)(buf.f_blocks*4))/(1024*1024);
    log_percent_used = ((float)(buf.f_blocks - buf.f_bfree)) / (float)buf.f_blocks * 100;
    sprintf((unsigned char *)log_des_info,"运行日志空间总容量: %dG,已使用: %.2f %%",log_total_vol, log_percent_used);

    if(log_percent_used>=hd_percent_rate)
    {
		sprintf((unsigned char *)log_alarm_des_info, "运行日志空间已使用: %.2f %, 超过限定值: %ld %", log_percent_used, hd_percent_num);
		log_over_flag = 1;
    }    
  
}
static void check_process_status(int sig_no)
{
	//static unsigned long kill_times = 0;
	long tmp1 = 0;
	long tmp2 = 0;

	if(SIGALRM == sig_no)
	{
		//	char cmd[24];
		/*add 2009 11 17 test*/
		//if((kill_times == 3600)&&(capture_pid>0)){
		//	kill_times = 0;
			//sprintf(cmd,"%s%ld","kill -9 ",capture_pid);
			//printf("cmd = %s \n",cmd);
			///system(cmd);
		//}
		//kill_times++;
		/*add 2009 11 17 test*/


//		printf("===============%d\n", tmp_times);

		
		tmp1 = tmp_times % monitor_time;
		tmp2 = tmp_times % 7200;
		tmp_times++;

		if(!tmp1)
			timer_time_over_flag = 1;

		if(!tmp2)
			g_read_authorize = 1;


		if(!tmp1 && !tmp2)
			tmp_times = 0;
	}
	return;
}
/**********************************
*func name: 
*function: 处理主循环退出问题检查
*parameters:
*call:
*called:
*return: return 
*/
void main_process_circle(void)
{
#if 0
	SAIL_AUTH pData_auth;
	SAIL_Analysis_AUTH *pData_analysis=NULL;
	SAIL_Function_AUTH *pData_function=NULL;
	
	pData_analysis = (SAIL_Analysis_AUTH *)calloc(sizeof(SAIL_Analysis_AUTH),100);
	if(pData_analysis == NULL)
		 exit(EXIT_FAILURE);
	 pData_function = (SAIL_Function_AUTH *)calloc(sizeof(SAIL_Function_AUTH),30);
	if(pData_function == NULL)
		 exit(EXIT_FAILURE);
#endif
	while(1)
	{
		usleep(1);
#if 0
		if(g_read_authorize)
		{
		//	printf("=====%d\n", tmp_times);
			if(sail_read_authdata(1, &pData_auth, pData_analysis, pData_function))
			{
				g_Exit_eAudit_flag = 1;
			}
			g_read_authorize = 0;
		}
#endif
		if(g_Exit_eAudit_flag == 1)
			return;
	}
}
/**********************************
*func name: 
*function: 处理定时检查数据
*parameters:
*call:
*called:
*return: return 
*/
void timer_process(void){
	char pid_file_path[512];
       int i;
	FILE *fp = NULL;
	char buf[32+1];
	static char mem_flag = 0;
	static char hd_flag = 0;
	static char cpu_flag = 0;
	static char log_flag = 0;
	static unsigned long count_times =0;

	while(1){
		usleep(1);
//		printf("timer process ov er \n");
		if(timer_time_over_flag == 1){
			timer_time_over_flag=0;
//			printf("pid_num0 = %d\n",pid_num0);
			if(SAIL_ERR == run_chect_process_state(p0,pid_num0))
			{
			       memset(pid_file_path,0x00,512);
				strcpy(pid_file_path,pid_file0);
				//printf("pid_file = %s\n",pid_file_path);
				unlink(pid_file_path);
				  fp = fopen(pid_file_path,"a+b");
    				if (NULL == fp)
        				goto next;
				for(i=0;i<pid_num0;i++){
					if(p0[i].conect_flag ==1)
						continue;
					memset(buf,0x00,33);
					sprintf(buf,"%ld",p0[i].pid);
    					fputs(buf,fp);
   					fputc('\n',fp);
				}	
				 fflush(fp);
				 fclose(fp);
			}
next:

			check_sys_info();
			get_syscpu_occupy_ratio();
//printf("cpu_over_flag:%d cpu_flag:%d \n",cpu_over_flag,cpu_flag);			
			if((mem_over_flag== 1)&&(mem_flag==0)){
				mem_flag = 1;
				if(ESQL_ERR ==write_process_log_into_db((unsigned char *)mem_des_info))
					DEBUG("write snam sysinfo into db fail");
				if(ESQL_ERR ==write_process_alarm_into_db((unsigned char *)mem_alarm_des_info))
					DEBUG("write snam sysinfo into db fail");
				mem_over_flag== 0;
			}
			if((hd_over_flag== 1)&&(hd_flag==0)){
				hd_flag = 1;
				if(ESQL_ERR ==write_process_log_into_db((unsigned char *)hd_des_info))
					DEBUG("write snam sysinfo into db fail");
				if(ESQL_ERR ==write_process_alarm_into_db((unsigned char *)hd_alarm_des_info))
					DEBUG("write snam sysinfo into db fail");
				hd_over_flag== 0;
			}
			if((cpu_over_flag== 1)&&(cpu_flag==0)){
				cpu_flag = 1;
				if(ESQL_ERR ==write_process_log_into_db((unsigned char *)cpu_des_info))
					DEBUG("write snam sysinfo into db fail");
				if(ESQL_ERR ==write_process_alarm_into_db((unsigned char *)cpu_alarm_des_info))
					DEBUG("write snam sysinfo into db fail");
				cpu_over_flag== 0;
			}
			if((log_over_flag == 1)&& (log_flag == 0))
			{
				log_flag = 1;
				if(ESQL_ERR ==write_process_log_into_db((unsigned char *)log_des_info))
					DEBUG("write snam sysinfo into db fail");
				if(ESQL_ERR ==write_process_alarm_into_db((unsigned char *)log_alarm_des_info))
					DEBUG("write snam sysinfo into db fail");
				log_over_flag== 0;
			}
			/**process OK ,20 TIMES wtrite one db**/
			count_times++;
			if(count_times == monitor_val)  /************TWO HOURS CHECK************/
			{
				count_times =0;
				if(mem_flag == 1)
				{
					if(ESQL_ERR ==write_process_log_into_db((unsigned char *)mem_des_info))
						DEBUG("write snam sysinfo into db fail");
					if(ESQL_ERR ==write_process_alarm_into_db((unsigned char *)mem_alarm_des_info))
						DEBUG("write snam sysinfo into db fail");
					mem_flag = 0;
				}
				if(hd_flag == 1)
				{
					if(ESQL_ERR ==write_process_log_into_db((unsigned char *)hd_des_info))
						DEBUG("write snam sysinfo into db fail");
					if(ESQL_ERR ==write_process_alarm_into_db((unsigned char *)hd_alarm_des_info))
						DEBUG("write snam sysinfo into db fail");
					if(ESQL_ERR ==write_process_log_into_db((unsigned char *)db_des_info))
						DEBUG("write process log into db fail");
					hd_flag = 0;
				}
				if(cpu_flag == 1)
				{
					if(ESQL_ERR ==write_process_log_into_db((unsigned char *)cpu_des_info))
						DEBUG("write snam sysinfo into db fail");
					if(ESQL_ERR ==write_process_alarm_into_db((unsigned char *)cpu_alarm_des_info))
						DEBUG("write snam sysinfo into db fail");
					cpu_flag = 0;
				}
				if(log_flag == 1)
				{
					if(ESQL_ERR ==write_process_log_into_db((unsigned char *)log_des_info))
						DEBUG("write snam sysinfo into db fail");
					if(ESQL_ERR ==write_process_alarm_into_db((unsigned char *)log_alarm_des_info))
						DEBUG("write snam sysinfo into db fail");
					log_flag = 0;
				}
			}
		}
	}
}

int eAudit_Monitor(PID_INFO_ID p,int pid_num,char *pid_file,long monitor_times,MONITOR_SYSINFO_ID monitor_sysinfo_id,long monitor_number,SUPPORT_PRO_NODE_ID pro_items_id1,int pro_num1){

	long long now_time=0;
	long long old_time =0;
	DB_CFG_INFO db_cfg_info;
	static unsigned long count_times = 0;
	static unsigned char flag0=0;
	static unsigned char flag1=0;
	pid_t pid;
	int i,j;
	pthread_t thread_proc1,thread_proc2;
	 FILE *fp = NULL;
	// printf("monitor times  = %d \n",monitor_times);
	// printf("monitor_number = %d \n",monitor_number);
	// printf("pid num = %d \n",pid_num);
	 //printf("pid file = %s \n",pid_file);
	// printf("mem rate = %d \n",monitor_sysinfo_id->mem_use_rate);
	 for(i=0;i<pid_num;i++)
	 	printf("p[i].serv_name = %s\n",p[i].exec_path);

	monitor_time = monitor_times;
	struct itimerval value, ovalue;
	value.it_value.tv_sec = 1;
	value.it_value.tv_usec = 0;
	value.it_interval.tv_sec = 1;
	value.it_interval.tv_usec = 0;
	
	signal(SIGALRM, check_process_status);
	setitimer(ITIMER_REAL,&value,&ovalue);

	while(TRUE)
	{
		if(g_Exit_eAudit_flag)
			return SAIL_ERR;	
	// printf("jfasldkjfalsdjflkasdjflasjdflafjl22222\n");
		if(read_db_cfg_info(&db_cfg_info)== ERR)
		{
			INFO("READ DB CINFIG FILE FAIL");
		}
	//printf("jfasldkjfalsdjflkasdjflasjdflafjl3333\n");
	//printf("ip = %s port = %d db = %s db_usr = %s pass = %s \n",db_cfg_info.ip, db_cfg_info.port, db_cfg_info.db, db_cfg_info.usr_name, db_cfg_info.password);
		if(connect_db(db_cfg_info.ip, db_cfg_info.port, db_cfg_info.db, db_cfg_info.usr_name, db_cfg_info.password) == ESQL_OK)
		{
//			write_log(LOG_INFO,FILE_LOG,__FILE__,__LINE__,SINGLE,"Connect to datebase OK");
			break;
		}
		else
		{
//			write_log(LOG_WARNING,FILE_LOG,__FILE__,__LINE__,SINGLE,"Connect to datebase falure");
//			DEBUG("Connect to datebase falure");
			sleep(1);
		}
	}
      //printf("jfasldkjfalsdjflkasdjflasjdflafjl\n");
/****************snam system boot check state*************************/	
	 p0 = p;
        pid_num0 = pid_num;
        pid_file0 = pid_file;
        hd_percent_num = monitor_sysinfo_id->hd_use_rate;
	 mem_percent_num = monitor_sysinfo_id->mem_use_rate;
	 cpu_percent_num = monitor_sysinfo_id->cpu_use_rate;
        monitor_val = monitor_number;
	
	boot_chect_process_state(p,pid_num);
	//printf("111111111111111111111\n");
	if(ESQL_ERR ==write_process_log_into_db((unsigned char *)boot_des_info))
	{
		DEBUG("write first process state log into db fali");
	}
	if((pro_num1>0)&&(pro_items_id1 !=NULL))
		if(ESQL_ERR == write_authorizeinfo_into_db(pro_items_id1,pro_num1)){
			DEBUG("write protocol type info  into db fali");
		}
	//printf("##########################################################\n");
	 check_sys_info();
        get_syscpu_occupy_ratio();


	pthread_create(&thread_proc1,NULL,(void*)main_process_circle,NULL);
	pthread_create(&thread_proc2,NULL,(void*)timer_process,NULL);
	pthread_join(thread_proc1,NULL);
	return SAIL_ERR;	
}
/*name:
*function:
*parameters:
*call:
*called:
*return:
*/
#if 0
void get_now_time(char *str_time)
{
    time_t now;
    struct tm *p;   
 //   char *week[]={"-Sun-","-Mon-","-Tue-","-Wed-","-Thu-","-Fri-","-Sat-"};

    time(&now);
    p = localtime(&now);

    sprintf(str_time,"%04d-%02d-%02d %d:%d:%d",1900+p->tm_year,1+p->tm_mon,\
	 p->tm_mday,p->tm_hour, p->tm_min, p->tm_sec);
}
#endif
static void boot_chect_process_state(PID_INFO_ID p,int pid_num){
       int boot_flag=0;
	int i;
	
	for(i=0;i<pid_num;i++){
		if (kill((pid_t)p[i].pid, SIGNAL_ZERO) != SIGNAL_ZERO)
			boot_flag++;
	}
	
	if(boot_flag ==0){ 
		strcpy((unsigned char *)boot_des_info,"SNAM系统启动成功!");
	}
	else{ 
		strcpy((unsigned char *)boot_des_info,"SNAM系统启动失败!");
	}
}

static int run_chect_process_state(PID_INFO_ID p,int pid_num){
		int i;
		pid_t pid;
		char wk_info_file[1024];
		unsigned char proccess_flag = 0;
		
		for(i=0;i<pid_num;i++){
			/*add 2009 11 17 test*/
		//	if(i==0){
		//		capture_pid =p[i].pid;
		//	}
			/*add 2009 11 17 test*/
			if (kill((pid_t)p[i].pid, SIGNAL_ZERO) != SIGNAL_ZERO){
				if(g_Exit_eAudit_flag == 1){
					printf("start stop eAudit ,do not restart process #############\n");
					continue;
				}	
				proccess_flag =1;
				pid = fork();
				switch(pid){
					case -1:
           					 break;
        				case 0: 
						 if(p[i].para_flag == 1)
            						execl(p[i].exec_path,(char *)p[i].parameter,(char *)0);
						 else
						 	execl(p[i].exec_path,(char *)0,(char *)0);
            					error("[Err]Start  %s process Fail.\n", p[i].exec_path);
						//sprintf(wk_info_file,"%s/%s",SYS_WORK_INFO_DIR_PATH,SYS_WORK_INFO_FILE_NAME);
						 //(void)record_sys_work_info(wk_info_file,"restart protocol process @@@@.",\
                                                     // RECORD_INC_TIME); 
          					exit(EXIT_FAILURE);
            					break;
        				default:
							p[i].pid = pid;
						break;
				}
				usleep(100);
			}
		}
		if(proccess_flag ==1)
			return SAIL_ERR;
	return SAIL_OK;							
}

static int file_is_exist(char* filename){
	if(NULL==filename)
		return NOT_EXIST;
	if(0==access(filename,F_OK))
		return IS_EXIST;
	else
		return NOT_EXIST;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void DEBUG(const char *fmt, ...)
{
#ifdef _DEBUG
    va_list ap;

    (void)fprintf(stderr, "[DEBUG]%s:", "SNAM_DEAMON");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {	
        fmt += strlen(fmt);
	 if (fmt[-1] != '\n')
	    (void)fputc('\n', stderr);
    }
#endif
    return;
}
/**************************get cpu occupy ratio *********************************************/
void get_syscpu_occupy_ratio()                  
{ 
  struct occupy ocpu[10];    
  struct occupy ncpu[10];   
  int i;                   
   unsigned char info[64];
   float all_cpu_use_rate = 0.0;
   float average_cpu_use_rate = 0.0;
  cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
  for(;;)                                   
  {   
      sleep(1);                              
      get_occupy(ocpu);                     
      sleep(1);                              
      get_occupy(ncpu);                      
      for (i=0; i<cpu_num; i++)             
      { 
              cal_occupy(&ocpu[i], &ncpu[i]); 
              sprintf((unsigned char *)cpu_des_info," cup%d占有率 = %.2f % \n",i, g_cpu_used);  
		all_cpu_use_rate +=g_cpu_used;
      } 
      average_cpu_use_rate =(float) (all_cpu_use_rate/cpu_num);
      if(average_cpu_use_rate>=cpu_percent_num)
      {
         	sprintf((unsigned char *)cpu_alarm_des_info, "cpu已使用: %.2f %, 超过限定值: %ld %",  average_cpu_use_rate, cpu_percent_num);
	  	cpu_over_flag =1;
      	}
      break;
  } 
} 
/************************calc cpu occupy ratio****************************************/
void cal_occupy(struct occupy * o, struct occupy * n)
{ 
    double od, nd;   
    double id, sd;  
    double scale;   
    od = (double) (o->user + o->nice + o->system +o->idle);
    nd = (double) (n->user + n->nice + n->system +n->idle);
    scale = 100.0 / (float)(nd-od);       
    id = (double) (n->user - o->user);    
    sd = (double) (n->system - o->system);
    g_cpu_used = ((sd+id)*100.0)/(nd-od); 
} 
/*********************get cpu occupy ratio *****************************************/
void  get_occupy (struct occupy *o) 
{ 
    FILE *fd;         
    int n;            
    char buff[10000];  
                                                                                                               
   if((fd = fopen (PROC_CPUINFO_FILE,"r"))<=0)
	DEBUG("file open fail");
    for(n=0;n<cpu_num;n++)          
    { 
      fgets (buff, sizeof(buff),fd);
      sscanf (buff, "%s %u %u %u %u", &o[n].name, &o[n].user, &o[n].nice,&o[n].system, &o[n].idle); 
    } 
   fclose(fd);     
}  

int connect_db(const char *host, const int port, const char *database, const char *user, const char *password)
{
	if(password != NULL && password[0] == 0x00)
	{
		password = NULL;
	}
	if ((host != NULL) && (port != 0) && (database!= NULL ) && (user != NULL) && (password != NULL))
	{
		if(ESQL_OK == conn_db( host, port, database, user, password))
		{
			INFO("Connect Database %s OK.", host);
			return ESQL_OK;
		}
	}

	if(ESQL_OK == conn_local_db())
	{
		INFO("Connect Local Database OK.");
		return ESQL_OK;
	}
	DEBUG("Connect to datebase falure");
	return ESQL_ERR;
}



int read_db_cfg_info(DB_CFG_INFO_ID db_cfg_info_id)
{
	char db_cfg_path[MAX_FILE_PATH_SIZE + 1];
	sprintf(db_cfg_path,"%s/conf/%s","/eAudit", DB_CFG_FILE_NAME);

	return get_db_cfg_info(db_cfg_info_id,db_cfg_path);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_db_cfg_info(DB_CFG_INFO_ID p,char *path)
{
	int ret;
	int fd = -1;
	unsigned long file_size = 0;
	char *file_cnt_buf = NULL;
	int mode;

	if (NULL == path)
	{
		get_db_cfg_info_by_def(p);
		return OK;
	}
      
	mode = get_read_cfg_mode(path,&fd,&file_size);
	if (DEF_MODE == mode)
	{
		get_db_cfg_info_by_def(p);
		return OK;
	}
    
	if (READ_FILE == mode)
	{
		file_cnt_buf = malloc(file_size + 1);
		if (NULL == file_cnt_buf)
		{
			close(fd);
			return ERR;
		}
        
		if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
		{
			close(fd);
			return ERR;
		}

		file_cnt_buf[file_size] = '\0';
		ret = get_db_cfg_info_by_file(p,file_cnt_buf);
		free(file_cnt_buf);
		close(fd);
		return ret;
	}

    return ERR;     
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_db_cfg_info_by_def(DB_CFG_INFO_ID p)
{
	strncpy(p->ip,DEF_DB_CONN_IP, MAX_STR_IP_LEN);
	p->ip[MAX_STR_IP_LEN] = '\0';
	p->port = DEF_DB_PORT;
	strncpy(p->db,DEF_DB_CONN_DB_NAME, MAX_DB_NAME_SIZE);
	p->db[MAX_DB_NAME_SIZE] = '\0';
	strncpy(p->usr_name,DEF_DB_CONN_USR_NAME, MAX_DB_USR_NAME_SIZE);
	p->usr_name[MAX_DB_USR_NAME_SIZE] = '\0';
	p->password[0] = '\0';
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_db_cfg_info_by_file(DB_CFG_INFO_ID p,const char *file_cnt_buf)
{
	int ret;
	char *tmp_buf = (char *)file_cnt_buf;
	char key_val[CFG_BLK_SIZE+1];    
    
	ret = cfg_get_key_val(tmp_buf,DB_CONN_CFG_SECT,CONN_IP_KEY,key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get DB CFG ip err.\n");
		return ERR;
	}else
	{
		strncpy(p->ip,key_val, MAX_STR_IP_LEN);
		p->ip[MAX_STR_IP_LEN] = 0x00;
	}
	ret = cfg_get_key_val(tmp_buf,DB_CONN_CFG_SECT,CONN_PORT_KEY,key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get DB CFG port err.\n");
		return ERR;
	}else
	{
		p->port = atoi(key_val);
	}
	ret = cfg_get_key_val(tmp_buf,DB_CONN_CFG_SECT,CONN_DB_NAME_KEY,key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get DB CFG dbname err.\n");
		return ERR;
	}else
	{
		strncpy(p->db,key_val, MAX_DB_NAME_SIZE);
		p->db[MAX_DB_NAME_SIZE] = 0x00;
	}
	ret = cfg_get_key_val(tmp_buf,DB_CONN_CFG_SECT,CONN_USR_NAME_KEY,key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get DB CFG usrname err.\n");
		return ERR;
	}
	else
	{
		strncpy(p->usr_name,key_val, MAX_DB_USR_NAME_SIZE);
		p->usr_name[MAX_DB_USR_NAME_SIZE] = 0x00;
	}
	
	ret = cfg_get_key_val(tmp_buf, DB_CONN_CFG_SECT, CONN_PASSWORD_KEY, key_val, CFG_BLK_SIZE+1);
	if(GET_CFG_VAL_FAIL == ret)
	{
		p->password[0] = '\0';
	}
    	else
   	{
	 	strncpy(p->password,key_val, MAX_PASSWORD_SIZE);
		p->password[MAX_PASSWORD_SIZE] = 0x00;
    	}

	return OK; 
}

int get_eth0_info(char *ip,char* mac)
{
#if 0
#include  <stdio.h>      
#include  <sys/types.h>      
#include  <sys/param.h>      
 
#include  <sys/ioctl.h>      
#include  <sys/socket.h>      
#include  <net/if.h>      
#include  <netinet/in.h>      
#include  <net/if_arp.h>      
#include  <arpa/inet.h>  
#include  <unistd.h>  //for  close()  
#endif
 
#define  MAXINTERFACES      16      
 
	int  fd,  intrface,  retn  =  0;      
	struct  ifreq  buf[MAXINTERFACES];      
	struct  arpreq  arp;      
	struct  ifconf  ifc;      
 
	if  ((fd  =  socket(AF_INET,  SOCK_DGRAM,  0))  >=  0)  
	{  
		ifc.ifc_len  =  sizeof(buf);      
		ifc.ifc_buf  =  (caddr_t)  buf;      
		if  (!ioctl(fd,  SIOCGIFCONF,  (char  *)  &ifc))  
		{  
			intrface  =  ifc.ifc_len  /  sizeof(struct  ifreq);    
//			printf("interface  num  is  intrface=%d\n\n\n",  intrface);      
			
			while  (intrface--  >  0)  
			{  
//				printf("net  device  %s\n",  buf[intrface].ifr_name);      
				if(strcmp(buf[intrface].ifr_name,"eth0") != 0)
					continue;
				/*Jugde  whether  the  net  card  status  is  promisc    */      
				if  (!(ioctl(fd,  SIOCGIFFLAGS,  (char  *)  &buf[intrface])))  
				{  
					if  (buf[intrface].ifr_flags  &  IFF_PROMISC)  
					{  
//						puts("the  interface  is  PROMISC");      
						retn++;  
					}  
				}  
//				else  
//				{  
//					char  str[256];      
//					sprintf(str,  "cpm:  ioctl  device  %s", buf[intrface].ifr_name);      
//					perror(str);  
//				}      
 
				/*Jugde  whether  the  net  card  status  is  up                  */      
//				if  (buf[intrface].ifr_flags  &  IFF_UP)  
//				{  
//					puts("the  interface  status  is  UP");  
//				}  
//				else  
//				{  
//					puts("the  interface  status  is  DOWN");  
//				}      
 
				/*Get  IP  of  the  net  card  */      
				if  (!(ioctl(fd,  SIOCGIFADDR,  (char  *)  &buf[intrface])))  
				{  
//					puts("IP  address  is:");      
//					puts(inet_ntoa(((struct  sockaddr_in  *)(&buf[intrface].ifr_addr))->sin_addr)); 
					sprintf(ip,"%s",inet_ntoa(((struct  sockaddr_in  *)(&buf[intrface].ifr_addr))->sin_addr));
//					puts("");      
					//puts  (buf[intrface].ifr_addr.sa_data);      
				}  
//				else  
//				{  
//					char  str[256];      
// 
//					sprintf(str,  "cpm:  ioctl  device  %s",  buf[intrface].ifr_name);      
 //
//					perror(str);  
//				}      
                                                 
 
				/*Get  HW  ADDRESS  of  the  net  card  */      
				if  (!(ioctl(fd,  SIOCGIFHWADDR,  (char  *)  &buf[intrface])))  
				{  
//					puts("HW  address  is:");      
 
//					printf("%02x:%02x:%02x:%02x:%02x:%02x\n",  
//						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[0],    
//						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[1],  
//						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[2],    
//						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[3],    
//						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[4],    
//						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[5]);  
					sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X",  
						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[0],    
						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[1],  
						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[2],    
						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[3],    
						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[4],    
						(unsigned  char)  buf[intrface].ifr_hwaddr.sa_data[5]); 
//						puts("");      
//						puts("");  
				}  
//				else  
//				{  
//					char  str[256];      
// 
//					sprintf(str,  "cpm:  ioctl  device  %s",  buf[intrface].ifr_name);      
// 
//					perror(str);  
//				}  
			}  
		}  
//		else  
//			perror("cpm:  ioctl");  
	}  
//	else  
//		perror("cpm:  socket");      
 
	close(fd);      
	return  retn;  
}


