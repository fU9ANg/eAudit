
#ifndef _CTL_MONITOR_H
#define _CTL_MONITOR_H
#include <sys/types.h>
#include "interface_monitor.h"

#define MAX_FILE_PATH_SIZE 512
#define MAX_TIME_OUT            1*60
#define SAIL_OK                       0
#define SAIL_ERR                     -1
#define NOT_EXIST                   0
#define IS_EXIST                      1
#define SIGNAL_ZERO              0
#define MAX_DES_INFO_SIZE     8000
#define MAX_CONN_DB_TIMES    10

#define PROCFS "/proc"
#define PROC_SUPER_MAGIC  0x9fa0
#define PROC_MEMINFO_FILE "/proc/meminfo"
#define PROC_CPUINFO_FILE "/proc/stat"
#define MAX_PROC_FILE_SIZE 4096
#define _DEBUG

enum BOOTFLAG{
	BOOT_SUCCESS=0,
	BOOT_FAIL,
	BOOT_UNSTATE
};

struct occupy       
{ 
        char name[20];      
        unsigned int user; 
        unsigned int nice;  
        unsigned int system;
        unsigned int idle;  
}; 

//extern void get_now_time(char *str_time);
extern int eAudit_Monitor(PID_INFO_ID p,int pid_num,char *pid_file,long monitor_times,MONITOR_SYSINFO_ID monitor_sysinfo_id,long monitor_number,SUPPORT_PRO_NODE_ID pro_items_id1,int pro_num1);
extern unsigned char g_Exit_eAudit_flag;



#define MAX_DB_USR_NAME_SIZE 32
#define MAX_DB_NAME_SIZE     32
#define MAX_PASSWORD_SIZE   64

#define DB_CONN_CFG_SECT            	"DB_CONN_CFG"
#define CONN_IP_KEY                 		"IP"
#define CONN_PORT_KEY               		"Port"
#define CONN_DB_NAME_KEY           	"DbName"
#define CONN_USR_NAME_KEY          	"UsrName"
#define CONN_PASSWORD_KEY			"Password"

#define DEF_DB_CONN_IP              		"127.0.0.1"
#define DEF_DB_PORT		             		5432
#define DEF_DB_CONN_DB_NAME         	"eAudit"
#define DEF_DB_CONN_USR_NAME        	"postgres"

#define DB_CFG_FILE_NAME			"eAudit_db_conn.conf"
#define MAX_STR_IP_LEN					15

#define CFG_BLK_SIZE 				63
#define GET_CFG_VAL_FAIL   			1
#define GET_CFG_VAL_OK     			0

typedef struct tagDB_CFG_INFO
{
	char ip[MAX_STR_IP_LEN+1];
	int port;
	char usr_name[MAX_DB_USR_NAME_SIZE+1];
	char db[MAX_DB_NAME_SIZE+1];
	char password[MAX_PASSWORD_SIZE+1];
}DB_CFG_INFO,*DB_CFG_INFO_ID;
#define DB_CFG_INFO_SIZE sizeof(DB_CFG_INFO)


int read_db_cfg_info(DB_CFG_INFO_ID db_cfg_info_id);
int get_db_cfg_info(DB_CFG_INFO_ID p,char *path);
void get_db_cfg_info_by_def(DB_CFG_INFO_ID p);
int get_db_cfg_info_by_file(DB_CFG_INFO_ID p,const char *file_cnt_buf);

extern int get_eth0_info(char *ip,char* mac);

#endif 

