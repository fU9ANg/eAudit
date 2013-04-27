/*************************************************************************************a
* Copyright (c)
* All rights reserved.
* 
* This is unpublished proprietary source code of Shanghai Sail Infomation TEC Co. LTD
*
* The copyright notice above does not evidence any actual or intended
* publication of such source code.
*
* file name:
* file id:
* summary:
* 
* current edition:
* author:daiping
* date:2007-9
*
* history of modification:
*    modificator:
*    date:2009/03/16
*    content:增加了NTP配置文件定义和系统配置信息定义
*
* Copyright (c) 2007
*	
*/
#ifndef _INTERFACE_PUB_H
#define _INTERFACE_PUB_H

#include <sys/types.h>
#include "eAudit_pub.h"


#define SIG_STOP_SNAM_MSG (SIGUSR1+10)   


/****系统各类路径定义*/
#define SNAM_CFG_DIR    "/eAudit/conf"  
#define SNAM_BIN_DIR    "/eAudit/bin"   
#define SNAM_PKTS_DIR   "/data/pkts"  
#define SNAM_CODE_DIR   "/eAudit/code" 
#define SNAM_LOG_DIR    "/log"    
#define SNAM_DATA_DIR   "/data/prodata"  
#define SNAM_RULES_DIR  "/eAudit/rules" 
#define SNAM_RES_DIR    "/eAudit/res"    
#define SNAM_INFO_DIR   "/eAudit/info"   
#define SNAM_BACKUP_DIR     "/eAudit/backup"  
#define SNAM_DEF_CFG_DIR    "/eAudit/default_conf"
#define SNAM_SYS_CFG_DIR    "eAudit/sys"


/*设备序列号文件*/
#define DEV_ID_SET_PATH "/var/lib/eAudit/data"
#define DEV_ID_FILE_NAME "SNAM_DEV_ID.conf"

/*数据库配置相关*/
#define PMC_DB_CONN_CFG_FILE_NAME "eAudit_db_conn.conf"
#define PMC_DB_CONN_CFG_SECT      "DB_CONN_CFG"
#define PMC_CONN_IP_KEY           "IP"
#define PMC_CONN_PORT_KEY         "Port"
#define PMC_CONN_DB_NAME_KEY      "DbName"
#define PMC_CONN_USR_NAME_KEY     "UsrName"
#define PMC_CONN_DB_PASSWORD_KEY "Password"
/*用户列表*/
#define PMC_FLOWCTRL_FILE_NAME "Flow_Control.conf"
#define PMC_FLOWCTRL_SWITCH_IP "Flow_Control_Dev_Ip.conf"
#define PMC_ARP_FILE_NAME    "Arp_Check.conf"
#define PMC_USR_LIST_FILE_NAME "eAudit_Authorize_User.conf"
#define PMC_PROTECT_RESOURCE_FILE_NAME  "eAudit_Protected_Resource.conf"
#define PMC_AUTHORIZE_ACCESS_NETWORK_FILE_NAME "eAudit_Authorize_Access_Network.conf"
#define PMC_AUTHORIZE_ACCESS_CMD_FILE_NAME "eAudit_Authorize_Access_Cmd.conf"
#define PMC_AUTHORIZE_ACCESS_ACCOUNT_FILE_NAME "eAudit_Authorize_Access_Account.conf"
#define PMC_AUTHORIZE_ACCESS_CUSTOM_FILE_NAME "eAudit_Authorize_Access_Custom.conf"
/*定义NTP配置文件*/
#define PMC_NETTIMESYN_FILE_NAME "eAudit_NetTimeSyn_conf.conf"
#define PMC_SECONDTIMESYN_FILE_NAME "eAudit_SecondTimeSyn_conf.conf"
#define PMC_HANDNETTIME_FILE_NAME "eAudit_HandNetTime_conf.conf"
#define PMC_MONITOR_SYS_INFO_FILE_NAME "eAudit_Monitor_Sys_conf.conf"




/*审计方向取值*/
#define UP_DIRECT_CH  '0'
#define DN_DIRECT_CH  '1'
#define ALL_DIRECT_CH '2'
/*保护资源方向定义*/
#define NO_USE			0

#define SMAC 			1
#define DMAC			2
#define SMAC_DMAC   		3

#define SIP				1
#define DIP 				2
#define SIP_DIP			3

#define SPORT			1
#define DPORT			2
#define SPORT_DPORT	 	3

/*transfer type*/
#define TCP				0x06
#define UDP				0x11
#define ICMP                      0x01
/*ethernet type */
#define ARP				0
#define IP				1

#define AND				1
#define OR                         	2
/*port mode define */
#define SINGLE_PORT       				0
#define CONTINUE_PORT  				1
#define INTERVAL_PORT   				2
#define CONTINUE_INTERVAL_PORT 	3

#define MAX_PRO_NAME_SIZE  16   



/*审计级别配置结构*/
typedef struct tagAUDIT_CLASS
{
    int audit_class_id;
    unsigned char audit_class_name[32];
}AUDIT_CLASS,*AUDIT_CLASS_ID;
#define AUDIT_CLASS_SIZE sizeof(AUDIT_CLASS)
/*保护规则列表*/
typedef struct tagRULE_NODE
{
    unsigned long rule_id;
    int pro_id;
    unsigned long id;
    unsigned long ip_addr;
    unsigned long net_mask;
    unsigned short port;
    unsigned char direct;       /*value is:EN_DIRECT*/
    unsigned long net;
    short sq_class;     //授权审计级别
    short wsq_class;    //未授权审计级别
    int rule_group_id;         //资源组I
}RULE_NODE,*RULE_NODE_ID;
#define RULE_NODE_SIZE sizeof(RULE_NODE)

/*网络授权列表结构体定义*/
typedef struct tagEAUDIT_LEVEL{
	unsigned char eaudit_direction;
	unsigned char session_level;
	unsigned char record_level;
	unsigned char event_level;
	unsigned char analysis_level;
	unsigned char total_analysis_level;
	unsigned char custom_made_level;
	unsigned char manage_level;
}EAUDIT_LEVEL,*EAUDIT_LEVEL_ID;
#define eaudit_level_size sizeof(EAUDIT_LEVEL)
/*保护资源列表结构体定义*/

/*保存字符串，以便于后面分析用*/
typedef struct tagSAVE_STRING{
	unsigned char str[512];
}SAVE_STRING,*SAVE_STRING_ID;
#define save_string_size sizeof(SAVE_STRING)

/*三元组结构体定义*/

typedef struct tagCONTINUE_PORT{
	int min_port;
	int max_port;
}CONTINUE_PORTS,*CONTINUE_PORT_ID;
#define continue_port_size sizeof(CONTINUE_PORTS)

typedef struct tagINTERVAL_PORT{
		int port;
}INTERVAL_PORTS,*INTERVAL_PORT_ID;
#define interval_port_size sizeof(INTERVAL_PORTS)

typedef struct tagNOT_AUTHORIZE_EVENT{
	unsigned char block_flag;
	unsigned char warn_flag;
	unsigned char log_flag;
}NOT_AUTHORIZE_EVENT,*NOT_AUTHORIZE_EVENT_ID;
#define not_authorize_event_size sizeof(NOT_AUTHORIZE_EVENT)
/*三元组结构体定义*/
typedef struct tagTHREE_GROUP{
        unsigned long ip;
        unsigned long mask;
        unsigned short single_port;
        INTERVAL_PORT_ID port_id;
        CONTINUE_PORT_ID continue_port_id;
        unsigned char src_port_express;
        unsigned char dst_port_express;
        int  continue_port_num;
        int  interval_port_num;
        key_t continue_port_shm_key;
        key_t interval_port_shm_key;
}HREE_GROUP,*HREE_GROUP_ID;
#define three_group_size sizeof(HREE_GROUP)
typedef struct tagPROTECTED_RESOURCE{
       int res_index;
       unsigned char dispose_object_relation; /*and/or*/
	int mode_switch;    
	int rule_id;
	unsigned char rule_name[256];
        int pro_no;
	char pro_name[32];
	unsigned char use_mac_flag;/*1-smac,2-dmac,3-smac,dmac*/
	unsigned char use_ip_flag; /*1-sip,2-dip,3-sip,dip*/
	unsigned char use_port_flag;/*1-sport,2-dport,3-sport,dport*/
	int transfer_type;		/*0-udp,1-tcp*/
	int ethernet_type;
	HREE_GROUP sip;
	HREE_GROUP dip;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	EAUDIT_LEVEL eaudit_level;
	unsigned char smac[32];
	unsigned char dmac[32];
}PROTECTED_RESOURCE,*PROTECTED_RESOURCE_ID;
#define protected_resource_size sizeof(PROTECTED_RESOURCE)
/*定义ARP信息表*/
typedef struct tagARP_FILTER_INFO{
	int rule_id;
	int pro_id;
}ARP_FILTER_INFO,*ARP_FILTER_INFO_ID;
#define arp_filter_info_size sizeof(ARP_FILTER_INFO)
/* 1     用户列表信息定义*/
/*用户信息列表结构体定义*/
typedef struct tagUSRLISTMEM
{
    unsigned char usr_status;   //用户在线状态 0表示下线 1表示上线
    int iUsrId;				    //用户ID
    unsigned long ip;             //IP地址
    unsigned char strMac[32];              //MAC地址
    unsigned char strUsrName[256]; //用户名
    int iUsrCertifyMethod;
    int Mode_Switch;               
}USR_LIST_MEM,*USR_LIST_MEM_ID;
#define USR_LIST_MEM_SIZE sizeof(USR_LIST_MEM)
/*			2 网络授权结构体定义 */
/*授权关系列表结构体定义*/
typedef struct tagAUTHORIZE_LEVEL{
	unsigned char  authorize_account;
	unsigned char  authorize_cmd;
	unsigned char  authorize_custom_made;
	unsigned char authorize_pro_feature_made;
}AUTHORIZE_LEVEL,*AUTHORIZE_LEVEL_ID;
#define authorize_level_size sizeof(AUTHORIZE_LEVEL)
/*网络授权列表结构体定义*/
typedef struct tagAUTHORIZE_ACCESS_NETWORK{
	unsigned long authorize_id;
	unsigned long usr_id;
	unsigned long protect_resource_id;
	int mode_switch;    
	EAUDIT_LEVEL eaudit_level;
	AUTHORIZE_LEVEL authorize_level;
}AUTHORIZE_ACCESS_NETWORK,*AUTHORIZE_ACCESS_NETWORK_ID;
#define authorize_access_network_size  sizeof(AUTHORIZE_ACCESS_NETWORK)
/* 3 指令授权列表机构体定义*/
	/*定义命令结构体*/
 typedef struct tagAUTHORIZE_CMD_CONTENT{
		unsigned char cmd[128];
}AUTHORIZE_CMD_CONTENT,*AUTHORIZE_CMD_CONTENT_ID;
#define authorize_cmd_content_size sizeof(AUTHORIZE_CMD_CONTENT)
	/*定义授权命令列表结构体定义*/
typedef struct tagAUTHORIZE_CMD{
	int mode_switch;
	unsigned long cmd_num;
	unsigned long authorize_id;
	key_t authorize_cmd_key;
	NOT_AUTHORIZE_EVENT against_authorize_event;
}AUTHORIZE_CMD,*AUTHORIZE_CMD_ID;
#define authorize_cmd_size sizeof(AUTHORIZE_CMD)

/*4 账号授权列表结构体定义*/
typedef struct tagAUTHORIZE_ACCOUNT_CONTENT{
		unsigned char account[128];
}AUTHORIZE_ACCOUNT_CONTENT,*AUTHORIZE_ACCOUNT_CONTENT_ID;
#define authorize_account_content_size sizeof(AUTHORIZE_ACCOUNT_CONTENT)
	/*定义授权账号列表结构体定义*/
typedef struct tagAUTHORIZE_ACCOUNT{
	int mode_switch;
	unsigned long account_num;
	unsigned long authorize_id;
	key_t authorize_account_key;
	NOT_AUTHORIZE_EVENT against_authorize_event;
}AUTHORIZE_ACCOUNT,*AUTHORIZE_ACCOUNT_ID;
#define authorize_account_size sizeof(AUTHORIZE_ACCOUNT)
/* 5 自定义通用授权列表结构体定义*/
typedef struct tagAUTHORIZE_CUSTOM_CONTENT{
		unsigned char custom[128];
}AUTHORIZE_CUSTOM_CONTENT,*AUTHORIZE_CUSTOM_CONTENT_ID;
#define authorize_custom_content_size sizeof(AUTHORIZE_CUSTOM_CONTENT)
	/*自定义授权通用列表结构体定义*/
typedef struct tagAUTHORIZE_CUSTOM{
	int mode_switch;
	unsigned long custom_num;
	unsigned long authorize_id;
	key_t authorize_custom_key;
	NOT_AUTHORIZE_EVENT against_authorize_event;
}AUTHORIZE_CUSTOM,*AUTHORIZE_CUSTOM_ID;
#define authorize_custom_size sizeof(AUTHORIZE_CUSTOM)

/* 6 自定义协议特征授权列表结构体定义*/
typedef struct tagAUTHORIZE_PROTOCOL_FEATURE_CONTENT{
		unsigned char pro_feature_content[256];
}AUTHORIZE_PROTOCOL_FEATURE_CONTENT,*AUTHORIZE_PROTOCOL_FEATURE_CONTENT_ID;
#define authorize_protocol_feature_content_size sizeof(AUTHORIZE_PROTOCOL_FEATURE_CONTENT)
/*协议特征内容数定义*/
typedef struct tagAUTHORIZE_PROTOCOL_FEATURE_TYPE{
		unsigned char authorize_type;
		unsigned long authorize_feature_content_num;
		key_t authorize_protocol_feature_content_key;
}AUTHORIZE_PROTOCOL_FEATURE_TYPE,*AUTHORIZE_PROTOCOL_FEATURE_TYPE_ID;
#define authorize_protocol_feature_type_size sizeof(AUTHORIZE_PROTOCOL_FEATURE_TYPE)
	/*自定义授权协议特征列表结构体定义*/
typedef struct tagAUTHORIZE_PROTOCOL_FEATURE{
	int mode_switch;
	unsigned long pro_feature_num;
	unsigned long authorize_id;
	key_t authorize_protocol_feature_key;
	NOT_AUTHORIZE_EVENT against_authorize_event;
}AUTHORIZE_PROTOCOL_FEATURE,*AUTHORIZE_PROTOCOL_FEATURE_ID;
#define authorize_protocol_feature_size sizeof(AUTHORIZE_PROTOCOL_FEATURE)
/*协议特征参数*/
typedef struct tagPRO_FEATURE_PARA{
	key_t pro_feature_key;
	int pro_feature_num;
        int shm_id;
}PRO_FEATURE_PARA,*PRO_FEATURE_PARA_ID;
#define pro_feature_para_size sizeof(PRO_FEATURE_PARA)

typedef struct tagSRC_INFO{
	unsigned long src_ip;
	unsigned char src_mac[20];
	unsigned short sport;
}SRC_INFO,*SRC_INFO_ID;
#define SRC_INFO_SIZE sizeof(SRC_INFO)

/*目的信息*/
typedef struct tagDST_INFO{
	unsigned long dst_ip;
	unsigned char dst_mac[20];
	unsigned short dport;
}DST_INFO,*DST_INFO_ID;
#define DST_INFO_SIZE sizeof(DST_INFO)

/*重定向端口*/
typedef struct tagREDIRECTION_BASIC_INFO{
	unsigned long rule_id;
	unsigned long pro_id;
	char pro_name[32];
	unsigned char filter_pkt_type;
	unsigned long  ip;
	unsigned short port;
        int mode_switch;
	unsigned long res_index;
}REDIRECTION_BASIC_INFO,*REDIRECTION_BASIC_INFO_ID;
#define REDIRECTION_BASIC_INFO_SIZE sizeof(REDIRECTION_BASIC_INFO)

typedef struct tagREDIRECTION_PORT_INFO{
	unsigned char flag;
	REDIRECTION_BASIC_INFO redirect_info;
}REDIRECTION_PORT_INFO,*REDIRECTION_PORT_INFO_ID;
#define REDIRECTION_PORT_INFO_SIZE sizeof(REDIRECTION_PORT_INFO)
/*定义监控系统信息配置结构体*/
 typedef struct tagMONITOR_SYSINFO{
	int cpu_use_rate;
	int mem_use_rate;
	int hd_use_rate;
}MONITOR_SYSINFO,*MONITOR_SYSINFO_ID;
#define MONITOR_SYSINFO_SIZE sizeof(MONITOR_SYSINFO)
/*定义阻断队列数配置结构体*/
typedef struct tagBLOCK_QUEQUE_NUM{
	unsigned long fst_block_queque_num;
	unsigned long snd_block_queque_num;
	unsigned long block_ip_queque_num;
	unsigned long snd_check_block_queque_num;
}BLOCK_QUEQUE_NUM,*BLOCK_QUEQUE_NUM_ID;
#define BLOCK_QUEQUE_NUM_SIZE sizeof(BLOCK_QUEQUE_NUM)
/*为了授权信息改造工程修改结构FOR 2009/06/09*/
/*the function switch*/
typedef struct tagFUNC_SWITCH
{
    int iAlarmSwitch;
    int iErrSwitch;
    int iStatSwitch;
}FUNC_SWITCH,*FUNC_SWITCH_ID;
#define FUNC_SWITCH_SIZE sizeof(FUNC_SWITCH)

/*packets file set*/
typedef struct tagCFG_FILE_SET
{
    unsigned long maxPktFileSize;   /*每个文件的最大大小*/
    unsigned long maxPktFileNum;
}CFG_FILE_SET,*CFG_FILE_SET_ID;
#define CFG_FILE_SET_SIZE sizeof(CFG_FILE_SET)

/*the que cfg information*/
//#pragma pack(4)
typedef struct tagQUE_INFO
{
    int iQueBlkNum;
    int iQueBlkSize;

    key_t shmKey;
    key_t semKey;
}QUE_INFO,*QUE_ID;
#define QUE_INFO_SIZE sizeof(QUE_INFO)
/* 1 eAudit_sys.conf配置文件结构体定义*/
typedef struct tagEAUDIT_SYS_CONF{
	char NicForManagement[16];
	char PacketsFilesDir[256];
	char ProtectRulesFileDir[256];
	CFG_FILE_SET cfg_file_set;
	unsigned long DepositIntervalSeconds;
	unsigned long MaxProtectRulesNum;
	FUNC_SWITCH func_switch;
	int FlowSwitch;
	int MonitorTimeIntervals;
	int MonitorNum;
	int DynamicProtectResNum;
	struct tagBLOCK_QUEQUE_NUM BlockInfo;
	char DcAuthServIp[20];
	unsigned short DcAuthServPort;
	unsigned  long work_mode;
}EAUDIT_SYS_CONF,*EAUDIT_SYS_CONF_ID;
#define EAUDIT_SYS_CONF_SIZE sizeof(EAUDIT_SYS_CONF)
/*the header info of file*/
typedef struct tagCFG_HEAD
{
    int iNICNum;
    int iPerNICQueNum;
}CFG_HEAD,*CFG_HEAD_ID;
#define CFG_HEAD_SIZE sizeof(CFG_HEAD) 

/*the cfg header info of file*/
#define cfg_file_header_size sizeof(CFG_FILE_HEADER)

/*the NIC basic config info*/
typedef struct tagCFG_NIC_BASIC
{
    char NICName[NICNAMESIZE+1];
    key_t hdQueShmKey;
    key_t hdQueSemKey;
}CFG_NIC_BASIC,*CFG_NIC_BASIC_ID;
#define CFG_NIC_BASIC_SIZE sizeof(CFG_NIC_BASIC)
/* 2 Capture_NIC.conf配置文件结构定义*/
typedef struct tagCAPTURE_NIC_CONF{
	CFG_HEAD cfg_hdr;
	CFG_NIC_BASIC_ID nic_basic_buf;
	QUE_ID cfg_que_info;
}CAPTURE_NIC_CONF,*CAPTURE_NIC_CONF_ID;
#define CAPTURE_NIC_CONF_SIZE sizeof(CAPTURE_NIC_CONF)

typedef struct tagSUPPORT_PRO_NODE
{
    int pro_no;
    char pro_name[MAX_PRO_NAME_SIZE + 1];
    int protect_num;
    int code;
}SUPPORT_PRO_NODE,*SUPPORT_PRO_NODE_ID;
#define SUPPORT_PRO_NODE_SIZE sizeof(SUPPORT_PRO_NODE)
/*配置各个KEY  值和配置数*/
typedef struct tagCONFIG_KEY{
	key_t pro_tbl_shm_key;
	int pro_tbl_shm_id;
	int pro_num;
	
       key_t protected_resources_list_key;
	int protected_resource_list_id;
	int protected_resources_num;
	
	key_t usr_list_key;
	int usr_list_id;
	int usr_all_num;
	
	key_t authorize_account_list_key;
	int authorize_account_id;
	int authorize_account_num;
	
	key_t authorize_cmd_list_key;
	int authorize_cmd_id;
	int authorize_cmd_num;
	
	key_t authorize_custom_list_key;
	int authorize_custom_id;
	int authorize_custom_num;
	
	key_t authorize_network_key;
	int authorize_network_id;
	int authorize_network_num;
	
	key_t  redirect_port_key;
	int redirect_port_shm_id;
	int redirect_port_list_num;
	
	key_t tcpclosequeptr_key;
	int tcpclosequequeptr_shmid;
    	int  tcpclosefirstque_shmid;
    	int tcpclosesecondque_shmid;
   	int ipque_shmid;
	int snd_check_block_shmid;
	key_t tcpclosefirstque_key;
	key_t tcpclosesecondque_key;
	key_t ipque_key;
	key_t snd_check_block_key;
	
	key_t pid_info_shm_key;
	int pid_info_shm_id;
	key_t ip_queque_sem_key;
      	int ip_queque_sem_id;
       
	
	key_t run_cfg_shm_key;
	int run_cfg_shm_id;
	pid_t filter_pid;
	SUPPORT_PRO_NODE_ID pro_tbl_shm_addr;
	PRO_FEATURE_PARA_ID pro_feature_id;
	PROTECTED_RESOURCE_ID protect_res_addr;  
	int UsrNum;
	int ProResNum;
	int Pro_Real_Line;
}CONFIG_KEY,*CONFIG_KEY_ID;
#define CONFIG_KEY_SIZE sizeof(CONFIG_KEY)
//2009 11 03 add flux connection configure
typedef struct tagFLUXCONNECTION{
		int pro_id;
		int flux_num;
		int flux_check_timevals;
		int connect_num;
		int connect_check_timevals;
		NOT_AUTHORIZE_EVENT against_authorize_event;
}FLUXCONECTION,*FLUXCONECTION_ID;
#define FLUXCONNETION_SIZE sizeof(FLUXCONECTION)


/*配置启动基本服务结构体定义*/
 typedef struct tagBASIC_SERV{
	char serv_name[32];
}BASIC_SERV,*BASIC_SERV_ID;
#define BASIC_SERV_SIZE sizeof(BASIC_SERV)

/*动态身份认证网络通信结构体*/
typedef struct tag_SESSION_HDR
{  
    unsigned char  flag[4];
    unsigned short  version;
    unsigned long   serial;
    unsigned char  mode;     
    unsigned char  opt_code;
    unsigned long  param_length;
    unsigned long  reserved;
    unsigned long  prt_crc;
}PSESSION_HDR,*PSESSION_HDR_ID;          /*session head define*/




/*授权关系列表*/
typedef struct tagSQ_LIST_MEM
{
    int iUsrGId;       //用户组ID
    int iRuleGId;      //资源组ID
}SQ_LIST_MEM,*SQ_LIST_MEM_ID;
#define SQ_LIST_MEM_SIZE sizeof(SQ_LIST_MEM)

/*get now seconds*/
#define TIME_GET() time(NULL)

/*parameter direct*/
#define OUT
#define IN

/*1G\1K\1M*/
#define _1K 1024
#define _1M (1024*1024)
#define _1G (1024*1024*1024)

/*can capture packet max size*/
#define MAX_CAP_PKT_SIZE  65535

typedef unsigned char UINT8;
typedef unsigned short UINT16;

/*NIC NAME SIZE*/
#define NICNAMESIZE 16 

/*FIFO pipe path*/
#define SRV_FIFO_PATH "/tmp/eAudit_fifo.srv"
#define FIFO_FILE_MODE 

/*变量地址*/
#define B_PTR(var) ((UINT8 *)(void *)&(var))
#define W_PTR(var) ((UINT16 *)(void *)&(var))

/*pipe fd type*/
typedef enum
{ 
    PIPE_READ = 0, 
    PIPE_WRITE,
    PIPE_DES_NUM
}EN_WR_PIPE; 

/*the name of sys*/
#define SYS_NAME STR(eAudit)

/*sys support protocols dir and file name*/
#define SUPPORT_PRO_DIR_PATH   "/eAudit/sys"      
#define SUPPORT_PRO_FILE_NAME  "eAudit_support_protocols.sys"   
#define SUPPORT_SERV_FILE_NAME "eAudit_support_server.sys"

/*sys config dir and file name*/
#define CFG_DIR_PATH              "/eAudit/conf"      
#define SYS_CFG_FILE_NAME         "eAudit_sys.conf"        
#define CAPTURE_NIC_CFG_NAME      "capture_NIC.conf"          

/*sys protect rules dir and file name*/
#define PROTECT_RULES_DIR_PATH    "/eAudit/rules"
#define PROTECT_RULES_FILE_NAME   "eAudit_protect_rules" 

/*sys work info dir and file name*/
#define SYS_WORK_INFO_DIR_PATH     "/eAudit/info"
#define SYS_WORK_INFO_FILE_NAME    "eAudit_run_info.rd"

/*packets files dir and file name*/
#define PKT_FILE_DIR         "/data/pkts"
#define PKT_WR_NO_FILE_NAME  "file_write_no"
#define PKT_RD_NO_FILE_NAME  "file_read_no"

/*stat file dir and file name*/
#define PKT_STAT_FILE_DIR            "/eAudit/info"
#define CAPTURE_PKT_STAT_FILE_NAME   "_capture.stat"
#define FILTER_PKT_STAT_FILE_NAME    "_filter.stat"

/*process with process par interval*/
#define PAR_DELIM 					"+"   

#define MAX_PROC_NAME_SIZE 64

/*filter and ctl*/
#define MAX_PRO_NUM_SIZE 32

#define STAT_IVL_SECONDS 5
#define STAT_IVL_USEC    3000000

/*pkt fils pcap header default value*/
#define EAUDIT_MAGIC   0xa0b1c2d3
#define EAUDIT_VERSION_MAJOR 1
#define EAUDIT_VERSION_MINOR 0

/*the status of the sys*/
typedef enum{
    SYS_NO_WORK = 0,
    SYS_FOR_READY,	
    SYS_CONFIGING,
    SYS_CFG_OK,
    SYS_START_CF, 
    SYS_START_ANALYSIS,  
    SYS_START_MOT, 
    SYS_RUNNING
}EN_SYS_STATUS;

/*open dir return value*/
typedef enum{
    DIR_IS_NOEXISTS = 0,
    DIR_IS_EMPTY	 = 1,
    DIR_IS_NOEMPTY = 2,
    OPEN_DIR_ERR
}EN_PROC_DIR_RET;

/*the function switch value*/
typedef enum{
    OFF = 0,
    ON
}EN_SWITCH_STAT;




//#pragma pack()

/*资源文件*/
#define MEM_RES_FILE_NAME  STR(MEM_RES)
#define SHM_RES_FILE_NAME  STR(SHM_RES)
#define SEM_RES_FILE_NAME  STR(SEM_RES)
#define FILE_RES_FILE_NAME STR(FILE_RES)
#define ALL_RES_FILE_NAME  STR(ALL_RES)
#define SHM_KEY_RES_FILE_NAME STR(SHM_KEY_RES)

/*the process start mark flg str*/
#define START_MODEL_NAME    STR(start)
#define CAPTURE_MODEL_NAME  STR(capture)
#define FILTER_MODEL_NAME   STR(filter)
#define ANALYZE_MODEL_NAME  STR(analysis)

/*sys hw val*/
#define CAPTURE_FILTER_PROPORTION  0.45
#define PKT_SHM_QUE_PROPORTION     0.2
#define MMAP_FILE_PROPORTION       0.2
#define RULE_PROPORTION            0.2

#define HDD_PROPORTION             0.8

#define ANALYSIS_PROPORTION   0.45

/*str end char*/
#define EOS '\0'

/*full and empty sem ivl*/
#define FULE_SEM_IVL   1
#define EMPTY_SEM_IVL 2

/*macro funtion*/
#define FREE(buf) do{\
    if (NULL != buf){\
        free(buf);\
        buf = NULL;}\
}while(0)

#define DEL_SYS_MSG_QUE(id) do{\
    if (id >= 0){\
        (void)delete_sys_msg_que(id);\
        id = -1;}\
}while(0)

#define DEL_SHM(shmid) do{\
    if (DEF_SHM_ID_VAL != shmid){\
        del_shm(shmid);\
        shmid = DEF_SHM_ID_VAL;}\
}while(0)
        
#define StrNCpy(dst,src,len) do{\
    if (len > 0){\
        strncpy(dst,(src),len);\
        dst[len-1] = '\0'; }\
}while(0)

#define CLOSE_FILE(fd) do{\
    if (DEF_FILE_DES_VAL != fd) {\
        close(fd);\
        fd = DEF_FILE_DES_VAL;}\
}while(0)

#define GET_TEXT(x) (x)
#define _(x) GET_TEXT((x))

#define IS_DIR_SEP(ch) ((ch) == '/')
#define CHKDEC(c) ((c) >= '0' && (c) <= '9')
#define DECFLOW(d) (d = ((d) + 1 > (d)?(d)+1:-1))



/*new read conf*/
typedef struct
{
	int p_type_id;
	int conn_interval;
	int conn_threshold;
	int flux_interval;
	int flux_threshold;
	NOT_AUTHORIZE_EVENT not_authorize_event;
}P_MONITOR_INFO, *P_MONITOR_INFO_ID;
#define P_MONITOR_INFO_SIZE sizeof(P_MONITOR_INFO)


typedef struct
{
	int mode;
	int num;
	int usr_id;
	unsigned long ip;
	char mac[13];
	char user[256];
	int flag;
}P_USER_INFO, *P_USER_INFO_ID;
#define P_USER_INFO_SIZE sizeof(P_USER_INFO)



#endif

