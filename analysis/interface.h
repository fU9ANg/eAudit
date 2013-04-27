/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_INTERFACE_H
#define ANALYZE_INTERFACE_H

#include <sys/types.h>MAX_MODEL_NAME_SIZE
#include <signal.h>

#define PAR_DELIM					    "+"
#define MAX_STR_IP_LEN					15
#define MAX_DB_NAME_LEN					63
#define MAX_DB_USRNAME_LEN				127
#define MAX_DB_PASSWD_LEN				15
#define U_LONG_SIZE  					31


#define MAX_PRO_NAME_SIZE				16


#define MAX_PROGRAM_NAME_SIZE				31
#define MAX_PROTOCOL_NAME_SIZE 				31
#define ETHERNET_HEADER_LEN				14
#define PKT_FILE_SUFFIX					".pdat"
#define PKT_FILE_TMP_SUFFIX				".tmp"
#define PKT_RD_NO_FILE_NAME 				"file_read_no"
#define ANALYZE_PROC_SUFFIX  				"_analysis"

/* Definitions const for eAudit_Level */
#define SESSION_LEVEL					0x01
#define RECORD_LEVEL					0x02
#define EVENT_LEVEL					0x04
#define DETAIL_LEVEL					0x08
#define TOTAL_ANALYZE_LEVEL				0x10
#define CUSTOM_LEVEL					0x20
#define MANAGE_LEVEL					0x40


#define NORMAL_INTO_DB					0
#define ABNORMAL_INTO_DB				1


#define AUTHORIZE_NETWORK_INFO				0x01
#define AUTHORIZE_NOT_NETWORK_INFO			0x02		
#define AUTHORIZE_CMD_INFO				0x04
#define AUTHORIZE_ACCOUNT_INFO				0x08
#define AUTHORIZE_CUSTOM_INFO				0x10
#define AUTHORIZE_FEATURE_INFO				0x20							


#define BLOCK_HANDLE					0x40
#define LOG_HANDLE					0x80
#define ALARM_HANDLE					0x100


#define MAX_PKT_CNT_SIZE				1514

#define ESQL_OK 	    				0  
#define ESQL_ERR    					-1
#define MAC_ADDRESS_SIZE				6
#define MAX_STR_MAC_LEN					31
#define WR_PKT_FILE_FLAGS				(O_RDWR | O_CREAT)
#define RD_PKT_FILE_FLAGS				(O_RDONLY | O_CREAT)
#define TC_PKT_FILE_FLAGS				(O_RDWR | O_CREAT | O_TRUNC) 

#define FILE_NOT_EXIST 					0
#define FILE_EXIST 					1
#define OK            					0
#define ERR          					-1

#define TRUE						1
#define FALSE						0

#define FILE_LOG       					1
#define DB_LOG        			 		2
#define SYS_LOG        					3

#define LOG_NOT_FILTER 					-1
#define LOG_NOT_RECORD 					0

#define FILTER_LOG_PRI					LOG_NOTICE

#define SINGLE						0
#define MULTITASK					1


#define LINE_MAX_SIZE  					63
#define TIME_STR_SIZE  					31

/* Definitions const for Authorize_Level */
#define NETWORK						0
#define ACCOUNT						1
#define CMD						2
#define CUSTOM						3
#define FEATURE						4

/*对应级别日志的存放类型*/
#define MAX_LOG_FILE_SIZE   				1024*1024*512
#define LOG_PATH_SIZE  					511

#define LOG_DIR_PATH      				"/log"
#define DEBUG_LOG_FILE_NAME     			"debug_log.dat"
#define INFO_LOG_FILE_NAME      			"info_log.dat"
#define WARN_LOG_FILE_NAME      			"warn_log.dat"
#define ERR_LOG_FILE_NAME       			"err_log.dat"
#define FATAL_LOG_FILE_NAME     			"fatal_log.dat"

#define MAX_MODEL_NAME_SIZE				31


#define DB_ADDRESS					"127.0.0.1"
#define DB_PORT 					5432
#define DB_NAME						"eAudit"
#define DB_USRNAME					"postgres"
#define MAX_CONN_DB_TIMES         			3
#define CONN_DB_FAIL_SLEEP_SEC 				1

#define EAUDIT_DIR_PATH					"/eAudit"

#define PKT_HIT_SRC					0
#define PKT_HIT_DST					1
#define PKT_HIT_SRC_DST					2
/* 定义TCP 连接状态*/
typedef enum 
{
	TCP_SYN=0x02,
	TCP_SYN_ACK=0x12,
	TCP_ACK=0x10,
	TCP_FIN	=0x01,
	TCP_RST=0x04,		/*带缓冲复位0001,0100B*/
	TCP_RST1=0x0c,       	/*TCP连接紧急复位0000,0100B*/
	DEF_STATE
}EN_TCP_PKT_BASE_TYPE;

typedef enum
{
	DN_DIRECT = 0, 
	UP_DIRECT = 1,
	ALL_DIRECT = 2 
}EN_EAUDIT_DIRECT;


typedef enum
{
	FULL_MATCH_MODE= 0,
	SUBSTRING_MATCH_MODE
}AUTHORIZE_MATCH_MODE;


/*保护资源方向定义*/
#define NO_USE			0

#define SMAC 			1
#define DMAC			2
#define SMAC_DMAC   		3

#define SIP			1
#define DIP 			2
#define SIP_DIP			3

#define SPORT			1
#define DPORT			2
#define SPORT_DPORT	 	3

/*transfer type*/
#define TCP			0x06
#define UDP			0x11
#define ICMP                    0x01

/*ethernet type */
#define ARP			0
#define IP			1

#define AND			1
#define OR                      2

/*port mode define */
#define SINGLE_PORT       	0
#define CONTINUE_PORT  		1
#define INTERVAL_PORT   	2
#define CONTINUE_INTERVAL_PORT 	3

#define MAX_FILE_PATH_SIZE	511
#define MAX_USR_NAME_SIZE	255

#define MAX_RES_NAME_SIZE	255

#define AUTH_STATE_SIZE		31
#define AUTH_INFO_DES_SIZE	127
#define EAUDIT_INFO_DES_SIZE	127

#define BIZ_ACCOUNT_SIZE	255


#define MAX_LOGIN_USER_NAME_SIZE	63
#define DETAIL_RECORD_LEN	(1024*1024)
#define RECORD_DATA_LEN		(1024*1024)



#define EVENT_UNKNOWN		0
#define EVENT_LOGIN		1
#define EVENT_LOGOUT		2
#define EVENT_UPLOAD		3
#define EVENT_DOWNLOAD		4
#define EVENT_RENAME		5
#define EVENT_NEWCREAT		6
#define EVENT_RECEIVEMAIL	7
#define EVENT_SENDMAIL		8
#define EVENT_REMOVE		9
#define EVENT_HTTPACCESS	10

#define PRO_TYPE_HTTP		0
#define PRO_TYPE_FTP		1
#define PRO_TYPE_SMTP		2
#define PRO_TYPE_POP3		3

#define RESULT_FAIL		0
#define RESULT_SUCCESS		1

#define MAX_CMD_TBL_NUM		100

#define FILE_DATA_PATH		"/data/prodata"



/* 定义ARP信息表 */
typedef struct tagARP_FILTER_INFO
{
	int rule_id;
	int pro_id;
}ARP_FILTER_INFO,*ARP_FILTER_INFO_ID;
#define ARP_FILTER_INFO_SIZE sizeof(ARP_FILTER_INFO)


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
    short sq_class;     /*授权审计级别*/
    short wsq_class;    /*未授权审计级别*/
    int rule_group_id;         /*资源组I*/
}RULE_NODE,*RULE_NODE_ID;
#define RULE_NODE_SIZE sizeof(RULE_NODE)


typedef struct tagSAVE_STRING {

	unsigned char 	str[512];

}	save_string, 	*save_string_id,		\
	SAVE_STRING, 	*SAVE_STRING_ID;
#define SAVE_STRING_SIZE sizeof(SAVE_STRING)
#define save_string_size sizeof(save_string)


/*
 *  From here is begin.
 *  Definitions for the eaudit, authorize and certify
 */
typedef struct tagCONTINUE_PORT {

	int	min_port;
	int	max_port;

}	continue_ports, *continue_port_id,		\
	CONTINUE_PORTS, *CONTINUE_PORT_ID;
#define CONTINUE_PORTS_SIZE sizeof(CONTINUE_PORTS)
#define continue_ports_size sizeof(continue_ports)


typedef struct tagINTERVAL_PORT {

	int	port;

}	interval_ports, *interval_port_id,		\
	INTERVAL_PORTS, *INTERVAL_PORT_ID;
#define INTERVAL_PORTS_SIZE sizeof(INTERVAL_PORTS)
#define interval_ports_size sizeof(interval_ports)


/* 未授权事件 */
typedef struct tagNOT_AUTHORIZE_EVENT {

	unsigned char	block_flag;		/* 1/0 (YES/NO) for block */
	unsigned char	warn_flag ;		/* 1/0 (YES/NO) for warn  */
	unsigned char	log_flag  ;		/* 1/0 (YES/NO) for log	  */

}	not_authorize_event, *not_authorize_event_id,	\
	NOT_AUTHORIZE_EVENT, *NOT_AUTHORIZE_EVENT_ID;
#define NOT_AUTHORIZE_EVENT_SIZE sizeof(NOT_AUTHORIZE_EVENT)
#define not_authorize_event_size sizeof(not_authorize_event)


/* 审计级别 */
typedef struct tagEAUDIT_LEVEL {
	/* 
 	 *  if 1 then yes.
	 *  else if 1 then no.
	 */
	unsigned char	eaudit_direction;	/* 0上行；1下行；2上下行 */
	unsigned char 	session_level;
	unsigned char 	record_level;
	unsigned char 	event_level;
	unsigned char 	analysis_level;
	unsigned char 	total_analysis_level;
	unsigned char 	custom_made_level;
	unsigned char 	manage_level;

}	eaudit_level,	*eaudit_level_id,		\
	EAUDIT_LEVEL,	*EAUDIT_LEVEL_ID;
#define EAUDIT_LEVEL_SIZE sizeof(EAUDIT_LEVEL)
#define eaudit_level_size sizeof(eaudit_level)


typedef struct tagTHREE_GROUP {

        unsigned long	  ip;
        unsigned long	  mask;
        unsigned short	  single_port;
        INTERVAL_PORT_ID  port_id;
        CONTINUE_PORT_ID  continue_port_id;
        unsigned char 	  src_port_express;
        unsigned char 	  dst_port_express;
        int  		  continue_port_num;
        int  		  interval_port_num;
        key_t 		  continue_port_shm_key;
        key_t 	  	  interval_port_shm_key;

}	hree_group, *hree_group_id,			\
	HREE_GROUP, *HREE_GROUP_ID;
#define HREE_GROUP_SIZE sizeof(HREE_GROUP)
#define hree_group_size sizeof(hree_group)


/*
 * For an eAudit_Protected_Resource.conf config file.
 *
 * Format: protected_resource_infomation/unauthorize_event/eaudit_level
 * protected_resource_infomation:
 * 	   rule_id + rule_name + ethernet_type + transfer_type + 
 * 	   howto   + dispose_object_relation   + protocol_name .
 * Example:
 *		[COMMON]
 *		LIST_NUM=1;
 *		MODE_GETE=OFF;
 *		[LIST_INFO]
 *		INFO0=ftp+3+1+1+224+2+2#20,21+2+2#20,21+FTP/0+1+1/2+1+1+1+1+0+0+0;
 *		INFO0=http+1+1+1+224+0+1#80+0+1#80+HTTP/0+1+1/2+1+1+1+1+0+0+0;
 */
typedef struct tagPROTECTED_RESOURCE {

	int 		mode_switch;			/* ON/OFF */
       	int 		res_index;			/* Resource id */
	int		ethernet_type;			/* ARP/RARP/IP */
	int		transfer_type;			/* UDP/TCP/UDP+TCP */

       	unsigned char	dispose_object_relation; 	/* and/or */
        unsigned char   use_mac_flag;                   /* SMAC/DMAC/SMAC+DMAC */
        unsigned char   use_ip_flag;                    /* SIP/DIP/SIP+DIP  */
        unsigned char   use_port_flag;                  /* SPORT/DPORT/SPORT+DPORT */

	int 		rule_id;
	unsigned char 	rule_name[256];
	int 		pro_no;				/* Application Level Protocol. such as: */
	char 		pro_name[32];			/* HTTP/FTP/SMTP/POP ... */
	unsigned char	smac[32];			/* Source MAC Address */
	unsigned char	dmac[32];			/* Dest MAC Address */
	HREE_GROUP	sip;
	HREE_GROUP	dip;

	NOT_AUTHORIZE_EVENT unauthorize_event;
	EAUDIT_LEVEL 	    eaudit_level;

}	protected_resource, *protected_resource_id,	\
	PROTECTED_RESOURCE, *PROTECTED_RESOURCE_ID;
#define PROTECTED_RESOURCE_SIZE sizeof(PROTECTED_RESOURCE)
#define protected_resource_size sizeof(protected_resource)


/*
 * 1.) 用户列表信息定义
 */
/*
 * For an eAudit_Authorize_User.conf config file.
 *
 * Format: User_id + User_ip + User_mac + User_name + CertifyMethod
 * Example:
 *		[COMMON]
 *		LIST_NUM=1;
 *		MODE_GETE=OFF;
 *		[LIST_INFO]
 *		INFO0=32+192.168.10.192+FFFFFFFFFFFF+bnL+0;
 * 		INFO1=78+192.168.10.183+000000000000+fxg+1;
 */
typedef struct tagUSRLISTMEM {

	unsigned char	usr_status;		/* 用户在线状态 0表示下线 1表示上线 */
	int		iUsrId;			/* UserID */
	unsigned long	ip;			/* IP Address */
	unsigned char	strMac[32];	 	/* MAC Address */
	unsigned char	strUsrName[256];	/* Username */
	int		iUsrCertifyMethod;	/* 0-IP, 1-MAC, 2-IP+MAC, 3-Dynamic */
	int		Mode_Switch;		/* ON/OFF */
               
}	usr_list_mem,	*usr_list_mem_id,	\
	USR_LIST_MEM,	*USR_LIST_MEM_ID;
#define USR_LIST_MEM_SIZE sizeof(USR_LIST_MEM)
#define usr_list_mem_size sizeof(usr_list_mem)


/*
 * 2.) 网络授权结构体定义
 */
/* 授权关系列表结构体定义 */
typedef struct tagAUTHORIZE_LEVEL {

	unsigned char	authorize_account;
	unsigned char	authorize_cmd;
	unsigned char	authorize_custom_made;
	unsigned char	authorize_pro_feature_made;

}	authorize_level,*authorize_level_id,	\
	AUTHORIZE_LEVEL,*AUTHORIZE_LEVEL_ID;
#define AUTHORIZE_LEVEL_SIZE sizeof(AUTHORIZE_LEVEL)
#define authorize_level_size sizeof(authorize_level)


/* 网络授权列表结构体定义 */
/*
 * For an eAudit_Authorize_Access_Network.conf config file.
 *
 * Format: Authorize_id / User_id / Protected_resource_id /
	   eAudit_level / Authorize_level.
 * Example:
 *		[COMMON]
 *		LIST_NUM=1;
 *		MODE_GETE=OFF;
 *		[LIST_INFO]
 *		INFO0=3001/190/3001/2+1+0+0+0+0+0+0/1+1+1+1;
 *		INFO1=5222/190/5222/2+1+0+0+0+0+0+0/1+1+1+1;
 */
typedef struct tagAUTHORIZE_ACCESS_NETWORK {

	int		mode_switch;		/* ON/OFF */
	unsigned long	authorize_id;		/* GUID authorize_id */
	unsigned long	usr_id;			/* GUID user_id */
	unsigned long	protect_resource_id;	/* GUID protected_resource_id */    
	EAUDIT_LEVEL	eaudit_level;
	AUTHORIZE_LEVEL	authorize_level;

}	authorize_access_network,		\
	AUTHORIZE_ACCESS_NETWORK,		\
	*AUTHORIZE_ACCESS_NETWORK_ID,		\
	*authorize_access_network_id;
#define AUTHORIZE_ACCESS_NETWORK_SIZE	sizeof(AUTHORIZE_ACCESS_NETWORK)
#define authorize_access_network_size	sizeof(authorize_access_network)


/*
 * 3.) 指令授权列表机构体定义
 */
/* 定义命令结构体 */
 typedef struct tagAUTHORIZE_CMD_CONTENT {

	unsigned char	cmd[128];

}	authorize_cmd_content,			\
	*authorize_cmd_content_id,		\
	AUTHORIZE_CMD_CONTENT,			\
	*AUTHORIZE_CMD_CONTENT_ID;
#define AUTHORIZE_CMD_CONTENT_SIZE sizeof(AUTHORIZE_CMD_CONTENT)
#define authorize_cmd_content_size sizeof(authorize_cmd_content)


/* 定义授权命令列表结构体定义 */
/*
 * For an eAudit_Authorize_Access_Cmd.conf config file.
 *
 * Format: Authorize_id/Not_Authorize_event/Command_number + content
 * Example:
 *		[COMMON]
 *		LIST_NUM=1;
 *		MODE_GETE=OFF;
 *		[LIST_INFO]
 *		INFO0=3001/0+1+1/4+du+df+od+ld
 *		INFO1=5222/0+1+1/2+mv+cp
 */
typedef struct tagAUTHORIZE_CMD {

	int		mode_switch;		/* ON/OFF */
	unsigned long	authorize_id;		/* GUID authorize_id */
	unsigned long	cmd_num;		/* Command Number */

	key_t		authorize_cmd_key;	/* what's U f**king mean.*/
	NOT_AUTHORIZE_EVENT	against_authorize_event;

}	authorize_cmd, *authorize_cmd_id,	\
	AUTHORIZE_CMD, *AUTHORIZE_CMD_ID;
#define AUTHORIZE_CMD_SIZE sizeof(AUTHORIZE_CMD)
#define authorize_cmd_size sizeof(authorize_cmd)


/*
 * 4.) 账号授权列表结构体定义
 */
/* 定义账号结构体 */
typedef struct tagAUTHORIZE_ACCOUNT_CONTENT {

	unsigned char	account[128];

}	authorize_account_content,		\
	AUTHORIZE_ACCOUNT_CONTENT,		\
	*authorize_account_content_id,		\
	*AUTHORIZE_ACCOUNT_CONTENT_ID;
#define AUTHORIZE_ACCOUNT_CONTENT_SIZE sizeof(AUTHORIZE_ACCOUNT_CONTENT)
#define authorize_account_content_size sizeof(authorize_account_content)


/* 定义授权账号列表结构体定义 */
/*
 * For an eAudit_Authorize_Access_Account.conf config file.
 *
 * Format: Authorize_id/Not_Authorize_event/Account_number + content
 * Example:
 *		[COMMON]
 *		LIST_NUM=1;
 *		MODE_GETE=OFF;
 *		[LIST_INFO]
 *		INFO0=3001/0+1+1/4+root+administrator+admin+sa
 *		INFO1=5222/0+1+1/2+fU9ANg+bnL
 */
typedef struct tagAUTHORIZE_ACCOUNT {

	int		mode_switch;		/* ON/OFF */
	unsigned long	authorize_id;		/* GUID authorize_id */
	unsigned long	account_num;		/* Account Number */
	key_t		authorize_account_key;
	NOT_AUTHORIZE_EVENT	against_authorize_event;

}	authorize_account,			\
	AUTHORIZE_ACCOUNT,			\
	*authorize_account_id,			\
	*AUTHORIZE_ACCOUNT_ID;
#define AUTHORIZE_ACCOUNT_SIZE sizeof(AUTHORIZE_ACCOUNT)
#define authorize_account_size sizeof(authorize_account)


/*
 * 5.) 自定义通用授权列表结构体定义
 */
/* 定义自定义结构体 */
typedef struct tagAUTHORIZE_CUSTOM_CONTENT {

	unsigned char	custom[128];

}	authorize_custom_content,		\
	AUTHORIZE_CUSTOM_CONTENT,		\
	*authorize_custom_content_id,		\
	*AUTHORIZE_CUSTOM_CONTENT_ID;
#define AUTHORIZE_CUSTOM_CONTENT_SIZE sizeof(AUTHORIZE_CUSTOM_CONTENT)
#define authorize_custom_content_size sizeof(authorize_custom_content)


/* 自定义授权通用列表结构体定义 */
/*
 * For an eAudit_Authorize_Access_Custom.conf config file.
 *
 * Format: Authorize_id/Not_Authorize_event/Custom_number + content
 * Example:
 *		[COMMON]
 *		LIST_NUM=1;
 *		MODE_GETE=OFF;
 *		[LIST_INFO]
 *		INFO0=3001/0+1+1/4+root+administrator+admin+sa
 *		INFO1=5222/0+1+1/2+fU9ANg+bnL
 */
typedef struct tagAUTHORIZE_CUSTOM {

	int		mode_switch;
	unsigned long	authorize_id;
	unsigned long	custom_num;

	key_t		authorize_custom_key;
	NOT_AUTHORIZE_EVENT	against_authorize_event;

}	authorize_custom, *authorize_custom_id,	\
	AUTHORIZE_CUSTOM, *AUTHORIZE_CUSTOM_ID;
#define AUTHORIZE_CUSTOM_SIZE sizeof(AUTHORIZE_CUSTOM)
#define authorize_custom_size sizeof(authorize_custom)

/*
 * 5.) 自定义协议特征授权列表结构体定义
 */
/* 定义协议特征结构体 */
typedef struct tagAUTHORIZE_PROTOCOL_FEATURE_CONTENT {

	unsigned char	pro_feature_content[256];

}	authorize_protocol_feature_content,	\
	AUTHORIZE_PROTOCOL_FEATURE_CONTENT,	\
	*authorize_protocol_feature_content_id,	\
	*AUTHORIZE_PROTOCOL_FEATURE_CONTENT_ID;
#define AUTHORIZE_PROTOCOL_FEATURE_CONTENT_SIZE sizeof(AUTHORIZE_PROTOCOL_FEATURE_CONTENT)
#define authorize_protocol_feature_content_size sizeof(authorize_protocol_feature_content)


typedef struct tagAUTHORIZE_PROTOCOL_FEATURE_TYPE {

	unsigned char	authorize_type;
	unsigned long	authorize_feature_content_num;
	key_t		authorize_protocol_feature_content_key;

}	authorize_protocol_feature_type,	\
	AUTHORIZE_PROTOCOL_FEATURE_TYPE,	\
	*authorize_protocol_feature_type_id,	\
	*AUTHORIZE_PROTOCOL_FEATURE_TYPE_ID;
#define AUTHORIZE_PROTOCOL_FEATURE_TYPE_SIZE sizeof(AUTHORIZE_PROTOCOL_FEATURE_TYPE)
#define authorize_protocol_feature_type_size sizeof(authorize_protocol_feature_type)


/* 协议特征授权通用列表结构体定义 */
/*
 * For an eAudit_Authorize_access_FTP_feature.conf config file.
 *
 * Format: Authorize_id/Not_Authorize_event/	\
 *	   number_of_type + 			\
 *	   type1 + number_of_content +content1 + content2 + ...
 *	   type2 + number_of_content +content1 + content2 + ... +
 *	   ....
 * Example:
 *		[COMMON]
 *		LIST_NUM=1;
 *		MODE_GETE=OFF;
 *		[LIST_INFO]
 *		INFO0=3001/0+1+1/3+0+3+hack.txt+fuck.txt+fun.txt+1+2+bz2+gz+2+1+wget
 */
typedef struct tagAUTHORIZE_PROTOCOL_FEATURE{

	int		mode_switch;
	unsigned long	pro_feature_num;
	unsigned long	authorize_id;

	key_t		authorize_protocol_feature_key;
	NOT_AUTHORIZE_EVENT against_authorize_event;

}	authorize_protocol,			\
	AUTHORIZE_PROTOCOL_FEATURE,		\
	*authorize_protocol_feature_id,		\
	*AUTHORIZE_PROTOCOL_FEATURE_ID;
#define AUTHORIZE_PROTOCOL_FEATURE_SIZE sizeof(AUTHORIZE_PROTOCOL_FEATURE)
#define authorize_protocol_feature_size sizeof(authorize_protocol_feature)

/* Here, ended of eaudit, authorize and certify. */

/*协议特征参数*/
typedef struct tagPRO_FEATURE_PARA
{
	key_t pro_feature_key;
	int pro_feature_num;
        int shm_id;
}PRO_FEATURE_PARA,*PRO_FEATURE_PARA_ID;
#define PRO_FEATURE_PARA_SIZE sizeof(PRO_FEATURE_PARA)


typedef struct tagSRC_INFO
{
	unsigned long src_ip;
	unsigned char src_mac[20];
	unsigned short sport;
}SRC_INFO,*SRC_INFO_ID;
#define SRC_INFO_SIZE sizeof(SRC_INFO)

/*重定向端口*/
typedef struct tagREDIRECTION_BASIC_INFO
{
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

typedef struct tagREDIRECTION_PORT_INFO
{
	unsigned char flag;
	REDIRECTION_BASIC_INFO redirect_info;
}REDIRECTION_PORT_INFO,*REDIRECTION_PORT_INFO_ID;
#define REDIRECTION_PORT_INFO_SIZE sizeof(REDIRECTION_PORT_INFO)


/*packets file set*/
typedef struct tagCFG_FILE_SET
{
    unsigned long maxPktFileSize;
    unsigned long maxPktFileNum;
}CFG_FILE_SET, *CFG_FILE_SET_ID;
#define CFG_FILE_SET_SIZE sizeof(CFG_FILE_SET)

/*equal to the function switch*/
typedef struct tagFUNC_SWITCH
{
    int iAlarmSwitch;
    int iErrSwitch;
    int iStatSwitch;
}FUNC_SWITCH, *FUNC_SWITCH_ID;
#define FUNC_SWITCH_SIZE sizeof(FUNC_SWITCH)
/*the par to the analyze process*/
typedef struct tagPAR_ITF_ANALYZE
{
	int pro_id;
	key_t pro_tbl_shm_key;
	CFG_FILE_SET cfg_file_set;
	FUNC_SWITCH func_switch;
	key_t rule_pool_key;
	unsigned long rule_num;
	char pkt_file_dir[MAX_FILE_PATH_SIZE + 1];
	long deposit_ivl_sec;
	key_t usr_list_key;
	unsigned long usr_num;

	key_t authorize_network_key;
	unsigned long authorize_network_num;

	key_t authorize_account_key;
	unsigned long authorize_account_num;

	key_t authorize_cmd_key;
	unsigned long authorize_cmd_num;

	key_t authorize_custom_key;
	unsigned long authorize_custom_num;

	key_t authorize_feature_key;
	unsigned long authorize_feature_num;

	key_t redirect_key;
	pid_t redirect_pid;
	key_t sem_key;
}PAR_ITF_ANALYZE,*PAR_ITF_ANALYZE_ID;
#define PAR_ITF_ANALYZE_SIZE sizeof(PAR_ITF_ANALYZE)

typedef struct tagSUPPORT_PRO_NODE {

	int  pro_no;
	char pro_name[MAX_PRO_NAME_SIZE + 1];	/* 协议名+++*/
	int  protect_num;
	int  code;

}	support_pro_node, *support_pro_node,	/* use by the get_protocol_name */
	SUPPORT_PRO_NODE, *SUPPORT_PRO_NODE_ID;	/* function in param.c file     */
#define SUPPORT_PRO_NODE_SIZE sizeof(SUPPORT_PRO_NODE)
#define support_pro_node_size sizeof(support_pro_node)



typedef struct tagAUTHORIZE_PROTOCOL_CONTENT
{
	unsigned char content[256];
}AUTHORIZE_PROTOCOL_CONTENT,*AUTHORIZE_PROTOCOL_CONTENT_ID;

typedef struct tagAUTHORIZE_PROTOCOL_TYPE
{
	unsigned char type;
	unsigned long content_num;
	AUTHORIZE_PROTOCOL_CONTENT_ID content_id;
}AUTHORIZE_PROTOCOL_TYPE,  *AUTHORIZE_PROTOCOL_TYPE_ID;
#define AUTHORIZE_PROTOCOL_TYPE_SIZE sizeof(AUTHORIZE_PROTOCOL_TYPE)




typedef struct tagEAUDIT_AUTHORIZE_INFO
{
	unsigned long eaudit_info;
//  	unsigned char eaudit_info_describe[EAUDIT_INFO_DES_SIZE+1];
	
	unsigned long authorize_info;
	unsigned char handle_info;
//  	unsigned char authorize_state[AUTH_STATE_SIZE+1];
//  	unsigned char authorize_info_describe[AUTH_INFO_DES_SIZE+1];
	
    	int cmd_index;
	int account_index;
    	int custom_made_index;
    	int custom_made_pro_index;

	AUTHORIZE_CMD_CONTENT_ID authorize_cmd_content_addr;
	AUTHORIZE_ACCOUNT_CONTENT_ID authorize_account_content_addr;
   	AUTHORIZE_CUSTOM_CONTENT_ID authorize_custom_content_addr;
	AUTHORIZE_PROTOCOL_TYPE authorize_protocol_type[15];
}EAUDIT_AUTHORIZE_INFO, *EAUDIT_AUTHORIZE_INFO_ID;
#define EAUDIT_AUTHORIZE_INFO_SIZE sizeof(EAUDIT_AUTHORIZE_INFO)

typedef struct tagUSR_INFO
{
    	int src_usrid;
    	char src_usrname[MAX_USR_NAME_SIZE+1];
}USR_INFO,*USR_INFO_ID;
#define USR_INFO_SIZE sizeof(USR_INFO)


#define 	IP_CERTIFITY 		0
#define   MAC_CERTIFITY  		1
#define   IP_MAC_CERTIFITY 	2
#define   DYNAMIC_CERTIFITY 3

#define MAX_RULE_CNT_SIZE			511



typedef struct tagEA_COMMON_SESSION_TBL
{
	unsigned long session_id;
	unsigned long data_session_id;
	unsigned long protected_res_no;
	char protected_res_content[MAX_RULE_CNT_SIZE+1];
	char protected_res_name[MAX_RES_NAME_SIZE+1];

	int pro_type_id;
	unsigned long src_ip;
	unsigned short src_port;
	unsigned char src_mac[MAC_ADDRESS_SIZE];
	int src_usrid;
	char src_usrname[MAX_USR_NAME_SIZE+1];
	

	unsigned long dst_ip;
	unsigned short dst_port;
	unsigned char dst_mac[MAC_ADDRESS_SIZE];

	
	struct timeval start_time;
	struct timeval end_time;

	char session_state;
    	char login_user[MAX_LOGIN_USER_NAME_SIZE + 1];
	int risk_level;
	
	unsigned long pgt_len;PGconn
	unsigned long pgt_num;
	double pgt_flux;

	unsigned char authorize_flag;
	unsigned char eaudit_info_state;
}EA_COMMON_SESSION_TBL, *EA_COMMON_SESSION_TBL_ID;
#define EA_COMMON_SESSION_TBL_SIZE sizeof(EA_COMMON_SESSION_TBL)

#define MAX_LOG_DETAIL_SIZE		1023
#define MAX_SYS_NAME_SIZE			31
#define MAX_OPERATER_TYPE_SIZE 	255
#define MAX_MODEL_NAME			31


typedef struct tagEA_LOG_TBL
{
	struct timeval logdate_time;
	char* logdetail;
	char* sys_name;
	char* model_name;
	int p_type_id;
	char* operater_type;
}EA_LOG_TBL, *EA_LOG_TBL_ID;
#define EA_LOG_TBL_SIZE sizeof(EA_LOG_TBL)


#define MAX_ALARM_DES_SIZE	1023
typedef struct tagEA_AlARM_TBL
{
	unsigned long session_id;
	int p_type_id;
	int pro_id;
	char* pro_name;
	char* model_name;
	unsigned char* src_mac;
	unsigned long src_ip;
	unsigned char* dst_mac;
	unsigned long dst_ip;
	char* src_username;
	int usr_id;
	struct timeval alarm_date;
	char* description;

}EA_ALARM_TBL,*EA_AlARM_TBL_ID;
#define EA_ALARM_TBL_SIZE sizeof(EA_ALARM_TBL)


typedef struct tagEA_ITF_PAR_INFO
{
	char protocol_name[MAX_PROTOCOL_NAME_SIZE+1];
	
	CFG_FILE_SET cfg_file_set;
	FUNC_SWITCH func_switch;

	char pkt_file_dir[MAX_FILE_PATH_SIZE + 1];
    	long deposit_ivl_sec;

	PROTECTED_RESOURCE_ID protect_res_id;
	unsigned long protect_res_num;

	USR_LIST_MEM_ID usr_list_id;
	unsigned long usr_all_num;

	AUTHORIZE_ACCESS_NETWORK_ID authorize_network_id;
	unsigned long authorize_network_num;

	AUTHORIZE_ACCOUNT_ID authorize_account_id;
	unsigned long authorize_account_num;

	AUTHORIZE_CMD_ID authorize_cmd_id;
	unsigned long authorize_cmd_num;

	AUTHORIZE_CUSTOM_ID authorize_custom_id;
	unsigned long authorize_custom_num;

	AUTHORIZE_PROTOCOL_FEATURE_ID authorize_pro_feature_id;
	unsigned long authorize_pro_feature_num;
	
	REDIRECTION_PORT_INFO_ID redirection_port_info_id;
	pid_t redirect_pid;
	int semid;
}EA_ITF_PAR_INFO, *EA_ITF_PAR_INFO_ID;
#define EA_ITF_PAR_INFO_SIZE sizeof(EA_ITF_PAR_INFO)


/*
 *  DEFINITIONS SOME DATA STRUCTURE
 *  FOR THE MMAP FILE INFORMATION .
 */

/*
 *  Format of the content of packet file
 *  Example: /data/FTP/1.tmp
 */
/*
 *  包文件使用的格式结构 
 * 
 *  0.) 文件格式	mmap_file_info
 *	文件头定义+用户自定义+保护资源ID+以太网帧格式
 * 
 *  1.) 文件头定义	pkt_file_hdr
 *	文件标志+文件包个数+文件长度+32位CRC校验+4个字节预留+主版本号+
 *	次版本号+本版本号+gmt时间+时间撮+下一分片大小+连接类型
 *  2.) 用户自定义包头	pkt_usr_hdr
 *	时间戳+抓包长度+本报文长度 
*/
typedef struct tagPKT_FILE_USR_HDR {

	int		file_flag;		/* 文件标志 */   
	unsigned long	all_packets_num;	/* 文件包的个数 */
	unsigned long	all_packets_size;    	/* 文件包的大小(长度) */
	unsigned long	crc_num;		/* 32位CRC校验 */
	unsigned long	reseaved;		/* 4个字节预留 */

}	pkt_file_usr_hdr, *pkt_file_usr_hdr_id;
	PKT_FILE_USR_HDR, *PKT_FILE_USR_HDR_ID;
#define pkt_file_usr_hdr_size sizeof(pkt_file_usr_hdr)
#define PKT_FILE_USR_HDR_SIZE sizeof(PKT_FILE_USR_HDR)

typedef struct tagPKT_FILE_PCAP_HDR {

	unsigned long	magic; 
	unsigned long	version_major;		/* the major version */
	unsigned long	version_minor;		/* the minor version */
	unsigned long	thiszone;		/* gmt to local correction */
	unsigned long	sigfigs;		/* accuracy of timestamps */
	unsigned long	snaplen;		/* max length saved portion of each pkt */
	unsigned long	linktype;		/* data link type (LINKTYPE_*) */

}	pkt_file_pcap_hdr, *pkt_file_pcap_hdr_id,
	PKT_FILE_PCAP_HDR, *PKT_FILE_PCAP_HDR_ID;
#define pkt_file_pcap_hdr_size sizeof(pkt_file_pcap_hdr)
#define PKT_FILE_PCAP_HDR_SIZE sizeof(PKT_FILE_PCAP_HDR)

typedef struct tagPKT_FILE_HDR {

	PKT_FILE_USR_HDR_ID  usr_hdr_id;	/* defined on above */
	PKT_FILE_PCAP_HDR_ID pcap_hdr_id;	/* defined on above */

}	pkt_file_hdr,	     PKT_FILE_HDR,	\
	*pkt_file_hdr_id,   *PKT_FILE_HDR_ID;
#define pkt_file_hdr_size sizeof(pkt_file_hdr)
#define PKT_FILE_HDR_SIZE sizeof(PKT_FILE_HDR)

typedef struct tagPKT_USR_HDR {

	struct timeval	ts;
	unsigned long	cap_len;		/* the length of the capture packet */
	unsigned long	pkt_size;   		/* all length of this packet */

}	pkt_usr_hdr,	PKT_USR_HDR,		\
	*pkt_usr_hdr_id,*PKT_USR_HDR_ID;
#define pkt_usr_hdr_size sizeof(pkt_usr_hdr)
#define PKT_USR_HDR_SIZE sizeof(PKT_USR_HDR)

typedef struct tagRULE_ID_ST { /* EQ protected resource?*/

	unsigned long	rule_id; 
	unsigned long	authorize_id;
	unsigned long	usr_id;   
	unsigned long	res_index;
	unsigned long	net_index;
	unsigned char	hit_direct;

}	rule_id_st,	*rule_id_st_id,		\
	RULE_ID_ST,	*RULE_ID_ST_ID;
#define rule_id_st_size sizeof(rule_id_st)
#define RULE_ID_ST_SIZE sizeof(RULE_ID_ST)

typedef struct tagMMAP_FILE_INFO {

	int 		fd;
	unsigned long	file_no;
	unsigned char*	mmap_addr;
	unsigned char*	cur_pos;
	unsigned char*	cur_pos_bk;
	unsigned char*	next_pkt_pos;

	PKT_FILE_HDR	pkt_file_hdr;		/* 文件头结构 */
	PKT_USR_HDR_ID	libpcap_hdr_id;		/* 用户头结构 */
	RULE_ID_ST_ID	rule_id_st_id;

}	mmap_file_info, *mmap_file_info_id,	\
	MMAP_FILE_INFO, *MMAP_FILE_INFO_ID;
#define mmap_file_info_size sizeof(mmap_file_info)
#define MMAP_FILE_INFO_SIZE sizeof(MMAP_FILE_INFO)

/* ENDED OF DS FOR MMAP */


typedef void(*PFUNC_ANALYZE)(EA_ITF_PAR_INFO_ID, MMAP_FILE_INFO_ID);
typedef void(*PFUNC_FLUSH )(char);
typedef void(*PFUNC_FORCE_INTO_DB)(void);

typedef struct tagCALLBACK_FUNC_SET
{
	PFUNC_ANALYZE analyze_fptr;
	PFUNC_FLUSH flush_fptr;
	PFUNC_FORCE_INTO_DB force_into_db_fptr;
}CALLBACK_FUNC_SET, *CALLBACK_FUNC_SET_ID;
#define CALLBACK_FUNC_SET_SIZE sizeof(CALLBACK_FUNC_SET)


typedef struct tagEA_EVENT_COMMON_TBL
{
	unsigned long session_id;
	int event_seq;
	int p_type_id;
	int event_type;
	int result;
	struct timeval event_time;
	char event_des[64];
}EA_EVENT_COMMON_TBL, *EA_EVENT_COMMON_TBL_ID;
#define EA_EVENT_COMMON_TBL_SIZE sizeof(EA_EVENT_COMMON_TBL)


typedef struct tagEA_CMD_TBL
{
	char cmd_name[10];
	int cmd_no;
	char cmd_ch[1024];
}EA_CMD_TBL, *EA_CMD_TBL_ID;
#define EA_CMD_TBL_SIZE sizeof(EA_CMD_TBL)

typedef struct tagEA_MONITOR_INFO
{
	int conn_interval;
	int conn_threshold;
	
	int flux_interval;
	double flux_threshold;

}EA_MONITOR_INFO, *EA_MONITOR_INFO_ID;
#define EA_MONITOR_INFO_SIZE sizeof(EA_MONITOR_INFO)


typedef void (*sa_sigaction_t)(int, siginfo_t*, void *);




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


#endif /* ANALYZE_INTERFACE_H */
