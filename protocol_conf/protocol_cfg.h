
#ifndef _PROTOCOL_CFG_H
#define _PROTOCOL_CFG_H

#include "interface_analyze.h"
#include "interface_pub.h"


#define LIST_ITEMS_DELIM		"+"
#define LIST_ITEMS_DELIM_CHAR	'+'
#define LIST_ITEMS_INDER		"/"
#define LIST_LINE_DELIM_INDER	"+/"

/*the line end char*/
#define LIST_LINE_END_ASC	59             /*';'*/
#define LIST_LINE_DELIM		";"

#define MONITOR_FILE					"eAudit_Monitor_FluxConnect.conf"

/*log mode*/
#define LOG_TOOL SYS_LOG



/*协议保护资源信息结构体定义*/
typedef struct tagPRO_PROTECTED_RESOURCE{
	char protected_res_name[32];
	int protected_res_id;
	char protected_res_content[256];	/* 待定 */
	NOT_AUTHORIZE_EVENT unauthorize_event;
	EAUDIT_LEVEL eaudit_level;
	int authorize_flag;					/* 待定 */
	int eaudit_info_state;				/* 待定 */
}PRO_PROTECTED_RESOURCE, *PRO_PROTECTED_RESOURCE_ID;
#define PRO_PROTECTED_RESOURCE_SIZE sizeof(PRO_PROTECTED_RESOURCE)

/*协议网络授权信息结构体定义*/
typedef struct tagPRO_NETWORK_INFO{
	int authorize_id;
	int usr_id;
	int protected_res_id;
	EAUDIT_LEVEL eaudit_level;
	AUTHORIZE_LEVEL authorize_level;
	int authorize_flag;
	int eaudit_info_state;
} PRO_NETWORK_INFO, *PRO_NETWORK_INFO_ID;
#define PRO_NETWORK_INFO_SIZE  sizeof(PRO_NETWORK_INFO)

/*协议用户信息结构体定义*/
typedef struct tagPRO_USR_INFO
{
	int usr_id;					//用户ID
//	unsigned long ip;			//IP地址
//	unsigned char strMac[32];	//MAC地址
	char strUsrName[256];		//用户名
//	int iUsrCertifyMethod;
} PRO_USR_INFO, *PRO_USR_INFO_ID;
#define PRO_USR_INFO_SIZE sizeof(PRO_USR_INFO)

/*协议账号授权信息结构体定义*/
typedef struct tagPRO_ACCOUNT_INFO{
	int authorize_id;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	int account_num;
	char authorize_account[64][128];
} PRO_ACCOUNT_INFO, *PRO_ACCOUNT_INFO_ID;
#define PRO_ACCOUNT_INFO_SIZE sizeof(PRO_ACCOUNT_INFO)

/*协议指令授权信息结构体定义*/
typedef struct tagPRO_CMD_INFO{
	int authorize_id;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	int cmd_num;
	char authorize_cmd[64][128];
} PRO_CMD_INFO, *PRO_CMD_INFO_ID;
#define PRO_CMD_INFO_SIZE sizeof(PRO_CMD_INFO)

/*协议通用授权信息结构体定义*/
typedef struct tagPRO_CUSTOM_INFO{
	int authorize_id;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	int custom_num;
	char authorize_custom[64][128];
} PRO_CUSTOM_INFO, *PRO_CUSTOM_INFO_ID;
#define PRO_CUSTOM_INFO_SIZE sizeof(PRO_CUSTOM_INFO)

/*协议特征授权信息结构体定义*/
typedef struct tagPRO_FEATURE_INFO{
	int authorize_id;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	int type_num;	//类型个数
	struct{
		int type;
		int content_num;		//内容个数
		char content[64][128];
	}authorize_feature[16];
} PRO_FEATURE_INFO, *PRO_FEATURE_INFO_ID;
#define PRO_AUTHORIZE_FEATURE_INFO_SIZE sizeof(PRO_FEATURE_INFO)

/*协议授权关系结构体定义*/
typedef struct tagPRO_AUTHRIZ_RELATION_INFO{
	PRO_NETWORK_INFO *network_addr;				//网络授权指针
	PRO_USR_INFO *usr_addr;						//用户信息指针
	PRO_PROTECTED_RESOURCE *protected_res_addr;	//保护资源信息指针
	PRO_ACCOUNT_INFO *account_addr;				//账号授权信息指针
	PRO_CMD_INFO *cmd_addr;						//指令授权信息指针
	PRO_CUSTOM_INFO *custom_addr;				//通用授权信息指针
	PRO_FEATURE_INFO *feature_addr;				//协议特征授权信息指针
}PRO_AUTHRIZ_RELATION_INFO, *PRO_AUTHRIZ_RELATION_INFO_ID;
#define PRO_AUTHRIZ_RELATION_INFO_SIZE sizeof(PRO_AUTHRIZ_RELATION_INFO)

/*协议分析结构体*/
typedef struct tagPRO_ANALYSIS_INFO{
	int protected_res_num;						//根据协议ID过滤出的保护资源个数
	PRO_PROTECTED_RESOURCE *protected_res_addr;	//根据协议ID过滤出的保护资源列表首地址指针
	int usr_num;								//用户个数
	PRO_USR_INFO *usr_addr;						//用户信息首地址
	int network_num;							//网络授权个数
	PRO_NETWORK_INFO *network_addr;				//网络授权首地址
	int relation_num;							//协议授权关系个数, 与network_num相等
	PRO_AUTHRIZ_RELATION_INFO *relation_addr;	//协议授权关系列表
} PRO_ANALYSIS_INFO, *PRO_ANALYSIS_INFO_ID;
#define PRO_ANALYSIS_INFO_SIZE  sizeof(PRO_ANALYSIS_INFO)




/**********************************
*func name: proCreatPorotcolAnalysisInfo
*function: 创建协议分析所需数据
*parameters:
		输入参数: protocol_id: 协议ID
				  cfg_dir: 配置文件存放路径
		输出参数:protocol_analysis_info: 协议分析所需数据结构体
*call: 
*called: 
*return:
*/
int proCreatPorotcolAnalysisInfo (PRO_ANALYSIS_INFO *protocol_analysis_info, int protocol_id, const char *cfg_dir);

/**********************************
*func name: proDestroyPorotcolAnalysisInfo
*function: 释放协议分析数据
*parameters:
		输入参数: protocol_analysis_info:协议分析所需数据结构体
*call:
*called:
*return:
*/
void proDestroyPorotcolAnalysisInfo (PRO_ANALYSIS_INFO *protocol_analysis_info);

/**********************************
*func name: ProGetMonitorConf
*function: 根据协议ID，读取协议监测配置信息
*parameters:
		输入参数: protocol_id: 协议ID
		输出参数: p_monitor_conf_ptr: 监测配置信息结构地址
*call:
*called:
*return: 成功:TRUE，失败:FALSE
*/
int proGetMonitorConf(P_MONITOR_INFO *p_monitor_conf_ptr, int protocol_id, const char *cfg_dir);


#endif
