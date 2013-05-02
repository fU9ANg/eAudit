
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



/*Э�鱣����Դ��Ϣ�ṹ�嶨��*/
typedef struct tagPRO_PROTECTED_RESOURCE{
	char protected_res_name[32];
	int protected_res_id;
	char protected_res_content[256];	/* ���� */
	NOT_AUTHORIZE_EVENT unauthorize_event;
	EAUDIT_LEVEL eaudit_level;
	int authorize_flag;					/* ���� */
	int eaudit_info_state;				/* ���� */
}PRO_PROTECTED_RESOURCE, *PRO_PROTECTED_RESOURCE_ID;
#define PRO_PROTECTED_RESOURCE_SIZE sizeof(PRO_PROTECTED_RESOURCE)

/*Э��������Ȩ��Ϣ�ṹ�嶨��*/
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

/*Э���û���Ϣ�ṹ�嶨��*/
typedef struct tagPRO_USR_INFO
{
	int usr_id;					//�û�ID
//	unsigned long ip;			//IP��ַ
//	unsigned char strMac[32];	//MAC��ַ
	char strUsrName[256];		//�û���
//	int iUsrCertifyMethod;
} PRO_USR_INFO, *PRO_USR_INFO_ID;
#define PRO_USR_INFO_SIZE sizeof(PRO_USR_INFO)

/*Э���˺���Ȩ��Ϣ�ṹ�嶨��*/
typedef struct tagPRO_ACCOUNT_INFO{
	int authorize_id;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	int account_num;
	char authorize_account[64][128];
} PRO_ACCOUNT_INFO, *PRO_ACCOUNT_INFO_ID;
#define PRO_ACCOUNT_INFO_SIZE sizeof(PRO_ACCOUNT_INFO)

/*Э��ָ����Ȩ��Ϣ�ṹ�嶨��*/
typedef struct tagPRO_CMD_INFO{
	int authorize_id;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	int cmd_num;
	char authorize_cmd[64][128];
} PRO_CMD_INFO, *PRO_CMD_INFO_ID;
#define PRO_CMD_INFO_SIZE sizeof(PRO_CMD_INFO)

/*Э��ͨ����Ȩ��Ϣ�ṹ�嶨��*/
typedef struct tagPRO_CUSTOM_INFO{
	int authorize_id;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	int custom_num;
	char authorize_custom[64][128];
} PRO_CUSTOM_INFO, *PRO_CUSTOM_INFO_ID;
#define PRO_CUSTOM_INFO_SIZE sizeof(PRO_CUSTOM_INFO)

/*Э��������Ȩ��Ϣ�ṹ�嶨��*/
typedef struct tagPRO_FEATURE_INFO{
	int authorize_id;
	NOT_AUTHORIZE_EVENT unauthorize_event;
	int type_num;	//���͸���
	struct{
		int type;
		int content_num;		//���ݸ���
		char content[64][128];
	}authorize_feature[16];
} PRO_FEATURE_INFO, *PRO_FEATURE_INFO_ID;
#define PRO_AUTHORIZE_FEATURE_INFO_SIZE sizeof(PRO_FEATURE_INFO)

/*Э����Ȩ��ϵ�ṹ�嶨��*/
typedef struct tagPRO_AUTHRIZ_RELATION_INFO{
	PRO_NETWORK_INFO *network_addr;				//������Ȩָ��
	PRO_USR_INFO *usr_addr;						//�û���Ϣָ��
	PRO_PROTECTED_RESOURCE *protected_res_addr;	//������Դ��Ϣָ��
	PRO_ACCOUNT_INFO *account_addr;				//�˺���Ȩ��Ϣָ��
	PRO_CMD_INFO *cmd_addr;						//ָ����Ȩ��Ϣָ��
	PRO_CUSTOM_INFO *custom_addr;				//ͨ����Ȩ��Ϣָ��
	PRO_FEATURE_INFO *feature_addr;				//Э��������Ȩ��Ϣָ��
}PRO_AUTHRIZ_RELATION_INFO, *PRO_AUTHRIZ_RELATION_INFO_ID;
#define PRO_AUTHRIZ_RELATION_INFO_SIZE sizeof(PRO_AUTHRIZ_RELATION_INFO)

/*Э������ṹ��*/
typedef struct tagPRO_ANALYSIS_INFO{
	int protected_res_num;						//����Э��ID���˳��ı�����Դ����
	PRO_PROTECTED_RESOURCE *protected_res_addr;	//����Э��ID���˳��ı�����Դ�б��׵�ַָ��
	int usr_num;								//�û�����
	PRO_USR_INFO *usr_addr;						//�û���Ϣ�׵�ַ
	int network_num;							//������Ȩ����
	PRO_NETWORK_INFO *network_addr;				//������Ȩ�׵�ַ
	int relation_num;							//Э����Ȩ��ϵ����, ��network_num���
	PRO_AUTHRIZ_RELATION_INFO *relation_addr;	//Э����Ȩ��ϵ�б�
} PRO_ANALYSIS_INFO, *PRO_ANALYSIS_INFO_ID;
#define PRO_ANALYSIS_INFO_SIZE  sizeof(PRO_ANALYSIS_INFO)




/**********************************
*func name: proCreatPorotcolAnalysisInfo
*function: ����Э�������������
*parameters:
		�������: protocol_id: Э��ID
				  cfg_dir: �����ļ����·��
		�������:protocol_analysis_info: Э������������ݽṹ��
*call: 
*called: 
*return:
*/
int proCreatPorotcolAnalysisInfo (PRO_ANALYSIS_INFO *protocol_analysis_info, int protocol_id, const char *cfg_dir);

/**********************************
*func name: proDestroyPorotcolAnalysisInfo
*function: �ͷ�Э���������
*parameters:
		�������: protocol_analysis_info:Э������������ݽṹ��
*call:
*called:
*return:
*/
void proDestroyPorotcolAnalysisInfo (PRO_ANALYSIS_INFO *protocol_analysis_info);

/**********************************
*func name: ProGetMonitorConf
*function: ����Э��ID����ȡЭ����������Ϣ
*parameters:
		�������: protocol_id: Э��ID
		�������: p_monitor_conf_ptr: ���������Ϣ�ṹ��ַ
*call:
*called:
*return: �ɹ�:TRUE��ʧ��:FALSE
*/
int proGetMonitorConf(P_MONITOR_INFO *p_monitor_conf_ptr, int protocol_id, const char *cfg_dir);


#endif
