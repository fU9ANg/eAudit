
/*
 * file: interface_pmc.h
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 * �������������ͷ��������Ӵ���ͷ����
 */

#ifndef _INTERFACE_PMC_H
#define _INTERFACE_PMC_H

#include "interface_pub.h"
#include "interface_net.h"

/*�����ʽ������VC++�����Ǻ�*/

/*ͨ�Ŷ˿ں�*/
#define PMC_SEVER_PORT       5431
#define PMC_SIN_ZERO_LEN     8
#define MAX_PMC_REQURE_NUM   5
#define MAX_PMC_RW_SIZE      1024*10 /*100MBps * 0.050(RTT) sec / 8 */

#define MAX_PMC_DEV_ID_SIZE 128

#define PMC_NET_PKT_FLAG "SAIL"
#define LIST_COMMON_KEY  "COMMON"
#define LIST_NUM_KEY         "LIST_NUM"
#define LIST_MODE_GETE_KEY "MODE_GETE"

#define LIST_INFO_KEY         "LIST_INFO"
#define LIST_RESOURCE_KEY "INFO"

/*���ݰ������*/
typedef enum{
    MSG_XXX_NET = 0,
    MSG_DEV_HEART,
    CMD_GET_JC_PARS,
    RET_GET_JC_PARS,
    CMD_GET_SJ_PARS,
    RET_GET_SJ_PARS,
    CMD_GET_SJ_DEF,
    RET_GET_SJ_DEF,
    CMD_GET_JC_DEF,
    RET_GET_JC_DEF,
    CMD_CFG_SJ_JC,

    MSG_CMD_DEV_IP=17,
    RESPONSE_OK = 19,
    RESPONSE_ERR,
    MSG_CMD_FLOWCONTROL=29,
    MSG_CMD_MODIFY_SWITCHDEV_IP,
    MSG_CMD_ARP,
    MSG_CMD_USR_INFO_LIST,
    MSG_CMD_PROTECT_RESOURCE_LIST,
    MSG_CMD_NETWORK_AUTHORIZE_LIST,
    MSG_CMD_CMD_AUTHORIZE_LIST,
    MSG_CMD_ACCOUNT_AUTHORIZE_LIST,
    MSG_CMD_PROTOCOL_ACUSTOM_AUTHORIZE_LIST,
    MSG_CMD_PROTOCOL_FEATURE_AUTHORIZE_LIST,
    MSG_CMD_LINK_FLUX_MONITOR_LIST,
    MSG_CMD_NETTIMESYN_LIST,
    MSG_CMD_SECONDTIMESYN_LIST,
    MSG_CMD_HANDNETTIME_LIST,
    MSG_CMD_MONITOR_SYS_INFO_LIST,
    MSG_CMD_AUTH_FILE_INFO_LIST,
    MSG_CMD_EAUDITWORKMODE_LIST,
   MSB_CMD_TRANSFER_FILE_OVER = 255
}EN_NET_MSG_TYPE;

typedef enum{
    STATUS_UNKNOW = 0,
    STATUS_CFG_SJ_JC,
    STATUS_MD_IP,
    STATUS_FLOWCONTROL,
    STATUS_MODIFY_SWITCHDEV_IP,
    STATUS_ARP,
    STATUS_USR_INFO,
    STATUS_PROTECT_RESOURCE,
    STATUS_NETWORK_AUTHORIZE,
    STATUS_CMD_AUTHORIZE,
    STATUS_ACCOUNT_AUTHORIZE,
    STATUS_PROTOCOL_ACUSTOM_AUTHORIZE,
    STATUS_PROTOCOL_FEATURE_AUTHORIZE,
    STATUS_LINK_FLUX_MONITOR,
    STATUS_NETTIMESYN,
    STATUS_SECONDTIMESYN,
    STATUS_HANDNETTIME,
    STATUS_MONITOR_SYS_INFO,
    STATUS_AUTH_FILE_INFO,
    STATUS_EAUDITWORKMODE_LIST
}EN_NET_STATUS;
typedef enum{
	AMC_POLICY_SUCCESS = 0x800000,
	AUTH_USR_NUM_ERR,
	AUTH_PROTECT_NUM_ERR,
	AUTH_HTTP_PROTECT_NUM_ERR,
	AUTH_FTP_PROTECT_NUM_ERR,
	AUTH_SMTP_PROTECT_NUM_ERR,
	AUTH_POP3_PROTECT_NUM_ERR,
	AUTH_TELNET_PROTECT_NUM_ERR,
	AUTH_MSN_PROTECT_NUM_ERR,
	AUTH_EMULE_PROTECT_NUM_ERR,
	AUTH_X11_PROTECT_NUM_ERR,
	AUTH_RDP_PROTECT_NUM_ERR,
	AUTH_RLOGIN_PROTECT_NUM_ERR,
	AUTH_NETBIOS_PROTECT_NUM_ERR,
	AUTH_SYBASE_PROTECT_NUM_ERR,
	AUTH_SQLSERVER_PROTECT_NUM_ERR,
	AUTH_ORACLE_PROTECT_NUM_ERR,
	AUTH_INFORMIX_PROTECT_NUM_ERR,
	AUTH_DB2_PROTECT_NUM_ERR,
	AUTH_ARP_PROTECT_NUM_ERR,
	AUTH_SKYPE_PROTECT_NUM_ERR,
	AUTH_QQ_PROTECT_NUM_ERR,
	AUTH_THUNDER_PROTECT_NUM_ERR,
	AUTH_BT_PROTECT_NUM_ERR,
	AUTH_FETION_PROTECT_NUM_ERR,
	READ_AUTH_FILE_ERR,
	AUTH_PROTOCOL_NAME_ERR
}CMD_RESPONSE;
/*������Ϣ��ʽ*/
//������Ϣֻ����ͷ��

#pragma pack(1)

/*����豸����*/
typedef struct stuJDEVPARS
{
    char strJDevSeq[64];
}JDEVPARS_STU,*JDEVPARS_ID;
#define JDEVPARS_STU_SIZE sizeof(JDEVPARS_STU)

typedef struct stuJDEVPARS_PKT
{
    NET_MSG_HDR hdr;
    JDEVPARS_STU body;
}JDEVPARS_PKT,*JDEVPARS_PKT_ID;
#define JDEVPARS_PKT_SIZE sizeof(JDEVPARS_PKT)

/*����豸Ĭ�����ò���*/
typedef struct stuJDEVDEFCFG
{
    char strIP[32];             //������IP��ַ
    char strJDevSeq[64];   //����豸���к�
    unsigned short port;      //������ͨ�Ŷ˿�
} JDEVDEFCFG_STU,* JDEVDEFCFG_ID;
#define JDEVDEFCFG_STU_SIZE sizeof(JDEVDEFCFG_STU)

typedef struct stuJDEVDEFCFG_PKT
{
    NET_MSG_HDR hdr;
    JDEVDEFCFG_STU body;
}JDEVDEFCFG_PKT,*JDEVDEFCFG_PKT_ID;
#define JDEVDEFCFG_PKT_SIZE sizeof(JDEVDEFCFG_PKT)

/*����豸Ĭ�����ò���*/
typedef struct stuSDEVDEFCFG
{
    char strIP[32];               //������IP��ַ
    char strSDevSeq[64];    //����豸���к�
    unsigned short port;       //������ͨ�Ŷ˿�
} SDEVDEFCFG_STU,*SDEVDEFCFG_ID;
#define SDEVDEFCFG_STU_SIZE sizeof(SDEVDEFCFG_STU)

typedef struct stuSDEVDEFCFG_PKT
{
    NET_MSG_HDR hdr;
    SDEVDEFCFG_STU body;
}SDEVDEFCFG_PKT,*SDEVDEFCFG_PKT_ID;
#define SDEVDEFCFG_PKT_SIZE sizeof(SDEVDEFCFG_PKT)

/*����豸����*/
typedef struct stuSDEVPARS
{
    char strSDevSeq[64];
}SDEVPARS_STU,*SDEVPARS_ID;
#define SDEVPARS_STU_SIZE sizeof(SDEVPARS_STU)

typedef struct stuSDEVPARS_PKT
{
    NET_MSG_HDR hdr;
    SDEVPARS_STU body;
}SDEVPARS_PKT,*SDEVPARS_PKT_ID;
#define SDEVPARS_PKT_SIZE sizeof(SDEVPARS_PKT)

/*��Ʒ���������������Ķ�Ӧ��ϵ*/
typedef struct stuSDBCONNINFO
{
    char strIP[32];            //��Ʒ�����IP��ַ
    unsigned short port;     //��Ʒ�����ͨ�Ŷ˿�
    char strUsrName[64]; //�������ݿ��û���
    char strPwd[64];         //�������ݿ�����
    char strDbName[64];  //���ݿ���
}SDBCONNINFO_STU,*SDBCONNINFO_ID;
#define SDBCONNINFO_STU_SIZE sizeof(SDBCONNINFO_STU)

typedef struct stuSDBCONNINFO_PKT
{
    NET_MSG_HDR hdr;
    SDBCONNINFO_STU body;
}SDBCONNINFO_PKT,*SDBCONNINFO_PKT_ID;
#define SDBCONNINFO_PKT_SIZE sizeof(SDBCONNINFO_PKT)

/*�û��б�*/
typedef struct stuUSRLIST
{
    char strIp[32];            //IP��ַ
    char strMac[16];         //MAC��ַ
    int iUsrId;                   //�û�ID
    unsigned char strUsrName[64]; //�û���
    int iUsrGId;                               //�û���ID
}USRLIST_STU,*USRLIST_ID;
#define USRLIST_STU_SIZE sizeof(USRLIST_STU)

typedef struct stuUSRLIST_PKT
{
    NET_MSG_HDR hdr;
    USRLIST_STU body;
}USRLIST_PKT,*USRLIST_PKT_ID;
#define USRLIST_PKT_SIZE sizeof(USRLIST_PKT)

/*��Ȩ��ϵ�б�*/
typedef struct stuSQLIST
{
    int iUsrGId;  //�û���ID
    int iRuleGId; //��Դ��ID
}SQLIST_STU,*SQLIST_ID;
#define SQLIST_STU_SIZE sizeof(SQLIST_STU)

typedef struct stuSQLIST_PKT
{
    NET_MSG_HDR hdr;
    SQLIST_STU body;
}SQLIST_PKT,*SQLIST_PKT_ID;
#define SQLIST_PKT_SIZE sizeof(SQLIST_PKT)

/*������Դ�б�*/
typedef struct stuRULESLIST
{
    long lRuleId;          //��ԴID
    char strIp[32];       //IP
    char strMask[32];  //����
    short port;             //�˿� 
    short sProClass;    //Э�����
    short sSQclass;     //��Ȩ��Ƽ���
    short sWSQclass;  //δ��Ȩ��Ƽ���
    int iRuleGId;         //��Դ��ID
}RULESLIST_STU,*RULESLIST_ID;
#define RULESLIST_STU_SIZE sizeof(RULESLIST_STU)

typedef struct stuRULESLIST_PKT
{
    NET_MSG_HDR hdr;
    RULESLIST_STU body;
}RULESLIST_PKT,*RULESLIST_PKT_ID;
#define RULESLIST_PKT_SIZE sizeof(RULESLIST_PKT)

#pragma pack()

#endif
