
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "protocol_ini.h"
#include "protocol_cfg.h"
#include "eAudit_log.h"

const char* proto_list[] = {"HTTP", "FTP", "SMTP", "POP3", "TELNET", "MSN", "EMULE", "X11",
					  "RDP", "RLOGIN", "NETBIOS", "SYBASE", "SQLSERVER", "ORACLE",
					  "INFORMIX", "DB2", "ARP", "SKYPE","QQ","THUNDER","BT", "FETION"};


/**********************************
*func name: proGetProtectedRes
*function: ��ȡ������Դ�����ļ���Э��IDΪpro_id����Ӧ�ı�����Դ��Ϊ�������ڴ�ռ�,
		   ����������ԴID���򣬽��׵�ַ����protected_res_ptr
*parameters:
		�������: protocol_id: Э��ID
				  cfg_dir: �����ļ����Ŀ¼
		�������: protected_res_ptr: ������Դ�б��׵�ַָ��
*call:
*called:
*return: �ɹ�ʱ���ػ�ȡ���ı�����Դ�б���������󷵻�-1
*/
int proGetProtectedRes (PRO_PROTECTED_RESOURCE **protected_res_ptr, 
								int protocol_id, const char *cfg_dir)
{
	int i = 0;
	int listNum = 0;
	int match_num = 0; //������Э��ID��ƥ��ı�����Դ����
	int protected_res_num = -1;	//�ɹ��������ı�����Դ����, ��ʵ������ı�����Դ����
	char file_path[MAX_FILE_PATH_SIZE+1];
	char info_str[32];
	char key_val_tmp[512];	//�����ö�ȡ����һ��������Դ�ִ�
	char key_val_cur[512];	//�Ե�ǰ������Դ�ִ��ı���
	char key_val_match[255][512];	//������Э��IDƥ������б�����Դ�ִ�
	int key_val_seq[255];	//key_val_match�а��ձ�����ԴID�±�����Ľ��
	int protected_res_id_tmp[255];//��ʱ��ŵ�������Э��IDƥ������б�����ԴID, ���ڶԱ�����Դ��Ϣ�����±�����
	FILE *fp = NULL;
	char *protocol_str;
	char *protect_resource_addr, *not_authorize_info_addr, *eaudit_level_info_addr;
	char *protected_res_name, *protected_res_id, *protected_res_content;
	char *block_flag, *warn_flag, *log_flag;
	char *eaudit_direction, *session_level, *record_level, *event_level,
		 *analysis_level, *total_analysis_level, *custom_made_level, *manage_level;
	int authorize_flag, eaudit_info_state;
	PRO_PROTECTED_RESOURCE *protected_res_cur;


	/*	1 �ӱ�����Դ�����ļ���ȡlistNum
		2 ѭ��listNum�ζ�ȡ������Դ��Ϣ
		3 ���ڶ�ȡ�ı�����Դ��Ϣ���ж���Э�����ͺ�����Э��ID�Ƿ�ƥ��, ���ƥ�䱣��
		  ����������Դ��Ϣ������key_val_match, ��¼����������Դ��Ϣ��ID, ��ѯ����
		  ��ƥ��ı�����Դ����match_num��һ
		4 ѭ������������match_num��Ԫ�ı�����Դ��Ϣ�ڴ�
		5 ���ձ�����ԴID�Թ��˳��ı�����Դ��Ϣ�����±�����
		6 ��������Ľ����һ��������key_val_match�еı�����Դ, ���ѽ������д������
		  ���ڴ�, ��¼�ɹ��������ı�����Դ����protected_res_num
		7 ���򷵻�
	*/
	if (NULL != protected_res_ptr)
		*protected_res_ptr = NULL;//��ֹ���ú���ʱ����û������, ���������ڴ�ǰ��goto�����

	if (NULL == protected_res_ptr || NULL == cfg_dir)
		goto sailing_return;

	memset(key_val_seq, 0x00, sizeof(key_val_seq));
	memset(protected_res_id_tmp, 0x00, sizeof(protected_res_id_tmp));
	memset(key_val_match, 0x00, sizeof(key_val_match));
	memset(file_path, 0x00, sizeof(file_path));

	if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
		sprintf(file_path, "%s/%s", cfg_dir, PMC_PROTECT_RESOURCE_FILE_NAME);
	else
		sprintf(file_path, "%s%s", cfg_dir, PMC_PROTECT_RESOURCE_FILE_NAME);

	fp = fopen(file_path, "r");
	if (NULL == fp)
		goto sailing_return;

	cfgGetListNum(fp, &listNum);
	if (listNum <= 0)
	{
		protected_res_num = 0;
		goto sailing_return;
	}


	//����������Դ�����е�ÿ��������Դ��Ϣ
	for (i=0; i<listNum; i++)
	{
		memset(key_val_tmp, 0x00, sizeof(key_val_tmp));
		memset(key_val_cur, 0x00, sizeof(key_val_cur));
		memset(info_str, 0x00, sizeof(info_str));

		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//��ȡһ��������Դ��Ϣ(�����ĵڶ���������ʹ��NULL, ��Ϊ�˱�֤����Ŀɿ���!)
		if (TRUE != cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val_tmp, sizeof(key_val_tmp)))
			continue;
		strcpy(key_val_cur, key_val_tmp);

		protect_resource_addr = strtok(key_val_tmp, LIST_ITEMS_INDER);
		protocol_str = strrchr(protect_resource_addr, LIST_ITEMS_DELIM_CHAR);
		if(NULL == protocol_str)
			continue;

		//�жϸ���������Դ��Ϣ�Ƿ�������Э��IDƥ��
		//���ƥ�䱣��ñ�����Դ��Ϣ�������Դ���������
		if (strcmp(protocol_str+1, proto_list[protocol_id]) == 0)
		{
			strtok(protect_resource_addr, LIST_ITEMS_DELIM);
			protected_res_id = strtok(NULL, LIST_ITEMS_DELIM);
			if(NULL == protected_res_id)
				continue;

			protected_res_id_tmp[match_num] = atoi(protected_res_id);
			strcpy(key_val_match[match_num], key_val_cur);
			match_num++;
		}
	}

	
	if (match_num <= 0)
	{
		protected_res_num = 0;
		goto sailing_return;
	}

	//�����ڴ浥Ԫ���ڴ洢������Դ��Ϣ�����
	*protected_res_ptr = (PRO_PROTECTED_RESOURCE_ID)calloc(PRO_PROTECTED_RESOURCE_SIZE, match_num);
	if (NULL == *protected_res_ptr)
		goto sailing_return;

	//���ձ�����ԴID�Ի���key_val_match������¼�ı�����Դ�����±�����
	//�±�����Ľ��������key_val_seq��
	if (FALSE == sortIndex(protected_res_id_tmp, key_val_seq, match_num))
		goto sailing_return;


	//���������е�ÿ��������Դ��д��������ڴ�
	protected_res_cur = *protected_res_ptr;
	protected_res_num = 0;

	for (i=0; i<match_num; i++)
	{//δ���!!!!!!
		protect_resource_addr = strtok(key_val_match[key_val_seq[i]], LIST_ITEMS_INDER);

		if(NULL == protect_resource_addr)
			continue;
        not_authorize_info_addr = strtok(NULL, LIST_ITEMS_INDER);
		if(NULL == not_authorize_info_addr)
			continue;
		eaudit_level_info_addr = strtok(NULL, LIST_ITEMS_INDER);
        if(NULL == eaudit_level_info_addr)
			continue;

        protected_res_name = strtok(protect_resource_addr, LIST_ITEMS_DELIM);
		if(NULL == protected_res_name)
			continue;
        protected_res_id = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == protected_res_id)
			continue;
        protected_res_content = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == protected_res_content)
			continue;

        block_flag = strtok(not_authorize_info_addr, LIST_ITEMS_DELIM);
		if(NULL == block_flag)
			continue;
        warn_flag = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == warn_flag)
			continue;
        log_flag = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == log_flag)
			continue;

        eaudit_direction = strtok(eaudit_level_info_addr, LIST_ITEMS_DELIM);
		if(NULL == eaudit_direction)
			continue;
        session_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == session_level)
			continue;
        record_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == record_level)
			continue;
        event_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == event_level)
			continue;
        analysis_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == analysis_level)
			continue;
        total_analysis_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == total_analysis_level)
			continue;
        custom_made_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == custom_made_level)
			continue;
        manage_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == manage_level)
			continue;

		if (strlen(protected_res_name) < sizeof(protected_res_cur->protected_res_name))
			strcpy(protected_res_cur->protected_res_name, protected_res_name);
		protected_res_cur->protected_res_id = atoi(protected_res_id);
		//protected_res_content�Ĵ������!!!!!
		protected_res_cur->protected_res_content =
			proGetContofProt(protected_res_content);

		protected_res_cur->unauthorize_event.block_flag = atoi(block_flag);
		protected_res_cur->unauthorize_event.warn_flag = atoi(warn_flag);
		protected_res_cur->unauthorize_event.log_flag = atoi(log_flag);

		protected_res_cur->eaudit_level.eaudit_direction = atoi(eaudit_direction);
		protected_res_cur->eaudit_level.session_level = atoi(session_level);
		protected_res_cur->eaudit_level.record_level = atoi(record_level);
		protected_res_cur->eaudit_level.event_level = atoi(event_level);
		protected_res_cur->eaudit_level.analysis_level = atoi(analysis_level);
		protected_res_cur->eaudit_level.total_analysis_level = atoi(total_analysis_level);
		protected_res_cur->eaudit_level.custom_made_level = atoi(custom_made_level);
		protected_res_cur->eaudit_level.manage_level = atoi(manage_level);

		//authorize_flag��eaudit_info_state�Ĵ������!!!!!!

		protected_res_cur++;
		protected_res_num++;
	}

sailing_return:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}

	if (protected_res_num <= 0 && NULL != *protected_res_ptr)
	{
		free(*protected_res_ptr);
		*protected_res_ptr = NULL;
	}

	return protected_res_num;
}

/**********************************
*func name: proGetAuthrizUsers
*function: ��ȡ�û������ļ��е��û���Ϣ��Ϊ�������ڴ�ռ䣬�����û�ID���򣬽��׵�ַ
		   ����pro_user_ptr
*parameters:
		�������: cfg_dir: �����ļ����Ŀ¼
		�������: pro_user_ptr: �û��б��׵�ַָ��
*call:
*called:
*return: �ɹ�ʱ���ػ�ȡ�����û���Ϣ�б���������󷵻�-1
*/
int proGetAuthrizUsrs(PRO_USR_INFO **pro_usr_ptr, const char *cfg_dir)
{
	int i = 0;
	int listNum = 0;
	int read_num = 0;	//�����ö�ȡ�����û���Ϣ�ĸ���
	int usr_num = -1;	//�ɹ����������û���Ϣ�ĸ�������ʵ��������û���Ϣ�ĸ���
	int usr_id[512];
	int key_val_seq[512];
	char info_str[32];
	char key_val_tmp[512];		//��ȡ����һ���û���Ϣ�ִ�
	char key_val_cur[512];		//�Ե�ǰ�û���Ϣ�ִ��ı���
	char key_val[255][512];		//��ȡ���������û���Ϣ�ִ�
	char file_path[MAX_FILE_PATH_SIZE+1];
	FILE *fp = NULL;
	char *usr_id_cur, *usr_name_cur;
	PRO_USR_INFO *pro_usr_cur;


	/*	1 ���û������ļ���ȡ�û���Ϣ����listNum
		2 ѭ��listNum�Σ���ȡ�û���Ϣ, �����û�ID���ڻ���usr_id, �����û���Ϣ����
		  ����key_val
		3 ����listNum����Ԫ���û���Ϣ�ڴ�
		4 �����û�ID���û���Ϣ�����±�����
		5 ��������Ľ����һ��������key_val�е��û���Ϣ, ���ѽ������д������
		  ���ڴ�, ��¼�ɹ����������û���Ϣ����usr_num
		7 ���򷵻�
	*/
	if (NULL != pro_usr_ptr)
		*pro_usr_ptr = NULL;//��ֹ���ú���ʱ����û������, ���������ڴ�ǰ��goto�����

	if (NULL == pro_usr_ptr || NULL == cfg_dir)
		goto sailing_return;
	
	memset(usr_id, 0x00, sizeof(usr_id));
	memset(key_val_seq, 0x00, sizeof(key_val_seq));
	memset(key_val, 0x00, sizeof(key_val));
	memset(file_path, 0x00, sizeof(file_path));

	if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
		sprintf(file_path, "%s/%s", cfg_dir, PMC_USR_LIST_FILE_NAME);
	else
		sprintf(file_path, "%s%s", cfg_dir, PMC_USR_LIST_FILE_NAME);
	
	fp = fopen(file_path, "r");
	if (NULL == fp)
		goto sailing_return;

	cfgGetListNum(fp, &listNum);
	if (listNum <= 0)
	{
		usr_num = 0;
		goto sailing_return;
	}


	//�����ö�ȡ�û���Ϣ����ڻ���key_val��������usr id����ڻ���usr_id
	for (i=0; i<listNum; i++)
	{
		memset(key_val_tmp, 0x00, sizeof(key_val_tmp));
		memset(key_val_cur, 0x00, sizeof(key_val_cur));
		memset(info_str, 0x00, sizeof(info_str));

		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//��ȡһ���û���Ϣ
		if (TRUE != cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val_tmp, sizeof(key_val_tmp)))
			continue;
		strcpy(key_val_cur, key_val_tmp);

		//��ȡ��usr_id
		usr_id_cur = strtok(key_val_tmp, LIST_ITEMS_DELIM);
		if (NULL == usr_id_cur)
			continue;

		usr_id[i] = atoi(usr_id_cur);
		strcpy(key_val[i], key_val_cur);
		read_num++;
	}

	if (read_num <= 0)
	{
		usr_num = 0;
		goto sailing_return;
	}


	*pro_usr_ptr = (PRO_USR_INFO_ID)calloc(PRO_USR_INFO_SIZE, read_num);
	if (NULL == *pro_usr_ptr)
		goto sailing_return;


	//����usr id�Ի���key_val������¼���û���Ϣ�����±�����
	//�±�����Ľ��������key_val_seq��
	if (FALSE == sortIndex(usr_id, key_val_seq, read_num))
		goto sailing_return;


	//����usr id����Ľ�����������ö�ȡ���û���Ϣ����key_val
	pro_usr_cur = *pro_usr_ptr;
	usr_num = 0;

	for (i=0; i<read_num; i++)
	{
		//��ȡ��usr_id��usr_name
		usr_id_cur = strtok(key_val[key_val_seq[i]], LIST_ITEMS_DELIM);
		if (NULL == usr_id_cur)
			continue;
		strtok(NULL, LIST_ITEMS_DELIM);
		strtok(NULL, LIST_ITEMS_DELIM);
		usr_name_cur = strtok(NULL, LIST_ITEMS_DELIM);
		if (NULL == usr_name_cur || strlen(usr_name_cur) >= sizeof(pro_usr_cur->strUsrName))
			continue;

		//��usr_id��usr_name��ֵ������������ڴ�
		strcpy(pro_usr_cur->strUsrName, usr_name_cur);
		pro_usr_cur->usr_id = atoi(usr_id_cur);

		pro_usr_cur++;
		usr_num++;
	}

sailing_return:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}

	if (usr_num <= 0 && NULL != *pro_usr_ptr)
	{
		free(*pro_usr_ptr);
		*pro_usr_ptr = NULL;
	}

	return usr_num;
}

/**********************************
*func name: proGetAuthrizNets
*function: ���ݱ�����Դ�б������еı�����ԴID����ȡ��ص�����������Ȩ��Ϣ��Ϊ������
		   �ڴ�ռ䣬����������ȨID���򣬽��׵�ַ����pro_network_ptr
*parameters:
		�������: protected_res_ptr: ������Դ�б��׵�ַָ��
				  protected_res_num: ������Դ�б��еı�����Դ����
				  cfg_dir: �����ļ����Ŀ¼
		�������: pro_ network_ptr: ������Ȩ�б��׵�ַָ��
*call:
*called:
*return: �ɹ�ʱ���ػ�ȡ����������Ȩ��Ϣ�б���������󷵻�-1
*/
int proGetAuthrizNets(PRO_NETWORK_INFO **pro_network_ptr,
		const PRO_PROTECTED_RESOURCE *protected_res_ptr, int protected_res_num, const char *cfg_dir)
{
	int i, j;
	int listNum = 0;
	int match_num = 0;	//�뱣����Դ�б��б�����ԴIDƥ���������Ȩ��Ϣ����
	int network_num = -1;	//�ɹ�������������Ȩ��Ϣ��������ʵ�������������Ȩ��Ϣ����
	char file_path[MAX_FILE_PATH_SIZE+1];
	FILE *fp = NULL;
    char info_str[32];
	char key_val_tmp[512];	//��ȡ����һ��������Ȩ�ִ�
	char key_val_cur[512];	//�Ե�ǰ������Ȩ�ִ��ı���
	char key_val_match[255][512];	//�뱣����ԴIDƥ���һ��������Ȩ�ִ�
	int key_val_seq[255];	//key_val_match�а�����ȨID�±�����Ľ��
	int authorize_id_tmp[255];
	const PRO_PROTECTED_RESOURCE *protected_res_cur;
	PRO_NETWORK_INFO *pro_network_cur;
	char *authorize_id, *usr_id, *protected_res_id, *eaudit_level_info_addr, *authorize_info_addr;
	char *eaudit_direction, *session_level, *record_level, *event_level,
		 *analysis_level, *total_analysis_level, *custom_made_level, *manage_level;
	char *authorize_account, *authorize_cmd, *authorize_custom_made, *authorize_pro_feature_made;
	int authorize_flag, eaudit_info_state;


	/*	1 ��������Ȩ�����ļ���ȡ������Ȩ��Ϣ����listNum
		2 ѭ��listNum�Σ���ȡ������Ȩ��Ϣ
		3 ���ڶ�ȡ��ÿ��������Ȩ��Ϣ, ����������Դ�б�, ���ұ�����Դ�б��б�����ԴID
		  �Ƿ������������Ȩ��Ϣƥ��, ���ƥ��Ѹ���������Ȩ��Ϣ�����ڻ���key_val_match, 
		  ��¼����������Ȩ��Ϣ��������ȨID, ��ѯ������ƥ���������Ȩ��Ϣ����match_num��һ
		4 ����match_num����Ԫ��������Ȩ��Ϣ�ڴ�
		5 ����������ȨID�Թ��˳���������Ȩ��Ϣ�����±�����
		6 ��������Ľ����һ���������е�������Ȩ���ò�д��������ڴ����, ��¼�ɹ�����
		  ����������Ȩ��Ϣ����network_num
		7 ���򷵻�
	*/
	if (NULL != pro_network_ptr)
		*pro_network_ptr = NULL;//��ֹ���ú���ʱ����û������, ���������ڴ�ǰ��goto�����

	if (NULL == pro_network_ptr || NULL == protected_res_ptr 
								|| protected_res_num <= 0 || NULL == cfg_dir)
		goto sailing_return;

	memset(key_val_seq, 0x00, sizeof(key_val_seq));
	memset(authorize_id_tmp, 0x00, sizeof(authorize_id_tmp));
	memset(file_path, 0x00, sizeof(file_path));

	if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
		sprintf(file_path, "%s/%s", cfg_dir, PMC_AUTHORIZE_ACCESS_NETWORK_FILE_NAME);
	else
		sprintf(file_path, "%s%s", cfg_dir, PMC_AUTHORIZE_ACCESS_NETWORK_FILE_NAME);
	
	fp = fopen(file_path, "r");
	if (NULL == fp)
		goto sailing_return;

	cfgGetListNum(fp, &listNum);
	if (listNum <= 0)
	{
		network_num = 0;
		goto sailing_return;
	}


	for (i=0; i<listNum; i++)
	{
		memset(key_val_cur, 0x00, sizeof(key_val_cur));
		memset(key_val_tmp, 0x00, sizeof(key_val_tmp));
		memset(info_str, 0x00, sizeof(info_str));
		sprintf(info_str, "%s%d",LIST_RESOURCE_KEY, i);

		//��ȡһ��������Ȩ
		if (TRUE != cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val_tmp, sizeof(key_val_tmp)))
			continue;
		strcpy(key_val_cur, key_val_tmp);

		authorize_id = strtok(key_val_tmp, LIST_ITEMS_INDER);
        if(NULL == authorize_id)
			continue;
        usr_id = strtok(NULL, LIST_ITEMS_INDER);
        if(NULL == usr_id)
			continue;
		protected_res_id = strtok(NULL, LIST_ITEMS_INDER);
        if(NULL == protected_res_id)
			continue;


		//�жϸ���������Ȩ��Ϣ�Ƿ��뱣����Դ�б��еĸ���������Դƥ��
		//���ƥ�䱣�����������Ȩ��Ϣ�����棬�Դ���������
		protected_res_cur = protected_res_ptr;

		for (j=0; j<protected_res_num; j++)
		{
			if (atoi(protected_res_id) == protected_res_cur->protected_res_id)
			{
				authorize_id_tmp[match_num] = atoi(authorize_id);
				strcpy(key_val_match[match_num], key_val_cur);
				match_num++;
			}

			protected_res_cur++;
		}
	}

	if (match_num <= 0)
	{
		network_num = 0;
		goto sailing_return;
	}

	//����������Ȩ��Ϣ�ڴ�
	*pro_network_ptr = (PRO_NETWORK_INFO_ID)calloc(PRO_NETWORK_INFO_SIZE, match_num);
	if (NULL == *pro_network_ptr)
		goto sailing_return;


	//������ȨID�Ի���key_val_match������¼��������Ȩ�����±�����
	//�±�����Ľ��������key_val_seq��
	if (FALSE == sortIndex(authorize_id_tmp, key_val_seq, match_num))
		goto sailing_return;


	pro_network_cur = *pro_network_ptr;
	network_num = 0;

	//���������е�������Ȩ��Ϣ��д��������ڴ����
	for (i=0; i<match_num; i++)
	{//����key_val_match
		//δ���!!!!!!
		authorize_id = strtok(key_val_match[key_val_seq[i]], LIST_ITEMS_INDER);
		if(NULL == authorize_id)
			continue;
        usr_id = strtok(NULL, LIST_ITEMS_INDER);
		if(NULL == usr_id)
			continue;
		protected_res_id = strtok(NULL, LIST_ITEMS_INDER);
        if(NULL == protected_res_id)
			continue;
		eaudit_level_info_addr = strtok(NULL, LIST_ITEMS_INDER);
        if(NULL == eaudit_level_info_addr)
			continue;
		authorize_info_addr = strtok(NULL, LIST_ITEMS_INDER);
        if(NULL == authorize_info_addr)
			continue;

        eaudit_direction = strtok(eaudit_level_info_addr, LIST_ITEMS_DELIM);
		if(NULL == eaudit_direction)
			continue;
        session_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == session_level)
			continue;
        record_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == record_level)
			continue;
        event_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == event_level)
			continue;
        analysis_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == analysis_level)
			continue;
        total_analysis_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == total_analysis_level)
			continue;
        custom_made_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == custom_made_level)
			continue;
        manage_level = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == manage_level)
			continue;

        authorize_cmd = strtok(authorize_info_addr, LIST_ITEMS_DELIM);
		if(NULL == authorize_cmd)
			continue;
        authorize_account = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == authorize_account)
			continue;
        authorize_custom_made = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == authorize_custom_made)
			continue;
        authorize_pro_feature_made = strtok(NULL, LIST_ITEMS_DELIM);
		if(NULL == authorize_pro_feature_made)
			continue;

		pro_network_cur->authorize_id = atoi(authorize_id);
		pro_network_cur->usr_id= atoi(usr_id);
		pro_network_cur->protected_res_id = atoi(protected_res_id);

		pro_network_cur->eaudit_level.eaudit_direction = atoi(eaudit_direction);
		pro_network_cur->eaudit_level.session_level = atoi(session_level);
		pro_network_cur->eaudit_level.record_level = atoi(record_level);
		pro_network_cur->eaudit_level.event_level = atoi(event_level);  
		pro_network_cur->eaudit_level.analysis_level = atoi(analysis_level);
		pro_network_cur->eaudit_level.total_analysis_level = atoi(total_analysis_level);
		pro_network_cur->eaudit_level.custom_made_level = atoi(custom_made_level);
		pro_network_cur->eaudit_level.manage_level = atoi(manage_level);

		pro_network_cur->authorize_level.authorize_cmd = atoi(authorize_cmd);
		pro_network_cur->authorize_level.authorize_account = atoi(authorize_account);
		pro_network_cur->authorize_level.authorize_custom_made = atoi(authorize_custom_made);
		pro_network_cur->authorize_level.authorize_pro_feature_made = atoi(authorize_pro_feature_made);

		pro_network_cur++;
		network_num++;
	}

sailing_return:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}

	if (network_num <= 0 && NULL != *pro_network_ptr)
	{
		free(*pro_network_ptr);
		*pro_network_ptr = NULL;
	}

	return network_num;
}

/**********************************
*func name: proCallocAuthrizRelatInfos
*function: ����������Ȩ�б���������벢��ʼ����Ȩ��ϵ�б�ռ䣬���ռ��׵�ַ��ֵ��authorize_rel_ptr
*parameters:
		�������: network_num: ������Ȩ��Ϣ�б����
		�������: authorize_rel_ptr: ��Ȩ��ϵ�б�ռ��׵�ַָ��
*call:
*called:
*return: �ɹ�ʱ��������ռ��ַ�����󷵻�NULL
*/
PRO_AUTHRIZ_RELATION_INFO* proCallocAuthrizRelatInfos(PRO_AUTHRIZ_RELATION_INFO** 
											authorize_rel_ptr, int network_num)
{
	if (NULL == authorize_rel_ptr || network_num <= 0)
		return NULL;

	*authorize_rel_ptr = 
		(PRO_AUTHRIZ_RELATION_INFO_ID)calloc(PRO_AUTHRIZ_RELATION_INFO_SIZE, network_num);
	if (NULL == *authorize_rel_ptr)
		return NULL;

	return *authorize_rel_ptr;
}

/**********************************
*func name: proInitRelatInfNets
*function: ��ʼ����Ȩ��ϵ�б�ռ��е�������Ȩ��Ϣָ�롣
		   ����������ȨID����ʽ��ֵ��Ȩ��ϵ�б�ռ��е�������Ȩ��Ϣָ��
*parameters:
		�������: authorize_rel_num: ��Ȩ��ϵ�б����
				  pro_ network_ptr: ������Ȩ�б��׵�ַָ��
		�������: authorize_rel_ptr: ��Ȩ��ϵ�б�ռ��׵�ַָ��
*call:
*called:
*return: �ɹ�ʱ����1�����󷵻�0
*/
int proInitRelatInfNets(PRO_AUTHRIZ_RELATION_INFO *authorize_rel_ptr, 
							int authorize_rel_num, PRO_NETWORK_INFO *network_info_ptr)
{
	int i;
	
	if (NULL == authorize_rel_ptr || authorize_rel_num <= 0 || NULL == network_info_ptr)
		return FALSE;

	for (i=0; i<authorize_rel_num; i++)
	{
		(authorize_rel_ptr+i)->network_addr = network_info_ptr+i;
	}

	return TRUE;
}

/**********************************
*func name: proInitRelatInfProRes
*function: ��ʼ����Ȩ��ϵ�б�ռ��еı�����Դ��Ϣָ�롣
		   ��������Ȩ��ϵ�б�ռ��е�������Ȩ��ϵ�����Ҷ�Ӧ�ı�����Դָ��

*parameters:
		�������: authorize_rel_num: ��Ȩ��ϵ�б����
				  protected_res_ptr: ������Դ�б��׵�ַָ��
				  protected_res_num: ������Դ�б��еı�����Դ����
		�������: authorize_rel_ptr: ��Ȩ��ϵ�б�ռ��׵�ַָ��
*call:
*called:
*return: �ɹ�ʱ����1�����󷵻�0
*/
int proInitRelatInfProRes(PRO_AUTHRIZ_RELATION_INFO *authorize_rel_ptr, int authorize_rel_num, 
					PRO_PROTECTED_RESOURCE *protected_res_ptr, int protected_res_num)
{
	int i, j;
	PRO_AUTHRIZ_RELATION_INFO *authorize_rel_cur = NULL;
	PRO_PROTECTED_RESOURCE *protected_res_cur = NULL;

	if (NULL == authorize_rel_ptr || authorize_rel_num <= 0
							|| NULL == protected_res_ptr || protected_res_num <= 0)
		return FALSE;


	authorize_rel_cur = authorize_rel_ptr;

	for (i=0; i<authorize_rel_num; i++)
	{
		protected_res_cur = protected_res_ptr;

		for (j=0; j<protected_res_num; j++)
		{
			if (authorize_rel_cur->network_addr->protected_res_id
					== protected_res_cur->protected_res_id)
			{
				authorize_rel_cur->protected_res_addr = protected_res_cur;
				break;
			}

			protected_res_cur++;
		}

		authorize_rel_cur++;
	}

	return TRUE;
}

/**********************************
*func name: proInitRelatInfUsr
*function: ��ʼ����Ȩ��ϵ�б�ռ��е��û���Ϣָ�롣
		   ��������Ȩ��ϵ�б�ռ��е�������Ȩ��ϵ�����Ҷ�Ӧ���û���Ϣָ��
*parameters:
		�������: authorize_rel_num: ��Ȩ��ϵ�б����
				  usr_ptr: �û���Ϣ�б��׵�ַָ��
				  usr_num: �û���Ϣ�б����
		�������: authorize_rel_ptr: ��Ȩ��ϵ�б�ռ��׵�ַָ��
*call:
*called:
*return: �ɹ�ʱ����1�����󷵻�0
*/
int proInitRelatInfUsr(PRO_AUTHRIZ_RELATION_INFO *authorize_rel_ptr, int authorize_rel_num, 
								PRO_USR_INFO *usr_ptr, int usr_num)
{
	int i, j;
	PRO_AUTHRIZ_RELATION_INFO *authorize_rel_cur = NULL;
	PRO_USR_INFO *usr_cur = NULL;

	if (NULL == authorize_rel_ptr || authorize_rel_num <= 0
							|| NULL == usr_ptr || usr_num <= 0)
		return FALSE;

	authorize_rel_cur = authorize_rel_ptr;

	for (i=0; i<authorize_rel_num; i++)
	{
		usr_cur = usr_ptr;

		for (j=0; j<usr_num; j++)
		{
			if (authorize_rel_cur->network_addr->usr_id == usr_cur->usr_id)
			{
				authorize_rel_cur->usr_addr = usr_cur;
				break;
			}

			usr_cur++;
		}

		authorize_rel_cur++;
	}

	return TRUE;
}

/**********************************
*func name: proGetAuthrizAccts
*function: ������Ȩ��ϵ�б��е�������ȨID, ��ȡ�˺���Ȩ������Ϣ, Ϊ�������ڴ�ռ�,
		   �����׵�ַ������Ӧ���˺���Ȩָ��
*parameters:
		�������: authorize_rel_num: ��Ȩ��ϵ�б����
				  cfg_dir: �����ļ����Ŀ¼
		�������: authorize_rel_ptr: ��Ȩ��ϵ�б�ռ��׵�ַָ��
*call:
*called:
*return: �ɹ�ʱ���ػ�õ��˺���Ȩ��ϵ���������󷵻�-1
*/
int proGetAuthrizAccts(PRO_AUTHRIZ_RELATION_INFO *authorize_rel_ptr, 
							int authorize_rel_num, const char *cfg_dir)
{
	int i, j, k;
	int listNum;
	int authorize_id_cur;
	int AuthrizAcctsNum = -1;
    char info_str[32];
	char file_path[MAX_FILE_PATH_SIZE+1];
	FILE *fp = NULL;
	char key_val[512];	//��ȡ����һ���˺���Ȩ�ִ�
	char *authorize_id, *unauthorize_event, *authorize_content;
	char *block_flag, *warn_flag, *log_flag, *account_num, *authorize_account;
	PRO_AUTHRIZ_RELATION_INFO_ID authorize_rel_cur;


	/*	1 ���˺���Ȩ�����ļ���ȡ�˺���Ȩ��Ϣ����listNum
		2 ѭ��listNum�Σ���ȡ�˺���Ȩ��Ϣ
		3 ���ڶ�ȡ��ÿ���˺���Ȩ��Ϣ, ������Ȩ��ϵ�б�, ������Ȩ��ϵ�б���������ȨID
		  �Ƿ�������˺���Ȩ��Ϣƥ��, ���ƥ������һ����Ԫ���˺���Ȩ��Ϣ�ڴ�, ָ��
		  ��ǰ����Ȩ��ϵ�б���˺���Ȩ��Ϣָ��, �������˺���Ȩ��Ϣ��д��������ڴ�, 
		  AuthrizAcctsNum��һ
		4 ���򷵻�
	*/
	if (NULL == authorize_rel_ptr || authorize_rel_num <= 0 || NULL == cfg_dir)
		goto sailing_return;

	memset(file_path, 0x00, sizeof(file_path));

	if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
		sprintf(file_path, "%s/%s", cfg_dir, PMC_AUTHORIZE_ACCESS_ACCOUNT_FILE_NAME);
	else
		sprintf(file_path, "%s%s", cfg_dir, PMC_AUTHORIZE_ACCESS_ACCOUNT_FILE_NAME);
	
	fp = fopen(file_path, "r");
	if (NULL == fp)
		goto sailing_return;

	cfgGetListNum(fp, &listNum);
	if (listNum <= 0)
	{
		AuthrizAcctsNum = 0;
		goto sailing_return;
	}


	AuthrizAcctsNum = 0;

	for (i=0; i<listNum; i++)
	{
		memset(key_val, 0x00, sizeof(key_val));
		memset(info_str, 0x00, sizeof(info_str));
		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//���Կ����ȶ��������ڻ��棬Ȼ����ʹ��!!!!!!!!!
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		authorize_id = strtok(key_val, LIST_ITEMS_INDER);
		if (authorize_id == NULL)
			continue;
		authorize_id_cur = atoi(authorize_id);


		authorize_rel_cur = authorize_rel_ptr;
		for (j=0; j<authorize_rel_num; j++)
		{
			if (authorize_id_cur == authorize_rel_cur->network_addr->authorize_id)
			{//���ҵ���������ȨIDƥ����˺���Ȩ��Ϣ
				authorize_rel_cur->account_addr = (PRO_ACCOUNT_INFO_ID)calloc(PRO_ACCOUNT_INFO_SIZE, 1);
				if (NULL == authorize_rel_cur->account_addr)
					goto sailing_return;


				unauthorize_event = strtok(NULL, LIST_ITEMS_INDER);
				if (NULL == unauthorize_event)
					break;
				authorize_content = strtok(NULL, LIST_ITEMS_INDER);
				if (NULL == authorize_content)
					break;

				block_flag = strtok(unauthorize_event, LIST_ITEMS_DELIM);
				if (NULL == block_flag)
					break;
				warn_flag = strtok(NULL, LIST_ITEMS_DELIM);
				if (NULL == warn_flag)
					break;
				log_flag = strtok(NULL, LIST_ITEMS_DELIM);
				if (NULL == log_flag)
					break;

				account_num = strtok(authorize_content, LIST_ITEMS_DELIM);
				if (NULL == account_num)
					break;

				authorize_rel_cur->account_addr->authorize_id = atoi(authorize_id);
				authorize_rel_cur->account_addr->unauthorize_event.block_flag = atoi(block_flag);
				authorize_rel_cur->account_addr->unauthorize_event.warn_flag = atoi(warn_flag);
				authorize_rel_cur->account_addr->unauthorize_event.log_flag = atoi(log_flag);
				authorize_rel_cur->account_addr->account_num = atoi(account_num);

				if (authorize_rel_cur->account_addr->account_num > 64)
					authorize_rel_cur->account_addr->account_num = 64;

				for (k=0; k<authorize_rel_cur->account_addr->account_num; k++)
				{
					authorize_account = strtok(NULL, LIST_ITEMS_DELIM);
					if (NULL == authorize_account || strlen(authorize_account) > 127)
						continue;
					
					strcpy(authorize_rel_cur->account_addr->authorize_account[k], authorize_account);
				}

				AuthrizAcctsNum++;
				break; //�����޶�һ��������ȨID����Ӧһ���˺���Ȩ��Ϣ!!!!!!
			}

			authorize_rel_cur++;
		}
	}

sailing_return:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}

	return AuthrizAcctsNum;
}

/**********************************
*func name: proGetAuthrizCmds
*function: ������Ȩ��ϵ�б��е�������ȨID����ȡָ����Ȩ������Ϣ��Ϊ�������ڴ�ռ䣬
		   �����׵�ַ������Ӧ��ָ����Ȩָ��
*parameters:
		�������: int authorize_rel_num: ��Ȩ��ϵ�б����
				  cfg_dir: �����ļ����Ŀ¼
		�������: authorize_rel_ptr:��Ȩ��ϵ�б��׵�ַ
*call:
*called:
*return: �ɹ�ʱ���ػ�õ�ָ����Ȩ��ϵ���������󷵻�-1
*/
int proGetAuthrizCmds(PRO_AUTHRIZ_RELATION_INFO *authorize_rel_ptr, 
						int authorize_rel_num, const char *cfg_dir)
{
	int i, j, k;
	int listNum;
	int AuthrizCmdsNum = -1;
    char info_str[32];
	char file_path[MAX_FILE_PATH_SIZE+1];
	FILE *fp = NULL;
	char key_val[512];	//��ȡ����һ��ָ����Ȩ�ִ�
	char *authorize_id, *unauthorize_event, *authorize_content;
	char *block_flag, *warn_flag, *log_flag, *cmd_num, *authorize_cmd;
	PRO_AUTHRIZ_RELATION_INFO_ID authorize_rel_cur;


	/*	1 ��ָ����Ȩ�����ļ���ȡָ����Ȩ��Ϣ����listNum
		2 ѭ��listNum�Σ���ȡָ����Ȩ��Ϣ
		3 ���ڶ�ȡ��ÿ��ָ����Ȩ��Ϣ, ������Ȩ��ϵ�б�, ������Ȩ��ϵ�б���������ȨID
		  �Ƿ������ָ����Ȩ��Ϣƥ��, ���ƥ������һ����Ԫ��ָ����Ȩ��Ϣ�ڴ�, ָ��
		  ��ǰ����Ȩ��ϵ�б��ָ����Ȩ��Ϣָ��, ������ָ����Ȩ��Ϣ��д��������ڴ�, 
		  AuthrizCmdsNum��һ
		4 ���򷵻�
	*/
	if (NULL == authorize_rel_ptr || authorize_rel_num <= 0 || NULL == cfg_dir)
		goto sailing_return;

	memset(file_path, 0x00, sizeof(file_path));

	if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
		sprintf(file_path, "%s/%s", cfg_dir, PMC_AUTHORIZE_ACCESS_CMD_FILE_NAME);
	else
		sprintf(file_path, "%s%s", cfg_dir, PMC_AUTHORIZE_ACCESS_CMD_FILE_NAME);
	
	fp = fopen(file_path, "r");
	if (NULL == fp)
		goto sailing_return;

	cfgGetListNum(fp, &listNum);
	if (listNum <= 0)
	{
		AuthrizCmdsNum = 0;
		goto sailing_return;
	}


	AuthrizCmdsNum = 0;

	for (i=0; i<listNum; i++)
	{
		memset(key_val, 0x00, sizeof(key_val));
		memset(info_str, 0x00, sizeof(info_str));
		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//���Կ����ȶ��������ڻ��棬Ȼ����ʹ��!!!!!!!!!
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		authorize_id = strtok(key_val, LIST_ITEMS_INDER);
		if (authorize_id == NULL)
			continue;


		authorize_rel_cur = authorize_rel_ptr;
		for (j=0; j<authorize_rel_num; j++)
		{
			if (atoi(authorize_id) == authorize_rel_cur->network_addr->authorize_id)
			{//���ҵ���������ȨIDƥ���ָ����Ȩ��Ϣ
				authorize_rel_cur->cmd_addr = (PRO_CMD_INFO_ID)calloc(PRO_CMD_INFO_SIZE, 1);
				if (NULL == authorize_rel_cur->cmd_addr)
					goto sailing_return;


				unauthorize_event = strtok(NULL, LIST_ITEMS_INDER);
				if (NULL == unauthorize_event)
					break;
				authorize_content = strtok(NULL, LIST_ITEMS_INDER);
				if (NULL == authorize_content)
					break;

				block_flag = strtok(unauthorize_event, LIST_ITEMS_DELIM);
				if (NULL == block_flag)
					break;
				warn_flag = strtok(NULL, LIST_ITEMS_DELIM);
				if (NULL == warn_flag)
					break;
				log_flag = strtok(NULL, LIST_ITEMS_DELIM);
				if (NULL == log_flag)
					break;

				cmd_num = strtok(authorize_content, LIST_ITEMS_DELIM);
				if (NULL == cmd_num)
					break;

				authorize_rel_cur->cmd_addr->authorize_id = atoi(authorize_id);
				authorize_rel_cur->cmd_addr->unauthorize_event.block_flag = atoi(block_flag);
				authorize_rel_cur->cmd_addr->unauthorize_event.warn_flag = atoi(warn_flag);
				authorize_rel_cur->cmd_addr->unauthorize_event.log_flag = atoi(log_flag);
				authorize_rel_cur->cmd_addr->cmd_num = atoi(cmd_num);

				if (authorize_rel_cur->cmd_addr->cmd_num > 64)
					authorize_rel_cur->cmd_addr->cmd_num = 64;

				for (k=0; k<authorize_rel_cur->cmd_addr->cmd_num; k++)
				{
					authorize_cmd = strtok(NULL, LIST_ITEMS_DELIM);
					if (NULL == authorize_cmd || strlen(authorize_cmd) > 127)
						continue;
					
					strcpy(authorize_rel_cur->cmd_addr->authorize_cmd[k], authorize_cmd);
				}

				AuthrizCmdsNum++;
				break; //�����޶�һ��ָ����ȨID����Ӧһ���˺���Ȩ��Ϣ!!!!!!
			}

			authorize_rel_cur++;
		}
	}

sailing_return:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}

	return AuthrizCmdsNum;
}

/**********************************
*func name: proGetAuthrizCustoms
*function: ������Ȩ��ϵ�б��е�������ȨID����ȡͨ����Ȩ������Ϣ��Ϊ�������ڴ�ռ䣬
		   �����׵�ַ������Ӧ��ͨ����Ȩָ��
*parameters:
		�������: authorize_rel_num: ��Ȩ��ϵ�б����
				  cfg_dir: �����ļ����Ŀ¼
		�������: authorize_rel_ptr:��Ȩ��ϵ�б��׵�ַ
*call:
*called:
*return: �ɹ�ʱ���ػ�õ�ͨ����Ȩ��ϵ���������󷵻�-1
*/
int proGetAuthrizCustoms(PRO_AUTHRIZ_RELATION_INFO *authorize_rel_ptr, 
							int authorize_rel_num, const char *cfg_dir)
{
	int i, j, k;
	int listNum;
	int AuthrizCustomsNum = -1;
    char info_str[32];
	char file_path[MAX_FILE_PATH_SIZE+1];
	FILE *fp = NULL;
	char key_val[512];	//��ȡ����һ��ͨ����Ȩ�ִ�
	char *authorize_id, *unauthorize_event, *authorize_content;
	char *block_flag, *warn_flag, *log_flag, *cmd_num, *authorize_custom;
	PRO_AUTHRIZ_RELATION_INFO_ID authorize_rel_cur;


	/*	1 ��ͨ����Ȩ�����ļ���ȡͨ����Ȩ��Ϣ����listNum
		2 ѭ��listNum�Σ���ȡͨ����Ȩ��Ϣ
		3 ���ڶ�ȡ��ÿ��ͨ����Ȩ��Ϣ, ������Ȩ��ϵ�б�, ������Ȩ��ϵ�б���������ȨID
		  �Ƿ������ͨ����Ȩ��Ϣƥ��, ���ƥ������һ����Ԫ��ͨ����Ȩ��Ϣ�ڴ�, ָ��
		  ��ǰ����Ȩ��ϵ�б��ͨ����Ȩ��Ϣָ��, ������ͨ����Ȩ��Ϣ��д��������ڴ�, 
		  AuthrizCustomsNum��һ
		4 ���򷵻�
	*/
	if (NULL == authorize_rel_ptr || authorize_rel_num <= 0 || NULL == cfg_dir)
		goto sailing_return;

	memset(file_path, 0x00, sizeof(file_path));

	if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
		sprintf(file_path, "%s/%s", cfg_dir, PMC_AUTHORIZE_ACCESS_CUSTOM_FILE_NAME);
	else
		sprintf(file_path, "%s%s", cfg_dir, PMC_AUTHORIZE_ACCESS_CUSTOM_FILE_NAME);
	
	fp = fopen(file_path, "r");
	if (NULL == fp)
		goto sailing_return;

	cfgGetListNum(fp, &listNum);
	if (listNum <= 0)
	{
		AuthrizCustomsNum = 0;
		goto sailing_return;
	}


	AuthrizCustomsNum = 0;

	for (i=0; i<listNum; i++)
	{
		memset(key_val, 0x00, sizeof(key_val));
		memset(info_str, 0x00, sizeof(info_str));
		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//���Կ����ȶ��������ڻ��棬Ȼ����ʹ��!!!!!!!!!
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		authorize_id = strtok(key_val, LIST_ITEMS_INDER);
		if (authorize_id == NULL)
			continue;


		authorize_rel_cur = authorize_rel_ptr;
		for (j=0; j<authorize_rel_num; j++)
		{
			if (atoi(authorize_id) == authorize_rel_cur->network_addr->authorize_id)
			{//���ҵ���������ȨIDƥ���ͨ����Ȩ��Ϣ
				authorize_rel_cur->custom_addr = (PRO_CUSTOM_INFO_ID)calloc(PRO_CUSTOM_INFO_SIZE, 1);
				if (NULL == authorize_rel_cur->custom_addr)
					goto sailing_return;


				unauthorize_event = strtok(NULL, LIST_ITEMS_INDER);
				if (NULL == unauthorize_event)
					break;
				authorize_content = strtok(NULL, LIST_ITEMS_INDER);
				if (NULL == authorize_content)
					break;

				block_flag = strtok(unauthorize_event, LIST_ITEMS_DELIM);
				if (NULL == block_flag)
					break;
				warn_flag = strtok(NULL, LIST_ITEMS_DELIM);
				if (NULL == warn_flag)
					break;
				log_flag = strtok(NULL, LIST_ITEMS_DELIM);
				if (NULL == log_flag)
					break;

				cmd_num = strtok(authorize_content, LIST_ITEMS_DELIM);
				if (NULL == cmd_num)
					break;

				authorize_rel_cur->custom_addr->authorize_id = atoi(authorize_id);
				authorize_rel_cur->custom_addr->unauthorize_event.block_flag = atoi(block_flag);
				authorize_rel_cur->custom_addr->unauthorize_event.warn_flag = atoi(warn_flag);
				authorize_rel_cur->custom_addr->unauthorize_event.log_flag = atoi(log_flag);
				authorize_rel_cur->custom_addr->custom_num = atoi(cmd_num);

				if (authorize_rel_cur->custom_addr->custom_num > 64)
					authorize_rel_cur->custom_addr->custom_num = 64;

				for (k=0; k<authorize_rel_cur->custom_addr->custom_num; k++)
				{
					authorize_custom = strtok(NULL, LIST_ITEMS_DELIM);
					if (NULL == authorize_custom || strlen(authorize_custom) > 127)
						continue;
					
					strcpy(authorize_rel_cur->custom_addr->authorize_custom[k], authorize_custom);
				}

				AuthrizCustomsNum++;
				break; //�����޶�һ��ͨ����ȨID����Ӧһ���˺���Ȩ��Ϣ!!!!!!
			}

			authorize_rel_cur++;
		}
	}

sailing_return:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}

	return AuthrizCustomsNum;
}

/**********************************
*func name: proGetAuthrizFeatures
*function: ������Ȩ��ϵ�б��е�������ȨID����ȡЭ��������Ȩ������Ϣ��Ϊ�������ڴ�ռ䣬
		   �����׵�ַ������Ӧ��Э��������Ȩָ��
*parameters:
		�������: authorize_rel_num: ��Ȩ��ϵ�б����
				  cfg_dir: �����ļ����Ŀ¼
		�������: authorize_rel_ptr:��Ȩ��ϵ�б��׵�ַ
*call:
*called:
*return: �ɹ�ʱ���ػ�õ�Э��������Ȩ��ϵ���������󷵻�-1
*/
int proGetAuthrizFeatures(PRO_AUTHRIZ_RELATION_INFO *authorize_rel_ptr, 
					int authorize_rel_num, int protocol_id, const char *cfg_dir)
{
	int i, j, k, m;
	int listNum;
	int AuthrizFeaturesNum = -1;
    char info_str[32];
	char file_path[MAX_FILE_PATH_SIZE+1];
	FILE *fp = NULL;
	char key_val[512];	//��ȡ����һ��Э��������Ȩ�ִ�
	char *authorize_id, *unauthorize_event, *authorize_content;
	char *block_flag, *warn_flag, *log_flag, *type_num, *type, *content_num, *content;
	PRO_AUTHRIZ_RELATION_INFO_ID authorize_rel_cur;
	const char* proto_list_low[] = {"http", "ftp", "smtp", "pop3", "telnet", "msn", 
		"emule", "x11", "rdp", "rlogin", "netbios", "sybase", "sqlserver", "oracle",
		"informix", "db2", "arp", "skype", "qq", "thunder", "bt", "fetion"};


	/*	1 ��Э��������Ȩ�����ļ���ȡЭ��������Ȩ��Ϣ����listNum
		2 ѭ��listNum�Σ���ȡЭ��������Ȩ��Ϣ
		3 ���ڶ�ȡ��ÿ��Э��������Ȩ��Ϣ, ������Ȩ��ϵ�б�, ������Ȩ��ϵ�б���
		  ������ȨID�Ƿ������Э��������Ȩ��Ϣƥ��, ���ƥ������һ����Ԫ��Э��
		  ������Ȩ��Ϣ�ڴ�, ָ��ǰ����Ȩ��ϵ�б��Э��������Ȩ��Ϣָ��, ����
		  ��Э��������Ȩ��Ϣ��д��������ڴ�, AuthrizFeaturesNum��һ
		4 ���򷵻�
	*/
	if (NULL == authorize_rel_ptr || authorize_rel_num <= 0 || NULL == cfg_dir)
		goto sailing_return;

	memset(file_path, 0x00, sizeof(file_path));

	//��Э��������Ȩ��Ϣ�����ļ�
	if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
		sprintf(file_path, "%s/%s%s%s", cfg_dir, "eAudit_Authorize_access_", proto_list[protocol_id], "_feature.conf");
	else
		sprintf(file_path, "%s%s%s%s", cfg_dir, "eAudit_Authorize_access_", proto_list[protocol_id], "_feature.conf");
	
	fp = fopen(file_path, "r");
	if (NULL == fp)
	{
		if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
			sprintf(file_path, "%s/%s%s%s", cfg_dir, "eAudit_Authorize_access_", proto_list_low[protocol_id], "_feature.conf");
		else
			sprintf(file_path, "%s%s%s%s", cfg_dir, "eAudit_Authorize_access_", proto_list_low[protocol_id], "_feature.conf");

		fp = fopen(file_path, "r");
		if (NULL == fp)
			goto sailing_return;
	}
	
	cfgGetListNum(fp, &listNum);
	if (listNum <= 0)
	{
		AuthrizFeaturesNum = 0;
		goto sailing_return;
	}


	AuthrizFeaturesNum = 0;

	for (i=0; i<listNum; i++)
	{
		memset(key_val, 0x00, sizeof(key_val));
		memset(info_str, 0x00, sizeof(info_str));
		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//���Կ����ȶ��������ڻ��棬Ȼ����ʹ��!!!!!!!!!
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		authorize_id = strtok(key_val, LIST_ITEMS_INDER);
		if (authorize_id == NULL)
			continue;


		authorize_rel_cur = authorize_rel_ptr;
		for (j=0; j<authorize_rel_num; j++)
		{
			if (atoi(authorize_id) == authorize_rel_cur->network_addr->authorize_id)
			{//���ҵ���������ȨIDƥ���Э��������Ȩ��Ϣ
				authorize_rel_cur->feature_addr = 
					(PRO_FEATURE_INFO_ID)calloc(PRO_AUTHORIZE_FEATURE_INFO_SIZE, 1);
				if (NULL == authorize_rel_cur->feature_addr)
					goto sailing_return;


				unauthorize_event = strtok(NULL, LIST_ITEMS_INDER);
				if (NULL == unauthorize_event)
					break;
				authorize_content = strtok(NULL, LIST_ITEMS_INDER);
				if (NULL == authorize_content)
					break;

				block_flag = strtok(unauthorize_event, LIST_ITEMS_DELIM);
				if (NULL == block_flag)
					break;
				warn_flag = strtok(NULL, LIST_ITEMS_DELIM);
				if (NULL == warn_flag)
					break;
				log_flag = strtok(NULL, LIST_ITEMS_DELIM);
				if (NULL == log_flag)
					break;

				type_num = strtok(authorize_content, LIST_ITEMS_DELIM);
				if (NULL == type_num)
					break;

				authorize_rel_cur->feature_addr->authorize_id = atoi(authorize_id);
				authorize_rel_cur->feature_addr->unauthorize_event.block_flag = atoi(block_flag);
				authorize_rel_cur->feature_addr->unauthorize_event.warn_flag = atoi(warn_flag);
				authorize_rel_cur->feature_addr->unauthorize_event.log_flag = atoi(log_flag);
				authorize_rel_cur->feature_addr->type_num = atoi(type_num);

				if (authorize_rel_cur->feature_addr->type_num > 16)
					authorize_rel_cur->feature_addr->type_num = 16;

				for (k=0; k<authorize_rel_cur->feature_addr->type_num; k++)
				{
					type = strtok(NULL, LIST_ITEMS_DELIM);
					if (NULL == type)
						break;
					content_num = strtok(NULL, LIST_ITEMS_DELIM);
					if (NULL == content_num)
						break;

					authorize_rel_cur->feature_addr->authorize_feature[k].type = atoi(type);
					authorize_rel_cur->feature_addr->authorize_feature[k].content_num = atoi(content_num);

					if (authorize_rel_cur->feature_addr->authorize_feature[k].content_num > 64)
						authorize_rel_cur->feature_addr->authorize_feature[k].content_num = 64;

					for (m=0; m<authorize_rel_cur->feature_addr->authorize_feature[k].content_num; m++)
					{
						content = strtok(NULL, LIST_ITEMS_DELIM);
						if (NULL == content)
							break;

						strcpy(authorize_rel_cur->feature_addr->authorize_feature[k].content[m], content);
					}
				}

				AuthrizFeaturesNum++;
				break; //�����޶�һ��Э��������ȨID����Ӧһ���˺���Ȩ��Ϣ!!!!!!
			}

			authorize_rel_cur++;
		}
	}

sailing_return:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}

	return AuthrizFeaturesNum;
}

/**********************************
*func name: ProGetMonitorConf
*function: ����Э��ID����ȡЭ����������Ϣ
*parameters:
		�������: protocol_id��Э��ID
				  cfg_dir: �����ļ����Ŀ¼
		�������: p_monitor_conf_ptr�����������Ϣ�ṹ��ַ
*call:
*called:
*return: �ɹ�:TRUE��ʧ��:FALSE
*/
int proGetMonitorConf(P_MONITOR_INFO *p_monitor_conf_ptr, int protocol_id, const char *cfg_dir)
{
	int i, listNum = 0;
	FILE *fp = NULL;
	char file_path[MAX_FILE_PATH_SIZE+1];
	char info_str[32];
	char key_val[512];		//��ȡ����һ��Э�����������Ϣ�ִ�
	char *protocol_id_cur;
	char *conn_interval, *conn_threshold, *flux_interval, *flux_threshold;
	char *block_flag, *warn_flag, *log_flag;


	/*	1 ��Э���������ļ���ȡЭ����������Ϣ����listNum
		2 ѭ��listNum�Σ���ȡ���������Ϣ, ֱ����ȡ���ļ��������Ϣ��Э��ID��
		  ����Э��ID��ͬ
		3 ����ҵ�������Э��IDƥ���Э����������Ϣ, ��������Ϣ�����, ���򷵻�TRUE
		4 ���ֱ��ѭ��������û���ҵ�������Э��ID��ƥ��ļ��������Ϣ, ���򷵻�FALSE
	*/
	if (NULL == p_monitor_conf_ptr || NULL == cfg_dir)
		goto sailing_return;

	memset(info_str, 0x00, sizeof(info_str));
	memset(file_path, 0x00, sizeof(file_path));

	if (*(cfg_dir+strlen(cfg_dir)-1) != '/')
		sprintf(file_path, "%s/%s", cfg_dir, MONITOR_FILE);
	else
		sprintf(file_path, "%s%s", cfg_dir, MONITOR_FILE);
	
	fp = fopen(file_path, "r");
	if (NULL == fp)
		goto sailing_return;

	cfgGetListNum(fp, &listNum);
	if (listNum <= 0)
		goto sailing_return;


	//���������еļ��������Ϣ, ֱ�����ҵ�������Э��ID��ƥ���
	for (i=0; i<listNum; i++)
	{
		memset(key_val, 0x00, sizeof(key_val));

		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//��ȡһ�����������Ϣ
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		//��ȡ������¼��Э��ID
		protocol_id_cur = strtok(key_val, LIST_LINE_DELIM_INDER);
		if (NULL == protocol_id_cur)
			continue;

		//�ü��������Ϣ��Э��ID������ID��ͬ, �˳�����ѭ������ȡ��һ��
		if (atoi(protocol_id_cur) != protocol_id)
			continue;

		//�ü��������Ϣ��Э��ID������ID��ͬ����������Ϣ�����
		conn_threshold = strtok(NULL, LIST_LINE_DELIM_INDER);
		if (NULL == conn_threshold)
			goto sailing_return;
		conn_interval = strtok(NULL, LIST_LINE_DELIM_INDER);
		if (NULL == conn_threshold)
			goto sailing_return;
		flux_threshold = strtok(NULL, LIST_LINE_DELIM_INDER);
		if (NULL == flux_threshold)
			goto sailing_return;
		flux_interval = strtok(NULL, LIST_LINE_DELIM_INDER);
		if (NULL == flux_interval)
			goto sailing_return;
		block_flag = strtok(NULL, LIST_LINE_DELIM_INDER);
		if (NULL == block_flag)
			goto sailing_return;
		warn_flag = strtok(NULL, LIST_LINE_DELIM_INDER);
		if (NULL == warn_flag)
			goto sailing_return;
		log_flag = strtok(NULL, LIST_LINE_DELIM_INDER);
		if (NULL == log_flag)
			goto sailing_return;

		p_monitor_conf_ptr->p_type_id = protocol_id;
		p_monitor_conf_ptr->conn_interval = atoi(conn_interval);
		p_monitor_conf_ptr->conn_threshold = atoi(conn_threshold);
		p_monitor_conf_ptr->flux_interval = atoi(flux_interval);
		p_monitor_conf_ptr->flux_threshold = atoi(flux_threshold);
		p_monitor_conf_ptr->not_authorize_event.block_flag = atoi(block_flag);
		p_monitor_conf_ptr->not_authorize_event.warn_flag = atoi(warn_flag);
		p_monitor_conf_ptr->not_authorize_event.log_flag = atoi(log_flag);

		fclose(fp);
		fp = NULL;
		return TRUE;
	}

sailing_return:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}

	return FALSE;
}

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
int proCreatPorotcolAnalysisInfo (PRO_ANALYSIS_INFO *protocol_analysis_info, int protocol_id, const char *cfg_dir)
{
	//int log_pri = LOG_DEBUG;
	int log_pri = 0;//��������ʱ��һ��!!!!!!!!!!!!!!!

	if (NULL == protocol_analysis_info || NULL == cfg_dir)
		return FALSE;


	protocol_analysis_info->protected_res_num = 
		proGetProtectedRes(&(protocol_analysis_info->protected_res_addr), protocol_id, cfg_dir);
	if (protocol_analysis_info->protected_res_num <= 0)
		return FALSE;//���������Ϣ
	//write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get protected resources fail!");

	protocol_analysis_info->usr_num = proGetAuthrizUsrs(&(protocol_analysis_info->usr_addr), cfg_dir);
	if (protocol_analysis_info->usr_num <= 0)
		;//���������Ϣ
	//write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get authorize users fail!");

	protocol_analysis_info->network_num = proGetAuthrizNets(&(protocol_analysis_info->network_addr),
		protocol_analysis_info->protected_res_addr, protocol_analysis_info->protected_res_num, cfg_dir);
	if (protocol_analysis_info->network_num <= 0)
		;//���������Ϣ
	//write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get authorize access network fail!");

	protocol_analysis_info->relation_num = protocol_analysis_info->network_num;

	if (NULL == proCallocAuthrizRelatInfos(&(protocol_analysis_info->relation_addr), protocol_analysis_info->relation_num))
	{
		//write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"calloc authorize relation info fail!");

		;//���������Ϣ
		return FALSE;
	}

	proInitRelatInfNets(protocol_analysis_info->relation_addr, 
		protocol_analysis_info->relation_num, protocol_analysis_info->network_addr);

	proInitRelatInfProRes(protocol_analysis_info->relation_addr, protocol_analysis_info->relation_num, 
		protocol_analysis_info->protected_res_addr, protocol_analysis_info->protected_res_num);

	proInitRelatInfUsr(protocol_analysis_info->relation_addr, protocol_analysis_info->relation_num, 
		protocol_analysis_info->usr_addr, protocol_analysis_info->usr_num);

	proGetAuthrizAccts(protocol_analysis_info->relation_addr, protocol_analysis_info->relation_num, cfg_dir);

	proGetAuthrizCmds(protocol_analysis_info->relation_addr, protocol_analysis_info->relation_num, cfg_dir);

	proGetAuthrizCustoms(protocol_analysis_info->relation_addr, protocol_analysis_info->relation_num, cfg_dir);

	proGetAuthrizFeatures(protocol_analysis_info->relation_addr, protocol_analysis_info->relation_num, protocol_id, cfg_dir);


	return TRUE;
}


/**********************************
*func name: proDestroyPorotcolAnalysisInfo
*function: �ͷ�Э���������
*parameters:
		�������: protocol_analysis_info:Э������������ݽṹ��
*call:
*called:
*return:
*/
void proDestroyPorotcolAnalysisInfo (PRO_ANALYSIS_INFO *protocol_analysis_info)
{
	int i;
	PRO_AUTHRIZ_RELATION_INFO *relation_addr_cur = NULL;
	

	if (NULL != protocol_analysis_info->protected_res_addr)
	{
		free(protocol_analysis_info->protected_res_addr);
		protocol_analysis_info->protected_res_addr = NULL;
	}

	if (NULL != protocol_analysis_info->usr_addr)
	{
		free(protocol_analysis_info->usr_addr);
		protocol_analysis_info->usr_addr = NULL;
	}

	if (NULL != protocol_analysis_info->network_addr)
	{
		free(protocol_analysis_info->network_addr);
		protocol_analysis_info->network_addr = NULL;
	}

	if (NULL != protocol_analysis_info->relation_addr)
	{
		relation_addr_cur = protocol_analysis_info->relation_addr;

		for (i=0; i<protocol_analysis_info->relation_num; i++)
		{

			if (NULL != relation_addr_cur->account_addr)
			{
				free(relation_addr_cur->account_addr);
				relation_addr_cur->account_addr = NULL;
			}

			if (NULL != relation_addr_cur->cmd_addr)
			{
				free(relation_addr_cur->cmd_addr);
				relation_addr_cur->cmd_addr = NULL;
			}

			if (NULL != relation_addr_cur->custom_addr)
			{
				free(relation_addr_cur->custom_addr);
				relation_addr_cur->custom_addr = NULL;
			}

			if (NULL != relation_addr_cur->feature_addr)
			{
				free(relation_addr_cur->feature_addr);
				relation_addr_cur->feature_addr = NULL;
			}

			relation_addr_cur++;
		}

		free(protocol_analysis_info->relation_addr);
		protocol_analysis_info->relation_addr = NULL;
	}

	return;
}


