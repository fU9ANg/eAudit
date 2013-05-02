
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
*function: 获取保护资源配置文件中协议ID为pro_id所对应的保护资源，为其申请内存空间,
		   并按保护资源ID排序，将首地址赋给protected_res_ptr
*parameters:
		输入参数: protocol_id: 协议ID
				  cfg_dir: 配置文件存放目录
		输出参数: protected_res_ptr: 保护资源列表首地址指针
*call:
*called:
*return: 成功时返回获取到的保护资源列表个数，错误返回-1
*/
int proGetProtectedRes (PRO_PROTECTED_RESOURCE **protected_res_ptr, 
								int protocol_id, const char *cfg_dir)
{
	int i = 0;
	int listNum = 0;
	int match_num = 0; //与输入协议ID相匹配的保护资源个数
	int protected_res_num = -1;	//成功解析到的保护资源个数, 即实际输出的保护资源个数
	char file_path[MAX_FILE_PATH_SIZE+1];
	char info_str[32];
	char key_val_tmp[512];	//从配置读取到的一条保护资源字串
	char key_val_cur[512];	//对当前保护资源字串的备份
	char key_val_match[255][512];	//与输入协议ID匹配的所有保护资源字串
	int key_val_seq[255];	//key_val_match中按照保护资源ID下标排序的结果
	int protected_res_id_tmp[255];//临时存放的与输入协议ID匹配的所有保护资源ID, 用于对保护资源信息进行下标排序
	FILE *fp = NULL;
	char *protocol_str;
	char *protect_resource_addr, *not_authorize_info_addr, *eaudit_level_info_addr;
	char *protected_res_name, *protected_res_id, *protected_res_content;
	char *block_flag, *warn_flag, *log_flag;
	char *eaudit_direction, *session_level, *record_level, *event_level,
		 *analysis_level, *total_analysis_level, *custom_made_level, *manage_level;
	int authorize_flag, eaudit_info_state;
	PRO_PROTECTED_RESOURCE *protected_res_cur;


	/*	1 从保护资源配置文件读取listNum
		2 循环listNum次读取保护资源信息
		3 对于读取的保护资源信息，判断其协议类型和输入协议ID是否匹配, 如果匹配保存
		  该条保护资源信息到缓存key_val_match, 记录该条保护资源信息的ID, 查询到的
		  相匹配的保护资源个数match_num加一
		4 循环结束后申请match_num单元的保护资源信息内存
		5 按照保护资源ID对过滤出的保护资源信息进行下标排序
		6 按照排序的结果逐一解析缓存key_val_match中的保护资源, 并把解析结果写入申请
		  的内存, 记录成功解析到的保护资源个数protected_res_num
		7 程序返回
	*/
	if (NULL != protected_res_ptr)
		*protected_res_ptr = NULL;//防止调用函数时参数没有清零, 否则申请内存前的goto会出错

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


	//遍历保护资源配置中的每条保护资源信息
	for (i=0; i<listNum; i++)
	{
		memset(key_val_tmp, 0x00, sizeof(key_val_tmp));
		memset(key_val_cur, 0x00, sizeof(key_val_cur));
		memset(info_str, 0x00, sizeof(info_str));

		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//读取一个保护资源信息(函数的第二个参数不使用NULL, 是为了保证程序的可靠性!)
		if (TRUE != cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val_tmp, sizeof(key_val_tmp)))
			continue;
		strcpy(key_val_cur, key_val_tmp);

		protect_resource_addr = strtok(key_val_tmp, LIST_ITEMS_INDER);
		protocol_str = strrchr(protect_resource_addr, LIST_ITEMS_DELIM_CHAR);
		if(NULL == protocol_str)
			continue;

		//判断该条保护资源信息是否与输入协议ID匹配
		//如果匹配保存该保护资源信息到缓存以待后续处理
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

	//申请内存单元用于存储保护资源信息并输出
	*protected_res_ptr = (PRO_PROTECTED_RESOURCE_ID)calloc(PRO_PROTECTED_RESOURCE_SIZE, match_num);
	if (NULL == *protected_res_ptr)
		goto sailing_return;

	//按照保护资源ID对缓存key_val_match中所记录的保护资源进行下标排序
	//下标排序的结果保存在key_val_seq中
	if (FALSE == sortIndex(protected_res_id_tmp, key_val_seq, match_num))
		goto sailing_return;


	//解析缓存中的每条保护资源并写入申请的内存
	protected_res_cur = *protected_res_ptr;
	protected_res_num = 0;

	for (i=0; i<match_num; i++)
	{//未完成!!!!!!
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
		//protected_res_content的处理待定!!!!!
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

		//authorize_flag和eaudit_info_state的处理待定!!!!!!

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
*function: 获取用户配置文件中的用户信息，为其申请内存空间，并按用户ID排序，将首地址
		   赋给pro_user_ptr
*parameters:
		输入参数: cfg_dir: 配置文件存放目录
		输出参数: pro_user_ptr: 用户列表首地址指针
*call:
*called:
*return: 成功时返回获取到的用户信息列表个数，错误返回-1
*/
int proGetAuthrizUsrs(PRO_USR_INFO **pro_usr_ptr, const char *cfg_dir)
{
	int i = 0;
	int listNum = 0;
	int read_num = 0;	//从配置读取到的用户信息的个数
	int usr_num = -1;	//成功解析出的用户信息的个数，即实际输出的用户信息的个数
	int usr_id[512];
	int key_val_seq[512];
	char info_str[32];
	char key_val_tmp[512];		//获取到的一条用户信息字串
	char key_val_cur[512];		//对当前用户信息字串的备份
	char key_val[255][512];		//获取到的所有用户信息字串
	char file_path[MAX_FILE_PATH_SIZE+1];
	FILE *fp = NULL;
	char *usr_id_cur, *usr_name_cur;
	PRO_USR_INFO *pro_usr_cur;


	/*	1 从用户配置文件读取用户信息个数listNum
		2 循环listNum次，读取用户信息, 解析用户ID放于缓存usr_id, 并把用户信息放于
		  缓存key_val
		3 申请listNum个单元的用户信息内存
		4 按照用户ID对用户信息进行下标排序
		5 按照排序的结果逐一解析缓存key_val中的用户信息, 并把解析结果写入申请
		  的内存, 记录成功解析到的用户信息个数usr_num
		7 程序返回
	*/
	if (NULL != pro_usr_ptr)
		*pro_usr_ptr = NULL;//防止调用函数时参数没有清零, 否则申请内存前的goto会出错

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


	//从配置读取用户信息存放于缓存key_val，并解析usr id存放于缓存usr_id
	for (i=0; i<listNum; i++)
	{
		memset(key_val_tmp, 0x00, sizeof(key_val_tmp));
		memset(key_val_cur, 0x00, sizeof(key_val_cur));
		memset(info_str, 0x00, sizeof(info_str));

		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//读取一个用户信息
		if (TRUE != cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val_tmp, sizeof(key_val_tmp)))
			continue;
		strcpy(key_val_cur, key_val_tmp);

		//提取出usr_id
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


	//按照usr id对缓存key_val中所记录的用户信息进行下标排序
	//下标排序的结果保存在key_val_seq中
	if (FALSE == sortIndex(usr_id, key_val_seq, read_num))
		goto sailing_return;


	//按照usr id排序的结果解析从配置读取的用户信息缓存key_val
	pro_usr_cur = *pro_usr_ptr;
	usr_num = 0;

	for (i=0; i<read_num; i++)
	{
		//提取出usr_id和usr_name
		usr_id_cur = strtok(key_val[key_val_seq[i]], LIST_ITEMS_DELIM);
		if (NULL == usr_id_cur)
			continue;
		strtok(NULL, LIST_ITEMS_DELIM);
		strtok(NULL, LIST_ITEMS_DELIM);
		usr_name_cur = strtok(NULL, LIST_ITEMS_DELIM);
		if (NULL == usr_name_cur || strlen(usr_name_cur) >= sizeof(pro_usr_cur->strUsrName))
			continue;

		//把usr_id和usr_name的值拷贝到申请的内存
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
*function: 根据保护资源列表中所有的保护资源ID，获取相关的所有网络授权信息，为其申请
		   内存空间，并按网络授权ID排序，将首地址赋给pro_network_ptr
*parameters:
		输入参数: protected_res_ptr: 保护资源列表首地址指针
				  protected_res_num: 保护资源列表中的保护资源个数
				  cfg_dir: 配置文件存放目录
		输出参数: pro_ network_ptr: 网络授权列表首地址指针
*call:
*called:
*return: 成功时返回获取到的网络授权信息列表个数，错误返回-1
*/
int proGetAuthrizNets(PRO_NETWORK_INFO **pro_network_ptr,
		const PRO_PROTECTED_RESOURCE *protected_res_ptr, int protected_res_num, const char *cfg_dir)
{
	int i, j;
	int listNum = 0;
	int match_num = 0;	//与保护资源列表中保护资源ID匹配的网络授权信息个数
	int network_num = -1;	//成功解析的网络授权信息个数，即实际输出的网络授权信息个数
	char file_path[MAX_FILE_PATH_SIZE+1];
	FILE *fp = NULL;
    char info_str[32];
	char key_val_tmp[512];	//获取到的一条网络授权字串
	char key_val_cur[512];	//对当前网络授权字串的备份
	char key_val_match[255][512];	//与保护资源ID匹配的一条网络授权字串
	int key_val_seq[255];	//key_val_match中按照授权ID下标排序的结果
	int authorize_id_tmp[255];
	const PRO_PROTECTED_RESOURCE *protected_res_cur;
	PRO_NETWORK_INFO *pro_network_cur;
	char *authorize_id, *usr_id, *protected_res_id, *eaudit_level_info_addr, *authorize_info_addr;
	char *eaudit_direction, *session_level, *record_level, *event_level,
		 *analysis_level, *total_analysis_level, *custom_made_level, *manage_level;
	char *authorize_account, *authorize_cmd, *authorize_custom_made, *authorize_pro_feature_made;
	int authorize_flag, eaudit_info_state;


	/*	1 从网络授权配置文件读取网络授权信息个数listNum
		2 循环listNum次，读取网络授权信息
		3 对于读取的每条网络授权信息, 遍历保护资源列表, 查找保护资源列表中保护资源ID
		  是否与该条网络授权信息匹配, 如果匹配把该条网络授权信息保存于缓存key_val_match, 
		  记录该条网络授权信息的网络授权ID, 查询到的相匹配的网络授权信息个数match_num加一
		4 申请match_num个单元的网络授权信息内存
		5 按照网络授权ID对过滤出的网络授权信息进行下标排序
		6 按照排序的结果逐一解析缓存中的网络授权配置并写入申请的内存输出, 记录成功解析
		  到的网络授权信息个数network_num
		7 程序返回
	*/
	if (NULL != pro_network_ptr)
		*pro_network_ptr = NULL;//防止调用函数时参数没有清零, 否则申请内存前的goto会出错

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

		//读取一个网络授权
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


		//判断该条网络授权信息是否与保护资源列表中的该条保护资源匹配
		//如果匹配保存该条网络授权信息到缓存，以待后续处理
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

	//申请网络授权信息内存
	*pro_network_ptr = (PRO_NETWORK_INFO_ID)calloc(PRO_NETWORK_INFO_SIZE, match_num);
	if (NULL == *pro_network_ptr)
		goto sailing_return;


	//按照授权ID对缓存key_val_match中所记录的网络授权进行下标排序
	//下标排序的结果保存在key_val_seq中
	if (FALSE == sortIndex(authorize_id_tmp, key_val_seq, match_num))
		goto sailing_return;


	pro_network_cur = *pro_network_ptr;
	network_num = 0;

	//解析缓存中的网络授权信息并写入申请的内存输出
	for (i=0; i<match_num; i++)
	{//解析key_val_match
		//未完成!!!!!!
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
*function: 根据网络授权列表个数，申请并初始化授权关系列表空间，将空间首地址赋值给authorize_rel_ptr
*parameters:
		输入参数: network_num: 网络授权信息列表个数
		输出参数: authorize_rel_ptr: 授权关系列表空间首地址指针
*call:
*called:
*return: 成功时返回申请空间地址，错误返回NULL
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
*function: 初始化授权关系列表空间中的网络授权信息指针。
		   即按网络授权ID排序方式赋值授权关系列表空间中的网络授权信息指针
*parameters:
		输入参数: authorize_rel_num: 授权关系列表个数
				  pro_ network_ptr: 网络授权列表首地址指针
		输出参数: authorize_rel_ptr: 授权关系列表空间首地址指针
*call:
*called:
*return: 成功时返回1，错误返回0
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
*function: 初始化授权关系列表空间中的保护资源信息指针。
		   即根据授权关系列表空间中的网络授权关系，查找对应的保护资源指针

*parameters:
		输入参数: authorize_rel_num: 授权关系列表个数
				  protected_res_ptr: 保护资源列表首地址指针
				  protected_res_num: 保护资源列表中的保护资源个数
		输出参数: authorize_rel_ptr: 授权关系列表空间首地址指针
*call:
*called:
*return: 成功时返回1，错误返回0
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
*function: 初始化授权关系列表空间中的用户信息指针。
		   即根据授权关系列表空间中的网络授权关系，查找对应的用户信息指针
*parameters:
		输入参数: authorize_rel_num: 授权关系列表个数
				  usr_ptr: 用户信息列表首地址指针
				  usr_num: 用户信息列表个数
		输出参数: authorize_rel_ptr: 授权关系列表空间首地址指针
*call:
*called:
*return: 成功时返回1，错误返回0
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
*function: 根据授权关系列表中的网络授权ID, 获取账号授权配置信息, 为其申请内存空间,
		   并将首地址赋给相应的账号授权指针
*parameters:
		输入参数: authorize_rel_num: 授权关系列表个数
				  cfg_dir: 配置文件存放目录
		输出参数: authorize_rel_ptr: 授权关系列表空间首地址指针
*call:
*called:
*return: 成功时返回获得的账号授权关系个数，错误返回-1
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
	char key_val[512];	//获取到的一条账号授权字串
	char *authorize_id, *unauthorize_event, *authorize_content;
	char *block_flag, *warn_flag, *log_flag, *account_num, *authorize_account;
	PRO_AUTHRIZ_RELATION_INFO_ID authorize_rel_cur;


	/*	1 从账号授权配置文件读取账号授权信息个数listNum
		2 循环listNum次，读取账号授权信息
		3 对于读取的每条账号授权信息, 遍历授权关系列表, 查找授权关系列表中网络授权ID
		  是否与该条账号授权信息匹配, 如果匹配申请一个单元的账号授权信息内存, 指向
		  当前的授权关系列表的账号授权信息指针, 解析该账号授权信息并写入申请的内存, 
		  AuthrizAcctsNum加一
		4 程序返回
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

		//可以考虑先读出来放于缓存，然后再使用!!!!!!!!!
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
			{//查找到与网络授权ID匹配的账号授权信息
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
				break; //这里限定一个网络授权ID最多对应一条账号授权信息!!!!!!
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
*function: 根据授权关系列表中的网络授权ID，获取指令授权配置信息，为其申请内存空间，
		   并将首地址赋给相应的指令授权指针
*parameters:
		输入参数: int authorize_rel_num: 授权关系列表个数
				  cfg_dir: 配置文件存放目录
		输出参数: authorize_rel_ptr:授权关系列表首地址
*call:
*called:
*return: 成功时返回获得的指令授权关系个数，错误返回-1
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
	char key_val[512];	//获取到的一条指令授权字串
	char *authorize_id, *unauthorize_event, *authorize_content;
	char *block_flag, *warn_flag, *log_flag, *cmd_num, *authorize_cmd;
	PRO_AUTHRIZ_RELATION_INFO_ID authorize_rel_cur;


	/*	1 从指令授权配置文件读取指令授权信息个数listNum
		2 循环listNum次，读取指令授权信息
		3 对于读取的每条指令授权信息, 遍历授权关系列表, 查找授权关系列表中网络授权ID
		  是否与该条指令授权信息匹配, 如果匹配申请一个单元的指令授权信息内存, 指向
		  当前的授权关系列表的指令授权信息指针, 解析该指令授权信息并写入申请的内存, 
		  AuthrizCmdsNum加一
		4 程序返回
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

		//可以考虑先读出来放于缓存，然后再使用!!!!!!!!!
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		authorize_id = strtok(key_val, LIST_ITEMS_INDER);
		if (authorize_id == NULL)
			continue;


		authorize_rel_cur = authorize_rel_ptr;
		for (j=0; j<authorize_rel_num; j++)
		{
			if (atoi(authorize_id) == authorize_rel_cur->network_addr->authorize_id)
			{//查找到与网络授权ID匹配的指令授权信息
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
				break; //这里限定一个指令授权ID最多对应一条账号授权信息!!!!!!
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
*function: 根据授权关系列表中的网络授权ID，获取通用授权配置信息，为其申请内存空间，
		   并将首地址赋给相应的通用授权指针
*parameters:
		输入参数: authorize_rel_num: 授权关系列表个数
				  cfg_dir: 配置文件存放目录
		输出参数: authorize_rel_ptr:授权关系列表首地址
*call:
*called:
*return: 成功时返回获得的通用授权关系个数，错误返回-1
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
	char key_val[512];	//获取到的一条通用授权字串
	char *authorize_id, *unauthorize_event, *authorize_content;
	char *block_flag, *warn_flag, *log_flag, *cmd_num, *authorize_custom;
	PRO_AUTHRIZ_RELATION_INFO_ID authorize_rel_cur;


	/*	1 从通用授权配置文件读取通用授权信息个数listNum
		2 循环listNum次，读取通用授权信息
		3 对于读取的每条通用授权信息, 遍历授权关系列表, 查找授权关系列表中网络授权ID
		  是否与该条通用授权信息匹配, 如果匹配申请一个单元的通用授权信息内存, 指向
		  当前的授权关系列表的通用授权信息指针, 解析该通用授权信息并写入申请的内存, 
		  AuthrizCustomsNum加一
		4 程序返回
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

		//可以考虑先读出来放于缓存，然后再使用!!!!!!!!!
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		authorize_id = strtok(key_val, LIST_ITEMS_INDER);
		if (authorize_id == NULL)
			continue;


		authorize_rel_cur = authorize_rel_ptr;
		for (j=0; j<authorize_rel_num; j++)
		{
			if (atoi(authorize_id) == authorize_rel_cur->network_addr->authorize_id)
			{//查找到与网络授权ID匹配的通用授权信息
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
				break; //这里限定一个通用授权ID最多对应一条账号授权信息!!!!!!
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
*function: 根据授权关系列表中的网络授权ID，获取协议特征授权配置信息，为其申请内存空间，
		   并将首地址赋给相应的协议特征授权指针
*parameters:
		输入参数: authorize_rel_num: 授权关系列表个数
				  cfg_dir: 配置文件存放目录
		输出参数: authorize_rel_ptr:授权关系列表首地址
*call:
*called:
*return: 成功时返回获得的协议特征授权关系个数，错误返回-1
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
	char key_val[512];	//获取到的一条协议特征授权字串
	char *authorize_id, *unauthorize_event, *authorize_content;
	char *block_flag, *warn_flag, *log_flag, *type_num, *type, *content_num, *content;
	PRO_AUTHRIZ_RELATION_INFO_ID authorize_rel_cur;
	const char* proto_list_low[] = {"http", "ftp", "smtp", "pop3", "telnet", "msn", 
		"emule", "x11", "rdp", "rlogin", "netbios", "sybase", "sqlserver", "oracle",
		"informix", "db2", "arp", "skype", "qq", "thunder", "bt", "fetion"};


	/*	1 从协议特征授权配置文件读取协议特征授权信息个数listNum
		2 循环listNum次，读取协议特征授权信息
		3 对于读取的每条协议特征授权信息, 遍历授权关系列表, 查找授权关系列表中
		  网络授权ID是否与该条协议特征授权信息匹配, 如果匹配申请一个单元的协议
		  特征授权信息内存, 指向当前的授权关系列表的协议特征授权信息指针, 解析
		  该协议特征授权信息并写入申请的内存, AuthrizFeaturesNum加一
		4 程序返回
	*/
	if (NULL == authorize_rel_ptr || authorize_rel_num <= 0 || NULL == cfg_dir)
		goto sailing_return;

	memset(file_path, 0x00, sizeof(file_path));

	//打开协议特征授权信息配置文件
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

		//可以考虑先读出来放于缓存，然后再使用!!!!!!!!!
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		authorize_id = strtok(key_val, LIST_ITEMS_INDER);
		if (authorize_id == NULL)
			continue;


		authorize_rel_cur = authorize_rel_ptr;
		for (j=0; j<authorize_rel_num; j++)
		{
			if (atoi(authorize_id) == authorize_rel_cur->network_addr->authorize_id)
			{//查找到与网络授权ID匹配的协议特征授权信息
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
				break; //这里限定一个协议特征授权ID最多对应一条账号授权信息!!!!!!
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
*function: 根据协议ID，读取协议监测配置信息
*parameters:
		输入参数: protocol_id：协议ID
				  cfg_dir: 配置文件存放目录
		输出参数: p_monitor_conf_ptr：监测配置信息结构地址
*call:
*called:
*return: 成功:TRUE，失败:FALSE
*/
int proGetMonitorConf(P_MONITOR_INFO *p_monitor_conf_ptr, int protocol_id, const char *cfg_dir)
{
	int i, listNum = 0;
	FILE *fp = NULL;
	char file_path[MAX_FILE_PATH_SIZE+1];
	char info_str[32];
	char key_val[512];		//获取到的一条协议监听配置信息字串
	char *protocol_id_cur;
	char *conn_interval, *conn_threshold, *flux_interval, *flux_threshold;
	char *block_flag, *warn_flag, *log_flag;


	/*	1 从协议监测配置文件读取协议监测配置信息个数listNum
		2 循环listNum次，读取监测配置信息, 直到读取到的监测配置信息的协议ID与
		  输入协议ID相同
		3 如果找到与输入协议ID匹配的协议监测配置信息, 解析该信息并输出, 程序返回TRUE
		4 如果直到循环结束还没有找到与输入协议ID相匹配的监测配置信息, 程序返回FALSE
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


	//遍历配置中的监测配置信息, 直到查找到与输入协议ID相匹配的
	for (i=0; i<listNum; i++)
	{
		memset(key_val, 0x00, sizeof(key_val));

		sprintf(info_str, "%s%d", LIST_RESOURCE_KEY, i);

		//读取一个监测配置信息
		if (cfgGetKeyValue(fp, LIST_INFO_SECTION, info_str, key_val, sizeof(key_val)) != TRUE)
			continue;

		//提取该条记录的协议ID
		protocol_id_cur = strtok(key_val, LIST_LINE_DELIM_INDER);
		if (NULL == protocol_id_cur)
			continue;

		//该监测配置信息的协议ID与输入ID不同, 退出本次循环，读取下一条
		if (atoi(protocol_id_cur) != protocol_id)
			continue;

		//该监测配置信息的协议ID与输入ID相同，解析该信息并输出
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
*function: 创建协议分析所需数据
*parameters:
		输入参数: protocol_id: 协议ID
				  cfg_dir: 配置文件存放路径
		输出参数:protocol_analysis_info: 协议分析所需数据结构体
*call: 
*called: 
*return:
*/
int proCreatPorotcolAnalysisInfo (PRO_ANALYSIS_INFO *protocol_analysis_info, int protocol_id, const char *cfg_dir)
{
	//int log_pri = LOG_DEBUG;
	int log_pri = 0;//这里是临时用一下!!!!!!!!!!!!!!!

	if (NULL == protocol_analysis_info || NULL == cfg_dir)
		return FALSE;


	protocol_analysis_info->protected_res_num = 
		proGetProtectedRes(&(protocol_analysis_info->protected_res_addr), protocol_id, cfg_dir);
	if (protocol_analysis_info->protected_res_num <= 0)
		return FALSE;//输出出错信息
	//write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get protected resources fail!");

	protocol_analysis_info->usr_num = proGetAuthrizUsrs(&(protocol_analysis_info->usr_addr), cfg_dir);
	if (protocol_analysis_info->usr_num <= 0)
		;//输出出错信息
	//write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get authorize users fail!");

	protocol_analysis_info->network_num = proGetAuthrizNets(&(protocol_analysis_info->network_addr),
		protocol_analysis_info->protected_res_addr, protocol_analysis_info->protected_res_num, cfg_dir);
	if (protocol_analysis_info->network_num <= 0)
		;//输出出错信息
	//write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get authorize access network fail!");

	protocol_analysis_info->relation_num = protocol_analysis_info->network_num;

	if (NULL == proCallocAuthrizRelatInfos(&(protocol_analysis_info->relation_addr), protocol_analysis_info->relation_num))
	{
		//write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,SINGLE,"calloc authorize relation info fail!");

		;//输出出错信息
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
*function: 释放协议分析数据
*parameters:
		输入参数: protocol_analysis_info:协议分析所需数据结构体
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


