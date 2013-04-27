/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sem.h>

#include "interface.h"
#include "param.h"
#include "debug.h"


/* 
 *	分析包字符串p_par, 把以PAR_DELIM分开的数据,
 *	分别存放在PAR_ITF_ANALYZE_ID结构中.
 * 	Example: p_par= "0+11+2+4096000+100+1+1+1+1+29053356+29053360+29053359+	\
 *		  1+/data/pkts+lo+29053390+1+29053391+500+29053363+2+29063356+	\
 *		  29053392+29053393                       +100000"
 */
void get_itf_par(
	PAR_ITF_ANALYZE_ID	par_itf_analyze_id,
	char*			p_par,
	char			redirect_flag	/* what's mean. */
	)
{
	char *p = NULL;
    
	p=strtok(p_par, PAR_DELIM);	/* 协议号 */
	par_itf_analyze_id->pro_id = atoi(p);

	p = strtok(NULL, PAR_DELIM);	/* 协议名称共享内存 */
	par_itf_analyze_id->pro_tbl_shm_key = atol(p);

	p = strtok(NULL, PAR_DELIM);	/* 协议报文文件最大长度 */
	par_itf_analyze_id->cfg_file_set.maxPktFileSize = strtoul(p, NULL, 10);

	p = strtok(NULL,PAR_DELIM);	/* 协议报文文件最大文件数 */
	par_itf_analyze_id->cfg_file_set.maxPktFileNum  = strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 开关选项: 报警 */
	par_itf_analyze_id->func_switch.iAlarmSwitch = atoi(p);

	p = strtok(NULL, PAR_DELIM);	/* 开关选项: 错误处理 */
	par_itf_analyze_id->func_switch.iErrSwitch   = atoi(p);

	p = strtok(NULL, PAR_DELIM);	/* 开关选项: 状态报告 */
	par_itf_analyze_id->func_switch.iStatSwitch  = atoi(p);

	p = strtok(NULL, PAR_DELIM);	/* 保护资源列表KEY */
	par_itf_analyze_id->rule_pool_key = strtoul(p, NULL, 10);
    
	p = strtok(NULL, PAR_DELIM);	/* 保护资源个数 */
	par_itf_analyze_id->rule_num= strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 报文存放路径 */
	strcpy(par_itf_analyze_id->pkt_file_dir,p);

	p = strtok(NULL, PAR_DELIM);	/* 报文处理时间间隔 */
	par_itf_analyze_id->deposit_ivl_sec = strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 账号授权KEY */
	par_itf_analyze_id->usr_list_key    = strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 账号授权个数 */
	par_itf_analyze_id->usr_num         = strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 网络授权KEY */
	par_itf_analyze_id->authorize_network_key = strtoul(p, NULL, 10);
  
	p = strtok(NULL, PAR_DELIM);	/* 网络授权个数 */
	par_itf_analyze_id->authorize_network_num = strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 指令授权KEY */
	par_itf_analyze_id->authorize_account_key = strtoul(p, NULL, 10);
  
	p = strtok(NULL, PAR_DELIM);	/* 指令授权个数 */
	par_itf_analyze_id->authorize_account_num = strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 指令授权KEY */
	par_itf_analyze_id->authorize_cmd_key = strtoul(p, NULL, 10);
	  
	p = strtok(NULL, PAR_DELIM);	/* 指令授权个数 */
	par_itf_analyze_id->authorize_cmd_num = strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 通用授权KEY */
	par_itf_analyze_id->authorize_custom_key = strtoul(p, NULL, 10);
	  
	p = strtok(NULL, PAR_DELIM);	/* 通用授权个数 */
	par_itf_analyze_id->authorize_custom_num = strtoul(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);	/* 协议自定义授权KEY */
	par_itf_analyze_id->authorize_feature_key= strtoul(p, NULL, 10);
	  
	p = strtok(NULL, PAR_DELIM);	/* 协议自定义授权个数 */
	par_itf_analyze_id->authorize_feature_num= strtoul(p, NULL, 10);

	if(redirect_flag) {
		p = strtok(NULL, PAR_DELIM);
		par_itf_analyze_id->redirect_key = strtoul(p, NULL, 10);

		p = strtok(NULL, PAR_DELIM);
		par_itf_analyze_id->redirect_pid = strtoul(p, NULL, 10);

		p = strtok(NULL, PAR_DELIM);
		par_itf_analyze_id->sem_key      = strtoul(p, NULL, 10);
	}
	DEBUG("get_itf_par parameter OK");
}


/*
 *	打印PAR_ITF_ANALYZE_ID结构中的每个字段.
 */
void print_itf_par(
	PAR_ITF_ANALYZE_ID	par_itf_analyze_id
	)
{
	printf("par_itf_analyze_id->pro_id = %d\n",				\
		par_itf_analyze_id->pro_id);
	printf("par_itf_analyze_id->pro_tbl_shm_key = %d\n",			\
		par_itf_analyze_id->pro_tbl_shm_key);
	printf("par_itf_analyze_id->cfg_file_set.maxPktFileSize = %lu\n",	\
		par_itf_analyze_id->cfg_file_set.maxPktFileSize);
	printf("par_itf_analyze_id->cfg_file_set.maxPktFileNum = %lu\n",	\
		par_itf_analyze_id->cfg_file_set.maxPktFileNum);
	printf("par_itf_analyze_id->func_switch.iAlarmSwitch = %d\n",		\
		par_itf_analyze_id->func_switch.iAlarmSwitch);
	printf("par_itf_analyze_id->func_switch.iErrSwitch = %d\n",		\
		par_itf_analyze_id->func_switch.iErrSwitch);
	printf("par_itf_analyze_id->func_switch.iStatSwitch = %d\n",		\
		par_itf_analyze_id->func_switch.iStatSwitch);
	printf("par_itf_analyze_id->rule_pool_key = %d\n",			\
		par_itf_analyze_id->rule_pool_key);
	printf("par_itf_analyze_id->rule_num = %lu\n",				\
		par_itf_analyze_id->rule_num);
	printf("par_itf_analyze_id->pkt_file_dir = %s\n",			\
		par_itf_analyze_id->pkt_file_dir);
	printf("par_itf_analyze_id->deposit_ivl_sec = %ld\n",			\
		par_itf_analyze_id->deposit_ivl_sec);
	printf("par_itf_analyze_id->usr_list_key = %d\n",			\
		par_itf_analyze_id->usr_list_key);
	printf("par_itf_analyze_id->usr_num = %lu\n",				\
		par_itf_analyze_id->usr_num);
	printf("par_itf_analyze_id->authorize_network_key = %d\n",		\
		par_itf_analyze_id->authorize_network_key);
	printf("par_itf_analyze_id->authorize_network_num = %lu\n",		\
		par_itf_analyze_id->authorize_network_num);
	printf("par_itf_analyze_id->authorize_account_key = %d\n",		\
		par_itf_analyze_id->authorize_account_key);
	printf("par_itf_analyze_id->authorize_account_num = %lu\n",		\
		par_itf_analyze_id->authorize_account_num);
	printf("par_itf_analyze_id->authorize_cmd_key = %d\n",			\
		par_itf_analyze_id->authorize_cmd_key);
	printf("par_itf_analyze_id->authorize_cmd_num = %lu\n",			\
		par_itf_analyze_id->authorize_cmd_num);
	printf("par_itf_analyze_id->authorize_custom_key = %d\n",		\
		par_itf_analyze_id->authorize_custom_key);
	printf("par_itf_analyze_id->authorize_custom_num = %lu\n",		\
		par_itf_analyze_id->authorize_custom_num);
	printf("par_itf_analyze_id->authorize_feature_key = %d\n",		\
		par_itf_analyze_id->authorize_feature_key);
	printf("par_itf_analyze_id->authorize_feature_num = %lu\n",		\
		par_itf_analyze_id->authorize_feature_num);
	
}


int get_resource_port(
	PROTECTED_RESOURCE_ID	protected_resource_id,
	unsigned long		res_index
	)
{

	int	shmid = 0;

	if(protected_resource_id[res_index].sip.interval_port_shm_key > 0) {

		shmid = shmget(protected_resource_id[res_index].sip.interval_port_shm_key,0,IPC_CREAT);
		if (shmid < 0) {
			//error("Get interval port shm id fail.");
			//write_log(LOG_ERR, FILE_LOG, __FILE__, __LINE__, SINGLE,"Get interval port shm id fail.");
			return(FALSE);
		}

		protected_resource_id[res_index].sip.port_id = (INTERVAL_PORT_ID)shmat(shmid,NULL,SHM_RDONLY);
		if (protected_resource_id[res_index].sip.port_id == -1) {
			//error("Attach interval port shm fail.");
			//write_log(LOG_ERR, FILE_LOG, __FILE__, __LINE__, SINGLE,"Attach interval port shm fail.");
			return(FALSE);
		}
	}

	if(protected_resource_id[res_index].sip.continue_port_shm_key > 0) {
		shmid = shmget(protected_resource_id[res_index].sip.continue_port_shm_key,0,IPC_CREAT);
		if (shmid < 0) {
			//error("Get continue port shm id fail.");
			//write_log(LOG_ERR, FILE_LOG, __FILE__, __LINE__, SINGLE,"Get continue port shm id fail.");
			return(FALSE);
		}
		protected_resource_id[res_index].sip.continue_port_id = (CONTINUE_PORT_ID)shmat(shmid,NULL,SHM_RDONLY);
		if (protected_resource_id[res_index].sip.continue_port_id == -1) {
			//write_log(LOG_ERR, FILE_LOG, __FILE__, __LINE__, SINGLE,"Attach continue port shm fail.");
			//error("Attach continue port shm fail.");
			return(FALSE);
		}
	}

	if(protected_resource_id[res_index].dip.interval_port_shm_key > 0) {
		shmid = shmget(protected_resource_id[res_index].dip.interval_port_shm_key,0,IPC_CREAT);
		if (shmid < 0) {
			//error("Get interval port shm id fail.");
			//write_log(LOG_ERR, FILE_LOG, __FILE__, __LINE__, SINGLE,"Get interval port shm id fail.");
			return(FALSE);
		}
		protected_resource_id[res_index].dip.port_id = (INTERVAL_PORT_ID)shmat(shmid,NULL,SHM_RDONLY);
		if (protected_resource_id[res_index].dip.port_id == -1) {
			//error("Attach interval port shm fail.");
			//write_log(LOG_ERR, FILE_LOG, __FILE__, __LINE__, SINGLE,"Attach interval port shm fail.");
			return(FALSE);
		}
	}

	if(protected_resource_id[res_index].dip.continue_port_shm_key > 0) {
		shmid = shmget(protected_resource_id[res_index].dip.continue_port_shm_key,0,IPC_CREAT);
		if (shmid < 0) {
			//error("Get continue port shm id fail.");
			//write_log(LOG_ERR, FILE_LOG, __FILE__, __LINE__, SINGLE,"Get continue port shm id fail.");
			return(FALSE);
		}
		protected_resource_id[res_index].dip.continue_port_id = (CONTINUE_PORT_ID)shmat(shmid,NULL,SHM_RDONLY);
		if (protected_resource_id[res_index].dip.continue_port_id == -1) {
				        
			//error("Attach continue port shm fail.");
			//write_log(LOG_ERR, FILE_LOG, __FILE__, __LINE__, SINGLE,"Attach continue port shm fail.");
			return(FALSE);
		}
	}
				
	return(TRUE);
}

/*
 *	把PAR_ITF_ANALYZE_ID结构转换成EA_ITF_PAR_INFO_ID结构.
 */
void convet_par_itf(
	EA_ITF_PAR_INFO_ID	itf_par_info_id,
	PAR_ITF_ANALYZE_ID	par_itf_analysis_id,
	char			redirect_flag
	)
{

	PROTECTED_RESOURCE_ID	tmp = NULL;
	int			i   = 0;
	
	get_protocol_name(itf_par_info_id->protocol_name, par_itf_analysis_id);
	
	itf_par_info_id->cfg_file_set    = par_itf_analysis_id->cfg_file_set;
	itf_par_info_id->func_switch     = par_itf_analysis_id->func_switch;
	strcpy(itf_par_info_id->pkt_file_dir, par_itf_analysis_id->pkt_file_dir);
	itf_par_info_id->deposit_ivl_sec = par_itf_analysis_id->deposit_ivl_sec;
	
	itf_par_info_id->usr_list_id     = (USR_LIST_MEM_ID)			\
		get_shm_addr( par_itf_analysis_id->usr_list_key, SHM_RDONLY);
	itf_par_info_id->usr_all_num     = par_itf_analysis_id->usr_num;
	
   	tmp = (PROTECTED_RESOURCE_ID)get_shm_addr(par_itf_analysis_id->rule_pool_key, SHM_RDONLY);
	itf_par_info_id->protect_res_num = par_itf_analysis_id->rule_num;

	if(tmp == -1)	exit(-1);
	else {
		if((itf_par_info_id->protect_res_id = (PROTECTED_RESOURCE_ID)	\
			calloc(itf_par_info_id->protect_res_num,		\
				PROTECTED_RESOURCE_SIZE)) == NULL) {
			printf("protected_resource_id calloc error\n");
			exit(-1);	
		}

		memcpy(itf_par_info_id->protect_res_id, tmp,			\
			(itf_par_info_id->protect_res_num) * PROTECTED_RESOURCE_SIZE);
		for(i = 0; i < itf_par_info_id->protect_res_num; i++)
			if(get_resource_port(itf_par_info_id->protect_res_id, i)\
				 == FALSE)	exit(-1);/* where is get_resource_port */
				
	}  /* ended of if-else */

	itf_par_info_id->authorize_network_id  = (AUTHORIZE_ACCESS_NETWORK_ID)	\
		get_shm_addr(par_itf_analysis_id->authorize_network_key, SHM_RDONLY);
	itf_par_info_id->authorize_network_num = par_itf_analysis_id->authorize_network_num;

	itf_par_info_id->authorize_cmd_id      = (AUTHORIZE_CMD_ID)		\
		get_shm_addr(par_itf_analysis_id->authorize_cmd_key, SHM_RDONLY);
	itf_par_info_id->authorize_cmd_num     = par_itf_analysis_id->authorize_cmd_num;

	itf_par_info_id->authorize_account_id  = (AUTHORIZE_ACCOUNT_ID)		\
		get_shm_addr(par_itf_analysis_id->authorize_account_key, SHM_RDONLY);
	itf_par_info_id->authorize_account_num = par_itf_analysis_id->authorize_account_num;

   	itf_par_info_id->authorize_custom_id   = (AUTHORIZE_CUSTOM_ID)		\
		get_shm_addr( par_itf_analysis_id->authorize_custom_key, SHM_RDONLY);
	itf_par_info_id->authorize_custom_num  = par_itf_analysis_id->authorize_custom_num;

	itf_par_info_id->authorize_pro_feature_id  = (AUTHORIZE_PROTOCOL_FEATURE_ID)
		get_shm_addr( par_itf_analysis_id->authorize_feature_key, SHM_RDONLY);
	itf_par_info_id->authorize_pro_feature_num = par_itf_analysis_id->authorize_feature_num;

	if(redirect_flag)  { /* is true */
		itf_par_info_id->redirection_port_info_id = (REDIRECTION_PORT_INFO_ID)
			get_shm_addr(par_itf_analysis_id->redirect_key, 0);
		itf_par_info_id->redirect_pid = par_itf_analysis_id->redirect_pid;
		itf_par_info_id->semid        = semget(par_itf_analysis_id->sem_key, 0, IPC_CREAT);
	}
}


void get_protocol_name(
	char*			protocol_name,
	PAR_ITF_ANALYZE_ID	par_itf_analysis_id
	)
{
	
	SUPPORT_PRO_NODE_ID	shm_addr;

   	if((shm_addr = (SUPPORT_PRO_NODE_ID)
		get_shm_addr(par_itf_analysis_id->pro_tbl_shm_key,
			     SHM_RDONLY)) == NULL) {

		printf("Protocol list is not exist.");
		exit(EXIT_FAILURE);
	}

  	strcpy(protocol_name, shm_addr[par_itf_analysis_id->pro_id].pro_name);
}


void* get_shm_addr(
	key_t	key,
	int	shmflg
	)
{
	int	shmid	 = -1;
	void*	shm_addr = NULL;

	if(!key) /* key is zero */ return(NULL);
	shmid = shmget(key, 0, IPC_CREAT);
	if(shmid < 0) {
		error("[ERROR]***get shm id fail.");
		return(NULL);
	}
	
	if((shm_addr = shmat(shmid, NULL, shmflg)) == -1) {
        	error("[ERROR]***attach shm fail.");
		return(NULL);
	}
	else	return(shm_addr);
}
