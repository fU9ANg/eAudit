/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "analyze_authorize.h"
#include "analyze_debug.h"
#include "analyze_param.h"


/*
 *  An implementation for Get Username.
 *
 *  usr_list_id is a DS for save content of
 *  eAudit_Authorize_User.conf config file.
 *
 *  Example for testing:
	main()
	{
	        SRC_INFO     src_info;
	        USR_LIST_MEM usr_list[2];
	        USR_INFO     usr_info;

	        usr_list[0].usr_status = 1;
	        usr_list[0].iUsrId     = 100;
	        usr_list[0].ip         = 192;
	        strcpy(usr_list[0].strMac, "FFFFFF00FF00");
	        strcpy(usr_list[0].strUsrName, "fg");
	        usr_list[0].iUsrCertifyMethod = MAC_CERTIFITY;

	        usr_list[1].usr_status = 1;
	        usr_list[1].iUsrId     = 100;
	        usr_list[1].ip         = 192;
	        strcpy(usr_list[1].strMac, "00FFFF00FF00");
	        strcpy(usr_list[1].strUsrName, "bnL");
	        usr_list[1].iUsrCertifyMethod = IP_CERTIFITY;

	        src_info.src_ip        = 192;
	        strcpy(src_info.src_mac, "00FFFF00FF00");
	        src_info.sport         = 21;

	        get_usr_info(&usr_info, usr_list, 2, &src_info, 1008);

	        fprintf(stdout, "usrname=%s\n", usr_info.src_usrname);
	}
*/
	int 
get_usr_info(
	USR_INFO_ID	usr_info_id,
	USR_LIST_MEM_ID usr_list_id,
	unsigned long	usr_num,
	SRC_INFO_ID	src_info,
	unsigned long	user_id
	)
{ 
	unsigned long	i = 0;

	if((!usr_info_id) || (!src_info) || (!usr_list_id)) return(ERR);
	
	usr_info_id->src_usrid = -1;
  
	for(i=0; i<usr_num; i++) {

		switch(usr_list_id[i].iUsrCertifyMethod) {
		case IP_CERTIFITY:
			if(usr_list_id[i].ip == src_info->src_ip) {

				usr_info_id->src_usrid = usr_list_id[i].iUsrId;

				strncpy((char*)usr_info_id->src_usrname,	\
					(char*)usr_list_id[i].strUsrName,	\
					MAX_USR_NAME_SIZE);
				usr_info_id->src_usrname[MAX_USR_NAME_SIZE] = 0x00;
			} break;

		case MAC_CERTIFITY:
			if(!strcasecmp((char*)usr_list_id[i].strMac, 
				       (char*)src_info->src_mac)) { /* EQ */

				usr_info_id->src_usrid = usr_list_id[i].iUsrId;

				strncpy((char*)usr_info_id->src_usrname,	\
					(char*)usr_list_id[i].strUsrName,	\
					MAX_USR_NAME_SIZE);
				usr_info_id->src_usrname[MAX_USR_NAME_SIZE] = 0x00;
			} break;

		case IP_MAC_CERTIFITY:
			if((usr_list_id[i].ip == src_info->src_ip) &&
			   (strcasecmp((char*)usr_list_id[i].strMac,
			               (char*)src_info->src_mac)==0)) {

				usr_info_id->src_usrid = usr_list_id[i].iUsrId;

				strncpy((char*)usr_info_id->src_usrname,	\
					(char*)usr_list_id[i].strUsrName,	\
					MAX_USR_NAME_SIZE);
				usr_info_id->src_usrname[MAX_USR_NAME_SIZE] = 0x00;
			} break;

		case DYNAMIC_CERTIFITY:
			if(usr_list_id[i].iUsrId==user_id &&
			   usr_list_id[i].usr_status==1)  {

				usr_info_id->src_usrid = usr_list_id[i].iUsrId;
				strncpy((char*)usr_info_id->src_usrname,	\
					(char*)usr_list_id[i].strUsrName,	\
					MAX_USR_NAME_SIZE);
				usr_info_id->src_usrname[MAX_USR_NAME_SIZE] = 0x00;
			} break;

		default:  break;

		} /* htiws */

		if(usr_info_id->src_usrid != -1) break;
		else strcpy((char*)usr_info_id->src_usrname, "N/A");

	} /* rof */
	return(OK);
}



/*
 * read fields of protect_res_id array, so
 * construct content of config file (
 * eAudit_protected_resource.conf ).
*/
	void
construct_protected_res_content(
	char*	protected_res_content_id,
	PROTECTED_RESOURCE_ID protect_res_id,
	unsigned long	      res_index
	)
{
	struct	in_addr	ip_st;
	char	tmp_str[64];
	int	i = 0;

	if(!protected_res_content_id) return;

	/* get string */
	sprintf(protected_res_content_id, "%d+", 				\
		protect_res_id[res_index].rule_id);

	switch(protect_res_id[res_index].use_mac_flag) {

		case SMAC:
			strcat(protected_res_content_id, (char*)protect_res_id[res_index].smac);
			strcat(protected_res_content_id, "+");
		break;

		case DMAC:
			strcat(protected_res_content_id, (char*)protect_res_id[res_index].dmac);
			strcat(protected_res_content_id, "+");
		break;

		case SMAC_DMAC:
			strcat(protected_res_content_id, (char*)protect_res_id[res_index].smac);
			strcat(protected_res_content_id, "+");
			strcat(protected_res_content_id, (char*)protect_res_id[res_index].dmac);
			strcat(protected_res_content_id, "+");
		break;
	}

	switch(protect_res_id[res_index].use_ip_flag) {

		case SIP:
			ip_st.s_addr = protect_res_id[res_index].sip.ip;
			strcat(protected_res_content_id, inet_ntoa(ip_st));
			strcat(protected_res_content_id, "+");
			ip_st.s_addr = protect_res_id[res_index].sip.mask;
			strcat(protected_res_content_id, inet_ntoa(ip_st));
			strcat(protected_res_content_id, "+");
		break;

		case DIP:
			ip_st.s_addr = protect_res_id[res_index].dip.ip;
			strcat(protected_res_content_id, inet_ntoa(ip_st));
			strcat(protected_res_content_id, "+");
			ip_st.s_addr = protect_res_id[res_index].dip.mask;
			strcat(protected_res_content_id, inet_ntoa(ip_st));
			strcat(protected_res_content_id, "+");
		break;

		case SIP_DIP:
			ip_st.s_addr = protect_res_id[res_index].sip.ip;
			strcat(protected_res_content_id, inet_ntoa(ip_st));
			strcat(protected_res_content_id, "+");
			ip_st.s_addr = protect_res_id[res_index].sip.mask;
			strcat(protected_res_content_id, inet_ntoa(ip_st));
			strcat(protected_res_content_id, "+");

			ip_st.s_addr = protect_res_id[res_index].dip.ip;
			strcat(protected_res_content_id, inet_ntoa(ip_st));
			strcat(protected_res_content_id, "+");
			ip_st.s_addr = protect_res_id[res_index].dip.mask;
			strcat(protected_res_content_id, inet_ntoa(ip_st));
			strcat(protected_res_content_id, "+");
		break;
	}

	switch(protect_res_id[res_index].use_port_flag) {

	case SPORT:
		switch(protect_res_id[res_index].sip.src_port_express) {

		case SINGLE_PORT:
			sprintf(tmp_str, "%d+", protect_res_id[res_index].sip.single_port);
			strcat(protected_res_content_id, tmp_str);
		break;

		case CONTINUE_PORT:
			for(i=0; i<protect_res_id[res_index].sip.continue_port_num; i++) {

				sprintf(tmp_str, "%d-%d+", 			\
					protect_res_id[res_index].sip.continue_port_id[i].min_port,
					protect_res_id[res_index].sip.continue_port_id[i].max_port);

				strcat(protected_res_content_id, tmp_str);
			}
		break;

		case INTERVAL_PORT:
			for(i=0; i<protect_res_id[res_index].sip.interval_port_num; i++) {

				sprintf(tmp_str, "%d+",				\
					protect_res_id[res_index].sip.port_id[i].port);

				strcat(protected_res_content_id, tmp_str);
			}
		break;

		case CONTINUE_INTERVAL_PORT:
			for(i=0; i<protect_res_id[res_index].sip.continue_port_num; i++) {

				sprintf(tmp_str, "%d-%d+",			\
					protect_res_id[res_index].sip.continue_port_id[i].min_port,
					protect_res_id[res_index].sip.continue_port_id[i].max_port);
				strcat(protected_res_content_id, tmp_str);
			}
			for(i=0; i<protect_res_id[res_index].sip.interval_port_num; i++) {
				sprintf(tmp_str, "%d+",				\
					protect_res_id[res_index].sip.port_id[i].port);
				strcat(protected_res_content_id,tmp_str);
			}
		break;
		} /* hctiws */
	break; /* SPORT */

	case DPORT:
		switch(protect_res_id[res_index].dip.dst_port_express) {

		case SINGLE_PORT:
			sprintf(tmp_str, "%d+", protect_res_id[res_index].dip.single_port);
			strcat(protected_res_content_id, tmp_str);
		break;

		case CONTINUE_PORT:
			for(i=0; i<protect_res_id[res_index].dip.continue_port_num; i++) {
				sprintf(tmp_str, "%d-%d+", 			\
					protect_res_id[res_index].dip.continue_port_id[i].min_port,
					protect_res_id[res_index].dip.continue_port_id[i].max_port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;

		case INTERVAL_PORT:
			for(i=0; i<protect_res_id[res_index].dip.interval_port_num; i++) {
				sprintf(tmp_str, "%d+", 			\
					protect_res_id[res_index].dip.port_id[i].port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;

		case CONTINUE_INTERVAL_PORT:
			for(i=0; i<protect_res_id[res_index].dip.continue_port_num; i++) {
				sprintf(tmp_str, "%d-%d+", 			\
					protect_res_id[res_index].dip.continue_port_id[i].min_port,
					protect_res_id[res_index].dip.continue_port_id[i].max_port);
				strcat(protected_res_content_id, tmp_str);
			}
			for(i=0; i<protect_res_id[res_index].dip.interval_port_num; i++) {
				sprintf(tmp_str, "%d+",				\
					protect_res_id[res_index].dip.port_id[i].port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;
		} /* hctiws */
	break; /* DPORT */

	case SPORT_DPORT:
		switch(protect_res_id[res_index].sip.src_port_express) {
		case SINGLE_PORT:
			sprintf(tmp_str, "%d+",					\
				protect_res_id[res_index].sip.single_port);
			strcat(protected_res_content_id, tmp_str);
		break;
			
		case CONTINUE_PORT:
			for(i=0; i<protect_res_id[res_index].sip.continue_port_num; i++) {
				sprintf(tmp_str, "%d-%d+",			\
					protect_res_id[res_index].sip.continue_port_id[i].min_port,
					protect_res_id[res_index].sip.continue_port_id[i].max_port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;

		case INTERVAL_PORT:
			for(i=0; i<protect_res_id[res_index].sip.interval_port_num; i++) {
				sprintf(tmp_str, "%d+",				\
					protect_res_id[res_index].sip.port_id[i].port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;

		case CONTINUE_INTERVAL_PORT:
			for(i=0; i<protect_res_id[res_index].sip.continue_port_num; i++) {
				sprintf(tmp_str, "%d-%d+",			\
					protect_res_id[res_index].sip.continue_port_id[i].min_port,
					protect_res_id[res_index].sip.continue_port_id[i].max_port);
				strcat(protected_res_content_id, tmp_str);
			 }
			for(i=0;i<protect_res_id[res_index].sip.interval_port_num;i++) {
				sprintf(tmp_str, "%d+", protect_res_id[res_index].sip.port_id[i].port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;
		} /* hctiws */

		switch(protect_res_id[res_index].dip.dst_port_express) {
		case SINGLE_PORT:
			sprintf(tmp_str, "%d+",					\
				protect_res_id[res_index].dip.single_port);
			strcat(protected_res_content_id, tmp_str);
		break;

		case CONTINUE_PORT:
			for(i=0; i<protect_res_id[res_index].dip.continue_port_num; i++) {
				sprintf(tmp_str, "%d-%d+",			\
					protect_res_id[res_index].dip.continue_port_id[i].min_port,
					protect_res_id[res_index].dip.continue_port_id[i].max_port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;

		case INTERVAL_PORT:
			for(i=0; i<protect_res_id[res_index].dip.interval_port_num; i++) {
				sprintf(tmp_str, "%d+",				\
					protect_res_id[res_index].dip.port_id[i].port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;
		
		case CONTINUE_INTERVAL_PORT:
			for(i=0; i<protect_res_id[res_index].dip.continue_port_num; i++) {
				sprintf(tmp_str, "%d-%d+",			\
					protect_res_id[res_index].dip.continue_port_id[i].min_port,
					protect_res_id[res_index].dip.continue_port_id[i].max_port);
				strcat(protected_res_content_id, tmp_str);
			}
			for(i=0; i<protect_res_id[res_index].dip.interval_port_num; i++) {
				sprintf(tmp_str, "%d+",				\
					protect_res_id[res_index].dip.port_id[i].port);
				strcat(protected_res_content_id, tmp_str);
			}
		break;
		} /* hctiws */
	break; /* SPORT_DPORT */
   	} /* main hctiws */

	strcat(protected_res_content_id, protect_res_id[res_index]. pro_name);
}


	unsigned long
search_in_cmd_authorize_list(
	AUTHORIZE_CMD_CONTENT_ID* p_authorize_cmd_content_id,
	AUTHORIZE_CMD_ID	    authorize_cmd_id,
	unsigned long		    authorize_cmd_num,
	unsigned long		    authorize_id
	)
{
	int i, shm_id = -1;

	if(!authorize_cmd_id) return(-1);
	if(authorize_cmd_num==0 || p_authorize_cmd_content_id==NULL)  return(-1);

	for(i=0; i<authorize_cmd_num; i++) {

		if(authorize_cmd_id[i].authorize_id ==authorize_id) {

			shm_id = shmget(authorize_cmd_id[i].authorize_cmd_key, 0, IPC_CREAT);
    			if (shm_id < 0) {
       				error("[Err]authorize_protol feature shm fail.\n");
        			return(-1);
    			}
   			*p_authorize_cmd_content_id = 				\
			(AUTHORIZE_CMD_CONTENT_ID)shmat(shm_id, NULL, SHM_RDONLY);

   			if ((*p_authorize_cmd_content_id) == -1) {
        			error("[Err]Attach authorize_protol feature content shm fail.\n");
       				return(-1);
   			}
			return(i);
		}
	} /* rof */

 	return(-1);
}

	unsigned long
search_in_account_authorize_list(
	AUTHORIZE_ACCOUNT_CONTENT_ID* p_authorize_account_content_id,
	AUTHORIZE_ACCOUNT_ID 		authorize_account_id,
	unsigned long			authorize_account_num,
	unsigned long			authorize_id
	)
{
	int i,shm_id = -1;
	
	if(!authorize_account_id) return(-1);

	if(authorize_account_num==0 || p_authorize_account_content_id == NULL)
		return(-1);

     	for(i=0; i<authorize_account_num; i++) {

		if(authorize_account_id[i].authorize_id == authorize_id) {

			shm_id = shmget(authorize_account_id[i].authorize_account_key, 0, IPC_CREAT);
    			if (shm_id < 0) {
       				error("[Err]authorize_protol feature shm fail.\n");
        			return(-1);
    			}
   			*p_authorize_account_content_id = 			\
			(AUTHORIZE_ACCOUNT_CONTENT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   			if ((*p_authorize_account_content_id) == -1) {

        			error("[Err]Attach authorize_protol feature content shm fail.\n");
       				return -1;
   			}
			return(i);
		}
	}
 	return(-1);
}


	unsigned long
search_in_custom_authorize_list(
	AUTHORIZE_CUSTOM_CONTENT_ID*  p_authorize_custom_content_id,
	AUTHORIZE_CUSTOM_ID		authorize_custom_id,
	unsigned long			authorize_custom_num,
	unsigned long			authorize_id
	)
{
	int i,shm_id = -1;
	if(!authorize_custom_id) return(-1);

	if(authorize_custom_num==0 || p_authorize_custom_content_id == NULL)
		return -1;

	for(i=0; i < authorize_custom_num; i++) {

		if(authorize_custom_id[i].authorize_id ==authorize_id) {

			shm_id = shmget(authorize_custom_id[i].authorize_custom_key, 0, IPC_CREAT);
    			if (shm_id < 0) {

				error("[Err]authorize_custom_key shm fail.\n");
        			return -1;
    			}
   			*p_authorize_custom_content_id =			\
			(AUTHORIZE_CUSTOM_CONTENT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   			if ((*p_authorize_custom_content_id) == -1) {

        			error("[Err]Attach authorize_custom content shm fail.\n");
       				return -1;
   			}
			return(i);
		}
	}
	return(-1);
}


	unsigned long
search_in_custom_protol_authorize_list (
	AUTHORIZE_PROTOCOL_TYPE_ID    authorize_protocol_type_id,
	AUTHORIZE_PROTOCOL_FEATURE_ID authorize_protocol_feature_id,
	unsigned long		      authorize_pro_feature_num,
	unsigned long		      authorize_id
	)
{
	int i, j, shm_id = -1;
	AUTHORIZE_PROTOCOL_FEATURE_TYPE_ID authorize_protocol_feature_type_id = NULL;
	if(authorize_protocol_feature_id == NULL || \
		authorize_pro_feature_num == 0 ||   \
		authorize_protocol_type_id == NULL)
	{
		 return -1;
	}
	for(i=0; i<authorize_pro_feature_num; i++) {

		if(authorize_protocol_feature_id[i].authorize_id ==authorize_id) {

			shm_id = 
			shmget(authorize_protocol_feature_id[i].authorize_protocol_feature_key, 0, IPC_CREAT);
    			if (shm_id < 0) {

       				error("[Err]authorize_protol feature type shm fail.\n");
        			return -1;
    			}
   			authorize_protocol_feature_type_id = 			\
			(AUTHORIZE_PROTOCOL_FEATURE_TYPE_ID)shmat(shm_id,NULL,SHM_RDONLY);
   			if ((authorize_protocol_feature_type_id) == -1) {

        			error("[Err]authorize_protol feature  type shm fail.\n");
       				return -1;
   			}
			for(j = 0; j<authorize_protocol_feature_id[i].pro_feature_num; j++) {

				authorize_protocol_type_id[j].type  	  = 	\
				authorize_protocol_feature_type_id[j].authorize_type;
				authorize_protocol_type_id[j].content_num = 	\
				authorize_protocol_feature_type_id[j].authorize_feature_content_num;
				shm_id = shmget(authorize_protocol_feature_type_id[j].\
				authorize_protocol_feature_content_key,0,IPC_CREAT);
    				if (shm_id < 0) {

       					error("[Err]authorize_protol feature content shm fail.\n");
        				return -1;
    				}
				authorize_protocol_type_id[j].content_id = 	\
				(AUTHORIZE_PROTOCOL_CONTENT_ID)shmat(shm_id, NULL, SHM_RDONLY);
				if (authorize_protocol_type_id[j].content_id == -1) {

        				error("[Err]authorize_protol feature  content shm fail.\n");
       					return -1;
   				}
			}
			return i;
		}
	}
 	return -1;
}


	void
set_eaudit_authorize_info(
	EAUDIT_AUTHORIZE_INFO_ID    eaudit_authorize_info_id,
	PROTECTED_RESOURCE_ID	    protect_res_id,
	AUTHORIZE_ACCESS_NETWORK_ID authorize_network_id,
	RULE_ID_ST_ID		    rule_id_st_id
	)
{
   	if((rule_id_st_id->authorize_id == 0) || (rule_id_st_id->usr_id == 0))  {

		if(protect_res_id[rule_id_st_id->res_index].			\
			eaudit_level.session_level)	
			eaudit_authorize_info_id->eaudit_info |= SESSION_LEVEL;

		if(protect_res_id[rule_id_st_id->res_index].			\
			eaudit_level.record_level == 1)
			eaudit_authorize_info_id->eaudit_info |= RECORD_LEVEL;

		if(protect_res_id[rule_id_st_id->res_index].			\
			eaudit_level.analysis_level == 1)
			eaudit_authorize_info_id->eaudit_info |= DETAIL_LEVEL;

		if(protect_res_id[rule_id_st_id->res_index].			\
			eaudit_level.total_analysis_level == 1)
			eaudit_authorize_info_id->eaudit_info |= TOTAL_ANALYZE_LEVEL;

		if(protect_res_id[rule_id_st_id->				\
			res_index].eaudit_level.event_level == 1)
			eaudit_authorize_info_id->eaudit_info |= EVENT_LEVEL;

		if(protect_res_id[rule_id_st_id->res_index].			\
			eaudit_level.custom_made_level == 1)
			eaudit_authorize_info_id->eaudit_info |= CUSTOM_LEVEL;

		if(protect_res_id[rule_id_st_id->res_index].			\
			eaudit_level.manage_level == 1)
			eaudit_authorize_info_id->eaudit_info |= MANAGE_LEVEL;
		
		eaudit_authorize_info_id->authorize_info |= AUTHORIZE_NOT_NETWORK_INFO;

	  	if(protect_res_id[rule_id_st_id->res_index].unauthorize_event.block_flag == 1)
			eaudit_authorize_info_id->handle_info |= BLOCK_HANDLE;

	   	if(protect_res_id[rule_id_st_id->res_index].unauthorize_event.log_flag == 1)
	   	 	eaudit_authorize_info_id->handle_info |= LOG_HANDLE;

	   	if(protect_res_id[rule_id_st_id->res_index].unauthorize_event.warn_flag == 1)
	   		eaudit_authorize_info_id->handle_info |= ALARM_HANDLE;  
   	} else {

		if(authorize_network_id[rule_id_st_id->net_index].		\
			eaudit_level.session_level)
			eaudit_authorize_info_id->eaudit_info |= SESSION_LEVEL;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			eaudit_level.record_level == 1)
			eaudit_authorize_info_id->eaudit_info |= RECORD_LEVEL;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			eaudit_level.analysis_level == 1)
			eaudit_authorize_info_id->eaudit_info |= DETAIL_LEVEL;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			eaudit_level.total_analysis_level == 1)
			eaudit_authorize_info_id->eaudit_info |= TOTAL_ANALYZE_LEVEL;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			eaudit_level.event_level == 1)
			eaudit_authorize_info_id->eaudit_info |= EVENT_LEVEL;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			eaudit_level.custom_made_level == 1)
			eaudit_authorize_info_id->eaudit_info |= CUSTOM_LEVEL;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			eaudit_level.manage_level == 1)
			eaudit_authorize_info_id->eaudit_info |= MANAGE_LEVEL;

		
        	eaudit_authorize_info_id->authorize_info |= AUTHORIZE_NETWORK_INFO;
		if(authorize_network_id[rule_id_st_id->net_index].		\
			authorize_level.authorize_account == 1)
			eaudit_authorize_info_id->authorize_info |= AUTHORIZE_ACCOUNT_INFO;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			authorize_level.authorize_cmd ==1)
			eaudit_authorize_info_id->authorize_info|=AUTHORIZE_CMD_INFO;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			authorize_level.authorize_custom_made==1)
			eaudit_authorize_info_id->authorize_info|=AUTHORIZE_CUSTOM_INFO;

		if(authorize_network_id[rule_id_st_id->net_index].		\
			authorize_level.authorize_pro_feature_made ==1)
			eaudit_authorize_info_id->authorize_info|=AUTHORIZE_FEATURE_INFO;
		
		if(protect_res_id[rule_id_st_id->res_index].unauthorize_event.block_flag == 1)
		{
			eaudit_authorize_info_id->handle_info |= BLOCK_HANDLE;
			eaudit_authorize_info_id->authorize_info |= BLOCK_HANDLE;
		}
	   	if(protect_res_id[rule_id_st_id->res_index].unauthorize_event.log_flag == 1)
	   	{
	   	 	eaudit_authorize_info_id->handle_info |= LOG_HANDLE;  
			eaudit_authorize_info_id->authorize_info |= LOG_HANDLE;
	   	}
	   	if(protect_res_id[rule_id_st_id->res_index].unauthorize_event.warn_flag == 1)
	   	{
	   		eaudit_authorize_info_id->handle_info |= ALARM_HANDLE; 
			eaudit_authorize_info_id->authorize_info |= ALARM_HANDLE;
	   	}
   	} /* fi */
}


	int
search_in_account_list(
	const char*		     pattern,
	AUTHORIZE_ACCOUNT_ID	     account_id,
	AUTHORIZE_ACCOUNT_CONTENT_ID account_content_id,
	unsigned long 		     index
	)
{
	int	 i;
	if(!pattern || !account_id || index < 0 || !account_content_id) return(FALSE);

	for(i=0; i<account_id[index].account_num; i++) {

		if(strcmp(pattern, (char*)account_content_id[i].account) == 0)
			return(TRUE);
	}
	return(FALSE);
}


	int
search_in_cmd_list(
	const char*		 pattern,
	AUTHORIZE_CMD_ID	 cmd_id,
	AUTHORIZE_CMD_CONTENT_ID cmd_content_id,
	unsigned long		 index
	)
{
	int	 i;
	if(!pattern || !cmd_id || index < 0 || !cmd_content_id) return(FALSE);

	for(i=0; i<cmd_id[index].cmd_num; i++) {
		if(strcmp(pattern, (char*)cmd_content_id[i].cmd) == 0) return(TRUE);

	}
	return(FALSE);
}


	int
search_in_custom_list(
	const char*		    pattern,
	AUTHORIZE_CUSTOM_ID	    custom_id,
	AUTHORIZE_CUSTOM_CONTENT_ID custom_content_id,
	unsigned long		    index,
	char			    match_mode
	)
{	
	int	 i;
	if(!pattern || !custom_id || !custom_content_id || index < 0 ||		\
	  (match_mode!=FULL_MATCH_MODE && match_mode != SUBSTRING_MATCH_MODE))	{
		return(FALSE);
	}

	for(i=0; i<custom_id[index].custom_num; i++) {

		if(match_mode == FULL_MATCH_MODE)    {

			if(strcmp(pattern, (char*)custom_content_id[i].custom)==0)
				return(TRUE);
		} else {
			if(strstr(pattern, (char*)custom_content_id[i].custom)!=NULL)
				return(TRUE);
		}
	} /* rof */

	return(FALSE);
}


	int
search_in_protocol_list(
	const char*		      pattern,
	char			      pattern_type,
	AUTHORIZE_PROTOCOL_FEATURE_ID protocol_id,
	AUTHORIZE_PROTOCOL_TYPE_ID    protocol_type_id,
	unsigned long		      index,
	char			      match_mode
	)
{
	int	 i, j;
	if(!pattern || !protocol_id || !protocol_type_id || index < 0 ||	\
	  (match_mode!= FULL_MATCH_MODE && match_mode != SUBSTRING_MATCH_MODE)) {
		return(FALSE);
	}

	for(i=0; i<protocol_id[index].pro_feature_num; i++) {

		if(match_mode == FULL_MATCH_MODE) 	    {

			if(protocol_type_id[i].type == pattern_type) {

				for(j=0; j<protocol_type_id[i].content_num;j++) {

					if(strcmp(pattern,			\
					  (char*)(protocol_type_id[i].content_id[j].content))==0)
						return(TRUE);
				}
			}
		} else  {

			if(protocol_type_id[i].type == pattern_type) {

				for(j=0; j<protocol_type_id[i].content_num;j++) {

					if(strstr(pattern,			\
					  (char*)(protocol_type_id[i].content_id[j].content))!=NULL)
						return(TRUE);
				}
			}
		}
	} /* rof */

	return(FALSE);
}
