/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_AUTHORIZE_H
#define ANALYZE_AUTHORIZE_H

#include "interface.h"


/* prototypes for all authorize files. */
int get_usr_info (
	USR_INFO_ID		usr_info_id,
	USR_LIST_MEM_ID		usr_list_id,
	unsigned long		usr_num,
	SRC_INFO_ID		src_info,
	unsigned long		user_id );

void construct_protected_res_content (
	char*			protected_res_content_id,
	PROTECTED_RESOURCE_ID	protect_res_id,
	unsigned long		res_index );


unsigned long search_in_cmd_authorize_list (
	AUTHORIZE_CMD_CONTENT_ID*	p_authorize_cmd_content_id,
	AUTHORIZE_CMD_ID	  	authorize_cmd_id,
	unsigned long		  	authorize_cmd_num,
	unsigned long		  	authorize_id );

unsigned long search_in_account_authorize_list (
	AUTHORIZE_ACCOUNT_CONTENT_ID* p_authorize_account_content_id,
	AUTHORIZE_ACCOUNT_ID		authorize_account_id,
	unsigned long			authorize_account_num,
	unsigned long			authorize_id );

unsigned long search_in_custom_authorize_list (
	AUTHORIZE_CUSTOM_CONTENT_ID*  p_authorize_custom_content_id,
	AUTHORIZE_CUSTOM_ID	        authorize_custom_id,
	unsigned long			authorize_custom_num,
	unsigned long			authorize_id );

unsigned long search_in_custom_protol_authorize_list (
	AUTHORIZE_PROTOCOL_TYPE_ID	authorize_protocol_type_id,
	AUTHORIZE_PROTOCOL_FEATURE_ID	authorize_protocol_feature_id,
	unsigned long			authorize_pro_feature_num,
	unsigned long			authorize_id );

void set_eaudit_authorize_info (
	EAUDIT_AUTHORIZE_INFO_ID	eaudit_authorize_info_id,
	PROTECTED_RESOURCE_ID		protect_res_id,
	AUTHORIZE_ACCESS_NETWORK_ID	authorize_network_id,
	RULE_ID_ST_ID			rule_id_st_id );

int search_in_account_list (
	const char*			pattern,
	AUTHORIZE_ACCOUNT_ID		account_id,
	AUTHORIZE_ACCOUNT_CONTENT_ID	account_content_id,
	unsigned long			index );

int search_in_cmd_list (
	const char*			pattern,
	AUTHORIZE_CMD_ID		cmd_id,
	AUTHORIZE_CMD_CONTENT_ID	cmd_content_id,
	unsigned long index );

int search_in_custom_list (
	const char*			pattern,
	AUTHORIZE_CUSTOM_ID		custom_id,
	AUTHORIZE_CUSTOM_CONTENT_ID	custom_content_id,
	unsigned long			index,
	char				match_mode );

int search_in_protocol_list (
	const char*			pattern,
	char				pattern_type,
	AUTHORIZE_PROTOCOL_FEATURE_ID	protocol_id,
	AUTHORIZE_PROTOCOL_TYPE_ID	protocol_type_id,
	unsigned long			index,
	char				match_mode );


#endif /* ANALYZE_AUTHORIZE_H */
