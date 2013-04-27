/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

/* IF U DON'T UNDERSTAND, PLEASE READ THE F**KING SOURCE CODE */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include "analyze_interface.h"
#include "analyze_db_config.h"
#include "analyze_config.h"
#include "analyze_debug.h"
#include "analyze_common.h"


/*
 *  IMPLEMENTATION FOR OPERATION
 *  CONFIG FILE OF DATABASE SERVER.
 */

	int
read_db_cfg_info(
	DB_CFG_INFO_ID	db_cfg_info_id
	)
{
	/* example: "/eAudit/conf/eAudit_db_conn.conf" */
	char    db_cfg_path[MAX_FILE_PATH_SIZE + 1];
	sprintf(db_cfg_path, "%s/conf/%s", EAUDIT_DIR_PATH, DB_CFG_FILE_NAME);

	return get_db_cfg_info(db_cfg_info_id,db_cfg_path);
}



	int
get_db_cfg_info(
	DB_CFG_INFO_ID	p,
	char*		path
	)
{
	int		ret;
	int		fd = -1;
	unsigned long	file_size = 0;
	char*		file_cnt_buf = NULL;
	int		mode;

	if(!path) { /* NULL */
		get_db_cfg_info_by_def(p);
		return OK;
	}

	mode = get_read_cfg_mode(path, &fd, &file_size);
	if (DEF_MODE == mode) {
		get_db_cfg_info_by_def(p);
		return OK;
	}
    
	if (READ_FILE == mode){
		file_cnt_buf = malloc(file_size + 1);
		if (!file_cnt_buf) { /* NULL */
			close(fd);
			return ERR;
		}
        
		/* cnt mean is content, context or count? FK */
		if (!cfg_get_file_cnt(fd, file_cnt_buf, file_size)) {
			close(fd);
			return ERR;
		}

		file_cnt_buf[file_size] = '\0';
		ret = get_db_cfg_info_by_file(p, file_cnt_buf);
		free(file_cnt_buf);
		close(fd);
		return ret;
	} /* fi */

    return ERR;     
}


/*
 *  Get the default config for db.
 */
void get_db_cfg_info_by_def(DB_CFG_INFO_ID p)
{
	/* get the ip */
	strncpy(p->ip, DEF_DB_CONN_IP, MAX_STR_IP_LEN);
	p->ip[MAX_STR_IP_LEN] = '\0';

	/* get the port */
	p->port = DEF_DB_PORT;

	/* get the name of database */
	strncpy(p->db,DEF_DB_CONN_DB_NAME, MAX_DB_NAME_SIZE);
	p->db[MAX_DB_NAME_SIZE] = '\0';

	/* get the username of database */
	strncpy(p->usr_name,DEF_DB_CONN_USR_NAME, MAX_DB_USR_NAME_SIZE);
	p->usr_name[MAX_DB_USR_NAME_SIZE] = '\0';

	/* the p->password set NULL */
	p->password[0] = '\0';
}


/*
 *  get the config information of db on file.
 */
	int
get_db_cfg_info_by_file(
	DB_CFG_INFO_ID 	p,
	const char*	file_cnt_buf
	)
{
	int 	ret;
	char*	tmp_buf = (char *)file_cnt_buf;
	char 	key_val[CFG_BLK_SIZE + 1];
    
	/* get the ip of database server */
	ret = 	cfg_get_key_val(tmp_buf, DB_CONN_CFG_SECT, CONN_IP_KEY, 	\
			key_val, CFG_BLK_SIZE + 1);

	if (GET_CFG_VAL_FAIL == ret) {
		error("[Err]Get DB CFG ip err.\n");
		return ERR;
	} else {
		strncpy(p->ip, key_val, MAX_STR_IP_LEN);
		p->ip[MAX_STR_IP_LEN] = 0x00;	/* '\0' */
	}

	/* get the database's port */
	ret =   cfg_get_key_val(tmp_buf, DB_CONN_CFG_SECT, CONN_PORT_KEY,	\
			key_val, CFG_BLK_SIZE + 1);

	if (GET_CFG_VAL_FAIL == ret) {
		error("[Err]Get DB CFG port err.\n");
		return ERR;
	} else {
		p->port = atoi(key_val);
	}

	/* get the database's name */
	ret = 	cfg_get_key_val(tmp_buf, DB_CONN_CFG_SECT, CONN_DB_NAME_KEY,	\
			key_val, CFG_BLK_SIZE + 1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get DB CFG dbname err.\n");
		return ERR;
	} else {
		strncpy(p->db,key_val, MAX_DB_NAME_SIZE);
		p->db[MAX_DB_NAME_SIZE] = 0x00;
	}

	/* do the same as above for the user name of database server */
	ret = 	cfg_get_key_val(tmp_buf, DB_CONN_CFG_SECT, CONN_USR_NAME_KEY,	\
			key_val, CFG_BLK_SIZE + 1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get DB CFG usrname err.\n");
		return ERR;
	} else {
		strncpy(p->usr_name, key_val, MAX_DB_USR_NAME_SIZE);
		p->usr_name[MAX_DB_USR_NAME_SIZE] = 0x00;
	}
	
	/* password */
	ret = 	cfg_get_key_val(tmp_buf, DB_CONN_CFG_SECT, CONN_PASSWORD_KEY, 	\
			key_val, CFG_BLK_SIZE + 1);

	if(GET_CFG_VAL_FAIL == ret)
		p->password[0] = '\0';
    	else {
	 	strncpy(p->password,key_val, MAX_PASSWORD_SIZE);
		p->password[MAX_PASSWORD_SIZE] = 0x00;
    	}

	return OK; 
}


/*
 *  TEST
 */
	int
read_cmd_cfg_file(
	char* 	      cmd_file_path, 
	EA_CMD_TBL_ID cmd_tbl_id, 
	unsigned long*cmd_tbl_sum_id
	)
{
	int file_size = 0;
	int left_size = 0;
	int readn_len = 0;
	char* file_content = NULL;
	int fd 	      = -1;
	char line_str[2048];
	int i         = 0;
	char* p       = NULL;
	char* p1      = NULL;
	unsigned long cmd_tbl_sum = 0;	

	if(file_is_exist(cmd_file_path)==FILE_NOT_EXIST) return(ERR);

	if((file_size = get_file_size(cmd_file_path))==0)return(ERR);

	if((file_content=(char*)malloc(file_size))==NULL)return(ERR);
	
	if((fd = open(cmd_file_path, O_RDONLY)) < 0)	 return(ERR);

	memset(line_str, 0x00, 2048);
	left_size = file_size;
	while(left_size > 0) {

		if((readn_len=
		read(fd, file_content+file_size-left_size, left_size))<0) {
			if(errno == EINTR) continue;
			free(file_content);
			return(ERR);
		} else
			left_size-=readn_len;
	} /* elihw */

	close(fd);
	cmd_tbl_sum = 0;
	p 	    = file_content;

	while(p - file_content < file_size) {
		i = 0;
		while(*p != '\n')
			line_str[i++] = *p++;
		
		if((p1 = strchr(line_str, ';')) == NULL)
			continue;

		*p1 = '\0';
		if((p1 = strchr(line_str, ':')) == NULL)
			continue;

		memcpy(cmd_tbl_id[cmd_tbl_sum].cmd_name, line_str, p1-line_str);
		cmd_tbl_id[cmd_tbl_sum].cmd_name[p1 - line_str] = '\0';
		p1++;
		cmd_tbl_id[cmd_tbl_sum].cmd_no = strtol(p1, NULL, 10);
		
		if((p1 = strchr(p1, ':')) == NULL)
			continue;

		p1++;
		strcpy(cmd_tbl_id[cmd_tbl_sum++].cmd_ch, p1);
		p++;
		
	} /* elihw */

	free(file_content);
	*cmd_tbl_sum_id = cmd_tbl_sum;

	return(OK);
}
