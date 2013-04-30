
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include "capture_db_config.h"
#include "capture_config.h"
#include "capture_debug.h"
#include "capture_process.h"
#include "eAudit_pub.h"

int read_db_cfg_info(DB_CFG_INFO_ID db_cfg_info_id)
{
	char db_cfg_path[MAX_FILE_PATH_SIZE + 1];
	sprintf(db_cfg_path,"%s/conf/%s",EAUDIT_DIR_PATH, DB_CFG_FILE_NAME);

	return get_db_cfg_info(db_cfg_info_id,db_cfg_path);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_db_cfg_info(DB_CFG_INFO_ID p,char *path)
{
	int ret;
	int fd = -1;
	unsigned long file_size = 0;
	char *file_cnt_buf = NULL;
	int mode;

	if (NULL == path)
	{
		get_db_cfg_info_by_def(p);
		return OK;
	}
      
	mode = get_read_cfg_mode(path,&fd,&file_size);
	if (DEF_MODE == mode)
	{
		get_db_cfg_info_by_def(p);
		return OK;
	}
    
	if (READ_FILE == mode)
	{
		file_cnt_buf = malloc(file_size + 1);
		if (NULL == file_cnt_buf)
		{
			close(fd);
			return ERR;
		}
        
		if (NULL == cfg_get_file_cnt1(fd,file_cnt_buf,file_size))
		{
			close(fd);
			return ERR;
		}

		file_cnt_buf[file_size] = '\0';
		ret = get_db_cfg_info_by_file(p,file_cnt_buf);
		free(file_cnt_buf);
		close(fd);
		return ret;
	}

    return ERR;     
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_db_cfg_info_by_def(DB_CFG_INFO_ID p)
{
	strncpy(p->ip,DEF_DB_CONN_IP, MAX_STR_IP_LEN);
	p->ip[MAX_STR_IP_LEN] = '\0';
	p->port = DEF_DB_PORT;
	strncpy(p->db,DEF_DB_CONN_DB_NAME, MAX_DB_NAME_SIZE);
	p->db[MAX_DB_NAME_SIZE] = '\0';
	strncpy(p->usr_name,DEF_DB_CONN_USR_NAME, MAX_DB_USR_NAME_SIZE);
	p->usr_name[MAX_DB_USR_NAME_SIZE] = '\0';
	p->password[0] = '\0';
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_db_cfg_info_by_file(DB_CFG_INFO_ID p,const char *file_cnt_buf)
{
	int ret;
	char *tmp_buf = (char *)file_cnt_buf;
	char key_val[CFG_BLK_SIZE+1];    
    
	ret = cfg_get_key_val1(tmp_buf,DB_CONN_CFG_SECT,CONN_IP_KEY,key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		DEBUG("[Err]Get DB CFG ip err.\n");
		return ERR;
	}else
	{
		strncpy(p->ip,key_val, MAX_STR_IP_LEN);
		p->ip[MAX_STR_IP_LEN] = 0x00;
	}
	ret = cfg_get_key_val1(tmp_buf,DB_CONN_CFG_SECT,CONN_PORT_KEY,key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		DEBUG("[Err]Get DB CFG port err.\n");
		return ERR;
	}else
	{
		p->port = atoi(key_val);
	}
	ret = cfg_get_key_val1(tmp_buf,DB_CONN_CFG_SECT,CONN_DB_NAME_KEY,key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		DEBUG("[Err]Get DB CFG dbname err.\n");
		return ERR;
	}else
	{
		strncpy(p->db,key_val, MAX_DB_NAME_SIZE);
		p->db[MAX_DB_NAME_SIZE] = 0x00;
	}
	ret = cfg_get_key_val1(tmp_buf,DB_CONN_CFG_SECT,CONN_USR_NAME_KEY,key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		DEBUG("[Err]Get DB CFG usrname err.\n");
		return ERR;
	}
	else
	{
		strncpy(p->usr_name,key_val, MAX_DB_USR_NAME_SIZE);
		p->usr_name[MAX_DB_USR_NAME_SIZE] = 0x00;
	}
	
	ret = cfg_get_key_val1(tmp_buf, DB_CONN_CFG_SECT, CONN_PASSWORD_KEY, key_val, CFG_BLK_SIZE+1);
	if(GET_CFG_VAL_FAIL == ret)
	{
		p->password[0] = '\0';
	}
    	else
   	{
	 	strncpy(p->password,key_val, MAX_PASSWORD_SIZE);
		p->password[MAX_PASSWORD_SIZE] = 0x00;
    	}

	return OK; 
}


