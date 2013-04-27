/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "interface.h"

#include "ftp_config.h"
#include "ftp_global.h"


int read_ftp_cfg_file()
{
	char		ftp_cfg_path[MAX_FILE_PATH_SIZE + 1];
	FTP_CFG_INFO	ftp_cfg_info;

	sprintf(ftp_cfg_path, "%s/conf/%s", EAUDIT_DIR_PATH, FTP_CFG_FILE_NAME);
	
	/* 
   	 * get values of variables
	 * (interval_time, data_interval_time, max_supported_session).
	 */
	if(get_ftp_cfg_info(&ftp_cfg_info, ftp_cfg_path) == OK) {
		if(ftp_cfg_info.interval_time != 0)
			 g_interval_time = ftp_cfg_info.interval_time;
		if(ftp_cfg_info.data_interval_time != 0)
			 g_data_interval_time = ftp_cfg_info.data_interval_time;
		if(ftp_cfg_info.max_supported_session != 0)
			 g_max_supported_session = ftp_cfg_info.max_supported_session;

		return(OK);
	}
	return(ERR);
}


int read_ftp_monitor_cfg_file()
{
	int m_flag = 0;
	if((monitor_info = (P_MONITOR_INFO_ID)calloc(1, P_MONITOR_INFO_SIZE)) == NULL) {
		printf("monitor_info calloc error\n");
		return(ERR);
	}

	if(read_monitor_conf(PRO_TYPE_FTP, monitor_info, &m_flag)) {
		monitor_info->flux_threshold *= 1024;

		if(monitor_info->conn_threshold <= 0)
			monitor_info->conn_threshold = 1;

		if(monitor_info->flux_threshold <= 0)
			monitor_info->flux_threshold = 1;
	} else {
		if(monitor_info)
			memset(monitor_info, 0x00, P_MONITOR_INFO_SIZE);
		return(ERR);
	}
	
	return(OK);
}


int read_ftp_cmd_cfg_file()
{
	char ftp_cmd_cfg_path[MAX_FILE_PATH_SIZE + 1];
	sprintf(ftp_cmd_cfg_path, "%s/conf/%s", EAUDIT_DIR_PATH, FTP_CMD_CFG_NAME);

	if((g_cmd_tbl_id = calloc(g_supported_cmd_num, EA_CMD_TBL_SIZE)) == NULL)
		return(ERR);

	return(read_cmd_cfg_file(ftp_cmd_cfg_path,g_cmd_tbl_id, &g_cmd_tbl_sum));

}


int get_ftp_cfg_info(
	FTP_CFG_INFO_ID	p,
	char*		path
	)
{

    int		  ret;
    int		  mode;
    int		  fd 		= -1;
    unsigned long file_size 	= 0;
    char*	  file_cnt_buf  = NULL;


    if (!path) {/* path is NULL */
        get_ftp_cfg_info_by_def(p);
        return(OK);
    }
      
    /* where is get_read_cfg_mode */
    mode = get_read_cfg_mode(path,&fd,&file_size);
    if (DEF_MODE == mode) {
        get_ftp_cfg_info_by_def(p);
        return OK;
    }
    
    if (READ_FILE == mode) {
        file_cnt_buf = malloc(file_size + 1);

        if (!file_cnt_buf) {
            close(fd);
            return ERR;
        }
        
        if (!cfg_get_file_cnt(fd,file_cnt_buf,file_size)) {
            close(fd);
            return ERR;
        }
        
	file_cnt_buf[file_size] = '\0';
        ret = get_ftp_cfg_info_by_file(p,file_cnt_buf);
        free(file_cnt_buf);
        close(fd);
        return ret;
    }

    return ERR;     
}


void get_ftp_cfg_info_by_def(FTP_CFG_INFO_ID p)
{
	p->interval_time	= DEF_INTERVAL_TIME;
	p->data_interval_time	= DEF_DATA_INTERFAL_TIME;
	p->max_supported_session= DEF_SUPPORT_SESSION;
}


int get_ftp_cfg_info_by_file(
	FTP_CFG_INFO_ID	p,
	const char*	file_cnt_buf
	)
{
	int	ret;
	char*	tmp_buf = (char *)file_cnt_buf;
	char	key_val[CFG_BLK_SIZE];
    
	memset(key_val, 0x00, CFG_BLK_SIZE);
	ret = cfg_get_key_val(tmp_buf,FTP_CFG_SECT, FTP_INTERVAL_TIME,		\
		key_val, CFG_BLK_SIZE + 1);
	if(GET_CFG_VAL_FAIL == ret) {
	        error("[Err]Get FTP CFG interval time err.\n");
		return(ERR);
	} else {
		p->interval_time = strtoul(key_val, NULL, 10);
	}


	memset(key_val,0x00,CFG_BLK_SIZE);
	ret = cfg_get_key_val(tmp_buf,FTP_CFG_SECT, FTP_DATA_INTERVAL_TIME,	\
		key_val, CFG_BLK_SIZE + 1);
	if(GET_CFG_VAL_FAIL == ret) {
        	error("[Err]Get FTP CFG data interval time err.\n");
		return(ERR);
	} else {
		p->data_interval_time = strtoul(key_val, NULL, 10);
	}


	memset(key_val,0x00,CFG_BLK_SIZE);
	ret = cfg_get_key_val(tmp_buf,FTP_CFG_SECT, FTP_SUPPORT_SESSION,	\
		key_val, CFG_BLK_SIZE + 1);
	if(GET_CFG_VAL_FAIL == ret) {
	        error("[Err]Get FTP CFG support session err.\n");
		return(ERR);
	} else {
		p->max_supported_session= strtoul(key_val, NULL, 10);
	}
  
	return(OK); 	
}
