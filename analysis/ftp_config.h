/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef FTP_ANALYZE_CONFIG_H
#define FTP_ANALYZE_CONFIG_H

#include "interface.h"

#define FTP_CFG_FILE_NAME		"ftp_cfg_file.conf"
#define FTP_CMD_CFG_NAME		"ftp_cmd_cfg.conf"
#define FTP_MONITOR_CFG_NAME		"ftp_monitor_cfg.conf"

#define FTP_CFG_SECT			"FTP_CFG"
#define FTP_INTERVAL_TIME		"Interval_Time"
#define FTP_DATA_INTERVAL_TIME		"Data_Interval_Time"
#define FTP_SUPPORT_SESSION		"Max_Supported_Session"

#define DEF_INTERVAL_TIME		60
#define DEF_DATA_INTERFAL_TIME		120
#define DEF_SUPPORT_SESSION		100
#define DEF_SUPPORT_DATA_SESSION	100

typedef struct tagFTP_CFG_INFO
{
	unsigned long interval_time;
	unsigned long data_interval_time;
	unsigned long max_supported_session;

}	ftp_cfg_info, *ftp_cfg_info_id,	\
	FTP_CFG_INFO, *FTP_CFG_INFO_ID;
#define FTP_CFG_INFO_SIZE sizeof(FTP_CFG_INFO)
#define ftp_cfg_info_size sizeof(ftp_cfg_info)

/* prototypes. */
int read_ftp_cfg_file();
int read_ftp_cmd_cfg_file();
int  get_ftp_cfg_info        (FTP_CFG_INFO_ID p, char *path);
int  get_ftp_cfg_info_by_file(FTP_CFG_INFO_ID p, const char* file_cnt_buf);
void get_ftp_cfg_info_by_def (FTP_CFG_INFO_ID p);
int read_cmd_cfg_file(char*	     cmd_file_path, 
		      EA_CMD_TBL_ID  cmd_tbl_id,
		      unsigned long* cmd_tbl_sum_id);


#endif /* FTP_ANALYZE_CONFIG_H */
