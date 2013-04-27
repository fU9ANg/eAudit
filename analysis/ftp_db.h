/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef FTP_ANALYZE_DB_H
#define FTP_ANALYZE_DB_H

#include "ftp_interface.h"

/* prototypes */
void force_sessions_into_db();
void write_abnormal_session_into_db(char flag);
int  write_session_into_db(EA_SESSION_TBL_ID session_tbl_id);



/* 事件级表保存网络中发生的事件, 如登录, 退出, 下载文件等. */
int  write_event_common_db_tbl	 (			/* COMMON */
	EA_EVENT_COMMON_TBL_ID   event_common_tbl_id);
int  write_event_auth_db_tbl	 (			/* AUTH */
	EA_EVENT_AUTH_TBL_ID     event_auth_tbl_id, char* protocol);
int  write_event_remove_db_tbl	 (			/* REMOVE */
	EA_EVENT_REMOVE_TBL_ID   ea_event_remove_tbl_id);
int  write_event_rename_db_tbl	 (			/* RENAME */
	EA_EVENT_RENAME_TBL_ID   ea_event_rename_tbl_id);
int  write_event_download_db_tbl (			/* DOWNLOAD */
	EA_EVENT_DOWNLOAD_TBL_ID ea_event_download_tbl_id);
int  write_event_upload_db_tbl	 (			/* UPLOAD */
	EA_EVENT_UPLOAD_TBL_ID   ea_event_upload_tbl_id);


/*
 * 详细级表保存网络中的所有数据, 这种格式保存的数据量也是很大的,
 * 所以采用了近似于记录级表的结构, 但是可能描述没有记录级具体 .
 */
int  write_detail_ftp_db_tbl	 (EA_ANALYSIS_FTP_CMD_TBL_ID analysis_ftp_cmd_tbl_id);
int  write_detail_data_ftp_db_tbl(EA_DETAIL_DIVIDE_ID detail_divide_id, int detail_record_len);


/* 记录级保存网络中的某个记录的具体内容, 如http的网页, telnet的文件等.
 * 由于这些文件有大有小, 如果都保存在数据表中, 首先是因为有些文件保存不下,
 * 还有就是如果直接保存在数据库中, 这给数据库造成很大的压力, 
 * 对整个系统的存取的负面影响也是很大的. */
int  write_record_file_db_tbl(EA_RECORD_FILE_TBL_ID record_file_tbl_id);
int  write_record_data_file_db_tbl(EA_RECORD_DATA_FILE_TBL_ID record_data_file_tbl_id,
	int   record_data_len);


void handle_ultravires(EA_SESSION_TBL_ID session_id,
	char* operater_type, char* log_detail, char* description, int flag);
int  close_tcp(EA_SESSION_TBL_ID session_id, EA_AlARM_TBL_ID alarm_tbl);


#endif /* FTP_ANALYZE_DB_H */
