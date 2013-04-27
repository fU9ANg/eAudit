/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef FTP_ANALYZE_GLOBAL_H
#define FTP_ANALYZE_GLOBAL_H

#include <libpq-fe.h>

#include "interface.h"
#include "ftp_interface.h"
#include "db_config.h"


/*
 *  define all global object(variable, struct ...)
 *  for ftp analysis program.
 */
extern char	g_cur_date[32];
extern char	g_valid_ds;
extern char	g_check_conn_flag;
extern char	g_check_flux_flag;
extern char	g_model_name[MAX_MODEL_NAME_SIZE + 1];

extern struct	tm   g_old_time;
extern unsigned long g_tick_time;
extern unsigned long g_session_tbl_sum;
extern unsigned long g_conn_times_tbl_sum;
extern unsigned long g_cmd_tbl_sum;
extern unsigned long g_supported_cmd_num;
extern unsigned long g_interval_time;
extern unsigned long g_data_interval_time;
extern unsigned long g_max_supported_session;

extern PGconn*			g_data_conn;
extern PKT_FILE_HDR		g_pkt_file_hdr;         /* In interface.h */
extern DB_CFG_INFO		db_cfg_info;            /* In db_config.h */
extern PKT_BASIC_INFO		g_pkt_basic_info;       /* In ftp_interface.h */
extern MMAP_FILE_INFO	 	g_mmap_file_info;       /* In interface.h */
extern EA_MONITOR_INFO 		g_monitor_info;         /* In interface.h */
extern EA_ITF_PAR_INFO	 	g_itf_par_info;         /* In interface.h */

extern EA_CMD_TBL_ID	 	g_cmd_tbl_id;           /* In interface.h */
extern EA_CMD_TBL_ID	 	g_cmd_pos;              /* In interface.h */
extern RULE_ID_ST_ID	 	g_rule_id_st_id;        /* In interface.h */
extern PKT_USR_HDR_ID	 	g_libpcap_hdr_id;       /* In interface.h */
extern P_MONITOR_INFO_ID 	monitor_info;           /* In interface.h */
extern EA_SESSION_TBL_ID 	g_session_tbl_id;       /* In ftp_interface.h */
extern EA_SESSION_TBL_ID 	g_session_pos;          /* In ftp_interface.h */
extern EA_CONN_TIMES_TBL_ID 	g_conn_times_tbl_id;    /* In ftp_interface.h */
extern EA_DATA_SESSION_TBL_ID 	g_data_session_pos;     /* In ftp_interface.h */


#endif /* FTP_ANALYZE_GLOBAL_H */
