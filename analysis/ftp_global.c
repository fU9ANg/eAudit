/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <time.h>
#include <libpq-fe.h>

#include "ftp_global.h"


char	g_cur_date[32];
char	g_valid_ds;
char	g_check_conn_flag;
char	g_check_flux_flag;
char	g_model_name[MAX_MODEL_NAME_SIZE + 1];

struct	tm    g_old_time;
unsigned long g_tick_time;
unsigned long g_session_tbl_sum;
unsigned long g_conn_times_tbl_sum;
unsigned long g_cmd_tbl_sum;
unsigned long g_supported_cmd_num;
unsigned long g_interval_time;
unsigned long g_data_interval_time;
unsigned long g_max_supported_session;

PGconn*			g_data_conn;
PKT_FILE_HDR		g_pkt_file_hdr;
DB_CFG_INFO		db_cfg_info;
PKT_BASIC_INFO		g_pkt_basic_info;
MMAP_FILE_INFO	 	g_mmap_file_info;
EA_MONITOR_INFO 	g_monitor_info;
EA_ITF_PAR_INFO	 	g_itf_par_info;

EA_CMD_TBL_ID	 	g_cmd_tbl_id;
EA_CMD_TBL_ID	 	g_cmd_pos;
RULE_ID_ST_ID	 	g_rule_id_st_id;
PKT_USR_HDR_ID	 	g_libpcap_hdr_id;
P_MONITOR_INFO_ID 	monitor_info;
EA_SESSION_TBL_ID 	g_session_tbl_id;
EA_SESSION_TBL_ID 	g_session_pos;
EA_CONN_TIMES_TBL_ID 	g_conn_times_tbl_id;
EA_DATA_SESSION_TBL_ID 	g_data_session_pos;
