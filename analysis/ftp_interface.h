/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef FTP_ANALYZE_INTERFACE_H
#define FTP_ANALYZE_INTERFACE_H

#include<time.h>
#include<sys/types.h>

#include "interface.h"


#define MAX_REQUEST_LEN					511

#define NO_ENTRY					0
#define EXIST_ENTRY					1

#define STATE_CONN					0
#define STATE_PASV					1
#define STATE_PORT					2

int	raw_socket;
int	raw_socket_arp;


/* 报文基本信息 */
typedef struct tagPKT_BASIC_INFO {

	unsigned long	session_id;
	struct timeval	ts;
	unsigned long	pkt_len;			/* 抓取的包的长度 */
	unsigned char*	pkt_addr;			/* 包的首地址,链路层 */
	unsigned char	src_mac[MAC_ADDRESS_SIZE];	/* 六元组 源MAC地址 */
	unsigned char	dst_mac[MAC_ADDRESS_SIZE];	/* 六元组 目的MAC地址 */
	unsigned long	src_ip;				/* 源IP */
	unsigned long	dst_ip;				/* 目的IP */
   	unsigned short	th_sport;			/* 源端口 */
	unsigned short	th_dport;			/* 目的端口 */
	unsigned long	data_len;			/* 数据长度 */
	unsigned char*	data_addr;			
	unsigned char	ip_hdr_len;			/* IP */
	unsigned char	ip_proto;			/* IP上层协议 */
	unsigned long	src_net;
	unsigned long	dst_net;
	unsigned char	tcp_hdr_len;			/* TCP 首部长度 */
	unsigned long	th_seq;				/* TCP 序号 */
	unsigned long	th_ack;				/* TCP 确认号 */
	unsigned char	th_flags;			/* TCP 标志 */

}	pkt_basic_info, *pkt_basic_info_id,		\
	PKT_BASIC_INFO, *PKT_BASIC_INFO_ID;
#define PKT_BASIC_INFO_SIZE sizeof(PKT_BASIC_INFO)
#define pkt_basic_info_size sizeof(pkt_basic_info)


struct HANDLE_FLAG {
	char		block;
	char		log;
	char		warn;
};


typedef struct tagEA_SESSION_TBL { /* session table */

	int		utf8_flag;
	char		g_cur_date[32];			/* current date */
	struct		HANDLE_FLAG account;		/* command authorize */
	struct		HANDLE_FLAG cmd;		/* account authorize */
	struct		HANDLE_FLAG custom;		/* custom  authorize */
	struct		HANDLE_FLAG pro_feature;	/* authorize of protocol\
							feature */

	unsigned long	up_seq;
	unsigned long	up_ack;
	unsigned long	down_seq;
	unsigned long	down_ack;
	
	char		flag;			  	/* this session is vaild? */
	unsigned long	session_id;			/* session id */
	int		pro_type_id;			/* protocol type id */
   	unsigned char	src_mac[MAC_ADDRESS_SIZE];	/* source mac address */
	unsigned char	dst_mac[MAC_ADDRESS_SIZE];	/* dest mac address */
	unsigned long	src_ip;				/* source ip address */
	unsigned long	dst_ip;				/* dest ip address */
	unsigned short	src_port;			/* source port */
	unsigned short	dst_port;			/* dest port */
	
	unsigned long	src_net;
	unsigned long	dst_net;

   	struct timeval	ts_start;			/* begin time of session */
   	struct timeval	ts_end;				/* end time of session */
   	time_t        	ts_last;			/* the time of last data packet */
   	unsigned long	pgt_len;			/* total length of packet */
	unsigned long	pgt_num;			/* total number of packet */
	unsigned long	flux;	

	unsigned long	protected_res_no;		/* protected resource number */
	char		protected_res_content[MAX_RULE_CNT_SIZE + 1];	/* content */
	char		protected_res_name[MAX_RES_NAME_SIZE + 1];	/* name */

	unsigned long	up_ackno;			/* packet number of up */
	unsigned long	dn_ackno;			/* packet number of down */
	char		send_closeflag;
	char		recv_closeflag;
	
	char		data_flag;
	char		login_flag;
	int		risk_level;
	
	EA_DETAIL_TBL	detail_tbl;			/* deatil of session */
	USR_INFO	usr_info;			/* user information */
	EAUDIT_AUTHORIZE_INFO	eaudit_authorize_info;	/* authorize information */
	EA_DATA_SESSION_TBL	data_session_tbl;	/* data session */

}	ea_session_tbl, *ea_session_tbl_id,			\
	EA_SESSION_TBL, *EA_SESSION_TBL_ID;
#define EA_SESSION_TBL_SIZE sizeof(EA_SESSION_TBL)
#define ea_session_tbl_size sizeof(ea_session_tbl)


typedef struct tagEA_DETAIL_TBL { /* detail session */

	char		cur_dir[MAX_FILE_PATH_SIZE + 1];
	char		login_user[MAX_LOGIN_USER_NAME_SIZE + 1];
	int		fd;
	char		save_path[MAX_FILE_PATH_SIZE + 1];
	
	char		request[MAX_REQUEST_LEN + 1];
	char		rename_from[MAX_FILE_PATH_SIZE + 1];

	char		file_name[MAX_FILE_PATH_SIZE + 1];
	char		file_suffix[MAX_FILE_PATH_SIZE + 1];
	long		file_size;
	int		file_no;
	
	int		start_anlaysis_index;
	int		cur_analysis_index;
	struct timeval	start_cmd_time;
	struct timeval	cur_cmd_time;

	int		record_id;
	int		event_seq;
	
}	ea_detail_tbl, 	*ea_detail_tbl,			\
	EA_DETAIL_TBL, 	*EA_DETAIL_TBL_ID;
#define EA_DETAIL_TBL_SIZE sizeof(EA_DETAIL_TBL)
#define ea_detail_tbl_size sizeof(ea_detail_tbl)


typedef struct tagEA_DATA_SESSION { /* data session */

	char		flag;
	char		state;

	unsigned long	data_session_id;
  	unsigned char 	src_mac[MAC_ADDRESS_SIZE];
	unsigned char 	dst_mac[MAC_ADDRESS_SIZE];
	unsigned long	src_ip;
	unsigned long 	dst_ip;
	unsigned short 	src_port;
	unsigned short 	dst_port;

   	struct timeval 	ts_start;
   	struct timeval 	ts_end;	

   	time_t  	ts_last;

	unsigned long 	pgt_len;
	unsigned long  	pgt_num;
	unsigned long 	data_len;
		
	unsigned long 	up_ackno;
	unsigned long 	dn_ackno;
	
	char		send_closeflag;
	char		recv_closeflag;
	
}	ea_data_session_tbl, *ea_data_session_tbl,	\
	EA_DATA_SESSION_TBL, *EA_DATA_SESSION_TBL_ID;
#define EA_DATA_SESSION_TBL_SIZE sizeof(EA_DATA_SESSION_TBL)
#define ea_data_session_tbl_size sizeof(ea_data_session_tbl)


typedef struct tagEA_CONN_TIMES_TBL {

	char		flag;
	unsigned long	session_id;
	unsigned long	protected_res_no;
	char		protected_res_name[MAX_RES_NAME_SIZE + 1];	/*新加*/	

	unsigned long	dst_addr;
	unsigned short	dst_port;
	
	unsigned long	src_addr;
	unsigned char	src_mac[MAC_ADDRESS_SIZE];
	unsigned char	dst_mac[MAC_ADDRESS_SIZE];

	
	USR_INFO	usr_info;
	int		conn_time;

}	ea_conn_times_tbl, *ea_conn_times_tbl_id,		\
	EA_CONN_TIMES_TBL, *EA_CONN_TIMES_TBL_ID;
#define EA_CONN_TIMES_TBL_SIZE sizeof(EA_CONN_TIMES_TBL)
#define ea_conn_times_tbl_size sizeof(ea_conn_times_tbl)


/* the table of all ftp command */
typedef struct tagEA_ANALYSIS_FTP_CMD_TBL {

	unsigned long	session_id;
	int		analysis_index;
	struct timeval  request_time;
	struct timeval  response_time;
	char		cmd_name[16];			/* FTP command name */
	int		cmd_no;				/* FTP command number */
	char		cmd_param[64];			/* FTP command parameters */
	char		res_info[256];			/* FTP command response information */
	char		cmd_chinese[1024];		/* chinese information of FTP */

}	ea_analysis_ftp_cmd_tbl, *ea_analysis_ftp_cmd_tbl_id,	\
	EA_ANALYSIS_FTP_CMD_TBL, *EA_ANALYSIS_FTP_CMD_TBL_ID;
#define EA_ANALYSIS_FTP_CMD_TBL_SIZE  sizeof(EA_ANALYSIS_FTP_CMD_TBL)
#define ea_analysis_ftp_cmd_tbl_size  sizeof(ea_analysis_ftp_cmd_tbl)


/* login or quit event of the FTP */
typedef struct tagEA_EVENT_AUTH_TBL { /* alias EVENT_LOGIN_TBL */

	unsigned long	session_id;
	int		event_seq;
	int		p_type_id;
	int		event_type;
	char		result;
	struct timeval 	event_time;
	
	int		analysis_start;
	int		analysis_end;
	char		user_name[64];
	char		object_name[64];
	char		event_des[128];

}	ea_event_auth_tbl, *ea_event_auth_tbl_id,		\
	EA_EVENT_AUTH_TBL, *EA_EVENT_AUTH_TBL_ID;
#define EA_EVENT_AUTH_TBL_SIZE sizeof(EA_EVENT_AUTH_TBL)
#define ea_event_auth_tbl_size sizeof(ea_event_auth_tbl)


/* the remove event of FTP */
typedef struct tagEA_EVENT_REMOVE_TBL {

	unsigned long	session_id;
	int		event_seq;
	int		p_type_id;
	int		event_type;
	char		result;
	struct timeval  event_time;

	int		analysis_start;
	int		analysis_end;
	char		object_name[64];
	char		event_des[128];

}	ea_event_remove_tbl, *ea_event_remove_tbl_id,		\
	EA_EVENT_REMOVE_TBL, *EA_EVENT_REMOVE_TBL_ID;
#define EA_EVENT_REMOVE_TBL_SIZE sizeof(EA_EVENT_REMOVE_TBL)
#define ea_event_remove_tbl_size sizeof(ea_event_remove_tbl)


/* the rename event of FTP */
typedef struct tagEA_EVENT_RENAME_TBL {

	unsigned long	session_id;
	int		event_seq;
	int		p_type_id;
	int		event_type;
	char		result;
	struct timeval  event_time;

	int		analysis_start;
	int		analysis_end;
	char		object_src[64];
	char		object_dst[64];
	char		event_des[128];

}	ea_event_rename_tbl, *ea_event_rename_tbl_id,		\
	EA_EVENT_RENAME_TBL, *EA_EVENT_RENAME_TBL_ID;
#define EA_EVENT_RENAME_TBL_SIZE sizeof(EA_EVENT_RENAME_TBL)
#define ea_event_rename_tbl_size sizeof(ea_event_rename_tbl)


/* the upload event of FTP */
typedef struct tagEA_EVENT_UPLOAD_TBL {

	unsigned long	session_id;
	int		event_seq;
	int		p_type_id;
	int		event_type;
	char		result;
	struct timeval  event_time;

	int		analysis_start;
	int		analysis_end;
	char		object_src[64];
	char		object_dst[64];
	long		object_size;
	char		event_des[128];

}	ea_event_upload_tbl, *ea_event_upload_tbl_id,		\
	EA_EVENT_UPLOAD_TBL, *EA_EVENT_UPLOAD_TBL_ID;
#define EA_EVENT_UPLOAD_TBL_SIZE sizeof(EA_EVENT_UPLOAD_TBL)
#define ea_event_upload_tbl_size sizeof(ea_event_upload_tbl)


/* the download event of FTP */
typedef struct tagEA_EVENT_DOWNLOAD_TBL {

	unsigned long	session_id;
	int		event_seq;
	int		p_type_id;
	int		event_type;
	char		result;
	struct timeval  event_time;

	int		analysis_start;
	int		analysis_end;
	char		object_src[64];
	char		object_dst[64];
	long		object_size;
	char		event_des[512];

}	ea_event_download_tbl, *ea_event_download_tbl_id,	\
	EA_EVENT_DOWNLOAD_TBL, *EA_EVENT_DOWNLOAD_TBL_ID;
#define EA_EVENT_DOWNLOAD_TBL_SIZE sizeof(EA_EVENT_DOWNLOAD_TBL)
#define ea_event_download_tbl_size sizeof(ea_event_download_tbl)


/* the data type of record */
typedef struct tagEA_RECORD_FILE_TBL {

	unsigned long	session_id;
	int		file_no;
	int		p_type_id;
	struct timeval  start_time;
	struct timeval  end_time;
	char		file_name[MAX_FILE_PATH_SIZE + 1];
	char		file_suffix[MAX_FILE_PATH_SIZE + 1];
	long		real_size;
	long		nego_size;
	int		result;
	char		save_path[MAX_FILE_PATH_SIZE + 1];

}	ea_record_file_tbl, *ea_record_file_tbl_id,		\
	EA_RECORD_FILE_TBL, *EA_RECORD_FILE_TBL_ID;
#define EA_RECORD_FILE_TBL_SIZE sizeof(EA_RECORD_FILE_TBL)
#define ea_record_file_tbl_size sizeof(ea_record_file_tbl)


typedef struct tagEA_RECORD_DATA_FILE_TBL {

	unsigned long	session_id;
	int		record_id;
	int		file_neaf_id;
	char*		save_content;

}	ea_record_data_file_tbl, *ea_record_data_file_tbl_id,	\
	EA_RECORD_DATA_FILE_TBL, *EA_RECORD_DATA_FILE_TBL_ID;
#define EA_RECORD_DATA_FILE_TBL_SIZE sizeof(EA_RECORD_DATA_FILE_TBL)
#define ea_record_data_file_tbl_size sizeof(ea_record_data_file_tbl)


typedef struct tagEA_DETAIL_DIVIDE {

	unsigned long	session_id;
	int		analysis_index;
	int		record_index;
	char*		detail_record_ptr;

}	ea_detail_divide, *ea_detail_divide_id,			\
	EA_DETAIL_DIVIDE, *EA_DETAIL_DIVIDE_ID;
#define EA_DETAIL_DIVIDE_SIZE sizeof(EA_DETAIL_DIVIDE)
#define ea_detail_divide_size sizeof(ea_detail_divide)


#endif /* FTP_ANALYZE_INTERFACE_H */
