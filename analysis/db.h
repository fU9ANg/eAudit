/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_DB_H
#define ANALYZE_DB_H

#include <libpq-fe.h>

#include "interface.h"


/* PROTOTYPES. */
void connect_db(PGconn**    conn,
		const char* host,
		const int   port,
		const char* database,
		const char* user,
		const char* password);

int  conn_db   (const char* host,
		const int   port,
		const char* database,
		const char* user,
		const char* password);

int  conn_db_data(PGconn ** conn,
		const char* host,
		const int   port,
		const char* database,
		const char* user,
		const char* password,
		int	    timeout);

int  conn_local_db();
int  conn_local_db_data(PGconn** conn);

int  disconn_db(void);
int  write_common_session_into_db(
		EA_COMMON_SESSION_TBL_ID common_session_tbl_id,
		char*			 cur_date,
		char*			 protocol);
/*int  write_pkt_into_db(
		EA_RECORD_FILE_TBL_ID	 record_tbl_id,
		char*			 cur_date);
int  string_to_bits(
		unsigned char*		 pkt_data,
		int			 pkt_len,
		char*			 data,
		int			 data_len); */
int  write_log_into_db(
		EA_LOG_TBL_ID		 log_tbl_id,
		char*	     		 cur_date);
int  write_alarm_into_db(
		EA_AlARM_TBL_ID		 alarm_tbl_id,
		char*			 cur_date);


#endif /* ANALYZE_DB_H */
