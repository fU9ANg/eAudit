/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_DB_CONFIG_H
#define ANALYZE_DB_CONFIG_H

#include "interface.h"


#define MAX_DB_USR_NAME_SIZE	32
#define MAX_DB_NAME_SIZE	32
#define MAX_PASSWORD_SIZE	64

#define DB_CONN_CFG_SECT        "DB_CONN_CFG"
#define CONN_IP_KEY             "IP"	  /* database server's ip */
#define CONN_PORT_KEY           "Port"	  /* database server's port */
#define CONN_DB_NAME_KEY        "DbName"  /* database server's dbname */
#define CONN_USR_NAME_KEY       "UsrName" /* database server's user name */
#define CONN_PASSWORD_KEY	"Password"/* server's password of database user */


/* default value for connect to DB server */
#define DEF_DB_CONN_IP          "127.0.0.1"
#define DEF_DB_PORT		5432
#define DEF_DB_CONN_DB_NAME     "eAudit"
#define DEF_DB_CONN_USR_NAME    "postgres"
#define DEF_DB_CONN_TIEMOUT	10

#define DB_CFG_FILE_NAME	"eAudit_db_conn.conf"


/* data type for config file of db */
typedef struct tagDB_CFG_INFO {

	int	port;
	char	ip[MAX_STR_IP_LEN + 1];
	char	db[MAX_DB_NAME_SIZE + 1];
	char	password[MAX_PASSWORD_SIZE + 1];
	char	usr_name[MAX_DB_USR_NAME_SIZE + 1];

}	db_cfg_info,			\
	DB_CFG_INFO,			\
	*db_cfg_info_id,		\
	*DB_CFG_INFO_ID;
#define DB_CFG_INFO_SIZE sizeof(DB_CFG_INFO)


/* prototypes. */
int  read_db_cfg_info(DB_CFG_INFO_ID db_cfg_info_id);
int  get_db_cfg_info (DB_CFG_INFO_ID p, char* path);
void get_db_cfg_info_by_def (DB_CFG_INFO_ID p);
int  get_db_cfg_info_by_file(DB_CFG_INFO_ID p, const char* file_cnt_buf);


#endif /* ANALYZE_DB_CONFIG_H */
