
#ifndef CAPTURE_DB_CONFIG_H
#define CAPTURE_DB_CONFIG_H

#define MAX_STR_IP_LEN					15

#define EAUDIT_DIR_PATH				"/eAudit"

#define MAX_DB_USR_NAME_SIZE 32
#define MAX_DB_NAME_SIZE     32
#define MAX_PASSWORD_SIZE   64

#define DB_CONN_CFG_SECT            	"DB_CONN_CFG"
#define CONN_IP_KEY                 		"IP"
#define CONN_PORT_KEY               		"Port"
#define CONN_DB_NAME_KEY           	"DbName"
#define CONN_USR_NAME_KEY          	"UsrName"
#define CONN_PASSWORD_KEY			"Password"

#define DEF_DB_CONN_IP              		"127.0.0.1"
#define DEF_DB_PORT		             		5432
#define DEF_DB_CONN_DB_NAME         	"eAudit"
#define DEF_DB_CONN_USR_NAME        	"postgres"

#define DB_CFG_FILE_NAME			"eAudit_db_conn.conf"

typedef struct tagDB_CFG_INFO
{
	char ip[MAX_STR_IP_LEN+1];
	int port;
	char usr_name[MAX_DB_USR_NAME_SIZE+1];
	char db[MAX_DB_NAME_SIZE+1];
	char password[MAX_PASSWORD_SIZE+1];
}DB_CFG_INFO,*DB_CFG_INFO_ID;
#define DB_CFG_INFO_SIZE sizeof(DB_CFG_INFO)


int read_db_cfg_info(DB_CFG_INFO_ID db_cfg_info_id);
int get_db_cfg_info(DB_CFG_INFO_ID p,char *path);
void get_db_cfg_info_by_def(DB_CFG_INFO_ID p);
int get_db_cfg_info_by_file(DB_CFG_INFO_ID p,const char *file_cnt_buf);


#endif


