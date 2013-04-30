
#ifndef _CTL_DB_H
#define _CTL_DB_H

#define ESQL_OK                1
#define ESQL_ERR               0

extern int conn_db(const char *host, const int port, const char *database,const char *user, const char *password);
extern int close_db(void);
extern int write_process_log_into_db(unsigned char* str);
extern int write_snam_sysinfo_into_db(unsigned char* str);
extern int write_authorizeinfo_into_db(char* str,int pro_num);

#endif
