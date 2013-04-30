
#ifndef CAPTURE_DB_H
#define CAPTURE_DB_H

#include "interface_block.h"


#define ESQL_ERR	 -1
#define ESQL_OK 		0

int connect_db(const char *host, const int port, const char *database, const char *user, const char *password);
int conn_db(const char *host, const int port, const char *database, const char *user, const char *password);
int conn_local_db();
int disconn_db(void);
int write_block_log(BLOCKLOGINFO_ID blockloginfo_id);



#endif
