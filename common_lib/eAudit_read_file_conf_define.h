/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_READ_FILE_CONF_DEFINE_H
#define _EAUDIT_READ_FILE_CONF_DEFINE_H

#include "interface_pub.h"

#define MONITOR_PATH					"/eAudit/conf/eAudit_Monitor_FluxConnect.conf"


#define CONF_PATH						"/eAudit/conf"
#define MONITOR_FILE					"eAudit_Monitor_FluxConnect.conf"
#define USER_FILE						"eAudit_Authorize_User.conf"

#ifdef TRUE
#undef TRUE
#endif
#define TRUE								1

#ifdef FALSE
#undef FALSE
#endif
#define FALSE								0
#define LINE_LEN						1024

static int clear_enter(char *tmp, int len);
static int read_conf_front(FILE *fd, char *buff, int *num);
static int read_monitor_conf_data(FILE *fd, char *buff, int num, P_MONITOR_INFO_ID p_monitor_conf_id, int id);
static P_USER_INFO_ID read_user_conf_data(FILE *fd, char *buff, int num);


#endif
