/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_READ_FILE_CONF_H
#define _EAUDIT_READ_FILE_CONF_H

#include "interface_pub.h"


extern P_MONITOR_INFO_ID read_monitor_conf(int id, P_MONITOR_INFO_ID p_monitor__conf_id, int *flag);
extern P_USER_INFO_ID read_user_conf();
extern void close_user_conf(P_USER_INFO_ID p_user_info_id);

#endif
