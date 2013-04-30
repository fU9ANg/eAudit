
#ifndef _CTL_PUB_H
#define _CTL_PUB_H

#include "sail_errorcode.h"
#include "eAudit_pub.h"
#include "interface_pub.h"
#include "ctl_model_ctl.h"

#define LIST_ITEMS_DELIM       "+"
#define LIST_ITEMS_DELIM_CHAR   '+'
#define LIST_ITEMS_INDER            "/"

/*the line end char*/
#define LIST_LINE_END_ASC     59             /*';'*/
#define LIST_LINE_DELIM         ";"

/*min and max que num*/
#define MIN_QUE_NUM 2
#define MAX_QUE_NUM 10

/*log mode*/
#define LOG_TOOL SYS_LOG

/*the increase value compare max shm key*/
#define SHM_KEY_IVL ((key_t)1)  
#define SEM_KEY_IVL ((key_t)1) 

#endif
