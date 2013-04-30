
#ifndef _FILTER_PUB_H
#define _FILTER_PUB_H

#include "sail_errorcode.h"
#include "eAudit_pub.h"
#include "filter_model_ctl.h"

/*log type*/
#define LOG_TOOL SYS_LOG

/*IF FILTER ok*/
typedef enum{
    IS_PROTECTED_PKT = 0,
    NOT_PROTECTED_PKT
}EN_PKT_CLASS;

extern unsigned long g_protect_rule_id;
extern int g_block_flag;
extern int g_can_filter;
extern unsigned long authorize_id ;
extern unsigned long usr_id ;
extern unsigned long res_index;
extern unsigned char direction;
extern unsigned long network_index;
#endif
