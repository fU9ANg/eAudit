
#ifndef _CTL_CMD_H
#define _CTL_CMD_H

#include "interface_monitor.h"

#define SKT_PKT_FLAG "SAIL_CD"

typedef enum
{
    ONLY_CMD,
    CMD_AND_DATA
}EN_SKT_PKT_TYPE;

typedef enum
{
    CFG_SYS_CMD,
    CFG_CAP_NIC_CMD,
    CFG_ADD_RULE_CMD,
    CFG_DEL_RULE_CMD,
    CFG_MODIFY_RULE_CMD,
    CFG_MOT_CMD,
    SYS_START_CMD,
    SYS_STOP_CMD,
    SYS_RESTART_CMD,
    REFRESH_STAT_CMD,
    REFRESH_MOT_CMD
}EN_SYS_CMD;

typedef struct tagSYS_SKT_PKT
{
    char company_name[7];  /*flag*/
    EN_SKT_PKT_TYPE type;
    EN_SYS_CMD cmd;
    int cnt_len;   /*对应数据长度*/
}SYS_SKT_PKT,*SYS_SKT_PKT_ID;
#define SYS_SKT_PKT_SIZE sizeof(SYS_SKT_PKT)

extern int g_sys_is_run;
extern PID_INFO_ID g_pid_info_id;

/*function declaration*/
extern void ctl_analysis_pkt(char *pbuf);
extern void net_start_signal_callback(int sig_no);

#endif
