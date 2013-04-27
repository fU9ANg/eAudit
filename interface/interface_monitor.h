
/*
 * file: interface_monitor.h
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#ifndef _INTERFACE_MONITOR_H
#define _INTERFACE_MONITOR_H

#include "interface_pub.h"

#define MAX_REPORT_MSG_SIZE 1024

/*the process type*/
typedef enum{
    NO_PROCESS = 0,
    CTL_PROCESS = 1,
    NET_DAEMON_PROCESS = 2,
    CAPTURE_CHILD_PROCESS = 3,
    FILTER_CHILD_PROCESS = 4,
    ANALYZE_CHILD_PROCESS = 5,
    STAT_CHILD_PROCESS = 6,
    MOT_CHILD_PROCESS = 7,
    PMC_SERVER_PROCESS = 8
}EN_PROCESS_TYPE;

/*the process status*/
typedef enum{
    PROC_NO_START = 0,
    PROC_RUNNING = 1,
    PROC_STOP = 2
}EN_PROCESS_STATUS;

typedef enum{
    RPT_DEBUG_MSG = 0,
    RPT_INFO_MSG,
    RPT_ERR_MSG
}EN_RPT_MSG_TYPE;

/*the pid information*/
typedef struct tagPID_INFO{
    long pid;
    char exec_path[256];
    char parameter[1024];
    char para_flag;
    char conect_flag;
   // EN_PROCESS_TYPE pid_type;
    //EN_PROCESS_STATUS pid_status;
}PID_INFO,*PID_INFO_ID;
#define PID_INFO_SIZE sizeof(PID_INFO)

typedef struct tagRTP_MSG{
    EN_RPT_MSG_TYPE msg_type;
    long  msg_no;
}RTP_MSG,RTP_MSG_ID;
#define RTP_MSG_SIZE sizeof(RTP_MSG)

typedef struct tagPAR_ITF_MOT{
    int process_num;
    int capture_nic_num;

    char pkt_file_dir[MAX_DIR_SIZE+1];
	
    key_t pid_info_shm_key;
    key_t capture_nic_shm_key;
}__attribute__ ((packed)) PAR_ITF_MOT,*PAR_ITF_MOT_ID;
#define PAR_ITF_MOT_SIZE sizeof(PAR_ITF_MOT)

#endif
