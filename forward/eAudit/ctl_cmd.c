
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "ctl_pub.h"
#include "ctl_debug.h"
#include "ctl_cmd.h"

/*global var declaration*/
int g_sys_is_run = SAIL_FALSE;
PID_INFO_ID g_pid_info_id = NULL;

/*static function declaration*/
static int chk_pkt_flg(char *name);
static void proc_cmd(EN_SYS_CMD cmd);
static void proc_start_cmd(pid_t pid);
static void proc_stop_cmd(pid_t pid);
static void proc_restart_cmd(pid_t pid);

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void net_start_signal_callback(int sig_no)
{
    g_sys_is_run= SAIL_TRUE;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void ctl_analysis_pkt(char *pbuf)
{
    SYS_SKT_PKT_ID pkt_id = (SYS_SKT_PKT_ID)pbuf;

    assert(pbuf!=NULL);
	
    if (ERR == chk_pkt_flg(pkt_id->company_name))
        return;

    switch (pkt_id->type){
        case ONLY_CMD:
	     if (SAIL_TRUE == g_sys_is_run)
	         proc_cmd(pkt_id->cmd);
	     break;
	 case CMD_AND_DATA:
	     //proc_data();
	     break;
	 default:
	     break;
    }

    return;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int chk_pkt_flg(char *name)
{
    assert(name!=NULL);
    return (strcmp(name,SKT_PKT_FLAG) ? ERR:OK);  
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void proc_cmd(EN_SYS_CMD cmd)
{
    pid_t pid = -1;
    
    switch (cmd){
        case SYS_START_CMD:
	     proc_start_cmd(pid);
	     break;
        case SYS_STOP_CMD:
	     proc_stop_cmd(pid);
	     break;
        case SYS_RESTART_CMD:
	     proc_restart_cmd(pid);
	     break;
        default :
	     break;
    }

    return;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void proc_start_cmd(pid_t pid)
{
    kill(pid,SIGUSR1);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void proc_stop_cmd(pid_t pid)
{
    kill(pid,SIGTERM);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void proc_restart_cmd(pid_t pid)
{
    kill(pid,SIGUSR2);
}
