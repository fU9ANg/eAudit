
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <stdarg.h> 
#include <time.h>

#include <sys/param.h>
#include <pcap.h>
#include <syslog.h>

#include "eAudit_config.h"
#include "eAudit_log.h"
#include "eAudit_mem.h"
#include "eAudit_res_callback.h"

#include "capture_pub.h"
#include "interface_capture.h"
#include "capture_debug.h"
#include "capture_signal.h"
#include "capture_process.h"
#include "capture_main.h"

/*function declaration*/
static void get_itf_capture_par(PAR_ITF_CAPTURE *par_itf_capture_id,char *s);
static void print_itf_par(PAR_ITF_CAPTURE *par_itf_capture_id);
static void print_cfg_par(QUE_ID shm_start_addr);

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int main(int argc,char **argv)
{
    char *opts = NULL;    
    PAR_ITF_CAPTURE par_itf_capture;
    int cfg_shm_id;
    QUE_ID shm_addr = NULL; 
 
    if (argc <= 0)
    {
        error("[Err]No interface parameters.\n");
        write_log(DEF_LOG_PRI,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"no interface parameters.");
        exit(EXIT_FAILURE);
    }

    DEBUG("Enter Capture process.\n");

#ifdef _DEBUG
    PRINT_PAR("[Capture]argv = %s\n",argv[0]);
#endif

    opts = strdup(argv[0]);
    if (NULL == opts)
    {
        error("[Err]Copy arg fail.\n");
        write_log(DEF_LOG_PRI,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"copy arg fail.");
        exit(EXIT_FAILURE);
    }
	
    get_itf_capture_par(&par_itf_capture,opts);
    FREE(opts);

#ifdef _DEBUG
    print_itf_par(&par_itf_capture);
#endif

    cfg_shm_id = shmget(par_itf_capture.run_cfg_shm_key,0,IPC_CREAT);
    if (cfg_shm_id < 0)
    {
        error("[Err]Get cfg shm fail.\n");
        write_log(DEF_LOG_PRI,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get cfg shm fail.");
        exit(EXIT_FAILURE);
    }
    
    shm_addr = (QUE_ID)shmat(cfg_shm_id,NULL,SHM_RDONLY);
    if (!shm_addr)
    {
        error("[Err]Attach cfg shm fail.\n");
        write_log(DEF_LOG_PRI,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
        exit(EXIT_FAILURE);
    }

#ifdef _DEBUG
    print_cfg_par(shm_addr);
#endif

#ifdef INC_REG_RES
    //signal(SIGINT,catch_proc);
   // signal(SIGINT,SIG_IGN);
    //signal(SIGKILL,catch_proc);
#endif

    capture_process(shm_addr,&par_itf_capture);
 
   // printf("####Capture process Quit OK.\n");

    exit(EXIT_SUCCESS);
}/*end of main*/

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void get_itf_capture_par(PAR_ITF_CAPTURE *par_itf_capture_id,char *s)
{
    register char *p = NULL;

    memset(par_itf_capture_id,0x00,PAR_ITF_CAPTURE_SIZE);

    strtok(s,PAR_DELIM);
    strcpy(par_itf_capture_id->nic_name,s);

    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->nic_no = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->que_num = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->func_switch.iAlarmSwitch = atoi(p);
	
    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->func_switch.iErrSwitch = atoi(p);
	
    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->func_switch.iStatSwitch = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->run_cfg_shm_key = (key_t)strtoul(p,NULL,10);
	
    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->nic_num = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->deposit_ivl_sec = atol(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_capture_id->flow_switch = atoi(p);
	
     p = strtok(NULL,PAR_DELIM);
    strcpy(par_itf_capture_id->manage_nic_name,p);


	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->tcp_block_queue_sem_key= (key_t)strtoul(p,NULL,10);
	
	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->tcp_block_queue1_shm_key= (key_t)strtoul(p,NULL,10);

	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->tcp_block_queue1_num= atol(p);

	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->tcp_block_queue2_check_shm_key= (key_t)strtoul(p,NULL,10);

	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->tcp_block_queue2_check_num= atol(p);


	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->tcp_block_queue2_shm_key= (key_t)strtoul(p,NULL,10);

	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->tcp_block_queue2_num= atol(p);

	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->ip_block_queue_shm_key= (key_t)strtoul(p,NULL,10);


	p = strtok(NULL,PAR_DELIM);
	par_itf_capture_id->ip_queue_num= atol(p);



	

	p = strtok(NULL, PAR_DELIM);
	par_itf_capture_id->res_key = (key_t)strtol(p, NULL, 10);

	p = strtok(NULL, PAR_DELIM);
	par_itf_capture_id->res_num = (key_t)strtoul(p, NULL, 10);
	
	p = strtok(NULL, PAR_DELIM);
	par_itf_capture_id->user_key = (key_t)strtol(p, NULL ,10);

	p = strtok(NULL, PAR_DELIM);
	par_itf_capture_id->user_num = (key_t)strtoul(p, NULL ,10);

	p = strtok(NULL, PAR_DELIM);
	par_itf_capture_id->authorize_key = (key_t)strtol(p, NULL, 10);
	
	p = strtok(NULL, PAR_DELIM);
	par_itf_capture_id->authorize_num= (key_t)strtoul(p, NULL ,10);
    
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
static void print_itf_par(PAR_ITF_CAPTURE *par_itf_capture_id)
{
   // printf("[Capture]nic name = %s\n",par_itf_capture_id->nic_name);
   // printf("[Capture]nic no = %d\n",par_itf_capture_id->nic_no);
   // printf("[Capture]que num = %d\n",par_itf_capture_id->que_num);
   // printf("[Capture]cfg shm key = %ld\n",(unsigned long)par_itf_capture_id->run_cfg_shm_key);
  //  printf("[Capture]cfg shm key = %ld\n",(unsigned long)par_itf_capture_id->run_cfg_shm_key);

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
static void print_cfg_par(QUE_ID shm_start_addr)
{
    //printf("capture que key = %ld\n",(long)(shm_start_addr->shmKey));
    //printf("sem key = %ld\n",(long)shm_start_addr->semKey);
   // printf("que_blk_num = %d\n",shm_start_addr->iQueBlkNum);
   // printf("que_blk_size = %d\n",shm_start_addr->iQueBlkSize);
	
    return;
}
