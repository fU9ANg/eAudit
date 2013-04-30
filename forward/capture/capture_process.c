
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
 #include <netinet/if_ether.h>  
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <stdarg.h> 
#include <time.h>
#include <sys/time.h>
#include <sys/param.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <pcap.h>
#include <syslog.h>
#include <pthread.h>



#include "eAudit_config.h"
#include "eAudit_log.h"
#include "eAudit_sem.h"
#include "eAudit_shm.h"
#include "eAudit_mem.h"
#include "eAudit_dir.h"
#include "eAudit_shm_que.h"
#include "eAudit_res_callback.h"
#include "eAudit_timer.h"
#include "eAudit_pipe.h"
#include "eAudit_sendtcp.h"

#include "sail_ether.h"
#include "sail_arp.h"
#include "sail_ip.h"
#include "sail_tcp.h"
#include "sail_udp.h"

#include "interface_flow.h"

#include "capture_pub.h"
#include "interface_capture.h"
#include "interface_analyze.h"
#include "interface_block.h"
#include "capture_signal.h"
#include "capture_debug.h"
#include "capture_stat.h"
#include "capture_process.h"
#include "capture_config.h"
#include "capture_db.h"
#include "capture_db_config.h"

/*global var*/
pcap_t *pd = NULL;  /* 捕获数据包句柄*/

BLOCK_POLICY_LIST g_tcp_block_policy_list;

BLOCK_POLICY_LIST g_udp_block_policy_list;

PROTECTED_RESOURCE_ID g_res_list_id = NULL;
int g_res_num = 0;
USR_LIST_MEM_ID g_user_list_id = NULL;
int g_user_num = 0;
AUTHORIZE_ACCESS_NETWORK_ID g_auth_list_id = NULL;
int g_auth_num = 0;

int m_block_queue_semid = -1;

int m_ip_block_queue_semid = 0;
int m_tcp_close_queue1_semid = 1;
int m_tcp_close_queue2_check_semid = 2;
int m_tcp_close_queue2_semid = 3;

IP_PACKET_ID g_ip_block_queue_id = NULL;
BLOCK_QUEUE_INFO g_ip_block_queue_info;

TCP_CLOSEINFO_ID g_tcp_close_queue1_ptr = NULL;
BLOCK_QUEUE_INFO g_tcp_close_queue1_info;

TCP_CLOSEINFO_ID g_tcp_close_queue2_check_ptr = NULL;
BLOCK_QUEUE_INFO g_tcp_close_queue2_check_info;

TCP_CLOSEINFO_ID g_tcp_close_queue2_ptr = NULL;
BLOCK_QUEUE_INFO g_tcp_close_queue2_info;

UDP_CLOSEINFO_ID   g_udp_close_queue_ptr = NULL;
UDP_BLOCK_QUEUE_INFO   g_udp_block_queue_info;

BLOCKLOGINFO_ID g_blocklog_info_ptr = NULL;
BLOCKLOG_QUEUE_INFO g_blocklog_queue_info;

pthread_mutex_t g_udp_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t g_blocklog_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

PKTS_STAT g_pkt_stat;
PKTS_STAT g_old_pkt_stat;

int g_block_flag = SHM_NOT_BLOCK;
int g_capture_cmd;

int g_can_capture = SAIL_TRUE;
int g_sys_msg_que_id;
int g_flow_switch = OFF;

#ifdef INC_FLOW_STAT_ANALYSIS_MODEL
unsigned short g_arp_type;
unsigned short g_ip_type;
unsigned short g_revarp_type;
#endif

/*static function declaration*/
static void init_global_var();
static void capture_stop(void);
static void capture_stop_signal_handler(int signo);

static int get_per_nic_shm(int que_num,QUE_ID que_id,NIC_QUE_INFO_ID nic_que_info_id);
static int get_per_nic_sem(int que_num,QUE_ID que_id,NIC_QUE_INFO_ID nic_que_info_id);

static int reg_capture_res(int que_num,NIC_QUE_INFO_ID nic_que_info_id);
static void copy_pcap_pkt(u_char *userData, const struct pcap_pkthdr *h, const u_char *pkt);
static void send_ok_to_parent(void);

static int cmp_capture_stat();
static void report_capture_stat(char *mmap_buf);

static void que_timeout();
static void callback_signal_que(int sig_no);

#ifdef SIGINFO
static void signal_report_stat(void);
static void report_stat_siginfo(int sig_no);
#endif

#ifdef INC_PT_PKT_CNT
static void print_packet(const unsigned char *h);
#endif

static void print_cfg_par(QUE_ID shm_start_addr,int que_num);
static void print_itf_capture_par(PAR_ITF_CAPTURE *par_itf_capture_id);

static void printf_ether_hdr(unsigned char *packet);
static void printf_ip_hdr(unsigned char *packet);
static void print_packet(const unsigned char *h);
int filter_pcap_pkt(struct singleton_t *p,unsigned long eth_ip);
unsigned long Get_Manage_Ipsaddr(char *manage_nic);

static int raw_net_socket1();
static void     send_arp_block_pkt1(int sockfd, UDP_CLOSEINFO_ID udp_close_info_id);
static void send_icmp_host_unreachable1(int sockfd, UDP_CLOSEINFO_ID udp_close_info_id);



/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void capture_process(QUE_ID cfg_que_id,PAR_ITF_CAPTURE_ID par_itf_capture_id)
{ 
    register QUE_ID cfg_que_addr = NULL;
    register NIC_QUE_INFO_ID nic_que_info_id = NULL;
    int que_num = par_itf_capture_id->que_num;  //que_num = 2
    unsigned int capture_ivl_time = par_itf_capture_id->deposit_ivl_sec;
    unsigned int que_timeout_time;

    int log_pri = LOG_DEBUG;	
	
    char ebuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr hdr;                 
    char *device;
   /*2008/08/01*/
    struct timeval tv;
    struct timezone tz;
   /*2008/08/01*/
    register int now_que_no = 0;	    /*队列序号*/
    register int now_write_loc = 0;  /*Block 序号*/
    int semid = DEF_SEM_ID_VAL;
    int empty_semid = DEF_SEM_ID_VAL;
    int full_semid = DEF_SEM_ID_VAL;

    unsigned long pkt_cp_size = 0;
    unsigned long manage_nic_saddr =0;
    int que_blk_num = 0;
    int que_blk_size = 0;
    register char *shm_addr = NULL;
    register char *shm_cp_addr = NULL;

    char capture_start_time[TIME_STR_SIZE];    

    int stat_fd = DEF_FILE_DES_VAL;
    char stat_file_path[MAX_FILE_PATH_SIZE];

	


	pthread_t  policy_analysis_thread;
	pthread_t first_block_thread;
	pthread_t second_block_thread;
	pthread_t block_queue_update_thread;


	pthread_t udp_block_analysis_thread;

	pthread_t alarm_thread;
	
	void *     thread_result; 
	
#ifdef INC_FIRST_DROPS
    struct pcap_stat stats;
#endif

#ifdef INC_FIRST_DROPS
    int stat_status = FIRST_STAT;
#endif
    char *mmap_buf = NULL;

#ifdef INC_PT_PKT
    ETHER_HDR *eth_hdr;
    IP_HDR *ip_hdr;
#endif	

#ifdef INC_PCAP_FIND_DEVICE
    register char *device;
#endif

#ifdef INC_PRINT_VERSION
    int major_version;
    int minor_version;
#endif

    struct singleton_t pcap_pkt_addr;
    pcap_handler callback = copy_pcap_pkt;
    int inpkts;
    time_t upd_time, cur_time;

#ifdef _DEBUG
    print_itf_capture_par(par_itf_capture_id);
#endif	

    signal(SIGKILL, capture_stop_signal_handler);
    signal(SIGTERM, capture_stop_signal_handler);

    g_flow_switch = par_itf_capture_id->flow_switch;

#ifdef INC_FLOW_STAT_ANALYSIS_MODEL
    if (ON == g_flow_switch){
        g_ip_type = htons(2048);
        g_arp_type = htons(2054);
        g_revarp_type = htons(32821);
        if (-1 == (g_sys_msg_que_id = get_sys_msg_que(STAT_MSG_QUE_KEY)))
        {
            error("[Err]Get sys mag que id fail.\n");
            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get sys mag que id fail!");
            exit(EXIT_FAILURE);
        }
    }
#endif

    if ((nic_que_info_id = (NIC_QUE_INFO_ID)malloc((NIC_QUE_INFO_SIZE)*que_num)) == NULL)
    {
        error("[Err]Malloc for nic que info Fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Malloc for nic que info Fail!");
        exit(EXIT_FAILURE);
    }

    cfg_que_addr = cfg_que_id + (par_itf_capture_id->nic_no)*que_num;
    if (ERR == get_per_nic_shm(que_num,cfg_que_addr,nic_que_info_id))
    {
        error("[Err]Get shm que Err.\n");
	 FREE(nic_que_info_id);
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get shm que Err!");
        exit(EXIT_FAILURE);
    }
    
    INFO("[Info]Get Que Shm OK.");
 
    if (ERR == get_per_nic_sem(que_num,cfg_que_addr,nic_que_info_id))
    {
        error("[Err]Get Que Sem Err.\n");
        FREE(nic_que_info_id);
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get Que Sem Err.");
        exit(EXIT_FAILURE);
    }

    INFO("[Info]Get Que Sem OK.");

#ifdef INC_REG_RES
    (void)reg_capture_res(que_num,nic_que_info_id);
#endif

    INFO("[Info]Capture Init.");

#ifdef _DEBUG
    print_cfg_par(cfg_que_addr,que_num);
#endif	

#ifdef SIGINFO
    signal_report_stat();
#endif
    INFO("[Info]BEGIN CAPTURE......");
#ifdef INC_PCAP_FIND_DEVICE
    device = pcap_lookupdev(ebuf);	
    if (NULL == device)
    {
        error("[Err]No sutiable device.");
        FREE(nic_que_info_id);
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"No sutiable device.");
        exit(EXIT_FAILURE);
    }
   
    DEBUG("device = %s\n",device);
   manage_nic_saddr = Get_Manage_Ipsaddr(par_itf_capture_id->manage_nic_name);
  
#endif

    init_global_var();

    memset(&capture_start_time,0x00,TIME_STR_SIZE);
    (void)get_now_time(capture_start_time);

    if (ON == par_itf_capture_id->func_switch.iStatSwitch)
    {
        sprintf(stat_file_path,"%s/%s%s",PKT_STAT_FILE_DIR,par_itf_capture_id->nic_name,\
		    CAPTURE_PKT_STAT_FILE_NAME);
        mmap_buf = create_stat_mmap_file(stat_file_path,&stat_fd);
        if (NULL == mmap_buf)
        {
            error("[Err]Mmap stat file fail.\n");
            FREE(nic_que_info_id);
            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Mmap stat file fail.");
            exit(EXIT_FAILURE);
        }
    }
   /*很重要2009 04 29*/
    pcap_pkt_addr.hdr = &hdr;

    que_timeout_time = (capture_ivl_time < DEF_QUE_TIMEOUT_TIME ? DEF_QUE_TIMEOUT_TIME:capture_ivl_time);
	
    signal(SIGALRM,callback_signal_que);
    //printf("Nic device = %s \n",par_itf_capture_id->nic_name);
    if (NULL == (pd = pcap_open_live(par_itf_capture_id->nic_name,MAX_CAP_PKT_SIZE, 1, CAP_READ_TIMEOUT, ebuf)))
    {
        error("[Err]Open Nic %s fail.\n",par_itf_capture_id->nic_name);
        FREE(nic_que_info_id);
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Open Nic fail!");
        exit(EXIT_FAILURE);
    }

#ifdef INC_PRINT_VERSION
     major_version = pcap_major_version(pd);
    minor_version = pcap_minor_version(pd);
    DEBUG("major version = %d\n",major_version);
    DEBUG("minor version = %d\n",minor_version);
    
#endif
//	sleep(10);
	if(par_itf_capture_id->res_key > 0 && (g_res_list_id= (PROTECTED_RESOURCE_ID)get_shm_addr(par_itf_capture_id->res_key, SHM_RDONLY)) == NULL)
	{
		error("[Err]get shm res queque shmid fail.\n");
	}
	g_res_num = par_itf_capture_id->res_num;


	if(par_itf_capture_id->user_key > 0 && (g_user_list_id= (USR_LIST_MEM_ID)get_shm_addr(par_itf_capture_id->user_key, SHM_RDONLY)) == NULL)
	{
		error("[Err]get shm user queque shmid fail.\n");
	}
	g_user_num = par_itf_capture_id->user_num;

	if(par_itf_capture_id->authorize_key > 0 && (g_auth_list_id= (AUTHORIZE_ACCESS_NETWORK_ID)get_shm_addr(par_itf_capture_id->authorize_key, SHM_RDONLY)) == NULL)
	{
		error("[Err]get shm auth queque shmid fail.\n");
	}
	g_auth_num = par_itf_capture_id->authorize_num;


///SEM
	if((m_block_queue_semid = Get_Sem_Queque_SemID(par_itf_capture_id->tcp_block_queue_sem_key, 0))==-1)
	{
		error("[Err]get sem block_sem queque semid fail.\n");
		FREE(nic_que_info_id);
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"get sem block_sem queque semid fail.");
		exit(EXIT_FAILURE);			
	}
	

///TCP_CLOSE_QUEUE1

	if((g_tcp_close_queue1_ptr = (TCP_CLOSEINFO_ID)get_shm_addr(par_itf_capture_id->tcp_block_queue1_shm_key, 0)) == NULL)
	{
		error("[Err]get shm tcp_close1 queque shmid fail.\n");
		FREE(nic_que_info_id);
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"get shm ip queque shmid fail.");
		exit(EXIT_FAILURE);	
	}

	memset(&g_tcp_close_queue1_info, 0x00, TCP_CLOSE_INFO_SIZE);
	g_tcp_close_queue1_info.total_num = par_itf_capture_id->tcp_block_queue1_num;


///TCP_CLOSE_QUEUE2_CHECK

	if((g_tcp_close_queue2_check_ptr = (TCP_CLOSEINFO_ID)get_shm_addr(par_itf_capture_id->tcp_block_queue2_check_shm_key, 0)) == NULL)
	{
		error("[Err]get shm tcp_close2_check queque shmid fail.\n");
		FREE(nic_que_info_id);
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"get shm ip queque shmid fail.");
		exit(EXIT_FAILURE);	
	}

	memset(&g_tcp_close_queue2_check_info, 0x00, TCP_CLOSE_INFO_SIZE);
	g_tcp_close_queue2_check_info.total_num = par_itf_capture_id->tcp_block_queue2_check_num;

///TCP_CLOSE_QUEUE2

	if((g_tcp_close_queue2_ptr = (TCP_CLOSEINFO_ID)get_shm_addr(par_itf_capture_id->tcp_block_queue2_shm_key, 0)) == NULL)
	{
		error("[Err]get shm  tcp_close2 queque shmid fail.\n");
		FREE(nic_que_info_id);
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"get shm ip queque shmid fail.");
		exit(EXIT_FAILURE);	
	}	
	memset(&g_tcp_close_queue2_info, 0x00, TCP_CLOSE_INFO_SIZE);
	g_tcp_close_queue2_info.total_num = par_itf_capture_id->tcp_block_queue2_num;
	
///IP_QUEUE
	if((g_ip_block_queue_id = (IP_PACKET_ID)get_shm_addr(par_itf_capture_id->ip_block_queue_shm_key, 0)) == NULL)
	{
		error("[Err]get shm ip queue shmid fail.\n");
		FREE(nic_que_info_id);
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"get shm ip queque shmid fail.");
		exit(EXIT_FAILURE);
	}
	memset(&g_ip_block_queue_info, 0x00, BLOCK_QUEUE_INFO_SIZE);
	g_ip_block_queue_info.total_num = par_itf_capture_id->ip_queue_num;
	
///UDP_QUEUE
	if((g_udp_close_queue_ptr = (UDP_CLOSEINFO_ID)calloc(UDP_CLOSEINFO_SIZE, UDP_BLOCK_QUEUE_LEN)) == NULL)
	{
		error("[Err]ALLOC UDP queue shmid fail.\n");
		FREE(nic_que_info_id);
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"ALLOC UDP queue shmid fail.");
		exit(EXIT_FAILURE);
	}
	memset(&g_udp_block_queue_info, 0x00, UDP_BLOCK_QUEUE_INFO_SIZE);
	g_udp_block_queue_info.total_num = UDP_BLOCK_QUEUE_LEN;


///BLOCKLOG_QUEUE
	if((g_blocklog_info_ptr = (BLOCKLOGINFO_ID)calloc(BLOCKLOGINFO_SIZE, BLOCKLOG_QUEUE_LEN)) == NULL)
	{
		error("[Err]ALLOC BLOCKLOG queue shmid fail.\n");
		FREE(nic_que_info_id);
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"ALLOC BLOCKLOG queue shmid fail.");
		exit(EXIT_FAILURE);
	}
	memset(&g_blocklog_queue_info, 0x00, BLOCKLOG_QUEUE_INFO_SIZE);
	g_blocklog_queue_info.total_num = BLOCKLOG_QUEUE_LEN;

	
	read_http_warning();
   
	/*end of write 2009 04 30*/
	upd_time = TIME_GET();


//	sleep(10);


	if(generate_block_policy(par_itf_capture_id) == ERR)
	{
		exit(EXIT_FAILURE);
	}
	

	if(init_block_protected_res() == -1)
	{
		exit(EXIT_FAILURE);
	}

	

	if(pthread_create(&policy_analysis_thread, NULL, policy_analysis_handler, NULL) != 0)
	{
		exit(EXIT_FAILURE);
	}
	if(pthread_create(&first_block_thread, NULL, first_block_handler, NULL) != 0)
	{
		exit(EXIT_FAILURE);
	}
	if(pthread_create(&second_block_thread, NULL, second_block_handler, NULL) != 0)
	{
		exit(EXIT_FAILURE);
	}
	
	if(pthread_create(&block_queue_update_thread, NULL, block_queue_update_handler, NULL) != 0)
	{
		exit(EXIT_FAILURE);
	}

	if(pthread_create(&udp_block_analysis_thread, NULL, udp_block_analysis_handler, NULL) != 0)
	{
		exit(EXIT_FAILURE);
	}
	
	if(pthread_create(&alarm_thread, NULL, blocklog_handler, NULL) != 0)
	{
		exit(EXIT_FAILURE);
	}

    while (g_can_capture)
    {
	 inpkts = pcap_dispatch(pd, 1, callback, (u_char *)&pcap_pkt_addr);
	 if((-1 == filter_pcap_pkt(&pcap_pkt_addr,manage_nic_saddr)) || (inpkts <= 0))
	 	continue;
        
        if (ON == par_itf_capture_id->func_switch.iStatSwitch)
        {      
	    cur_time = TIME_GET();
	    if (cur_time - upd_time > capture_ivl_time) 
	    {
               upd_time = cur_time;
               report_capture_stat(mmap_buf);
            }
         }
        
         if ((UNLOCK_SHM_CMD == g_capture_cmd)\
               &&(SHM_BLOCK == g_block_flag)\
               &&(now_write_loc > 0))
         {
             set_blk_num(shm_addr,now_write_loc);
         #ifdef INC_FULL_FLAG
             set_que_status(shm_addr,QUE_FULL);
         #endif
             sem_unlock(semid);
             sem_unlock(full_semid);
             g_block_flag = SHM_NOT_BLOCK;

             now_write_loc = 0;
             ++now_que_no;
             if (now_que_no >= que_num)
                 now_que_no = 0;

             g_capture_cmd = LOCK_SHM_CMD;
         }
	
        while (SAIL_TRUE)//////////////
        {
            if (SHM_NOT_BLOCK == g_block_flag)
            {
               que_blk_num = (cfg_que_addr + now_que_no)->iQueBlkNum;
	        que_blk_size = (cfg_que_addr + now_que_no)->iQueBlkSize;

	        semid = (nic_que_info_id + now_que_no)->semid;
		 empty_semid = (nic_que_info_id + now_que_no)->empty_semid;
		 full_semid = (nic_que_info_id + now_que_no)->full_semid;
		  
               shm_addr = (nic_que_info_id + now_que_no)->shm_addr;

		 sem_lock(empty_semid);
               sem_lock(semid);
                g_block_flag = SHM_BLOCK;
            
            #ifdef INC_FULL_FLAG
              //  DEBUG("ok");
                if (SAIL_TRUE == is_full_que(shm_addr))///////////++++
                {
                    sem_unlock(semid);
                    sem_unlock(empty_semid);
                    g_block_flag = SHM_NOT_BLOCK;

                    ++g_pkt_stat.wait_times;

                #ifdef INC_PRINT_WAIT_INFO
                    fprintf(stderr, "%Ld time wait\n",g_pkt_stat.wait_times);
                    DEBUG("Write Que> Write File  que buffer overflow\n");
                #endif
			//add 2009 11 23
                    now_write_loc = 0;
			++now_que_no;
			if (now_que_no >= que_num)
	        	{
	            		now_que_no = 0;
	        	}
                    continue;  //add 2009 11 23				
                }
            #endif

                alarm(que_timeout_time);
		g_capture_cmd = LOCK_SHM_CMD;
            }
			
	    if (now_write_loc >= que_blk_num )
            {
                set_blk_num(shm_addr,now_write_loc);
            #ifdef INC_FULL_FLAG
                set_que_status(shm_addr,QUE_FULL);
            #endif

                sem_unlock(semid);
                sem_unlock(full_semid);
                g_block_flag = SHM_NOT_BLOCK;

                now_write_loc = 0;
		++now_que_no;
		if (now_que_no >= que_num)
	        {
	            now_que_no = 0;
	        }
		  
                alarm(0);
		g_capture_cmd = LOCK_SHM_CMD;

	        continue;
            }/////
        
             /*next packet*/
             if (hdr.caplen < 54)
             {
                 if (ON == par_itf_capture_id->func_switch.iStatSwitch)
                 {
                     ++g_pkt_stat.us_recv;
                     g_pkt_stat.us_recv_size += pkt_cp_size;

                 #ifdef INC_FIRST_DROPS
                     if (FIRST_STAT == stat_status)
                     {
                         if (pcap_stats(pd, &stats) >= 0)
                         {
                             g_pkt_stat.ps_first_drop = stats.ps_drop;
                         }

                         stat_status = OTR_STAT;
                     }
                 #endif
                 }

   //          ++now_write_loc;  //2009 11 23
                 break;
             }

             pkt_cp_size = (hdr.caplen > que_blk_size?que_blk_size:hdr.caplen);
	     shm_cp_addr = get_blk_addr(shm_addr,now_write_loc,que_blk_size);
	    /*2008/08/01*/
#if 0
             gettimeofday (&tv , &tz);
	     hdr.ts = tv;
#endif
	     /*2008/08/01*/
	     *(struct pcap_pkthdr *)shm_cp_addr = hdr;
	     //memcpy((void *)shm_cp_addr,(void *)&hdr,BLK_HDR_SIZE);
	     memcpy((void *)(shm_cp_addr+BLK_HDR_SIZE),(void *)(pcap_pkt_addr.pkt),pkt_cp_size);
             
            if (ON == par_itf_capture_id->func_switch.iStatSwitch)
            {
                ++g_pkt_stat.us_recv;
                g_pkt_stat.us_recv_size += pkt_cp_size;

	     #ifdef INC_FIRST_DROPS
                if (FIRST_STAT == stat_status)
                {
                    if (pcap_stats(pd, &stats) >= 0)
                    {
                        g_pkt_stat.ps_first_drop = stats.ps_drop;
                    }

                    stat_status = OTR_STAT;
                }
	     #endif
            }

	     ++now_write_loc;
	     break;
        }
    	}

    FREE(nic_que_info_id);
    if (ON == par_itf_capture_id->func_switch.iStatSwitch)
    {
        if (NULL != mmap_buf)
            munmap_stat_file(stat_fd,(void *)mmap_buf);
    }
    
    pcap_close(pd);

	
	pthread_join(policy_analysis_thread,&thread_result);
	pthread_join(first_block_thread,&thread_result);
	pthread_join(second_block_thread,&thread_result);
	pthread_join(block_queue_update_thread,&thread_result);
	
	close(g_nRawSocket1);
	close(g_nRawSocket2);
	
    pd = NULL;
}





/*初始化保护资源列表*/
int init_block_protected_res()
{
	int i;
	int shm_id =0;
	unsigned char chk_flag = 0;
	PROTECTED_RESOURCE_ID protected_res_id = NULL;
	
	i = 0;
	while(i < g_tcp_block_policy_list.block_policy_num)
	{
		protected_res_id = &(g_tcp_block_policy_list.block_policy_item_id[i].res);
		if(get_block_protected_res_shm(protected_res_id) == -1)
		{
			return -1;
		}
		i++;
	}
	
	i = 0;
	while(i < g_udp_block_policy_list.block_policy_num)
	{
		protected_res_id = &(g_udp_block_policy_list.block_policy_item_id[i].res);
		if(get_block_protected_res_shm(protected_res_id) == -1)
		{
			return -1;
		}
		i++;
	}
	return 0;
}

int get_block_protected_res_shm(PROTECTED_RESOURCE_ID protected_res_id)
{
   	switch(protected_res_id->use_port_flag)
	{
		case SPORT:///
  			switch(protected_res_id->sip.src_port_express)
			{
					case INTERVAL_PORT:
					if((protected_res_id->sip.port_id = (INTERVAL_PORT_ID)get_shm_addr(protected_res_id->sip.interval_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
				case CONTINUE_PORT:
					if((protected_res_id->sip.continue_port_id = (CONTINUE_PORT_ID)get_shm_addr(protected_res_id->sip.continue_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
					
				case CONTINUE_INTERVAL_PORT:
					if((protected_res_id->sip.port_id = (INTERVAL_PORT_ID)get_shm_addr(protected_res_id->sip.interval_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					if((protected_res_id->sip.continue_port_id = (CONTINUE_PORT_ID)get_shm_addr(protected_res_id->sip.continue_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
				}
				break;
		case DPORT:///
			switch(protected_res_id->dip.dst_port_express)
			{
					case INTERVAL_PORT:
					if((protected_res_id->dip.port_id = (INTERVAL_PORT_ID)get_shm_addr(protected_res_id->dip.interval_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
				case CONTINUE_PORT:
					if((protected_res_id->dip.continue_port_id = (CONTINUE_PORT_ID)get_shm_addr(protected_res_id->dip.continue_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
					
				case CONTINUE_INTERVAL_PORT:
					if((protected_res_id->dip.port_id = (INTERVAL_PORT_ID)get_shm_addr(protected_res_id->dip.interval_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					if((protected_res_id->dip.continue_port_id = (CONTINUE_PORT_ID)get_shm_addr(protected_res_id->dip.continue_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
  			}
			break;
		case SPORT_DPORT:///
			switch(protected_res_id->sip.src_port_express)
			{
				case INTERVAL_PORT:
				if((protected_res_id->sip.port_id = (INTERVAL_PORT_ID)get_shm_addr(protected_res_id->sip.interval_port_shm_key, SHM_RDONLY)) == NULL)
				{
					return -1;
				}
				break;
				case CONTINUE_PORT:
					if((protected_res_id->sip.continue_port_id = (CONTINUE_PORT_ID)get_shm_addr(protected_res_id->sip.continue_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
				case CONTINUE_INTERVAL_PORT:
					if((protected_res_id->sip.port_id = (INTERVAL_PORT_ID)get_shm_addr(protected_res_id->sip.interval_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					if((protected_res_id->sip.continue_port_id = (CONTINUE_PORT_ID)get_shm_addr(protected_res_id->sip.continue_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
			}
			switch(protected_res_id->dip.dst_port_express)
			{
				case INTERVAL_PORT:
					if((protected_res_id->dip.port_id = (INTERVAL_PORT_ID)get_shm_addr(protected_res_id->dip.interval_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
				case CONTINUE_PORT:
					if((protected_res_id->dip.continue_port_id = (CONTINUE_PORT_ID)get_shm_addr(protected_res_id->dip.continue_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
					
				case CONTINUE_INTERVAL_PORT:
					if((protected_res_id->dip.port_id = (INTERVAL_PORT_ID)get_shm_addr(protected_res_id->dip.interval_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					if((protected_res_id->dip.continue_port_id = (CONTINUE_PORT_ID)get_shm_addr(protected_res_id->dip.continue_port_shm_key, SHM_RDONLY)) == NULL)
					{
						return -1;
					}
					break;
			}
			break;
	}
	return 0;
}

void* get_shm_addr(int shmid,  int shmflg)
{
	void* shm_addr;
	
	if((shmid = shmget(shmid,0,IPC_CREAT))<0)
	{
		return NULL;

	}
	if((shm_addr = shmat(shmid,NULL,shmflg))==NULL)
	{
		return NULL;
	}
	return shm_addr;
}
void policy_analysis_handler()
{
	unsigned int i;
	unsigned int j;
	unsigned int read_index;
	unsigned int src_index;
	unsigned int dst_index;
	unsigned int update_index;
	IP_PACKET ip_packet;

	
	while(1)
	{
		if(queue_sem_lock(m_ip_block_queue_semid) == 0)
		{
			if(g_ip_block_queue_info.exist_num <= 0)
			{
				while(queue_sem_unlock(m_ip_block_queue_semid) == -1)
				{
					usleep(USLEEP_TIME);
				}
				usleep(USLEEP_TIME);
				continue;
			}
			ip_packet = g_ip_block_queue_id[g_ip_block_queue_info.read_index];
			g_ip_block_queue_info.exist_num--;
			g_ip_block_queue_info.read_index = (++g_ip_block_queue_info.read_index)%g_ip_block_queue_info.total_num;
			
			while(queue_sem_unlock(m_ip_block_queue_semid) == -1)
			{
				usleep(USLEEP_TIME);
			}


			while(1)
			{
				if(queue_sem_lock(m_tcp_close_queue2_check_semid) == 0)
				{
					for(i = g_tcp_close_queue2_check_info.read_index; i<g_tcp_close_queue2_check_info.read_index + g_tcp_close_queue2_check_info.exist_num; i++)
					{
						read_index = i%g_tcp_close_queue2_check_info.total_num;
						if((g_tcp_close_queue2_check_ptr[read_index].dst_ip == ip_packet.dst_ip&&\
							g_tcp_close_queue2_check_ptr[read_index].src_ip == ip_packet.src_ip&&\
							g_tcp_close_queue2_check_ptr[read_index].dst_port == ip_packet.dst_port&&\
							g_tcp_close_queue2_check_ptr[read_index].src_port == ip_packet.src_port)||\
							
							(g_tcp_close_queue2_check_ptr[read_index].dst_ip == ip_packet.src_ip&&\
							g_tcp_close_queue2_check_ptr[read_index].src_ip == ip_packet.dst_ip&&\
							g_tcp_close_queue2_check_ptr[read_index].dst_port == ip_packet.src_port&&\
							g_tcp_close_queue2_check_ptr[read_index].src_port == ip_packet.dst_port))
						{
							//printf("macth in g_tcp_close_queue2_check\n");
							for(j = i; j<g_tcp_close_queue2_check_info.read_index + g_tcp_close_queue2_check_info.exist_num-1; j++)
							{
								dst_index = j%g_tcp_close_queue2_check_info.total_num;
								src_index = (j+1)%g_tcp_close_queue2_check_info.total_num;
								memcpy(g_tcp_close_queue2_check_ptr+dst_index, g_tcp_close_queue2_check_ptr+src_index, BLOCK_QUEUE_INFO_SIZE);
							}
							g_tcp_close_queue2_check_info.exist_num--;
							//while(queue_sem_unlock(m_tcp_close_queue2_check_semid) == -1)
							//{
							//	usleep(USLEEP_TIME);
							//}
							while(1)
							{
								if(queue_sem_lock(m_tcp_close_queue2_semid) == 0)
								{
									g_tcp_close_queue2_ptr[g_tcp_close_queue2_info.write_index].src_ip  = ip_packet.src_ip;
									g_tcp_close_queue2_ptr[g_tcp_close_queue2_info.write_index].dst_ip = ip_packet.dst_ip;
									g_tcp_close_queue2_ptr[g_tcp_close_queue2_info.write_index].src_port = ip_packet.src_port;
									g_tcp_close_queue2_ptr[g_tcp_close_queue2_info.write_index].dst_port = ip_packet.dst_port;
									g_tcp_close_queue2_ptr[g_tcp_close_queue2_info.write_index].next_seqno = ip_packet.next_seqno;
									g_tcp_close_queue2_ptr[g_tcp_close_queue2_info.write_index].ackno = ip_packet.ackno;
									g_tcp_close_queue2_ptr[g_tcp_close_queue2_info.write_index].ts = ip_packet.ts;
									g_tcp_close_queue2_info.write_index = (++g_tcp_close_queue2_info.write_index)%g_tcp_close_queue2_info.total_num;
									if(g_tcp_close_queue2_info.exist_num >= g_tcp_close_queue2_info.total_num)
									{
										g_tcp_close_queue2_info.read_index = (++g_tcp_close_queue2_info.read_index)%g_tcp_close_queue2_info.total_num;
									}else
									{
										g_tcp_close_queue2_info.exist_num++;
									}
									while(queue_sem_unlock(m_tcp_close_queue2_semid) == -1)
									{
										usleep(USLEEP_TIME);
									}
									break;
								}else
								{
									usleep(USLEEP_TIME);
								}
							}
						}
					}
					while(queue_sem_unlock(m_tcp_close_queue2_check_semid) == -1)
					{
						usleep(USLEEP_TIME);
					}
					if(i == g_tcp_close_queue2_check_info.read_index + g_tcp_close_queue2_check_info.exist_num)
					{
						judge_in_block_policy(&ip_packet);
					}
					break;
				}else
				{
					usleep(USLEEP_TIME);
				}
			}
			
		}else
		{
			usleep(USLEEP_TIME);
		}
	}

}

void first_block_handler()
{
	TCP_CLOSEINFO  tcp_close_info;
	unsigned long nextseq;
	g_nRawSocket1 = RawSocket();
	if(g_nRawSocket1 == -1)
	{
		DEBUG("Thread_Snd_TCPClose::create raw socket fail");
		return;
	}

	while(1)
	{
		if(queue_sem_lock(m_tcp_close_queue1_semid) == 0)
		{
			if(g_tcp_close_queue1_info.exist_num <=0)
			{
				while(queue_sem_unlock(m_tcp_close_queue1_semid) == -1)
				{
					usleep(USLEEP_TIME);
				}
				usleep(USLEEP_TIME);
				continue;
			}
		
			tcp_close_info = g_tcp_close_queue1_ptr[g_tcp_close_queue1_info.read_index];
			g_tcp_close_queue1_info.exist_num--;
			g_tcp_close_queue1_info.read_index = (++g_tcp_close_queue1_info.read_index)%g_tcp_close_queue1_info.total_num;

			while(queue_sem_unlock(m_tcp_close_queue1_semid) == -1)
			{
				usleep(USLEEP_TIME);
			}
			if (ntohs(tcp_close_info.src_port) != 80 && ntohs(tcp_close_info.dst_port) != 80 && ntohs(tcp_close_info.src_port) != 8080 && ntohs(tcp_close_info.dst_port) != 8080)
			{
				SendCloseTcp(g_nRawSocket1,tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.src_ip, tcp_close_info.src_port,tcp_close_info.ackno, tcp_close_info.next_seqno);
				SendCloseTcp(g_nRawSocket1,tcp_close_info.src_ip, tcp_close_info.src_port, tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.next_seqno, tcp_close_info.ackno);
//				printf("SendCloseTcp in first_block_handler no http\n");
			}else
			{
				if (ntohs(tcp_close_info.dst_port) == 80 || ntohs(tcp_close_info.dst_port) == 8080)
				{
					SendCloseTcp(g_nRawSocket1,tcp_close_info.src_ip, tcp_close_info.src_port, tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.next_seqno, tcp_close_info.ackno);
					SendAckTcp(g_nRawSocket1,tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.src_ip, tcp_close_info.src_port,tcp_close_info.ackno, tcp_close_info.next_seqno);
					usleep(USLEEP_TIME);
					nextseq = htonl(ntohl(tcp_close_info.next_seqno) + strlen(g_HttpWarning));
					SendCloseTcp(g_nRawSocket1,tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.src_ip, tcp_close_info.src_port,nextseq, tcp_close_info.next_seqno);
//					printf("SendCloseTcp in first_block_handler http\n");					
				}
				else
				{
					SendCloseTcp(g_nRawSocket1,tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.src_ip, tcp_close_info.src_port,tcp_close_info.ackno, tcp_close_info.next_seqno);
					SendAckTcp(g_nRawSocket1,tcp_close_info.src_ip, tcp_close_info.src_port, tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.next_seqno, tcp_close_info.ackno);
					usleep(USLEEP_TIME);
					nextseq = htonl(ntohl(tcp_close_info.next_seqno) + strlen(g_HttpWarning));
					SendCloseTcp(g_nRawSocket1,tcp_close_info.src_ip, tcp_close_info.src_port, tcp_close_info.dst_ip,tcp_close_info.dst_port, nextseq, tcp_close_info.ackno);
//					printf("SendCloseTcp in first_block_handler http\n");						
				}
			}

			write_into_second_block_check_queue(&tcp_close_info);
		}else
		{
			usleep(USLEEP_TIME);
		}
	}
}

void second_block_handler()
{
	TCP_CLOSEINFO  tcp_close_info;
	unsigned long nextseq;
	g_nRawSocket2 = RawSocket();
	if(g_nRawSocket2 == -1)
	{
		DEBUG("Thread_Snd_TCPClose::create raw socket fail");
		return;
	}
	while(1)
	{
		if(queue_sem_lock(m_tcp_close_queue2_semid) == 0)
		{
			if(g_tcp_close_queue2_info.exist_num <= 0)
			{
				while(queue_sem_unlock(m_tcp_close_queue2_semid) == -1)
				{
					usleep(USLEEP_TIME);
				}
				usleep(USLEEP_TIME);
				continue;
			}
		
			tcp_close_info = g_tcp_close_queue2_ptr[g_tcp_close_queue2_info.read_index];
			g_tcp_close_queue2_info.exist_num--;
			g_tcp_close_queue2_info.read_index = (++g_tcp_close_queue2_info.read_index)%g_tcp_close_queue2_info.total_num;

			while(queue_sem_unlock(m_tcp_close_queue2_semid) == -1)
			{
				usleep(USLEEP_TIME);
			}
			if (ntohs(tcp_close_info.src_port) != 80 && ntohs(tcp_close_info.dst_port) != 80 && ntohs(tcp_close_info.src_port) != 8080 && ntohs(tcp_close_info.dst_port) != 8080)
			{
				SendCloseTcp(g_nRawSocket1,tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.src_ip, tcp_close_info.src_port,tcp_close_info.ackno, tcp_close_info.next_seqno);
				SendCloseTcp(g_nRawSocket1,tcp_close_info.src_ip, tcp_close_info.src_port, tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.next_seqno, tcp_close_info.ackno);
			}else
			{
				if (ntohs(tcp_close_info.dst_port) == 80 || ntohs(tcp_close_info.dst_port) == 8080)
				{
					SendCloseTcp(g_nRawSocket1,tcp_close_info.src_ip, tcp_close_info.src_port, tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.next_seqno, tcp_close_info.ackno);
					SendAckTcp(g_nRawSocket1,tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.src_ip, tcp_close_info.src_port,tcp_close_info.ackno, tcp_close_info.next_seqno);
					usleep(USLEEP_TIME);
					nextseq = htonl(ntohl(tcp_close_info.next_seqno) + strlen(g_HttpWarning));
					SendCloseTcp(g_nRawSocket1,tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.src_ip, tcp_close_info.src_port,nextseq, tcp_close_info.next_seqno);
				}
				else
				{
					SendCloseTcp(g_nRawSocket1,tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.src_ip, tcp_close_info.src_port,tcp_close_info.ackno, tcp_close_info.next_seqno);
					SendAckTcp(g_nRawSocket1,tcp_close_info.src_ip, tcp_close_info.src_port, tcp_close_info.dst_ip,tcp_close_info.dst_port, tcp_close_info.next_seqno, tcp_close_info.ackno);
					usleep(USLEEP_TIME);
					nextseq = htonl(ntohl(tcp_close_info.next_seqno) + strlen(g_HttpWarning));
					SendCloseTcp(g_nRawSocket1,tcp_close_info.src_ip, tcp_close_info.src_port, tcp_close_info.dst_ip,tcp_close_info.dst_port, nextseq, tcp_close_info.ackno);
				}
			}
		}else
		{
			usleep(USLEEP_TIME);
		}
	}
}



void block_queue_update_handler()
{
	unsigned int i;
	unsigned int index;
	unsigned int start_index;
	unsigned int src_index;
	unsigned int dst_index;
	
	struct timeval tv;
	unsigned int offset_num = 0;
	unsigned int* offset;
	char interval_flag = 0;
	unsigned int interval_num = 0;
	offset = calloc(sizeof(unsigned int), g_tcp_close_queue2_check_info.total_num*3);

	while(1)
	{
		if(queue_sem_lock(m_tcp_close_queue2_check_semid) == 0)
		{
			if(g_tcp_close_queue2_check_info.exist_num <=0)
			{
				while(queue_sem_unlock(m_tcp_close_queue2_check_semid) == -1)
				{
					usleep(USLEEP_TIME);
				}
				usleep(USLEEP_TIME);
				continue;
			}
			gettimeofday(&tv, NULL);
			offset_num = 0;
			interval_flag = 0;
			interval_num = 0;
			for(i = g_tcp_close_queue2_check_info.read_index; i < g_tcp_close_queue2_check_info.read_index+g_tcp_close_queue2_check_info.exist_num; i++)
			{
				index = i%g_tcp_close_queue2_check_info.total_num;
				if(abs(g_tcp_close_queue2_check_ptr[index].ts.tv_sec - tv.tv_sec) > INTERVAL_TIME)
				{
					if(interval_flag == 0)
					{
						if(interval_num != 0)
						{
							offset[offset_num*3+1] = index;
							offset[offset_num*3+2] = interval_num;
							offset_num++;
						}
						interval_flag = 1;
					}
					interval_num++;
				}else
				{
					if(interval_flag == 1)
					{
						offset[offset_num*3] = index;
						
						interval_flag = 0;
					}
				}
			}
			index = (i-1)%g_tcp_close_queue2_check_info.total_num;
			if(interval_flag == 0 && interval_num != 0)
			{
				offset[offset_num*3+1] = index;
				offset[offset_num*3+2] = interval_num;
				offset_num++;
			}

			g_tcp_close_queue2_check_info.exist_num-= interval_num;
			g_tcp_close_queue2_check_info.write_index = (g_tcp_close_queue2_check_info.write_index - interval_num + g_tcp_close_queue2_check_info.total_num)%g_tcp_close_queue2_check_info.total_num;
			
			for(i = 0; i < offset_num; i++)
			{
				start_index = offset[i*3];
				while(start_index != offset[i*3+1])
				{
					src_index = start_index;
					dst_index = (src_index - offset[i*3+2] +g_tcp_close_queue2_check_info.total_num) % g_tcp_close_queue2_check_info.total_num;
					memcpy(g_tcp_close_queue2_check_ptr+dst_index, g_tcp_close_queue2_check_ptr+src_index, TCP_CLOSE_INFO_SIZE);
					
					start_index = (++start_index)% g_tcp_close_queue2_check_info.total_num;
				}
			}
			while(queue_sem_unlock(m_tcp_close_queue2_check_semid) == -1)
			{
				usleep(USLEEP_TIME);
			}
		}else
		{
			usleep(USLEEP_TIME);
		}
	}
}

void judge_in_block_policy(IP_PACKET_ID ip_packet_id)
{
	unsigned int i;
	
	PROTECTED_RESOURCE_ID protected_res_id = NULL;
	unsigned char hit_direction;

	for(i = 0; i < g_tcp_block_policy_list.block_policy_num; i++)
	{
		protected_res_id = &(g_tcp_block_policy_list.block_policy_item_id[i].res);
		switch(protected_res_id->dispose_object_relation)
		{
			case 1:
				if(res_hit_mode_on_and(protected_res_id, ip_packet_id, &hit_direction) == ERR)
				{
					continue;/*不匹配*/
				}
				break;
			case 2:
				if(res_hit_mode_on_or(protected_res_id, ip_packet_id, &hit_direction) == ERR)
				{
					continue;/*不匹配*/
				}
				break;
			default:
				continue;
		}
		/*匹配*/
		if(auth_user_search(g_tcp_block_policy_list.block_policy_item_id+i, ip_packet_id, hit_direction) == ERR)
		{/*未授权,写一次阻断队列*/
			write_into_first_block_queue(ip_packet_id);
//			if(protected_res_id->unauthorize_event.log_flag)
//			{
				write_blocklog_queue(ip_packet_id, hit_direction);
//			}
			
		}
	}

}

void write_into_udp_block_queue(IP_PACKET_ID ip_packet_id)
{
	if(ip_packet_id == NULL)
	{
		return;
	}

	pthread_mutex_lock(&g_udp_queue_mutex);
	
	g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].src_ip = ip_packet_id->src_ip;
	g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].dst_ip = ip_packet_id->dst_ip;
	g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].src_port = ip_packet_id->src_port;
	g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].dst_port = ip_packet_id->dst_port;


	g_udp_block_queue_info.write_index = (++g_udp_block_queue_info.write_index)%g_udp_block_queue_info.total_num;
	if(g_udp_block_queue_info.exist_num < g_udp_block_queue_info.total_num)
	{
		g_udp_block_queue_info.exist_num++;
	}else
	{
		g_udp_block_queue_info.read_index = (++g_udp_block_queue_info.read_index)%g_udp_block_queue_info.total_num;
	}
	
	pthread_mutex_lock(&g_udp_queue_mutex);

}

void write_into_first_block_queue(IP_PACKET_ID ip_packet_id)
{
	if(ip_packet_id == NULL)
	{
		return;
	}
	while(1)
	{
		if(queue_sem_lock(m_tcp_close_queue1_semid) == 0)
		{
			g_tcp_close_queue1_ptr[g_tcp_close_queue1_info.write_index].src_ip = ip_packet_id->src_ip;
			g_tcp_close_queue1_ptr[g_tcp_close_queue1_info.write_index].dst_ip = ip_packet_id->dst_ip;
			g_tcp_close_queue1_ptr[g_tcp_close_queue1_info.write_index].src_port = ip_packet_id->src_port;
			g_tcp_close_queue1_ptr[g_tcp_close_queue1_info.write_index].dst_port = ip_packet_id->dst_port;
			g_tcp_close_queue1_ptr[g_tcp_close_queue1_info.write_index].next_seqno = ip_packet_id->next_seqno;
			g_tcp_close_queue1_ptr[g_tcp_close_queue1_info.write_index].ackno = ip_packet_id->ackno;
			g_tcp_close_queue1_ptr[g_tcp_close_queue1_info.write_index].ts = ip_packet_id->ts;
			
			g_tcp_close_queue1_info.write_index = (++g_tcp_close_queue1_info.write_index)%g_tcp_close_queue1_info.total_num;
			if(g_tcp_close_queue1_info.exist_num < g_tcp_close_queue1_info.total_num)
			{
				g_tcp_close_queue1_info.exist_num++;
			}else
			{
				g_tcp_close_queue1_info.read_index = (++g_tcp_close_queue1_info.read_index)%g_tcp_close_queue1_info.total_num;
			}
			while(queue_sem_unlock(m_tcp_close_queue1_semid) == -1)
			{
				usleep(USLEEP_TIME);
			}
			break;
		}else
		{
			usleep(USLEEP_TIME);
		}
	}
}

void write_into_second_block_check_queue(TCP_CLOSEINFO_ID tcp_closeinfo_id)
{
	int i;
	int j;
	int index;
	int src_index;
	int dst_index;
	char find_flag = 0;
	if(tcp_closeinfo_id == NULL)
	{
		return;
	}
	while(1)
	{
		if(queue_sem_lock(m_tcp_close_queue2_check_semid) == 0)
		{

			g_tcp_close_queue2_check_ptr[g_tcp_close_queue1_info.write_index] = *tcp_closeinfo_id;
			
			g_tcp_close_queue2_info.write_index = (++g_tcp_close_queue2_check_info.write_index)%g_tcp_close_queue2_check_info.total_num;
			if(g_tcp_close_queue2_check_info.exist_num < g_tcp_close_queue2_check_info.total_num)
			{
				g_tcp_close_queue2_check_info.exist_num++;
			}else
			{
				g_tcp_close_queue2_check_info.read_index = (++g_tcp_close_queue2_check_info.read_index)%g_tcp_close_queue2_check_info.total_num;
			}
			while(queue_sem_unlock(m_tcp_close_queue2_check_semid) == -1)
			{
				usleep(USLEEP_TIME);
			}
			break;
		}else
		{
			usleep(USLEEP_TIME);
		}
	}
}

int auth_user_search(BLOCK_POLICY_ITEM_ID block_policy_item_id, IP_PACKET_ID ip_packet_id, unsigned char hit_direction)
{
	int i;
	char src_mac[20];
	char dst_mac[20];
	if(block_policy_item_id == NULL || ip_packet_id == NULL)
	{
		return ERR;
	}
	sprintf(src_mac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->src_mac[0],ip_packet_id->src_mac[1],ip_packet_id->src_mac[2],\
		ip_packet_id->src_mac[3],ip_packet_id->src_mac[4],ip_packet_id->src_mac[5]);
	
	sprintf(dst_mac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->dst_mac[0],ip_packet_id->dst_mac[1],ip_packet_id->dst_mac[2],\
		ip_packet_id->dst_mac[3],ip_packet_id->dst_mac[4],ip_packet_id->dst_mac[5]);
	
	for(i = 0; i<block_policy_item_id->user_num; i++)
	{
		switch(block_policy_item_id->user_list_id[i].iUsrCertifyMethod)
		{
			case 0: /*ip*/
				if(((block_policy_item_id->user_list_id[i].ip == ip_packet_id->src_ip)&& (hit_direction == 1))||((block_policy_item_id->user_list_id[i].ip == ip_packet_id->dst_ip)&&(hit_direction == 0)))
				{
					return OK;
				}
				break;
			case 1: /*mac*/
				if(((strncmp(block_policy_item_id->user_list_id[i].strMac, src_mac,12) ==0)&&(hit_direction ==1))||((strncmp(block_policy_item_id->user_list_id[i].strMac, dst_mac,12)==0)&&(hit_direction ==0)))
				{
					return OK;
				}
				break;
			case 2:/*ip and mac*/
				if(((block_policy_item_id->user_list_id[i].ip == ip_packet_id->src_ip)&&(strncmp(block_policy_item_id->user_list_id[i].strMac,src_mac,12)==0)&&(hit_direction ==1))||\
					((block_policy_item_id->user_list_id[i].ip == ip_packet_id->dst_ip)&&(strncmp(block_policy_item_id->user_list_id[i].strMac,dst_mac,12)==0)&&(hit_direction ==0)))
				{
					return OK;
				}	
				break;
			case 3: /*令牌*/
				if(((g_user_list_id[block_policy_item_id->user_list_id[i].Mode_Switch].ip == ip_packet_id->src_ip)&&\
					g_user_list_id[block_policy_item_id->user_list_id[i].Mode_Switch].usr_status==1 &&(hit_direction ==1))||\
					
					((g_user_list_id[block_policy_item_id->user_list_id[i].Mode_Switch].ip == ip_packet_id->dst_ip)&&\
					g_user_list_id[block_policy_item_id->user_list_id[i].Mode_Switch].usr_status==1 &&(hit_direction ==0)))
				{
					return OK;
				}
				break;
		}
	}
	return ERR;
}



int res_hit_mode_on_and(	PROTECTED_RESOURCE_ID protected_res_id  , IP_PACKET_ID ip_packet_id, unsigned char *hit_direction)
{
	unsigned char smac[20];
	unsigned char dmac[20];
	unsigned short src_port = htons(ip_packet_id->src_port);
	unsigned short dst_port = htons(ip_packet_id->dst_port);
	char port_hit_flag = 0;
	int i;
	
	if(protected_res_id == NULL || ip_packet_id == NULL || hit_direction == NULL)
	{
		return ERR;
	}
	*hit_direction = 2;
	switch(protected_res_id->use_mac_flag)
	{
		case SMAC:
			sprintf((char *)smac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->src_mac[0],ip_packet_id->src_mac[1],ip_packet_id->src_mac[2],\
			ip_packet_id->src_mac[3],ip_packet_id->src_mac[4],ip_packet_id->src_mac[5]);
			if(strncmp((char *)protected_res_id->smac,(char *)smac,12) != 0)
			{
				return ERR;
			}
			break;
		case DMAC:
			sprintf((char *)dmac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->dst_mac[0],ip_packet_id->dst_mac[1],ip_packet_id->dst_mac[2],\
			ip_packet_id->dst_mac[3],ip_packet_id->dst_mac[4],ip_packet_id->dst_mac[5]);
			if(strncmp((char *)protected_res_id->dmac,(char *)dmac,12) != 0)
			{
				return ERR;
			}
			break;
		case SMAC_DMAC:
			sprintf((char *)smac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->src_mac[0],ip_packet_id->src_mac[1],ip_packet_id->src_mac[2],\
			ip_packet_id->src_mac[3],ip_packet_id->src_mac[4],ip_packet_id->src_mac[5]);
			if(strncmp((char *)protected_res_id->smac,(char *)smac,12) != 0)
			{
				return ERR;
			}
			sprintf((char *)dmac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->dst_mac[0],ip_packet_id->dst_mac[1],ip_packet_id->dst_mac[2],\
			ip_packet_id->dst_mac[3],ip_packet_id->dst_mac[4],ip_packet_id->dst_mac[5]);
			if(strncmp((char *)protected_res_id->dmac,(char *)dmac,12) != 0)
			{
				return ERR;
			}
			break;
		case NO_USE:
		default:
			break;
	}

	switch(protected_res_id->use_ip_flag)
	{
		case SIP:
			if(((protected_res_id->sip.ip)&(protected_res_id->sip.mask))!=(ip_packet_id->src_ip&(protected_res_id->sip.mask)))
			{
				return ERR;
			}
			break;
		case DIP:
			if(((protected_res_id->dip.ip)&(protected_res_id->dip.mask))!=(ip_packet_id->dst_ip&(protected_res_id->dip.mask)))
			{
				return ERR;
			}
			break;
		case SIP_DIP:
			if(((protected_res_id->sip.ip)&(protected_res_id->sip.mask))!=(ip_packet_id->src_ip&(protected_res_id->sip.mask)))
			{
				return ERR;
			}
			if(((protected_res_id->dip.ip)&(protected_res_id->dip.mask))!=(ip_packet_id->dst_ip&(protected_res_id->dip.mask)))
			{
				return ERR;
			}
			break;
		case NO_USE:
		default:
			break;
	}
	switch(protected_res_id->use_port_flag)
	{
		case SPORT:
			  switch(protected_res_id->sip.src_port_express)
			  {
			  	case SINGLE_PORT:
				 	if(src_port !=protected_res_id->sip.single_port)
						return ERR;
					break;
				case INTERVAL_PORT:
					for(i=0;i<protected_res_id->sip.interval_port_num;i++)
					{
						if(src_port == protected_res_id->sip.port_id[i].port)
						{
							port_hit_flag == 1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag = 1;
					break;
				case CONTINUE_PORT:
					for(i=0;i<protected_res_id->sip.continue_port_num;i++)
					{
						if((src_port >=protected_res_id->sip.continue_port_id[i].min_port)&&(src_port <=protected_res_id->sip.continue_port_id[i].max_port))
						{
							port_hit_flag=1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				case CONTINUE_INTERVAL_PORT:
					for(i=0;i<protected_res_id->sip.interval_port_num;i++)
					{
						if(src_port == protected_res_id->sip.port_id[i].port)
						{
							port_hit_flag =1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					
					for(i=0;i<protected_res_id->sip.continue_port_num;i++)
					{
						if((src_port >=protected_res_id->sip.continue_port_id[i].min_port)&&(src_port <=protected_res_id->sip.continue_port_id[i].max_port))
						{
							port_hit_flag=1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				default:
					break;
			  }
			  break;
		case DPORT:
			switch(protected_res_id->dip.dst_port_express)
			{
			  	case SINGLE_PORT:
				 	if(dst_port !=protected_res_id->dip.single_port)
						return ERR;
					break;
				case INTERVAL_PORT:
					for(i=0;i<protected_res_id->dip.interval_port_num;i++)
					{
						if(dst_port == protected_res_id->dip.port_id[i].port)
						{
							port_hit_flag =1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				case CONTINUE_PORT:
					for(i=0;i<protected_res_id->dip.continue_port_num;i++)
					{
						if((dst_port >=protected_res_id->dip.continue_port_id[i].min_port)&&(dst_port <=protected_res_id->dip.continue_port_id[i].max_port))
						{
							port_hit_flag=1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				case CONTINUE_INTERVAL_PORT:
					for(i=0;i<protected_res_id->dip.interval_port_num;i++)
					{
						if(dst_port == protected_res_id->dip.port_id[i].port)
						{
							port_hit_flag =1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					
					for(i=0;i<protected_res_id->dip.continue_port_num;i++)
					{
						if((dst_port >=protected_res_id->dip.continue_port_id[i].min_port)&&(dst_port <=protected_res_id->dip.continue_port_id[i].max_port))
						{
							port_hit_flag=1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				default:
					break;
			  }
			  break;
		case SPORT_DPORT:
			 switch(protected_res_id->sip.src_port_express)
			 {
			  	case SINGLE_PORT:
				 	if(src_port !=protected_res_id->sip.single_port)
						return ERR;
					break;
				case INTERVAL_PORT:
					for(i=0;i<protected_res_id->sip.interval_port_num;i++)
					{
						if(src_port == protected_res_id->sip.port_id[i].port)
						{
							port_hit_flag =1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				case CONTINUE_PORT:
					for(i=0;i<protected_res_id->sip.continue_port_num;i++)
					{
						if((src_port >=protected_res_id->sip.continue_port_id[i].min_port)&&(src_port <=protected_res_id->sip.continue_port_id[i].max_port))
						{
							port_hit_flag=1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				case CONTINUE_INTERVAL_PORT:
					for(i=0;i<protected_res_id->sip.interval_port_num;i++)
					{
						if(src_port == protected_res_id->sip.port_id[i].port)
						{
							port_hit_flag =1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					
					for(i=0;i<protected_res_id->sip.continue_port_num;i++)
					{
						if((src_port >=protected_res_id->sip.continue_port_id[i].min_port)&&(src_port <=protected_res_id->sip.continue_port_id[i].max_port))
						{
							port_hit_flag=1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				default:
					break;
			}
			/*DPORT */
			switch(protected_res_id->dip.dst_port_express)
			{
			  	case SINGLE_PORT:
				 	if(dst_port !=protected_res_id->dip.single_port)
						return ERR;
					break;
				case INTERVAL_PORT:
					for(i=0;i<protected_res_id->dip.interval_port_num;i++)
					{
						if(dst_port == protected_res_id->dip.port_id[i].port)
						{
							port_hit_flag =1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				case CONTINUE_PORT:
					for(i=0;i<protected_res_id->dip.continue_port_num;i++)
					{
						if((dst_port >=protected_res_id->dip.continue_port_id[i].min_port)&&(dst_port <=protected_res_id->sip.continue_port_id[i].max_port))
						{
							port_hit_flag=1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				case CONTINUE_INTERVAL_PORT:
					for(i=0;i<protected_res_id->dip.interval_port_num;i++)
					{
						if(dst_port == protected_res_id->dip.port_id[i].port)
						{
							port_hit_flag =1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					
					for(i=0;i<protected_res_id->dip.continue_port_num;i++)
					{
						if((dst_port >=protected_res_id->dip.continue_port_id[i].min_port)&&(dst_port <=protected_res_id->dip.continue_port_id[i].max_port))
						{
							port_hit_flag=1;
							break;
						}
					}
					if(port_hit_flag == 0)
						return ERR;
					port_hit_flag=0;
					break;
				default:
					break;
			  }
			break;
		case NO_USE:
		default:
			break;
	}
	return OK;
}

int res_hit_mode_on_or(PROTECTED_RESOURCE_ID protected_res_id  , IP_PACKET_ID ip_packet_id, unsigned char *hit_direction)
{
	unsigned char smac[20];
	unsigned char dmac[20];
	unsigned short src_port = htons(ip_packet_id->src_port);
	unsigned short dst_port = htons(ip_packet_id->dst_port);
	int i;
	unsigned char hit_flag =0;

	if(protected_res_id == NULL || ip_packet_id == NULL || hit_direction == NULL)
	{
		return ERR;
	}

/*	if(dst_port == 8000)
	{
		printf("aaaa\n");
		getchar();
	}
*/
	switch(protected_res_id->use_mac_flag)
	{
		case SMAC:
			sprintf((char *)smac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->src_mac[0],ip_packet_id->src_mac[1],ip_packet_id->src_mac[2],\
			ip_packet_id->src_mac[3],ip_packet_id->src_mac[4],ip_packet_id->src_mac[5]);
			if(strncmp((char *)protected_res_id->smac,(char *)smac,12) == 0)
			{
				hit_flag|=0x01;
			}
			hit_flag|=0x02;
			break;
		case DMAC:
			sprintf((char *)dmac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->dst_mac[0],ip_packet_id->dst_mac[1],ip_packet_id->dst_mac[2],\
			ip_packet_id->dst_mac[3],ip_packet_id->dst_mac[4],ip_packet_id->dst_mac[5]);
			if(strncmp((char *)protected_res_id->dmac,(char *)dmac,12) == 0)
			{
				hit_flag|=0x02;
			}
			hit_flag|=0x01;
			break;
		case SMAC_DMAC:
			sprintf((char *)smac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->src_mac[0],ip_packet_id->src_mac[1],ip_packet_id->src_mac[2],\
			ip_packet_id->src_mac[3],ip_packet_id->src_mac[4],ip_packet_id->src_mac[5]);
			if(strncmp((char *)protected_res_id->smac,(char *)smac,12) == 0)
			{
				hit_flag |= 0x01;
			}
			sprintf((char *)dmac,"%.2X%.2X%.2X%.2X%.2X%.2X",ip_packet_id->dst_mac[0],ip_packet_id->dst_mac[1],ip_packet_id->dst_mac[2],\
			ip_packet_id->dst_mac[3],ip_packet_id->dst_mac[4],ip_packet_id->dst_mac[5]);
			if(strncmp((char *)protected_res_id->dmac,(char *)dmac,12) == 0)
			{
				hit_flag |= 0x02;
			}
			break;
		case NO_USE:
		default:
			hit_flag |= 0x01;
			hit_flag |= 0x02;			
			break;
	}

	switch(protected_res_id->use_ip_flag)
	{
		case SIP:
			if(((protected_res_id->sip.ip)&(protected_res_id->sip.mask))==(ip_packet_id->src_ip&(protected_res_id->sip.mask)))
			{
				hit_flag |=0x04;
			}
			hit_flag |=0x08;			
			break;
		case DIP:
			if(((protected_res_id->dip.ip)&(protected_res_id->dip.mask))==(ip_packet_id->dst_ip&(protected_res_id->dip.mask)))
			{
				hit_flag |=0x08;	
			}
			hit_flag |=0x04;	
			break;
		case SIP_DIP:
			if(((protected_res_id->sip.ip)&(protected_res_id->sip.mask))==(ip_packet_id->src_ip&(protected_res_id->sip.mask)))
			{
				hit_flag |=0x04;
			}
			if(((protected_res_id->dip.ip)&(protected_res_id->dip.mask))==(ip_packet_id->dst_ip&(protected_res_id->dip.mask)))
			{
				hit_flag |=0x08;	
			}
			break;
		case NO_USE:
		default:
			hit_flag |=0x04;
			hit_flag |=0x08;
			break;
	}
	switch(protected_res_id->use_port_flag)
	{
		case SPORT:
			switch(protected_res_id->sip.src_port_express)
			{
				case SINGLE_PORT:
					if(src_port ==protected_res_id->sip.single_port)
					{
						if((hit_flag&0x01)&&(hit_flag&0x04))
						{
							*hit_direction = 0;
							return OK;
						}
					}
				break;
				case INTERVAL_PORT:
					if((hit_flag&0x01)&&(hit_flag&0x04))
					{
						for(i=0;i<protected_res_id->sip.interval_port_num;i++)
						{
							if(src_port == protected_res_id->sip.port_id[i].port)
								{
								*hit_direction = 0;
								return OK;
								}
							}
						}
					break;
				case CONTINUE_PORT:
					if((hit_flag&0x01)&&(hit_flag&0x04))
					{
						for(i=0;i<protected_res_id->sip.continue_port_num;i++)
						{
							if((src_port >=protected_res_id->sip.continue_port_id[i].min_port)&&(src_port <=protected_res_id->sip.continue_port_id[i].max_port))
							{
							*hit_direction = 0;
							return OK;
							}
						}
					}
					break;
				case CONTINUE_INTERVAL_PORT:
					if((hit_flag&0x01)&&(hit_flag&0x04))
					{
						for(i=0;i<protected_res_id->sip.interval_port_num;i++)
						{
							if(src_port == protected_res_id->sip.port_id[i].port)
							{
								*hit_direction = 0;
								return OK;
							}
						}
						for(i=0;i<protected_res_id->sip.continue_port_num;i++)
						{
							if((src_port >=protected_res_id->sip.continue_port_id[i].min_port)&&(src_port <=protected_res_id->sip.continue_port_id[i].max_port))
							{
								*hit_direction = 0;
								return OK;
							}
						}
					}
					break;
					default:
						break;
			}
			break;
		case DPORT:
			switch(protected_res_id->dip.dst_port_express)
			{
			  	case SINGLE_PORT:
				 	if(dst_port ==protected_res_id->dip.single_port)
				 	{
						if((hit_flag&0x02)&&(hit_flag&0x08))
						{
							*hit_direction = 1;
							return OK;
						}
					}
					break;
				case INTERVAL_PORT:
					if((hit_flag&0x02)&&(hit_flag&0x08))
					{
						for(i=0;i<protected_res_id->dip.interval_port_num;i++)
						{
							if(dst_port == protected_res_id->dip.port_id[i].port)
							{
								*hit_direction = 1;
								return OK;
							}
						}
					}
					break;
				case CONTINUE_PORT:
					if((hit_flag&0x02)&&(hit_flag&0x08))
					{
						for(i=0;i<protected_res_id->dip.continue_port_num;i++)
						{
							if((dst_port >=protected_res_id->dip.continue_port_id[i].min_port)&&(dst_port <=protected_res_id->dip.continue_port_id[i].max_port))
							{
								*hit_direction = 1;
								return OK;
							}
						}
					}
					break;
				case CONTINUE_INTERVAL_PORT:
					if((hit_flag&0x02)&&(hit_flag&0x08))
					{
						for(i=0;i<protected_res_id->dip.interval_port_num;i++)
						{
							if(dst_port == protected_res_id->dip.port_id[i].port)
							{
								*hit_direction = 1;
								return OK;
							}
						}
						
						for(i=0;i<protected_res_id->dip.continue_port_num;i++)
						{
							if((dst_port >=protected_res_id->dip.continue_port_id[i].min_port)&&(dst_port <=protected_res_id->dip.continue_port_id[i].max_port))
							{
								*hit_direction = 1;
								return OK;
							}
						}
					}
					break;
				default:
					break;
			  }
			  break;
		case SPORT_DPORT:
			  switch(protected_res_id->sip.src_port_express)
			  {
			  	case SINGLE_PORT:
				 	if(src_port ==protected_res_id->sip.single_port)
				 	{
						if((hit_flag&0x01)&&(hit_flag&0x04))
						{
							*hit_direction = 0;
							return OK;
						}
					}
					break;
				case INTERVAL_PORT:
					if((hit_flag&0x01)&&(hit_flag&0x04))
					{
						for(i=0;i<protected_res_id->sip.interval_port_num;i++)
						{
							if(src_port == protected_res_id->sip.port_id[i].port)
							{
								*hit_direction = 0;
								return OK;
							}
						}
					}
					break;
				case CONTINUE_PORT:
					if((hit_flag&0x01)&&(hit_flag&0x04))
					{
						for(i=0;i<protected_res_id->sip.continue_port_num;i++)
						{
							if((src_port >=protected_res_id->sip.continue_port_id[i].min_port)&&(src_port <=protected_res_id->sip.continue_port_id[i].max_port))
							{
								*hit_direction = 0;
								return OK;
							}
						}
					}
					break;
				case CONTINUE_INTERVAL_PORT:
					if((hit_flag&0x01)&&(hit_flag&0x04))
					{
						for(i=0;i<protected_res_id->sip.interval_port_num;i++)
						{
							if(src_port == protected_res_id->sip.port_id[i].port)
							{
								*hit_direction = 0;
								return OK;
							}
						}
						for(i=0;i<protected_res_id->sip.continue_port_num;i++)
						{
							if((src_port >=protected_res_id->sip.continue_port_id[i].min_port)&&(src_port <=protected_res_id->sip.continue_port_id[i].max_port))
							{
								*hit_direction = 0;
								return OK;
							}
						}
					}
					break;
				default:
					break;
			}
			switch(protected_res_id->dip.dst_port_express)
			{
			  	case SINGLE_PORT:
					if(dst_port ==protected_res_id->dip.single_port)
					{
						if((hit_flag&0x02)&&(hit_flag&0x08))
						{
							*hit_direction = 1;
							return OK;
						}
					}
					break;
				case INTERVAL_PORT:
					if((hit_flag&0x02)&&(hit_flag&0x08))
					{
						for(i=0;i<protected_res_id->dip.interval_port_num;i++)
						{
							if(dst_port == protected_res_id->dip.port_id[i].port)
							{
								*hit_direction = 1;
								return OK;
							}
						}
					}
					break;
				case CONTINUE_PORT:
					if((hit_flag&0x02)&&(hit_flag&0x08))
					{
						for(i=0;i<protected_res_id->dip.continue_port_num;i++)
						{
							if((dst_port >=protected_res_id->dip.continue_port_id[i].min_port)&&(dst_port <=protected_res_id->dip.continue_port_id[i].max_port))
							{
								*hit_direction = 1;
								return OK;
							}
						}
					}
					break;
				case CONTINUE_INTERVAL_PORT:
					if((hit_flag&0x02)&&(hit_flag&0x08))
					{
						for(i=0;i<protected_res_id->dip.interval_port_num;i++)
						{
							if(dst_port == protected_res_id->dip.port_id[i].port)
							{
								*hit_direction = 1;
								return OK;
							}
						}
						
						for(i=0;i<protected_res_id->dip.continue_port_num;i++)
						{
							if((dst_port >=protected_res_id->dip.continue_port_id[i].min_port)&&(dst_port <=protected_res_id->dip.continue_port_id[i].max_port))
							{
								*hit_direction = 1;
								return OK;
							}
						}
					}
					break;
				default:
					break;
			}
			break;
		case NO_USE:
		default:
			if((hit_flag&0x02)&&(hit_flag&0x08))
			{
				*hit_direction = 1;
				return OK;
			}
			if((hit_flag&0x01)&&(hit_flag&0x04))
			{
				*hit_direction = 0;
				return OK;
			}
			break;
	}
	return ERR;
}
int queue_sem_unlock(int sem_seq)
{
	switch(sem_seq)
	{
		case 0:
			if (-1==Sem_V(0,m_block_queue_semid))
			{
				DEBUG("queue_sem_unlock(): Sem_V(0) failed");
				return -1;
			}
			break;

		case 1:
			if (-1==Sem_V(1, m_block_queue_semid))
			{
				DEBUG("queue_sem_unlock(): Sem_V(1) failed");
				return -1;
			}
			break;

		case 2:
			if (-1==Sem_Unlock(0, m_block_queue_semid))
			{
				DEBUG("queue_sem_unlock():Sem_Unlock(2) failed");
				return -1;
			}
			break;

		case 3:
			if (-1==Sem_Unlock(1, m_block_queue_semid))
			{
				DEBUG("queue_sem_unlock():Sem_Unlock(3) failed");
				return -1;
			}
			break;
		default:

			break;
	}

	return 0;
}
int queue_sem_lock(int sem_seq)
{
	switch(sem_seq)
	{
		case 0:
			if (-1==Sem_P(0,m_block_queue_semid))
			{
				DEBUG("queue_sem_unlock(): Sem_P(0) failed");
				return -1;
			}
			break;

		case 1:
			if (-1==Sem_P(1, m_block_queue_semid))
			{
				DEBUG("queue_sem_unlock(): Sem_P(1) failed");
				return -1;
			}
			break;

		case 2:
			if (-1==Sem_Lock(0, m_block_queue_semid))
			{
				DEBUG("queue_sem_unlock():Sem_Lock(0) failed");
				return -1;
			}
			break;

		case 3:
			if (-1==Sem_Lock(1, m_block_queue_semid))
			{
				DEBUG("queue_sem_unlock():Sem_Lock(1) failed");
				return -1;
			}
			break;
		default:

			break;
	}

	return 0;
}



int  generate_block_policy()
{
	int shm_id = -1;
	int tcp_res_block_num = 0;
	int udp_res_block_num = 0;
	int i;
	int k;
	int m;
	int n;

	USR_LIST_MEM_ID user_list_id;
	int auth_usr_num;
	
	int tcp_policy_index;
	int udp_policy_index;
	i = 0;
	while(i < g_res_num)/*计算有阻断标志的保护资源数*/
	{
		if(g_res_list_id[i].ethernet_type == IP && g_res_list_id[i].unauthorize_event.block_flag)
		{
			if(g_res_list_id[i].transfer_type == 1)  ///TCP
			{
				tcp_res_block_num++;
			}else if(g_res_list_id[i].transfer_type == 0)   ///UDP
			{
				udp_res_block_num++;
			}
		}
		i++;
	}

	g_tcp_block_policy_list.block_policy_num = tcp_res_block_num;
	g_udp_block_policy_list.block_policy_num = udp_res_block_num;

	if(tcp_res_block_num > 0)
	{
		if((g_tcp_block_policy_list.block_policy_item_id = (BLOCK_POLICY_ITEM_ID)calloc(sizeof(BLOCK_POLICY_ITEM), tcp_res_block_num)) == NULL)
		{
			return ERR;
		}
	}

	if(udp_res_block_num > 0)
	{
		if((g_udp_block_policy_list.block_policy_item_id = (BLOCK_POLICY_ITEM_ID)calloc(sizeof(BLOCK_POLICY_ITEM), udp_res_block_num)) == NULL)
		{
			return ERR;
		}
	}


	i = 0;
	tcp_policy_index = 0;
	udp_policy_index = 0;
	while(i < g_res_num)
	{
		if(g_res_list_id[i].ethernet_type == IP &&  g_res_list_id[i].unauthorize_event.block_flag)
		{

			k = 0;
			auth_usr_num = 0;
			while(k < g_auth_num)/*计算在授权列表中访问阻断保护资源的用户数*/
			{
				if(g_auth_list_id[k].protect_resource_id == g_res_list_id[i].rule_id)
				{
					auth_usr_num++;
				}
				k++;
			}
			if(auth_usr_num > 0)
			{
				if((user_list_id =  (USR_LIST_MEM_ID)calloc(sizeof(USR_LIST_MEM), auth_usr_num)) == NULL)
				{
					return ERR;
				}
			}else
			{
				user_list_id = NULL;
			}
			
			k = 0;
			m = 0;
			/*为有阻断标志的保护资源添加授权用户*/
			while(k < g_auth_num)
			{
				if(g_auth_list_id[k].protect_resource_id ==  g_res_list_id[i].rule_id)
				{
					n = 0;
					while(n < g_user_num)
					{
						if(g_user_list_id[n].iUsrId == g_auth_list_id[k].usr_id)
						{
							user_list_id[m] = g_user_list_id[n];
							user_list_id[m++].Mode_Switch = n;  /*保存在用户列表中的索引*/
							break;
						}
						n++;
					}
				}
				k++;
			}
			if(g_res_list_id[i].transfer_type == 1)
			{
				g_tcp_block_policy_list.block_policy_item_id[tcp_policy_index].res = g_res_list_id[i];
				g_tcp_block_policy_list.block_policy_item_id[tcp_policy_index].user_num = auth_usr_num;
				g_tcp_block_policy_list.block_policy_item_id[tcp_policy_index].user_list_id = user_list_id;
				tcp_policy_index++;
			}else if(g_res_list_id[i].transfer_type == 0)
			{
				g_udp_block_policy_list.block_policy_item_id[udp_policy_index].res = g_res_list_id[i];
				g_udp_block_policy_list.block_policy_item_id[udp_policy_index].user_num = auth_usr_num;
				g_udp_block_policy_list.block_policy_item_id[udp_policy_index].user_list_id = user_list_id;
				udp_policy_index++;
			}
		}
		i++;
	}
	return OK;
}


void udp_block_analysis_handler()
{
	IP_PACKET ip_packet;
	unsigned int i;
	PROTECTED_RESOURCE_ID protected_res_id = NULL;
	UDP_CLOSEINFO udp_close_info;
	unsigned char hit_direction;


	int sockfd1 = raw_net_socket1();
	int sockfd2 = raw_dlk_socket();
	if(sockfd1 == -1 || sockfd2 == -1)
	{
		exit(EXIT_FAILURE);
	}

	
	while(1)
	{
		pthread_mutex_lock(&g_udp_queue_mutex);
		
		if(g_udp_block_queue_info.exist_num <=0)
		{
			pthread_mutex_unlock(&g_udp_queue_mutex);
			usleep(USLEEP_TIME);
			continue;
		}

		udp_close_info = g_udp_close_queue_ptr[g_udp_block_queue_info.read_index];
		g_udp_block_queue_info.exist_num--;
		g_udp_block_queue_info.read_index = (++g_udp_block_queue_info.read_index)%g_udp_block_queue_info.total_num;
		
		pthread_mutex_unlock(&g_udp_queue_mutex);

		memcpy(ip_packet.src_mac, udp_close_info.src_mac, ETHER_ADDR_LEN);
		memcpy(ip_packet.dst_mac, udp_close_info.dst_mac, ETHER_ADDR_LEN);
		ip_packet.src_ip = udp_close_info.src_ip;
		ip_packet.dst_ip = udp_close_info.dst_ip;
		ip_packet.src_port = udp_close_info.src_port;
		ip_packet.dst_port = udp_close_info.dst_port;

		
		for(i = 0; i < g_udp_block_policy_list.block_policy_num; i++)
		{
			protected_res_id = &(g_udp_block_policy_list.block_policy_item_id[i].res);
			switch(protected_res_id->dispose_object_relation)
			{
				case 1:
					if(res_hit_mode_on_and(protected_res_id, &ip_packet, &hit_direction) == ERR)
					{
						continue;/*不匹配*/
					}
					break;
				case 2:
					if(res_hit_mode_on_or(protected_res_id, &ip_packet, &hit_direction) == ERR)
					{
						continue;/*不匹配*/
					}
					break;
				default:
					continue;
			}
			/*匹配*/
			if(auth_user_search(g_udp_block_policy_list.block_policy_item_id+i, &ip_packet, hit_direction) == ERR)
			{/*未授权,写一次阻断队列*/
				send_icmp_host_unreachable1(sockfd1,&udp_close_info);
				send_arp_block_pkt1(sockfd2,&udp_close_info);
//				if(protected_res_id->unauthorize_event.log_flag)
//				{
					write_blocklog_queue(&ip_packet, hit_direction);
//				}
			}
		}
	}
}

void blocklog_handler()
{
	DB_CFG_INFO db_cfg_info;
	BLOCKLOGINFO blocklog_info;
	
	if(read_db_cfg_info(&db_cfg_info)== ERR)
	{
		while(1)
		{
			if(conn_local_db() == ESQL_OK)
			{
				break;
			}
			usleep(100);
		}
	}else
	{
		while(1)
		{
			if(connect_db(db_cfg_info.ip, db_cfg_info.port, db_cfg_info.db, db_cfg_info.usr_name, db_cfg_info.password) == ESQL_OK)
			{
				break;
			}
			usleep(100);
		}

	}
	while(1)
	{
		if(pthread_mutex_trylock(&g_blocklog_queue_mutex) == 0)
		{
			if(g_blocklog_queue_info.exist_num <= 0)
			{
				pthread_mutex_unlock(&g_blocklog_queue_mutex);
				usleep(USLEEP_TIME);
				continue;
			}
			blocklog_info =  g_blocklog_info_ptr[g_blocklog_queue_info.read_index];
			
			g_blocklog_queue_info.exist_num--;
			g_blocklog_queue_info.read_index = (++g_blocklog_queue_info.read_index)%g_blocklog_queue_info.total_num;
			pthread_mutex_unlock(&g_blocklog_queue_mutex);

			write_block_log(&blocklog_info);
		}
		usleep(1);
	}

}
void write_blocklog_queue(IP_PACKET_ID ip_packet_id, unsigned char hit_direction)
{
	if(pthread_mutex_trylock(&g_blocklog_queue_mutex) == 0)
	{
		if(hit_direction == 1)
		{
			g_blocklog_info_ptr[g_blocklog_queue_info.write_index].src_ip= ip_packet_id->src_ip;
			g_blocklog_info_ptr[g_blocklog_queue_info.write_index].src_port = ip_packet_id->src_port;
			g_blocklog_info_ptr[g_blocklog_queue_info.write_index].dst_ip= ip_packet_id->dst_ip;
			g_blocklog_info_ptr[g_blocklog_queue_info.write_index].dst_port = ip_packet_id->dst_port;
			
		}else
		{
			g_blocklog_info_ptr[g_blocklog_queue_info.write_index].src_ip= ip_packet_id->dst_ip;
			g_blocklog_info_ptr[g_blocklog_queue_info.write_index].src_port = ip_packet_id->dst_port;			
			g_blocklog_info_ptr[g_blocklog_queue_info.write_index].dst_ip= ip_packet_id->src_ip;
			g_blocklog_info_ptr[g_blocklog_queue_info.write_index].dst_port = ip_packet_id->src_port;			
		}

		g_blocklog_info_ptr[g_blocklog_queue_info.write_index].time= ip_packet_id->ts.tv_sec;
			
		g_blocklog_queue_info.write_index = (++g_blocklog_queue_info.write_index)%g_blocklog_queue_info.total_num;
		if(g_blocklog_queue_info.exist_num < g_blocklog_queue_info.total_num)
		{
			g_blocklog_queue_info.exist_num++;
		}else
		{
			g_blocklog_queue_info.read_index = (++g_blocklog_queue_info.read_index)%g_blocklog_queue_info.total_num;
		}
		pthread_mutex_unlock(&g_blocklog_queue_mutex);
	}
}



static int raw_net_socket1()
{
	int on = 1;
	int sockfd;
	sockfd = socket(AF_INET,SOCK_RAW,SOCK_RAW);
	if(sockfd < 0)
	{
		error("UDP SOCKET FAIL!");
		return -1;
	}
	if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,(char*)&on,sizeof(on)))
	{
		error("SET UDP RAW SOCKET FAIL!");
		close(sockfd);
		return -1;
	}
	setuid(getuid());
	return sockfd;
}

int raw_dlk_socket()
{
     int sockfd;  
     //if((sockfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP))) < 0)  
     if((sockfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0)  
     {  
         error("The raw socket was not created.\n");
         return  -1;  
     }
     setuid(getuid());
     return sockfd;  
}


static void	send_arp_block_pkt1(int sockfd, UDP_CLOSEINFO_ID udp_close_info_id)
{
	struct etherhdr0* ether;
	struct arphdr0*  arp;
	unsigned char buffer[1514];
	int bufferlen;
	int rv;
	struct sockaddr from;  

	bufferlen = sizeof(struct etherhdr0) + sizeof(struct arphdr0);
		
	ether = buffer;
	memcpy(ether->dst_mac, udp_close_info_id->src_mac, ETHER_ADDR_LEN);
	memcpy(ether->src_mac, udp_close_info_id->dst_mac, ETHER_ADDR_LEN);
	ether->src_mac[ETHER_ADDR_LEN-1] = ~(ether->src_mac[ETHER_ADDR_LEN-1]);
	ether->type = htons(0x0806);

	arp = buffer + sizeof(struct etherhdr0);
	arp->hd_type = htons(1);
	arp->pro_type = htons(0x0800);
	arp->hd_len = 0x06;
	arp->pro_len = 0x04;
	arp->op = htons(0x0002);
	memcpy(arp->src_mac, ether->src_mac, ETHER_ADDR_LEN);
	arp->src_ip = udp_close_info_id->dst_ip;
	memcpy(arp->dst_mac, ether->dst_mac, ETHER_ADDR_LEN);
	arp->dst_ip = udp_close_info_id->src_ip;
	strcpy(from.sa_data, "eth0");  
	
	DEBUG("send arp pkt \n");
	if((rv = sendto(sockfd, buffer, bufferlen, 0, (struct sockaddr*)&from,sizeof(from))) == -1)
	{
//		perror("aa");
		DEBUG("send arp pkt fail.\n");
	}
	return rv;
}



static void send_icmp_host_unreachable1(int sockfd, UDP_CLOSEINFO_ID udp_close_info_id)
{

	struct iphdr0 *ip;
	struct icmphdr0 *icmp;
	unsigned char buffer[2048];
	int bufferlen;
	unsigned char* p;
	struct  sockaddr_in addr;
	int rv;
	

	bufferlen  = sizeof(struct iphdr0) + 8 + udp_close_info_id->data_len;
	
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = udp_close_info_id->src_port;
	addr.sin_addr.s_addr = udp_close_info_id->src_ip;

//	printf("send icmp:%s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	
	ip = (struct iphdr0* )buffer;
	
	ip->vhl = 0; 
	ip->vhl |= (4<<4);
	ip->vhl |= (sizeof(struct iphdr0)>>2);
	
	ip->tos = 0;
	ip->tot_len = htons(bufferlen);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = MAXTTL;
	ip->protocol = 1;
	ip->check = 0;
	ip->saddr = udp_close_info_id->dst_ip;
	ip->daddr = udp_close_info_id->src_ip;


	icmp = buffer+sizeof(struct iphdr0);
	icmp->type = 3;
	icmp->code = 2;
	icmp->check = 0;
	icmp->other = 0;

	p = buffer + sizeof(struct iphdr0) + sizeof(struct icmphdr0);
	memcpy(p, udp_close_info_id->data, udp_close_info_id->data_len);

	icmp->check = check_sum(icmp, 8+udp_close_info_id->data_len, NULL);
	ip->check = check_sum(ip, sizeof(struct iphdr0) , NULL);
	
	if((rv = sendto(sockfd, buffer, bufferlen,0,(struct sockaddr*)&addr,sizeof(addr))) == -1)
	{
		DEBUG("send icmp pkt fail.\n");
	}
	
	return rv;
}



/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void capture_stop(void)
{
    g_can_capture = SAIL_FALSE;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void capture_stop_signal_handler(int signo)
{
    write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Signal: Stop capture!");
    capture_stop();
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void copy_pcap_pkt(u_char *userData, const struct pcap_pkthdr *h, const u_char *pkt)
{
    
    struct singleton_t *sp = (struct singleton_t *)userData;
    *sp->hdr = *h;
    sp->pkt = pkt;

#ifdef INC_FLOW_STAT_ANALYSIS_MODEL
    if (ON == g_flow_switch){
    ETHER_HDR_ID ether_hdr_id = (ETHER_HDR_ID)pkt;
    ARP_FRAME_ID arp_frame_id = NULL;
    IP_HDR_ID ip_hdr_id = NULL;
    TCP_HDR_ID tcp_hdr_id = NULL;
    UDP_HDR_ID udp_hdr_id = NULL;
    STAT_MSG_FMT msg;

    if (h->caplen < ETHERNET_HEADER_LEN)
        return;

    msg.msg_type = DFL_SYS_MSG_SND_TYPE;

    msg.ether_hdr = *ether_hdr_id;
    msg.sum_info.ts = h->ts;
    msg.sum_info.cap_len = h->caplen;

    if ((g_arp_type == ether_hdr_id->ether_type)
        || (g_revarp_type == ether_hdr_id->ether_type))
    {
        arp_frame_id = (ARP_FRAME_ID)(pkt+IPV4_ETHER_HEADER_SIZE);

        msg.sum_info.src_ip = arp_frame_id->send_prot_addr;
        msg.sum_info.dest_ip= arp_frame_id->targ_prot_addr;
        msg.sum_info.ip_p = arp_frame_id->opcode; /*ARP/RARP*/
    }

    if (g_ip_type == ether_hdr_id->ether_type)
    {
        ip_hdr_id = (IP_HDR_ID)(pkt+IPV4_ETHER_HEADER_SIZE);

        msg.sum_info.src_ip = ip_hdr_id->ip_src.s_addr;
        msg.sum_info.dest_ip= ip_hdr_id->ip_dst.s_addr;
        msg.sum_info.ip_p = ip_hdr_id->ip_p; /*tcp/udp/igmp*/
        
        /*tcp*/
        if (IPPROTO_TCP == ip_hdr_id->ip_p)
        {
            tcp_hdr_id = (TCP_HDR_ID)(pkt+IP_ETHER_HEADER_SIZE);
            msg.sum_info.dest_port = tcp_hdr_id->th_dport;
            msg.sum_info.src_port = tcp_hdr_id->th_sport;
        }
       
        /*udp*/
        if (IPPROTO_UDP == ip_hdr_id->ip_p)
        {
            udp_hdr_id = (UDP_HDR_ID)(pkt+IP_ETHER_HEADER_SIZE);
            msg.sum_info.dest_port = udp_hdr_id->uh_dport;
            msg.sum_info.src_port = udp_hdr_id->uh_sport;
        }
    }

    (void)sys_msg_que_snd(g_sys_msg_que_id,&msg,STAT_MSG_DATA_SIZE);
    }
#endif
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int get_per_nic_sem(int que_num,QUE_ID que_id,NIC_QUE_INFO_ID nic_que_info_id)
{
    register int i;
    int semid;
    key_t sem_Key;

    for(i = 0;i < que_num;i++)
    {
        sem_Key = (que_id + i)->semKey;
        if ((semid = get_sem(sem_Key)) < 0)
        {
            return ERR;
        }
        (nic_que_info_id + i)->semid = semid;

        if ((semid = get_sem(sem_Key + FULE_SEM_IVL)) < 0)
        {
            return ERR;
        }
        (nic_que_info_id + i)->full_semid = semid;

        if ((semid = get_sem(sem_Key + EMPTY_SEM_IVL)) < 0)
        {
            return ERR;
        }
        (nic_que_info_id + i)->empty_semid = semid;
    }

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int get_per_nic_shm(int que_num,QUE_ID que_id,NIC_QUE_INFO_ID nic_que_info_id)
{
    register int i;
    int shmid;
    key_t shmKey;
    char *shm_que_addr = NULL;

    for (i = 0;i < que_num;i++)
    {
        shmKey = (que_id + i)->shmKey;
	 printf("capture shmkey = %ld \n",shmKey);
        if ((shmid = shmget(shmKey,0,IPC_CREAT)) < 0)
        {
            error("[Err]Get shm que fail.");
            return ERR;
        }

        shm_que_addr = (char *)shmat(shmid,NULL,0);
        if (!shm_que_addr)
        {
            error("[Err]Attach shm que fail.");
            return ERR;
        }
        
        (nic_que_info_id + i)->shmid= shmid;
        (nic_que_info_id + i)->shm_addr = shm_que_addr;
    }

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int reg_capture_res(int que_num,NIC_QUE_INFO_ID nic_que_info_id)
{
    register int i;
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char *shm_addr;
    char file_path[MAX_FILE_PATH_SIZE];
  
    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    (void)get_res_reg_file_path(file_path,ALL_RES_FILE_NAME,CAPTURE_MODEL_NAME);            

    if (NULL == (fp = fopen(file_path,"w+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",0);
    fputs(buf,fp);
    fputc('\n',fp);

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",que_num);
    fputs(buf,fp);
    fputc('\n',fp);

    for(i = 0 ;i < que_num;i++)
    {
        memset(buf,0x00,U_LONG_SIZE+1);
        shm_addr = (nic_que_info_id + i)->shm_addr;
        sprintf(buf,"%u",(unsigned long)(shm_addr));
        fputs(buf,fp);
        fputc('\n',fp);
    
        memset(buf,0x00,U_LONG_SIZE+1);
        sprintf(buf,"%d",-1);
        fputs(buf,fp);
        fputc('\n',fp);
    }

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",0);
    fputs(buf,fp);
    fputc('\n',fp);

    fflush(fp);
    fclose(fp);

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void report_capture_stat(char *mmap_buf)
{
    struct pcap_stat stats;   

    if (ERR == cmp_capture_stat())
        return;
	
    if (NULL != pd)
    {
        if (pcap_stats(pd, &stats) >= 0)
        {
            g_pkt_stat.ps_drop = stats.ps_drop;
        }
    }

#ifdef INC_FIRST_DROPS
    sprintf(mmap_buf,"%Ld,%Ld;%ld;%ld;%ld",g_pkt_stat.us_recv,g_pkt_stat.us_recv_size,\
            g_pkt_stat.ps_drop,g_pkt_stat.wait_times,g_pkt_stat.ps_first_drop);
#else
    sprintf(mmap_buf,"%Ld,%Ld;%ld;%ld;",g_pkt_stat.us_recv,g_pkt_stat.us_recv_size,\
            g_pkt_stat.ps_drop,g_pkt_stat.wait_times);
#endif

    g_old_pkt_stat = g_pkt_stat;
    
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
static int cmp_capture_stat()
{
    /*包括没数据报时的处理*/
    if (g_pkt_stat.us_recv > g_old_pkt_stat.us_recv)
        return OK;

    return ERR;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
#ifdef SIGINFO
static void signal_report_stat(void)
{
    signal(SIGINFO,report_stat_siginfo);
}
#endif

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
#ifdef SIGINFO
static void report_stat_siginfo(int sig_no)
{
    if (SIGINFO == sig_no)
    {
        fprintf(stderr, "%Ld packets captured.\n", g_pkt_stat.us_recv);
        fprintf(stderr, "%Ld size captured.\n", g_pkt_stat.us_recv_size);
        fprintf(stderr, "%ld packets libpcap captured.\n", g_pkt_stat.ps_recv);
        fprintf(stderr, "%ld packets libpcap drop.\n", g_pkt_stat.ps_drop);
    }
}
#endif

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void callback_signal_que(int sig_no)
{
    switch(sig_no)
    {
        case SIGALRM:
            que_timeout();
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
static void que_timeout()
{
    if (SHM_BLOCK == g_block_flag)
    {
        g_capture_cmd = UNLOCK_SHM_CMD;
    }
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void init_global_var()
{
    g_block_flag = SHM_NOT_BLOCK;
    g_capture_cmd = LOCK_SHM_CMD;
    g_can_capture = SAIL_TRUE;

    memset(&g_pkt_stat,0x00,PKTS_STAT_SIZE);
    memset(&g_old_pkt_stat,0x00,PKTS_STAT_SIZE);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void send_ok_to_parent(void)
{
    pipe_msg_to_parent(PIPE_CAPTURE_OK,"");
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
static void print_cfg_par(QUE_ID shm_start_addr,int que_num)
{
    register int i;

    for(i = 0;i < que_num;i++)
    {
        printf("capture que key[%d] = %ld\n",i,(long)(shm_start_addr+i)->shmKey);
        printf("sem key[%d] = %ld\n",i,(long)(shm_start_addr+i)->semKey);
        printf("que_blk_num[%d] = %d\n",i,(shm_start_addr+i)->iQueBlkNum);
        printf("que_blk_size[%d] = %d\n",i,(shm_start_addr+i)->iQueBlkSize);
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
static void print_itf_capture_par(PAR_ITF_CAPTURE *par_itf_capture_id)
{
    printf("[Capture]nic name = %s\n",par_itf_capture_id->nic_name);
    printf("[Capture]nic no = %d\n",par_itf_capture_id->nic_no);
    printf("[Capture]que num = %d\n",par_itf_capture_id->que_num);

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
static void printf_ether_hdr(unsigned char *packet)
{
    ETHER_HDR_ID eth_hdr = NULL;
	
    eth_hdr = (ETHER_HDR_ID)packet;

    printf("ether_dhost = %d\n",ntohs(eth_hdr->ether_dhost));
    printf("ether_shost = %d\n",ntohs(eth_hdr->ether_shost));
    printf("ether_type = %d\n",ntohs(eth_hdr->ether_type));
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void printf_ip_hdr(unsigned char *packet)
{
    IP_HDR_ID ip_hdr = (IP_HDR_ID)(packet + sizeof(ETHER_HDR));

    printf("ip_src = %s\n",inet_ntoa(ip_hdr->ip_src));
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
#ifdef INC_PT_PKT_CNT
static void print_packet(const unsigned char *h)
{
    unsigned char str[1518];

    memset(str,0x00,1518);
    strcpy(str,h);
   // memcpy(str,h,1518);
   // str[DEF_SNAPLEN]='\0';

    printf("\n[pkt]:%s\n",str);
}
#endif
/**********************************
*func name:比较报文过滤模块
*function:
*parameters:
*call:
*called:
*return:
*/
int filter_pcap_pkt(struct singleton_t *p,unsigned long eth_ip)
{
	int i;
	ETHER_HDR_ID ether_hdr_id = (ETHER_HDR_ID)p->pkt;
	IP_HDR_ID ip_hdr_id = NULL;
	TCP_HDR_ID tcp_hdr_id = NULL;
	UDP_HDR_ID udp_hdr_id = NULL;
	unsigned short ether_type=0;

	int ether_len = 0;
	int ip_hdr_len =0;
	char block_type =0;
	int data_len;
	if((p->hdr)->caplen <sizeof(struct tagIP_HDR)+sizeof( struct tagTCP_HDR ))
		return -1;
	ether_type = ntohs(ether_hdr_id->ether_type);	
	if(ether_type == 0x8100)
		ether_len = ETHER_HDR_SZIE+4; 
	else
		ether_len = ETHER_HDR_SZIE;
	ip_hdr_id  = (IP_HDR_ID)(p->pkt+ether_len);
	if((ip_hdr_id->ip_src.s_addr==eth_ip)||(ip_hdr_id->ip_dst.s_addr==eth_ip))
	{
		//printf("equal device ip ,filter ip ok \n");
		return -1;
	}
	ip_hdr_len = (ip_hdr_id->ip_vhl&0x0f)*4;
	
	if(ip_hdr_id->ip_p == IPPROTO_TCP)
	{
		tcp_hdr_id = (TCP_HDR_ID)(p->pkt+ether_len+ip_hdr_len);
		if((tcp_hdr_id->th_offx2 & 0x0f)==0x0e)
		{
			return -1;
		}
		if(tcp_hdr_id->th_flags == 0x04 ||tcp_hdr_id->th_flags == 0x14 ||\
			tcp_hdr_id->th_flags ==0x01||tcp_hdr_id->th_flags ==0x11)
			return 0;

		if(queue_sem_lock(m_ip_block_queue_semid) == -1)
		{
			DEBUG("get sem 1 id fail\n");
			return 0;
		}

		if(g_ip_block_queue_info.exist_num >= g_ip_block_queue_info.total_num)
		{
			g_ip_block_queue_info.read_index = (++g_ip_block_queue_info.read_index)%g_ip_block_queue_info.total_num;
		}else
		{
			g_ip_block_queue_info.exist_num++;
		}
		
		memcpy((char*)(g_ip_block_queue_id[g_ip_block_queue_info.write_index].src_mac), ether_hdr_id->ether_shost, ETHER_ADDR_LEN);
		memcpy((char*)(g_ip_block_queue_id[g_ip_block_queue_info.write_index].dst_mac), ether_hdr_id->ether_dhost, ETHER_ADDR_LEN);
		g_ip_block_queue_id[g_ip_block_queue_info.write_index].src_ip = (unsigned long)(ip_hdr_id->ip_src.s_addr);
		g_ip_block_queue_id[g_ip_block_queue_info.write_index].dst_ip = (unsigned long)(ip_hdr_id->ip_dst.s_addr);

		g_ip_block_queue_id[g_ip_block_queue_info.write_index].src_port = tcp_hdr_id->th_sport;
		g_ip_block_queue_id[g_ip_block_queue_info.write_index].dst_port = tcp_hdr_id->th_dport;

			
		data_len = ntohs(ip_hdr_id->ip_len) - ip_hdr_len - TH_OFF(tcp_hdr_id)<<2;
		g_ip_block_queue_id[g_ip_block_queue_info.write_index].next_seqno = tcp_hdr_id->th_seq;
		if(data_len > 0)
		{
			g_ip_block_queue_id[g_ip_block_queue_info.write_index].ackno = htonl(ntohl(tcp_hdr_id->th_ack) + data_len);
		}else
		{
			g_ip_block_queue_id[g_ip_block_queue_info.write_index].ackno = tcp_hdr_id->th_ack;
		}
		g_ip_block_queue_id[g_ip_block_queue_info.write_index].ts = (p->hdr)->ts;
		g_ip_block_queue_info.write_index = (++g_ip_block_queue_info.write_index)%g_ip_block_queue_info.total_num;

		while(queue_sem_unlock(m_ip_block_queue_semid) == -1)
		{
			usleep(USLEEP_TIME);
		}
	}else if( ip_hdr_id->ip_p == IPPROTO_UDP)
	{
		udp_hdr_id = (UDP_HDR_ID)(p->pkt+ether_len+ip_hdr_len);
		pthread_mutex_lock(&g_udp_queue_mutex);
		
		if(g_udp_block_queue_info.exist_num >= g_udp_block_queue_info.total_num)
		{
			g_udp_block_queue_info.read_index = (++g_udp_block_queue_info.read_index)%g_udp_block_queue_info.total_num;
		}else
		{
			g_udp_block_queue_info.exist_num++;
		}
		memcpy((char*)(g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].src_mac), ether_hdr_id->ether_shost, ETHER_ADDR_LEN);
		memcpy((char*)(g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].dst_mac), ether_hdr_id->ether_dhost, ETHER_ADDR_LEN);
		g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].src_ip = (unsigned long)(ip_hdr_id->ip_src.s_addr);
		g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].dst_ip = (unsigned long)(ip_hdr_id->ip_dst.s_addr);

		g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].src_port = udp_hdr_id->uh_sport;
		g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].dst_port = udp_hdr_id->uh_dport;
//		if(ntohs(udp_hdr_id->uh_sport) == 8000 || ntohs(udp_hdr_id->uh_dport) == 8000)
//		{
//			printf("write%d:%s:%d----->",g_udp_block_queue_info.write_index, inet_ntoa(ip_hdr_id->ip_src), ntohs(udp_hdr_id->uh_sport));
//			printf("%s:%d\n", inet_ntoa(ip_hdr_id->ip_dst), ntohs(udp_hdr_id->uh_dport));
//		}

		g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].data_len = ip_hdr_len + 8;
		memcpy(g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].data, (char*)ip_hdr_id, g_udp_close_queue_ptr[g_udp_block_queue_info.write_index].data_len);
		g_udp_block_queue_info.write_index = (++g_udp_block_queue_info.write_index)%g_udp_block_queue_info.total_num;
		pthread_mutex_unlock(&g_udp_queue_mutex);
	}
	return 0;
}





/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
unsigned long Get_Manage_Ipsaddr(char *manage_nic)
{
    FILE *fp = NULL;
    char buf[1024];
    char *keyAddr =NULL;
    char tmp_path[512];
    char *szBuf=NULL;
    char mm[64];
    unsigned long saddr=0;
    sprintf(tmp_path,"/etc/sysconfig/network-scripts/ifcfg-%s",manage_nic);
    fp = fopen(tmp_path,"r+");
    if (NULL == fp)
        return 0;
    while (!feof(fp))
    {
        memset(buf,0x00,1024);
        if (NULL == fgets(buf,1024,fp))
            continue;
        keyAddr = strstr(buf,"IPADDR=");
        if (NULL == keyAddr)
        {
            continue;
        }
        szBuf = (char *)buf+sizeof(char)*7;
        strcpy(buf,szBuf);
        memcpy(mm,buf,strlen(buf));
        saddr = inet_addr(mm);
        fclose(fp);
        return saddr;
    }
    fclose(fp);
    return 0;
}

void read_http_warning()
{	
	char http_warning_file[256] = {0};
	sprintf(http_warning_file,"%s","/eAudit/conf/http_warning.html.in");
	FILE* file = fopen(http_warning_file, "r");
	if (file == NULL)
	{
		strcpy(g_HttpWarning, 
 				"HTTP/1.1 200 OK\r\n\
				Content-Type: text/html; Language=GB2312\r\n\
				Content-Length: 348\r\n\
  				\r\n\
  				<html>\r\n\
				<body topmargin=50>\r\n\
				<table width=360 align=center border=2 cellpadding=2 cellspacing=1 bordercolor=#ffaa00>\r\n\
				<tr><td align=left>SNAM安全警告</td></tr>\r\n\
				</table>\r\n\
				<table width=360 height=120 align=center border=2 cellpadding=2 cellspacing=1 bordercolor=#ffaa00>\r\n\
				<tr><td align=center>你无权访问，请与管理员联系。</td></tr>\r\n\
				</table>\r\n\
				</body>\r\n\
				</html>");
	}
	else
	{
		char rbuf[1024] = {0};
		rbuf[sizeof(rbuf)-1] = '\0';
		size_t bytes = fread(rbuf, sizeof(char), sizeof(rbuf)-1, file);
		fclose(file);
		snprintf(g_HttpWarning, sizeof(g_HttpWarning), 
				"HTTP/1.1 200 OK\r\n\
				Content-Type: text/html; Language=GB2312\r\n\
				Content-Length: %d\r\n\
				\r\n\
				%s", bytes, rbuf);
	}
}
