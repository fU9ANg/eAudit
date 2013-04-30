
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
#include <sys/sem.h>

#include <stdarg.h> 
#include <time.h>
#include <sys/time.h>
#include <sys/param.h>

#include <signal.h>
#include <sys/mman.h>
#include <syslog.h>
#include <errno.h>

#include "eAudit_config.h"
#include "eAudit_log.h"
#include "eAudit_sem.h"
#include "eAudit_shm.h"
#include "eAudit_mem.h"
#include "eAudit_dir.h"
#include "eAudit_shm_que.h"
#include "eAudit_single_run.h"
#include "eAudit_res_callback.h"
#include "eAudit_timer.h"
#include "eAudit_pipe.h"

#include "sail_ip.h"
#include "sail_ether.h"
#include "sail_tcp.h"
#include "sail_udp.h"

#include "filter_pub.h"
#include "interface_capture.h"
#include "interface_filter.h"
#include "interface_pub.h"
#include "interface_analyze.h"
#include "interface_block.h"
#include "filter_debug.h"
#include "filter_signal.h"
#include "filter_file.h"
#include "filter_packets.h"
#include "filter_pkt_file.h"
#include "filter_main.h"

#define INC_ANALYSE_MODEL

/*global var*/
PKT_FILE_LIST g_file_list;

FILTER_STAT g_pkt_stat;
FILTER_STAT g_old_pkt_stat;

int g_can_close_file_num = 0;

int g_pro_num = 0;
unsigned long g_file_size = 0;
REDIRECTION_PORT_INFO_ID redirect_port_addr =NULL;
unsigned long  cur_redirect_port_num= 0;
PROTECTED_RESOURCE_ID dynamic_protect_resource_addr=NULL;
unsigned long max_dynamic_protect_resource_num=0;
unsigned long sem_id=-1;
unsigned long g_protect_rule_id = 0;
unsigned long authorize_id = 0;
unsigned long usr_id = 0;
unsigned long res_index=0;
unsigned char direction;
unsigned long network_index=0;
int g_block_flag = SHM_NOT_BLOCK;
static char g_stat_file_path[MAX_FILE_PATH_SIZE];

int g_can_filter = SAIL_TRUE;
unsigned char g_Has_Arp_Flag = 0;
int ether_hdr_real_len = 0;
unsigned char Has_8021q_flag = 0;
unsigned char g_tcp_flag =0;
TCP_CLOSEINFO g_tcpclose_info;

unsigned long src_ip;
unsigned long dst_ip;
unsigned char smac[20];
unsigned char dmac[20];



/*function declaration*/
static void filter_stop(void);
static void filter_stop_signal_handler(int signo);

static void get_itf_filter_par(PAR_ITF_FILTER *par_itf_filter_id,char *s);
static void print_itf_par(PAR_ITF_FILTER *par_itf_filter_id);
static void print_cfg_file_set(CFG_FILE_SET_ID cfg_file_set_id);
static void init_filter_global_var(char *nic_name);

static int reg_filter_heap_num(int heap_num);
//static int reg_filter_heap(void *heap_addr);
static int reg_filter_shm_num(int shm_num);
static int reg_filter_shm(void *shm_addr,int shm_id);
static int reg_filter_sem_num(int sem_num);

#ifdef SIGINFO
    static void signal_report_stat(void);
    static void report_filter_stat_siginfo(int sig_no);
#endif

static void callback_signal_stat(int sig_no);
static int cmp_filter_stat_record();
static int report_filter_stat();

//static void make_pkt_file_name(char *file_name, char *orig_name, int cnt, int max_chars);
PORT_MAP_ID make_rule_map(PORT_INDEX_RULE_ID port_rule_addr);

//static void mmap_file_timout(unsigned long file_ivl_sec,char *pkt_file_dir,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr);
static void mmap_file_timout_proc(unsigned long file_ivl_sec,char *pkt_file_dir,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr,\
                                  NOW_PKT_FILE_ID p);

//static void insert_file_list_next(NOW_PKT_FILE_ID file_id);
//static void remove_file_list_next(NOW_PKT_FILE_ID file_id);
//static void change_file_list_hdr(void);
//static NOW_PKT_FILE_ID get_file_list_hdr(void);

static int filter_rename(char *pkt_file_dir,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr,NOW_PKT_FILE_ID pkt_file_id);
static void unmmap_all_file(char *pkt_file_dir,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr);
static void init_protected_resources_list_info(ARP_FILTER_INFO_ID arp_addr,SUPPORT_PRO_NODE_ID pro_addr,\
						PROTECTED_RESOURCE_ID rule_pool_addr,unsigned long *rule_num);
static int ip_packet_and_analysis(PROTECTED_RESOURCE_ID rule_pool_addr ,char *pkt_addr,int packet_type);
static int ip_packet_or_analysis(PROTECTED_RESOURCE_ID rule_pool_addr ,char *pkt_addr,int packet_type,unsigned char *hit_direction);
static int filter_packet(ARP_FILTER_INFO_ID arp_addr,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr,PROTECTED_RESOURCE_ID rule_pool_addr,\
			char *pkt_addr,FILTER_HIT_UNIT_ID fiter_hit_addr,unsigned long *hit_num,unsigned long rule_num);
static int com_network_res_id(const void* a,const void *b);
static int com_usr_list_id(const void* a,const void *b);
PROTECTED_RESOURCE_ID kkk3 = NULL;

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void SIGXCPU_proc(int no)
{
    printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@SIGXCPU_proc.\n");
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void SIGXFSZ_proc(int no)
{
    printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@SIGXFSZ_proc.\n");
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void SIGILL_proc(int no)
{
    printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@SIGILL_proc.\n");
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void SIGSEGV_proc(int no)
{
    printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@SIGSEVG_proc.\n");
    abort();
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void SIGBUS_proc(int no)
{
    printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@SIGBUS_proc.\n");
    abort();
}

void READ_Redirect_Pr(int signo){
    int i,j;
    unsigned long rule_id,dymatic_ip,dymatic_port;
    struct in_addr ip;
    if(SIGUSR1 == signo){
     	if(((redirect_port_addr->flag==1)||(redirect_port_addr->flag==5)||(redirect_port_addr->flag==3))&&(cur_redirect_port_num==max_dynamic_protect_resource_num)){
                   // sem_lock(dymanic_semid);
                     redirect_port_addr->flag = 0;
		    //sem_unlock(dymanic_semid);
			return;
     	}
	if((redirect_port_addr->flag==1)||(redirect_port_addr->flag==3)||(redirect_port_addr->flag==5)){
                
		dynamic_protect_resource_addr[cur_redirect_port_num].rule_id = redirect_port_addr->redirect_info.rule_id;
		dynamic_protect_resource_addr[cur_redirect_port_num].pro_no= redirect_port_addr->redirect_info.pro_id;
		strcpy(dynamic_protect_resource_addr[cur_redirect_port_num].pro_name,redirect_port_addr->redirect_info.pro_name);
		dynamic_protect_resource_addr[cur_redirect_port_num].dispose_object_relation =OR;
		dynamic_protect_resource_addr[cur_redirect_port_num].ethernet_type = 1;
		dynamic_protect_resource_addr[cur_redirect_port_num].mode_switch = redirect_port_addr->redirect_info.mode_switch;
                
	dynamic_protect_resource_addr[cur_redirect_port_num].transfer_type =redirect_port_addr->redirect_info.filter_pkt_type;
       		dynamic_protect_resource_addr[cur_redirect_port_num].res_index = redirect_port_addr->redirect_info.res_index;
		dynamic_protect_resource_addr[cur_redirect_port_num].use_ip_flag = SIP_DIP;
		dynamic_protect_resource_addr[cur_redirect_port_num].use_mac_flag = NO_USE;
		dynamic_protect_resource_addr[cur_redirect_port_num].use_port_flag = SPORT_DPORT;
		dynamic_protect_resource_addr[cur_redirect_port_num].sip.single_port = redirect_port_addr->redirect_info.port;
                
		dynamic_protect_resource_addr[cur_redirect_port_num].sip.ip = redirect_port_addr->redirect_info.ip;
		dynamic_protect_resource_addr[cur_redirect_port_num].sip.mask =htonl(4294967295);
		dynamic_protect_resource_addr[cur_redirect_port_num].sip.src_port_express = SINGLE;
		ip.s_addr = redirect_port_addr->redirect_info.ip;
		dynamic_protect_resource_addr[cur_redirect_port_num].dip.single_port = redirect_port_addr->redirect_info.port;
		dynamic_protect_resource_addr[cur_redirect_port_num].dip.ip = redirect_port_addr->redirect_info.ip;
		dynamic_protect_resource_addr[cur_redirect_port_num].dip.mask = htonl(4294967295);
		dynamic_protect_resource_addr[cur_redirect_port_num].dip.dst_port_express = SINGLE;
		cur_redirect_port_num++;
		if((redirect_port_addr->flag==3)||(redirect_port_addr->flag==5)){
		
			dynamic_protect_resource_addr[cur_redirect_port_num].rule_id = redirect_port_addr->redirect_info.rule_id;
			dynamic_protect_resource_addr[cur_redirect_port_num].pro_no= redirect_port_addr->redirect_info.pro_id;
			strcpy(dynamic_protect_resource_addr[cur_redirect_port_num].pro_name,redirect_port_addr->redirect_info.pro_name);
			dynamic_protect_resource_addr[cur_redirect_port_num].dispose_object_relation =OR;
			dynamic_protect_resource_addr[cur_redirect_port_num].ethernet_type = 1;
			dynamic_protect_resource_addr[cur_redirect_port_num].mode_switch = redirect_port_addr->redirect_info.mode_switch;
              
			dynamic_protect_resource_addr[cur_redirect_port_num].transfer_type =0;
       			dynamic_protect_resource_addr[cur_redirect_port_num].res_index = redirect_port_addr->redirect_info.res_index;
			dynamic_protect_resource_addr[cur_redirect_port_num].use_ip_flag = SIP_DIP;
			dynamic_protect_resource_addr[cur_redirect_port_num].use_mac_flag = NO_USE;
			dynamic_protect_resource_addr[cur_redirect_port_num].use_port_flag = SPORT_DPORT;
			dynamic_protect_resource_addr[cur_redirect_port_num].sip.single_port = redirect_port_addr->redirect_info.port;
			dynamic_protect_resource_addr[cur_redirect_port_num].sip.ip = redirect_port_addr->redirect_info.ip;
			dynamic_protect_resource_addr[cur_redirect_port_num].sip.mask = htonl(4294967295);
			dynamic_protect_resource_addr[cur_redirect_port_num].sip.src_port_express = SINGLE;
			ip.s_addr = redirect_port_addr->redirect_info.ip;
			dynamic_protect_resource_addr[cur_redirect_port_num].dip.single_port = redirect_port_addr->redirect_info.port;
			dynamic_protect_resource_addr[cur_redirect_port_num].dip.ip = redirect_port_addr->redirect_info.ip;
			dynamic_protect_resource_addr[cur_redirect_port_num].dip.mask = htonl(4294967295);
			dynamic_protect_resource_addr[cur_redirect_port_num].dip.dst_port_express = SINGLE;
			cur_redirect_port_num++;
		}
		//sem_lock(dymanic_semid);
		redirect_port_addr->flag = 0;
		//sem_unlock(dymanic_semid);
		return;
	}
	if((redirect_port_addr->flag==2)||(redirect_port_addr->flag==4)||(redirect_port_addr->flag==6)){
		if(cur_redirect_port_num ==0)
			return;
		else{
				//printf("tcp udp delete ok \n");
				rule_id = redirect_port_addr->redirect_info.rule_id;
                                dymatic_ip = redirect_port_addr->redirect_info.ip;
				dymatic_port = redirect_port_addr->redirect_info.port;
				for(i=0;i<cur_redirect_port_num;i++){
					if((rule_id == dynamic_protect_resource_addr[i].rule_id)&&(dymatic_ip == dynamic_protect_resource_addr[i].dip.ip)&&\
						(dymatic_ip == dynamic_protect_resource_addr[i].sip.ip)&&(dymatic_port == dynamic_protect_resource_addr[i].sip.single_port)&&\
						(dymatic_port == dynamic_protect_resource_addr[i].dip.single_port))
						break;
				}
				if(i==cur_redirect_port_num)
					return;
				memset((char *)(dynamic_protect_resource_addr+i),0x00,protected_resource_size);

				if(i<cur_redirect_port_num-1){
					for(j = i;j<cur_redirect_port_num-1;j++)
							memcpy((char *)&dynamic_protect_resource_addr[j],(char *)&dynamic_protect_resource_addr[j+1],protected_resource_size);
				memset((char *)&dynamic_protect_resource_addr[cur_redirect_port_num-1],0x00,protected_resource_size);
				}
				--cur_redirect_port_num;
                                if((redirect_port_addr->flag==4)||(redirect_port_addr->flag==6)){
					for(i=0;i<cur_redirect_port_num;i++){
						if((rule_id == dynamic_protect_resource_addr[i].rule_id)&&(dymatic_ip == dynamic_protect_resource_addr[i].dip.ip)&&\
						(dymatic_ip == dynamic_protect_resource_addr[i].sip.ip)&&(dymatic_port == dynamic_protect_resource_addr[i].sip.single_port)&&\
						(dymatic_port == dynamic_protect_resource_addr[i].dip.single_port))
							break;
					}
					if(i==cur_redirect_port_num)
						return;
					memset((char *)(dynamic_protect_resource_addr+i),0x00,protected_resource_size);

					if(i<cur_redirect_port_num-1){
						for(j = i;j<cur_redirect_port_num-1;j++)
							memcpy((char *)&dynamic_protect_resource_addr[j],(char *)&dynamic_protect_resource_addr[j+1],protected_resource_size);
					memset((char *)&dynamic_protect_resource_addr[cur_redirect_port_num-1],0x00,protected_resource_size);
					}
					--cur_redirect_port_num;
				}
				//sem_lock(dymanic_semid);
				redirect_port_addr->flag = 0;
			      //  sem_unlock(dymanic_semid);
				return;
		}
	}
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
int log_pri = LOG_DEBUG;
int main(int argc,char **argv)
{
	sleep(30);
	int t;///xiehongbo add
    register int i,j,k,n,m;
    register int que_idx;
   // int log_pri = LOG_DEBUG;	
	  
    PAR_ITF_FILTER par_itf_filter;
    
    FUNC_SWITCH func_switch;
    CFG_FILE_SET cfg_file_set;
    int nic_no;
    int que_num;
    key_t run_cfg_shm_key;
    key_t rule_pool_shm_key;
    key_t pro_table_shm_key;
    char pkt_file_dir[MAX_DIR_SIZE + 1];
    unsigned long  protect_rule_num = 0;
    struct timeval tv;
    struct timezone tz;

    
#ifdef MULTITASK_FILTER
    key_t pkt_wr_info_key;
#endif
#ifdef _INC_POOL_SEM
    int rule_pool_sem_id;
#endif
#ifdef _MULTITASK_FILTER
    key_t pro_sem_id;
#endif

    key_t pro_shm_id;
    int cfg_shm_id;
    int que_shm_id;
	
    key_t que_shm_key = 0;
    key_t que_sem_key = 0;
    register char *shm_addr = NULL;
    char *shm_blk_addr = NULL;
    QUE_ID shm_start_addr = NULL;
    int que_blk_num = 0;
    int que_blk_size = 0;
    unsigned long pkt_size = 0;
    

    int semid = DEF_SEM_ID_VAL;
    int empty_semid = DEF_SEM_ID_VAL;
    int full_semid = DEF_SEM_ID_VAL;
    int shm_id;

    char pkt_file_name_prefix[MAX_FILE_PATH_SIZE+1];
    char pkt_file_name_prefix_add_one[MAX_FILE_PATH_SIZE+1];
    char pkt_file_name[MAX_FILE_PATH_SIZE+1];
    char pkt_file_name_add_one[MAX_FILE_PATH_SIZE+1];
    char tmp_pkt_file_name[MAX_FILE_PATH_SIZE+1];
    
    int ret;
    int fd = DEF_FILE_DES_VAL;
    unsigned long file_no = 1;
    unsigned long file_tmp_no=0;

    register char *opts = NULL;

    register SUPPORT_PRO_NODE_ID pro_tbl_shm_addr = NULL;
    register PROTECTED_RESOURCE_ID rule_pool_addr = NULL;
    register ARP_FILTER_INFO_ID arp_filter_addr =NULL;
    register AUTHORIZE_ACCESS_NETWORK_ID authorize_network_addr =NULL;
    register USR_LIST_MEM_ID usr_list_addr = NULL;	
#ifdef MULTITASK_FILTER
    PKT_FILE_PROC_INFO_ID pkt_wr_info_addr  = NULL;
#endif
    int pro_no;
    AUTHORIZE_ACCESS_NETWORK_ID authorize_network_id= NULL;
    unsigned long authorize_network_num =0;
    USR_LIST_MEM_ID usr_list_id = NULL;
    unsigned long usr_list_num = 0;

#ifdef INC_PT_PKT
    IP_HDR *ip_hdr;
#endif

    SHM_QUE_ADDR_ID shm_que_addr = NULL;
 
    struct itimerval ovalue_pkt;

    register NOW_PKT_FILE_ID pkt_file_id = NULL;   
    FILTER_HIT_UNIT_ID filter_hit_id = NULL;
    char *mapped_buf = NULL;

    unsigned long deposit_ivl_sec;
    unsigned long file_ivl_sec;
    unsigned long filter_hit_num =0;
   /*2009 05 02 \D4\F6\BC\D3\D7\E8\B6Ϲ\A6\C4\DC*/
    unsigned long tcpfirstclosequeque_num = 0;
    TCP_CLOSEINFO_ID g_tcpfirstclose_addr = NULL;
//    TCPCLOSE_QUEUE_PTR_INFO_ID g_tcpclose_hdr_addr = NULL;

    INFO("Enter Filter process.\n");
 
    if (argc <= 0)
    {
        error("[Err]No interface parameters.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"no interface parameters.");
        exit(EXIT_FAILURE);
    }
   
    opts = strdup(argv[0]);
    if (NULL == opts)
    {
        error("[Err]copy arg fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"copy arg fail.");
        exit(EXIT_FAILURE);
    }

    signal(SIGKILL, filter_stop_signal_handler);
    signal(SIGTERM, filter_stop_signal_handler);

    //test
    signal(SIGXCPU,SIGXCPU_proc);
    signal(SIGXFSZ,SIGXFSZ_proc);
    signal(SIGILL,SIGILL_proc);
    signal(SIGSEGV,SIGSEGV_proc); 
    signal(SIGUSR1,READ_Redirect_Pr);
    //signal(SIGBUS,SIGBUS_proc); 
 
    init_log("filter",FILE_LOG,0);
    set_base_dir(SNAM_LOG_DIR);
 
#ifdef _DEBUG
    DEBUG("par = %s\n",opts);
#endif

    get_itf_filter_par(&par_itf_filter,opts);
    FREE(opts);
	
#ifdef _DEBUG
    print_itf_par(&par_itf_filter);
#endif

    nic_no = par_itf_filter.nic_no;
    g_pro_num = par_itf_filter.pro_num;
    que_num = par_itf_filter.que_num;

    
    memset(&func_switch,0x00,FUNC_SWITCH_FILTER_SIZE);
    func_switch = par_itf_filter.func_switch;
    
    memset(&cfg_file_set,0x00,CFG_FILE_SET_SIZE);
    cfg_file_set = par_itf_filter.cfg_file_set;

#ifdef _DEBUG
    print_cfg_file_set(&cfg_file_set);
#endif    

    g_file_size = cfg_file_set.maxPktFileSize;
    //printf("#######g_file_size = %u\n",g_file_size);
 //   dymanic_semid = par_itf_filter.dymanic_sem_id;
    run_cfg_shm_key = par_itf_filter.run_cfg_shm_key;
    rule_pool_shm_key = par_itf_filter.protected_resources_key;
    protect_rule_num =  par_itf_filter.protected_resources_num;
    pro_table_shm_key = par_itf_filter.pro_table_shm_key;
    strcpy(pkt_file_dir,par_itf_filter.pkt_file_dir);
    deposit_ivl_sec = par_itf_filter.deposit_ivl_sec;
   authorize_network_num= par_itf_filter.authorize_network_num;////-1
   usr_list_num = par_itf_filter.usr_num;///-1
   tcpfirstclosequeque_num= par_itf_filter.fst_block_queque_num;

   
    file_ivl_sec = deposit_ivl_sec + INCREASE_FILTER_IVL;
    if (file_ivl_sec < DEF_PKT_FILE_WAIT_SENCONDS)
        file_ivl_sec = DEF_PKT_FILE_WAIT_SENCONDS;
	
	
#ifdef MULTITASK_FILTER
    pkt_wr_info_key = par_itf_filter.pkt_wr_info_key;
#endif    
    /*\D4\F6\BC\D3\D7\E8\B6Ϲ\A6\C4\DCģ\BF\E9*/
    INFO("Get filter par OK");
#if 0
    if((sem_id = Get_Sem_Ip_Queque_SemID(par_itf_filter.ipqueque_sem_key))==-1){
		error("[Err]GET ip queque sem  fail.\n");
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"GET ip queque sem fail.");
        	exit(EXIT_FAILURE);
    }

    Sem_V(0, sem_id);
    Sem_Unlock(0, sem_id);
    if((shm_id = shmget(par_itf_filter.tcpclosequeptr_key,0,IPC_CREAT))<-1)
    {
		error("[Err]GET ip queque ptr shm  fail.\n");
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"GET ip queque ptr shm fail.");
        	exit(EXIT_FAILURE);
    }
    if((g_tcpclose_hdr_addr=(TCPCLOSE_QUEUE_PTR_INFO_ID)shmat(shm_id,NULL,0))==NULL){
		error("[Err]GET ip queque ptr attach  fail.\n");
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"GET ip queque ptr attach fail.");
        	exit(EXIT_FAILURE);

    }
    memset(g_tcpclose_hdr_addr,0,TCPCLOSE_QUEUE_PTR_SIZE);
    if((shm_id = shmget(par_itf_filter.tcpclosefirstque_key,0,IPC_CREAT))<-1)
    {
		error("[Err]GET ip first queque ptr shm  fail.\n");
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"GET ip first queque ptr shm fail.");
        	exit(EXIT_FAILURE);
    }
    if((g_tcpfirstclose_addr=(TCP_CLOSEINFO_ID)shmat(shm_id,NULL,0))==NULL){
		error("[Err]GET ip first queque ptr attach  fail.\n");
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"GET ip first queque ptr attach fail.");
        	exit(EXIT_FAILURE);
    }
    memset((char *)g_tcpfirstclose_addr,0,TCP_CLOSE_INFO_SIZE*tcpfirstclosequeque_num);
   /*\CD\EA\B3\C9\D7\E8\B6\CFģ\BF鹲\CF\ED\C4ڴ\E6\B3\F5ʼ\BB\AF\B9\A4\D7\F7*/
#endif
    cfg_shm_id = shmget(run_cfg_shm_key,0,IPC_CREAT);
    if (cfg_shm_id < 0)
    {
        error("[Err]GET cfg shm fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"get cfg shm fail.");
        exit(EXIT_FAILURE);
    }
    
    INFO("Get cfg shm id OK");

    shm_start_addr = (QUE_ID)shmat(cfg_shm_id,NULL,SHM_RDONLY);
    if (!shm_start_addr)
    {
        error("[Err]Attach cfg shm fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
        exit(EXIT_FAILURE);
    }
    
    shm_que_addr = (SHM_QUE_ADDR_ID)calloc(SHM_QUE_ADDR_SIZE,que_num);
    if (NULL == shm_que_addr)
    {
        error("[Err]Calloc for que shm addr fail.\n");
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Calloc for que shm addr fail.");
        exit(EXIT_FAILURE);
    }
    
    for (i = 0;i < que_num;i++)
    {
        que_idx = nic_no*que_num + i;
        que_shm_key = (shm_start_addr + que_idx)->shmKey;
		
        /*get que shm id*/
        que_shm_id = shmget(que_shm_key,0,IPC_CREAT);
        if (que_shm_id < 0)
        {
            error("[Err]Get capture que shm fail.\n");
	     FREE(shm_que_addr);
            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"get que shm fail.");
            exit(EXIT_FAILURE);
        }
    
        /*attch the que shm*/
        shm_addr = shmat(que_shm_id,NULL,0);
        if (!shm_addr)
        {
            error("[Err]Attach capture que shm fail.\n");
	    FREE(shm_que_addr);
            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach que shm fail.");
            exit(EXIT_FAILURE);
        }
        
        que_sem_key = (shm_start_addr + que_idx)->semKey;
        semid = semget(que_sem_key,0,IPC_CREAT);
        if (semid < 0)
        {
            error("[Err]Get que mutex sem id fail.\n");
	    FREE(shm_que_addr);
            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get que mutex sem id fail.");
            exit(EXIT_FAILURE);
        } 

	empty_semid = semget(que_sem_key + EMPTY_SEM_IVL,0,IPC_CREAT);
        if (empty_semid < 0)
        {
            error("[Err]Get que empty sem id fail.\n");
	    FREE(shm_que_addr);
            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get que sem id fail.");
            exit(EXIT_FAILURE);
        } 

	full_semid = semget(que_sem_key + FULE_SEM_IVL,0,IPC_CREAT);
        if (full_semid < 0)
        {
            error("[Err]Get que full sem id fail.\n");
	    FREE(shm_que_addr);
            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get que full sem id fail.");
            exit(EXIT_FAILURE);
        } 
       
        (shm_que_addr + i)->shm_que_addr = shm_addr;
        (shm_que_addr + i)->blk_num = (shm_start_addr + que_idx)->iQueBlkNum;
        (shm_que_addr + i)->blk_size = (shm_start_addr + que_idx)->iQueBlkSize;
        (shm_que_addr + i)->sem_id = semid;
	(shm_que_addr + i)->empty_semid = empty_semid;
	(shm_que_addr + i)->full_semid = full_semid;
    }
    if(pro_table_shm_key>0){
    pro_shm_id = shmget(pro_table_shm_key,0,IPC_CREAT);
    if (pro_shm_id < 0)
    {
        error("[Err]Get support proocols table shm fail.\n");
        FREE(shm_que_addr);
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get support proocols table shm fail.");
        exit(EXIT_FAILURE);
    }

    pro_tbl_shm_addr = (SUPPORT_PRO_NODE_ID)shmat(pro_shm_id,NULL,SHM_RDONLY);
    if (!pro_tbl_shm_addr)
    {
        error("[Err]Attach support proocols table shm fail.\n");
        FREE(shm_que_addr);
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach support proocols table shm fail.");
        exit(EXIT_FAILURE);
    } 
   }
   if(rule_pool_shm_key>0){
    	shm_id = shmget(rule_pool_shm_key,0,IPC_CREAT);
    	if (shm_id < 0)
    	{
        	error("[Err]Get protect rules pool shm fail.\n");
        	FREE(shm_que_addr);
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get protect rules shm fail.");
        	exit(EXIT_FAILURE);
    	}

    	rule_pool_addr = (PROTECTED_RESOURCE_ID)shmat(shm_id,NULL,0);
    	if (!rule_pool_addr)
    	{
        	error("[Err]Attach protect rules pool shm fail.\n");
        	FREE(shm_que_addr);
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach protect rules pool shm fail.");
        	exit(EXIT_FAILURE);
    	} 
  }
   arp_filter_addr = (ARP_FILTER_INFO_ID)calloc(arp_filter_info_size,1);
   if(arp_filter_addr ==NULL){
		error("[Err]alloc mem for arp filter info  fail.\n");
        	FREE(shm_que_addr);
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"alloc mem for arp filter info  fail.");
        	exit(EXIT_FAILURE);
   }
  init_protected_resources_list_info(arp_filter_addr,pro_tbl_shm_addr,rule_pool_addr,&protect_rule_num);
  pkt_file_id = (NOW_PKT_FILE_ID)calloc(NOW_PKT_FILE_SIZE,g_pro_num);
  if (NULL == pkt_file_id)
  {
        error("[Err]Calloc for protocols files info fail.\n");
        FREE(shm_que_addr);
        write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Calloc for protocols files info fail.");
        exit(EXIT_FAILURE);
  }
  /*\B5õ\BD\CD\F8\C2\E7\CA\DAȨ\CA\FD\BE\DD*/
  if(par_itf_filter.authorize_network_key!=0){
 		shm_id = shmget(par_itf_filter.authorize_network_key,0,IPC_CREAT);
    		if (shm_id < 0)
    		{
        		error("[Err]Get network authorize shm fail.\n");
        		FREE(shm_que_addr);
        		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get network authorize  shm fail.");
        		exit(EXIT_FAILURE);
    		}

    		authorize_network_addr = (AUTHORIZE_ACCESS_NETWORK_ID)shmat(shm_id,NULL,0);
   		 if (!authorize_network_addr)
    		{
        		error("[Err]Attach network authorize  shm fail.\n");
        		FREE(shm_que_addr);
        		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach network authorize  shm fail.");
        		exit(EXIT_FAILURE);
    		} 
  }	
  /*\B5õ\BD\B6˿\DA\D6ض\A8\CF\F2*/
      if(par_itf_filter.redirect_port_key>0){
		shm_id = shmget(par_itf_filter.redirect_port_key,0,IPC_CREAT);
    		if (shm_id < 0)
    		{
        		error("[Err]Get redirection port  shm fail.\n");
        		FREE(shm_que_addr);
        		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get  redirection port    shm fail.");
        		exit(EXIT_FAILURE);
    		}
    		redirect_port_addr = (REDIRECTION_PORT_INFO_ID)shmat(shm_id,NULL,0);
      		if (!redirect_port_addr)
    		{
        		error("[Err]Attach  redirection port   shm fail.\n");
        		FREE(shm_que_addr);
        		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach redirection port   shm fail.");
        		exit(EXIT_FAILURE);
    		} 
      	}
	max_dynamic_protect_resource_num = par_itf_filter.dynamic_protect_resource_num;
      /*\B4\B4\BD\A8\B6\AF̬\B2\DF\C2\D4\C4ڴ\E6\C7\F8\D3\F2*/
     dynamic_protect_resource_addr = (PROTECTED_RESOURCE_ID)calloc(protected_resource_size,par_itf_filter.dynamic_protect_resource_num);
     if (NULL == dynamic_protect_resource_addr)
    {
        	error("[Err]Get DYNAMIC PROTECT RESOURCE MEMORY fail.\n");
        	FREE(shm_que_addr);
        	write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get  DYNAMIC PROTECT RESOURCE MEMORY fail.");
        	exit(EXIT_FAILURE);
    }
   /* \B5õ\BD\D3û\A7\C1б\ED\B9\B2\CF\ED\C4ڴ\E6\B5\D8ַ*/
  if(par_itf_filter.usr_list_key>0){
		shm_id = shmget(par_itf_filter.usr_list_key,0,IPC_CREAT);
    		if (shm_id < 0)
    		{
        		error("[Err]Get usr list   shm fail.\n");
        		FREE(shm_que_addr);
        		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Get   usr list     shm fail.");
        		exit(EXIT_FAILURE);
    		}
		usr_list_addr = (USR_LIST_MEM_ID)shmat(shm_id,NULL,0);
      		if (!usr_list_addr)
    		{
        		error("[Err]Attach usr list    shm fail.\n");
        		FREE(shm_que_addr);
        		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attachusr list    shm fail.");
        		exit(EXIT_FAILURE);
    		} 		
  }
  	  
#ifdef SIGINFO 
    signal_report_stat();
#endif

#ifdef INC_REG_RES
    signal(SIGINT,SIG_IGN);
#endif

#ifdef INC_REG_RES
    (void)reg_filter_heap_num(0);
    (void)reg_filter_shm_num(3);
    (void)reg_filter_shm((void *)shm_start_addr,-1);
    (void)reg_filter_shm((void *)shm_addr,-1);
    (void)reg_filter_sem_num(0);
#endif

    i = 0;
    j = 0;
    file_no = 1;
    init_filter_global_var(par_itf_filter.nic_name);
    INFO("IVL SEC = %d\n",deposit_ivl_sec);
    if (ON == par_itf_filter.func_switch.iStatSwitch)
    {
        signal(SIGALRM,callback_signal_stat);
        set_sec_timer(ITIMER_REAL,deposit_ivl_sec,ovalue_pkt);  
    }
    INFO("Now get the packets from the que shm.");
    filter_hit_id = (FILTER_HIT_UNIT_ID)calloc(filter_hit_unit_size,MAX_FILTER_HIT_UNIT);
    if(NULL == filter_hit_id){
		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"alloc memory for filter hit unit fail.");
              exit(EXIT_FAILURE);
    }
		
    while (g_can_filter)
    {   
        //mmap_file_timout(file_ivl_sec,pkt_file_dir,pro_tbl_shm_addr);
	mmap_file_timout_proc(file_ivl_sec,pkt_file_dir,pro_tbl_shm_addr,pkt_file_id);	
        if (SHM_NOT_BLOCK == g_block_flag)
        {
            semid = (shm_que_addr + i)->sem_id;
	    empty_semid = (shm_que_addr + i)->empty_semid;
	    full_semid = (shm_que_addr + i)->full_semid;
            shm_addr = (shm_que_addr + i)->shm_que_addr;
            que_blk_size = (shm_que_addr + i)->blk_size;

            sem_lock(full_semid);
            sem_lock(semid);
            g_block_flag = SHM_BLOCK;
			
       #ifdef INC_FULL_FLAG
            if (SAIL_TRUE == is_empty_pkt_que(shm_addr))
            {
                sem_unlock(semid);
                sem_unlock(full_semid);
                g_block_flag = SHM_NOT_BLOCK;
                continue;
            }
        #endif
            que_blk_num = get_blk_num(shm_addr);
        }
        
        for (;;)
        {
            if (j >= que_blk_num )
            {
               ++i;
	       if (i >= que_num)
	       {
	           i = 0;
	       }
               j = 0;	
	    #ifdef INC_FULL_FLAG
                set_que_status(shm_addr,QUE_EMPTY);
            #endif
                sem_unlock(semid);
                sem_unlock(empty_semid);
                g_block_flag = SHM_NOT_BLOCK;
                
                break;
            } 
          /*\BF\AAʼȡ\B0\FC\C0\B4\B9\FD\C2˷\D6\CE\F6*/
            shm_blk_addr = get_blk_addr(shm_addr,j,que_blk_size);
  //          printf("j ==%d \n",j);
            pkt_size = get_frame_size(shm_blk_addr);		
           if(ERR == filter_packet(arp_filter_addr,pro_tbl_shm_addr,rule_pool_addr , shm_blk_addr,filter_hit_id,&filter_hit_num,protect_rule_num))
		   	goto next_packet;
		   
            for(k=0;k<filter_hit_num;k++)
            {   
                	pro_no = filter_hit_id[k].pro_no;
			g_protect_rule_id = filter_hit_id[k].rule_no;
			res_index = filter_hit_id[k].resource_index;
			direction = filter_hit_id[k].hit_direction;
			authorize_id =0;
			usr_id = 0;
			network_index = 0;

			for(t=0; t < par_itf_filter.authorize_network_num; t++)
			{
				if(g_protect_rule_id == authorize_network_addr[t].protect_resource_id)
				{
					authorize_network_id = authorize_network_addr+t;
					if((par_itf_filter.usr_num>0)&&((usr_list_id = (USR_LIST_MEM*) bsearch((const void*)authorize_network_id->usr_id,(void*)usr_list_addr,usr_list_num,USR_LIST_MEM_SIZE,com_usr_list_id))!=NULL))
					{
						switch(usr_list_id->iUsrCertifyMethod)
						{
							case 0: /*ip*/
								if(((usr_list_id->ip == src_ip)&& (direction ==1))||((usr_list_id->ip == dst_ip)&&(direction ==0)))
								{
									authorize_id = authorize_network_id->authorize_id;
  									usr_id =  authorize_network_id->usr_id;
									network_index = authorize_network_id-authorize_network_addr;
									goto next0;
								}
								break;
							case 1: /*mac*/
								if(((strncmp((char *)(usr_list_id->strMac),(char *)smac,12)==0)&&(direction ==1))||((strncmp((char *)(usr_list_id->strMac),(char *)dmac,12)==0)&&(direction ==0)))
								{
									authorize_id = authorize_network_id->authorize_id;
  									usr_id =  authorize_network_id->usr_id;
									network_index = authorize_network_id-authorize_network_addr;
									goto next0;
								}	
								break;
							case 2: /*ip and mac*/
								if((usr_list_id->ip == src_ip)&&(strncmp((char *)(usr_list_id->strMac),(char *)smac,12)==0)&&(direction ==1))
								{
									authorize_id = authorize_network_id->authorize_id;
  									usr_id =  authorize_network_id->usr_id;
									network_index = authorize_network_id-authorize_network_addr;
									goto next0;
								}	
								if((usr_list_id->ip == dst_ip)&&(strncmp((char *)(usr_list_id->strMac),(char *)dmac,12)==0)&&(direction ==0))
								{
									authorize_id = authorize_network_id->authorize_id;
  									usr_id =  authorize_network_id->usr_id;
									network_index = authorize_network_id-authorize_network_addr;
									goto next0;
								}	
								break;
							case 3: /*\C1\EE\C5\C6*/
								if((usr_list_id->ip == src_ip)/*&&(strncmp((char *)(usr_list_id->strMac),(char *)smac,12)==0)*/&& usr_list_id->usr_status==1 &&(direction ==1))
								{
									authorize_id = authorize_network_id->authorize_id;
  									usr_id =  authorize_network_id->usr_id;
									network_index = authorize_network_id-authorize_network_addr;
									goto next0;
								}	
								if((usr_list_id->ip == dst_ip)/*&&(strncmp((char *)(usr_list_id->strMac),(char *)dmac,12)==0)*/&& usr_list_id->usr_status==1 &&(direction ==0))
								{
									authorize_id = authorize_network_id->authorize_id;
  									usr_id =  authorize_network_id->usr_id;
									network_index = authorize_network_id-authorize_network_addr;
									goto next0;
								}
								break;
						}
					}
				}
           	}
#if 0
		/*1 \D7\E8\B6Ϲ\A6\C4\DC*/
  		if(rule_pool_addr[res_index].unauthorize_event.block_flag ==1){
		/*write block info  **********************/
		   if(g_tcp_flag ==1){
			Sem_Lock(0, sem_id);
			Sem_P(0,sem_id);	
			g_tcpclose_hdr_addr->lAllInputNum0++;
			if (g_tcpclose_hdr_addr->nTotalNum0 >= tcpfirstclosequeque_num)
			{
				g_tcpclose_hdr_addr->lAllDiscardNum0++;
				Sem_Unlock(0,sem_id);
				Sem_V(0,sem_id);
				continue;
			}
			memcpy((char *)(&g_tcpfirstclose_addr[g_tcpclose_hdr_addr->nWritePtr0]),(char *)&g_tcpclose_info,TCP_CLOSE_INFO_SIZE);
			g_tcpclose_hdr_addr->nWritePtr0++;
			if(g_tcpclose_hdr_addr->nWritePtr0 ==tcpfirstclosequeque_num)
				g_tcpclose_hdr_addr->nWritePtr0=0;
			g_tcpclose_hdr_addr->nTotalNum0++;
			//printf("g_tcpclose_hdr_addr->nTotalNum0 = %ld\n",g_tcpclose_hdr_addr->nTotalNum0);
			Sem_Unlock(0, sem_id);
			Sem_V(0,sem_id);
		   }
		   continue;
		}
#endif
		/*2 Ĭ\C8\CF\CE\DE\C9\F3\BCƣ\AC\BEͲ\BB\D3\C3дЭ\D2\E9\CEļ\FE\A3\AC\B9\FD\C2˵\F4\B4˱\A8\CE\C4*/
	//	if((rule_pool_addr[res_index].eaudit_level.session_level == 0)||(rule_pool_addr[res_index].unauthorize_event.block_flag ==1))
		if(rule_pool_addr[res_index].unauthorize_event.block_flag ==1)
		  		continue;

next0:
                while(SAIL_TRUE)
                {           
                    if (0 == (pkt_file_id + pro_no)->start_sec)
                    {
                        fd = open_file_no_file(PKT_WR_NO_FILE_NAME,(pro_tbl_shm_addr + pro_no)->pro_name,pkt_file_dir);				
			file_no = get_file_no(fd);

                        sprintf(pkt_file_name_prefix,"%s/%s/%ld",pkt_file_dir,(pro_tbl_shm_addr + pro_no)->pro_name,\
                                  file_no);
                        sprintf(pkt_file_name,"%s%s",pkt_file_name_prefix,PKT_FILE_SUFFIX);
			sprintf(tmp_pkt_file_name,"%s%s",pkt_file_name_prefix,PKT_FILE_TMP_SUFFIX);
                        if (IS_EXIST == file_is_exist(pkt_file_name))   /*check have pkt file is not .pdat */
                        {
				if (file_no + 1 > cfg_file_set.maxPktFileNum){
					file_tmp_no = 1;
					sprintf(pkt_file_name_prefix_add_one,"%s/%s/%ld",pkt_file_dir,(pro_tbl_shm_addr + pro_no)->pro_name,\
                                  	file_tmp_no);
					sprintf(pkt_file_name_add_one,"%s%s",pkt_file_name_prefix_add_one,PKT_FILE_TMP_SUFFIX);
				}else{
					sprintf(pkt_file_name_prefix_add_one,"%s/%s/%ld",pkt_file_dir,(pro_tbl_shm_addr + pro_no)->pro_name,\
                                  file_no+1);
				      sprintf(pkt_file_name_add_one,"%s%s",pkt_file_name_prefix_add_one,PKT_FILE_TMP_SUFFIX);
				}
					
				if(IS_EXIST == file_is_exist(pkt_file_name_add_one)){
					rename(tmp_pkt_file_name,pkt_file_name);
				}else{
                            		close(fd);
                            		write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"The analysis slower than filter.");
                            		//continue;
					break;
				}
                        }
                                 
                      
                        /*mmap the file*/
                        ret = mmap_file(tmp_pkt_file_name,&((pkt_file_id + pro_no)->fd),\
                                                   g_file_size,&((pkt_file_id + pro_no)->mapped_buf));
                    #ifdef WITH_PKT_FILE_FLG
                        if (FILTER_FILE_HAS_CNT_OFFSET == ret) /*lose the pakets*/
                        {
                            if (MUNMAP_FAIL == munmap_file((pkt_file_id+pro_no)->fd,(pkt_file_id + pro_no)->mapped_buf,\
                                                                                   g_file_size))
                            {
                                DEBUG("mumap the pkt file fail.");
                                if (SHM_BLOCK == g_block_flag)
                                {
                                    sem_unlock(semid);
                                    sem_unlock(empty_semid);
                                    g_block_flag = SHM_NOT_BLOCK;
                                }
                                write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"mumap the Pkt file fail.");
                                exit(EXIT_FAILURE);
                            }
                            close(fd);
                            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"The analysis slower than filter.");
                            continue;
                        }
                    #endif
                    
                        if (SAIL_OK != ret)
                        {
                            DEBUG("mmap the Pkt file  fail[mmap_file].");
                            if (SHM_BLOCK == g_block_flag)
                            {
                                sem_unlock(semid);
                                sem_unlock(empty_semid);
                                g_block_flag = SHM_NOT_BLOCK;
                            }
                            close(fd);
                            write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"mmap the Pkt file fail.");
                            exit(EXIT_FAILURE);
                        }   
						
                        (pkt_file_id + pro_no)->offset = PKT_FILE_HDR_SIZE;  
                        (pkt_file_id + pro_no)->packets_num = 0;
                        (pkt_file_id + pro_no)->start_sec = time(NULL);  
                        (pkt_file_id + pro_no)->pro_id = pro_no;
                        (pkt_file_id + pro_no)->file_no = file_no;
                        if (file_no + 1 > cfg_file_set.maxPktFileNum)
                        {
                            set_file_no(fd,1);
                        }
                        else
                        {
                            set_file_no(fd,file_no+1);
                        }

                        close(fd);
                    }/*first write*/
                
                   
		    mapped_buf = (pkt_file_id + pro_no)->mapped_buf;
                 if (g_file_size <= (pkt_size + PKT_USR_HDR_SIZE + RULE_ID_ST_SIZE + (pkt_file_id + pro_no)->offset))
                 {	
                        (pkt_file_id + pro_no)->start_sec = 0;   
			 			 
                        set_packets_num(mapped_buf,(pkt_file_id + pro_no)->packets_num);
                        set_pcap_info(mapped_buf);

                    #ifdef WITH_PKT_FILE_FLG
                        set_file_flag(mapped_buf,HAS_CNT);
                    #endif
                        msync((void *)mapped_buf,g_file_size,MS_SYNC);

                        if (MUNMAP_FAIL == munmap_file((pkt_file_id + pro_no)->fd,(void *)mapped_buf,g_file_size))
                        {
                            DEBUG("mumap the pkt file fail.");
                            if (SHM_BLOCK == g_block_flag)
                            {
                                sem_unlock(semid);
                                sem_unlock(empty_semid);
                                g_block_flag = SHM_NOT_BLOCK;
                            }
                            write_log(log_pri,FILE_LOG,__FILE__,__LINE__,MULTITASK,"mumap the Pkt file fail.");
                            exit(EXIT_FAILURE);
                        }

                        if (-1 == filter_rename(pkt_file_dir,pro_tbl_shm_addr,pkt_file_id + pro_no))
                        {
                            //printf("rename file name fail.\n");
                            warning("rename file name fail.");
                        }
                        continue;
                    }
                    set_pkt_rule_id((mapped_buf + (pkt_file_id + pro_no)->offset));
		    (pkt_file_id + pro_no)->offset += RULE_ID_ST_SIZE;
		   /**2008/08.01*/
		   gettimeofday (&tv , &tz);
		   ((PKT_USR_HDR_ID)(mapped_buf+(pkt_file_id + pro_no)->offset))->ts = tv;
		   /**2008/08.01*/
		   if(Has_8021q_flag ==0){
                 	memcpy((void *)(mapped_buf + (pkt_file_id+pro_no)->offset),\
                                  (void *)shm_blk_addr,pkt_size + PKT_USR_HDR_SIZE);
		   	(pkt_file_id + pro_no)->offset = (pkt_file_id + pro_no)->offset + pkt_size + PKT_USR_HDR_SIZE;
		   }
		   else{
			memcpy((void *)(mapped_buf + (pkt_file_id+pro_no)->offset),\
                                  (void *)shm_blk_addr,12+PKT_USR_HDR_SIZE);
			((PKT_USR_HDR_ID)(mapped_buf+(pkt_file_id + pro_no)->offset))->cap_len -= 4;
			memcpy((void *)(mapped_buf + (pkt_file_id+pro_no)->offset)+12+PKT_USR_HDR_SIZE,\
                                  (void *)shm_blk_addr+16+PKT_USR_HDR_SIZE,pkt_size-16);
			(pkt_file_id + pro_no)->offset = (pkt_file_id + pro_no)->offset + pkt_size-4 + PKT_USR_HDR_SIZE;
		   }   
                    ++((pkt_file_id+pro_no)->packets_num);
                   // (pkt_file_id + pro_no)->offset = (pkt_file_id + pro_no)->offset + pkt_size + PKT_USR_HDR_SIZE;			
                    break;
                }
            }/*is protect pakcets*/  
	/*\BC\C7¼\B9\FD\C2˵\BDʵ\BCʱ\A8\CE\C4\CA\FDĿ*/
	    if (ON == par_itf_filter.func_switch.iStatSwitch)
           {
                    ++g_pkt_stat.us_out;
           }
next_packet:		
         
            if (ON == par_itf_filter.func_switch.iStatSwitch)
            {
                ++g_pkt_stat.us_in;
            } 

            ++j;
        }
    }/*read all ques*/

    unmmap_all_file(pkt_file_dir,pro_tbl_shm_addr);
    printf("[Filter]unmmap all packets files OK.\n");
    FREE(pkt_file_id);
    FREE(shm_que_addr);
    exit(EXIT_SUCCESS);
} /*end of main*/

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int 
reg_filter_heap_num(int heap_num)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];
  
    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    (void)get_res_reg_file_path(file_path,ALL_RES_FILE_NAME,FILTER_MODEL_NAME);                   

    if (NULL == (fp = fopen(file_path,"a+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",heap_num);
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
#if 0
static int 
reg_filter_heap(void *heap_addr)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];
  
    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    (void)get_res_reg_file_path(file_path,ALL_RES_FILE_NAME,FILTER_MODEL_NAME);       

    if (NULL == (fp = fopen(file_path,"a+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%ld",(unsigned long)heap_addr);
    fputs(buf,fp);
    fputc('\n',fp);

    fflush(fp);
    fclose(fp);

    return OK;
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
static int 
reg_filter_shm_num(int shm_num)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];

    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    (void)get_res_reg_file_path(file_path,ALL_RES_FILE_NAME,FILTER_MODEL_NAME);       

    if (NULL == (fp = fopen(file_path,"a+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",shm_num);
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
static int 
reg_filter_shm(void *shm_addr,int shm_id)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];

    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    (void)get_res_reg_file_path(file_path,ALL_RES_FILE_NAME,FILTER_MODEL_NAME);       
    if (NULL == (fp = fopen(file_path,"a+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%ld",(unsigned long)shm_addr);
    fputs(buf,fp);
    fputc('\n',fp);

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",-1);
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
static int 
reg_filter_sem_num(int sem_num)
{
    char buf[U_LONG_SIZE+1];
    FILE *fp = NULL;
    char file_path[MAX_FILE_PATH_SIZE];

    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    (void)get_res_reg_file_path(file_path,ALL_RES_FILE_NAME,FILTER_MODEL_NAME);       

    if (NULL == (fp = fopen(file_path,"a+")))
        return ERR;

    memset(buf,0x00,U_LONG_SIZE+1);
    sprintf(buf,"%d",sem_num);
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
#if 0
static void
make_pkt_file_name(char *file_name, char *orig_name, int cnt, int max_chars)
{
	if (cnt == 0 && max_chars == 0)
		strcpy(file_name, orig_name);
	else
		sprintf(file_name, "%s%0*d", orig_name, max_chars, cnt);
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
static void 
signal_report_stat(void)
{
    signal(SIGINFO, report_filter_stat_siginfo);
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
static void 
report_filter_stat_siginfo(int sig_no)
{
    if (SIGINFO == sig_no)
    {
        fprintf(stderr, "%Ld packets will filter\n", g_all_pkt_num);
        fprintf(stderr, "%Ld packets filtered\n", g_filtered_pkt_num);
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
#if 0
PORT_MAP_ID make_rule_map(PORT_INDEX_RULE_ID port_rule_addr)
{
;
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
static int report_filter_stat()
{
    int fd = DEF_FILE_DES_VAL;
    char buf[64];

    if (ERR == cmp_filter_stat_record())
        return ERR;

    if ((fd = open(g_stat_file_path,O_RDWR | O_CREAT | O_TRUNC)) < 0)
    {
        error("[Err]Open pkt stat file Fail.[in filter]");
        return ERR;
    }

    sprintf(buf,"%Ld,%Ld",g_pkt_stat.us_in,g_pkt_stat.us_out);
    if (-1 == write(fd,buf,strlen(buf)))
    {
        error("[Err]Write pkts stat file fail.");
        close(fd);
        return ERR;
    }

    close(fd);

    g_old_pkt_stat = g_pkt_stat;

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
static int cmp_filter_stat_record()
{
    if (g_pkt_stat.us_in > g_old_pkt_stat.us_in)
        return OK;

    if (g_pkt_stat.us_out > g_old_pkt_stat.us_out)
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
static void callback_signal_stat(int sig_no)
{
    switch(sig_no)
    {
        case SIGALRM:
            report_filter_stat();
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
#if 0
static void mmap_file_timout(unsigned long file_ivl_sec,char *pkt_file_dir,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr)
{
    NOW_PKT_FILE_ID now_file_id = g_file_list.head;
    time_t cur_time;	

    if (NULL == now_file_id)
        return;

    cur_time = TIME_GET();	
    if (now_file_id->start_sec > 0)
    {
        if (cur_time > now_file_id->start_sec + file_ivl_sec)
        {
            
            set_packets_num(now_file_id->mapped_buf,now_file_id->packets_num);
            set_pcap_info(now_file_id->mapped_buf);
            set_file_flag(now_file_id->mapped_buf,HAS_CNT);
	    if (MUNMAP_FAIL == munmap_file(now_file_id->fd,now_file_id->mapped_buf,g_file_size))
            {
                error("[Err]Munmap file Fail.\n");
                write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,MULTITASK,"mumap the Pkt file fail.");
                exit(EXIT_FAILURE);
            }
		 
	    g_file_list.head->start_sec = 0;   
            if (-1 == filter_rename(pkt_file_dir,pro_tbl_shm_addr,now_file_id))
            {
                warning("[Timeout Proc]rename file name fail.");
            }
            change_file_list_hdr();
        }
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
static void mmap_file_timout_proc(unsigned long file_ivl_sec,char *pkt_file_dir,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr,\
                                  NOW_PKT_FILE_ID p)
{   
    int i;
    NOW_PKT_FILE_ID now_file_id = g_file_list.head;
    time_t cur_time = TIME_GET();
    
    for (i = 0;i < g_pro_num;i++)
    {
        now_file_id = p + i;
    	if (now_file_id->start_sec > 0)
    	{
            if (cur_time > now_file_id->start_sec + file_ivl_sec)
            {
                set_packets_num(now_file_id->mapped_buf,now_file_id->packets_num);
                set_pcap_info(now_file_id->mapped_buf);
                set_file_flag(now_file_id->mapped_buf,HAS_CNT);
                if (MUNMAP_FAIL == munmap_file(now_file_id->fd,(void *)(now_file_id->mapped_buf),g_file_size))
                {
                    error("[Err]Munmap file Fail.\n");
                    write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,MULTITASK,"mumap the Pkt file fail.");
                    exit(EXIT_FAILURE);
                }

                now_file_id->start_sec = 0;
                if (-1 == filter_rename(pkt_file_dir,pro_tbl_shm_addr,now_file_id))
                {
                    warning("[Timeout Proc]rename file name fail.");
                }
        	
            }
        }
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


static void print_itf_par(PAR_ITF_FILTER *par_itf_filter_id)
{
    printf("pro num = %d\n",par_itf_filter_id->pro_num);
    printf("run_cfg_shm_key = %ld\n",(unsigned long)(par_itf_filter_id->run_cfg_shm_key));
   // printf("rule_que_shm_key = %ld\n",(unsigned long)(par_itf_filter_id->rule_que_shm_key));

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
static void get_itf_filter_par(PAR_ITF_FILTER *par_itf_filter_id,char *s)
{
    register char *p = NULL;

    memset(par_itf_filter_id,0x00,PAR_ITF_FILTER_SIZE);

    strtok(s,PAR_DELIM);
    par_itf_filter_id->nic_no = atoi(s);

    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->pro_num = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->que_num = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->cfg_file_set.maxPktFileSize = strtoul(p,NULL,10);
    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->cfg_file_set.maxPktFileNum = strtoul(p,NULL,10);
    
    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->func_switch.iAlarmSwitch = atoi(p);
    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->func_switch.iErrSwitch = atoi(p);
    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->func_switch.iStatSwitch = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->protected_resources_num = strtoul(p,NULL,10);
    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->run_cfg_shm_key = strtoul(p,NULL,10);
    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->protected_resources_key =strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->pro_table_shm_key = strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->deposit_ivl_sec = atol(p);

    p = strtok(NULL,PAR_DELIM);
    strcpy(par_itf_filter_id->pkt_file_dir,p);

    p = strtok(NULL,PAR_DELIM);
    strcpy(par_itf_filter_id->nic_name,p);
    
     p = strtok(NULL,PAR_DELIM); 
    par_itf_filter_id->authorize_network_key= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->authorize_network_num= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM); 
    par_itf_filter_id->redirect_port_key= strtoul(p,NULL,10);

     p = strtok(NULL,PAR_DELIM); 
    par_itf_filter_id->dynamic_protect_resource_num= strtoul(p,NULL,10);
    p = strtok(NULL,PAR_DELIM); 
    par_itf_filter_id->usr_list_key= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM); 
    par_itf_filter_id->usr_num= strtoul(p,NULL,10);
   
    p = strtok(NULL,PAR_DELIM); 
    par_itf_filter_id->ipqueque_sem_key= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM); 
    par_itf_filter_id->tcpclosequeptr_key= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM); 
    par_itf_filter_id->tcpclosefirstque_key = strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->fst_block_queque_num= atol(p);

    #ifdef MULTITASK_FILTER
    p = strtok(NULL,PAR_DELIM);
    par_itf_filter_id->pkt_wr_info_key = strtoul(p,NULL,10);
    #endif
	
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
static void print_cfg_file_set(CFG_FILE_SET_ID cfg_file_set_id)
{
    printf("[filter]max file num = %ld\n",cfg_file_set_id->maxPktFileNum);
    printf("[filter]max file size = %ld\n",cfg_file_set_id->maxPktFileSize);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void init_filter_global_var(char *nic_name)
{
    g_block_flag = SHM_NOT_BLOCK;

    memset(&g_pkt_stat,0x00,FILTER_STAT_SIZE);
    memset(&g_old_pkt_stat,0x00,FILTER_STAT_SIZE);
    memset(g_stat_file_path,0x00,MAX_FILE_PATH_SIZE);
    sprintf(g_stat_file_path,"%s/%s%s",PKT_STAT_FILE_DIR,nic_name,FILTER_PKT_STAT_FILE_NAME);

    g_file_list.head = NULL;
    g_file_list.tail = NULL;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
#if 0
static void insert_file_list_next(NOW_PKT_FILE_ID file_id)
{
    if (NULL == g_file_list.head)
    {
        g_file_list.head = file_id;
	g_file_list.tail = g_file_list.head;
        file_id->next = NULL;
	file_id->prev = g_file_list.head;
    }
    else
    {
        g_file_list.tail->next = file_id;
	file_id->next = NULL;
        file_id->prev = g_file_list.tail;
	g_file_list.tail = file_id;
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
#if 0
static void remove_file_list_next(NOW_PKT_FILE_ID file_id)
{
    NOW_PKT_FILE_ID prev_node_id = NULL;
    NOW_PKT_FILE_ID next_node_id = NULL;

    prev_node_id = file_id->prev;
    next_node_id = file_id->next;

    /*1*/
    if (g_file_list.head == g_file_list.tail)
    {
        if (g_file_list.head == prev_node_id)
        {
            g_file_list.head = NULL;
            g_file_list.tail = NULL;
            file_id->prev = NULL;
            file_id->next = NULL;
            memset(file_id,0x00,NOW_PKT_FILE_SIZE);
            return;
        }
        else
        {
            //error("This node not in the list.\n");
            write_log(LOG_DEBUG,FILE_LOG,__FILE__,__LINE__,MULTITASK,"This node not in the list");
            file_id->prev = NULL;
            file_id->next = NULL;
            memset(file_id,0x00,NOW_PKT_FILE_SIZE);
            return;
        }
    }

    /*2*/
    if ((NULL == next_node_id) &&(g_file_list.tail == file_id))
    {
        prev_node_id->next = NULL;
        g_file_list.tail = prev_node_id;
        file_id->prev = NULL;
        file_id->next = NULL;
        memset(file_id,0x00,NOW_PKT_FILE_SIZE);
        return;        
    }

    /*3*/
    if (g_file_list.head == prev_node_id)
    {
	g_file_list.head = next_node_id;
	next_node_id->prev = g_file_list.head;
        file_id->prev = NULL;
        file_id->next = NULL;
        memset(file_id,0x00,NOW_PKT_FILE_SIZE);
        return;
    }

    prev_node_id->next = next_node_id;
    next_node_id->prev = prev_node_id;

    file_id->prev = NULL;
    file_id->next = NULL;
    memset(file_id,0x00,NOW_PKT_FILE_SIZE);
    return;
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
#if 0
static void change_file_list_hdr(void)
{
    NOW_PKT_FILE_ID hdr_node = g_file_list.head;
    NOW_PKT_FILE_ID next_node_id = NULL;
		
    if (NULL == g_file_list.head)
        return;

    if (g_file_list.head == g_file_list.tail)
    {
        g_file_list.head->next = NULL;
        g_file_list.head->prev = NULL;
        memset(g_file_list.head,0x00,NOW_PKT_FILE_SIZE);
        g_file_list.head = NULL;
	g_file_list.tail = NULL;
    }
    else
    {
        g_file_list.head = hdr_node->next;
        g_file_list.head->prev = g_file_list.head;

        hdr_node->next = NULL;
        hdr_node->prev = NULL;
        memset(hdr_node,0x00,NOW_PKT_FILE_SIZE);
    }
	
    return;
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
#if 0
static NOW_PKT_FILE_ID get_file_list_hdr(void)
{
    NOW_PKT_FILE_ID hdr_node = g_file_list.head;
		
    if (NULL == hdr_node)
        return NULL;

    return hdr_node;
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
static void filter_stop(void)
{
    g_can_filter = SAIL_FALSE;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void filter_stop_signal_handler(int signo)
{
    //write_log(LOG_DEBUG,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Signal: Stop filter!");
    filter_stop();
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int filter_rename(char *pkt_file_dir,SUPPORT_PRO_NODE_ID 
                                         pro_tbl_shm_addr,NOW_PKT_FILE_ID pkt_file_id)
{
    char old_name[MAX_FILE_PATH_SIZE+1];
    char pkt_file_name[MAX_FILE_PATH_SIZE+1];
    int pro_no = pkt_file_id->pro_id;

    sprintf(pkt_file_name,"%s/%s/%ld%s",pkt_file_dir,(pro_tbl_shm_addr + 
              pro_no)->pro_name,\
            pkt_file_id->file_no,PKT_FILE_SUFFIX);
    sprintf(old_name,"%s/%s/%ld%s",pkt_file_dir,(pro_tbl_shm_addr + pro_no)->pro_name,\
             pkt_file_id->file_no,PKT_FILE_TMP_SUFFIX);

    return rename(old_name,pkt_file_name);
}


/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void unmmap_all_file(char *pkt_file_dir,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr)
{
    NOW_PKT_FILE_ID hdr = g_file_list.head;

    while(hdr != NULL)
    {
        if (hdr->start_sec > 0)
        {
            set_packets_num(hdr->mapped_buf,hdr->packets_num);
            set_pcap_info(hdr->mapped_buf);
            set_file_flag(hdr->mapped_buf,HAS_CNT);
	     if (MUNMAP_FAIL == munmap_file(hdr->fd,hdr->mapped_buf,g_file_size))
            {
                error("[Err]Munmap file Fail.\n");
                write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"mmap the Pkt file fail.");
                exit(EXIT_FAILURE);
            }
		 
	     (void)filter_rename(pkt_file_dir,pro_tbl_shm_addr,hdr);   
             printf("Rename packets files OK.\n");
        }

        hdr = hdr->next;
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
static int filter_packet(ARP_FILTER_INFO_ID arp_addr,SUPPORT_PRO_NODE_ID pro_tbl_shm_addr,PROTECTED_RESOURCE_ID rule_pool_addr ,char *pkt_addr,FILTER_HIT_UNIT_ID fiter_hit_addr,unsigned long *hit_num,unsigned long rule_num){
	int i,j=0;
	int packet_type =0;
	int mode_switch = 0;
	unsigned short ether_type;
    	ETHER_HDR_ID ether_hdr_id = NULL;
    	IP_HDR_ID ip_hdr_id = NULL;
	unsigned char hit_direction;
	char* now_addr=NULL;
	
       ether_hdr_real_len = 0;
	Has_8021q_flag =0;
	g_tcp_flag =0;
	if((g_Has_Arp_Flag==0)&&(rule_num==0))
		return ERR;
	if(rule_pool_addr ==NULL||pkt_addr ==NULL||fiter_hit_addr == NULL||pro_tbl_shm_addr ==NULL)
		return ERR;
	 *hit_num =0;
	 mode_switch = rule_pool_addr[0].mode_switch;
	ether_hdr_id = (ETHER_HDR_ID)(pkt_addr + BLK_HDR_SIZE);
       ether_type = ntohs(ether_hdr_id->ether_type);
	if (IS_PROTECTED_PKT != first_filter(ether_type))
		return ERR;
	/*\D4\F6\BC\D3802.1q VLAN\BC\EC\B2\E22009/04/20*/
       if(ether_type == ETHERTYPE_8021Q){
		now_addr = (char *)(pkt_addr + BLK_HDR_SIZE+ETHER_HDR_SZIE+2);
		ether_type = ntohs(*(unsigned short *)now_addr);
		ether_hdr_real_len = ETHER_HDR_SZIE+4;
		Has_8021q_flag =1;
	}else
		ether_hdr_real_len = ETHER_HDR_SZIE;
     /*\D4\F6\BC\D3802.1q VLAN \BC\EC\B2\E2\CD\EA\B3\C92009/04/20*/	 
      switch(ether_type){
		case IP_PKT_TYPE:
	/*\CF\C8ƥ\C5侲̬\B2\DF\C2\D4*/
			for(i=0;i<rule_num;i++){
				switch(rule_pool_addr[i].dispose_object_relation){
					case AND:
						  ip_hdr_id = (IP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len);
						  switch(ip_hdr_id->ip_p){
							case TCP:
								g_tcp_flag =1;
								packet_type = 1;
								break;
							case UDP:
								packet_type = 0;
								break;
							case ICMP:
								packet_type = 2;
							default:
								continue;
						  }
						  if(rule_pool_addr[i].transfer_type!= packet_type)
						  	continue;
					if(ERR == ip_packet_and_analysis((PROTECTED_RESOURCE_ID)(rule_pool_addr+i),pkt_addr,packet_type))
						 	continue;
						 fiter_hit_addr[j].pro_no = rule_pool_addr[i].pro_no;
						 fiter_hit_addr[j].rule_no = rule_pool_addr[i].rule_id;
						 fiter_hit_addr[j].resource_index = i;
						 fiter_hit_addr[j].hit_direction = 2;  /*src and dst hit */
						 if(rule_pool_addr[i].mode_switch == 1){
							*hit_num = 1;
							return OK;
						 }
						 j++;
						 continue;
					case OR:  /*\D0\E8\D0޸\C4....*/
						//printf("or relation \n");
						 ip_hdr_id = (IP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len);
						 //printf("ip_p = %d \n",ip_hdr_id->ip_p);
						  switch(ip_hdr_id->ip_p){
							case TCP:
								g_tcp_flag = 1;
								packet_type = 1;
								break;
							case UDP:
								packet_type = 0;
								break;
							case ICMP:
								packet_type = 2;
							default:
								//printf("not tcp and not udp\n");
								continue;
						  }
						 //printf("cmp ip_p over \n");
						  if(rule_pool_addr[i].transfer_type!= packet_type)
						  	continue;
                                               //printf("start ip packet_or_analysis\n");
					if(ERR == ip_packet_or_analysis((PROTECTED_RESOURCE_ID)(rule_pool_addr+i),pkt_addr,packet_type,&hit_direction)){
						continue;
					}
						 fiter_hit_addr[j].pro_no = rule_pool_addr[i].pro_no;
						 fiter_hit_addr[j].rule_no = rule_pool_addr[i].rule_id;
 						 fiter_hit_addr[j].resource_index = i;
						 fiter_hit_addr[j].hit_direction = hit_direction;
						 if(rule_pool_addr[i].mode_switch == 1){
							*hit_num = 1;
							return OK;
						 }
						 j++;
						 continue;
					default:
						break;
				}
			}
/*\D4\D9ƥ\C5䶯̬\B2\DF\C2\D4*/
			for(i=0;i<cur_redirect_port_num;i++){
				switch(dynamic_protect_resource_addr[i].dispose_object_relation){
					case AND:
						  ip_hdr_id = (IP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len);
						  switch(ip_hdr_id->ip_p){
							case TCP:
								packet_type = 1;
								break;
							case UDP:
								packet_type = 0;
								break;
							case ICMP:
								packet_type = 2;
							default:
								continue;
						  }
						  if(dynamic_protect_resource_addr[i].transfer_type!= packet_type)
						  	continue;
					if(ERR == ip_packet_and_analysis((PROTECTED_RESOURCE_ID)(dynamic_protect_resource_addr+i),pkt_addr,packet_type))
						 	continue;
						 fiter_hit_addr[j].pro_no = dynamic_protect_resource_addr[i].pro_no;
						 fiter_hit_addr[j].rule_no = dynamic_protect_resource_addr[i].rule_id;
						 fiter_hit_addr[j].resource_index =  dynamic_protect_resource_addr[i].res_index;
						 fiter_hit_addr[j].hit_direction = 2;
						 if(dynamic_protect_resource_addr[i].mode_switch == 1){
							*hit_num = 1;
							return OK;
						 }
						 j++;
						 continue;
					case OR:  /*\D0\E8\D0޸\C4....*/
						 ip_hdr_id = (IP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len);
						 //printf("ip_p = %d \n",ip_hdr_id->ip_p);
						  switch(ip_hdr_id->ip_p){
							case TCP:
								packet_type = 1;
								break;
							case UDP:
								packet_type = 0;
								break;
							case ICMP:
								packet_type = 2;
							default:
							//	printf("not tcp and not udp\n");
								continue;
						  }
						  if(dynamic_protect_resource_addr[i].transfer_type!= packet_type)
						  	continue;
					if(ERR == ip_packet_or_analysis((PROTECTED_RESOURCE_ID)(dynamic_protect_resource_addr+i),pkt_addr,packet_type,&hit_direction)){
						continue;
					}
						//printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@dynamic ok\n");
						 fiter_hit_addr[j].pro_no = dynamic_protect_resource_addr[i].pro_no;
						 fiter_hit_addr[j].rule_no = dynamic_protect_resource_addr[i].rule_id;
 						 fiter_hit_addr[j].resource_index =  dynamic_protect_resource_addr[i].res_index;
						 fiter_hit_addr[j].hit_direction = hit_direction;
						 if(dynamic_protect_resource_addr[i].mode_switch == 1){
							*hit_num = 1;
							return OK;
						 }
						 j++;
						 continue;
					default:
						break;
				}
			}

/*ƥ\C5䶯̬\B2\DF\C2\D4\CD\EA\B3\C9*/			
			if(j>0){
				*hit_num =j;
				 return OK;
			}
			return ERR;
		case ARP_PKT_TYPE:
			//printf("arp flag = %d\n",g_Has_Arp_Flag);
			if(g_Has_Arp_Flag){
				fiter_hit_addr[0].pro_no  =arp_addr->pro_id;
				fiter_hit_addr[0].rule_no=arp_addr->rule_id;
				//printf("arp pro no = %d rule id = %d\n",arp_addr->pro_id,arp_addr->rule_id);
				*hit_num = 1;
				return OK;
			}
			return ERR;
		default:
			break;
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
static int ip_packet_and_analysis(PROTECTED_RESOURCE_ID rule_pool_addr ,char *pkt_addr,int packet_type){
	UDP_HDR_ID udp_hdr_id = NULL;
	IP_HDR_ID ip_hdr_id = NULL;
    	TCP_HDR_ID tcp_hdr_id = NULL;
	ETHER_HDR_ID ether_hdr_id = NULL;
       PROTECTED_RESOURCE_ID rule_addr = rule_pool_addr;
	unsigned long hlen;
	unsigned short src_port;
    	unsigned short dst_port;
       int i;
	unsigned char circle_chect_flag =0;
	/*\C5ж\CFMAC*/
       ether_hdr_id = (ETHER_HDR_ID)(pkt_addr + BLK_HDR_SIZE);
	sprintf((char *)smac,"%.2X%.2X%.2X%.2X%.2X%.2X",ether_hdr_id->ether_shost[0],ether_hdr_id->ether_shost[1],ether_hdr_id->ether_shost[2],\
				ether_hdr_id->ether_shost[3],ether_hdr_id->ether_shost[4],ether_hdr_id->ether_shost[5]);
	sprintf((char *)dmac,"%.2X%.2X%.2X%.2X%.2X%.2X",ether_hdr_id->ether_dhost[0],ether_hdr_id->ether_dhost[1],ether_hdr_id->ether_dhost[2],\
				ether_hdr_id->ether_dhost[3],ether_hdr_id->ether_dhost[4],ether_hdr_id->ether_dhost[5]);
	switch(rule_addr->use_mac_flag){
		case SMAC:
			if(strncmp((char *)rule_addr->smac,(char *)smac,12)!=0)
				return ERR;
			break;
		case DMAC:
			if(strncmp((char *)rule_addr->dmac,(char *)dmac,12)!=0)
				return ERR;
			break;
		case SMAC_DMAC:
			if(strncmp((char *)rule_addr->smac,(char *)smac,12)!=0)
				return ERR;
			if(strncmp((char *)rule_addr->dmac,(char *)dmac,12)!=0)
				return ERR;
			break;
		case NO_USE:
		default:
			break;
	}
	/*\C5ж\CFIP*/
	ip_hdr_id = (IP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len);
	hlen = IP_HL(ip_hdr_id) << 2;
	src_ip = ip_hdr_id->ip_src.s_addr;
       dst_ip = ip_hdr_id->ip_dst.s_addr;
       if (IS_PROTECTED_PKT != second_filter(src_ip,dst_ip))
		return ERR;
	switch(rule_addr->use_ip_flag){
		case SIP:
			if(((rule_addr->sip.ip)&(rule_addr->sip.mask))!=(src_ip&(rule_addr->sip.mask)))
				return ERR;
			break;
		case DIP:
			if(((rule_addr->dip.ip)&(rule_addr->dip.mask))!=(dst_ip&(rule_addr->dip.mask)))
				return ERR;
			break;
		case SIP_DIP:
			if(((rule_addr->sip.ip)&(rule_addr->sip.mask))!=(src_ip&(rule_addr->sip.mask)))
				return ERR;
			if(((rule_addr->dip.ip)&(rule_addr->dip.mask))!=(dst_ip&(rule_addr->dip.mask)))
				return ERR;
			break;
		case NO_USE:
		default:
			break;
	}
      /*\C5ж϶˿\DA*/
      switch(rule_addr->transfer_type){
		case 1:
			tcp_hdr_id = (TCP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len + hlen);
       			src_port = ntohs(tcp_hdr_id->th_sport);
       			dst_port = ntohs(tcp_hdr_id->th_dport);
                        //printf("src port = %d dst port = %d\n",src_port,dst_port);
			break;
		case 0:
			udp_hdr_id = (UDP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len + hlen);
       			src_port = ntohs(udp_hdr_id->uh_sport);
       			dst_port = ntohs(udp_hdr_id->uh_dport);
			break;
		case 3:
			  switch(packet_type){
				case 1:
					tcp_hdr_id = (TCP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len + hlen);
       				src_port = ntohs(tcp_hdr_id->th_sport);
       				dst_port = ntohs(tcp_hdr_id->th_dport);
					break;
				case 0:
					udp_hdr_id = (UDP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len + hlen);
       				src_port = ntohs(udp_hdr_id->uh_sport);
       				dst_port = ntohs(udp_hdr_id->uh_dport);
					break;
			    default:
					return ERR;
			  }
			  break;
		case 2:
		default:
			return ERR;
	}
       switch(rule_addr->use_port_flag){
		case SPORT:
			  switch(rule_addr->sip.src_port_express){
			  	case SINGLE_PORT:
					 	if(src_port !=rule_addr->sip.single_port)
							return ERR;
						break;
				case INTERVAL_PORT:
						for(i=0;i<rule_addr->sip.interval_port_num;i++){
							if(src_port == rule_addr->sip.port_id[i].port){
								circle_chect_flag =1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				case CONTINUE_PORT:
						for(i=0;i<rule_addr->sip.continue_port_num;i++){
							if((src_port >=rule_addr->sip.continue_port_id[i].min_port)&&(src_port <=rule_addr->sip.continue_port_id[i].max_port)){
								circle_chect_flag=1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				case CONTINUE_INTERVAL_PORT:
						for(i=0;i<rule_addr->sip.interval_port_num;i++){
							if(src_port == rule_addr->sip.port_id[i].port){
								circle_chect_flag =1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						
						for(i=0;i<rule_addr->sip.continue_port_num;i++){
							if((src_port >=rule_addr->sip.continue_port_id[i].min_port)&&(src_port <=rule_addr->sip.continue_port_id[i].max_port)){
								circle_chect_flag=1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				default:
						break;
			  }
			  break;
	case DPORT:
			switch(rule_addr->dip.dst_port_express){
			  	case SINGLE_PORT:
					 	if(dst_port !=rule_addr->dip.single_port)
							return ERR;
						break;
				case INTERVAL_PORT:
						for(i=0;i<rule_addr->dip.interval_port_num;i++){
							if(dst_port == rule_addr->dip.port_id[i].port){
								circle_chect_flag =1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				case CONTINUE_PORT:
						for(i=0;i<rule_addr->dip.continue_port_num;i++){
							if((dst_port >=rule_addr->dip.continue_port_id[i].min_port)&&(dst_port <=rule_addr->dip.continue_port_id[i].max_port)){
								circle_chect_flag=1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				case CONTINUE_INTERVAL_PORT:
						for(i=0;i<rule_addr->dip.interval_port_num;i++){
							if(dst_port == rule_addr->dip.port_id[i].port){
								circle_chect_flag =1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						
						for(i=0;i<rule_addr->dip.continue_port_num;i++){
							if((dst_port >=rule_addr->dip.continue_port_id[i].min_port)&&(dst_port <=rule_addr->dip.continue_port_id[i].max_port)){
								circle_chect_flag=1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				default:
						break;
			  }
			  break;
	case SPORT_DPORT:
			 switch(rule_addr->sip.src_port_express){
			  	case SINGLE_PORT:
					 	if(src_port !=rule_addr->sip.single_port)
							return ERR;
						break;
				case INTERVAL_PORT:
						for(i=0;i<rule_addr->sip.interval_port_num;i++){
							if(src_port == rule_addr->sip.port_id[i].port){
								circle_chect_flag =1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				case CONTINUE_PORT:
						for(i=0;i<rule_addr->sip.continue_port_num;i++){
							if((src_port >=rule_addr->sip.continue_port_id[i].min_port)&&(src_port <=rule_addr->sip.continue_port_id[i].max_port)){
								circle_chect_flag=1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				case CONTINUE_INTERVAL_PORT:
						for(i=0;i<rule_addr->sip.interval_port_num;i++){
							if(src_port == rule_addr->sip.port_id[i].port){
								circle_chect_flag =1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						
						for(i=0;i<rule_addr->sip.continue_port_num;i++){
							if((src_port >=rule_addr->sip.continue_port_id[i].min_port)&&(src_port <=rule_addr->sip.continue_port_id[i].max_port)){
								circle_chect_flag=1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				default:
						break;
			  }
			/*DPORT */
			switch(rule_addr->dip.dst_port_express){
			  	case SINGLE_PORT:
					 	if(dst_port !=rule_addr->dip.single_port)
							return ERR;
						break;
				case INTERVAL_PORT:
						for(i=0;i<rule_addr->dip.interval_port_num;i++){
							if(dst_port == rule_addr->dip.port_id[i].port){
								circle_chect_flag =1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				case CONTINUE_PORT:
						for(i=0;i<rule_addr->dip.continue_port_num;i++){
							if((dst_port >=rule_addr->dip.continue_port_id[i].min_port)&&(dst_port <=rule_addr->sip.continue_port_id[i].max_port)){
								circle_chect_flag=1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						break;
				case CONTINUE_INTERVAL_PORT:
						for(i=0;i<rule_addr->dip.interval_port_num;i++){
							if(dst_port == rule_addr->dip.port_id[i].port){
								circle_chect_flag =1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
						
						for(i=0;i<rule_addr->dip.continue_port_num;i++){
							if((dst_port >=rule_addr->dip.continue_port_id[i].min_port)&&(dst_port <=rule_addr->dip.continue_port_id[i].max_port)){
								circle_chect_flag=1;
								break;
							}
						}
						if(circle_chect_flag == 0)
							return ERR;
						circle_chect_flag=0;
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
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
	
/*\B3\F5ʼ\BB\AF\B1\A3\BB\A4\D7\CAԴ\C1б\ED*/
static void init_protected_resources_list_info(ARP_FILTER_INFO_ID arp_addr,SUPPORT_PRO_NODE_ID pro_addr,PROTECTED_RESOURCE_ID rule_pool_addr,unsigned long *rule_num){
	int i,j;
	int shm_id =0;
	unsigned char chk_flag = 0;
	unsigned long rule_no=*rule_num;
	i=0;
	if(rule_no ==0||rule_pool_addr ==NULL)
		return;
	while(i<rule_no)
	{
		switch(rule_pool_addr[i].ethernet_type)
		{
			case ARP:
				 for(j=0;j<g_pro_num;j++)
				 {
				 	if(strncmp((pro_addr+j)->pro_name, "ARP", 3) == 0)
					{
							       arp_addr->pro_id = j;
								arp_addr->rule_id = rule_pool_addr[i].rule_id;
								g_Has_Arp_Flag =1;
								break;		
					}
				 }
move_protect_resource:
				 /*\D2Ƴ\FD\B4\ED\CE󱣻\A4\D7\CAԴ\C5\E4\D6\C3*/
				memset((char *)&rule_pool_addr[i],0x00,protected_resource_size);
				if(i<rule_no-1){
					for(j = i;j<rule_no-1;j++)
							memcpy((char *)&rule_pool_addr[j],(char *)&rule_pool_addr[j+1],protected_resource_size);
				memset((char *)&rule_pool_addr[rule_no-1],0x00,protected_resource_size);
				}
                                --rule_no;
				*rule_num = rule_no;
				continue;                  /*\B1\A3\B3\D6\D7\CAԴ\BAŲ\BB\B1䣬\D7\DC\D7\CAԴ\CA\FD\BC\F5һ\A3\AC\BD\F8\D0\D0\CF\C2һ\B4\CEƥ\C5\E4*/
		       case IP:
				 for(j=0;j<g_pro_num;j++)
				 {
				 	if(strcmp((pro_addr+j)->pro_name, rule_pool_addr[i].pro_name) == 0)
					{
							       rule_pool_addr[i].pro_no =j;
								chk_flag = 1;
								break;		
					}
				 }
				 if(chk_flag==0)
				  		goto move_protect_resource;
                                chk_flag =0;
			   	switch(rule_pool_addr[i].use_port_flag){
					case SPORT:
			  				switch(rule_pool_addr[i].sip.src_port_express){
			  						case INTERVAL_PORT:
											shm_id = shmget(rule_pool_addr[i].sip.interval_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].sip.port_id= (INTERVAL_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].sip.port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									case CONTINUE_PORT:
											shm_id = shmget(rule_pool_addr[i].sip.continue_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].sip.continue_port_id= (CONTINUE_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].sip.continue_port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									case CONTINUE_INTERVAL_PORT:
					     						shm_id = shmget(rule_pool_addr[i].sip.interval_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].sip.port_id= (INTERVAL_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].sip.port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
						
											shm_id = shmget(rule_pool_addr[i].sip.continue_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].sip.continue_port_id= (CONTINUE_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].sip.continue_port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									default:
											break;
			  				}
			  				break;
				case DPORT:
							switch(rule_pool_addr[i].dip.dst_port_express){
									case INTERVAL_PORT:
											shm_id = shmget(rule_pool_addr[i].dip.interval_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].dip.port_id= (INTERVAL_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].dip.port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									case CONTINUE_PORT:
											shm_id = shmget(rule_pool_addr[i].dip.continue_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].dip.continue_port_id= (CONTINUE_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].dip.continue_port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									case CONTINUE_INTERVAL_PORT:
					     						shm_id = shmget(rule_pool_addr[i].dip.interval_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].dip.port_id= (INTERVAL_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].dip.port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
						
											shm_id = shmget(rule_pool_addr[i].dip.continue_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].dip.continue_port_id= (CONTINUE_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].dip.continue_port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}	
											break;
									default:
											break;
			  			}
			 			 break;
	case SPORT_DPORT:
				//printf("sport and dport \n");
				switch(rule_pool_addr[i].sip.src_port_express){
			  						case INTERVAL_PORT:
											shm_id = shmget(rule_pool_addr[i].sip.interval_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
																									rule_pool_addr[i].sip.port_id = (INTERVAL_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].sip.port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									case CONTINUE_PORT:
											shm_id = shmget(rule_pool_addr[i].sip.continue_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].sip.continue_port_id= (CONTINUE_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].sip.continue_port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									case CONTINUE_INTERVAL_PORT:
					     						shm_id = shmget(rule_pool_addr[i].sip.interval_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].sip.port_id= (INTERVAL_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].sip.port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
						
											shm_id = shmget(rule_pool_addr[i].sip.continue_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].sip.continue_port_id= (CONTINUE_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].sip.continue_port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									default:
											break;
			  				}

							switch(rule_pool_addr[i].dip.dst_port_express){
									case INTERVAL_PORT:
											shm_id = shmget(rule_pool_addr[i].dip.interval_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].dip.port_id= (INTERVAL_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].dip.port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											//printf("get dport interval port success ok\n");
											break;
									case CONTINUE_PORT:
											shm_id = shmget(rule_pool_addr[i].dip.continue_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].dip.continue_port_id= (CONTINUE_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].dip.continue_port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
											break;
									case CONTINUE_INTERVAL_PORT:
					     						shm_id = shmget(rule_pool_addr[i].dip.interval_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].dip.port_id= (INTERVAL_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].dip.port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}
						
											shm_id = shmget(rule_pool_addr[i].dip.continue_port_shm_key,0,IPC_CREAT);
    											if (shm_id < 0)
    											{
       											error("[Err]interval port shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"interval port shm fail.");
        											goto move_protect_resource;
    											}
   											rule_pool_addr[i].dip.continue_port_id= (CONTINUE_PORT_ID)shmat(shm_id,NULL,SHM_RDONLY);
   											if (!rule_pool_addr[i].dip.continue_port_id)
    											{
        											error("[Err]Attach cfg shm fail.\n");
        											write_log(log_pri,LOG_TOOL,__FILE__,__LINE__,MULTITASK,"Attach cfg shm fail.");
       											goto move_protect_resource;
   				 							}	
											break;
									default:
											break;
			  			}
						break;
				}
				break;/*IP*/
			default:
				break;
		}
		i++;
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
static int ip_packet_or_analysis(PROTECTED_RESOURCE_ID rule_pool_addr ,char *pkt_addr,int packet_type,unsigned char *hit_direction){
	UDP_HDR_ID udp_hdr_id = NULL;
	IP_HDR_ID ip_hdr_id = NULL;
    	TCP_HDR_ID tcp_hdr_id = NULL;
	ETHER_HDR_ID ether_hdr_id = NULL;
       PROTECTED_RESOURCE_ID rule_addr = rule_pool_addr;
	unsigned long hlen,tlen,ip_len;
	unsigned short src_port;
    	unsigned short dst_port;
        int i;
	unsigned char hit_flag =0;
	PKT_QUE_BLK_HDR_ID pkt_que_blk_hdr_addr=NULL;
	pkt_que_blk_hdr_addr = (PKT_QUE_BLK_HDR_ID)pkt_addr;
	/*\C5ж\CFMAC*/
	//printf("mac analysis \n");
       	ether_hdr_id = (ETHER_HDR_ID)(pkt_addr + BLK_HDR_SIZE);
	sprintf((char *)smac,"%.2X%.2X%.2X%.2X%.2X%.2X",ether_hdr_id->ether_shost[0],ether_hdr_id->ether_shost[1],ether_hdr_id->ether_shost[2],\
				ether_hdr_id->ether_shost[3],ether_hdr_id->ether_shost[4],ether_hdr_id->ether_shost[5]);
	sprintf((char *)dmac,"%.2X%.2X%.2X%.2X%.2X%.2X",ether_hdr_id->ether_dhost[0],ether_hdr_id->ether_dhost[1],ether_hdr_id->ether_dhost[2],\
				ether_hdr_id->ether_dhost[3],ether_hdr_id->ether_dhost[4],ether_hdr_id->ether_dhost[5]);
	switch(rule_addr->use_mac_flag){
		case SMAC:
			if(strncmp((char *)rule_addr->smac,(char *)smac,12)==0)
				hit_flag |= 0x01;
			hit_flag |= 0x02;
			break;
		case DMAC:
			if(strncmp((char *)rule_addr->dmac,(char *)dmac,12)==0)
				hit_flag |= 0x02;
			hit_flag |= 0x01;
			break;
		case SMAC_DMAC:
			if(strncmp((char *)rule_addr->smac,(char *)smac,12)==0)
				hit_flag |= 0x01;
			if(strncmp((char *)rule_addr->dmac,(char *)dmac,6)==0)
				hit_flag |= 0x02;
			break;
		case NO_USE:
		default:
			hit_flag |= 0x01;
			hit_flag |= 0x02;
			break;
	}
        //printf("mac hit flag = %d\n",hit_flag);
	//printf("IP analysis\n");
	/*\C5ж\CFIP*/
	ip_hdr_id = (IP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len);
	hlen = IP_HL(ip_hdr_id) << 2;
	src_ip = ip_hdr_id->ip_src.s_addr;
       dst_ip = ip_hdr_id->ip_dst.s_addr;
	ip_len = ntohs(ip_hdr_id->ip_len);
       if (IS_PROTECTED_PKT != second_filter(src_ip,dst_ip))
		return ERR;
	switch(rule_addr->use_ip_flag){
		case SIP:
			if(((rule_addr->sip.ip)&(rule_addr->sip.mask))==(src_ip&(rule_addr->sip.mask)))
				hit_flag |=0x04;
			hit_flag |=0x08;
			break;
		case DIP:
			if(((rule_addr->dip.ip)&(rule_addr->dip.mask))==(dst_ip&(rule_addr->dip.mask)))
				hit_flag |=0x08;
			hit_flag |=0x04;
			break;
		case SIP_DIP:
			if(((rule_addr->sip.ip)&(rule_addr->sip.mask))==(src_ip&(rule_addr->sip.mask)))
				hit_flag |=0x04;
			if(((rule_addr->dip.ip)&(rule_addr->dip.mask))==(dst_ip&(rule_addr->dip.mask)))
				hit_flag |=0x08;
			break;
		case NO_USE:
		default:
			hit_flag |=0x04;
			hit_flag |=0x08;
			break;
	}
        //printf("ip hit flag = %d\n",hit_flag);
	//printf("port analysis\n");
      /*\C5ж϶˿\DA*/
      switch(rule_addr->transfer_type){
		case 1:
			tcp_hdr_id = (TCP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len + hlen);
       			src_port = ntohs(tcp_hdr_id->th_sport);
       			dst_port = ntohs(tcp_hdr_id->th_dport);
				tlen = TH_OFF(tcp_hdr_id)<<2;
                        //printf("src port = %d dst port = %d\n",src_port,dst_port);
			break;
		case 0:
			udp_hdr_id = (UDP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len + hlen);
       			src_port = ntohs(udp_hdr_id->uh_sport);
       			dst_port = ntohs(udp_hdr_id->uh_dport);
			break;
		case 3:
			  switch(packet_type){
				case 1:
					tcp_hdr_id = (TCP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len + hlen);
       				src_port = ntohs(tcp_hdr_id->th_sport);
       				dst_port = ntohs(tcp_hdr_id->th_dport);
					tlen = TH_OFF(tcp_hdr_id)<<2;
					break;
				case 0:
					udp_hdr_id = (UDP_HDR_ID)(pkt_addr + BLK_HDR_SIZE + ether_hdr_real_len + hlen);
       				src_port = ntohs(udp_hdr_id->uh_sport);
       				dst_port = ntohs(udp_hdr_id->uh_dport);
					break;
				default:
					return ERR;
			  }
			  break;
		case 2:
		default:
			return ERR;
	}
#if 0	  
	/*add block fuction define area 2009 05 02*/
	if(g_tcp_flag) {
		g_tcpclose_info.datalen = ip_len - hlen - tlen;
		g_tcpclose_info.sIP= ip_hdr_id->ip_src.s_addr;
       	g_tcpclose_info.dIP= ip_hdr_id->ip_dst.s_addr;
		g_tcpclose_info.sPort = tcp_hdr_id->th_sport;
		g_tcpclose_info.dPort = tcp_hdr_id->th_dport;
		g_tcpclose_info.seq = tcp_hdr_id->th_seq;
		if(g_tcpclose_info.datalen>0)
			g_tcpclose_info.ack_seq = htonl(ntohl(tcp_hdr_id->th_ack)+g_tcpclose_info.datalen);
		//g_tcpclose_info.seq = tcp_hdr_id->th_ack;
		//g_tcpclose_info.ack_seq = tcp_hdr_id->th_seq;
		g_tcpclose_info.ts = pkt_que_blk_hdr_addr->ts;
		//g_tcpclose_info.datalen = ip_len - hlen - tlen;
		
	} 
#endif
       switch(rule_addr->use_port_flag){
		case SPORT:
			  switch(rule_addr->sip.src_port_express){
			  	case SINGLE_PORT:
					 	if(src_port ==rule_addr->sip.single_port)
							if((hit_flag&0x01)&&(hit_flag&0x04)){
								*hit_direction = 0;
								return OK;
							}
						break;
				case INTERVAL_PORT:
						if((hit_flag&0x01)&&(hit_flag&0x04)){
							for(i=0;i<rule_addr->sip.interval_port_num;i++){
								if(src_port == rule_addr->sip.port_id[i].port){
								*hit_direction = 0;
								return OK;
							}
							}
						}
						break;
				case CONTINUE_PORT:
						if((hit_flag&0x01)&&(hit_flag&0x04)){
							for(i=0;i<rule_addr->sip.continue_port_num;i++){
								if((src_port >=rule_addr->sip.continue_port_id[i].min_port)&&(src_port <=rule_addr->sip.continue_port_id[i].max_port)){
								*hit_direction = 0;
								return OK;
							}
							
							}
						}
						break;
				case CONTINUE_INTERVAL_PORT:
						if((hit_flag&0x01)&&(hit_flag&0x04)){
							for(i=0;i<rule_addr->sip.interval_port_num;i++){
								if(src_port == rule_addr->sip.port_id[i].port){
								*hit_direction = 0;
								return OK;
							}
							}
							for(i=0;i<rule_addr->sip.continue_port_num;i++){
								if((src_port >=rule_addr->sip.continue_port_id[i].min_port)&&(src_port <=rule_addr->sip.continue_port_id[i].max_port)){
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
			switch(rule_addr->dip.dst_port_express){
			  	case SINGLE_PORT:
					 	if(dst_port ==rule_addr->dip.single_port)
							if((hit_flag&0x02)&&(hit_flag&0x08)){
								*hit_direction = 1;
								return OK;
							}
						break;
				case INTERVAL_PORT:
						if((hit_flag&0x02)&&(hit_flag&0x08)){
							for(i=0;i<rule_addr->dip.interval_port_num;i++){
								if(dst_port == rule_addr->dip.port_id[i].port){
								*hit_direction = 1;
								return OK;
							}
							}
						}
						break;
				case CONTINUE_PORT:
						if((hit_flag&0x02)&&(hit_flag&0x08)){
							for(i=0;i<rule_addr->dip.continue_port_num;i++){
								if((dst_port >=rule_addr->dip.continue_port_id[i].min_port)&&(dst_port <=rule_addr->dip.continue_port_id[i].max_port)){
								*hit_direction = 1;
								return OK;
							}
							}
						}
						break;
				case CONTINUE_INTERVAL_PORT:
						if((hit_flag&0x02)&&(hit_flag&0x08)){
							for(i=0;i<rule_addr->dip.interval_port_num;i++){
								if(dst_port == rule_addr->dip.port_id[i].port){
								*hit_direction = 1;
								return OK;
							}
							}
							for(i=0;i<rule_addr->dip.continue_port_num;i++){
								if((dst_port >=rule_addr->dip.continue_port_id[i].min_port)&&(dst_port <=rule_addr->dip.continue_port_id[i].max_port)){
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
			 switch(rule_addr->sip.src_port_express){
			  	case SINGLE_PORT:
						//printf("src port = %d rule_addr->sip.single_port =%d\n",src_port,rule_addr->sip.single_port);
					 	if(src_port ==rule_addr->sip.single_port)
							if((hit_flag&0x01)&&(hit_flag&0x04)){
								*hit_direction = 0;
								return OK;
							}
						break;
				case INTERVAL_PORT:
						if((hit_flag&0x01)&&(hit_flag&0x04)){
							for(i=0;i<rule_addr->sip.interval_port_num;i++){
								if(src_port ==rule_addr->sip.port_id[i].port){
								*hit_direction = 0;
								return OK;
							}
							}
						}
						break;
				case CONTINUE_PORT:
						if((hit_flag&0x01)&&(hit_flag&0x04)){
							for(i=0;i<rule_addr->sip.continue_port_num;i++){
								if((src_port >=rule_addr->sip.continue_port_id[i].min_port)&&(src_port <=rule_addr->sip.continue_port_id[i].max_port)){
								*hit_direction = 0;
								return OK;
							}
							}
						}
						break;
				case CONTINUE_INTERVAL_PORT:
						if((hit_flag&0x01)&&(hit_flag&0x04)){
							for(i=0;i<rule_addr->sip.interval_port_num;i++){
								if(src_port == rule_addr->sip.port_id[i].port){
								*hit_direction = 0;
								return OK;
							}
							}
							for(i=0;i<rule_addr->sip.continue_port_num;i++){
								if((src_port >=rule_addr->sip.continue_port_id[i].min_port)&&(src_port <=rule_addr->sip.continue_port_id[i].max_port)){
								*hit_direction = 0;
								return OK;
							}
							}
						}
						break;
				default:
						break;
			  }
			/*DPORT */
			switch(rule_addr->dip.dst_port_express){
			  	case SINGLE_PORT:
					 	if(dst_port ==rule_addr->dip.single_port)
							if((hit_flag&0x02)&&(hit_flag&0x08)){
								*hit_direction = 1;
								return OK;
							}
						break;
				case INTERVAL_PORT:
						if((hit_flag&0x02)&&(hit_flag&0x08)){
							for(i=0;i<rule_addr->dip.interval_port_num;i++){
								if(dst_port == rule_addr->dip.port_id[i].port){
								*hit_direction = 1;
								return OK;
							}
							}
						}
						break;
				case CONTINUE_PORT:
						if((hit_flag&0x02)&&(hit_flag&0x08)){
							for(i=0;i<rule_addr->dip.continue_port_num;i++){
								if((dst_port >=rule_addr->dip.continue_port_id[i].min_port)&&(dst_port <=rule_addr->dip.continue_port_id[i].max_port)){
								*hit_direction = 1;
								return OK;
							}
							
							}
						}
						break;
				case CONTINUE_INTERVAL_PORT:
						if((hit_flag&0x02)&&(hit_flag&0x08)){
							for(i=0;i<rule_addr->dip.interval_port_num;i++){
								if(dst_port == rule_addr->dip.port_id[i].port)
									return OK;
							}
							for(i=0;i<rule_addr->dip.continue_port_num;i++){
								if((dst_port >=rule_addr->dip.continue_port_id[i].min_port)&&(dst_port <=rule_addr->dip.continue_port_id[i].max_port)){
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
			if((hit_flag&0x02)&&(hit_flag&0x08)){
				*hit_direction = 1;
				return OK;
			}
			if((hit_flag&0x01)&&(hit_flag&0x04)){
                                *hit_direction = 0;
                                return OK;
                        }
			break;
	}
	return ERR;
}

static int com_network_res_id(const void* a,const void *b){
	if((unsigned long )a==((AUTHORIZE_ACCESS_NETWORK*)b)->protect_resource_id)
		return 0;
	else if((unsigned long )a > ((AUTHORIZE_ACCESS_NETWORK*)b)->protect_resource_id)
		return 1;
	else 
		return -1;
}
static int com_usr_list_id(const void* a,const void *b){
	if((unsigned long )a==((USR_LIST_MEM*)b)->iUsrId)
		return 0;
	else if((unsigned long )a > ((USR_LIST_MEM*)b)->iUsrId)
		return 1;
	else 
		return -1;
}

