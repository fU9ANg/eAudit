
#ifndef _CTL_CONFIG_H
#define _CTL_CONFIG_H

#define MAX_NIC_NUM 16     

/*pak files set max and min value*/
#define MIN_PKT_FILE_SIZE  40960      /*20K byte*/
#define MAX_PKT_FILE_SIZE  4194304   /*4M byte*/
#define MIN_PKT_FILE_NUM   100

/*配置文件的格式*/
typedef enum 
{
    DETAILS_FORMAT = 0,         
    BRIEFLY_FORMAT         
}EN_CFG_FILE_MODE;

#define CFG_FILE_FORMAT BRIEFLY_FORMAT

/*eAudit_sys.conf file*/
/*the eAudit sys cfg file section name and key*/
/*manage nic cfg*/
#define NICFORMANAGE_SECT     "NIC_FOR_MANAGE"
#define NICFORMANAGE_KEY        "NicForManagement"

/*sy dir cfg*/
#define SYSDIR_SECT                     "SYS_DIR"
#define PKT_FILES_DIR_KEY          "PacketsFilesDir"
#define PROTECT_RULES_FILE_DIR_KEY    "ProtectRulesFileDir"

/*packets files cfg*/
#define PKTSFILEPOOL_SECT         "PACKETS_FILE_POOL"
#define MAX_PKTFILE_SIZE_KEY   "MaxPktFileSize" 
#define MAX_PKTFILE_NUM_KEY   "MaxPktFileNum"

/*deposit interval seconds cfg*/
#define DEPOSIT_INTERVAL_SECT       "DEPOSIT_INTERVAL"
#define DEPOSIT_INTERVAL_SEC_KEY "DepositIntervalSeconds"

/*max protect rules num cfg*/
#define PROTECT_RULESNUM_SECT          "PROTECT_RULES_NUM"
#define MAX_PROTECT_RULESNUM_KEY   "MaxProtectRulesNum"
/*DC AUTH CONFIG INFO */
#define DC_AUTH_SERV_SECT "DC_AUTH_INFO"
#define DC_AUTH_SERV_IP   "Dc_Auth_Serv_Ip"
#define DC_AUTH_SERV_PORT "Dc_Auth_Serv_Port"
#define DC_WORK_MODE "Dc_Work_Mode"
#define DC_INFORM_CHILD_IP "Dc_Inform_Child_Ip"
/*monitor interval seconds cfg*/
#define MONITOR_SET                         "MONITOR_SET"
#define MONITOR_SET_TIME_INTERVALS "monitor_time_intervals"
#define MONITOR_NUM 		  "monitor_num"

/*monitor interval seconds cfg*/
#define MONITOR_HD_SET                         "HD_PRECENT_MONITOR"
#define MONITOR_HD_SET_VALS  "Hd_precent"

/*Dynamic protect resource cfg*/
#define DYNAMIC_PROTECT_RESOURCE                         "DYNAMIC_PR"
#define DYNAMIC_PROTECT_RESOURCE_NUM                "Dynamic_Protect_Resource_Num"

/*function switch cfg*/
#define FUNCSWITCH_SECT   "FUNCTION_SWITCH"
#define ALARM_SWITCH_KEY  "AlarmSwitch"
#define ERR_SWITCH_KEY    "ErrSwitch"
#define STAT_SWITCH_KEY   "StatSwitch"
#define FLOW_SWITCH_KEY   "FlowSwitch"

/*default manage nic name*/
#define DEF_MAN_NIC_NAME  "eth1"
#define DEF_DC_SERV_IP "127.0.0.1"
#define DEF_DC_SERV_PORT 5800
#define DEF_WORK_MODE  1

/*default sys dir*/
#define DEF_PKT_FILE_DIR              "./data/pkts"
#define DEF_PROTECT_RULES_DIR   "./eAudit/conf"

/*default packets files cfg*/
#define DEF_MAX_PKT_FILE_SIZE 4096*500
#define DEF_MAX_PKT_FILE_NUM  2000

/*default deposit interval seconds */
#define DEF_DEPOSIT_IVL_SEC 10
#define DEF_MONITOR_IVL_SEC 120
#define DEF_MONITOR_HD_PRECENT  80
#define DEF_MONITOR_NUM 60
#define DEF_DYNAMIC_PROTECT_RESOURCE_NUM 100
/*default protect rules num*/
#define DEF_MAX_RULES_NUM  10000

/*default block queque num */
#define DEF_MAX_FST_BLOCK_QUEQUE_NUM   100000
#define DEF_MAX_SND_BLOCK_QUEQUE_NUM   100000
#define DEF_MAX_BLOCK_IP_QUEQUE_NUM      200000
#define DEF_MAX_SND_CHECK_BLOCK_QUEQUE_NUM      100000
/*BLOCK BASIC INFO DESCRIBE*/
#define BLOCK_INFO "BLOCK_INFO"
#define FIRST_BLOCK_NUM "First_Block_Queque_num"
#define SECOND_BLOCK_NUM "Second_Block_Queque_num"
#define BLOCK_IP_QUEQUE_NUM "Block_Ip_Queque_num"
#define SECOND_CHECK_BLOCK_NUM "Second_Check_Queque_Num"
/*default function switch*/
#define DEF_ALARM_SWITCH  ON        
#define DEF_ERR_SWITCH      ON        
#define DEF_STAT_SWITCH     ON 
#define DEF_FLOW_SWITCH     OFF 

/*file size in packets files cfg about*/
#define MAX_MULTIPLIERS_NUM 5
#define PER_FILE_SIZE_DELIM   "*"

/*capture_NIC.conf*/
/*file header*/
#define NIC_CFG_HEAD_SECT   "HEAD"
#define NICNUM_KEY        "NumOfNIC"
#define QUENUM_KEY       "QueNumOfNIC"

/*NIC basic info*/
#define NIC_SECT_PREFIX     "NIC"
#define QUE_SECT_MIDDLE   "_QUE"
#define NICNAME_KEY      "Name"
#define HEADQUE_SHM_KEY  "HeadQueShmKey"
#define HEADQUE_SEM_KEY   "HeadQueSemKey"

/*que info*/
#define QUE_SHM_KEY            "QueShmKey"
#define QUE_SEM_KEY            "QueSemKey"
#define QUEBLKNUM_KEY        "QueBlockNum"
#define QUEBLKSIZE_KEY       "QueBlockSize"

/*2008-11-13*/
/*CFG LIST INFO*/
#define LIST_COMMON_KEY  "COMMON"
#define LIST_NUM_KEY         "LIST_NUM"
#define LIST_MODE_GETE_KEY "MODE_GETE"

#define LIST_INFO_KEY         "LIST_INFO"
#define LIST_RESOURCE_KEY "INFO"



/*the default value of capture_NIC.conf file key value*/
/*default file header value*/
#define DEF_NIC_NUM  1   
#define DEF_QUE_NUM  MIN_QUE_NUM

/*default NIC basic info value*/
#define DEF_NIC_NAME          "eth0"      
#define DEF_HEAD_SHM_KEY   ((key_t)1198322)   
#define DEF_HEAD_SEM_KEY   ((key_t)1198322)   

/*default que info value*/
#define DEF_QUE_SEM_KEY              ((key_t)1196322)    
#define DEF_QUE_SHM_KEY              ((key_t)1296322)     
#define DEF_QUE_BLK_NUM         2000        
#define DEF_QUE_BLK_SIZE         MAX_BLK_SIZE       

typedef enum 
{
    DEF_MODE = 0,         
    READ_FILE           
}EN_GET_CFG_MODE;
#if 0
/*the header info of file*/
typedef struct tagCFG_HEAD
{
    int iNICNum;
    int iPerNICQueNum;
}CFG_HEAD,*CFG_HEAD_ID;
#define CFG_HEAD_SIZE sizeof(CFG_HEAD) 

/*the cfg header info of file*/
#define cfg_file_header_size sizeof(CFG_FILE_HEADER)

/*the NIC basic config info*/
typedef struct tagCFG_NIC_BASIC
{
    char NICName[NICNAMESIZE+1];
    key_t hdQueShmKey;
    key_t hdQueSemKey;
}CFG_NIC_BASIC,*CFG_NIC_BASIC_ID;
#define CFG_NIC_BASIC_SIZE  sizeof(CFG_NIC_BASIC)
#endif
/*the declaration of glabol function*/
extern int get_read_cfg_mode(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);

extern void get_sys_dir_by_def(OUT char *pkt_file_dir,OUT char *protect_rule_dir);
extern int get_sys_dir_by_file(char *pkt_file_dir,char *protect_rule_dir,char *file_cnt_buf);

extern int get_manage_nic_name(OUT char *nic_name,char *file_cnt_buf);
extern int check_manage_nic(char *nic_name);

extern int get_deposit_ivl_sec(OUT long *psec,char *file_cnt_buf);

extern void get_cfg_hdr_by_def(CFG_HEAD_ID cfg_hdr_ptr);
extern int get_cfg_hdr_by_file(CFG_HEAD_ID cfg_hdr_ptr,char *file_cnt_buf);

extern void get_nic_basic_info_by_def(CFG_NIC_BASIC_ID nic_basic_addr,int nic_num);
extern int get_nic_basic_info_by_file(CFG_NIC_BASIC_ID nic_basic_addr,int nic_num,char *file_cnt_buf);

extern void get_que_info_by_def(QUE_ID que_addr,int nic_num,int per_nic_que_num);
extern int get_que_info_by_file(QUE_ID que_addr,int nic_num,int per_nic_que_num,char *file_cnt_buf);

extern void get_file_set_by_def(CFG_FILE_SET_ID cfg_file_set_id);
extern int get_file_set_by_file(CFG_FILE_SET_ID cfg_file_set_id,char *file_cnt_buf);

extern void get_rulenum_set_by_def(unsigned long *rule_num);
extern int get_rulenum_set_by_file(unsigned long *rule_num,char *file_cnt_buf);

extern void get_func_switch_by_def(FUNC_SWITCH_ID func_switch_ptr);
extern int get_func_switch_by_file(FUNC_SWITCH_ID func_switch_ptr,char *file_cnt_buf);

extern void get_flow_switch_by_def(int *flag);
extern int get_flow_switch_by_file(int *flag,char *file_cnt_buf);

extern int chk_switch_val(int switch_val);
extern int check_nic_basic_info(CFG_NIC_BASIC_ID nic_basic_buf,int nic_num,char *man_nic);
extern int check_que_info(QUE_ID que_addr,int que_num);

extern int get_shm_key_array(key_t *shm_key_array,int nic_num,int per_nic_que_num,char *file_cnt_buf);
extern key_t get_max_shm_key(key_t *shm_key_array,int que_num);

extern int get_sem_key_array(key_t *sem_key_array,int nic_num,int per_nic_que_num,char *file_cnt_buf);
extern key_t get_max_sem_key(key_t *sem_key_array,int que_num);
extern int get_monitor_ivl_sec(OUT long *psec,char *file_cnt_buf);
extern int get_monitor_hd_precent(OUT long *psec,char *file_cnt_buf);
extern int get_monitor_num(OUT long *psec,char *file_cnt_buf);
extern int get_block_queque_conf_num(BLOCK_QUEQUE_NUM_ID p,char *file_cnt_buf);
extern int get_dc_serv_ip(OUT char *ip,char *file_cnt_buf);
extern int get_dc_serv_port(OUT long *psec,char *file_cnt_buf);
extern int get_dc_work_mode(OUT long *psec,char *file_cnt_buf);
extern int get_child_process_serv_ip(OUT char *ip,char *file_cnt_buf);
#endif
