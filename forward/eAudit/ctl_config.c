
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <stdarg.h>
#include <time.h>
#include <pcap.h>

#include <syslog.h>

#include "eAudit_config.h"
#include "eAudit_log.h"
#include "eAudit_mem.h"
#include "eAudit_shm_que.h"

#include "ctl_pub.h"
#include "ctl_debug.h"
#include "interface_pub.h"
#include "ctl_sys_info.h"
#include "ctl_config.h"

/*static function declaration*/
static int if_exist_nic(pcap_if_t *device_list,char *device);
static int sem_key_comp(const void *a ,const void *b);
static int is_digit_str(const char *str);

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_read_cfg_mode(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(DEF_MODE);
	
    if (NOT_EXIST == file_is_exist(file_path)) 
        return(DEF_MODE);

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)  
       return(DEF_MODE);

    if (0 == (file_size = get_file_size(file_path)))
    {  
        close(fd);
        return(DEF_MODE);
    }

    *fd_ptr = fd;
    *file_size_ptr = file_size;
	
    return(READ_FILE); 
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_cfg_hdr_by_file(CFG_HEAD_ID cfg_hdr_ptr,char *file_cnt_buf)
{
    int get_val_ok;
    
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,NIC_CFG_HEAD_SECT,NICNUM_KEY,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        cfg_hdr_ptr->iNICNum = DEF_NIC_NUM;
    }
    else
    {
        if (ERR == is_digit_str(key_val))
        {
            error("[configer file]the iNICNum set Err.\n");
            return ERR;
        }
	 cfg_hdr_ptr->iNICNum =  atoi(key_val);
    }

    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,NIC_CFG_HEAD_SECT,QUENUM_KEY,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        cfg_hdr_ptr->iPerNICQueNum = DEF_NIC_NUM;
    }
    else
    {
        if (ERR == is_digit_str(key_val))
        {
            error("[configer file]the iPerNICQueNum set Error.\n");
            return ERR;
        }
	 cfg_hdr_ptr->iPerNICQueNum =  atoi(key_val);
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_deposit_ivl_sec(OUT long *psec,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,DEPOSIT_INTERVAL_SECT,DEPOSIT_INTERVAL_SEC_KEY,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]Deposit interval seconds set err.\n");
	 return ERR;
    }
    else
    {
	 *psec = atol(key_val);
    }

    return OK;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_monitor_ivl_sec(OUT long *psec,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,MONITOR_SET,MONITOR_SET_TIME_INTERVALS,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]Deposit interval seconds set err.\n");
	 return ERR;
    }
    else
    {
	 *psec = atol(key_val);
    }

    return OK;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/

int get_monitor_num(OUT long *psec,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,MONITOR_SET,MONITOR_NUM,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]Deposit interval seconds set err.\n");
	 return ERR;
    }
    else
    {
	 *psec = atol(key_val);
    }

    return OK;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_monitor_hd_precent(OUT long *psec,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,MONITOR_HD_SET,MONITOR_HD_SET_VALS,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]Deposit interval seconds set err.\n");
	 return ERR;
    }
    else
    {
	 *psec = atol(key_val);
    }
    return OK;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_block_queque_conf_num(BLOCK_QUEQUE_NUM_ID p,char *file_cnt_buf){
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    /*get first queque num */
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,BLOCK_INFO,FIRST_BLOCK_NUM,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]get block first queque num  set err.\n");
	 return ERR;
    }
    else
    {
	 p->fst_block_queque_num= atol(key_val);
    }
     /*get snd queque num */
     memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,BLOCK_INFO,SECOND_BLOCK_NUM,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]get block snd queque num  set err.\n");
	 return ERR;
    }
    else
    {
	 p->snd_block_queque_num= atol(key_val);
    }
      /*get ip queque num */
     memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,BLOCK_INFO,BLOCK_IP_QUEQUE_NUM,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]get block ip queque num  set err.\n");
	 return ERR;
    }
    else
    {
	 p->block_ip_queque_num= atol(key_val);
    }

    /*get snd check ip  queque num */
     memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,BLOCK_INFO,SECOND_CHECK_BLOCK_NUM,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]get block ip queque num  set err.\n");
	 return ERR;
    }
    else
    {
	 p->snd_check_block_queque_num= atol(key_val);
    }
    return OK;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_dynamic_protect_resource_num(OUT long *psec,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,DYNAMIC_PROTECT_RESOURCE,DYNAMIC_PROTECT_RESOURCE_NUM,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]DYNAMIC_PROTECT_RESOURCE set err.\n");
	 return ERR;
    }
    else
    {
	 *psec = atol(key_val);
    }

    return OK;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_sys_dir_by_def(OUT char *pkt_file_dir,OUT char *protect_rule_dir)
{
    strcpy(pkt_file_dir,DEF_PKT_FILE_DIR);
    strcpy(protect_rule_dir,DEF_PROTECT_RULES_DIR);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_sys_dir_by_file(OUT char *pkt_file_dir,OUT char *protect_rule_dir,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,SYSDIR_SECT,PKT_FILES_DIR_KEY,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]Packets files dir err.\n");
	 return ERR;
    }
    else
    {
	 strcpy(pkt_file_dir,key_val);
    }

    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,SYSDIR_SECT,PROTECT_RULES_FILE_DIR_KEY,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]Protect rules file dir err.\n");
	 return ERR;
    }
    else
    {
	 strcpy(protect_rule_dir,key_val);
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_manage_nic_name(OUT char *nic_name,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,NICFORMANAGE_SECT,NICFORMANAGE_KEY,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]Manage Nic Name Set  err.\n");
	 return ERR;
    }
    else
    {
	 strcpy(nic_name,key_val);
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_dc_serv_ip(OUT char *ip,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,DC_AUTH_SERV_SECT,DC_AUTH_SERV_IP,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]DC AUTH SERV IP Set  err.\n");
	 return ERR;
    }
    else
    {
	 strcpy(ip,key_val);
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_child_process_serv_ip(OUT char *ip,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,DC_AUTH_SERV_SECT,DC_INFORM_CHILD_IP,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]DC AUTH SERV IP Set  err.\n");
	 return ERR;
    }
    else
    {
	 strcpy(ip,key_val);
    }

    return OK;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_dc_serv_port(OUT long *psec,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,DC_AUTH_SERV_SECT,DC_AUTH_SERV_PORT,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]get_dc_serv_port  set err.\n");
	 return ERR;
    }
    else
    {
	 *psec = atol(key_val);
    }
    return OK;
}
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_dc_work_mode(OUT long *psec,char *file_cnt_buf)
{
    int get_val_ok;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];    
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,DC_AUTH_SERV_SECT,DC_WORK_MODE,key_val);
    if (GET_CFG_VAL_FAIL == get_val_ok)
    {
        error("[Err]get_dc_serv_port  set err.\n");
	 return ERR;
    }
    else
    {
	 *psec = atol(key_val);
    }
    return OK;
}
/***************
/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_cfg_hdr_by_def(CFG_HEAD_ID cfg_hdr_ptr)
{
    cfg_hdr_ptr->iNICNum = DEF_NIC_NUM;
    cfg_hdr_ptr->iPerNICQueNum= DEF_QUE_NUM;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_nic_basic_info_by_def(CFG_NIC_BASIC_ID nic_basic_addr,int nic_num)
{
    int i;
    CFG_NIC_BASIC_ID tmp_addr = nic_basic_addr;

    for (i = 0;i < nic_num;i++)
    {
        strcpy(tmp_addr->NICName, DEF_NIC_NAME); 
        tmp_addr->hdQueShmKey = DEF_HEAD_SHM_KEY + i*SHM_KEY_IVL;   
	 tmp_addr->hdQueSemKey = DEF_HEAD_SEM_KEY + i*SEM_KEY_IVL;  

	 tmp_addr++;
    }
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_nic_basic_info_by_file(CFG_NIC_BASIC_ID nic_basic_addr,int nic_num,char *file_cnt_buf)
{
    int i;
    char *tmp_buf = file_cnt_buf;
    CFG_NIC_BASIC_ID tmp_addr = nic_basic_addr;
    char key_val[CFG_BLK_SIZE];   
    char sec_key[CFG_BLK_SIZE];
    char tmp_key[CFG_KEY_SIZE];

    for (i = 0;i < nic_num;i++)
    {
        memset (&tmp_key,0x00,CFG_KEY_SIZE);   
        sprintf(tmp_key,"%d",i+1);

        memset (&sec_key,0x00,CFG_BLK_SIZE);
        strcpy(sec_key,NIC_SECT_PREFIX);	
        strcat(sec_key,tmp_key);
          
        if (GET_CFG_VAL_FAIL == cfg_get_key_val(tmp_buf,sec_key,NICNAME_KEY,(tmp_addr+i)->NICName))
        {
            write_log(LOG_DEBUG,LOG_NOT_RECORD,__FILE__,__LINE__,SINGLE,"get nic name fail!");
            return ERR;   
        }

        memset (&key_val,0x00,CFG_BLK_SIZE);   
        if (GET_CFG_VAL_FAIL == cfg_get_key_val(tmp_buf,sec_key,HEADQUE_SHM_KEY,key_val))
        {
            (tmp_addr+i)->hdQueShmKey = DEF_HEAD_SHM_KEY + + i*SHM_KEY_IVL;
        }
        else
        {
            if (ERR == is_digit_str(key_val))
            {
                error("[Err]The Shm Key for packets heads Que be set Err.");
		  return ERR;
            }
			
            (tmp_addr+i)->hdQueShmKey = strtoul(key_val,NULL,10);
	     printf("hdQueShmKey = %ld \n",(tmp_addr+i)->hdQueShmKey);
        }

	 memset (&key_val,0x00,CFG_BLK_SIZE);   
        if (GET_CFG_VAL_FAIL == cfg_get_key_val(tmp_buf,sec_key,HEADQUE_SEM_KEY,key_val))
        {
            (tmp_addr+i)->hdQueShmKey = DEF_HEAD_SEM_KEY + + i*SEM_KEY_IVL;
        }
        else
        {
            if (ERR == is_digit_str(key_val))
            {
                error("[Err]The Sem Key for packets heads Que be set Err.");
		  return ERR;
            }
			
            (tmp_addr+i)->hdQueSemKey = strtoul(key_val,NULL,10);
	     printf("hdQueSemKey = %ld \n",(tmp_addr+i)->hdQueSemKey);
	  
        }
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_que_info_by_def(QUE_ID que_addr,int nic_num,int per_nic_que_num)
{
    register int i;
    int que_num;
    QUE_ID tmp_addr = que_addr;

    que_num = nic_num*per_nic_que_num;
	
    for (i = 0;i < que_num;i++)
    {
        (tmp_addr+i)->iQueBlkNum  = DEF_QUE_BLK_NUM;
	 (tmp_addr+i)->iQueBlkSize = DEF_QUE_BLK_SIZE;
	 (tmp_addr+i)->shmKey = DEF_QUE_SHM_KEY+i*SHM_KEY_IVL;
        (tmp_addr+i)->semKey = DEF_QUE_SEM_KEY+i*(SEM_KEY_IVL + EMPTY_SEM_IVL);	 
    }     
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_que_info_by_file(QUE_ID que_addr,int nic_num,int per_nic_que_num,char *file_cnt_buf)
{
    register int i;
    register int j;
	
    char *file_buf = file_cnt_buf;
    QUE_ID tmp_addr = que_addr;
	
    char key_val[CFG_BLK_SIZE];   
    char sec_key[CFG_BLK_SIZE];
    char tmp_key[CFG_BLK_SIZE];
    char tmp_sec_key[CFG_BLK_SIZE];
	
    for (i = 0;i < nic_num;i++)
    {
        memset (tmp_key,0x00,CFG_BLK_SIZE);
        sprintf(tmp_key,"%d",i+1);
		
	 memset (sec_key,0x00,CFG_BLK_SIZE);
	 strcpy(sec_key,NIC_SECT_PREFIX);	 
	 strcat(sec_key,tmp_key);    

	 memset (tmp_key,0x00,CFG_BLK_SIZE);
	 strcpy(tmp_key,QUE_SECT_MIDDLE);
	 strcat(sec_key,tmp_key);

        for (j = 0;j < per_nic_que_num;j++)
        {
            memset (tmp_sec_key,0x00,CFG_BLK_SIZE);
	     strcpy(tmp_sec_key,sec_key);
		  
	     memset (tmp_key,0x00,CFG_BLK_SIZE);
	     sprintf(tmp_key,"%d",j+1);
	     strcat(tmp_sec_key,tmp_key);

            memset(key_val,0x00,CFG_BLK_SIZE);
            if (GET_CFG_VAL_FAIL == cfg_get_key_val(file_buf,tmp_sec_key,QUE_SHM_KEY,key_val))
            {
                error("shm key err.\n");
                return ERR;   
            }
			
	     if (ERR == is_digit_str(key_val))
            {
                error("shmKey err.[%i_%j]\n",i,j);
		  return ERR;
            }
   
	     tmp_addr->shmKey = (key_t)atol(key_val);
            printf("shmkey = %ld \n",tmp_addr->shmKey);
	     memset(key_val,0x00,CFG_BLK_SIZE);
            if (GET_CFG_VAL_FAIL == cfg_get_key_val(file_buf,tmp_sec_key,QUE_SEM_KEY,key_val))
            {
            	  error("sem key err.\n");
                return ERR;
            }
			
            if (ERR == is_digit_str(key_val))
            {
                error("semKey err.[%i_%j]\n",i,j);
		  return ERR;
            }
	     tmp_addr->semKey = (key_t)atol(key_val);
            printf("semkey = %ld \n",tmp_addr->semKey);
	     memset(key_val,0x00,CFG_BLK_SIZE);
            if (GET_CFG_VAL_FAIL == cfg_get_key_val(file_buf,tmp_sec_key,QUEBLKNUM_KEY,key_val))
            {
                tmp_addr->iQueBlkNum = DEF_QUE_BLK_NUM;    
            }
	     else
	     {
	          if (ERR == is_digit_str(key_val))
                {
                    error("iQueBlkNum err.[%i_%j]\n",i,j);
		      return ERR;
                }
                tmp_addr->iQueBlkNum = atoi(key_val);
		  printf("iQueBlkNum  = %ld \n",tmp_addr->iQueBlkNum );
	     }

	     memset(key_val,0x00,CFG_BLK_SIZE);
            if (GET_CFG_VAL_FAIL == cfg_get_key_val(file_buf,tmp_sec_key,QUEBLKSIZE_KEY,key_val))
            {
                tmp_addr->iQueBlkSize = DEF_QUE_BLK_SIZE;    
            }
	     else
	     {
	         if (ERR == is_digit_str(key_val))
                {
                    error("iQueBlkSize err.[%i_%j]\n",i,j);
		      return ERR;
                }
                tmp_addr->iQueBlkSize = atoi(key_val);
		printf("iQueBlkSize = %ld \n",tmp_addr->iQueBlkSize);
	     }	
            
	      tmp_addr++;
        }			
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_file_set_by_def(CFG_FILE_SET_ID cfg_file_set_id)
{
    long per_blk_num = 0;
	
    cfg_file_set_id->maxPktFileSize  = DEF_MAX_PKT_FILE_SIZE;
    cfg_file_set_id->maxPktFileNum = DEF_MAX_PKT_FILE_NUM;

    per_blk_num = (cfg_file_set_id->maxPktFileSize )/g_sys_hw_info.fs_info.f_bsize;
    if (per_blk_num * cfg_file_set_id->maxPktFileNum > \
	 g_sys_hw_info.fs_info.f_bfree * HDD_PROPORTION)
    {
        info("[Warning]DEF file num too big.\n");
	 cfg_file_set_id->maxPktFileNum = g_sys_hw_info.fs_info.f_bfree * HDD_PROPORTION;
    }
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_file_set_by_file(CFG_FILE_SET_ID cfg_file_set_id,char *file_cnt_buf)
{
    int get_val_ok;
    register int i=0,j=0;
    register char *s = NULL;
    register char *p = NULL;
    unsigned long file_size = 1;
    unsigned long file_num;
    unsigned long num[MAX_MULTIPLIERS_NUM];

    long per_blk_num = 0;
    
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,PKTSFILEPOOL_SECT,MAX_PKTFILE_SIZE_KEY,key_val);

#ifdef _DEBUG
  //  printf("file size char = %s\n",key_val);
#endif

    if (GET_CFG_VAL_OK == get_val_ok)
    {
        s = key_val;
        i = 0;
        strtok(s,PER_FILE_SIZE_DELIM);
	 if (ERR == is_digit_str(s))
        {
            error("[Err]pkt file size err.\n");
	     return ERR;
        }
        num[i] = strtoul(s,NULL,10);
        
        while ((p = strtok(NULL,PER_FILE_SIZE_DELIM)) != NULL)
        {
            if (i >= MAX_MULTIPLIERS_NUM)
                break;

            if (ERR == is_digit_str(p))
            {
                error("[Err]pkt file size err.\n");
	         return ERR;
            }
            i++;
            num[i] = strtoul(p,NULL,10);
        }

        for (j = 0;j <= i;j++)
        {
            file_size *= num[j];
        }

	 if (file_size < MIN_PKT_FILE_SIZE)
        {
            file_size = MIN_PKT_FILE_SIZE;
        }
        else
        {
            if (file_size > MAX_PKT_FILE_SIZE)
            {
                file_size = MAX_PKT_FILE_SIZE;
            } 
        }
    }
	
    if (0 != file_size%g_sys_hw_info.fs_info.f_bsize)
    {
        error("[ERR]File size must be blocks nums.\n");
        return ERR;
    }
	
    cfg_file_set_id->maxPktFileSize = (GET_CFG_VAL_FAIL == get_val_ok ? DEF_MAX_PKT_FILE_SIZE:file_size); 
   
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,PKTSFILEPOOL_SECT,MAX_PKTFILE_NUM_KEY,key_val);
    if (GET_CFG_VAL_OK == get_val_ok)
    {
        if (ERR == is_digit_str(key_val))
        {
            error("pkt file num err.[%i_%j]\n",i,j);
	    return ERR;
        }
        file_num = strtoul(key_val,NULL,10);
	 if (file_num < MIN_PKT_FILE_NUM)
	    file_num = MIN_PKT_FILE_NUM;

	 cfg_file_set_id->maxPktFileNum = file_num;
    }
    else
    {
        cfg_file_set_id->maxPktFileNum = DEF_MAX_PKT_FILE_NUM;
    }

    per_blk_num = file_size/g_sys_hw_info.fs_info.f_bsize;
    if (per_blk_num * cfg_file_set_id->maxPktFileNum > \
	 g_sys_hw_info.fs_info.f_bfree * HDD_PROPORTION)
    {
        error("[ERR]Set file num too big.\n");
        return ERR;
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_rulenum_set_by_def(unsigned long *rule_num)
{
    *rule_num = DEF_MAX_RULES_NUM;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_rulenum_set_by_file(unsigned long *rule_num,char *file_cnt_buf)
{
    int get_val_ok;
    unsigned long max_rule_num = 0;
    
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,PROTECT_RULESNUM_SECT,MAX_PROTECT_RULESNUM_KEY,key_val);
    
#ifdef _DEBUG
   // printf("MAX RULE NUM char = %s\n",key_val);
#endif

    if (GET_CFG_VAL_OK == get_val_ok)
    {
	if (ERR == is_digit_str(key_val))
       {
           error("[Err]Max rules num set err.\n");
	    return ERR;
       }
       max_rule_num = strtoul(key_val,NULL,10);
    } 
    else
    {
        max_rule_num = DEF_MAX_RULES_NUM;
    }
 
    *rule_num = max_rule_num;

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_func_switch_by_def(FUNC_SWITCH_ID func_switch_ptr)
{
    func_switch_ptr->iAlarmSwitch = DEF_ALARM_SWITCH;
    func_switch_ptr->iErrSwitch = DEF_ERR_SWITCH;
    func_switch_ptr->iStatSwitch = DEF_STAT_SWITCH;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_func_switch_by_file(FUNC_SWITCH_ID func_switch_ptr,char *file_cnt_buf)
{
    int get_val_ok;
    
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,FUNCSWITCH_SECT,ALARM_SWITCH_KEY,key_val);
    func_switch_ptr->iAlarmSwitch = (GET_CFG_VAL_FAIL == get_val_ok ? DEF_ALARM_SWITCH:atoi(key_val));
    if (ERR == chk_switch_val(func_switch_ptr->iAlarmSwitch))
        return ERR;
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,FUNCSWITCH_SECT,ERR_SWITCH_KEY,key_val);
    func_switch_ptr->iErrSwitch = (GET_CFG_VAL_FAIL == get_val_ok ? DEF_QUE_NUM:atoi(key_val));
    if (ERR == chk_switch_val(func_switch_ptr->iErrSwitch))
        return ERR;

    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,FUNCSWITCH_SECT,STAT_SWITCH_KEY,key_val);
    func_switch_ptr->iStatSwitch = (GET_CFG_VAL_FAIL == get_val_ok ? DEF_QUE_NUM:atoi(key_val));
    if (ERR == chk_switch_val(func_switch_ptr->iStatSwitch))
        return ERR;

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_flow_switch_by_def(int *flag)
{
    *flag = DEF_FLOW_SWITCH;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_flow_switch_by_file(int *flag,char *file_cnt_buf)
{
    int get_val_ok;
    int flow_switch;
    char *tmp_buf = file_cnt_buf;
    char key_val[CFG_BLK_SIZE];
    
    memset(key_val,0x00,CFG_BLK_SIZE);
    get_val_ok = cfg_get_key_val(tmp_buf,FUNCSWITCH_SECT,FLOW_SWITCH_KEY,key_val);
    flow_switch = (GET_CFG_VAL_FAIL == get_val_ok ? DEF_FLOW_SWITCH:atoi(key_val));
    if (ERR == chk_switch_val(flow_switch))
        return ERR;

    *flag = flow_switch;

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int chk_switch_val(int switch_val)
{
    int ret = OK;

    if ((switch_val != ON) && (switch_val != OFF))
    {
        ret = ERR;
    }

    return ret;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int check_manage_nic(char *nic_name)
{
    pcap_if_t *alldevs = NULL;
    register char *errbuf = NULL;

    if (NULL == nic_name)
        return ERR;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        error("[Err]Get sys Nic list fail.\n");
        return ERR;
    }

    if (alldevs == NULL || (alldevs->flags & PCAP_IF_LOOPBACK))
    {
        error("[Err]No suitable NIC device found.\n");
	 return ERR;
    }
	
    if (SAIL_FALSE == if_exist_nic(alldevs,nic_name))
    {
        pcap_freealldevs(alldevs);
	 error("[Err]The %s NIC device don't be found.\n",nic_name);
        return ERR;
    }
  
    pcap_freealldevs(alldevs);
    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int check_nic_basic_info(CFG_NIC_BASIC_ID nic_basic_buf,int nic_num,char *man_nic)
{
    register int i,j;  
    CFG_NIC_BASIC_ID tmpaddr = nic_basic_buf;
    pcap_if_t *alldevs;
    register char *errbuf = NULL;

    if (NULL == nic_basic_buf)
        return ERR;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        DEBUG("Get nic list fail.");
        return ERR;
    }

    if (alldevs == NULL || (alldevs->flags & PCAP_IF_LOOPBACK))
    {
        DEBUG("no suitable device found");
	 return ERR;
    }
	
    for (i = 0;i < nic_num;i++)
    {
	printf("nic name = %s\n",(tmpaddr+i)->NICName);
	 if (SAIL_FALSE == if_exist_nic(alldevs,(tmpaddr+i)->NICName))
        {
             DEBUG("NO THIS NIC.");
             goto func_err;
        }

        if (0 == strcmp((tmpaddr+i)->NICName,man_nic))
        {
             error("[Err]The capture Nic same with the management NIC.\n");
             goto func_err;
        }

         for(j = i+1;j < nic_num;j++)
         {
            if (0 == strcmp((tmpaddr+i)->NICName,(tmpaddr+j)->NICName))
	        goto func_err;
            
            if ((tmpaddr+i)->hdQueShmKey == (tmpaddr+j)->hdQueShmKey)
               goto func_err;
         }
    }
  
    pcap_freealldevs(alldevs);
    return OK;

func_err:
    pcap_freealldevs(alldevs);
    return ERR;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int if_exist_nic(pcap_if_t *device_list,char *device)
{
     pcap_if_t *list = device_list;

     while (list != NULL)
     {
         if (0 == strcmp(list->name,device))
	      return SAIL_TRUE;

         list = list->next;
     }

     return SAIL_FALSE;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int sem_key_comp(const void *a ,const void *b)
{
    key_t *c1= (key_t *)a;
    key_t *c2= (key_t *)b;
    
    if (c1 > c2)
        return 1;
    
    if (c1 == c2)
        return 0;
        
    if (c1 < c2)
        return -1;

    return 0;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int check_que_info(QUE_ID que_addr,int que_num)
{
    register int i,j;
    register QUE_ID tmpaddr = que_addr;
    unsigned long all_que_size = 0;
    key_t sem_key_arry[MAX_QUE_NUM];

    if (NULL == que_addr)
        return ERR;

    for (i = 0;i < que_num;i++)
    {
        for(j = i+1;j < que_num;j++)
        {
            if ((tmpaddr+i)->shmKey == (tmpaddr+j)->shmKey)
            {
            	  error("[Err]Que shm key equal.\n");
                return ERR;
            }

            if ((tmpaddr+i)->semKey == (tmpaddr+j)->semKey)
            {
            	  error("[Err]Que sem key equal.\n");
                return ERR;
            }
        }

	 sem_key_arry[i] = (tmpaddr+i)->semKey;

	 all_que_size += ((tmpaddr+j)->iQueBlkNum)*((tmpaddr+j)->iQueBlkSize) + PKT_SHM_QUE_HDR_SIZE;
    }

    qsort(sem_key_arry,que_num,sizeof(key_t),sem_key_comp);

    for (i = 0;i < que_num;i++)
    {
        for(j = i+1;j < que_num;j++)
        {
            if ((tmpaddr+i)->semKey + EMPTY_SEM_IVL + FULE_SEM_IVL > (tmpaddr+j)->semKey)
            {
               error("[Err]NIC que sem key ivl err.\n");
	        return ERR;
            }
        }
    }

    if (all_que_size >  (g_sys_hw_info.mem_info.free_mem_size)*1024 * CAPTURE_FILTER_PROPORTION \
       * PKT_SHM_QUE_PROPORTION)
    {
       error("[Err]All que shm size too big.\n");
	return ERR;
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_shm_key_array(key_t *shm_key_array,int nic_num,int per_nic_que_num,char *file_cnt_buf)
{
    register int i;
    register int j;
	
    char *file_buf = file_cnt_buf;
    key_t *tmp_addr = shm_key_array;
	
    char key_val[CFG_BLK_SIZE];   
    char sec_key[CFG_BLK_SIZE];
    char tmp_key[CFG_BLK_SIZE];
    char tmp_sec_key[CFG_BLK_SIZE];
	
#ifdef _DEBUG
   // info("NIC number:%d\n",nic_num);
   // info("que number of per nic:%d\n",per_nic_que_num);
#endif

    for (i = 0;i < nic_num;i++)
    {
        memset (tmp_key,0x00,CFG_BLK_SIZE);
        sprintf(tmp_key,"%d",i+1);
		
	 memset (sec_key,0x00,CFG_BLK_SIZE);
	 strcpy(sec_key,NIC_SECT_PREFIX);	 
	 strcat(sec_key,tmp_key);    

	 memset (tmp_key,0x00,CFG_BLK_SIZE);
	 strcpy(tmp_key,QUE_SECT_MIDDLE);
	 strcat(sec_key,tmp_key);

        for (j = 0;j < per_nic_que_num;j++)
        {
            memset (tmp_sec_key,0x00,CFG_BLK_SIZE);
	     strcpy(tmp_sec_key,sec_key);
		  
	     memset (tmp_key,0x00,CFG_BLK_SIZE);
	     sprintf(tmp_key,"%d",j+1);
	     strcat(tmp_sec_key,tmp_key);

            memset(key_val,0x00,CFG_BLK_SIZE);
            if (GET_CFG_VAL_FAIL == cfg_get_key_val(file_buf,tmp_sec_key,QUE_SHM_KEY,key_val))
            {
                info("[Err]hey_val = %s\n",key_val);
                return ERR;   
            }

	      *tmp_addr = (key_t)atol(key_val);
	      printf("*tmp_addr = %ld \n",*tmp_addr);


	      tmp_addr++;
        }			
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
key_t get_max_shm_key(key_t *shm_key_array,int que_num)
{
    register int i;
    key_t *tmp_addr = shm_key_array;
    key_t ret_key;
    
    if (NULL == shm_key_array)
        return 0;
        
    ret_key = tmp_addr[0];
    
    for (i = 1;i < que_num;i++)
    {
        if (ret_key < tmp_addr[i])
            ret_key = tmp_addr[i];
    }
    
    return ret_key;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_sem_key_array(key_t *sem_key_array,int nic_num,int per_nic_que_num,char *file_cnt_buf)
{
    register int i,j;
	
    char *file_buf = file_cnt_buf;
    key_t *tmp_addr = sem_key_array;
	
    char key_val[CFG_BLK_SIZE];   
    char sec_key[CFG_BLK_SIZE];
	
    char tmp_key[CFG_BLK_SIZE];
    char tmp_sec_key[CFG_BLK_SIZE];
	

    for (i = 0;i < nic_num;i++)
    {
        memset (tmp_key,0x00,CFG_BLK_SIZE);
        sprintf(tmp_key,"%d",i+1);
		
	 memset (sec_key,0x00,CFG_BLK_SIZE);
	 strcpy(sec_key,NIC_SECT_PREFIX);	 
	 strcat(sec_key,tmp_key);    

	 memset (tmp_key,0x00,CFG_BLK_SIZE);
	 strcpy(tmp_key,QUE_SECT_MIDDLE);
	 strcat(sec_key,tmp_key);

        for (j = 0;j < per_nic_que_num;j++)
        {
            memset (tmp_sec_key,0x00,CFG_BLK_SIZE);
	     strcpy(tmp_sec_key,sec_key);
		  
	     memset (tmp_key,0x00,CFG_BLK_SIZE);
	     sprintf(tmp_key,"%d",j+1);
	     strcat(tmp_sec_key,tmp_key);

            memset(key_val,0x00,CFG_BLK_SIZE);
            if (GET_CFG_VAL_FAIL == cfg_get_key_val(file_buf,tmp_sec_key,QUE_SEM_KEY,key_val))
            {
                info("hey_val = %s\n",key_val);
                return ERR;   
            }
	      *tmp_addr = (key_t)atol(key_val);
	       tmp_addr++;
        }			
    }

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
key_t get_max_sem_key(key_t *sem_key_array,int que_num)
{
    int i;
    key_t *tmp_addr = sem_key_array;
    key_t ret_key;
    
    if (NULL == sem_key_array)
        return 0;
        
    ret_key = tmp_addr[0];
        
    for (i = 1;i < que_num;i++)
    {
      
        if (ret_key < tmp_addr[i])
            ret_key = tmp_addr[i];
    }
    
    return ret_key;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int is_digit_str(const char *str)
{
    if (NULL == str)
        return ERR;

    while (*str != '\0')
    {
        if (!isdigit(*str))
            return ERR;

	++str;
    }

    return OK;
}

