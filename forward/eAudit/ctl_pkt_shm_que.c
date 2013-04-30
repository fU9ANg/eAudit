
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

#include <sys/param.h>
#include <syslog.h>

#include "eAudit_config.h"
#include "eAudit_log.h"
#include "eAudit_sem.h"
#include "eAudit_shm.h"
#include "eAudit_mem.h"
#include "eAudit_dir.h"
#include "eAudit_shm_que.h"
#include "eAudit_res_callback.h"

#include "interface_pub.h"
#include "ctl_pub.h"
#include "ctl_debug.h"
#include "ctl_pkt_shm_que.h"

/*global var*/
#ifdef WITH_FILE_REG_RES
RES_REG_INFO g_res_info;
#endif

/*static  function declaration */
static int create_full_sem(key_t key);
static int create_empty_sem(key_t key);

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int create_per_nic_shm(int per_nic_que_num,QUE_ID que_addr,NIC_QUE_INFO_ID nic_que_info_id)
{
    register int i;

    QUE_ID cfg_que_addr = que_addr;
    register NIC_QUE_INFO_ID nic_que_info_addr = nic_que_info_id;

    int shmid;
    int shmsize;
    key_t shmKey;
    char *shm_que_addr = NULL;

    int que_blk_num;
    int que_blk_size;

    for (i = 0;i < per_nic_que_num;i++)
    {
        que_blk_num = cfg_que_addr->iQueBlkNum;
        que_blk_size = cfg_que_addr->iQueBlkSize;
        shmKey = cfg_que_addr->shmKey;
		
        shmsize = que_blk_num*que_blk_size + PKT_SHM_QUE_HDR_SIZE;
        if ((shmid = shmget(shmKey,shmsize,IPC_CREAT|IPC_EXCL)) < 0)
        {
		shmid= get_shm(shmKey);
		if(shmid<0){
			   error("[Err]Create shm que fail.\n");
			   (void)del_per_nic_shm(i,nic_que_info_id);
        		   return ERR;
		}
		DEL_SHM(shmid);
	      shmid = shmget(shmKey,shmsize,IPC_CREAT|IPC_EXCL);
	       if(shmid<0){
		   	  error("[Err]Create shm que fail.\n");
			   (void)del_per_nic_shm(i,nic_que_info_id);
        		  return ERR;
	       }
        }
        
        shm_que_addr = (char *)shmat(shmid,NULL,0);
        if (!shm_que_addr)
        {
            error("[Err]Attach shm fail.\n");
            (void)del_per_nic_shm(i,nic_que_info_id);
            return ERR;
        }

        nic_que_info_addr->shmid= shmid;
        nic_que_info_addr->shm_addr = shm_que_addr;

        cfg_que_addr++;
        nic_que_info_addr++;
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
int create_per_nic_sem(int per_nic_que_num,QUE_ID cfgQueInfoAddr,NIC_QUE_INFO_ID nic_que_info_id)
{
    register int i;
    int semid;

    key_t sem_Key;
    QUE_ID cfg_que_addr = cfgQueInfoAddr;
    NIC_QUE_INFO_ID nic_que_addr = nic_que_info_id;

    for(i = 0;i < per_nic_que_num;i++)
    {
        sem_Key = (cfg_que_addr+i)->semKey;
        if ((semid = create_sem(sem_Key)) < 0)
        {
            semid = get_sem(sem_Key);
	    if(semid<0){
            	error("[Err]Create shm que mutex sem fail.\n");
            	(void)del_per_nic_sem(i,nic_que_info_id);
           	 return ERR;
	    }
	    del_sem(semid);
	    semid = create_sem(sem_Key);
	     if(semid<0){
            	error("[Err]Create shm que mutex sem fail.\n");
            	(void)del_per_nic_sem(i,nic_que_info_id);
           	 return ERR;
	    }
        }
        (nic_que_addr + i)->semid = semid;

        /*full sem*/		
	if ((semid = create_full_sem(sem_Key + FULE_SEM_IVL)) < 0)
        {

	     semid = get_sem(sem_Key);
	    if(semid<0){
             error("[Err]Create shm que full sem fail.\n");
            	(void)del_per_nic_sem(i,nic_que_info_id);
           	 return ERR;
	    }
	    del_sem(semid);
	    semid = create_sem(sem_Key);
	     if(semid<0){
            	 error("[Err]Create shm que full sem fail.\n");
            	(void)del_per_nic_sem(i,nic_que_info_id);
           	 return ERR;
	    }
 
        }
	 (nic_que_addr + i)->full_semid = semid;

	 if ((semid = create_empty_sem(sem_Key + EMPTY_SEM_IVL)) < 0)
        {
             semid = get_sem(sem_Key);
	    if(semid<0){
             error("[Err]Create shm que empty sem fail.\n");
            	(void)del_per_nic_sem(i,nic_que_info_id);
           	 return ERR;
	    }
	    del_sem(semid);
	    semid = create_sem(sem_Key);
	     if(semid<0){
            	error("[Err]Create shm que empty sem fail.\n");
            	(void)del_per_nic_sem(i,nic_que_info_id);
           	 return ERR;
	    }
            
        }
        (nic_que_addr + i)->empty_semid = semid;
    }

    return OK;
}

/*****************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int del_per_nic_shm(int num,NIC_QUE_INFO_ID nic_que_info_id)
{
    register int i;
    int ret;
    int shmid;
    char *shm_addr = NULL;

    for (i = 0;i <= num;i++)
    {
        shmid =  (nic_que_info_id + i)->shmid;
        shm_addr = (nic_que_info_id + i)->shm_addr;
        if (shm_addr != NULL)
        {
            ret = detach_shm(shm_addr);
            if (ret < 0)
                return ERR;
        }

        if (shmid != DEF_SHM_ID_VAL)
        {
            ret = del_shm(shmid);
            if (ret < 0)
                return ERR;
        }
    }

    return OK;
}

/****************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int del_per_nic_sem(int num,NIC_QUE_INFO_ID nic_que_info_id)
{
    register int i;
    int ret;
    int semid;

    for (i = 0;i < num;i++)
    {
        semid =  (nic_que_info_id + i)->semid;
        ret = del_sem(semid);
        if (ret < 0)
            return ERR;

        semid =  (nic_que_info_id + i)->full_semid;
	ret = del_sem(semid);
        if (ret < 0)
            return ERR;

        semid =  (nic_que_info_id + i)->empty_semid;
	ret = del_sem(semid);
        if (ret < 0)
            return ERR;
    }

    return OK;
}

/****************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void init_nic_que_info(int num,NIC_QUE_INFO_ID nic_que_info_id)
{
    register int i;

    for(i = 0;i < num;i++)
    {
        (nic_que_info_id + i)->shmid = DEF_SHM_ID_VAL;
        (nic_que_info_id + i)->semid = DEF_SEM_ID_VAL;

        (nic_que_info_id + i)->shm_addr = NULL;
    }

    return;
}

/****************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int callback_shm_que(QUE_ID cfg_que_info,int shmid)
{
    register int i;
    key_t shm_key;
    key_t sem_key;
    key_t full_sem_key;
    key_t empty_sem_key;
    int shm_id;
    int sem_id;
    int que_num = g_res_info.que_num;
	
    if (NULL == cfg_que_info)
        return OK;

     for (i = 0;i < que_num;i++)
     {
         shm_key = (cfg_que_info+i)->shmKey;
	  shm_id = shmget(shm_key,0,IPC_CREAT);
         if (shm_id < 0)
         {
            DEBUG("get QUE shm id fail.");
            return ERR;
         }

	 (void)del_shm(shm_id);
	  
	 sem_key = (cfg_que_info+i)->semKey;
	 sem_id = semget(sem_key,0,IPC_CREAT);
         if (sem_id < 0)
         {
             DEBUG("get QUE sem id fail.");
             return ERR;
         } 

         (void)del_sem(sem_id);

         full_sem_key = sem_key + FULE_SEM_IVL;
         sem_id = semget(full_sem_key,0,IPC_CREAT);
         if (sem_id < 0)
         {
             DEBUG("get QUE sem id fail.");
             return ERR;
         }
         (void)del_sem(sem_id);

         empty_sem_key = sem_key + EMPTY_SEM_IVL;
         sem_id = semget(empty_sem_key,0,IPC_CREAT);
         if (sem_id < 0)
         {
             DEBUG("get QUE sem id fail.");
             return ERR;
         }
         (void)del_sem(sem_id);
     }

     (void)detach_shm((char *)cfg_que_info) ;
     (void)del_shm(shmid);

     return OK;
}

int callback_shm_pretected_resource(PROTECTED_RESOURCE_ID res_addr,int shmid,int rule_num,int Line)
{
    register int i;
    key_t shm_key;
    int shm_id1;
   PROTECTED_RESOURCE_ID list_id = NULL;
   if (res_addr == NULL)
   	return OK;
    if (rule_num == 0 && Line ==1){
		goto next;
    	}
    if(rule_num == 0)
	return OK;
#if 0
      list_id = (PROTECTED_RESOURCE_ID)shmat(shmid,NULL,SHM_RDONLY);
     if(!list_id){
		DEBUG("get protected resource shm id fail.");
            	return ERR;
    }
#endif
     for (i = 0;i < rule_num;i++)
     {
         shm_key = res_addr[i].sip.interval_port_shm_key;
	  if(shm_key>0){
	  	shm_id1 = shmget(shm_key,0,IPC_CREAT);
         	if (shm_id1 < 0)
         	{
            		printf("get protected resource shm id fail.");
            		return ERR;
         	}
	 	(void)del_shm(shm_id1);
	  }
	   shm_key = res_addr[i].sip.continue_port_shm_key;
	  if(shm_key>0){
	  	shm_id1 = shmget(shm_key,0,IPC_CREAT);
         	if (shm_id1 < 0)
         	{
            		printf("get protected resource shm id fail.");
            		return ERR;
         	}
	 	(void)del_shm(shm_id1);
	  }
 		
	 shm_key = res_addr[i].dip.interval_port_shm_key;
          if(shm_key>0){
                shm_id1 = shmget(shm_key,0,IPC_CREAT);
                if (shm_id1 < 0)
                {
                        printf("get protected resource shm id fail.");
                        return ERR;
                }
                (void)del_shm(shm_id1);
          }
           shm_key = res_addr[i].dip.continue_port_shm_key;
          if(shm_key>0){
                shm_id1 = shmget(shm_key,0,IPC_CREAT);
                if (shm_id1 < 0)
                {
                        printf("get protected resource shm id fail.");
                        return ERR;
                }
                (void)del_shm(shm_id1);
          }
     }
next:
     (void)detach_shm((char *)list_id) ;
     (void)del_shm(shmid);
      free(res_addr);
     return OK;
}
int callback_shm_account(int shmid,int num)
{
    register int i;
    key_t shm_key;
    int shm_id1;
   AUTHORIZE_ACCOUNT_ID list_id = NULL;
    if (num == 0||shmid == 0)
        return OK;
      list_id = (AUTHORIZE_ACCOUNT_ID)shmat(shmid,NULL,0);
     if(!list_id){
		DEBUG("get authorize account shm id fail.");
            	return ERR;
    }
     for (i = 0;i < num;i++)
     {
         shm_key = list_id[i].authorize_account_key;
	  if(shm_key>0){
	  	shm_id1 = shmget(shm_key,0,IPC_CREAT);
         	if (shm_id1 < 0)
         	{
            		DEBUG("getauthorize account shm id fail.");
            		return ERR;
         	}
	 	(void)del_shm(shm_id1);
	  }
     }
     (void)detach_shm((char *)list_id) ;
     (void)del_shm(shmid);
     return OK;
}

int callback_shm_cmd(int shmid,int num)
{
    register int i;
    key_t shm_key;
    int shm_id1;
   AUTHORIZE_CMD_ID list_id = NULL;
    if (num == 0||shmid == 0)
        return OK;
      list_id = (AUTHORIZE_CMD_ID)shmat(shmid,NULL,0);
     if(!list_id){
		DEBUG("get authorize cmd shm id fail.");
            	return ERR;
    }
     for (i = 0;i < num;i++)
     {
         shm_key = list_id[i].authorize_cmd_key;
	  if(shm_key>0){
	  	shm_id1 = shmget(shm_key,0,IPC_CREAT);
         	if (shm_id1 < 0)
         	{
            		DEBUG("getauthorize cmd shm id fail.");
            		return ERR;
         	}
	 	(void)del_shm(shm_id1);
	  }
     }
     (void)detach_shm((char *)list_id) ;
     (void)del_shm(shmid);
     return OK;
}
int callback_shm_custom(int shmid,int num)
{
    register int i;
    key_t shm_key;
    int shm_id1;
   AUTHORIZE_CUSTOM_ID list_id = NULL;
    if (num == 0||shmid ==0)
        return OK;
      list_id = (AUTHORIZE_CUSTOM_ID)shmat(shmid,NULL,0);
     if(!list_id){
		DEBUG("get authorize custom shm id fail.");
            	return ERR;
    }
     for (i = 0;i < num;i++)
     {
         shm_key = list_id[i].authorize_custom_key;
	  if(shm_key>0){
	  	shm_id1 = shmget(shm_key,0,IPC_CREAT);
         	if (shm_id1 < 0)
         	{
            		DEBUG("getauthorize custom shm id fail.");
            		return ERR;
         	}
	 	(void)del_shm(shm_id1);
	  }
     }
     (void)detach_shm((char *)list_id) ;
     (void)del_shm(shmid);
     return OK;
}

int callback_shm_protocol_feature(int shmid,int num)
{
    register int i,j;
    key_t shm_key;
    int shm_id1,shm_id2;
   AUTHORIZE_PROTOCOL_FEATURE_ID list_id = NULL;
   AUTHORIZE_PROTOCOL_FEATURE_TYPE_ID list_id1=NULL;
   
    if (num == 0||shmid == 0)
        return OK;
      list_id = (AUTHORIZE_PROTOCOL_FEATURE_ID)shmat(shmid,NULL,0);
     if(!list_id){
		DEBUG("get authorize custom shm id fail.");
            	return ERR;
    }
    printf("num@@@@@@@@@@@@@@@line = %d\n",num);
     for (i = 0;i < num;i++)
     {
         shm_key = list_id[i].authorize_protocol_feature_key;
	printf("shm key = %u\n",shm_key);
	  if(shm_key>0){
	  	shm_id1 = shmget(shm_key,0,IPC_CREAT);
         	if (shm_id1 < 0)
         	{
            		DEBUG("getauthorize custom shm id fail.");
            		return ERR;
         	}
		list_id1 = (AUTHORIZE_PROTOCOL_FEATURE_TYPE_ID)shmat(shm_id1,NULL,0);
		if(!list_id1){
			DEBUG("get authorize custom shm id fail.");
            		return ERR;
    		}
		printf("##########pro_feature_type = %d\n",list_id[i].pro_feature_num);
		for(j=0;j<list_id[i].pro_feature_num;j++){
			if(list_id1[j].authorize_protocol_feature_content_key>0){
				shm_id2 = shmget(list_id1[j].authorize_protocol_feature_content_key,0,IPC_CREAT);
				if(shm_id2<0){
					DEBUG("getauthorize protocol feature content shm id fail.");
            				return ERR;
				}
				(void)del_shm(shm_id2);
				printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@shm_id2\n");
			}
		}
		(void)detach_shm((char *)list_id1) ;
	 	(void)del_shm(shm_id1);
		printf("######################################shm_id1\n");
	  }
	 (void)del_shm(shm_id1);
     }
     (void)detach_shm((char *)list_id) ;
     (void)del_shm(shmid);
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
static int create_full_sem(key_t key)
{ 
    int ret = -1;
    int semid;
    union semun arg;
    
    arg.val = FULL_SEM_INIT_VAL;
    semid = semget(key,1,IPC_CREAT|IPC_EXCL);
    if  (-1 != semid)
    {
        ret = semctl(semid,0,SETVAL,arg);
    }

    return (ret == -1?-1:semid);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int create_empty_sem(key_t key)
{ 
    int ret = -1;
    int semid;
    union semun arg;
    
    arg.val = EMPTY_SEM_INIT_VAL;
    semid = semget(key,1,IPC_CREAT|IPC_EXCL);
    if  (-1 != semid)
    {
        ret = semctl(semid,0,SETVAL,arg);
    }

    return (ret == -1?-1:semid);
}
