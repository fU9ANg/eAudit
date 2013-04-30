
#ifndef _CTL_PKT_SHM_QUE_H
#define _CTL_PKT_SHM_QUE_H

#define FULL_SEM_INIT_VAL    0
#define EMPTY_SEM_INIT_VAL 1

typedef struct tagNIC_QUE_INFO
{
    int shmid;
    char *shm_addr;
    int semid;
    int empty_semid;
    int full_semid;
}NIC_QUE_INFO,*NIC_QUE_INFO_ID;
#define NIC_QUE_INFO_SIZE sizeof(NIC_QUE_INFO)

typedef struct tagRES_REG_INFO
{
    int que_num;
    unsigned long rule_num;
    int pro_num;
}RES_REG_INFO,*RES_REG_INFO_ID;
#define RES_REG_INFO_SIZE sizeof(RES_REG_INFO)

extern RES_REG_INFO g_res_info;

extern void init_nic_que_info(int,NIC_QUE_INFO_ID);
extern int del_per_nic_sem(int,NIC_QUE_INFO_ID);
extern int del_per_nic_shm(int ,NIC_QUE_INFO_ID);
extern int create_per_nic_shm(int ,QUE_ID,NIC_QUE_INFO_ID);
extern int create_per_nic_sem(int ,QUE_ID,NIC_QUE_INFO_ID);
extern int callback_shm_que(QUE_ID,int);
extern int callback_shm_pretected_resource(PROTECTED_RESOURCE_ID res_addr,int shmid,int rule_num,int Line);
extern int callback_shm_account(int shmid,int num);
extern int callback_shm_cmd(int shmid,int num);
extern int callback_shm_custom(int shmid,int num);
extern int callback_shm_protocol_feature(int shmid,int num);
#endif
