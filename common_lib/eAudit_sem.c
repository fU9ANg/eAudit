/************************************************************************
* Copyright (c)
* All rights reserved.
* 
* This is unpublished proprietary source code of Shanghai Sail Infomation TEC Co. LTD
*
/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>

#include <sys/sem.h>

#include "eAudit_pub.h"
#include "eAudit_sem.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int create_sem(key_t key)
{ 
    int ret = -1;
    int semid;
    union semun arg;
    
    arg.val = SEM_INIT_VAL;
    //arg.val = 0;
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
int del_sem(int semid)
{
    int ret;

    ret = semctl(semid,0,IPC_RMID,0);

    return (ret == -1?ERR:OK);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_sem (key_t key)
{
    int semid;

    semid = semget(key,0,IPC_CREAT);
	
    return semid;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int sem_lock (int semid)
{
    struct sembuf waitop={0,-1,SEM_UNDO};
    return (semop(semid,&waitop,1));
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int sem_unlock (int semid)
{
    struct sembuf sops={0,+1,SEM_UNDO};
    return (semop(semid,&sops,1));
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void wait_sem(int semid)
{
    struct sembuf sops={0,0,0};
    semop(semid,&sops,1);
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int Sem_Ip_Queque_Create(key_t key)
{
	int m_semid = -1;
	m_semid = semget((key_t)key,4, 0600|IPC_CREAT);
	if (m_semid == -1)
		return -1;
	return m_semid;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int Sem_Ip_Queque_Destroy(int m_semid)
{
	union semun sem_union;
	
	int  ret_sem;
    if (semctl(m_semid, 4,IPC_RMID,sem_union) == -1)
		ret_sem = -1;
	else
		ret_sem = 0;
		
	return ret_sem;
	
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int Init_Sem_Ip_Queue(int m_semid)
{
	union semun sem_union;
	
	int ret_sem0, ret_sem1,ret_sem2,ret_sem3;
	sem_union.val = 0;
	ret_sem0 = (semctl(m_semid, 0,SETVAL,sem_union) != -1);
	sem_union.val = 0;
	ret_sem1 = (semctl(m_semid, 1,SETVAL,sem_union) != -1);
	sem_union.val = 0;
	ret_sem2 = (semctl(m_semid, 2,SETVAL,sem_union) != -1);
	sem_union.val = 0;
	ret_sem3 = (semctl(m_semid, 3,SETVAL,sem_union) != -1);
	
	if (!ret_sem0 || !ret_sem1 || !ret_sem2 || !ret_sem3)
	{
		Sem_Ip_Queque_Destroy(m_semid);
		return -1;
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
int Get_Sem_Queque_SemID(key_t key)
{
	int m_semid = -1;
	m_semid = semget((key_t)key,4, IPC_CREAT);
	if (m_semid == -1)
		return -1;
	return m_semid;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
// Wait, --
// No = 0, 1
int Sem_P(int No,int m_semid)
{
	struct sembuf sem_b;
	if (No == 0)
		sem_b.sem_num = 0;
	else if (No == 1)
		sem_b.sem_num = 2;
	else
		return -1;
	sem_b.sem_op = -1; // p()
	sem_b.sem_flg =SEM_UNDO;
	if (semop(m_semid, &sem_b, 1) == -1)
		return -1;
	else
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
//pass through, ++
//No = 0, 1
int Sem_V(int No,int m_semid)
{
	struct sembuf sem_b;
	if (No == 0)
		sem_b.sem_num = 0;
	else if (No == 1)
		sem_b.sem_num = 2;
	else
		return -1;
	sem_b.sem_op = 1; // V()
	sem_b.sem_flg = SEM_UNDO;
	if (semop(m_semid, &sem_b, 1) == -1)
		return -1;
	else
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
// No = 0, 1
int Sem_Lock(int No,int m_semid)
{
	struct sembuf sem_b;
	if (No == 0)
		sem_b.sem_num = 1;
	else if (No == 1)
		sem_b.sem_num = 3;
	else
		return -1;
	sem_b.sem_op = -1; // p()
	sem_b.sem_flg = SEM_UNDO;
	if (semop(m_semid, &sem_b, 1) == -1)
		return -1;
	else
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
// No = 0, 1
int Sem_Unlock(int No,int m_semid)
{
	struct sembuf sem_b;
	if (No == 0)
		sem_b.sem_num = 1;
	else if (No == 1)
		sem_b.sem_num = 3;
	else
		return -1;
	sem_b.sem_op = 1; // V()
	sem_b.sem_flg = SEM_UNDO;
	if (semop(m_semid, &sem_b, 1) == -1)
		return -1;
	else
		return 0;
}

