/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_SEM_H
#define _EAUDIT_SEM_H

#define SEM_INIT_VAL 1

#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h>; */
#else
/* according to X/OPEN, define it ourselves */
union semun
{
    int val;                                /* value for SETVAL */
    struct semid_ds *buf;         /* buffer for IPC_STAT, IPC_SET */
    unsigned short int *array;    /* array for GETALL, SETALL */
    struct seminfo *__buf;        /* buffer for IPC_INFO */
};
#endif

extern int create_sem(key_t key);
extern int del_sem(int semid);
extern int get_sem (key_t key);
extern int sem_lock (int semid);
extern int sem_unlock (int semid);
extern void wait_sem(int semid);
extern int Sem_Ip_Queque_Create(key_t key);
extern int Sem_Ip_Queque_Destroy(int m_semid);
extern int Init_Sem_Ip_Queue(int m_semid);
extern int Get_Sem_Ip_Queque_SemID(key_t key);
extern int Sem_P(int No,int m_semid);
extern int Sem_V(int No,int m_semid);
extern int Sem_Lock(int No,int m_semid);
extern int Sem_Unlock(int No,int m_semid);
#endif
