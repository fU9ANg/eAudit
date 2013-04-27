/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "eAudit_pub.h"
#include "eAudit_shm.h"

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int create_pub_shm(key_t shm_key,size_t shm_size)
{
    int shm_id = -1;

    shm_id = shmget(shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    return shm_id;
}

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int create_private_shm(key_t shm_key,size_t shm_size)
{
    int shmid;
	
    shmid = shmget(IPC_PRIVATE,shm_size,0);	
    return shmid;
}

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int get_shm(key_t shm_key)
{
    int shmid;
	
    shmid = shmget(shm_key,0,IPC_CREAT);

    return shmid;
}

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
char *attach_shm(int shm_id)
{
    char *shm_start_addr = NULL;
	
    shm_start_addr = (char *)shmat(shm_id,NULL,0);
    if (!shm_start_addr)
        return NULL;

    return shm_start_addr;
}

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int detach_shm(void *shm_start_addr)
{
    int ret;

    ret = shmdt(shm_start_addr);

    return ret;
}

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int del_shm(int shm_id)
{
    int ret;
    ret = shmctl(shm_id, IPC_RMID, 0);

    return(ret<0?ERR:OK);
}

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int get_shm_stat(int shm_id)
{
    int ret;
    ret = shmctl(shm_id,IPC_STAT, 0);

    return(ret<0?ERR:OK);
}

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int set_shm_stat(int shm_id,struct shmid_ds *smidds)
{
    int ret;
    ret = shmctl(shm_id,IPC_SET,smidds);

    return(ret<0?ERR:OK);
}

/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
void print_shm_stat(struct shmid_ds *buf)
{
    printf("struct ipc_perm:\n");
    printf("uid=%d\n", buf->shm_perm.uid);
    printf("gid=%d\n", buf->shm_perm.gid);
    printf("cuid=%d\n", buf->shm_perm.cuid);
    printf("cgid=%d\n", buf->shm_perm.cgid);
}
/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int Get_TcpCloseQueque_shm(key_t key,size_t shm_size){
	int shmid = -1;
	shmid = shmget(key,shm_size,IPC_CREAT|IPC_EXCL);
	if(shmid<0){
		shmid =get_shm(key);
		if(shmid<0)
			return -1;
		del_shm(shmid);
		shmid = shmget(key,shm_size,IPC_CREAT|IPC_EXCL);
		if(shmid<0)
			return -1;
	}	
	return shmid;
}
/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int Get_TcpCloseFirstQueque_shm(key_t key,size_t shm_size){
	int shmid = -1;
	shmid = shmget(key,shm_size,IPC_CREAT|IPC_EXCL);
	if(shmid<0){
		shmid =get_shm(key);
		if(shmid<0)
			return -1;
		del_shm(shmid);
		shmid = shmget(key,shm_size,IPC_CREAT|IPC_EXCL);
		if(shmid<0)
			return -1;
	}	
	return shmid;
}
/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int Get_TcpCloseSecondQueque_shm(key_t key,size_t shm_size){
	int shmid = -1;
	shmid = shmget(key,shm_size,IPC_CREAT|IPC_EXCL);
	if(shmid<0){
		shmid =get_shm(key);
		if(shmid<0)
			return -1;
		del_shm(shmid);
		shmid = shmget(key,shm_size,IPC_CREAT|IPC_EXCL);
		if(shmid<0)
			return -1;
	}	
	return shmid;
}
/*********************************
*func name£º
*function£º
*parameter£º
*caller£º
*called£º
*return£º
*/
int Get_IpQueque_shm(key_t key,size_t shm_size){
	int shmid = -1;
	shmid = shmget(key,shm_size,IPC_CREAT|IPC_EXCL);
	if(shmid<0){
		shmid =get_shm(key);
		if(shmid<0)
			return -1;
		del_shm(shmid);
		shmid = shmget(key,shm_size,IPC_CREAT|IPC_EXCL);
		if(shmid<0)
			return -1;
	}	
	return shmid;
}
