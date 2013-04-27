/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_SHM_H
#define _EAUDIT_SHM_H

enum EN_SHM_MODE
{
    AUTO_KEY = 0,
    NOT_AUTO_KEY
};

extern void print_shm_stat(struct shmid_ds *buf);
extern int set_shm_stat(int shm_id,struct shmid_ds *smidds);
extern int get_shm_stat(int shm_id);
extern int del_shm(int shm_id);
extern int detach_shm(void *shm_start_addr);
extern char *attach_shm(int shm_id );
extern int create_private_shm(key_t shm_key,size_t shm_size);
extern int create_pub_shm(key_t shm_key,size_t shm_size);
/*2009/04/29 增加阻断功能*/
extern int Get_TcpCloseQueque_shm(key_t key,size_t shm_size);
extern int Get_TcpCloseFirstQueque_shm(key_t key,size_t shm_size);
extern int Get_TcpCloseSecondQueque_shm(key_t key,size_t shm_size);
extern int Get_IpQueque_shm(key_t key,size_t shm_size);
#endif
