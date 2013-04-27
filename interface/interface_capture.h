/*
 * file: interface_capture.h
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#ifndef _INTERFACE_CAPTURE_H
#define _INTERFACE_CAPTURE_H

#include "interface_pub.h"

/*the par to the capture process*/
typedef struct tagPAR_ITF_CAPTURE
{
	char nic_name[NICNAMESIZE+1];
    int nic_no;
    int que_num;
    
    FUNC_SWITCH func_switch;
    key_t run_cfg_shm_key;
    
    int nic_num;
    long deposit_ivl_sec;
    int flow_switch;
    char manage_nic_name[NICNAMESIZE+1];
    
	key_t tcp_block_queue_sem_key;
	key_t tcp_block_queue1_shm_key;
   	unsigned long tcp_block_queue1_num;

	key_t tcp_block_queue2_check_shm_key;
	unsigned long tcp_block_queue2_check_num;
	
	key_t tcp_block_queue2_shm_key;
	unsigned long tcp_block_queue2_num;
	
	key_t ip_block_queue_shm_key;
	unsigned long ip_queue_num;

	key_t res_key;
	unsigned long res_num;
	key_t user_key;
	unsigned long user_num;
	key_t authorize_key;
	unsigned long authorize_num;

	
} __attribute__ ((packed)) PAR_ITF_CAPTURE,*PAR_ITF_CAPTURE_ID;
#define PAR_ITF_CAPTURE_SIZE sizeof(PAR_ITF_CAPTURE)

/*the block status*/
enum en_block_status
{
    SHM_BLOCK = 0,
    SHM_NOT_BLOCK             
};

#endif
