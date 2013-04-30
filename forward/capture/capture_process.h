
#ifndef _CAPTURE_PROCESS_H
#define _CAPTURE_PROCESS_H

#include "capture_model_ctl.h"
#include "interface_block.h"
#include "eAudit_sendtcp.h"
#include "interface_pub.h"


#define CAP_READ_TIMEOUT 1000

#define DEF_QUE_TIMEOUT_TIME 10

#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN       20
#define MIN_TCP_HEADER_LEN      20
#define UDP_HEADER_LEN      8
#define ICMP_HEADER_LEN     4

#define MIN_NET_PKT_SIZE 54

#define INTERVAL_TIME		14

typedef struct tagPKTS_STAT
{
    long long us_recv;
    long long us_recv_size;
    //long ps_recv;
    long ps_drop;
    //long ps_ifdrop;
    long wait_times;
#ifdef INC_FIRST_DROPS
    long ps_first_drop;
#endif
}PKTS_STAT,*PKTS_STAT_ID;
#define PKTS_STAT_SIZE sizeof(PKTS_STAT)

typedef struct tagNIC_QUE_INFO
{
    int shmid;
    int semid;
    int empty_semid;
    int full_semid;
    char *shm_addr;
}NIC_QUE_INFO,*NIC_QUE_INFO_ID;
#define NIC_QUE_INFO_SIZE sizeof(NIC_QUE_INFO)

/*struct define*/
struct singleton_t
{
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
};



typedef struct tagBLOCK_POLICY_ITEM
{
	PROTECTED_RESOURCE res;
	int user_num;
	USR_LIST_MEM_ID			user_list_id;
}BLOCK_POLICY_ITEM, *BLOCK_POLICY_ITEM_ID;
#define BLOCK_POLICY_ITEM_SIZE sizeof(BLOCK_POLICY_ITEM)

typedef struct tagBLOCK_POLICY_LIST
{
	int block_policy_num;
	BLOCK_POLICY_ITEM_ID block_policy_item_id;
}BLOCK_POLICY_LIST, *BLOCK_POLICY_LIST_ID;
#define BLOCK_POLICY_LIST_SIZE sizeof(BLOCK_POLICY_LIST)



#ifdef INC_FIRST_DROPS
typedef enum
{
    FIRST_STAT = 1,
    OTR_STAT
}EN_STAT_STATUS;
#endif

enum CAPTURES_CMD 
{ 
    LOCK_SHM_CMD, 
    UNLOCK_SHM_CMD
};


#define UDP_BLOCK_QUEUE_LEN	10000
#define BLOCKLOG_QUEUE_LEN		10000
#define USLEEP_TIME				1

/*extern function declaration*/


void policy_analysis_handler();
void first_block_handler();
void second_block_handler();
void block_queue_update_handler();
void udp_block_analysis_handler();
void blocklog_handler();
void* get_shm_addr(int shmid,  int shmflg);
int auth_user_search(BLOCK_POLICY_ITEM_ID block_policy_item_id, IP_PACKET_ID ip_packet_id, unsigned char hit_direction);
void write_blocklog_queue(IP_PACKET_ID ip_packet_id, unsigned char hit_direction);


#endif

