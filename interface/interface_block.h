
/*
 * file: interface_block.h
 * written 2009, 2010, 2011, 2012, 2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#ifndef _INTERFACE_BLOCK_H
#define _INTERFACE_BLOCK_H

#include "sail_ether.h"
#include <time.h>
#include <sys/time.h>

#define ETH_DATA_LEN 			1500
#define IP_DATA_LEN 			1500

/*ip header define*/
typedef struct iphdr0
{
//#if __BYTE_ORDER == __LITTLE_ENDIAN
//    unsigned char ihl:4;
//    unsigned char version:4;
//#elif __BYTE_ORDER == __BIG_ENDIAN
   // unsigned char version:4;
   // unsigned char ihl:4;
   unsigned char vhl;
//#else
//# error	"Please fix <bits/endian.h>"
//#endif
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
    /*The options start here. */

}   Iphdr_Info,*Iphdr_Info_ID;
#define IPHDR_INFO_SIZE sizeof(Iphdr_Info)

typedef struct icmphdr0
{
	unsigned char type;
	unsigned char code;
	unsigned short check;
	unsigned long other;

}   icmphdr0_info, *icmphdr0_info_id;
#define icmphdr0_info_size sizeof(icmphdr0_info)

typedef struct etherhdr0
{
	unsigned char dst_mac[ETHER_ADDR_LEN];
	unsigned char src_mac[ETHER_ADDR_LEN];
	unsigned short type;
}   etherhdr0_info, *etherhdr0_info_id;
#define etherhdr0_info_size sizeof(etherhdr0)



/*tcp  header define*/
typedef struct tcphdr0
  {
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;

    unsigned char th_offx2;	    /* data offset, rsvd */
    unsigned char th_flags;
   
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;

}   Tcphdr_Info,*Tcphdr_Info_ID;
#define TCP_HDR_INFO_SIZE  sizeof(Tcphdr_Info)

/*tcp 伪头定义，便于产生校验值*/
typedef struct psd_header
{ 
	unsigned long saddr;	//source addr
	unsigned long daddr;	//dest addr
	char mbz;		        //empty
	char ptcl;     		    //protocol type IPPROTO_TCP
	unsigned short tcpl;	//TCP length

}   Psd_Hdr_Info,*Psd_Hdr_Info_ID;
#define PSD_HEADER_SIZE  sizeof(Psd_Hdr_Info)

/*tcp close struct info */
typedef struct TCP_CLOSE_INFO
{
	unsigned long src_ip;
	unsigned long dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned long next_seqno;
	unsigned long ackno;
	struct timeval ts;

}   TCP_CLOSEINFO,*TCP_CLOSEINFO_ID;
#define TCP_CLOSE_INFO_SIZE sizeof(TCP_CLOSEINFO)

typedef struct tagBLOCK_QUEUE_INFO
{
	unsigned int read_index;
	unsigned int write_index;
	unsigned int total_num;
	unsigned int exist_num;

}   BLOCK_QUEUE_INFO, *BLOCK_QUEUE_INFO_ID;
#define BLOCK_QUEUE_INFO_SIZE sizeof(BLOCK_QUEUE_INFO)


typedef struct tagUDP_CLOSEINFO
{
	unsigned char src_mac[ETHER_ADDR_LEN];
	unsigned char dst_mac[ETHER_ADDR_LEN]; 
	unsigned long src_ip;
	unsigned long dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	char data_len;
	unsigned char data[68];

}   UDP_CLOSEINFO, *UDP_CLOSEINFO_ID;
#define UDP_CLOSEINFO_SIZE  sizeof(UDP_CLOSEINFO)

typedef struct tagUDP_BLOCK_QUEUE_INFO
{
	unsigned int read_index;
	unsigned int write_index;
	unsigned int total_num;
	unsigned int exist_num;

}   UDP_BLOCK_QUEUE_INFO, *UDP_BLOCK_QUEUE_INFO_ID;
#define UDP_BLOCK_QUEUE_INFO_SIZE sizeof(UDP_BLOCK_QUEUE_INFO)

typedef struct tagBLOCKLOGINFO
{
	unsigned long src_ip;
	unsigned short src_port;
	unsigned long dst_ip;
	unsigned short dst_port;
	time_t time;
}   BLOCKLOGINFO, *BLOCKLOGINFO_ID;
#define BLOCKLOGINFO_SIZE sizeof(BLOCKLOGINFO)

typedef struct tagBLOCKLOG_QUEUE_INFO
{
	unsigned int read_index;
	unsigned int write_index;
	unsigned int total_num;
	unsigned int exist_num;
}   BLOCKLOG_QUEUE_INFO, *BLOCKLOG_QUEUE_INFO_ID;
#define BLOCKLOG_QUEUE_INFO_SIZE sizeof(BLOCKLOG_QUEUE_INFO)

//IP address  information
typedef struct IPAddrInfo
{
	unsigned char	uVersion;
	unsigned short	nHeadLen;		//true head lenngth (*4)
	unsigned char	uServiceType;
	unsigned short	nTotalLen;
	unsigned short	nIdentification;
	unsigned char	zcaFragOff[2];
	unsigned char	uTtl;
	unsigned char	uFilter;//user define member
	unsigned long	seq;
	unsigned long	seqack;
	unsigned short	nChecksum;
	int	            tcp_status; //TCP_CLOSE,TCP_BEGIN_CONNECT,TCP_CONNECTED
	unsigned char	protocol;
	unsigned long	source_ip;
	unsigned long	dest_ip;
	unsigned short	source_port;
	unsigned short	dest_port;
	unsigned char	data[IP_DATA_LEN];
	unsigned short	datalen;
	int	        user_id;
	char		user_name[33];
	int 		direction;		// 1=up, 2=down
	int 		showtype;		// 0= normal, 1 = waring
    int             sid;		        //与一级表关联ID

}   IPADDR_INFO,*IPADDR_INFO_ID;
#define IPADDR_INFO_SIZE sizeof(IPADDR_INFO)

/**define transfer process parameter arg */
typedef struct BlockParaInfo{
	key_t block_sem_key;
	key_t ip_quequehdr_key;
	key_t first_ipqueque_key;
	int first_pkt_hdr_num;
	key_t second_ipqueque_key;
	int second_pkt_hdr_num;
	key_t ip_queque_key;
	int ip_queque_num;

}   ParaInfo,*ParaInfo_ID;
#define PARAINFO_SIZE  sizeof(ParaInfo)

/*定义IP数据报,报文队列信息*/
typedef struct tagIP_PACKET
{
	unsigned char src_mac[ETHER_ADDR_LEN];
	unsigned char dst_mac[ETHER_ADDR_LEN]; 
	unsigned long src_ip;
	unsigned long dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned long next_seqno;
	unsigned long ackno;
	struct timeval	ts;
}   IP_PACKET,*IP_PACKET_ID;
#define IP_PACKET_SIZE sizeof(IP_PACKET)

struct ST_THREADINFO
{
	unsigned int ip_queque_num;
	unsigned int first_block_queque_num;
	unsigned int second_block_queque_num;
};
#define ST_THREADINFO_SIZE sizeof(ST_THREADINFO)

#pragma pack(1)
typedef struct arphdr0
{
	unsigned short hd_type;
	unsigned short pro_type;
	unsigned char hd_len;
	unsigned char pro_len;
	unsigned short op;
	unsigned char src_mac[ETHER_ADDR_LEN];
	unsigned long src_ip;
	unsigned char dst_mac[ETHER_ADDR_LEN];
	unsigned long dst_ip;
}   arphdr0_info, *arphdr0_info_id;

#define arphdr0_info_size sizeof(arphdr0)
#pragma pack()

#endif
