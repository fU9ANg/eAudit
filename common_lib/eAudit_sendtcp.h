/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_SENDTCP_H
#define _EAUDIT_SENDTCP_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include "interface_block.h"

#define ETH_DATA_LEN 			1500
#define true 						1
#define false 					0

/*tcp connect state define */
#define	TCP_BEGIN_CONNECT		0
#define TCP_CONNECTED			1
#define TCP_CLOSE				2


//#define _DEBUG
/*外部变量声明定义区*/
extern int 	g_nRawSocket;
extern int	 	g_nRawSocket1;
extern int	 	g_nRawSocket2;
extern int   g_nFilterPortNum;
extern char	g_HttpWarning[1024] ;

/*定义外部调用函数接口*/
extern void DEBUG(const char *fmt, ...);
extern unsigned long atoul(char *p);
extern int RawSocket();
extern int SendCloseTcp(int sockfd,unsigned long sIP,unsigned short sPort,unsigned long dIP,unsigned short dPort,unsigned long seq, unsigned long ack_seq);
extern int SendAckTcp(int sockfd,unsigned long sIP,unsigned short sPort,unsigned long dIP,unsigned short dPort,unsigned long seq, unsigned long ack_seq);
unsigned short check_sum(unsigned short *pAddr,int nLen, struct psd_header *psd_hdr);
extern int raw_net_socket();
extern int raw_arp_socket();
extern int send_arp_block_pkt(int sockfd, UDP_CLOSEINFO_ID udp_close_info_id);
extern int  send_icmp_host_unreachable(int sockfd, UDP_CLOSEINFO_ID udp_close_info_id);
#endif
