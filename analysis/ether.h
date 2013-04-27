/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_ETHER_H
#define ANALYZE_ETHER_H

#include "interface.h"

#define ETHERNET_TYPE_IP				0x0800
#define ETHERNET_TYPE_ARP				0x0806
#define ETHERNET_TYPE_REVARP				0x8035
#define ETHERNET_TYPE_EAPOL				0x888e
#define ETHERNET_TYPE_IPV6				0x86dd
#define ETHERNET_TYPE_IPX				0x8137
#define ETHERNET_TYPE_PPPoE_DISC			0x8863
#define ETHERNET_TYPE_PPPoE_SESS			0x8864 
#define ETHERNET_TYPE_8021Q     	        	0x8100

typedef struct tagETHER_HDR_FTP
{
    unsigned char  ether_dhost[MAC_ADDRESS_SIZE];   	/* 目的主机的地址 */
    unsigned char  ether_shost[MAC_ADDRESS_SIZE];   	/* 源主机的地址 */
    unsigned short ether_type;                   	/* IP? ARP? RARP? etc */

}   ETHER_HDR_FTP,*ETHER_HDR_ID_FTP,
    ether_hdr_ftp,*ether_hdr_id_ftp;

#define ETHER_HDR_SIZE sizeof(ETHER_HDR_FTP)
#define ether_hdr_size sizeof(ether_hdr_ftp)


#endif /* ANALYZE_ETHER_H */
