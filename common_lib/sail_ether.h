/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _SAIL_ETHER_H
#define _SAIL_ETHER_H

#define ETHER_ADDR_LEN  6    /*Mac地址长度*/

typedef struct tagETHER_HDR
{
    unsigned char ether_dhost[ETHER_ADDR_LEN];   /* 目的主机的地址 */
    unsigned char ether_shost[ETHER_ADDR_LEN];   /* 源主机的地址 */
    unsigned short ether_type;                   /* IP? ARP? RARP? etc */
}   ETHER_HDR,*ETHER_HDR_ID;
#define ETHER_HDR_SZIE sizeof(ETHER_HDR)

#endif
