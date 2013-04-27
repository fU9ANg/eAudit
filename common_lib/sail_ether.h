/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _SAIL_ETHER_H
#define _SAIL_ETHER_H

#define ETHER_ADDR_LEN  6    /*Mac��ַ����*/

typedef struct tagETHER_HDR
{
    unsigned char ether_dhost[ETHER_ADDR_LEN];   /* Ŀ�������ĵ�ַ */
    unsigned char ether_shost[ETHER_ADDR_LEN];   /* Դ�����ĵ�ַ */
    unsigned short ether_type;                   /* IP? ARP? RARP? etc */
}   ETHER_HDR,*ETHER_HDR_ID;
#define ETHER_HDR_SZIE sizeof(ETHER_HDR)

#endif
