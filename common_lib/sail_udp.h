/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _SAIL_UDP_H
#define _SAIL_UDP_H

typedef struct tagUDP_HDR 
{
    unsigned short uh_sport;     /* source port */
    unsigned short uh_dport;     /* destination port */
    unsigned short uh_ulen;      /* udp length */
    unsigned short uh_sum;       /* udp checksum */
}   UDP_HDR,*UDP_HDR_ID;
#define UDP_HDR_SIZE sizeof(UDP_HDR)

#endif
