/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_UDP_H
#define ANALYZE_UDP_H

typedef struct tagUDP_HDR
{
	unsigned short	th_sport;
	unsigned short	th_dport;
	unsigned short	length;
	unsigned short	checksum;

}	UDP_HDR,	*UDP_HDR_ID,
	udp_hdr, 	*udp_hdr_id;
#define UDP_HDR_SIZE	sizeof(UDP_HDR)
#define udp_hdr_size	sizeof(udp_hdr)


#endif /* ANALYZE_UDP_H */
