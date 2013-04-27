/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_NET_H
#define ANALYZE_NET_H

#include "ether.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

typedef struct tagNET_HDR
{
	ETHER_HDR_ID_FTP	ether_hdr_id;
	IP_HDR_ID		ip_hdr_id;
	TCP_HDR_ID		tcp_hdr_id;
	UDP_HDR_ID		udp_hdr_id;

}	NET_HDR, 		*NET_HDR_ID,
	net_hdr, 		*net_hdr_id;
#define NET_HDR_SIZE		sizeof(NET_HDR)
#define net_hdr_size		sizeof(net_hdr)


#endif /* ANALYZE_NET_H */
