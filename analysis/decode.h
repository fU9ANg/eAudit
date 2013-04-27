/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_DECODE_H
#define ANALYZE_DECODE_H

#include "net.h"
#include "ether.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

/* prototypes for decode ethernet packet. */
int decode_net_pkt  (NET_HDR_ID net_hdr_id,
		     unsigned char** pcur_pos, unsigned long  left_len   );
int decode_ether_pkt(ETHER_HDR_ID_FTP* pether_hdr_id, 	
		     unsigned char** pcur_pos, unsigned long* left_len_id);
int decode_ip_pkt   (IP_HDR_ID* pip_hdr_id, 		
		     unsigned char** pcur_pos, unsigned long* left_len_id);
int decode_tcp_pkt  (TCP_HDR_ID* ptcp_hdr_id, 		
		     unsigned char** pcur_pos, unsigned long* left_len_id);
int decode_udp_pkt  (UDP_HDR_ID* pudp_hdr_id,
		     unsigned char** pcur_pos, unsigned long* left_len_id);


#endif /* ANALYZE_DECODE_H */
