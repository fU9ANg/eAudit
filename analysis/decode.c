/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <string.h>
#include <arpa/inet.h>

#include "decode.h"
#include "interface.h"
#include "debug.h"

/*
 *  network header:
 *  ----------------------------------------------------
 *  | ether_header | ip_header | tcp/udp_header | data |
 *  ----------------------------------------------------
 */

/* Please RTFSC */

int
decode_net_pkt(net_hdr_id, pcur_pos, left_len)
	NET_HDR_ID	net_hdr_id;
	unsigned char** pcur_pos;
	unsigned long 	left_len;
{
	unsigned short ether_type;
	unsigned char ip_proto;
	memset(net_hdr_id, 0x00, NET_HDR_SIZE);

	if(decode_ether_pkt(&(net_hdr_id->ether_hdr_id), pcur_pos, &left_len) == ERR) {
		return ERR;
	}
	ether_type = ntohs(net_hdr_id->ether_hdr_id->ether_type);
	switch(ether_type) {
		case ETHERNET_TYPE_IP:
			if(decode_ip_pkt(&(net_hdr_id->ip_hdr_id), pcur_pos, &left_len) == ERR) {
				return ERR;
			}
		break;
		case ETHERNET_TYPE_PPPoE_DISC:
		case ETHERNET_TYPE_PPPoE_SESS:
		case ETHERNET_TYPE_ARP:
		case ETHERNET_TYPE_REVARP:
		case ETHERNET_TYPE_IPV6:
		case ETHERNET_TYPE_IPX:
		case ETHERNET_TYPE_8021Q:

		default:
			return ERR;
	}
	ip_proto = net_hdr_id->ip_hdr_id->ip_p;
	switch(ip_proto) {
		case TCP:
			if(decode_tcp_pkt(&(net_hdr_id->tcp_hdr_id),		\
				pcur_pos, &left_len) == ERR) return(ERR);  break;

		case UDP:
			if(decode_udp_pkt(&(net_hdr_id->udp_hdr_id),		\
				pcur_pos, &left_len) == ERR) return(ERR);  break;

		case ICMP:

			break;

		default:
			return(ERR);
	}
	return(OK);
}


/*
 * decode ehternet packet header
 * from string.
 */
int decode_ether_pkt(
	ETHER_HDR_ID_FTP* pether_hdr_id,
	unsigned char**   pcur_pos,
	unsigned long*    left_len_id
	)
{
	if(*left_len_id < ETHERNET_HEADER_LEN) {
		warning("The Ether header is error.");
		return(ERR);
	}

	*pether_hdr_id = (ETHER_HDR_ID_FTP)(*pcur_pos);
	*pcur_pos     +=  ETHERNET_HEADER_LEN;
	*left_len_id  -=  ETHERNET_HEADER_LEN;
	
	return(OK);
}


/*
 * decode packet ip header
 * from string.
 */
int decode_ip_pkt(
	IP_HDR_ID*      pip_hdr_id, 
	unsigned char** pcur_pos, 
	unsigned long*  left_len_id)
{
	unsigned long   hlen;
	unsigned long   ip_len;
    
	unsigned char   mf;
	unsigned short  frag_offset;
	
	*pip_hdr_id = (IP_HDR_ID) (*pcur_pos);
	
	if  (*left_len_id < MIN_IP_HEADER_LEN) {
		warning("The Ip header is error.");
		return(ERR);
	}
	if(IP_V(*pip_hdr_id) != 4) {
		warning("The Ip Version is 6,Now only support 4.");
		return(ERR);
	}

	/* set the IP header length */
	hlen = IP_HL(*pip_hdr_id) << 2;
	if(hlen < MIN_IP_HEADER_LEN) {
		warning("The Ip header is error.");
		return(ERR);
	}

	/* set the IP datagram length */
	ip_len = htons((*pip_hdr_id)->ip_len);
	if (ip_len != *left_len_id) {
		if (ip_len > *left_len_id) 
			ip_len = *left_len_id;
	}
	if(ip_len < hlen) {
		warning("The Ip header is error.");
		return(ERR);
	}

	/*fragmented packets */
	frag_offset  = ntohs((*pip_hdr_id)->ip_off);
	mf           = (unsigned char)((frag_offset & 0x2000) >> 13);
	frag_offset &= IP_OFFMASK;
	if (frag_offset || mf)
		return(ERR);

	*pcur_pos += hlen;
	*left_len_id-= hlen;
	return(OK);
}
  
/*
 * decode packet tcp header
 * from string.
 */
int decode_tcp_pkt(
	TCP_HDR_ID*     ptcp_hdr_id,
	unsigned char** pcur_pos,
	unsigned long*  left_len_id)
{
	unsigned long   hlen;

	if(*left_len_id < MIN_TCP_HEADER_LEN) {
		warning("The TCP header is error.");
		return(ERR);
	}

	*ptcp_hdr_id = (TCP_HDR_ID)(*pcur_pos);
	hlen         =  TH_OFF(*ptcp_hdr_id) << 2;

	if(hlen < MIN_TCP_HEADER_LEN) {
		warning("The TCP header is error.");
		return(ERR);
	}

	if(hlen > *left_len_id) {
		warning("The TCP header is error.");
		return(ERR);
	}
	*pcur_pos   += hlen;
	*left_len_id-= hlen;

	return(OK);
}


/*
 * decode packet udp header
 * from string.
 */
int
decode_udp_pkt(pdup_hdr_id, pcur_pos, left_len_id)
	UDP_HDR_ID	*pudp_hdr_id;
	unsigned char	**pcur_pos;
	unsigned long	*left_len_id;
{
	*pudp_hdr_id = (UDP_HDR_ID)(*pcur_pos);
	if(*left_len_id < UDP_HDR_SIZE) {
		warning("The UDP header is error.");
		return ERR;
	}
	*pcur_pos   += UDP_HDR_SIZE;
	*left_len_id-= UDP_HDR_SIZE;

	return(OK);
}
