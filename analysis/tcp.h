/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_TCP_H
#define ANALYZE_TCP_H


#define MIN_TCP_HEADER_LEN      20

#define TH_OFF(th)		(((th)->th_offx2 & 0xf0) >> 4)

#define TH_FIN			0x01
#define TH_SYN			0x02
#define TH_RST			0x04
#define TH_PUSH			0x08
#define TH_ACK			0x10
#define TH_URG			0x20
#define TH_ECNECHO		0x40	/* ECN Echo */
#define TH_CWR			0x80	/* ECN Cwnd Reduced */


typedef	unsigned long  tcp_seq;  	//4

typedef struct tagTCP_HDR 
{
	unsigned short 	th_sport;	/* source port */
	unsigned short	th_dport;	/* destination port */
	tcp_seq		th_seq;		/* sequence number */
	tcp_seq		th_ack;		/* acknowledgement number */
	unsigned char 	th_offx2;	/* data offset, rsvd */

	unsigned char	th_flags;
	
	unsigned short 	th_win;		/* window */
	unsigned short 	th_sum;		/* checksum */
	unsigned short 	th_urp;		/* urgent pointer */

}	TCP_HDR,	*TCP_HDR_ID,
	tcp_hdr, 	*tcp_hdr_id;
#define TCP_HDR_SIZE	sizeof(TCP_HDR)
#define tcp_hdr_size	sizeof(tcp_hdr)


#endif /* ANALYZE_TCP_H */
