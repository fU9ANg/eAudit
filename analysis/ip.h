/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_IP_H
#define ANALYZE_IP_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define	IPVERSION		4
#define MIN_IP_HEADER_LEN       20


#define IP_V(ip)		(((ip)->ip_vhl & 0xf0) >> 4)

#define IP_HL(ip)		((ip)->ip_vhl & 0x0f)

#define IP_DF 0x4000	          	/* 保留的碎片标志 */
#define IP_MF 0x2000			/* more fragments flag */
#define IP_OFFMASK 0x1fff		/* 分段位 */


typedef struct tagIP_HDR 
{
	unsigned char	ip_vhl;
	unsigned char	ip_tos;		/* 服务的类型 */

	unsigned short	ip_len;		/* 总长度  */
	unsigned short	ip_id;		/* 包标志号  */
	unsigned short	ip_off;		/* 碎片偏移 */

	unsigned char	ip_ttl;		/* 数据包的生存时间 */
	unsigned char	ip_p;		/* 所使用的协议 */
	unsigned short	ip_sum;		/* 校验和 */
	struct in_addr	ip_src;
	struct in_addr	ip_dst;      	/* 源地址、目的地址 */

}	IP_HDR,		*IP_HDR_ID,
	ip_hdr, 	*ip_hdr_id;
#define IP_HDR_SIZE 	sizeof(IP_HDR)
#define ip_hdr_size	sizeof(ip_hdr)


#endif /* ANALYZE_IP_H */
