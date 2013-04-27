/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _SAIL_IP_H
#define _SAIL_IP_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define	IPVERSION	4

typedef struct tagIP_HDR 
{
    unsigned char ip_vhl;
	
    #define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
    #define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	
    unsigned char	ip_tos;		      /*���������*/
    unsigned short	ip_len;		      /*�ܳ���  */
    unsigned short	ip_id;		      /*����־��  */
    unsigned short	ip_off;		      /*��Ƭƫ��*/

    #define IP_DF 0x4000	          /*��������Ƭ��־*/
    #define IP_MF 0x2000			  /* more fragments flag */
    #define IP_OFFMASK 0x1fff		  /*�ֶ�λ */

    unsigned char	ip_ttl;		      /* ���ݰ�������ʱ�� */
    unsigned char	ip_p;		      /* ��ʹ�õ�Э�� */
    unsigned short	ip_sum;		      /* У��� */
    struct in_addr ip_src,ip_dst;     /* Դ��ַ��Ŀ�ĵ�ַ*/
}IP_HDR,*IP_HDR_ID;
#define IP_HDR_SIZE sizeof(IP_HDR)

#endif

