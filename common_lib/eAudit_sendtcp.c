/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/if_ether.h>  
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <ctype.h>
#include <stdarg.h> 

#include "eAudit_sendtcp.h"
#include "interface_block.h"

/*变量声明区*/
char	g_HttpWarning[1024] = {0}; //HTTP阻断时警告信息
int             	g_nRawSocket=-1;
int             	g_nRawSocket1 = -1;
int             	g_nRawSocket2 = -1;
/*函数声明定义区*/
int SendCloseTcp(int sockfd,unsigned long sIP,unsigned short sPort,unsigned long dIP,unsigned short dPort,unsigned long seq, unsigned long ack_seq);
int SendAckTcp(int sockfd,unsigned long sIP,unsigned short sPort,unsigned long dIP,unsigned short dPort,unsigned long seq, unsigned long ack_seq);
extern int errno;


/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
unsigned long atoul(char *p)
{
	return (unsigned long)atoi(p);
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int RawSocket()
{
	int on = 1;
	int sockfd = socket(AF_INET,SOCK_RAW,SOCK_RAW);//IPPROTO_TCP);SOCK_RAW
	if(sockfd<0)
	{
#ifdef _DEBUG
		printf("Create raw socket fail: %d, %s\n", errno, strerror(errno));
#endif
		return -1;
	}
	if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,(char*)&on,sizeof(on)))
	{
#ifdef _DEBUG
		printf("set socket options fail,%s\n",strerror(errno));
#endif
		return -1;
	}
	setuid(getuid());
	return sockfd;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
/*ip tcp pkt 函数校验值*/
unsigned short check_sum(unsigned short *pAddr,int nLen, struct psd_header *psd_hdr)
{
	register unsigned int nLeft;
	register unsigned int sum = 0;
	register unsigned short *w;
	unsigned short answer = 0;
	
	if(psd_hdr)
	{
		nLeft = sizeof( struct psd_header);
		w = (unsigned short*)psd_hdr;
		while(nLeft>0)
		{
			sum += *w++;
			nLeft -= 2;
		}
	}
	
	nLeft = nLen;
	w=pAddr;
	while(nLeft>1)
	{
		sum += *w++;
		nLeft-=2;
	}
	if(nLeft==1)
	{
		*(unsigned char*)(&answer) = *(unsigned char*)w;
		sum += answer;
	}
	sum = (sum>>16) + (sum&0xffff);
	sum += (sum>>16);
	answer = ~sum;
	return answer;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
/*
void DEBUG(const char *fmt, ...)
{
#ifdef _DEBUG
    va_list ap;

    (void)fprintf(stderr, "[DEBUG]%s:", "SNAM_DEAMON");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {	
        fmt += strlen(fmt);
	 if (fmt[-1] != '\n')
	    (void)fputc('\n', stderr);
    }
#endif
    return;
}
*/
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
//SendCloseTcp()
//send close tcp packet 
//notice: all param are in network order
int SendCloseTcp(int sockfd,unsigned long sIP,unsigned short sPort,unsigned long dIP,unsigned short dPort,unsigned long seq, unsigned long ack_seq)
{
	struct tcphdr0 *tcp;
	struct iphdr0 *ip;
	unsigned char 	buffer[2048];
	int	bufferlen;
	struct  sockaddr_in addr;
	struct psd_header  *psd_hdr;
	unsigned char   sz[128];
	int rv=0;
	
#ifdef _DEBUG
#if 0
	struct in_addr sIPin,dIPin;
	char szSrcIP[50],szDstIP[50];
	sIPin.s_addr = sIP;
	strcpy(szSrcIP, (char*)inet_ntoa(sIPin));
	dIPin.s_addr = dIP;
	strcpy(szDstIP, (char*)inet_ntoa(dIPin));
	printf("SendCloseTcp: sIP = %s,dIP = %s, \nsPort = %d, dPort = %d, %u, %u\n" ,
		szSrcIP, szDstIP,
		ntohs(sPort), ntohs(dPort),sIP,dIP);
#endif
#endif
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = dPort;
	addr.sin_addr.s_addr = dIP;

	psd_hdr = (struct psd_header  *)sz;
	psd_hdr->saddr = sIP;	//source addr
	psd_hdr->daddr = dIP;	//dest addr
	psd_hdr->mbz=0;		//empty
	psd_hdr->ptcl = IPPROTO_TCP;     		//protocol type IPPROTO_TCP
	psd_hdr->tcpl = htons(sizeof(struct tcphdr0));	//TCP length
	
	bufferlen = sizeof(struct iphdr0) + sizeof(struct tcphdr0);
	//printf("send to bufferlen = %d \n",bufferlen);
	memset(buffer,0,sizeof(buffer));
	ip = (struct iphdr0* )buffer;
	
	//ip->ihl = sizeof(struct iphdr0)>>2;
	//ip->version = IPVERSION;
	ip->vhl=0;
	ip->vhl|=(4<<4);
	ip->vhl|=(sizeof(struct iphdr0)>>2);
	
	ip->tos = 0;
	ip->tot_len=htons(bufferlen);
	ip->id=0;
	ip->frag_off=0;
	ip->ttl=MAXTTL;
	ip->protocol=IPPROTO_TCP;
	ip->check=0;
	ip->daddr=dIP;
	ip->saddr=sIP;

	tcp = (struct tcphdr0*)(buffer+sizeof(struct iphdr0));
	tcp->source = sPort;
	tcp->dest = dPort;
	tcp->seq = seq;
	tcp->ack_seq = ack_seq;
	tcp->th_offx2=0;
	tcp->th_offx2|=(5<<4);
	tcp->th_offx2|=0x0e;
	tcp->th_flags=0;
	tcp->th_flags|=0x14;
	//tcp->doff = 5;
	//tcp->rst = 1;
	//tcp->urg = 0;
	//tcp->psh = 1;
	//tcp->syn=1;
	//tcp->res1 = 0x0e;
	//tcp->window=htons(5840);
         tcp->window=htons(0);	

	ip->check=0;
	ip->check = check_sum((unsigned short*)ip,sizeof(struct iphdr0),NULL);
	tcp->check = 0;
	tcp->check=check_sum((unsigned short*)tcp,sizeof(struct tcphdr0),psd_hdr);

	rv = sendto(sockfd,buffer,bufferlen,0,(struct sockaddr*)&addr,sizeof(addr));//struct sockaddr_in));
	if(rv == -1)
	{
#ifdef _DEBUG
		printf("errno: %d,%s , %d\n",errno,strerror(errno),htons(sPort));	
#endif
	}
	return rv;
}
/**********************************
*func name:发HTTP回应数据，告诉用户情况
*function:
*parameters:
*call:
*called:
*return:
*/
int SendAckTcp(int sockfd,unsigned long sIP,unsigned short sPort,unsigned long dIP,unsigned short dPort,unsigned long seq, unsigned long ack_seq)
{
	struct tcphdr0 *tcp;
	struct iphdr0 *ip;
	unsigned char 	buffer[2048];
	int	bufferlen;
	struct  sockaddr_in addr;
	struct psd_header  *psd_hdr;
	unsigned char   sz[128];
	int rv=0;
	unsigned char	ck_buf[2048];
	unsigned char*	data;
	size_t	data_len;
	
#ifdef _DEBUG
/*
	struct in_addr sIPin,dIPin;
	char szSrcIP[50],szDstIP[50];
	sIPin.s_addr = sIP;
	strcpy(szSrcIP, (char*)inet_ntoa(sIPin));
	dIPin.s_addr = dIP;
	strcpy(szDstIP, (char*)inet_ntoa(dIPin));
	printf("SendCloseTcp: sIP = %s,dIP = %s, \nsPort = %d, dPort = %d, %d, %d\n" ,
		szSrcIP, szDstIP,
		ntohs(sPort), ntohs(dPort),sIP,dIP);
*/
#endif
	if (ntohs(sPort) != 80)
		return rv;

	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = dPort;
	addr.sin_addr.s_addr = dIP;

	data = (unsigned char *)g_HttpWarning;
	data_len = strlen((const char *)data);
	//printf("g_HttpWarning = %s \n",g_HttpWarning);
	psd_hdr = (struct psd_header  *)sz;
	psd_hdr->saddr = sIP;	//source addr
	psd_hdr->daddr = dIP;	//dest addr
	psd_hdr->mbz=0;		//empty
	psd_hdr->ptcl = IPPROTO_TCP;     		//protocol type IPPROTO_TCP
	psd_hdr->tcpl = htons(sizeof(struct tcphdr0) + data_len);	//TCP length
	
	bufferlen = sizeof(struct iphdr0) + sizeof(struct tcphdr0) + data_len;
	//printf("send to bufferlen = %d \n",bufferlen);
	memset(buffer,0,sizeof(buffer));
	ip = (struct iphdr0*)buffer;
	//ip->ihl = sizeof(struct iphdr0)>>2;
	//ip->version = IPVERSION;
	ip->vhl=0;
	ip->vhl|=(4<<4);
	ip->vhl|=(sizeof(struct iphdr0)>>2);
	ip->tos = 0;
	ip->tot_len=htons(bufferlen);
	ip->id=0;
	ip->frag_off=0;
	ip->ttl=MAXTTL;
	ip->protocol=IPPROTO_TCP;
	ip->check=0;
	ip->daddr=dIP;
	ip->saddr=sIP;

	tcp = (struct tcphdr0*)(buffer+sizeof(struct iphdr0));
	tcp->source = sPort;
	tcp->dest = dPort;
	tcp->seq = seq;
	tcp->ack_seq = ack_seq;
	tcp->th_offx2=0;
	tcp->th_offx2|=(5<<4);
	tcp->th_offx2|=0x0e;
	tcp->th_flags=0x10;
	//tcp->doff = 5;
	//tcp->ack = 1;
	//tcp->psh = 0;
	//tcp->res1 = 0x0e;
	tcp->window=htons(5840);

	ip->check=0;
	ip->check = check_sum((unsigned short*)ip,sizeof(struct iphdr0),NULL);
       //printf("ip_check = %.2x \n",ip->check);
	tcp->check = 0;
	//memcpy(ck_buf, psd_hdr, sizeof(struct psd_header));
     //  memcpy(ck_buf + sizeof(struct psd_header), tcp, sizeof(struct tcphdr0));
     memcpy(ck_buf, tcp, sizeof(struct tcphdr0));
     //  memcpy(ck_buf + sizeof(struct psd_header) + sizeof(struct tcphdr0), data, data_len);
     memcpy(ck_buf + sizeof(struct tcphdr0), data, data_len);
	//tcp->check = check_sum((unsigned short*)ck_buf, sizeof(struct psd_header) + sizeof(struct tcphdr0) + data_len, psd_hdr);
	tcp->check = check_sum((unsigned short*)ck_buf, sizeof(struct tcphdr0) + data_len, psd_hdr);
	//printf("tcp_check = %.2x \n",tcp->check);
	memcpy(buffer + sizeof(struct iphdr0) + sizeof(struct tcphdr0), data, data_len);
	rv = sendto(sockfd,buffer,bufferlen,0,(struct sockaddr*)&addr,sizeof(addr));//struct sockaddr_in));
	//for(i =0;i<bufferlen;i++)
	//	printf("%.2X ",buffer[i]);
	if(rv == -1)
	{
#ifdef _DEBUG
		printf("errno: %d,%s , %d\n",errno,strerror(errno),htons(sPort));	
#endif
	}
	return rv;
}

//************************************************************************//
//2009 10 26 add 
int raw_net_socket()
{
	int on = 1;
	int sockfd;
	sockfd = socket(AF_INET,SOCK_RAW,SOCK_RAW);
	if(sockfd < 0)
	{
		error("UDP SOCKET FAIL!");
		return -1;
	}
	if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,(char*)&on,sizeof(on)))
	{
		error("SET UDP RAW SOCKET FAIL!");
		close(sockfd);
		return -1;
	}
	setuid(getuid());  //获得root权限保证发送伪报文成功
	return sockfd;
}

int raw_arp_socket()
{
     int sockfd;  
     if((sockfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP))) < 0)  
   //  if((sockfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0)  
     {  
         error("The raw socket was not created.\n");
         return  -1;  
     }
     setuid(getuid()); //获得root权限保证发送伪报文成功
     return sockfd;  
}


int 	send_arp_block_pkt(int sockfd, UDP_CLOSEINFO_ID udp_close_info_id)
{
	struct etherhdr0* ether;
	struct arphdr0*  arp;
	unsigned char buffer[1514];
	int bufferlen;
	int rv;
	struct sockaddr from;  

	bufferlen = sizeof(struct etherhdr0) + sizeof(struct arphdr0);
		
	ether = buffer;
	memcpy(ether->dst_mac, udp_close_info_id->src_mac, ETHER_ADDR_LEN);
	memcpy(ether->src_mac, udp_close_info_id->dst_mac, ETHER_ADDR_LEN);
	ether->src_mac[ETHER_ADDR_LEN-1] = ~(ether->src_mac[ETHER_ADDR_LEN-1]);
	ether->type = htons(0x0806);

	arp = buffer + sizeof(struct etherhdr0);
	arp->hd_type = htons(1);
	arp->pro_type = htons(0x0800);
	arp->hd_len = 0x06;
	arp->pro_len = 0x04;
	arp->op = htons(0x0002);
	memcpy(arp->src_mac, ether->src_mac, ETHER_ADDR_LEN);
	arp->src_ip = udp_close_info_id->dst_ip;
	memcpy(arp->dst_mac, ether->dst_mac, ETHER_ADDR_LEN);
	arp->dst_ip = udp_close_info_id->src_ip;
	strcpy(from.sa_data, "eth0");  
	
	printf("send arp pkt \n");
	if((rv = sendto(sockfd, buffer, bufferlen, 0, (struct sockaddr*)&from,sizeof(from))) == -1)
	{
		perror("aa");
		printf("send arp pkt fail.\n");
	}
	return rv;
}



int  send_icmp_host_unreachable(int sockfd, UDP_CLOSEINFO_ID udp_close_info_id)
{

	struct iphdr0 *ip;
	struct icmphdr0 *icmp;
	unsigned char buffer[2048];
	int bufferlen;
	unsigned char* p;
	struct  sockaddr_in addr;
	int rv;
	

	bufferlen  = sizeof(struct iphdr0) + 8 + udp_close_info_id->data_len;
	
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = udp_close_info_id->src_port;
	addr.sin_addr.s_addr = udp_close_info_id->src_ip;

//	printf("send icmp:%s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	
	ip = (struct iphdr0* )buffer;
	
	ip->vhl = 0; 
	ip->vhl |= (4<<4);
	ip->vhl |= (sizeof(struct iphdr0)>>2);
	
	ip->tos = 0;
	ip->tot_len = htons(bufferlen);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = MAXTTL;
	ip->protocol = 1;
	ip->check = 0;
	ip->saddr = udp_close_info_id->dst_ip;
	ip->daddr = udp_close_info_id->src_ip;


	icmp = buffer+sizeof(struct iphdr0);
	icmp->type = 3;
	icmp->code = 2;
	icmp->check = 0;
	icmp->other = 0;

	p = buffer + sizeof(struct iphdr0) + sizeof(struct icmphdr0);
	memcpy(p, udp_close_info_id->data, udp_close_info_id->data_len);

	icmp->check = check_sum(icmp, 8+udp_close_info_id->data_len, NULL);
	ip->check = check_sum(ip, sizeof(struct iphdr0) , NULL);
	
	if((rv = sendto(sockfd, buffer, bufferlen,0,(struct sockaddr*)&addr,sizeof(addr))) == -1)
	{
		printf("send icmp pkt fail.\n");
	}
	
	return rv;
}

