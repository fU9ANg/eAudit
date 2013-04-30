
#ifndef _FILTER_PACKETS_H
#define _FILTER_PACKETS_H

#define IP_PKT_TYPE     2048
#define ARP_PKT_TYPE  2054
#define ETHERTYPE_8021Q 33024

#ifndef IPV6
#define LOC_IP 16777343
#else
#define LOC_IP
#endif
/*extern function decalration*/
extern int first_filter(unsigned short ether_type);
extern int second_filter(unsigned long src_ip,unsigned long dst_ip);

#endif
