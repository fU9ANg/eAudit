/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _SAIL_ICMP_H
#define _SAIL_ICMP_H

#include "sail_ip.h"

typedef struct tagICMP_HDR
{
    unsigned char type;
    unsigned char code;
    unsigned short csum;
    union
    {
        unsigned char pptr;

        struct in_addr gwaddr;

        struct idseq
        {
            unsigned short id;
            unsigned short seq;
        } idseq;

        int sih_void;

        struct pmtu 
        {
            unsigned short ipm_void;
            unsigned short nextmtu;
        } pmtu;

        struct rtradv 
        {
            unsigned char num_addrs;
            unsigned char wpa;
            unsigned short lifetime;
        } rtradv;
    } icmp_hun;

#define s_icmp_pptr       icmp_hun.pptr
#define s_icmp_gwaddr     icmp_hun.gwaddr
#define s_icmp_id         icmp_hun.idseq.id
#define s_icmp_seq        icmp_hun.idseq.seq
#define s_icmp_void       icmp_hun.sih_void
#define s_icmp_pmvoid     icmp_hun.pmtu.ipm_void
#define s_icmp_nextmtu    icmp_hun.pmtu.nextmtu
#define s_icmp_num_addrs  icmp_hun.rtradv.num_addrs
#define s_icmp_wpa        icmp_hun.rtradv.wpa
#define s_icmp_lifetime   icmp_hun.rtradv.lifetime

    union 
    {
        /* timestamp */
        struct ts 
        {
            unsigned long otime;
            unsigned long rtime;
            unsigned long ttime;
        } ts;
        
        /* IP header for unreach */
        struct ih_ip  
        {
            IP_HDR *ip;
            /* options and then 64 bits of data */
        } ip;
        
        struct ra_addr 
        {
            unsigned long addr;
            unsigned long preference;
        } radv;

        unsigned long mask;

        char    data[1];

    } icmp_dun;
#define s_icmp_otime        icmp_dun.ts.otime
#define s_icmp_rtime        icmp_dun.ts.rtime
#define s_icmp_ttime        icmp_dun.ts.ttime
#define s_icmp_ip           icmp_dun.ih_ip
#define s_icmp_radv         icmp_dun.radv
#define s_icmp_mask         icmp_dun.mask
#define s_icmp_data         icmp_dun.data

}   ICMP_HDR,*ICMP_HDR_ID;
#define ICMP_HDR_SIZE sizeof(ICMP_HDR)

#endif
