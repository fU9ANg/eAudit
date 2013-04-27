/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _ARP_H
#define _ARP_H

typedef struct tagARP_FRAME
{
    unsigned short hw_type;              /* hardware address */
    unsigned short Prot_type;            /* protocol address */
    unsigned char hw_addr_len;           /* length of hardware address */
    unsigned char orot_addr_len;         /* length of protocol address */
    unsigned short opcode;               /* ARP/RARP */

    unsigned char send_hw_addr[6];      /* sender hardware address */
    unsigned char send_prot_addr[4];       /* sender protocol address */
    unsigned char targ_hw_addr[6];      /* target hardware address */
    unsigned char targ_prot_addr[4];       /* target protocol address */
}   ARP_FRAME, *ARP_FRAME_ID;
#define ARP_FRAME_SIZE sizeof(ARP_FRAME)

#endif
