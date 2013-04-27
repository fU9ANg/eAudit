/*************************************************************************************
* Copyright (c)
* All rights reserved.
* 
* This is unpublished proprietary source code of Shanghai Sail Infomation TEC Co. LTD
*
* The copyright notice above does not evidence any actual or intended
* publication of such source code.
*
* file name:
* file id:
* summary:
* 
* current edition:
* author:tqy
* date:2007-9
*
* history of modification:
*    modificator:
*    date:
*    content:
*
* Copyright (c) 2007
*	
*/
#ifndef _INTERFACE_FLOW_H
#define _INTERFACE_FLOW_H

#include "sail_ether.h"
#include "eAudit_sys_msg_que.h"

#define STAT_MSG_QUE_KEY 88888L
#define FLOW_STAT_ANAS_MODEL_PATH "./FLOWSTAT_analysis"

#define IPV4_ETHER_HEADER_SIZE 14
#define IP_ETHER_HEADER_SIZE 34

#define LOC_IPPRO_TYPE 
#define LOC_ARPPRO_TYPE 
#define LOC_TCP_TYPE 

typedef struct tagPKT_SUM_INFO
{
    struct timeval ts;            /*time stamp*/
    unsigned long cap_len;        /*the porsion len*/
    unsigned char ip_p;          
    unsigned long src_ip;                      
    unsigned long dest_ip;               
    unsigned short src_port;    
    unsigned short dest_port;   
}__attribute__ ((packed))PKT_SUM_INFO,* PKT_SUM_INFO_ID;
#define PKT_SUM_INFO_SIZE sizeof(PKT_SUM_INFO)

//#define STAT_MSG_DATA_SIZE 39

typedef struct tagSTAT_MSG_FMT
{
    long msg_type;                  /*消息类型*/
    ETHER_HDR ether_hdr;      /*以太网帧头*/
    PKT_SUM_INFO sum_info;  /*报文简要信息*/
}STAT_MSG_FMT,*STAT_MSG_FMT_ID;
#define STAT_MSG_FMT_SIZE sizeof(STAT_MSG_FMT)

#define STAT_MSG_DATA_SIZE (STAT_MSG_FMT_SIZE - 4)

#endif
