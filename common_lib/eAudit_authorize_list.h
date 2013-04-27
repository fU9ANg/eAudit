/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_AUTHORIZE_LIST_H
#define _EAUDIT_AUTHORIZE_LIST_H
#include "interface_pub.h"
#include "interface_analyze.h"
/*∫Í∂®“Â«¯”Ú*/
#define 	IP_CERTIFITY 		0
#define   MAC_CERTIFITY  		1
#define   IP_MAC_CERTIFITY 	2
#define   DYNAMIC_CERTIFITY 3


/*define extern area*/
int get_usr_info(USR_LIST_MEM_ID src,USR_LIST_MEM_ID dst,USR_LIST_MEM_ID q,unsigned long usr_num,DST_INFO_ID dst_info,SRC_INFO_ID src_info);
void get_itf_par(PAR_ITF_ANALYZE_ID par_itf_analysis_id, char *p_par);
void print_itf_par(PAR_ITF_ANALYZE_ID par_itf_analysis_id);
#endif

