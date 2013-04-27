/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eAudit_authorize_list.h"
#include "eAudit_pub.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
/*
void get_itf_par(PAR_ITF_ANALYZE_ID par_itf_analysis_id,char *p_par)
{
    register char *p = NULL;
    
#ifdef _DEBUG
    assert((par_itf_analysis_id != NULL)||(p_par != NULL));
#endif

    p=strtok(p_par,PAR_DELIM);
    par_itf_analysis_id->pro_id = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->pro_tbl_shm_key = atol(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->cfg_file_set.maxPktFileSize = strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->cfg_file_set.maxPktFileNum = strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->func_switch.iAlarmSwitch = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->func_switch.iErrSwitch = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->func_switch.iStatSwitch = atoi(p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->rule_pool_key = strtoul(p,NULL,10);
    
    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->rule_num= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    strcpy(par_itf_analysis_id->pkt_file_dir,"%s",p);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->deposit_ivl_sec = strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->usr_list_key = strtoul(p,NULL,10);

     p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->usr_num = strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_network_key= strtoul(p,NULL,10);
  
    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_network_num= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_account_key= strtoul(p,NULL,10);
  
    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_account_num= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_cmd_key= strtoul(p,NULL,10);
  
    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_cmd_num= strtoul(p,NULL,10);

    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_custom_key= strtoul(p,NULL,10);
  
    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_custom_num= strtoul(p,NULL,10);

   p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_feature_key= strtoul(p,NULL,10);
  
    p = strtok(NULL,PAR_DELIM);
    par_itf_analysis_id->authorize_feature_num= strtoul(p,NULL,10);
    printf("get telnet parameter ok \n");
    return;
}
void print_itf_par(PAR_ITF_ANALYZE_ID par_itf_analysis_id)
{
    printf("FTP_analysis:pro_id = %d\n",par_itf_analysis_id->pro_id);
	
    printf("FTP_analysis:pro_tbl_shm_key = %d\n",par_itf_analysis_id->pro_tbl_shm_key);
	
    printf("FTP_analysis:cfg_file_set.maxPktFileSize = %ld\n",par_itf_analysis_id->cfg_file_set.maxPktFileSize);
	
    printf("FTP_analysis:cfg_file_set.maxPktFileNum = %ld\n",par_itf_analysis_id->cfg_file_set.maxPktFileNum);
	
    printf("FTP_analysis:func_switch.iAlarmSwitch = %d\n",par_itf_analysis_id->func_switch.iAlarmSwitch);
	
    printf("FTP_analysis:func_switch.iErrSwitch = %d\n",par_itf_analysis_id->func_switch.iErrSwitch);
	
    printf("FTP_analysis:func_switch.iStatSwitch = %d\n",par_itf_analysis_id->func_switch.iStatSwitch);
	
    printf("FTP_analysis:rule_pool_key = %d\n",par_itf_analysis_id->rule_pool_key);
	
    printf("FTP_analysis:rule_num = %ld\n",par_itf_analysis_id->rule_num);
	
    printf("FTP_analysis:pkt_file_dir = %s\n",par_itf_analysis_id->pkt_file_dir);
	
    printf("FTP_analysis:deposit_ivl_sec = %ld\n",par_itf_analysis_id->deposit_ivl_sec);
	
    printf("FTP_analysis:usr_list_key = %d\n",par_itf_analysis_id->usr_list_key);
	
    printf("FTP_analysis:usr_num = %ld\n",par_itf_analysis_id->usr_num);
	
    printf("FTP_analysis:authorize_network_key = %d\n",par_itf_analysis_id->authorize_network_key);
	
    printf("FTP_analysis:authorize_network_num = %ld\n",par_itf_analysis_id->authorize_network_num);
	
    printf("FTP_analysis:authorize_account_key = %d\n",par_itf_analysis_id->authorize_account_key);
	
    printf("FTP_analysis:authorize_account_num = %ld\n",par_itf_analysis_id->authorize_account_num);
	
    printf("FTP_analysis:authorize_cmd_key = %d\n",par_itf_analysis_id->authorize_cmd_key);
	
    printf("FTP_analysis:authorize_cmd_num = %ld\n",par_itf_analysis_id->authorize_cmd_num);
	
    printf("FTP_analysis:authorize_custom_key = %d\n",par_itf_analysis_id->authorize_custom_key);
	
    printf("FTP_analysis:authorize_custom_num = %ld\n",par_itf_analysis_id->authorize_custom_num);
	
    printf("FTP_analysis:authorize_feature_key = %d\n",par_itf_analysis_id->authorize_feature_key);
	
    printf("FTP_analysis:authorize_feature_num = %ld\n",par_itf_analysis_id->authorize_feature_num);
	
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
/*
int get_usr_info(USR_LIST_MEM_ID src,USR_LIST_MEM_ID dst,USR_LIST_MEM_ID q,unsigned long usr_num,DST_INFO_ID dst_info,SRC_INFO_ID src_info)
{  
    register unsigned long i = 0;
    USR_LIST_MEM_ID p = NULL;
    if ((NULL == src) || (NULL == dst)||(src_info==NULL)||(dst_info == NULL)||(q ==NULL))
        return ERR;
   
    for (i = 0;i < usr_num;i++)
    { 
        p = q + i;
        switch(p->iUsrCertifyMethod){
		case IP_CERTIFITY:
			if(p->ip==src_info->src_ip)
				*src = *p;
			if(p->ip == dst_info->dst_ip)
				*dst = *p;
			if((p->ip==src_info->src_ip)||(p->ip == dst_info->dst_ip))
				return OK;
			break;
		case MAC_CERTIFITY:
			if(strncmp((char *)p->strMac,(char *)src_info->src_mac,12)==0)
				*src = *p;
			if(strncmp((char *)p->strMac,(char *)dst_info->dst_mac,12)==0)
				*dst = *p;
			if((strncmp((char *)p->strMac,(char *)src_info->src_mac,6)==12)||(strncmp((char *)p->strMac,(char *)dst_info->dst_mac,12)==0))
				return OK;
			break;
		case IP_MAC_CERTIFITY:
			if((p->ip==src_info->src_ip)&&(strncmp((char *)p->strMac,(char *)src_info->src_mac,12)==0))
				*src = *p;
			if((p->ip == dst_info->dst_ip)&&(strncmp((char *)p->strMac,(char *)dst_info->dst_mac,12)==0))
				*dst = *p;
			if(((p->ip==src_info->src_ip)&&(strncmp((char *)p->strMac,(char *)src_info->src_mac,12)==0))||((p->ip == dst_info->dst_ip)&&(strncmp((char *)p->strMac,(char *)dst_info->dst_mac,12)==0)))
				return OK;
			break;
		case DYNAMIC_CERTIFITY:
			break;
		default:
			break;
		} 

	}
	return ERR;
}
*/
