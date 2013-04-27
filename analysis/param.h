/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_PARAM_H
#define ANALYZE_PARAM_H

#include <sys/types.h>


#include "analyze_interface.h"


/*
 *  把参数p_par中的数据流根据格式分解到PAR_ITF_ANALYZE_ID
 *  和EA_ITF_PAR_INFO_ID两个数据结构中.
 */
void get_itf_par      (PAR_ITF_ANALYZE_ID par_itf_analyze_id,			\
		       char* p_par,	char redirect_flag);

void print_itf_par    (PAR_ITF_ANALYZE_ID par_itf_analyze_id);

void convet_par_itf   (EA_ITF_PAR_INFO_ID itf_par_info_id,			\
		       PAR_ITF_ANALYZE_ID par_itf_analysis_id, char redirect_flag);

void* get_shm_addr    (key_t key, int shmflg);

void get_protocol_name(char* protocol_name,PAR_ITF_ANALYZE_ID par_itf_analysis_id);

#endif /* ANALYZE_PARAM_H */
