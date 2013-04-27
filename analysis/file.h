/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_FILE_H
#define ANALYZE_FILE_H

#include "interface.h"

#define MAX_RPT_RD_MMAP_FILE_TIMES	5
#define MAX_DELAY_SEC			1


void read_mmap_file (EA_ITF_PAR_INFO_ID itf_par_info_id,			\
		     MMAP_FILE_INFO_ID mmap_file_info_id,			\
		     CALLBACK_FUNC_SET_ID callback_func_set_id);

int inc_fileno      (EA_ITF_PAR_INFO_ID itf_par_info_id,			\
		    unsigned long fileno);

int open_fileno_file(EA_ITF_PAR_INFO_ID itf_par_info_id);

int set_file_no     (int fd,unsigned long file_no);

int mmap_file       (EA_ITF_PAR_INFO_ID itf_par_info_id,			\
		     MMAP_FILE_INFO_ID mmap_file_info_id,			\
		     char*	file_path);

int unmmap_file	    (EA_ITF_PAR_INFO_ID itf_par_info_id,			\
		     MMAP_FILE_INFO_ID mmap_file_info_id);

void analyze_pkt_file_hdr(MMAP_FILE_INFO_ID mmap_file_info_id);
void get_protect_rule_id (MMAP_FILE_INFO_ID mmap_file_info_id);
void get_libpcap_pkt_hdr (MMAP_FILE_INFO_ID mmap_file_info_id);

unsigned long read_file_no(int fd);


#endif /* ANALYZE_FILE_H */
