/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_COMMON_H
#define ANALYZE_COMMON_H

#include <sys/types.h>
#include <time.h>

#include "interface.h"


/* prototypes */
void analyze_common(EA_ITF_PAR_INFO_ID		itf_par_info_id, 
		    MMAP_FILE_INFO_ID		mmap_file_info_id,
		    CALLBACK_FUNC_SET_ID 	callback_func_set_id);

void modify_dynamic_strategy(unsigned long src_ip,
		    unsigned short	src_port,
		    char		pkt_type,
		    char		cmd,
		    unsigned long	res_index,
		    EA_ITF_PAR_INFO_ID	itf_par_info_id);

void stop_process(int sig_no);
void set_stop_handle();

void get_current_date(char* cur_date, int date_len);
void change_current_date(unsigned long cur_date, int date_len);
int  is_next_day(struct tm* ptime);

int  file_is_exist(char* filename);
int  sem_lock (int semid);
int  sem_unlock (int semid);
int  set_monitor_signal(int sig_num, sa_sigaction_t act_func);

off_t get_file_size(char *filename);

#endif /* ANALYZE_COMMON_H */
