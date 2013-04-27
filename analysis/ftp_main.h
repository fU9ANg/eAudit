/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef FTP_ANALYZE_MAIN_H
#define FTP_ANALYZE_MAIN_H

#include <signal.h>		
#include "ftp_interface.h"


/* prototypes */
void ftp_analyze(EA_ITF_PAR_INFO_ID	itf_par_info_id,
		 MMAP_FILE_INFO_ID	mmap_file_info_id);

void handle_session();
void terminate();
void terminate_session();
void add_new_session();
void ftp_analyze_process();
void analysis_ftp_cmd();

int  analysis_delay();
int  analysis_cmd_user();
int  analysis_cmd_pwd ();
int  analysis_cmd_cwd ();
int  analysis_cmd_size();
int  analysis_cmd_dele();
int  analysis_cmd_rnfr();
int  analysis_cmd_rnto();
int  analysis_cmd_port();
int  analysis_cmd_pasv();
int  analysis_cmd_retr(); 
int  analysis_cmd_stor();
int  analysis_cmd_quit();
int  is_new_session();
int  set_pkt_basic_info();
int  read_ftp_monitor_cfg_file();



void initialize_tbls();
void init_global_var();
void ftp_data_session_process();
void search_in_cmd_tbl(char* cmd_name);
void set_callback_fun_set(CALLBACK_FUNC_SET_ID callback_func_set_id);
void monitor_signal_handler(int signum, siginfo_t* siginfo, void* arg);

void monitor_conn();
void monitor_flux();
void add_conn_times();
void monitor_conn_times();
void display_data(PKT_BASIC_INFO_ID pkt_basic_info_id);
void display_pkt_basic_info(PKT_BASIC_INFO_ID pkt_basic_info_id);


#endif  /* FTP_ANALYZE_MAIN_H */

