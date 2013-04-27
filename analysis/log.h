/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_LOG_H
#define ANALYZE_LOG_H

#include <stdarg.h>
#include <sys/types.h>
#include <syslog.h>

int   init_log (char* model_name,
		char* protocol_name,
		int   tool,
		int   filter_pri);

int   write_log(char* model_name,
		char* protocol_name,
		int   level,
		int   tool,
		char* file_name,
		int   line_no,
		int   what_task, ...);

int   write_log_to_file    (char*  model_name,
			    char*  protocol_name,
			    int    level,
			    char*  file_name,
			    int    line_no,
			    int    what_task,
			   va_list log_cnt);

int   write_file_log_single(int    level,
			    char*  file_path,
			    char*  file_name,
			    int    line_no,
			   va_list log_cnt);

char* get_log_file_path    (char*  model_name,
			    char*  protocol_name,
			    int    level,
			    char*  file_path,
			    int	   path_len);

char* get_now_time(char* str_time,
		   int   str_len);

void  printf_log  (va_list log_cnt);


#endif /* ANALYZE_LOG_H */
