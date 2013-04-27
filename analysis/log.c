/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>

#include "log.h"
#include "interface.h"
#include "debug.h"
#include "common.h"
/*
 *  Two source files: log.c and log.h
 *  	insert data into log(type:err, info, debug, fatal, warn) file.
 *	example:
 *		FTP_analysis_debug_log.dat
 *		FTP_analysis_err_log.dat  
 *		FTP_analysis_fatal_log.dat  
 *		FTP_analysis_info_log.dat  
 *		FTP_analysis_warn_log.dat
 *
 *  Please RTFSC:read the f**king source code :-)
 */

	int 
init_log(model_name, protocol_name, tool, filter_pri)
	char	*model_name;
	char	*protocol_name;
	int	 tool;
	int	 filter_pri;
{

	char	program_name[MAX_PROGRAM_NAME_SIZE + 1];
	if((!model_name) || (!protocol_name))	return ERR;

	snprintf(program_name, MAX_PROGRAM_NAME_SIZE + 1,
		"%s%s", protocol_name, ANALYZE_PROC_SUFFIX);    /* ftp_analysis */
	
	if((tool==SYS_LOG) || (tool==FILE_LOG)) {
		if(program_name) {       /* string "program_name" is not NULL */
			if(strlen(program_name) > MAX_MODEL_NAME_SIZE)
				model_name[0] = '\0';
			else {
				strncpy(model_name, program_name, MAX_MODEL_NAME_SIZE);
				model_name[MAX_MODEL_NAME_SIZE] = '\0';
			}
		} else  
			model_name[0] = '\0';
	}

	switch(tool) {
		case SYS_LOG:
			openlog(program_name, LOG_PID | LOG_CONS, 0);
			if(filter_pri != LOG_NOT_FILTER)
				setlogmask(LOG_UPTO(FILTER_LOG_PRI));
			break;
		case FILE_LOG:	
			break;
		default:	
			break;
	}	/* switch */
	
	/* write data to log file(DEBUG, INFO, WARNING, ERR, NOTICE) */
	write_log(model_name, protocol_name, LOG_DEBUG,   FILE_LOG,
		  __FILE__, __LINE__, SINGLE, "Start analyze debug log");
	write_log(model_name, protocol_name, LOG_INFO,    FILE_LOG,
		  __FILE__, __LINE__, SINGLE, "Start analyze info log file");
	write_log(model_name, protocol_name, LOG_WARNING, FILE_LOG,
		  __FILE__, __LINE__, SINGLE, "Start analyze warning log");
	write_log(model_name, protocol_name, LOG_ERR,     FILE_LOG,
		  __FILE__, __LINE__, SINGLE, "Start analyze err log");
	write_log(model_name, protocol_name, LOG_NOTICE,  FILE_LOG,
		  __FILE__, __LINE__, SINGLE, "Start analyze notice log");

	return OK;
}


	int 
write_log(
	char	*model_name, 
	char	*protocol_name, 
	int 	level,
	int	tool, 
	char	*file_name,
	int	line_no,
	int	what_task,...)
{
	int ret = OK;
	va_list args;

	if ((what_task != SINGLE) && (what_task != MULTITASK))    
		return ERR;

	switch(tool) {
		case FILE_LOG:
			va_start(args, what_task);
			ret = write_log_to_file(model_name, protocol_name, level,
						file_name,  line_no, what_task, args);
			va_end(args); 
			break;
	     
		case SYS_LOG:
			va_start(args, what_task);
			syslog(level, args);
			va_end(args);
			break;
				 
		case DB_LOG:
			break;
		default:
			return ERR;
	}

	return ret;
}



	int
write_log_to_file(model_name, protocol_name, level, file_name, line_no, what_task, log_cnt)
	int	 what_task;
	int	 level;
	int	 line_no;
	va_list	 log_cnt;
	char	*model_name;
	char	*protocol_name;
	char	*file_name;
{
	int 	tmp_level	= level;
	int	ret		= OK;
	char	log_file_path[LOG_PATH_SIZE + 1];

	/*  value of level is (info, warn, err, debug, fatal) */
	if(!get_log_file_path(model_name, protocol_name, tmp_level, 
			       log_file_path, LOG_PATH_SIZE + 1))	return ERR;

	DEBUG("[DEBUG]***log_file_path:%s\n", log_file_path);
	switch(what_task) {
		case SINGLE: 
			ret = write_file_log_single(tmp_level, log_file_path, 	\
						    file_name, line_no, log_cnt);
			break;
		case MULTITASK:
			/* return write_file_log_multi(tmp_level, log_file_path,\
						       file_name,line_no,log_cnt); */
			break;
		default:
			return ERR;
	}
	return ret;
}


/*
 *  write a line data to log file
 *  format:
 *  "FileName:analyze_log.c Line No:102 content:Start analyze debug log Time:2010/6/12 -Sat- 11:10:0"
 */
int 
write_file_log_single(level, file_path, file_name, line_no, log_cnt)
int	 level;
char	*file_path;
char 	*file_name;
int	 line_no;
va_list  log_cnt;
{
	FILE	*fp 		= NULL;
	char	*log_cnt_ptr 	= NULL;
	char	 str_line_no[LINE_MAX_SIZE + 1];
	char	 str_time   [TIME_STR_SIZE + 1];


	if(!file_path) {
		DEBUG("file_path==NULL\n");	/* where is DEBUG? */
		return ERR;
	}

	if(!(log_cnt_ptr = va_arg(log_cnt, char *))) {
		DEBUG("log_cnt_ptr==NULL\n"); 
		return ERR;
	}

	if(get_file_size(file_path) > MAX_LOG_FILE_SIZE) {
		if (!(fp = fopen(file_path, "w+"))) {
			DEBUG("fopen(file_path, w+)==NULL\n");
			return ERR;
		}
	} else  {
		if (!(fp = fopen(file_path, "a+"))) {
			DEBUG("%s\n", file_path);
			DEBUG("fopen(file_path,a+)==NULL\n");     
			return ERR;
		}
	}
	
	if (file_name) {
		fputs("FileName:", fp);
		fputs(file_name, fp);
		fputs(" ", fp);
	}

	snprintf(str_line_no, LINE_MAX_SIZE+1, "%d", line_no);

	fputs("Line No:", fp);
	fputs(str_line_no, fp);
	fputs(" ", fp);

	fputs("content:", fp);
	fputs(log_cnt_ptr, fp);
	fputs(" ", fp);

	get_now_time(str_time, TIME_STR_SIZE+1);

	fputs("Time:", fp);
	fputs(str_time, fp);

	fputc('\n', fp);

	fflush(fp);
	fclose(fp);

    return OK;
}


/*
 *  Get a string for path of log file
 *  Format: 
 *		call get_log_file_path("FTP", "FTP", LOG_INFO, result-str, 256)
 *		result-str = "/log/FTP/FTP_analysis_err_log.dat"
 */
	char *
get_log_file_path(model_name, protocol_name, level, file_path, path_len)
	char *model_name;
	char *protocol_name;
	int   level;
	char *file_path;
	int   path_len;
{
	int tmp_level = level;
		
	if (!file_path)	/* string is NULL */
		return NULL;

	switch(tmp_level) {
		case LOG_DEBUG:
			snprintf(file_path, path_len, "%s/%s/%s_%s", LOG_DIR_PATH,\
				 protocol_name, model_name, DEBUG_LOG_FILE_NAME); break;

		case LOG_INFO:
			snprintf(file_path, path_len, "%s/%s/%s_%s", LOG_DIR_PATH,\
				 protocol_name, model_name, INFO_LOG_FILE_NAME);  break;

		case LOG_WARNING:
			snprintf(file_path, path_len, "%s/%s/%s_%s", LOG_DIR_PATH,\
				 protocol_name, model_name, WARN_LOG_FILE_NAME);  break;

		case LOG_ERR:
			snprintf(file_path, path_len, "%s/%s/%s_%s", LOG_DIR_PATH,\
				 protocol_name, model_name, ERR_LOG_FILE_NAME);   break;

		case LOG_NOTICE:
			snprintf(file_path, path_len, "%s/%s/%s_%s", LOG_DIR_PATH,\
				 protocol_name, model_name, FATAL_LOG_FILE_NAME); break;

		default:
			file_path = NULL;
		break;
	}
	return file_path;
}


/* 
 *  Get a string for now time.
 */
	char *
get_now_time(str_time, str_len)
	char *str_time;
	int   str_len;
{
	time_t 	now;
	struct 	tm *p;   
	char 	*addr 	= str_time;
	char 	*week[] = {	"-Sun-",
				"-Mon-",
				"-Tue-",
				"-Wed-",
				"-Thu-",
				"-Fri-",
				"-Sat-"};

	time(&now);
	p = localtime(&now);
	snprintf(str_time, str_len, "%d/%d/%d %s %d:%d:%d", 		\
		                     1900+p->tm_year, 1+p->tm_mon,	\
				     p->tm_mday, week[p->tm_wday],	\
				     p->tm_hour, p->tm_min, p->tm_sec);
	str_time[str_len] = 0x00;
	
	return addr;
}


void printf_log(
	va_list log_cnt
	)	/* print args arguments... */
{
	char *log_cnt_ptr = NULL;
	log_cnt_ptr = va_arg(log_cnt, char *);
	printf("%s\n", log_cnt_ptr);
}

