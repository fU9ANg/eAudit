/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_LOG_H
#define _EAUDIT_LOG_H
#include "interface_analyze.h"

#define MAX_LOG_FILE_SIZE   1024*1024*512

#define MAX_MODEL_NAME_SIZE 32

#define LOG_PATH_SIZE  512
#define LINE_MAX_SIZE  64
#define TIME_STR_SIZE  32

#define LOG_NOT_FILTER -1
#define FILTER_LOG_PRI LOG_NOTICE

/*对应级别日志的存放类型*/
#define DEBUG_LOG_FILE_NAME     "debug_log.dat"
#define INFO_LOG_FILE_NAME       "info_log.dat"
#define WARN_LOG_FILE_NAME      "warn_log.dat"
#define ERR_LOG_FILE_NAME         "err_log.dat"
#define FATAL_LOG_FILE_NAME     "fatal_log.dat"

/*记录日志用的工具类别*/
#define LOG_NOT_RECORD 0
#define FILE_LOG       1
#define DB_LOG         2
#define SYS_LOG        3

/*记日志环境*/
#define SINGLE    0
#define MULTITASK 1  /*多任务*/

/*extern global var declaration*/
extern char g_ModelName[MAX_MODEL_NAME_SIZE+1];

/*extern function declaration*/
extern void init_log(char *model_name,int tool,int filter_pri);
extern int write_log(int level,int tool,char *file_name,int line_no,int what_task,...);
extern char *get_now_time(char *str_time);
extern char *get_current_date(char *str_time);
extern char g_protocol_name[MAX_PRO_NAME_SIZE + 1];

#endif
