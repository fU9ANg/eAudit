/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdarg.h> 

#include <unistd.h>
#include <fcntl.h>

#include <time.h>
#include <syslog.h>

#include "eAudit_pub.h"
#include "eAudit_config.h"
#include "eAudit_file_lock.h"
#include "eAudit_log.h"

/*global var*/
char g_ModelName[MAX_MODEL_NAME_SIZE+1];
char g_Log_Base_Dir[MAX_DIR_SIZE+1];
char g_protocol_name[MAX_PRO_NAME_SIZE + 1];
/*static staticfunction declaration*/
static int write_log_to_file(int level,char *file_name,int line_no,int what_task, va_list log_cnt);

static int write_file_log_single(int level,char *file_path,char *file_name,int line_no,va_list log_cnt);
static int write_file_log_multi(int level,char *file_path,char *file_name,int line_no,va_list log_cnt);

static char *get_log_file_path(int  level,char *file_path);
static void printf_log(va_list log_cnt);

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void init_log(char *model_name,int tool,int filter_pri)
{
    switch (tool)
    {
        case FILE_LOG:
            memset(&g_ModelName,0x00,MAX_MODEL_NAME_SIZE);
            if (NULL != model_name)
            {
                if (strlen(model_name) > MAX_MODEL_NAME_SIZE)
                {
                    g_ModelName[0] = '\0';
                }
                else
                {
                    strncpy(g_ModelName,model_name,MAX_MODEL_NAME_SIZE);
                }
            }
            
            break;
        case SYS_LOG:
            memset(&g_ModelName,0x00,MAX_MODEL_NAME_SIZE);
            if (NULL != model_name)
            {
                if (strlen(model_name) > MAX_MODEL_NAME_SIZE)
                {
                    g_ModelName[0] = '\0';
                }
                else
                {
                    strncpy(g_ModelName,model_name,MAX_MODEL_NAME_SIZE);
                }
            }
            
            openlog(model_name,LOG_PID|LOG_CONS,0);
            if (filter_pri != LOG_NOT_FILTER)
            {
                (void)setlogmask(LOG_UPTO(FILTER_LOG_PRI));
            }
            break;
        default:
            break;
    }
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_base_dir(char *dir)
{
    if (NULL == dir)
        return;

    strcpy(g_Log_Base_Dir,dir);    
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void printf_log(va_list log_cnt)
{
    char *log_cnt_ptr = NULL;

    log_cnt_ptr = va_arg(log_cnt,char *);

    printf("%s",log_cnt_ptr);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int write_log(int level,int tool,char *file_name,int line_no,int what_task,...)
{
    int ret;
    va_list args;

    if ((what_task != SINGLE) && (what_task != MULTITASK))    
        return ERR;

    switch (tool)
    {
    case FILE_LOG:
	     va_start(args, what_task);
	     
       if (LOG_DEBUG == level)
	     {
           printf_log(args);
	     }

       if (FILE_LOG == tool)
       {
	         ret = write_log_to_file(level,file_name,line_no,what_task,args);
	     }
	     
       va_end(args); 
	     return ret;
	     
   case SYS_LOG:
       va_start(args, what_task);
       syslog(level,args);
       va_end(args); 
	 case DB_LOG:
	 default:
	     return ERR;
        
   }

   return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int write_log_to_file(int level,char *file_name,int line_no,int what_task, va_list log_cnt)
{
     int tmp_level = level;
     char log_file_path[LOG_PATH_SIZE];

     memset(&log_file_path,0x00,LOG_PATH_SIZE);
	 
     if (NULL == get_log_file_path(tmp_level,log_file_path))
         return ERR;

     switch (what_task)
     {
         case SINGLE: 
	     return write_file_log_single(tmp_level,log_file_path,file_name,line_no,log_cnt);
	 case MULTITASK:
             return write_file_log_multi(tmp_level,log_file_path,file_name,line_no,log_cnt);
	 default:
	     return ERR;
     }

     return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int write_file_log_single(int level,char *file_path,char *file_name,int line_no,va_list log_cnt)
{
    FILE *fp = NULL;
    char str_line_no[LINE_MAX_SIZE];
    char *log_cnt_ptr = NULL;
    char str_time[TIME_STR_SIZE];
    if (NULL == file_path)
        return ERR;

    if (NULL == (log_cnt_ptr = va_arg(log_cnt,char *)))
        return ERR;

    if (get_file_size(file_path) > MAX_LOG_FILE_SIZE)
    {
        if (NULL == (fp = fopen(file_path,"w+")))
            return ERR;
    }
    else
    {
        if (NULL == (fp = fopen(file_path,"a+")))
            return ERR;
    }
	
    if (NULL != file_name)
    {
        fputs("FileName:",fp);
        fputs(file_name,fp);
        fputs(" ",fp);
    }

    memset(&str_line_no,0x00,LINE_MAX_SIZE);
    sprintf(str_line_no,"%d",line_no);
    fputs("Line No:",fp);
    fputs(str_line_no,fp);
    fputs(" ",fp);

    fputs("content:",fp);
    fputs(log_cnt_ptr,fp);
    fputs(" ",fp);

    memset(&str_time,0x00,TIME_STR_SIZE);
    get_now_time(str_time);
    fputs("Time:",fp);     
    fputs(str_time,fp);

    fputc('\n',fp);

    fflush(fp);
    fclose(fp);

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int write_file_log_multi(int level,char *file_path,char *file_name,int line_no,va_list log_cnt)
{
    int fd;
    FILE *fp = NULL;
    char str_line_no[LINE_MAX_SIZE];
    char *log_cnt_ptr = NULL;
    char str_time[TIME_STR_SIZE];

    if (NULL == file_path)
        return ERR;

    if (NULL == (log_cnt_ptr = va_arg(log_cnt,char *)))
         return ERR;

    if (get_file_size(file_path) > MAX_LOG_FILE_SIZE)
    {
        if (NULL == (fp = fopen(file_path,"w+")))
            return ERR;
    }
    else
    {
        if (NULL == (fp = fopen(file_path,"a+")))
            return ERR;
    }

    fd = fileno(fp);
    if (CHK_LK_ERR == check_file_lock(fd,F_WRLCK))
    {
        fclose(fp);
        return ERR;
    }
    else if (-1 == check_file_lock(fd,F_WRLCK))
    {
        if (-1 == lock_all_file(fd,F_WRLCK))
        {
            fclose(fp);
            return ERR;
        }
    }
    else
    {
        fclose(fp);
        return OK;
    }

    if (NULL != file_name)
    {
        fputs("FileName:",fp);
        fputs(file_name,fp);
        fputs(" ",fp);
    }

    memset(&str_line_no,0x00,LINE_MAX_SIZE);
    sprintf(str_line_no,"%d",line_no);
    fputs("Line No:",fp);
    fputs(str_line_no,fp);
    fputs(" ",fp);

    fputs("content:",fp);
    fputs(log_cnt_ptr,fp);
    fputs(" ",fp);

    memset(&str_time,0x00,TIME_STR_SIZE);
    get_now_time(str_time);

    fputs("Time:",fp);    
    fputs(str_time,fp);

    fputc('\n',fp);

    if (-1 == unlock_all_file(fd))
    {
        fclose(fp);
        return ERR;
    }

    fflush(fp);
    fclose(fp);

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static char *get_log_file_path(int level,char *file_path)
{
    int tmp_level = level;
    char *addr = file_path;
    char log_path[LOG_PATH_SIZE+1];
		
    if (NULL == addr)
        return NULL;

    memset(&log_path,0x00,LOG_PATH_SIZE);
    switch (tmp_level)
    {
         case LOG_DEBUG:
             sprintf(log_path,"%s/%s/%s_%s",g_Log_Base_Dir,g_protocol_name,g_ModelName,DEBUG_LOG_FILE_NAME);     
	     addr = strcpy(file_path,log_path);
	     break;

	 case LOG_INFO:
             sprintf(log_path,"%s/%s/%s_%s",g_Log_Base_Dir,g_protocol_name,g_ModelName,INFO_LOG_FILE_NAME);
             addr = strcpy(file_path,log_path);
	     break;

	 case LOG_WARNING:
             sprintf(log_path,"%s/%s/%s_%s",g_Log_Base_Dir,g_protocol_name,g_ModelName,WARN_LOG_FILE_NAME);
             addr = strcpy(file_path,log_path);
             break;

	 case LOG_ERR:
             sprintf(log_path,"%s/%s/%s_%s",g_Log_Base_Dir,g_protocol_name,g_ModelName,ERR_LOG_FILE_NAME);
             addr = strcpy(file_path,log_path);
             break;

	 case LOG_NOTICE:
             sprintf(log_path,"%s/%s/%s_%s",g_Log_Base_Dir,g_protocol_name,g_ModelName,FATAL_LOG_FILE_NAME);
             addr = strcpy(file_path,log_path);
	     break;

	 default:
	     addr = NULL;
	     break;
    }

    return addr;
}


/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
char *get_current_date(char *str_time)
{
    time_t now;
    struct tm *p;   
    char *addr = str_time;
//    char *week[]={"-Sun-","-Mon-","-Tue-","-Wed-","-Thu-","-Fri-","-Sat-"};

    time(&now);
    p = localtime(&now);

//    sprintf(str_time,"%d/%d/%d %s %d:%d:%d",1900+p->tm_year,1+p->tm_mon,
//	p->tm_mday,week[p->tm_wday],p->tm_hour, p->tm_min, p->tm_sec);
     sprintf(str_time,"%d_%02d_%02d",1900+p->tm_year,1+p->tm_mon,p->tm_mday);

    return addr;
}
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
char *get_now_time(char *str_time)
{
    time_t now;
    struct tm *p;   
    char *addr = str_time;
//    char *week[]={"-Sun-","-Mon-","-Tue-","-Wed-","-Thu-","-Fri-","-Sat-"};

    time(&now);
    p = localtime(&now);

//    sprintf(str_time,"%d/%d/%d %s %d:%d:%d",1900+p->tm_year,1+p->tm_mon,
//	p->tm_mday,week[p->tm_wday],p->tm_hour, p->tm_min, p->tm_sec);
     sprintf(str_time,"%d/%d/%d %d:%d:%d",1900+p->tm_year,1+p->tm_mon,\
         p->tm_mday,p->tm_hour, p->tm_min, p->tm_sec);

    return addr;
}
#if 0
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
unsigned long get_log_line_num(int level)
{
    unsigned long log_line_num = 0;

    switch (level)
    {
         case LOG_DEBUG:
             log_line_num = g_DebugLogLineNum;
             break;

         case LOG_INFO:
             log_line_num = g_InfoLogLineNum;
             break;

         case LOG_WARN:
             log_line_num = g_WarnLogLineNum;
             break;

         case LOG_ERROR:
             log_line_num = g_ErrLogLineNum;
             break;

         case LOG_FATAL:
             log_line_num = g_FatalLogLineNum;
             break;

         default:
             log_line_num = 0;
             break;
    }

    return log_line_num;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void increase_log_line_num(int level)
{
    switch (level)
    {
         case LOG_DEBUG:
             g_DebugLogLineNum++;
             break;

         case LOG_INFO:
             g_InfoLogLineNum++;
             break;

         case LOG_WARN:
             g_WarnLogLineNum++;
             break;

         case LOG_ERROR:
             g_ErrLogLineNum++;
             break;

         case LOG_FATAL:
             g_FatalLogLineNum++;
             break;

         default:
             break;
    }

    return;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void init_log_line_num(int level)
{
    switch (level)
    {
         case LOG_DEBUG:
             g_DebugLogLineNum = 0;
             break;

         case LOG_INFO:
             g_InfoLogLineNum = 0;
             break;

         case LOG_WARN:
             g_WarnLogLineNum = 0;
             break;

         case LOG_ERROR:
             g_ErrLogLineNum = 0;
             break;

         case LOG_FATAL:
             g_FatalLogLineNum = 0;
             break;

         default:
             break;
    }

    return;
}
#endif
