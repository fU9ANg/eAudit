
/*
 * file: main.h
 * Written 2009-2013 by fU9ANg
 * bb.newlife@gmail.com
 */

#ifndef _PMC_MAIN_H
#define _PMC_MAIN_H

#define SNAM_LOCK_FILE   "/eAudit/bin/snam.LOCK"
#define SYS_CFG_SET_PATH "/var/lib/eAudit/data"

/*线程入口函数参数结构*/
typedef struct tagPTHREAD_ARGS
{
    unsigned long ip;
    int conn_fd;
}   PTHREAD_ARGS, *PTHREAD_ARGS_ID;

#define PTHREAD_ARGS_SIZE sizeof(PTHREAD_ARGS)

#endif 
