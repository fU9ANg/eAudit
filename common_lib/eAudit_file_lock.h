/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_FILE_LOCK_H
#define _EAUDIT_FILE_LOCK_H

#ifdef INC_NOT
struct flcok
{
    short int l_type;     /* 锁定的状态*/
    short int l_whence;/*决定l_start 位置*/
    off_t l_start;          /*锁定区域的开头位置*/
    off_t l_len;             /*锁定区域的大小*/
    pid_t l_pid;            /*锁定动作的进程*/
};
#endif

#define CHK_LK_ERR -2

/*extern function declaration*/
extern int lock_all_file(int fd,int type);
extern int unlock_all_file(int fd);
extern int check_file_lock(int fd,int type);

#endif
