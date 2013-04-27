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
    short int l_type;     /* ������״̬*/
    short int l_whence;/*����l_start λ��*/
    off_t l_start;          /*��������Ŀ�ͷλ��*/
    off_t l_len;             /*��������Ĵ�С*/
    pid_t l_pid;            /*���������Ľ���*/
};
#endif

#define CHK_LK_ERR -2

/*extern function declaration*/
extern int lock_all_file(int fd,int type);
extern int unlock_all_file(int fd);
extern int check_file_lock(int fd,int type);

#endif
