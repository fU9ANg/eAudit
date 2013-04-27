/************************************************************************
/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_SYS_MSG_QUE_H
#define _EAUDIT_SYS_MSG_QUE_H

#define DFL_SYS_MSG_SND_TYPE 1
#define CTOS_MSG_TYPE_ERR    -2

/*声明为全局函数*/
extern int create_sys_msg_que(key_t key);
extern int open_sys_msg_que(key_t key);
extern int get_sys_msg_que(key_t key);
extern int sys_msg_que_recv(int id,void *msg,long msg_cnt_len,long type);
extern int sys_msg_que_srecv(int id,void *msg,long msg_cnt_len);
extern int sys_msg_que_crecv(int id,void *msg,long msg_cnt_len,long type);
extern int sys_msg_que_snd(int id,void *msg, long msg_cnt_len);
extern int delete_sys_msg_que(int id);

#endif
