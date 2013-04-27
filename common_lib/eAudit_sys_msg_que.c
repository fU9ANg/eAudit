/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "eAudit_pub.h"
#include "eAudit_sys_msg_que.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int open_sys_msg_que(key_t key)
{
    return msgget(key,IPC_CREAT|0666);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int create_sys_msg_que(key_t key)
{
    return msgget(key,IPC_CREAT|IPC_EXCL|0666);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_sys_msg_que(key_t key)
{
    return msgget(key,IPC_CREAT);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int sys_msg_que_recv(int id,void *msg,long msg_cnt_len,long type)
{
    return msgrcv(id,msg,msg_cnt_len,type,IPC_NOWAIT);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int sys_msg_que_crecv(int id,void *msg,long msg_cnt_len,long type)
{
    return msgrcv(id,msg,msg_cnt_len,type,IPC_NOWAIT);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int sys_msg_que_srecv(int id,void *msg,long msg_cnt_len)
{  
    return msgrcv(id,msg,msg_cnt_len,DFL_SYS_MSG_SND_TYPE,IPC_NOWAIT);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int sys_msg_que_snd(int id,void *msg, long msg_cnt_len)
{
    return msgsnd(id,msg,msg_cnt_len,IPC_NOWAIT);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int delete_sys_msg_que(int id)
{
    return msgctl(id,IPC_RMID,NULL);
}
