/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <unistd.h>
#include <fcntl.h>

#include "eAudit_pub.h"
#include "eAudit_file_lock.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int lock_all_file(int fd,int type)
{
    struct flock lock;

    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_type = type;
	
    return(fcntl(fd,F_SETLK,&lock));
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int unlock_all_file(int fd)
{
    struct flock lock;

    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_type = F_UNLCK;
	
    return(fcntl(fd,F_SETLK,&lock));   
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int check_file_lock(int fd,int type)
{
    struct flock lock;

    lock.l_type = type;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_whence = SEEK_SET;
    lock.l_pid = -1;

    if (fcntl(fd,F_GETLK,&lock) < 0)
        return CHK_LK_ERR;

    return lock.l_pid;
}
