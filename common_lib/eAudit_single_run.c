/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

#include "eAudit_pub.h"
#include "eAudit_single_run.h"

/*static function declaration*/
static int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len);
static void err_sys(char * str);
static void check_running_by_lock(char *file_path);

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock        lock;
        
    lock.l_type = type;                /* F_RDLCK, F_WRLCK, F_UNLCK */
    lock.l_start = offset;             /* byte offset, relative to l_whence */
    lock.l_whence = whence;            /* SEEK_SET, SEEK_CUR, SEEK_END */
    lock.l_len = len;                  /* #bytes (0 means to EOF) */
        
    return( fcntl(fd, cmd, &lock) );
}

#define        read_lock(fd, offset, whence, len) \
lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)

#define        readw_lock(fd, offset, whence, len) \
lock_reg(fd, F_SETLKW, F_RDLCK, offset, whence, len)

#define        write_lock(fd, offset, whence, len) \
lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)

#define        writew_lock(fd, offset, whence, len) \
lock_reg(fd, F_SETLKW, F_WRLCK, offset, whence, len)

#define        un_lock(fd, offset, whence, len) \
lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void err_sys(char * str)
{
    printf("%s\n",str);
    exit(-2);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void proc_is_run(int check_mode,char *file_path)
{
    if (NULL == file_path)
        return;

    switch(check_mode)
    {
        case WITH_FILE_LOCK:
        default:
            check_running_by_lock(file_path);
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
static void check_running_by_lock(char *file_path)
{
    int fd;
    int val;
    char buf[MAX_PID_STR_SIZE];

    memset(buf,0x00,MAX_PID_STR_SIZE);
        
    if ((fd = open(file_path,O_WRONLY | O_CREAT,FILE_MODE)) < 0)
        err_sys("open file error\n");
        
    if (write_lock(fd, 0, SEEK_SET, 0) < 0)        
    {
        if (errno == EACCES || errno == EAGAIN)
        {
            (void)fprintf(stderr, "The process is already running!\n");
            exit(0);        /* gracefully exit, process is already running */
        }
        else
            err_sys("write_lock error");
    }
        
    if (ftruncate(fd, 0) < 0)
        err_sys("ftruncate error");
        
    sprintf(buf, "%d\n", getpid());
    if (write(fd,buf, strlen(buf)) != strlen(buf))
        err_sys("write error");
        
    if ((val = fcntl(fd, F_GETFD, 0)) < 0)
        err_sys("fcntl F_GETFD error");
    
    val |= FD_CLOEXEC;    
    if (fcntl(fd, F_SETFD, val) < 0)
        err_sys("fcntl F_SETFD error");
}
