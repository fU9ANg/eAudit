
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dirent.h>
#include <sys/mman.h>

#include <stdarg.h> 
#include <time.h>
#include <sys/param.h>

#include <syslog.h>

#include "eAudit_log.h"

#include "capture_pub.h"
#include "capture_debug.h"
#include "capture_stat.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
char *create_stat_mmap_file(char *file_path,int *fd_ptr)
{
    int fd;
    char *str_mmaped = NULL;

    if (NULL == file_path)
        return NULL;

    if ((fd = open(file_path,O_CREAT|O_RDWR|O_TRUNC,S_IRUSR|S_IWUSR)) < 0)
    {
        error("[Err]Open stat  file fail.\n");
        return NULL;
    }
           
    if (lseek(fd,STAT_MMAP_SIZE - 1,SEEK_SET) < 0)
    {
        error("[Err]Lseek the stat file fail");
        close(fd);
        return NULL;
    }

    if (write(fd,"",1) != 1)
    {
        error("[Err]Write to the pak file fail");
        close(fd);
        return NULL;
    }

    close(fd);
     
    if ((fd = open(file_path,O_RDWR)) < 0)
    {
        error("[Err]Open stat  file fail.\n");
        return NULL;
    }
        
    str_mmaped = (char *)mmap(0,STAT_MMAP_SIZE,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
    if (MAP_FAILED == str_mmaped)
    {
        error("[Err]File map Fail.");
        close(fd);
        fd = DEF_FILE_DES_VAL;
        return NULL;
    }
            
    *fd_ptr = fd;
    
    return str_mmaped;   
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int munmap_stat_file(int fd,void *start)
{
    int ret = MUNMAP_OK;

    ret = munmap(start,STAT_MMAP_SIZE);
    close (fd);
        
    return ret;
}
