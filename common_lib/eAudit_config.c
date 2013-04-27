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
#include <sys/stat.h>
#include <fcntl.h>

#include "eAudit_pub.h"
#include "eAudit_config.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int file_is_exist (char * filename)
{
    if (NULL == filename)
        return NOT_EXIST;

    if (0 == access(filename, F_OK))
        return IS_EXIST;
    else
        return NOT_EXIST;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
off_t get_file_size(char *filename)
{
    struct stat sbuf;
    int ret;

    ret = stat(filename, &sbuf);
    return (ret < 0 ? 0:sbuf.st_size);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
char * cfg_get_file_cnt (int fd,char *buffer,int size)
{
    char *tmpBuffer = buffer;
    size_t retsize = 0;

    lseek(fd,0,SEEK_SET);

    //fd、buffer、size的合法性在函数体外检查
    retsize = read(fd,tmpBuffer, size);
    return (retsize <= 0 ? NULL:tmpBuffer);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int cfg_get_key_val(char *src,char *seckey, char *key,char *dest)
{
    long i = 0;
    int iRet = GET_CFG_VAL_FAIL;
    char *secAddr = NULL;
    char *keyAddr = NULL;
    char *p= NULL;
    char *ps= NULL;

    secAddr = strstr(src,seckey);
    if (NULL == secAddr)
    {
        return iRet;
    }

    p = secAddr + strlen(seckey);
    keyAddr = strstr(p,key);
    if (NULL == keyAddr)
    {
        return iRet;
    }
    p = keyAddr;
    while(*p++ != '=');
   // p++;
    
    i = 0;
    ps = dest;
    while( (*p != '\n') && (*p != '\r') && (*p != '\0')
        //   && (*p != CFG_NOTE_SIGN1) && (*p != CFG_NOTE_SIGN2))
	&& (*p != CFG_NOTE_SIGN1))
    {
        if (!isspace(*p))
        {
            *ps = *p;
            ps++;
            i++;
        }

        p++;
    }

    if (i > 0)
    {
        *ps = '\0';
	iRet = GET_CFG_VAL_OK;
    }
	
    return iRet;
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
char *cfg_get_key_val(char *src,char *seckey, char *key,char *defval,char *dest)
{
    int i = 0;
    char *buf = NULL;
    char *secAddr = NULL;
    char *keyAddr = NULL;
    char *p= NULL;
    char *ps= NULL;

    secAddr = strstr(src,seckey);
    if (NULL == secAddr)
        return NULL;

    secAddr +=strlen(seckey)+2;
    p = secAddr;
    while (*p != ']')
    {
        i++;
        p++;
    }

    buf = (char*)malloc(i+1);
    if (NULL == buf)
        return NULL;

    ps = buf;
    p = secAddr;
    while( (*ps ++ = *p++ ) != '] ');
    *ps = '\0';

    keyAddr = strstr(buf, key);
    p = keyAddr;

    while (*p++ != '=');
    p++;

    i = 0;
    ps = dest;
    while( (*p != '\n') && (*p != '\r'))
    {
        if (isspace( *p))
        {
            *ps++ = *p++;
            i++;
        }
    }

    if (0 == i)
        strcpy(dest, defval);
    else
        *ps = '\0';
    
    free(buf);

    return dest;
}
#endif
