
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "capture_config.h"


/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_read_cfg_mode(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(DEF_MODE);
	
    if (NOT_EXIST == file_is_exist(file_path)) 
        return(DEF_MODE);

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)  
       return(DEF_MODE);

    if (0 == (file_size = get_file_size(file_path)))
    {  
        close(fd);
        return(DEF_MODE);
    }

    *fd_ptr = fd;
    *file_size_ptr = file_size;
	
    return(READ_FILE); 
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/

char * cfg_get_file_cnt1 (int fd,char *buffer,int size)
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
int cfg_get_key_val1(char *src,char *seckey, char *key,char *dest, int dest_len)
{
	long i = 0;
	int iRet = GET_CFG_VAL_FAIL;
	char *secAddr = NULL;
	char *keyAddr = NULL;
	char *p= NULL;
	char *ps= NULL;
	
	if(src == NULL || seckey == NULL || key == NULL || dest == NULL)
	{
		return iRet;
	}

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
	while(*p != '=')
		p++;
	p++;

	while(*p == ' ')
		p++;
	
	i = 0;
	ps = dest;
	while( (*p != '\n') && (*p != '\r') && (*p != '\0') && (*p != ';') && i < dest_len-1)
	{
		*ps++ = *p++;
		i++;
	}

	if(i > 0 && ((*p == '\n') || (*p == '\r') || (*p == '\0') || (*p == ';')))
	{
		*ps = '\0';
		iRet = GET_CFG_VAL_OK;
	}
	
	return iRet;
}

