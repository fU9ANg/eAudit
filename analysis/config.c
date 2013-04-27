/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
  
#include "config.h"
#include "common.h"
#include "debug.h"


/*
int get_monitor_cfg_info(EA_MONITOR_INFO_ID monitor_info_id, char* file_path)
{
	int ret;
	char* file_cnt_buf = NULL;
	char key_val[CFG_BLK_SIZE];
	int file_size = 0;
	int fd = -1;
	if(file_path == NULL || monitor_info_id == NULL)
	{
		return ERR;
	}

	if(file_is_exist(file_path) == FILE_NOT_EXIST)
	{
		return ERR;
	}
	if((file_size = get_file_size(file_path)) == 0)
	{
		return ERR;
	}
	if((file_cnt_buf = malloc(file_size * sizeof(char) + 1)) == NULL)
	{
		return ERR;
	}

	if((fd = open(file_path, O_RDONLY)) < 0)
	{
		free(file_cnt_buf);
		return ERR;
	}
	if (NULL == cfg_get_file_cnt(fd,file_cnt_buf,file_size))
	{
		close(fd);
		free(file_cnt_buf);	
		return ERR;
	}
	file_cnt_buf[file_size] = 0x00;
	
	memset(key_val,0x00,CFG_BLK_SIZE);
	ret = cfg_get_key_val(file_cnt_buf,MONITOR_CFG_SECT,CONN_INTERVAL, key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get FTP CFG interval time err.\n");
		return ERR;
	}else
	{
		monitor_info_id->conn_interval = strtoul(key_val, NULL, 10);
	
	}


	memset(key_val,0x00,CFG_BLK_SIZE);
	ret = cfg_get_key_val(file_cnt_buf,MONITOR_CFG_SECT,CONN_THRESHOLD, key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get FTP CFG data interval time err.\n");
		return ERR;
	}else
	{
		monitor_info_id->conn_threshold = strtoul(key_val, NULL, 10);
	}

	memset(key_val,0x00,CFG_BLK_SIZE);
	ret = cfg_get_key_val(file_cnt_buf,MONITOR_CFG_SECT,FLUX_INTERVAL, key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get FTP CFG data interval time err.\n");
		return ERR;
	}else
	{
		monitor_info_id->flux_interval = strtoul(key_val, NULL, 10);
	}


	memset(key_val,0x00,CFG_BLK_SIZE);
	ret = cfg_get_key_val(file_cnt_buf,MONITOR_CFG_SECT, FLUX_THRESHOLD, key_val, CFG_BLK_SIZE+1);
	if (GET_CFG_VAL_FAIL == ret)
	{
		error("[Err]Get FTP CFG support session err.\n");
		return ERR;
	}else
	{
		monitor_info_id->flux_threshold = strtod(key_val, NULL);
	}
  
	return OK; 	
}*/


int
get_read_cfg_mode(file_path, fd_ptr, file_size_ptr)
	char*	file_path;
	int *	fd_ptr;
	unsigned
	long*	file_size_ptr;
{
	int fd;
	unsigned long file_size;
	
	if (!file_path)						return(DEF_MODE);
	
	if (NOT_EXIST == file_is_exist(file_path))		return(DEF_MODE);

	if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)	return(DEF_MODE);

	if (0 == (file_size = get_file_size(file_path))) {
        	close(fd);
        	return(DEF_MODE);
	}

	*fd_ptr 	= fd;
	*file_size_ptr  = file_size;
	
	return(READ_FILE); 
}


char * cfg_get_file_cnt (
	int	fd,
	char*	buffer,
	int	size
	)
{
	char*	tmpBuffer = buffer;
	size_t	retsize   = 0;

	lseek(fd, 0, SEEK_SET);

	retsize = read(fd, tmpBuffer, size);
	return(retsize <= 0 ? NULL : tmpBuffer);
}


int cfg_get_key_val(
	char*	src,
	char*	seckey,
	char* 	key,
	char*	dest,
	int	dest_len
	)
{
	long	i       = 0;
	int	iRet    = GET_CFG_VAL_FAIL;
	char*	secAddr = NULL;
	char*	keyAddr = NULL;
	char*	p       = NULL;
	char*	ps      = NULL;
	
	if(!src || !seckey || !key || !dest)	return iRet;

	secAddr = strstr(src,seckey);
	if (!secAddr)				return iRet;

	p  = secAddr + strlen(seckey);
	keyAddr      = strstr(p, key);
	if (!keyAddr)				return iRet;

	p  = keyAddr;
	while(*p != '=') p++; p++;

	while(*p == ' ') p++;
	
	i  = 0;
	ps = dest;
	while( (*p!='\n') && (*p!='\r') && (*p!='\0') && (*p!=';') && i<dest_len-1) {
		*ps++ = *p++;
		i++;
	}

	if(i>0 && ((*p=='\n') || (*p=='\r') || (*p=='\0') || (*p ==';'))) {
		*ps = '\0';
		iRet = GET_CFG_VAL_OK;
	}
	
	return iRet;
}
