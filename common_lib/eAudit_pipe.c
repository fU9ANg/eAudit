/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h> 
#include <sys/types.h>

#include "eAudit_pub.h"
#include "eAudit_pipe.h"

/*the static declaration of glabol function*/
static void pipe_warning(const char *fmt, ...);
static int pipe_read_bytes(int pipe, char *pbuf, int len) ;
static void pipe_convert_hdr(const unsigned char *hdr, int hdr_len, char *type, int *msg_len);

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void pipe_warning(const char *fmt,...)
{
	va_list ap;

	(void)fprintf(stderr, "[WARNING]%s:", "Pipe");
	
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int pipe_write_hdr(int pipe, char type, int len)
{
    unsigned char hdr[PIPE_HDR_SIZE];  

    if (len > PIPE_MAX_MSG_LEN)
        pipe_warning("The pipe msg len too long.\n");

    hdr[0] = type;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >> 8) & 0xFF;
    hdr[3] = (len >> 0) & 0xFF;

    return write(pipe, hdr, sizeof hdr);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void
pipe_write_msg(int pipe, char type, const char *msg)
{
    int ret;
    size_t len;

    len = (msg != NULL?(strlen(msg) + 1):0);

    ret = pipe_write_hdr(pipe,type,len);
    if (-1 == ret) 
        return;

    /* write value (if we have one) */
    if(len) 
    {
        ret = write(pipe, msg, len);
        if (-1 == ret) 
            return;
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
void
pipe_msg_to_parent(char type,const char *msg)
{
    if (NULL == msg)
        return;
	
    pipe_write_hdr(1, type, strlen(msg) + 1 + PIPE_HDR_SIZE);
    pipe_write_msg(1, type, msg);

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
static int
pipe_read_bytes(int pipe, char *pbuf, int len) 
{
    int rd_len;
    int offset = 0;

    while(len) 
    {
        rd_len = read(pipe, &pbuf[offset], len);
        if (rd_len == 0) {
            return offset;
        }
		
        if (rd_len < 0) {
            return rd_len;
        }

        len -= rd_len;
        offset += rd_len;
    }

    return offset;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void
pipe_convert_hdr(const unsigned char *hdr, int hdr_len, char *type, int *msg_len) 
{    

    if (hdr_len != PIPE_HDR_SIZE)
        pipe_warning("The pipe header len not equal 4.\n");

    *type = hdr[0];
    *msg_len = hdr[1]<<16 | hdr[2]<<8 | hdr[3];
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int pipe_read_hdr(int pipe, char *hdr,char *type,int *msg_len)
{
    int rd_len;
	
    rd_len = pipe_read_bytes(pipe, hdr, PIPE_HDR_SIZE);
    if(rd_len != PIPE_HDR_SIZE) 
    {
        return -1;
    }

    *type = hdr[0];
    *msg_len = hdr[1]<<16 | hdr[2]<<8 | hdr[3];

    return PIPE_HDR_SIZE;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_pipe_msg_type(int pipe,char *type)
{
    unsigned char hdr[PIPE_HDR_SIZE];  
    int len;

    if (pipe_read_hdr(pipe,(char*)hdr,type,&len) < 0)
        return -1;

    return 0;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int
pipe_read_msg(int pipe, char *type, int len, char *msg) 
{
    int rd_len;
    int msg_len = 0;;
    unsigned char hdr[PIPE_HDR_SIZE];
	
    rd_len = pipe_read_bytes(pipe,(char*)hdr,PIPE_HDR_SIZE);
    if(rd_len != PIPE_HDR_SIZE) 
    {
        return -1;
    }

    pipe_convert_hdr(hdr, PIPE_HDR_SIZE, type, &msg_len);

    /* only indicator with no value? */
    if(msg_len == 0) 
    {
        return PIPE_HDR_SIZE;
    }

    /* does the data fit into the given buffer? */
    if(msg_len > len) 
    {
        /* we have a problem here, try to read some more bytes from the pipe to debug where the problem really is */
        memcpy(msg, hdr, sizeof(hdr));
        rd_len = read(pipe, &msg[sizeof(hdr)], len-sizeof(hdr));
        pipe_warning("Unknown message from pipe, try to show it as a string: %s", msg);
        return -1;
    }

    /* read the actual block data */
    rd_len = pipe_read_bytes(pipe, msg, msg_len);
    if(rd_len != msg_len) {
        return -1;
    }

    return rd_len + PIPE_HDR_SIZE;
}
