/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <stdlib.h>

#include "eAudit_pub.h"
#include "eAudit_shm_que.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int is_empty_pkt_que(char *shm_start_addr)
{
    
    PKT_SHM_QUE_HDR_ID tmp_addr = (PKT_SHM_QUE_HDR_ID)shm_start_addr;
	
    return (tmp_addr->que_status == QUE_EMPTY ? SAIL_TRUE:SAIL_FALSE);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int is_full_que(char *shm_start_addr)
{
    
    PKT_SHM_QUE_HDR_ID tmp_addr = (PKT_SHM_QUE_HDR_ID)shm_start_addr;
	
    return (tmp_addr->que_status == QUE_FULL ? SAIL_TRUE:SAIL_FALSE);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_blk_num(char *shm_start_addr,unsigned long blk_num)
{
    
    PKT_SHM_QUE_HDR_ID tmp_addr = (PKT_SHM_QUE_HDR_ID)shm_start_addr;
	
    tmp_addr->blk_num = blk_num;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
unsigned long get_blk_num(char *shm_start_addr)
{
    
    PKT_SHM_QUE_HDR_ID tmp_addr = (PKT_SHM_QUE_HDR_ID)shm_start_addr;
	
    return tmp_addr->blk_num;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void init_pkt_shm_que(char *shm_start_addr)
{
    PKT_SHM_QUE_HDR_ID tmp_addr = (PKT_SHM_QUE_HDR_ID)shm_start_addr;

    tmp_addr->que_status = QUE_EMPTY;
    
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
static char *get_blk_start_addr(char *shm_start_addr)
{
    char *tmp_addr = shm_start_addr;

    tmp_addr += PKT_SHM_QUE_HDR_SIZE;
	
    return tmp_addr;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
char *get_blk_addr(char *que_start_addr,unsigned long blk_no,unsigned long blk_size)
{
    char *blk_start_addr = get_blk_start_addr(que_start_addr);

    blk_start_addr += blk_no*blk_size;

    return blk_start_addr;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
PKT_QUE_BLK_HDR_ID get_blk_hdr(char *blk_start_addr)
{
    char *tmp_addr = blk_start_addr;
    
    return (PKT_QUE_BLK_HDR_ID)tmp_addr;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
unsigned long get_frame_size(char *blk_start_addr)
{
    PKT_QUE_BLK_HDR_ID blk_hdr = get_blk_hdr(blk_start_addr);

    return blk_hdr->caplen;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_que_status(char *shm_start_addr,int status)
{
    PKT_SHM_QUE_HDR_ID que_hdr = (PKT_SHM_QUE_HDR_ID)shm_start_addr;

    que_hdr->que_status = status;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_que_size(char *shm_start_addr,unsigned long blk_num)
{
    PKT_SHM_QUE_HDR_ID que_hdr = (PKT_SHM_QUE_HDR_ID)shm_start_addr;

    que_hdr->blk_num= blk_num;
}
