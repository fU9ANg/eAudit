/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eAudit_pub.h"
#include "eAudit_mem_map.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_mem_now_size(MEM_MAP_ID mem_map_id,unsigned long increase_size)
{
    mem_map_id->now_mem_size += increase_size;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
unsigned long get_mem_now_size(MEM_MAP_ID mem_map_id)
{
    return mem_map_id->now_mem_size;
}
