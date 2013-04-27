/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_MEM_MAP_H
#define _EAUDIT_MEM_MAP_H

typedef enum
{
    MEM_EMPTY = 1,
    MEM_FULL
}   EN_MEM_MAP_STATUS;

typedef struct st_mem_map
{
    int idx_item_num;
    unsigned long now_mem_size;
    unsigned long now_mem_loc;
    void *idx_item_addr;
}   MEM_MAP,*MEM_MAP_ID;
#define MEM_MAP_SIZE sizeof(MEM_MAP)

typedef struct st_idx_item
{
    int item_no;
    void *item_addr;
}   IDX_ITEM,*IDX_ITEM_ID;
#define IDX_ITEM_SIZE sizeof(IDX_ITEM)

extern void set_mem_now_size(MEM_MAP_ID mem_map_id,unsigned long increase_size);
extern unsigned long get_mem_now_size(MEM_MAP_ID mem_map_id);

#endif/*_EAUDIT_MEM_MAP_H*/
