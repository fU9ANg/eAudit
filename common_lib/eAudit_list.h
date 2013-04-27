/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_LIST_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct st_node
{
    void *data;
    struct st_node *next;
    struct st_node *prev;
}NODE,*NODE_ID;
#define NODE_SIZE sizeof(NODE)

typedef void (*DESTROY_FUNC)(void *data);

typedef struct st_list
{
    int size;
    NODE_ID head;
    NODE_ID tail;
    DESTROY_FUNC destroy;
}LIST,*LIST_ID;
#define LIST_SIZE sizeof(LIST)

/*extern function declaration*/
extern void init_list(LIST_ID list_id,DESTROY_FUNC destroy);
extern int delete_list(LIST_ID list_id);
extern int remove_list_next(LIST_ID list, NODE_ID node);
extern int insert_list_next(LIST_ID list, NODE_ID cur_pos, void *data,NODE_ID insert_node);
extern int append_list(LIST_ID list, void *data, NODE_ID node);
extern void print_list(LIST_ID list);

#ifdef	__cplusplus
}
#endif

#endif
