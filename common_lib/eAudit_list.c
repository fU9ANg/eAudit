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
#include "eAudit_list.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void init_list(LIST_ID list_id,DESTROY_FUNC destroy)
{
    list_id->size = 0;
    list_id->head = NULL;
    list_id->tail = NULL;
    list_id->destroy = destroy;
    
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
int delete_list(LIST_ID list_id)
{
    while(list_id->head != NULL)
    {
        remove_list_next(list_id, NULL);
    }
    
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
int remove_list_next(LIST_ID list, NODE_ID node) 
{
    NODE_ID tmp_node = NULL;
    void *data;

    if (0 == list->size)
    {
        return -1;
    }

    if (NULL == node)
    {
        tmp_node = list->head;
        data = tmp_node->data;
        list->head = tmp_node->next;
    }
    else
    {
        data = node->data;        
        if (node->next == NULL)
        {
            return -1;
        }

        tmp_node = node->next;
        node->next = tmp_node->next;
        node->prev = tmp_node->prev;
    }

    if (tmp_node->next != NULL)
    {
        tmp_node->next->prev = node;
    }

    
    if (list->destroy != NULL)
        list->destroy(data);
    
    list->size--;
    
    if (0 == list->size) 
    {
        list->tail = NULL;
    }

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
int remove_list(LIST_ID list, NODE_ID node)
{
    NODE_ID next_node;
    NODE_ID prev_node;

    if(NULL == node)
    {
        return -1;
    }

    next_node = node->next;
    prev_node = node->prev;

    if(next_node != NULL)
    {
        next_node->prev = prev_node;
    } 
    else 
    {
        list->tail = prev_node;
    }

    if(prev_node != NULL)
    {
        prev_node->next = next_node;       
    }
    else 
    {
        list->head = next_node;
    }
        
    if(list->destroy != NULL)
        list->destroy(node->data);


    list->size--;
    
    if(list->size == 0)
    {
        list->head = NULL;
        list->tail = NULL;
    }

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
int insert_list_next(LIST_ID list, NODE_ID cur_pos, void *data,NODE_ID insert_node) 
{
    NODE_ID new_node = insert_node;
    
    if(!new_node) return -1;

    new_node->data = data;

    if(cur_pos == NULL)
    {
        if(list->size == 0)
        {
            list->tail = new_node;
        }
        
        new_node->next = list->head;
        list->head = new_node;
    }
    else
    {
        if(cur_pos->next == NULL)
        {
            list->tail = new_node;
        }

        new_node->next = cur_pos->next;
        cur_pos->next = new_node;        
    }

    new_node->prev = new_node;
    list->size++;
    
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
int append_list(LIST_ID list, void *data, NODE_ID node) 
{
    return insert_list_next(list,list->tail,data,node);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void print_list(LIST_ID list)
{
    NODE_ID node;
    
    printf("***LIST CONTENT***");
    printf("list size: %d\n",list->size);
    
    for(node = list->head; node != NULL; node = node->next)
    {
        printf(" `- %p\n", node);
    }
}
