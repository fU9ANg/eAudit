
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include <stdarg.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <syslog.h>

#include "eAudit_log.h"
#include "eAudit_mem.h"
#include "eAudit_config.h"
#include "eAudit_string.h"
#include "eAudit_sem.h"
#include "eAudit_shm.h"

#include "ctl_pub.h"
#include "interface_filter.h"
#include "interface_analyze.h"
#include "ctl_debug.h"
#include "ctl_filter_rule.h"

/*global var*/
key_t g_max_shm_key = 0;
key_t g_max_sem_key = 0;

/*function declaration*/
int open_rules_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr);

unsigned long get_rules_num(char *file_cnt_buf);
void copy_item(FILTER_RULE_ID filter_rule_id,int item_no,char *item);
int set_rules_item(FILTER_RULE_ID filter_rule_id,char *buf);
int set_rules_buf(FILTER_RULE_ID filter_rule_id,char *file_cnt_buf,unsigned long buf_num);

static int port_comp(const void *a ,const void *b);
void qsort_by_port(FILTER_RULE_ID filter_rule_id,unsigned long buf_num);

static int pro_comp(const void *a ,const void *b);
static void qsort_by_pro(FILTER_RULE_ID filter_rule_id,unsigned long rule_num);

static void init_direct_idx_list(DIRECT_INDEX_RULE_ID directIndex);
static int create_node_idx_list(DIRECT_INDEX_RULE_ID directIndex);

PORT_INDEX_RULE_ID create_port_index(key_t *port_idx_shm_key,int *port_idx_shm_id);
RULE_NODE_ID create_rule_items_pool(unsigned long items_num,key_t *shm_pool_key,int *pool_shm_id);
int create_rule_tbl(PORT_INDEX_RULE_ID port_index_rule_id,RULE_NODE_ID rule_pool_id,\
                      FILTER_RULE_ID filter_rule_id,unsigned long rule_num);

int del_shm_deque(key_t shm_key,int flag);

int get_pro_num(FILTER_RULE_ID filter_rule_id,unsigned long rule_num);
static int get_direct_idx(unsigned char direct);

int callback_rule_shm(PORT_INDEX_RULE_ID port_index_rule_id,int shmid);

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int open_rules_file(char *file_path,int *fd_ptr,unsigned long *file_size_ptr)
{
    int fd;
    unsigned long file_size;
	
    if (NULL == file_path)
        return(CTL_PAR_ERR);
	
    if (NOT_EXIST == file_is_exist(file_path))  
    {
        error("[Err]Protect rules file don't exist.");
        return(CTL_FILE_NOT_EXIST);
    }

    if ((fd = open(file_path,O_RDONLY | O_CREAT)) < 0)
    {
        error("[Err]Open protect rules file fail.");     
        return(CTL_FILE_OPEN_FAIL);
    }

    if (0 == (file_size = get_file_size(file_path)))
    {  
        error("[Err]Protect rules file no content.");
        close(fd);
        return(CTL_FILE_IS_NULL);
    }

    *fd_ptr = fd;
    *file_size_ptr = file_size;
	
    return(SAIL_OK); 
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
unsigned long get_rules_num(char *file_cnt_buf)
{
    register unsigned long i = 0;
    register int num = 0;
    register char *str = file_cnt_buf;
    
    if (NULL == file_cnt_buf)
        return(CTL_PAR_ERR);
    
    while (str[i] != '\0')
    {
        if (RULE_LINE_END_ASC == str[i])
            num++;
        i++;
    }    
    
    return num;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void copy_item(FILTER_RULE_ID filter_rule_id,int item_no,char *item)
{
    register char *p = item;
    struct in_addr ip;
    char ip_str[20];

    switch(item_no)
    {
        case 1:
            filter_rule_id->rule_id = strtoul(p,NULL,10);
        #ifdef _DEBUG_
            printf("id = %ld\n",filter_rule_id->id);
        #endif
            break;

        case 2:
            strcpy(ip_str,p);
            if (0 == strncmp(ip_str,"255.255.255.255",15))
            {
            	filter_rule_id->ip_addr = 1;
            }
            else
            {
                inet_aton(ip_str,&ip);
                filter_rule_id->ip_addr = ip.s_addr;
            }
        #ifdef _DEBUG_
            printf("ip_addr = %ld\n",filter_rule_id->ip_addr);
        #endif
            break;

        case 3:
            strcpy(ip_str,p);
            if (0 == strncmp(ip_str,"255.255.255.255",15))
            {
                filter_rule_id->net_mask = 1;
            }
            else
            {
                inet_aton(ip_str,&ip);
                filter_rule_id->net_mask = ip.s_addr;
            }
        #ifdef _DEBUG_
            printf("net_mask = %ld\n",filter_rule_id->net_mask);
        #endif
            break;

        case 4:
            filter_rule_id->port = atoi(p);
        #ifdef _DEBUG_
            printf("port = %d\n",filter_rule_id->port);
        #endif
            break;

        case 5:
	     filter_rule_id->pro_id = atoi(p);
        #ifdef _DEBUG_
            printf("pro id = %d\n",filter_rule_id->pro_id);
        #endif
            break;

        case 6:
            filter_rule_id->sq_class = atoi(p);
            break;

        case 7:
            filter_rule_id->wsq_class = atoi(p);
            break;

        case 8:
            filter_rule_id->rule_group_id = atoi(p);
            break;

        default:  
            break;  
    }
  
    return;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int set_rules_item(FILTER_RULE_ID filter_rule_id,char *buf)
{
    register int i = 0;
    register char *s = buf;
    register char *p = NULL;
    FILTER_RULE_ID ptr = filter_rule_id;
    
    if ((NULL == filter_rule_id) || (NULL == buf))
        return(CTL_PAR_ERR);
    
    p = s;
    while (*s != '\0')
    {
        if (RULE_ID_DELIM_CHAR == *s)
        {
            i++;
            if (i > RULE_ITEMS_NUM)
                break;

            *s = '\0';
            trim(p);   
            copy_item(filter_rule_id,i,p);
            p = s + sizeof(char);       
        }
        
        if (RILE_ITEMS_DELIM_CHAR == *s)
        {
            i++;
            if (i >= RULE_ITEMS_NUM)
                break;

            *s = '\0';
            trim(p);          
            copy_item(ptr,i,p);
            p = s + sizeof(char);       
        }
        
        s++;
    }
    
    i++;
    trim(p);
    copy_item(ptr,i,p);
    ptr->direct = ALL_DIRECT_CH;
    
    return(SAIL_OK); 
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int set_rules_buf(FILTER_RULE_ID filter_rule_id,char *file_cnt_buf,unsigned long buf_num)
{
    unsigned long i = 0;
    char *p = NULL;
    char *s = file_cnt_buf;
    FILTER_RULE_ID d = filter_rule_id;
    
    if ((NULL == filter_rule_id) || (NULL == file_cnt_buf))
        return(CTL_PAR_ERR);

#ifdef _DEBUG_
    printf("rules file cnt:%s\n",file_cnt_buf);    
#endif

    strtok(s,RULE_LINE_DELIM);
  
#ifdef _DEBUG_
    printf("rules num:%ld\n",buf_num);
    printf("s = %s\n",s);
#endif

    trim(s);
    set_rules_item(d,s);
    i++;
    d->id = i - 1;
    
    while((p = strtok(NULL,RULE_LINE_DELIM)) != NULL)
    {
          i++;
          if (i > buf_num)
              break;
       
          if (i <= buf_num)
          {
              trim(p);
              d++;
    	      set_rules_item(d,p);
              d->id = i - 1;
    	  }
    }
    
    return(SAIL_OK);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int port_comp(const void *a ,const void *b)
{
    FILTER_RULE_ID c1= (FILTER_RULE_ID)a;
    FILTER_RULE_ID c2= (FILTER_RULE_ID)b;
    
    if (c1->port > c2->port)
        return 1;
    
    if (c1->port == c2->port)
        return 0;
        
    if (c1->port < c2->port)
        return -1;

    return 0;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void qsort_by_port(FILTER_RULE_ID filter_rule_id,unsigned long buf_num)
{
    void *base = filter_rule_id;
    size_t num = buf_num;
    size_t size = FILTER_RULE_BLK_SIZE;
    
    qsort(base,num,size,port_comp);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int pro_comp(const void *a ,const void *b)
{
    FILTER_RULE_ID c1= (FILTER_RULE_ID)a;
    FILTER_RULE_ID c2= (FILTER_RULE_ID)b;
    
    if (c1->pro_id > c2->pro_id)
        return 1;
    
    if (c1->pro_id == c2->pro_id)
        return 0;
        
    if (c1->pro_id < c2->pro_id)
        return -1;

    return 0;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void qsort_by_pro(FILTER_RULE_ID filter_rule_id,unsigned long rule_num)
{
    void *base = filter_rule_id;
    size_t num = rule_num;
    size_t size = FILTER_RULE_BLK_SIZE;
    
    qsort(base,num,size,pro_comp);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
PORT_INDEX_RULE_ID create_port_index(key_t *port_idx_shm_key,int *port_idx_shm_id)
{
    int shm_id;
    register int i;
    unsigned long shm_size = MAX_PORT*PORT_INDEX_RULE_SIZE;
    PORT_INDEX_RULE_ID port_index = NULL;
    
#ifdef _DEBUG_
    printf("shm_size = %ld\n",shm_size);
#endif

    g_max_shm_key += SHM_KEY_IVL;
    if ((shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL)) < 0)
    {
        error("[Err]Create port index shm fail.");
        write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"Create port index shm fail.");
        return NULL;  
    }
    
    *port_idx_shm_key = g_max_shm_key;
    
    port_index = (PORT_INDEX_RULE_ID)shmat(shm_id,NULL,0);
    if (!port_index)
    {
        error("[Err]Attach port index shm fail.");
        write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"Attach port index shm fail.");
        return NULL;
    }

#ifdef _INFO
    INFO("Init the port rules shm head.");    
#endif

    for (i = 0;i < MAX_PORT;i++)
    {
        (port_index+i)->port = i;
        (port_index+i)->shm_key = DEF_SHM_KEY_VAL;
    }
    
    *port_idx_shm_id = shm_id;
    
    return port_index;   
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
RULE_NODE_ID create_rule_items_pool(unsigned long items_num,key_t *shm_pool_key,int *pool_shm_id)
{
    int shm_id;
    unsigned long shm_size;
    RULE_NODE_ID rule_pool_id = NULL;

    g_max_shm_key += SHM_KEY_IVL;
    shm_size = RULE_NODE_SIZE*items_num;

#ifdef _DEBUG
    printf("pool shm size = %ld\n",shm_size);
    printf("shm key = %ld\n",(unsigned long)g_max_shm_key);
#endif
  
    shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL);
    if (shm_id < 0)
    {
        DEBUG("create rule pool shm fail.");
        write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"CREATE rule pool shm fail.");
        return NULL;
    }
    
    *shm_pool_key = g_max_shm_key;
    
    rule_pool_id = (RULE_NODE_ID)shmat(shm_id,NULL,0);
    if (!rule_pool_id)
    {
        DEBUG("attach rule pool shm fail.");
        write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"attach rule pool shm fail.");
        return NULL;
    }
    
    *pool_shm_id = shm_id;
    
    return rule_pool_id;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static void init_direct_idx_list(DIRECT_INDEX_RULE_ID directIndex)
{
    register int i;
    register DIRECT_INDEX_RULE_ID p = directIndex;
	  
    for(i = 0;i < AUDIT_DIRECT_NUM;i++)
    {
        (p + i)->direct = i;
        (p + i)->rule_num = 0;
        (p + i)->shm_key = DEF_SHM_KEY_VAL;    
    }
    
    return;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int create_node_idx_list(DIRECT_INDEX_RULE_ID directIndex)
{
    register int i;
    key_t shm_key;
    int rule_num;
    unsigned long shm_size;
    int shm_id;
    DIRECT_INDEX_RULE_ID p = directIndex;

    for(i = 0;i < AUDIT_DIRECT_NUM;i++)
    {
        shm_key = (p + i)->shm_key;
        rule_num = (p + i)->rule_num;
        if ((0 != rule_num) && (DEF_SHM_KEY_VAL != shm_key))
        {
        #ifdef _DEBUG
             printf("[XXXX]rule rum:%d\n",rule_num);
             printf("[XXXX]shm key:%ld\n",(unsigned long)shm_key);
        #endif
             shm_size = rule_num * RULE_NODE_IDX_SIZE;
             if ((shm_id = shmget(shm_key,shm_size,IPC_CREAT|IPC_EXCL)) < 0)
             {
                 DEBUG("create rule node index shm fail.");
                 write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"create rule list shm fail.");
                 return CTL_CRT_SHM_FAIL;  
             }
             
    #ifdef _DEBUG
        DEBUG("create rule node index shm OK.");
    #endif
             (p + i)->rule_num = 0;
        }
    }

    return(SAIL_OK);   
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int create_rule_tbl(PORT_INDEX_RULE_ID port_index_rule_id,RULE_NODE_ID rule_pool_id,
                      FILTER_RULE_ID filter_rule_id,unsigned long rule_num)
{
    int shm_id;
    key_t shm_key;
    unsigned long shm_size;

    register unsigned short port = 0;
    register unsigned long i = 0;
    register unsigned long idx = 0;
    register unsigned long index = 0;

    DIRECT_INDEX_RULE_ID directIndex = NULL;
    RULE_NODE_IDX_ID node_idx_id = NULL;
    register PORT_INDEX_RULE_ID d = port_index_rule_id;
    register RULE_NODE_ID pool_id = rule_pool_id;
    
    unsigned char direct;
    
    /*port index*/
    for (i = 0;i < rule_num;i++)
    {
        port = (filter_rule_id + i)->port;
        if (DEF_SHM_KEY_VAL == (d + port)->shm_key)
        {
            g_max_shm_key += SHM_KEY_IVL;
            shm_size = DIRECT_INDEX_RULE_SIZE*AUDIT_DIRECT_NUM;
            if ((shm_id = shmget(g_max_shm_key,shm_size,IPC_CREAT|IPC_EXCL)) < 0)
            {
                DEBUG("create direct index que head shm fail.");
                write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"create shm fail.");
                return CTL_CRT_SHM_FAIL;
            }
    
            directIndex = (DIRECT_INDEX_RULE_ID)shmat(shm_id,NULL,0);
            if (!directIndex)
            {
                DEBUG("attach direct index que head shm fail.");
                write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"attach shm fail.");
                return CTL_ATTACH_SHM_FAIL;
            }

            init_direct_idx_list(directIndex);
            
            (void)detach_shm(directIndex);
            directIndex = NULL;

            (d + port)->shm_key = g_max_shm_key;
        }
    }

    DEBUG("....CREATE DIRECT INDEX SHM OK.");

    /*direct index*/
    for (i = 0;i < rule_num;i++)
    {
        port = (filter_rule_id + i)->port;
        shm_key = (d + port)->shm_key;
        if (DEF_SHM_KEY_VAL != shm_key)
        {   
        #ifdef _DEBUG
            printf("[####]port = %d\n",port);
        #endif
            if ((shm_id = shmget(shm_key,0,IPC_CREAT)) < 0)
            {
                DEBUG("create direct index que head shm fail.");
                write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"create shm fail.");
                return CTL_CRT_SHM_FAIL;
            }
            
            directIndex = (DIRECT_INDEX_RULE_ID)shmat(shm_id,NULL,0);
            if (!directIndex)
            {
                DEBUG("attach direct index que head shm fail.");
                write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"attach shm fail.");
                return CTL_ATTACH_SHM_FAIL;
            }

            direct = (filter_rule_id + i)->direct;
            idx = get_direct_idx(direct);
            
            if (DEF_SHM_KEY_VAL == (directIndex + idx)->shm_key)
            {
                g_max_shm_key += SHM_KEY_IVL;
                (directIndex + idx)->shm_key = g_max_shm_key;
            }
 
            (directIndex + idx)->rule_num++;
 
        #ifdef _DEBUG
            printf("rule num[****] = %d\n",(directIndex + idx)->rule_num);
        #endif 
                
            (void)detach_shm(directIndex);
            directIndex = NULL;
        }
    }

    DEBUG("....CREATE NODE INDEX SHM OK");

    /*create node index list shm*/
    for (i = 0;i < MAX_PORT;i++)
    {
        shm_key = (d + i)->shm_key;
        if (DEF_SHM_KEY_VAL != shm_key)
        {
        #ifdef _DEBUG_
            printf("port = %d\n",port);
        #endif
            if ((shm_id = shmget(shm_key,0,IPC_CREAT)) < 0)
            {
                DEBUG("create direct index que head shm fail.");
                write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"create shm fail.");
                return CTL_CRT_SHM_FAIL;
            }
            
            directIndex = (DIRECT_INDEX_RULE_ID)shmat(shm_id,NULL,0);
            if (!directIndex)
            {
                DEBUG("attach direct index que head shm fail.");
                write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"attach shm fail.");
                return CTL_ATTACH_SHM_FAIL;
            }
            
            if (SAIL_OK != create_node_idx_list(directIndex))
            {
                DEBUG("create node list shm fail.\n");
                write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"create rule list shm fail.");
                return CTL_CRT_SHM_FAIL;  
            }
            
            (void)detach_shm(directIndex);
            directIndex = NULL;           
        }
    }

    DEBUG("....SET ALL INDEX SHM OK");

    /*add the rule node no*/
    d = port_index_rule_id;
    for (i = 0;i < rule_num;i++)
    {
        port = (filter_rule_id + i)->port;
        shm_key = (d + port)->shm_key;
        if ((shm_id = shmget(shm_key,0,IPC_CREAT)) < 0)
        {
            DEBUG("create direct index que head shm fail.");
            write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"create shm fail.");
            return CTL_CRT_SHM_FAIL;
        }
           
        directIndex = (DIRECT_INDEX_RULE_ID)shmat(shm_id,NULL,0);
        if (!directIndex)
        {
            DEBUG("attach direct index que head shm fail.");
            write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"attach shm fail.");
            return CTL_ATTACH_SHM_FAIL;
        } 
        
        direct = (filter_rule_id + i)->direct;
        idx = get_direct_idx(direct);
        shm_key = (directIndex + idx)->shm_key;
    #ifdef _DEBUG
        printf("the node index shm key is:%ld\n",(unsigned long)shm_key);    
    #endif
        if ((shm_id = shmget(shm_key,0,IPC_CREAT)) < 0)
        {
            DEBUG("get node index shm fail.");
            write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"get node index shm fail.");
            return CTL_CRT_SHM_FAIL;
        }
        
        node_idx_id = (RULE_NODE_IDX_ID)shmat(shm_id,NULL,0);
        if (!node_idx_id)
        {
            DEBUG("attach node index shm fail.");
            write_log(LOG_ERR,FILE_LOG,__FILE__,__LINE__,SINGLE,"attach node index shm fail.");
            return CTL_ATTACH_SHM_FAIL;
        } 
        
        index = (directIndex + idx)->rule_num;
        (node_idx_id + index)->node_no = (filter_rule_id + i)->id;
        (directIndex + idx)->rule_num++;
        
        idx = (filter_rule_id + i)->id;
        (pool_id + idx)->net_mask = (filter_rule_id + i)->net_mask;
        (pool_id + idx)->ip_addr = (filter_rule_id + i)->ip_addr;
	(pool_id + idx)->port = port;
	(pool_id + idx)->direct = direct;
        (pool_id + idx)->id = (filter_rule_id + i)->id;
        (pool_id + idx)->rule_id = (filter_rule_id + i)->rule_id;
        (pool_id + idx)->pro_id = (filter_rule_id + i)->pro_id;
        (pool_id + idx)->net = ((filter_rule_id + i)->ip_addr)&((filter_rule_id + i)->net_mask);
        (pool_id + idx)->sq_class = (filter_rule_id + i)->sq_class;
        (pool_id + idx)->wsq_class = (filter_rule_id + i)->wsq_class;
        (pool_id + idx)->rule_group_id = (filter_rule_id + i)->rule_group_id;        

       // DEBUG("##################(pool_id + %ld)->direct = %c",idx,(pool_id + idx)->direct);
       // DEBUG("##################(pool_id + %ld)->id = %ld",idx,(pool_id + idx)->id);
       // DEBUG("##################(pool_id + %ld)->pro_id = %d",idx,(pool_id + idx)->pro_id);
       // DEBUG("##################(pool_id + %ld)->port = %d",idx,(pool_id + idx)->port);

        (void)detach_shm(directIndex);
        directIndex = NULL;
        
        (void)detach_shm(node_idx_id);
        node_idx_id = NULL;
    }

    return SAIL_OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int del_shm_deque(key_t shm_key,int flag)
{
    register int i;
    register int j;
    int shm_id;
    int port_shm_id;
    int rule_shm_id;
    register PORT_INDEX_RULE_ID port_idx_id = NULL;
    register DIRECT_INDEX_RULE_ID direct_idx_id = NULL;

    port_shm_id = shmget(shm_key,0,IPC_CREAT);
    if (port_shm_id < 0)
    {
        DEBUG("get port index shm fail.\n");
        write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get port index shm fail.");
        return CTL_GET_SHM_FAIL;
    }

    port_idx_id = (PORT_INDEX_RULE_ID)shmat(port_shm_id,NULL,0);
    if (!port_idx_id)
    {
        DEBUG("attach port index shm fail.\n");
        write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"attach port index shm fail.");
        return CTL_ATTACH_SHM_FAIL;
    }

    for(i = 0;i < MAX_PORT;i++)
    {
        if (DEF_SHM_KEY_VAL != (port_idx_id + i)->shm_key)
        {
            shm_id = shmget((port_idx_id + i)->shm_key,0,IPC_CREAT);
            if (shm_id < 0)
            {
                DEBUG("get port index shm fail.\n");
                write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get port index shm fail.");
                return CTL_GET_SHM_FAIL;
            }

            direct_idx_id = (DIRECT_INDEX_RULE_ID)shmat(shm_id,NULL,0);
            if (!direct_idx_id)
            {
                DEBUG("attach direct index shm fail.\n");
                write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"attach direct index shm fail.");
                return CTL_ATTACH_SHM_FAIL;
            }
			
            for (j = 0;j < AUDIT_DIRECT_NUM;j++)
            {
                if (DEF_SHM_KEY_VAL != (direct_idx_id +j)->shm_key)
                {
                    rule_shm_id = shmget((direct_idx_id + j)->shm_key,0,IPC_CREAT);
                    if (rule_shm_id < 0)
                    {
                        DEBUG("get rule node shm fail.\n");
                        write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get rule node shm fail.");
                        return CTL_GET_SHM_FAIL;
                    }

                    if (ERR == del_shm(rule_shm_id))
                    {
                        DEBUG("del rule node shm fail.\n");
                        write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"del rule node shm fail.");
                        return CTL_DEL_SHM_FAIL;
                    }
                }
            }//end for(j....)

            if (ERR == del_shm(shm_id))
            {
                DEBUG("del rule node shm fail.\n");
                write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"del rule node shm fail.");
                return CTL_DEL_SHM_FAIL;
            }
        }//end if
    }
    
    if (DEL_MAIN_SHM == flag)
    {
        if (ERR == del_shm(port_shm_id))
        {
            DEBUG("del rule node shm fail.\n");
            write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"del rule node shm fail.");
            return CTL_DEL_SHM_FAIL;
        }
    }
    
    return SAIL_OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_pro_num(FILTER_RULE_ID filter_rule_id,unsigned long rule_num)
{
    register int i;
    register FILTER_RULE_ID base = filter_rule_id;
    int pro_num = 0;
    unsigned long pro_id;
       
    qsort_by_pro(base,rule_num);

    DEBUG("quick sort by protocol ok.");
    
    pro_id = base->pro_id;
    pro_num++;
    
    for (i = 1;i < rule_num;i++)
    {
        if (pro_id != (base + i)->pro_id)
        {
            pro_num++;
            pro_id = (base + i)->pro_id;
        }      
    }
    
    return pro_num;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int get_direct_idx(unsigned char direct)
{
    int idx = 0;

    if (UP_DIRECT_CH == direct)
    {
        idx = 0;
    }

    if (DN_DIRECT_CH == direct)
    {
        idx = 1;
    }

    if (ALL_DIRECT_CH == direct)
    {
        idx = 2;
    }

    return idx;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int callback_rule_shm(PORT_INDEX_RULE_ID port_index_rule_id,int shmid)
{
    register int i;
    register int j;
    int shm_id;
    int port_shm_id = shmid;
    int rule_shm_id;
    register PORT_INDEX_RULE_ID port_idx_id = port_index_rule_id;
    register DIRECT_INDEX_RULE_ID direct_idx_id = NULL;

    for(i = 0;i < MAX_PORT;i++)
    {
        if (DEF_SHM_KEY_VAL != (port_idx_id + i)->shm_key)
        {
            shm_id = shmget((port_idx_id + i)->shm_key,0,IPC_CREAT);
            if (shm_id < 0)
            {
                DEBUG("get port index shm fail.\n");
                write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get port index shm fail.");
                return ERR;
            }

            direct_idx_id = (DIRECT_INDEX_RULE_ID)shmat(shm_id,NULL,0);
            if (!direct_idx_id)
            {
                DEBUG("attach direct index shm fail.\n");
                write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"attach direct index shm fail.");
                return ERR;
            }
			
            for (j = 0;j < AUDIT_DIRECT_NUM;j++)
            {
                if (DEF_SHM_KEY_VAL != (direct_idx_id +j)->shm_key)
                {
                    rule_shm_id = shmget((direct_idx_id + j)->shm_key,0,IPC_CREAT);
                    if (rule_shm_id < 0)
                    {
                        DEBUG("get rule node shm fail.\n");
                        write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"get rule node shm fail.");
                        return ERR;
                    }

                    if (ERR == del_shm(rule_shm_id))
                    {
                        DEBUG("del rule node shm fail.\n");
                        write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"del rule node shm fail.");
                        return ERR;
                    }
                }
            }//end for(j....)

            if (ERR == del_shm(shm_id))
            {
                DEBUG("del rule node shm fail.\n");
                write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"del rule node shm fail.");
                return ERR;
            }
        }//end if
    }

    if (detach_shm((char *)port_index_rule_id) < 0)
        return ERR;
	
    if (ERR == del_shm(port_shm_id))
    {
        DEBUG("del rule node shm fail.\n");
        write_log(LOG_ERR,LOG_TOOL,__FILE__,__LINE__,SINGLE,"del rule node shm fail.");
        return ERR;
    }
    
    return OK;
}

