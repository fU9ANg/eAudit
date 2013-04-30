
#ifndef _FILTER_MAIN_H
#define _FILTER_MAIN_H

#define MAX_PRO_NUM 1024
#define MAX_FILTER_HIT_UNIT 1000
typedef enum{
    FIRST_WRITE = 1,
    NOT_FIRST_WRITE
}EN_READ_TIMES_STATUS;

typedef struct tagSHM_QUE_ADDR
{
    char *shm_que_addr;
    int blk_num;
    int blk_size;
    int sem_id;
    int empty_semid;
    int full_semid;
}SHM_QUE_ADDR,*SHM_QUE_ADDR_ID;
#define SHM_QUE_ADDR_SIZE sizeof(SHM_QUE_ADDR)

typedef enum
{
    PKT_FILE_IS_CLOSE = 0,
    PKT_FILE_IS_OPEN,
    PKT_FILE_WRITE_OK
}EN_PKT_FILE_STAUS;

typedef enum
{
    CAN_OPEN_PKT_FILE_CMD = 0,
    CAN_CLOSE_PKT_FILE_CMD
}EN_PKT_FILE_CMD;

/*pkts files node*/
typedef struct tagNOW_PKT_FILE
{
    int pro_id;  /*协议号*/
    int fd;
    unsigned long offset;
    char *mapped_buf;
    unsigned long packets_num;
    unsigned long start_sec; 
    unsigned long file_no;
    struct tagNOW_PKT_FILE *next;
    struct tagNOW_PKT_FILE *prev;
}NOW_PKT_FILE,*NOW_PKT_FILE_ID;
#define NOW_PKT_FILE_SIZE sizeof(NOW_PKT_FILE)

/*pkts files list*/
typedef struct tagPKT_FILE_LIST
{
    NOW_PKT_FILE_ID head;
    NOW_PKT_FILE_ID tail;
}PKT_FILE_LIST,*PKT_FILE_LIST_ID;
#define PKT_FILE_LIST_SIZE sizeof(PKT_FILE_LIST)

typedef struct tagFILTER_STAT
{
    long long us_in;
    long long us_out;
}FILTER_STAT,*FILTER_STAT_ID;
#define FILTER_STAT_SIZE sizeof(FILTER_STAT)
/*过滤命中结构体定义*/
typedef struct tagFILTER_HIT_UNIT{
	unsigned long rule_no;
       unsigned long pro_no;
       unsigned long resource_index;
	unsigned char hit_direction;
}FILTER_HIT_UNIT,*FILTER_HIT_UNIT_ID;
#define filter_hit_unit_size sizeof(FILTER_HIT_UNIT)

#endif
