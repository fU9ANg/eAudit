/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_SHM_QUE_H
#define _EAUDIT_SHM_QUE_H

/*队列状态*/
typedef enum{
    QUE_EMPTY = 0,
    QUE_FULL
}EN_QUE_STATUS;

/*共享内存队列头结构*/
typedef struct tagPKT_SHM_QUE_HDR
{
    int que_status;
    unsigned long blk_num;
} __attribute__ ((packed)) PKT_SHM_QUE_HDR,*PKT_SHM_QUE_HDR_ID;
#define PKT_SHM_QUE_HDR_SIZE sizeof(PKT_SHM_QUE_HDR)

/*共享内存队列的每个块的头部的定义*/
typedef struct tagPKT_QUE_BLK_HDR
{
    struct timeval ts;	       /* time stamp */
    unsigned long caplen;	  /* length of portion present */
    unsigned long len;	      /* length this packet (off wire) */
} __attribute__ ((packed)) PKT_QUE_BLK_HDR,*PKT_QUE_BLK_HDR_ID;
#define BLK_HDR_SIZE sizeof(PKT_QUE_BLK_HDR)

/*声明为全局函数*/
extern int is_empty_pkt_que(char *shm_start_addr);
extern int is_full_que(char *shm_start_addr);

extern void set_blk_num(char *shm_start_addr,unsigned long blk_num);
extern unsigned long get_blk_num(char *shm_start_addr);

extern void init_pkt_shm_que(char *shm_start_addr);

extern PKT_QUE_BLK_HDR_ID get_blk_hdr(char *blk_start_addr);
extern char *get_blk_addr(char *que_start_addr,unsigned long blk_no,unsigned long blk_size);
extern unsigned long get_frame_size(char *blk_start_addr);

extern void set_que_status(char *shm_start_addr,int status);
extern void set_que_size(char *shm_start_addr,unsigned long blk_num);

#endif
