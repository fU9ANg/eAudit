
#ifndef _CAPTURE_STAT_H
#define _CAPTURE_STAT_H

#define MUNMAP_OK    0
#define MUNMAP_FAIL  -1

#ifdef WITH_STAT_MMAP_ST
typedef struct tagSTAT_MMAP
{
    long long us_recv;
    char us_ivl;
    long long us_recv_size;
    char ps_ivl;
    long ps_drop;
    char drop_ivl;
    long long wait_times;
    char wait_ivl;
    long ps_first_drop;
}STAT_MMAP,*STAT_MMAP_ID;
#endif

#define STAT_MMAP_SIZE 90

/*function declaration*/
extern char *create_stat_mmap_file(char *file_path,int *fd_ptr);
extern int munmap_stat_file(int fd,void *start);

#endif

