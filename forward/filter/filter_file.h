
#ifndef _FILTER_FILE_H
#define _FILTER_FILE_H

//#define WR_PKT_FILE_FLAGS  (O_RDWR | O_CREAT | O_DIRECTORY)
#define WR_PKT_FILE_FLAGS  (O_RDWR | O_CREAT)
#define RD_PKT_FILE_FLAGS  (O_RDONLY | O_CREAT)
#define TC_PKT_FILE_FLAGS  (O_RDWR | O_CREAT | O_TRUNC) 

#define MMAP_PROT_WR_MODE     (PROT_READ | PROT_WRITE)
#define MMAP_PROT_RD_MODE     PROT_READ

#define MMAP_SHARED_FLAGS     MAP_SHARED
#define MMAP_PRIVATE_FLAGS    MAP_PRIVATE

#define TEST_FILE_STR_SIZE 1

#define MUNMAP_OK    0
#define MUNMAP_FAIL  -1

typedef enum{
    PKT_FILE_NOT_MAPPED = 1,
    PKT_FILE_MAPPED
}EN_PKT_FILE_MAPPED_STATUS;

/*extern function declaration*/
extern int mmap_file(char *file_path,int *fd_ptr,size_t file_size,char **mmaped_buf);
extern int munmap_file(int fd,void *start,size_t length);

extern void set_file_flag(char *mmaped_buf,EN_PKT_FILE_STATUS file_flag);
extern void set_packets_num(char *mmaped_buf,unsigned long num);
extern void set_pcap_info(char *mmaped_buf);
extern void set_pkt_rule_id(char *mmaped_buf);

extern int open_file_no_file(char *file_name,char *pro_name,char *base_dir);
extern int get_file_no(int fd);
extern void set_file_no(int fd,unsigned long file_no);
extern void close_file_no_file(int *fd);

#endif
