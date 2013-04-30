
#ifndef _CTL_SYS_INFO_H
#define _CTL_SYS_INFO_H

#define PROCFS "/proc"
#define PROC_SUPER_MAGIC  0x9fa0
#define PROC_MEMINFO_FILE "/proc/meminfo"

#define MAX_PROC_FILE_SIZE 4096

#define GET_DIR_PATH "/proc/self/exe"

#define RECORD_NO_TIME  1
#define RECORD_INC_TIME 2

typedef struct tagSYS_NIC_INFO{
       struct tagSYS_NIC_INFO *next;
	char	*name;                 /* e.g. "eth0" */
	char	*description;        /* from OS, e.g. "Local Area Connection" or NULL */
	int loopback;                /* TRUE if loopback, FALSE otherwise */
} SYS_NIC_INFO,*SYS_NIC_INFO_ID;
#define SYS_NIC_INFO_SIZE sizeof(SYS_NIC_INFO)

typedef struct tagSYS_MEM_INFO
{
    unsigned long total_mem_size;
    unsigned long free_mem_size;
}SYS_MEM_INFO,*SYS_MEM_INFO_ID;
#define SYS_MEM_INFO_SIZE sizeof(SYS_MEM_INFO)

typedef struct tagSYS_FS_INFO
{
    short f_bsize;
    long f_bfree;
}SYS_FS_INFO,*SYS_FS_INFO_ID;
#define SYS_FS_INFO_SIZE sizeof(SYS_FS_INFO)

typedef struct tagSYS_HW_INFO
{
    SYS_MEM_INFO mem_info;
    SYS_FS_INFO fs_info;
}SYS_HW_INFO,*SYS_HW_INFO_ID;
#define SYS_HW_INFO_SIZE sizeof(SYS_HW_INFO)

/*global var declaration*/
extern SYS_HW_INFO g_sys_hw_info;

/*function declaration*/
extern int get_sys_mem_size(SYS_MEM_INFO_ID sys_mem_info_id);
extern void get_proc_abt_dir(char *dir);
extern int get_sys_fs_info(SYS_FS_INFO_ID sys_fs_info_id,char *fs_path);
extern void show_sys_dir_info(void);
extern void show_if_list_findalldevs(void);
extern void show_sys_mem_size(void);
extern void show_sys_pagesize(void);

extern int create_sys_work_info_file(char *file_path);
extern int record_sys_work_info(char *path,char *pstr,int flags);

#endif
