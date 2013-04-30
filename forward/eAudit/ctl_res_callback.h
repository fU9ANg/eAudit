
#ifndef _CTL_RES_CALLBACK_H
#define _CTL_RES_CALLBACK_H

typedef enum
{
    MEM_RES = 0,
    SHM_RES,
    SEM_RES,
    FILE_RES,
    SHM_KEY_RES,
    ALL_RES
}EN_RES_TYPE;

#define MAX_RES_TYPE_NUM 4

#define MAX_MEM_NUM 5
#define MAX_SHM_NUM 5
#define MAX_SEM_NUM 5
#define MAX_FILE_NUM 10

typedef struct tagRES_MAP
{
    void **res_lst_id;
}RES_MAP,*RES_MAP_ID;
#define RES_MAP_SIZE sizeof(RES_MAP)

extern RES_MAP_ID g_res_map_id;
extern int g_mem_num;
extern int g_shm_num;
extern int g_sem_num;
extern int g_file_num;

extern RES_MAP_ID create_res_map(int);
extern int get_max_res_num(int);
extern int get_res_no(int);
extern void set_res_no(int);
extern void reg_res(int,void *);
extern int callback_res(RES_MAP_ID);

extern char *get_res_reg_file_path(char *,char *,char *);
extern int callback_reg_mem_res(FILE *);
extern int callback_reg_shm_res(FILE *);
extern int callback_last_reg_shm_res(FILE *fp);

#endif
