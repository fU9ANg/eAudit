/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_ERR_H
#define _EAUDIT_ERR_H

#define ERR_FILE_NAME_SIZE    128
#define MAX_USR_OBJ_NAME_SIZE 64
#define MAX_SYS_OBJ_NAME_SIZE 32
#define MAX_RET_STR_SIZE      16
#define MAX_OP_SIZE           16

typedef enum 
{
    EAUDIT_SYS_NO = 1
}EN_SYS_NO;

typedef enum
{
    CAPTURE_MODEL_NO = 1,
    FILTER_MODEL_NO = 2,
    ANALYSIS_MODEL_NO = 3,
    NET_COMM_MODEL_NO = 4
}EN_MODEL_NO;

typedef struct tagCODE_FILE_INFO
{
    unsigned short sys_no;
    unsigned short major_model_no;
    unsigned short minor_model_no;
    unsigned short reseaved;
    char file_name[ERR_FILE_NAME_SIZE+1];
}CODE_FILE_INFO,*CODE_FILE_INFO_ID;
#define CODE_FILE_INFO_SIZE sizeof(CODE_FILE_INFO)

typedef struct tagERR_CODE_ST
{
    unsigned long err_no;
    char op_name[MAX_OP_SIZE + 1];
    char usr_obj_name[MAX_USR_OBJ_NAME_SIZE + 1];
    char sys_obj_name[MAX_SYS_OBJ_NAME_SIZE + 1];
    char ret_string[MAX_RET_STR_SIZE + 1];
}ERR_CODE,*ERR_CODE_ID;
#define ERR_CODE_SIZE sizeof(ERR_CODE)

typedef struct tagERR_INFO
{
    CODE_FILE_INFO code_file_info;
    int line_no; 
    ERR_CODE err_code;
}ERR_INFO,*ERR_INFO_ID;
#define ERR_INFO_SIZE sizeof(ERR_INFO)

#define SYS_DIR_OBJ  "dir"
#define SYS_FILE_OBJ "file"
#define SYS_MEM_OBJ  "mem"
#define SYS_SHM_OBJ  "shm"
#define SYS_SEM_OBJ  "sem"
#define SYS_PIPE_OBJ "pipe"
#define SYS_SIGNAL_OBJ "signal"
#define SYS_MSQ_OBJ    "message que"
#define SYS_SOCKET_OBJ "socket"
#define SYS_ARRAY_OBJ  "array"
#define SYS_PROCESS_OBJ "process"
#define SYS_THREAD_OBJ  "thread"

#define ERR_RET_FAIL   "fail"
#define ERR_RET_ERR    "error"
#define ERR_RET_FATAL  "fatal"     

#define CREATE_OP      "create"
#define GET_OP         "get"
#define SET_OP         "set"
#define ATTACH_OP      "attach"
#define OPEN_OP        "open"
#define CLOSE_OP       "close" 

/*extern function declaration*/
extern void set_code_file_info(ERR_INFO_ID err_info_id,unsigned short major_model_no,\
                        unsigned short minor_model_no,char *file_name);
extern void set_err_code(ERR_INFO_ID err_info_id,unsigned long err_no,char *op_name,char *usr_obj_name,\
                        char *sys_obj_name,char *ret_string);
extern void print_err(ERR_INFO_ID err_info_id);

#endif
