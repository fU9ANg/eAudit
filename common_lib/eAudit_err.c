/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "eAudit_pub.h"
#include "eAudit_err.h"
                        
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_code_file_info(ERR_INFO_ID err_info_id,unsigned short major_model_no,\
                        unsigned short minor_model_no,char *file_name)
{
    err_info_id->code_file_info.sys_no = EAUDIT_SYS_NO;
    err_info_id->code_file_info.major_model_no = major_model_no;
    err_info_id->code_file_info.minor_model_no = minor_model_no;
    strncpy(err_info_id->code_file_info.file_name,file_name,ERR_FILE_NAME_SIZE);
    
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
void set_err_code(ERR_INFO_ID err_info_id,unsigned long err_no,char *op_name,char *usr_obj_name,\
                 char *sys_obj_name,char *ret_string)
{
    err_info_id->err_code.err_no = err_no;
    strncpy(err_info_id->err_code.op_name,op_name,MAX_OP_SIZE);
    strncpy(err_info_id->err_code.usr_obj_name,usr_obj_name,MAX_USR_OBJ_NAME_SIZE);
    strncpy(err_info_id->err_code.sys_obj_name,sys_obj_name,MAX_SYS_OBJ_NAME_SIZE);
    strncpy(err_info_id->err_code.ret_string,ret_string,MAX_RET_STR_SIZE);
    
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
void set_err_line_no(ERR_INFO_ID err_info_id,int line_no)
{
    err_info_id->line_no = line_no;
    
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
void print_err(ERR_INFO_ID err_info_id)
{
    char err_str[ERR_INFO_SIZE + 11];
    
    memset(err_str,0x00,ERR_INFO_SIZE + 11);
    
    sprintf(err_str,"%d%d%s%d:%ld %s %s %s %s.",err_info_id->code_file_info.sys_no,\
            err_info_id->code_file_info.major_model_no,err_info_id->code_file_info.file_name,\
            err_info_id->line_no,err_info_id->err_code.err_no,err_info_id->err_code.op_name,\
            err_info_id->err_code.usr_obj_name,err_info_id->err_code.sys_obj_name,\
            err_info_id->err_code.ret_string);
            
    printf("[ERR]%s\n",err_str);
}
