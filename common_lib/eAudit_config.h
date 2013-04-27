/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_CONFIG_H
#define _EAUDIT_CONFIG_H

#define GET_CFG_VAL_FAIL   1
#define GET_CFG_VAL_OK     0

#define IS_EXIST    1     /*文件存在*/
#define NOT_EXIST 0     /*文件不存在*/

#define CFG_NOTE_SIGN1 ';'
#define CFG_NOTE_SIGN2 '#'

#define CFG_SEC_SUFFIX ']'
#define CFG_SEX_PREFX  '['

#define CFG_BLK_SIZE 64
#define CFG_KEY_SIZE 32

/*extern function declaration*/
extern int file_is_exist (char * filename);
extern off_t get_file_size(char *filename);
extern char * cfg_get_file_cnt (int fd,char *buffer,int size);
extern int cfg_get_key_val(char *src,char *seckey, char *key,char *dest);

#endif
