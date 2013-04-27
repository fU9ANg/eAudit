/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_DIR_H
#define _EAUIDT_DIR_H

/*extern function declaration*/
extern int make_dir(char *dir_path,mode_t mode);
extern void del_dir_and_file(char *dir_path);
extern int dir_is_empty(char *dir_path);
extern void del_file(char *file_path);

#endif
