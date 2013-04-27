/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_SINGLE_RUN_H
#define _EAUDIT_SINGLE_RUN_H

enum check_mode
{
    WITH_PROC_NAME = 0,
    WITH_FILE_LOCK
};

#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern void proc_is_run(int check_mode,char *file_path);

#endif
