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
#include <dirent.h>

#include "eAudit_pub.h"
#include "eAudit_dir.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int make_dir(char *dir_path,mode_t mode)
{
    DIR *dir_ptr = NULL;

    if (NULL == (dir_ptr = opendir(dir_path)))
    {
        if (-1 == mkdir(dir_path,mode))
            return ERR;
    }
    else
    {
        closedir(dir_ptr);
    }

    return OK;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void del_dir_and_file(char *dir_path)
{
    DIR *dir;
    char cmd[MAX_SYS_CMD_SIZE];

    memset(cmd,0x00,MAX_SYS_CMD_SIZE);
   
    dir = opendir(dir_path);
    if (NULL != dir)
    {
        closedir(dir);

	strcpy(cmd, "rm -rf ");
	strcat(cmd, dir_path);	
	system(cmd);
    }
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int dir_is_empty(char *dir_path)
{
    DIR *dir = NULL;
    struct dirent *ptr = NULL;
    int num = 0;

    dir =opendir(dir_path);
    while(dir)
    {
        if ((ptr = readdir(dir)) != NULL)
        {
            if ((strcmp(ptr->d_name,".")) && (strcmp(ptr->d_name,"..")))
            {
                num++;
            }
        }
        else
        {
            break;
        }
    }

    if (NULL != dir)
        closedir(dir);

    return (num > 0?SAIL_FALSE:SAIL_TRUE);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void del_file(char *file_path)
{
    char cmd[MAX_SYS_CMD_SIZE];

    if (NULL != file_path)
    {
        memset(cmd,0x00,MAX_SYS_CMD_SIZE);

        strcpy(cmd, "rm -f ");
        strcat(cmd, file_path);
        system(cmd);
    }
}

