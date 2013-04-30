
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <signal.h>

#include <stdarg.h> 
#include <time.h>

#include <sys/param.h>

#include "eAudit_log.h"
#include "eAudit_mem.h"
#include "eAudit_dir.h"
#include "eAudit_config.h"
#include "eAudit_res_callback.h"

#include "interface_pub.h"
#include "interface_capture.h"
#include "filter_pub.h"
#include "filter_debug.h"
#include "filter_signal.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void callback_res_proc(int sig_no)
{
    char file_path[MAX_FILE_PATH_SIZE];

    memset(file_path,0x00,MAX_FILE_PATH_SIZE);
    if ((SIGINT == sig_no) || (SIGKILL == sig_no))
    {
    #ifdef WITH_FILE_REG_RES
        (void)get_res_reg_file_path(file_path,ALL_RES_FILE_NAME,FILTER_MODEL_NAME);       
        INFO("res reg file =%s\n",file_path);

        if (NULL == (fp = fopen(file_path,"r")))
        {
            DEBUG("fopen filter res file fail.");
            exit(EXIT_SUCCESS);;
        }

        if (ERR == callback_reg_sys_res(fp))
        {
            DEBUG("callback res fail.[filter]\n");
        }

        fclose(fp);
        unlink(file_path);

        DEBUG("Callback filter res OK.");
        exit(EXIT_SUCCESS);
    #else
        g_can_filter = SAIL_FALSE;
    #endif
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
char *get_res_reg_file_path(char *file_path,char *file_name,char *model_name)
{
    char *addr = file_path;

    sprintf(file_path,"%s/%s/%s.reg",RES_REG_DIR,model_name,file_name);

    return addr;        
}
