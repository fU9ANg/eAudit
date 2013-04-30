
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>

#include "ctl_pub.h"
#include "ctl_debug.h"
#include "ctl_version_info.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
const char *
get_copyright_info(void)
{
	return
"Copyright 2007-2017 Shanghai Sail Infomation TEC Co. LTD.\n";
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
const char *
get_pcap_version(void)
{
    return pcap_lib_version();
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
char *
get_sys_version(void)
{
    char *version;

    version = malloc(MAX_VERSION_SIZE+1);
    if (NULL == version)
        return NULL;

    memset(version,0x00,MAX_VERSION_SIZE+1);
    sprintf(version,"eAudit-SF--%d-%d",EAUDIT_VERSION_MAJOR,EAUDIT_VERSION_MINOR);
    return version;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void
show_version_info(void)
{
    char *version;
    printf("eAudit System Version Info:\n");
    printf("Copyright:%s",get_copyright_info());
    printf("Libpcap Lib version:%s\n",get_pcap_version());

    version = get_sys_version();
    printf("system version:%s\n",version);
    FREE(version);
}
