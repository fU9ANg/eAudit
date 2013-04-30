
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#include <stdarg.h> 
#include <time.h>
#include <syslog.h>

#include "eAudit_log.h"
#include "eAudit_shm.h"
#include "eAudit_sem.h"

#include "filter_pub.h"
#include "interface_analyze.h"
#include "interface_filter.h"
#include "filter_debug.h"
#include "filter_packets.h"



/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int first_filter(unsigned short ether_type)
{
    if ((IP_PKT_TYPE == ether_type) || (ARP_PKT_TYPE == ether_type)||(ether_type == ETHERTYPE_8021Q))
        return(IS_PROTECTED_PKT);

    return(NOT_PROTECTED_PKT);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int second_filter(unsigned long src_ip,unsigned long dst_ip)
{
    if ((src_ip == dst_ip) && (dst_ip == LOC_IP))
        return(NOT_PROTECTED_PKT);

    return(IS_PROTECTED_PKT); 
}

