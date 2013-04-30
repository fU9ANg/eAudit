
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <stdarg.h> 

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include <stdarg.h>
#include <time.h>
#include <sys/vfs.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include <syslog.h>
#include <pcap.h>

#include "eAudit_log.h"
#include "eAudit_mem.h"
#include "eAudit_config.h"
#include "eAudit_string.h"
#include "eAudit_sem.h"
#include "eAudit_shm.h"

#include "ctl_pub.h"
#include "ctl_debug.h"
#include "ctl_sys_info.h"

/*global var*/
SYS_HW_INFO g_sys_hw_info;

/*static function declaration*/
static inline char *skip_token(const char *p);
static unsigned long decide_divisor(unsigned long size,char *ch);

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_sys_mem_size(SYS_MEM_INFO_ID sys_mem_info_id)
{
    int len;
    int fd;
    struct statfs sb;
    char buffer[MAX_PROC_FILE_SIZE+1];
    char *p;
    
    memset(&sb,0x00,sizeof(struct statfs));
    memset(buffer,0x00,MAX_PROC_FILE_SIZE+1);
    
    if (statfs(PROCFS, &sb) < 0 || sb.f_type != PROC_SUPER_MAGIC)
    {
	DEBUG("proc filesystem not mounted on PROC");
	return ERR;
    }
	
    fd = open(PROC_MEMINFO_FILE, O_RDONLY);
    if (fd < 0)
    {
        error("[ERR]Open proc file fail.\n");
        return ERR;
    }
	
    len = read(fd, buffer, sizeof(buffer)-1);
    if (len < 0)
    {
    	 error("[ERR]Read proc file fail.\n");
	 close(fd);
        return ERR;
    }
	
    close(fd);
    buffer[len] = '\0';
	
    p = buffer;
    p = skip_token(p);
    sys_mem_info_id->total_mem_size = strtoul(p, &p, 10); 
	
    p = strchr(p, '\n');
    p = skip_token(p);
    sys_mem_info_id->free_mem_size = strtoul(p, &p, 10); 
	
    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_sys_fs_info(SYS_FS_INFO_ID sys_fs_info_id,char *fs_path)
{
    struct statfs buf;

    if ((NULL == sys_fs_info_id) || (NULL == fs_path))
        return ERR;

    memset(&buf,0x00,sizeof(buf));
	
    if (statfs(fs_path,&buf) != 0)
    {
        error("[Err]Can't read the packets files dir HDD info!\n");
        return ERR;
    }

    sys_fs_info_id->f_bfree = buf.f_bfree;
    sys_fs_info_id->f_bsize = buf.f_bsize;
	
    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static inline char *skip_token(const char *p)
{
    while (isspace(*p)) p++;
    while (*p && !isspace(*p)) p++;
    return (char *)p;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void get_proc_abt_dir(char *dir)
{
    register int i;
    int len;
    int count;
    char buf[MAX_DIR_SIZE+1];
    
    count = readlink("/proc/self/exe",buf,MAX_DIR_SIZE);
 
    if(count< 0 || count >= MAX_DIR_SIZE )
    {
        DEBUG("get_proc_abt_dir Failed\n");
        return;
    }

    buf[count] = '\0';

    len = strlen(buf);

    for (i = len-1;i > 0;i--)
    {
        if ('/' == buf[i])
            break;
    }

    buf[i + 1] = '\0';
    
    return;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void show_sys_dir_info(void)
{
    printf("*************************************************************************************\n");
    printf("*All the config files of system is below(The same no files belongs the same no dir):*\n");
    printf("*************************************************************************************\n");
    printf("1:The sys support protocols list dir:%s\n",SUPPORT_PRO_DIR_PATH);
    printf("1:The sys support protocols list file name:%s\n",SUPPORT_PRO_FILE_NAME);

    printf("2:The sys config dir:%s\n",CFG_DIR_PATH);
    printf("2:The sys config file name:%s\n",SYS_CFG_FILE_NAME);
    printf("2:The sys capture NIC config file name:%s\n",CAPTURE_NIC_CFG_NAME);

    printf("3:The sys work info dir:%s\n",SYS_WORK_INFO_DIR_PATH);
    printf("3:The sys work info file name:%s\n",SYS_WORK_INFO_FILE_NAME);

    printf("4:The sys stat dir:%s\n",PKT_STAT_FILE_DIR);
    printf("4:The sys capture stat  file name:NIC_Name%s\n",CAPTURE_PKT_STAT_FILE_NAME);
    printf("4:The sys filter stat  file name:NIC_Name%s\n",FILTER_PKT_STAT_FILE_NAME);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void
show_if_list_findalldevs(void)
{
    register int i;
    register char *errbuf = NULL;
    pcap_if_t *alldevs, *dev;
    struct pcap_addr *addr;
    struct sockaddr_in *p = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {
        warning("[Warning]Use pcap_findalldevs err.");
        return;
    }

    if (alldevs == NULL) 
    {
        warning("[Warning]No suitable NIC device found.");
        return;
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) 
    {
         info("****NIC name:%s.\n",dev->name);
	 info("NIC description:%s.\n",dev->description);
	 if (dev->flags & PCAP_IF_LOOPBACK)
	 {
	     info("NIC is a LOOP Back NIC.\n");
	 }

        for (addr = dev->addresses,i = 1;addr != NULL;addr = addr->next,i++)
        {
            p = (struct sockaddr_in *)(addr->addr);
            info("NIC addresses%d Info:\n",i);

            info("NIC ip address:%s.\n",inet_ntoa(p->sin_addr));

            p = (struct sockaddr_in *)(addr->addr);
	    info("NIC netmask:%s.\n",inet_ntoa(p->sin_addr));

            p = (struct sockaddr_in *)(addr->addr);
	    info("NIC broadcast address:%s.\n",inet_ntoa(p->sin_addr));

            p = (struct sockaddr_in *)(addr->addr);
	    info("NIC P2P destination address:%s.\n",inet_ntoa(p->sin_addr));
        }
        printf("\n");
    }

    pcap_freealldevs(alldevs);

    return;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:2007-1229
*/
void 
show_sys_mem_size(void)
{
    int len;
    int fd;
    struct statfs sb;
    char buffer[MAX_PROC_FILE_SIZE+1];
    char *p;
	
    unsigned long total_mem_size;
    unsigned long free_mem_size;
	
    unsigned long divisor;
    char units;
    double size;
    
    memset(&sb,0x00,sizeof(struct statfs));
    memset(buffer,0x00,MAX_PROC_FILE_SIZE+1);
    
    if (statfs(PROCFS, &sb) < 0 || sb.f_type != PROC_SUPER_MAGIC)
    {
	error("[ERR]proc filesystem not mounted on PROC");
	return;
    }
	
    fd = open(PROC_MEMINFO_FILE, O_RDONLY);
    if (fd < 0)
    {
        error("[ERR]Open proc file fail.\n");
        return;
    }
	
    len = read(fd, buffer, sizeof(buffer)-1);
    if (len < 0)
    {
    	 error("[ERR]Read proc file fail.\n");
	 close(fd);
        return;
    }
	
    close(fd);
    buffer[len] = '\0';
	
    p = buffer;
    p = skip_token(p);
    total_mem_size = strtoul(p, &p, 10); 
	
    p = strchr(p, '\n');
    p = skip_token(p);
    free_mem_size = strtoul(p, &p, 10); 

    divisor = decide_divisor(total_mem_size,&units);
    if (divisor > 1)
    {
        size = total_mem_size/divisor;
	 printf("system total memery size:%8.2f%c",size,units);
    }
    else
    {
        printf("system total memery size:%u",total_mem_size);
    }

    divisor = decide_divisor(free_mem_size,&units);
    if (divisor > 1)
    {
        size = free_mem_size/divisor;
	 printf("system free memery size:%8.2f%c",size,units);
    }
    else
    {
        printf("system free memery size:%u",free_mem_size);
    }
	
    return;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void
show_sys_pagesize(void)
{
    size_t page_size;

    page_size = getpagesize();

    printf("sys page size:%ld",(long)page_size);
	
    return;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int
create_sys_work_info_file(char *file_path)
{
    FILE *fp = NULL;

    if (NULL == file_path)
        return ERR;

    if (NULL == (fp = fopen(file_path,"w+")))
        return ERR;

    fclose(fp);

    return OK;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int 
record_sys_work_info(char *path,char *pstr,int flags)
{
    FILE *fp = NULL;
    char str_time[TIME_STR_SIZE];

    if (NULL == pstr)
        return ERR;
	
    if (NULL == (fp = fopen(path,"a+")))
         return ERR;

    fputs(pstr,fp);
	
    if (RECORD_INC_TIME == flags)
    {
        memset(&str_time,0x00,TIME_STR_SIZE);
        get_now_time(str_time);
        fputs(" Record Time:",fp);     
        fputs(str_time,fp);
    }

    fputc('\n',fp);

    fflush(fp);
    fclose(fp);

    return OK;
} 

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static unsigned long
decide_divisor(unsigned long size,char *ch)
{
    if (size > _1G){
	 *ch = 'G';
        return(_1G);
    }

    if (size > _1M)
    {
        *ch = 'M';
        return(_1M);
    }

    if (size > _1K)
    {
        *ch = 'K';
        return(_1K);
    }
	
    return(1);
}
    
