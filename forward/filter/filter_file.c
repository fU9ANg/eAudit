
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dirent.h>
#include <sys/mman.h>

#include <stdarg.h> 
#include <time.h>
#include <sys/param.h>

#include <syslog.h>

#include "eAudit_config.h"
#include "eAudit_log.h"
#include "interface_analyze.h"
#include "filter_pub.h"
#include "filter_model_ctl.h"
#include "filter_debug.h"
#include "filter_file.h"

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int mmap_file(char *file_path,int *fd_ptr,size_t file_size,char **mmaped_buf)
{
    int flag = NOT_EXIST;
    int fd;
    char *str_mmaped = NULL;

    if ((NULL == file_path) || (file_size <= 0))
        return FILTER_PAR_ERR_OFFSET;
     
    flag = file_is_exist(file_path);   
    if (NOT_EXIST == flag)
    {
        if ((fd = open(file_path,O_CREAT|O_RDWR|O_TRUNC,S_IRUSR|S_IWUSR)) < 0)
        {
            error("[Err]Open mmap file fail.\n");
            return FILTER_OPEN_FILE_FAIL_OFFSET;
        }
           
        if (lseek(fd,file_size - 1,SEEK_SET) < 0)
        {
            error("[Err]Lseek the mmap file fail.");
            close(fd);
            return FILTER_F_LSEEK_FAIL_OFFSET;
        }
              
        if (write(fd,"",TEST_FILE_STR_SIZE) != TEST_FILE_STR_SIZE)
        {
            error("[Err]Write to the mmap file fail.");
            close(fd);
            return FILTER_F_WRITE_FAIL_OFFSET;
        }
        
        str_mmaped = (char *)mmap(0,file_size,MMAP_PROT_WR_MODE,MMAP_SHARED_FLAGS,fd,0);
        if (MAP_FAILED == str_mmaped)
        {
            error("[Err]File map Fail.[in filter]");
            close(fd);
            fd = DEF_FILE_DES_VAL;
            return FILTER_MMAP_FAIL_OFFSET;
        }
            
        *mmaped_buf = str_mmaped;
        *fd_ptr = fd;
    }
        
    if (IS_EXIST == flag) 
    {
        if ((fd = open(file_path,WR_PKT_FILE_FLAGS)) < 0)
        {
            return FILTER_OPEN_FILE_FAIL_OFFSET;
        }
      
        str_mmaped = (char *)mmap(0,file_size,MMAP_PROT_WR_MODE,MMAP_SHARED_FLAGS,fd,0);
        if (MAP_FAILED == str_mmaped)
        {
            DEBUG("file map Fail.[in filter]");
            close(fd);
            return FILTER_MMAP_FAIL_OFFSET;
        }
 #if 0
    #ifdef WITH_PKT_FILE_FLG   
        pkt_file_hdr_id = (PKT_FILE_HDR_ID)str_mmaped;
        if (HAS_CNT == pkt_file_hdr_id->usr_hdr.file_flag)
        {
            warning("The %s file don't be analyzed.\n",file_path);
            close(fd);
            return FILTER_FILE_HAS_CNT_OFFSET;
        }
    #endif
#endif
        *mmaped_buf = str_mmaped;
        *fd_ptr = fd;
    }   
    
    return(SAIL_OK);   
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int munmap_file(int fd,void *start,size_t length)
{
    int ret = MUNMAP_OK;

    ret = munmap(start,length);
    close (fd);
        
    return ret;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_pkt_rule_id(char *mmaped_buf)
{
    ((RULE_ID_ST_ID)mmaped_buf)->rule_id = g_protect_rule_id;
    ((RULE_ID_ST_ID)mmaped_buf)->authorize_id = authorize_id;
    ((RULE_ID_ST_ID)mmaped_buf)->usr_id = usr_id;
    ((RULE_ID_ST_ID)mmaped_buf)->res_index = res_index;
    ((RULE_ID_ST_ID)mmaped_buf)->net_index = network_index;
    ((RULE_ID_ST_ID)mmaped_buf)->hit_direct = direction;
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
void set_file_flag(char *mmaped_buf,EN_PKT_FILE_STATUS file_flag)
{
    (((PKT_FILE_HDR_ID)mmaped_buf)->usr_hdr).file_flag = file_flag;

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
void set_packets_num(char *mmaped_buf,unsigned long num)
{
    (((PKT_FILE_HDR_ID)mmaped_buf)->usr_hdr).all_packets_num = num;

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
void set_pcap_info(char *mmaped_buf)
{
    (((PKT_FILE_HDR_ID)mmaped_buf)->pcap_hdr).magic = 0xa0b1c2d3;
    (((PKT_FILE_HDR_ID)mmaped_buf)->pcap_hdr).version_major = EAUDIT_VERSION_MAJOR;
    (((PKT_FILE_HDR_ID)mmaped_buf)->pcap_hdr).version_minor = EAUDIT_VERSION_MINOR;

    return;
}

#ifndef WITH_MMAP_FILE_NO_FILE
/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int open_file_no_file(char *file_name,char *pro_name,char *base_dir)
{
    char file_path[MAX_FILE_PATH_SIZE+1];
    int fd = DEF_FILE_DES_VAL;
    
    //error("###the pro_name is %s\n",pro_name);		
    sprintf(file_path,"%s/%s/%s",base_dir,pro_name,file_name);
    if ((fd = open(file_path,O_RDWR)) < 0)
    {
        error("[Err]Open write no file(%s) Fail.",file_path);
        return DEF_FILE_DES_VAL;
    }

    return fd;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int get_file_no(int fd)
{
    char buf[U_LONG_SIZE+1];
    unsigned long file_no;

    memset(buf,0x00,U_LONG_SIZE+1);
    lseek(fd,0,SEEK_SET);
    if (read(fd,buf,U_LONG_SIZE+1) < 0)
    {
        error("[Err]Read write no file fail.");
        exit(EXIT_FAILURE);
    }

    file_no = strtoul(buf,NULL,10);

    return file_no;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_file_no(int fd,unsigned long file_no)
{
    char buf[U_LONG_SIZE+1];
 
    memset(buf,0x00,U_LONG_SIZE+1);    
    sprintf(buf,"%ld",file_no);

    lseek(fd,0,SEEK_SET);
    if (-1 == write(fd,buf,U_LONG_SIZE+1))
    {
        error("[Err]Write write no file fail.[in filter]");
	 exit(EXIT_FAILURE);
    }

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
void close_file_no_file(int *fd)
{
    if (DEF_FILE_DES_VAL != *fd)
    {
        close(*fd);
        *fd = DEF_FILE_DES_VAL;
    }

    return;
}
#endif
