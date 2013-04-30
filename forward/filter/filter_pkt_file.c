
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

#include <pcap.h>

#include <syslog.h>

#include "eAudit_config.h"
#include "eAudit_log.h"
#include "interface_analyze.h"
#include "filter_pub.h"
#include "filter_model_ctl.h"
#include "filter_debug.h"
#include "filter_pkt_file.h"

/*function declaration*/
FILE *pkt_file_fopen(const char *fname);
static int pf_write_header(FILE *fp);
void pf_write_pkt(FILE *fp,unsigned char *pkt,unsigned long pkt_size);
int pf_pkt_flush(FILE *fp);

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
FILE *pkt_file_fopen(const char *fname)
{
	FILE *f;

	if (fname[0] == '-' && fname[1] == '\0') 
	{
		f = stdout;
		fname = "standard output";
	} 
	else 
	{
#if !defined(WIN32) && !defined(MSDOS)
		f = fopen(fname, "w");
#else
		f = fopen(fname, "wb");
#endif
		if (f == NULL) 
		{
            DEBUG("fopen err.");
			return (NULL);
		}
	}
	
	if (ERR == pf_write_header(f))
	    return NULL;
	
	return f;
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
static int pf_write_header(FILE *fp)
{
    PKT_FILE_HDR hdr;

    hdr.usr_hdr.file_flag = NO_CNT;
    hdr.usr_hdr.all_packets_num = 0;
    hdr.usr_hdr.all_packets_size = 0;
    hdr.usr_hdr.crc_num = 0;
    hdr.usr_hdr.reseaved = 0;
    
    hdr.pcap_hdr.magic = 0xa0b1c2d3;
    hdr.pcap_hdr.version_major = EAUDIT_VERSION_MAJOR;
    hdr.pcap_hdr.version_minor = EAUDIT_VERSION_MINOR;
    hdr.pcap_hdr.thiszone = 0;
    hdr.pcap_hdr.snaplen = MAX_CAP_PKT_SIZE;
    hdr.pcap_hdr.sigfigs = 0;
    hdr.pcap_hdr.linktype = 0;

    if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
        return ERR;

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
void pf_write_pkt(FILE *fp,unsigned char *pkt,unsigned long pkt_size)
{
	register FILE *f = fp;
	
	/* XXX we should check the return status */
	(void)fwrite((char *)pkt, pkt_size + PKT_USR_HDR_SIZE, 1, f);
}

/**********************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int pf_pkt_flush(FILE *fp)
{
	if (fflush(fp) == EOF)
		return (-1);
	else
		return (0);
}
