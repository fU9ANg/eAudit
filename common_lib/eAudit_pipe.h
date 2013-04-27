/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_PIPE_H
#define _EAUDIT_PIPE_H

#include "eAudit_pub.h"

#define PIPE_MAX_MSG_LEN 4096
#define PIPE_HDR_SIZE 4     /* 1:type + 3:byte len */

/*the process start mark flg str*/
#define CAPTURE_START_OK_STR  STR(f)
#define FILTER_START_OK_STR   STR(a)
#define ANALYZE_START_OK_STR  STR(w)

/*the process start mark flg char*/
#define PIPE_CAPTURE_OK        'f'
#define PIPE_FILTER_OK         'a'
#define PIPE_ANALYSIS_OK       'w'

#define PIPE_ERROR_MSG         'E'      /* error message */

#define PIPE_PACKET_COUNT      'P'      /* count of packets captured*/
#define PIPE_DROPS             'D'      /* count of packets dropped in capture */

/*the static declaration of glabol function*/
extern int pipe_write_hdr(int pipe, char type, int len);
extern int pipe_read_hdr(int pipe, char *hdr,char *type,int *msg_len);
extern void pipe_write_msg(int pipe, char type, const char *msg);
extern void pipe_msg_to_parent(char type,const char *msg);
extern int pipe_read_msg(int pipe, char *type, int len, char *msg);
extern int get_pipe_msg_type(int pipe,char *type);

#endif
