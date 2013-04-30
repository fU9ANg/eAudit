
#ifndef _CTL_SOCKET_H
#define _CTL_SOCKET_H

#define MONITOR_SVR_NAME "eAudit_monitor"

#define LOCAL_SEVER_PORT 2002
#define SND_SVR_PORT 2004

#define SIN_ZERO_LEN 8

#define MAX_REQURE_NUM   5
#define MAX_RECV_SIZE       1024*1024 /*100MBps * 0.050(RTT) sec / 8 */

enum EN_SOCKET_OPT_STAT{SOCKET_OPT_CLOSE,SOCKET_OPT_OPEN};

#define SKT_MAX(x,y) ((x) > (y)?(x):(y))

/*function declaration*/
extern void monitor_cmd_server();
extern int monitor_acting_client(void);
extern int skt_send(int sock_fd,void *buffer,int length);
extern int monitor_acting_client(void);

#endif 
