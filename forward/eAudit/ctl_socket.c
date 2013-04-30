
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include <syslog.h>
#include <errno.h>

#include "eAudit_pub.h"
#include "eAudit_log.h"
#include "eAudit_res_callback.h"

#include "ctl_pub.h"
#include "ctl_debug.h"
#include "ctl_cmd.h"
#include "ctl_socket.h"

typedef enum
{
    MOT_SVR_NO_WORK,
    MOT_SVR_WORK
}EN_MOT_SVR_STATUS;

/*global var declaration*/
EN_SYS_STATUS g_sys_status = SYS_FOR_READY;
EN_MOT_SVR_STATUS g_mot_status = MOT_SVR_NO_WORK;

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void monitor_cmd_server()
{
    int listen_sockfd;
    int com_sockfd = -1;
    char buf[MAX_RECV_SIZE];
    int sin_size; 
    struct sockaddr_in server_addr; 
    struct sockaddr_in client_addr;
    struct sockaddr_in mot_svr_addr;

    int flag;
    int nfds;
    int sel_ret;
    fd_set rfds;
    struct timeval timeout;
    unsigned int bytes_read;
    int ret;

    if((listen_sockfd = socket(PF_INET,SOCK_STREAM,0))== -1){ 
        error("[Err]Create monitor server socket err."); 
        exit(EXIT_FAILURE); 
    }

    flag = 1;
    if (setsockopt(listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
    {
        error("[Err]setsockopt SO_REUSEADDR err."); 
        exit(EXIT_FAILURE); 
    }

#if 1
    flag = 1;
    if (setsockopt(listen_sockfd, IPPROTO_TCP,TCP_NODELAY, (char *)&flag, sizeof(flag)) == -1)
    {
        error("[Err]setsockopt TCP_NODELAY err."); 
        exit(EXIT_FAILURE); 
    }
#endif

    server_addr.sin_family = PF_INET; 
    server_addr.sin_port = htons(LOCAL_SEVER_PORT); 
    server_addr.sin_addr.s_addr = INADDR_ANY; 
    bzero(&(server_addr.sin_zero),SIN_ZERO_LEN); 

    if(bind(listen_sockfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr)) == -1){ 
        error("[Err]Bind sever socket err."); 
        close(listen_sockfd);
        exit(EXIT_FAILURE); 
    }
 
    if(listen(listen_sockfd,MAX_REQURE_NUM)== -1){ 
        error("[Err]Listen sever socket err."); 
        close(listen_sockfd);
        exit(EXIT_FAILURE); 
    } 
    sin_size = sizeof(struct sockaddr_in);
    
    timeout.tv_sec = 0;
    timeout.tv_usec = 250*1000;
	
    while(SAIL_TRUE)
    {
        FD_ZERO(&rfds);
	 FD_SET(listen_sockfd, &rfds);
	 if (com_sockfd > 0){
	     FD_SET(com_sockfd, &rfds);
	     nfds = SKT_MAX(listen_sockfd,com_sockfd);
	 }
        else
	     nfds = listen_sockfd;
		
	 sel_ret = select(nfds+1, &rfds, NULL, NULL, &timeout);
	 switch(sel_ret){
	 case -1: /*select err*/
	     error("[Err]Select socket err."); 
	     close(listen_sockfd);
	     if (com_sockfd > 0)
	         close(com_sockfd);
            exit(EXIT_FAILURE); 
	     break;
	 case 0:  /*time out*/
            break;
	 default:
	     if (FD_ISSET(listen_sockfd,&rfds))
	     {
	         do
	         {
	             com_sockfd = accept(listen_sockfd,(struct sockaddr *)&client_addr,&sin_size);
	         }while (com_sockfd == -1 && errno == EINTR);
			 
                 if(-1 == com_sockfd){ 
                    error("[Err]Accept sever socket err."); 
                 } 

                 if (MOT_SVR_NO_WORK == g_mot_status){
                    ret = getpeername(com_sockfd,(struct sockaddr *)&mot_svr_addr,\
                                                sizeof mot_svr_addr);
                    if (-1 == ret)
                    {
                        error("[Err]Get peer ip addr err.\n");
                    }
                    else
                    {
                        g_mot_status = MOT_SVR_WORK;
                        //pipe_msg_to_parent(PIPE_NORMAL_MSG,(const char *)&mot_svr_addr);
                    }
                }
	     }

            if (com_sockfd > 0){
	         if (FD_ISSET(com_sockfd,&rfds))
	         {
	             bytes_read = recv(com_sockfd,buf,sizeof(buf),0); 
	             if (bytes_read)
	             {
	                 ctl_analysis_pkt(buf);
	             }
                    else
                    {
                        /* Peer closed the socket, finish the close */ 
                        close(com_sockfd);
                    }
	         }
            }
	     break;
	 }
    }

    exit(EXIT_SUCCESS);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int monitor_acting_client(void)
{
    struct hostent *hp;
    struct sockaddr_in sin;
	
    int client_sockfd;
    struct sockaddr_in server_addr; 
    int conn_stat;

    if (NULL == (hp = gethostbyname(MONITOR_SVR_NAME)))
    {
        error("[Err]Get host by name fail."); 
        return -1; 
    }

    memcpy(&(sin.sin_addr),hp->h_addr,hp->h_length);
	
    if(-1 == (client_sockfd = socket(PF_INET,SOCK_STREAM,0))){ 
        error("[Err]Create monitor acting socket err."); 
        return -1; 
    } 
	
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(SND_SVR_PORT); 
    server_addr.sin_addr  = sin.sin_addr; 
    bzero(&(server_addr.sin_zero),8); 

CONN_RETRY:
    if ((conn_stat = connect(client_sockfd,(struct sockaddr *) &server_addr, sizeof(server_addr))) < 0)
    {
        if (errno == EINTR)
	     goto CONN_RETRY;

	close(client_sockfd);
        return -1;
    }
	
     return  client_sockfd;
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
int skt_send(int sock_fd,void *buffer,int length) 
{ 
     int bytes_left = length;; 
     int senden_bytes; 
     char *ptr = buffer; 

     while(bytes_left>0) 
     { 
         senden_bytes = send(sock_fd,ptr,bytes_left,0); 
         if(senden_bytes <= 0) 
         {        
             if(errno==EINTR)  /* ÖÐ¶Ï´íÎó ¼ÌÐøÐ´*/ 
                 senden_bytes=0; 
             else            
                 return ERR; 
         } 
		 
         bytes_left -=senden_bytes; 
         ptr += senden_bytes;   
    } 
	 
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
int skt_recv(int sock_fd,void *buffer,int length) 
{ 
    int bytes_left = length;; 
    int bytes_recv = 0; 
    char *ptr = NULL; 
   
    while (bytes_left >0) 
    { 
        bytes_recv = recv(sock_fd,ptr,bytes_recv,0); 
        if (bytes_recv < 0) 
        { 
            if(errno==EINTR) 
                bytes_recv = 0; 
            else 
                return ERR; 
        } 
        else if(bytes_recv == 0) 
            break; 
        
        bytes_left -= bytes_recv; 
        ptr += bytes_recv; 
    }
    
    return(length-bytes_left); 
} 
