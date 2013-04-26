
/*
 * file: main.c
 * Written 2009-2013 by fU9ANg
 * bb.newlife@gmail.com
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "server.h"
#include "crc32.h"
#include "interface_pub.h"

/* 接收消息结构体 */

/* 全局定义区 */
sem_t sem;
int udp_socket_fd=-1;
MESSAGE_QUEUE * queue=NULL;
unsigned long queque_num = 4000;
PSRTA_HDR_ID pst;
USR_LIST_MEM_ID g_usr_list_id=NULL;
int g_usr_list_num=0;
//DCUSR_INFO_ID dcusr_addr=NULL;

/* 接收UDP线程处理 */
void udp_recev(void);
void udp_dispose_anwser(void);
static void get_itf_par(DC_INF_PARA_ID par_itf_id,char *p_par);
static int  com_usrid(const void* a,const void *b);

/**********************************
*function name: main program
*function:
*parameters:
*call:
*called:
*return:
*/
int main(int argc,char *argv[])
{
    pthread_t thread_proc1,thread_proc2;
    struct sockaddr_in sin;
    char *p_par = NULL;
    DC_INF_PARA dc_itf_para;
    int usr_shm_id;

    if(argc<=0)
    {
		perror("#################################DC DC transfer pare num err!");
		exit(1);
	}
  	queue=(MESSAGE_QUEUE *)calloc(sizeof(MESSAGE_QUEUE),queque_num);
	if(queue ==NULL){
		perror("message queue alloc mem fail!");
	//	free(dcusr_addr);
		exit(0);
	}
	/*得到参数*/
	 p_par = strdup(argv[0]);  
	 get_itf_par(&dc_itf_para,p_par);
	 g_usr_list_num = dc_itf_para.usr_num-1;
	 //printf("########dc usr num = %ld\n",dc_itf_para.usr_num);
	 /*得到用户信息共享内存*/
	if(dc_itf_para.usr_list_key>0&&dc_itf_para.usr_num>0){
       	usr_shm_id = shmget(dc_itf_para.usr_list_key,0,IPC_CREAT);
    		if (usr_shm_id < 0)
    		{
        		error("[Err]GET usr list  shm fail.\n");
        		exit(EXIT_FAILURE);
    		}
    		g_usr_list_id = (USR_LIST_MEM_ID)shmat(usr_shm_id,NULL,0);
    		if (!g_usr_list_id)
    		{
        		error("[Err]Attach usr list shm fail.\n");
        		exit(EXIT_FAILURE);
    		}
	}


	 
	 /*初始化SOCKET通信接口*/
    memset (&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons (5433);
        
    udp_socket_fd = socket (AF_INET,SOCK_DGRAM,0);
    if (udp_socket_fd < 0)
    {
        perror ("udp socket create fail!\n");
        free (queue);
        exit (1);
	}
    //printf("udp socket ok\n");
    if (bind (udp_socket_fd, (struct sockaddr *)&sin, sizeof(sin))<0)
    {
        perror ("udp server bind fail!\n");
        free (queue);
        close (udp_socket_fd);
        exit (1);
	}
    sem_init (&sem,0,0);
  	pthread_create (&thread_proc1, NULL, (void *)udp_dispose_anwser, NULL);
  	pthread_create (&thread_proc2, NULL, (void *)udp_recev, NULL);
  	pthread_join (thread_proc1, NULL);  /*父线程退出，进程退出*/
    close (udp_socket_fd);

	return 0;
}

/**********************************
*func name:接收UDP接收线程处理程序
*function:
*parameters:
*call:
*called:
*return:
*/
void udp_recev(void)
{
    struct sockaddr_in c_addr;
    socklen_t addr_len;
    int len,i;
    unsigned char msgbuf[RECV_BYTES_LEN];
        
    addr_len = sizeof(c_addr);

   	/* 循环接收数据 */
   	while (1)
    {
        memset(msgbuf,0,RECV_BYTES_LEN);
        len = recvfrom (udp_socket_fd, msgbuf, RECV_BYTES_LEN, 0, (struct sockaddr *) &c_addr, &addr_len);
        if (len < 0||len >RECV_BYTES_LEN)
        {
            perror("recvfrom fail !");
            exit(errno);
        }
        msgbuf[len] = '\0';
        //printf("len = %d\n",len);
        for (i=0;i<queque_num;i++)
            if (queue[i].flag==0) break;
        if(i ==queque_num )
            continue;

        queue[i].flag=1;
        queue[i].length=len;
        memcpy(queue[i].message,msgbuf,len+1);
        queue[i].addr = c_addr;
        sem_post(&sem);
        //printf("recv data ok\n");
    }
}

/**********************************
*func name:接收UDP处理及其应答回应线程处理程序
*function:
*parameters:
*call:
*called:
*return:
*/
void udp_dispose_anwser(void)
{
        unsigned long * pl,usrid,num0,crcnum;
		unsigned short *ps ,num1;
		unsigned char *one_byte,usr_token_status,num2;
                struct sockaddr_in c_addr;
		unsigned char usr_name[256];
		unsigned char usr_mac[7];
		char str[256],os_str[256],host_name[256],usr_register_info[256],strusrid[256],usr_ip[24],usr_real_ip[24];
  		int len,i,cur_len;
		unsigned char buff[RECV_BYTES_LEN],*offset,msgbuf[RECV_BYTES_LEN],usr_id_len;
		USR_LIST_MEM_ID cur_usr_list_id = NULL;
		USR_LIST_MEM	cur_usr_item;
		char usage_flag = 0;
                pl = &num0;
                ps = &num1;
                one_byte = &num2;
  		while (1) { 
     			sem_wait(&sem);
     			for (i=0;i<queque_num;i++)
       			if (queue[i].flag==1) {	
					     memset(buff,0x00,RECV_BYTES_LEN);
                                        c_addr = queue[i].addr;
                                        offset = buff;
         				len=queue[i].length;
                                        //printf("###queue len = %d\n",len);
         				memcpy(buff,queue[i].message,len);
                                        pst = (PSRTA_HDR_ID)buff;
					//printf("###pst.flag = %s\n",pst->flag);
                                        //printf("version = 0x%4x\n",pst->version);;
                                       // printf("opt_code = 0x%x\n",pst->opt_code);
                                       // printf("###param_lenth = %u\n",pst->param_length);
					crcnum = crc32(0,buff,(PSRTA_HDR_SIZE+pst->param_length));
                                       // printf("crc32 len = %d\n",(PSRTA_HDR_SIZE+pst->param_length));
					memcpy(pl,(buff+len-4),4);
					//printf("crcnum = %u   *pl = %u\n",crcnum,num0);
					if(crcnum == *pl)
					{
						//printf("recv data crc32 ok\n");
						if((strncmp(pst->flag,"SRTA",4)==0)&&(pst->opt_code==REGISTER_INFO)){
							/*REGISTER INFO*/
							offset+=PSRTA_HDR_SIZE;
							memcpy(one_byte,offset,1);
							cur_len = *one_byte;
							usr_id_len = cur_len;
							offset++;
                                                        //printf("cur len = %d\n",cur_len);
							memcpy(str,offset,cur_len);
							memcpy(strusrid,offset,cur_len);
							str[cur_len]='\0';
                                                        //printf("usr id str = %s\n",str);
							usrid = atoi(str);
							//printf("usrid = %u\n",usrid);
							offset += cur_len;
							memcpy(one_byte,offset,1);
							cur_len = *one_byte;
							offset++;
							memcpy(usr_name,offset,cur_len);
							usr_name[cur_len]='\0';
							offset+=cur_len;
							memcpy(usr_mac,offset,6);
							usr_mac[6]='\0';
							offset+=6;
							/*ip*/
							memcpy(one_byte,offset,1);
							cur_len = *one_byte;
							offset++;
							memcpy(usr_ip,offset,cur_len);	
							usr_ip[cur_len]='\0';
							//printf("usr ip =%s\n",usr_ip);
							offset+=cur_len;
							/*os info*/
							memcpy(one_byte,offset,1);
							cur_len = *one_byte;
							offset++;
							memcpy(os_str,offset,cur_len);
							os_str[cur_len]='\0';
							//printf("os info = %s\n",os_str);
							offset+= cur_len;
							/*host name */
							memcpy(one_byte,offset,1);
							cur_len = *one_byte;
							offset++;
							memcpy(host_name,offset,cur_len);
							host_name[cur_len]='\0';
							//printf("host name =%s\n",host_name);
							offset+=cur_len;
							/*usr token lock status */
							memcpy(one_byte,offset,1);
							usr_token_status = *one_byte;
							offset++;
							//printf("usr token lock status = %d\n",usr_token_status);
							/*usr register detail info */
							memcpy(one_byte,offset,1);
							cur_len = *one_byte;
							offset++;
							memcpy(usr_register_info,offset,cur_len);
							usr_register_info[cur_len]='\0';
							//printf("usr register info = %s\n",usr_register_info);
							offset +=cur_len;
							/*usr real ip info */
							memcpy(one_byte,offset,1);
							cur_len = *one_byte;
							offset++;
							memcpy(usr_real_ip,offset,cur_len);
							usr_real_ip[cur_len]='\0';
							//printf("usr real ip = %s\n",usr_real_ip);
							/*进入发送回应信息*/
							offset = msgbuf;
							memcpy(offset,&pst->flag,4);
							offset+=4;
							memcpy(offset,&pst->version,2);
							offset+=2;
							pst->opt_code = 0x81;
							memcpy(offset,&pst->opt_code,1);
							offset+=2;
							pst->param_length = 5+usr_id_len;
							memcpy(offset,&pst->param_length,4);
							//printf("send to param len = %d\n",pst->param_length);
							offset+=4;
							num0=0;
							memcpy(offset,&num0,4);
							offset+=4;
							memcpy(offset,&usr_id_len,1);
							offset++;
							memcpy(offset,strusrid,usr_id_len);
							offset+=usr_id_len;
                                                        //printf("usr id len = %d\n",usr_id_len);
							crcnum = crc32(0,msgbuf,(PSRTA_HDR_SIZE+pst->param_length));
							memcpy(offset,&crcnum,4);
                                                        //printf("crcnum ====%u\n",crcnum);
                                                        
							if(g_usr_list_num > 0)
							{
                                                 	cur_usr_list_id = (USR_LIST_MEM_ID)bsearch((const void*)usrid,(void*)g_usr_list_id,1/*g_usr_list_num*/,USR_LIST_MEM_SIZE,com_usrid); 
							}else if(g_usr_list_num == 0)
							{
								cur_usr_list_id = g_usr_list_id;
							}else
							{
								continue;
							}
							if(cur_usr_list_id !=NULL){
								cur_usr_item = *cur_usr_list_id;
								usage_flag = 1;
								cur_len = sizeof(usr_name)>255?255:sizeof(usr_name);
								memcpy(cur_usr_list_id->strUsrName,usr_name,cur_len);
//                                                        cur_usr_list_id->ip = inet_addr(usr_ip);
								cur_usr_list_id->ip = inet_addr(usr_real_ip);
                                                        memcpy(cur_usr_list_id->strMac,usr_mac, 6);
								cur_usr_list_id->usr_status=1; //online														
								printf("DC SERVER:usrid = %d,usr_name = %s,ip = %s,mac = %.2X%.2X%.2X%.2X%.2X%.2X online\n", \
									cur_usr_list_id->iUsrId,cur_usr_list_id->strUsrName,inet_ntoa(cur_usr_list_id->ip),\
									cur_usr_list_id->strMac[0], cur_usr_list_id->strMac[1], cur_usr_list_id->strMac[2], \
									cur_usr_list_id->strMac[3], cur_usr_list_id->strMac[4], cur_usr_list_id->strMac[5]);
							}					 
							//printf("send to len = %d \n",(PSRTA_HDR_SIZE+pst->param_length+4));
						sendto(udp_socket_fd,msgbuf,(PSRTA_HDR_SIZE+pst->param_length+4),0,&c_addr,sizeof(c_addr));
							goto next;
						}
						if((strncmp(pst->flag,"SRTA",4)==0)&&(pst->opt_code==UNREGISTER_INFO)){
							/*UNREGISTER INFO*/
                                                       //printf("UNREGISTER INFO\n");
                                                        offset+=PSRTA_HDR_SIZE;
                                                        memcpy(one_byte,offset,1);
                                                        cur_len = *one_byte;
							       usr_id_len = cur_len;
                                                        offset++;
                                                        //printf("cur len = %d\n",cur_len);
                                                        memcpy(str,offset,cur_len);
								memcpy(strusrid,offset,cur_len);
                                                        str[cur_len]='\0';
                                                        //printf("usr id str = %s\n",str);
                                                        usrid = atoi(str);

								if(g_usr_list_num > 0)
								{
									cur_usr_list_id = (USR_LIST_MEM_ID)bsearch((const void*)usrid,(void*)g_usr_list_id,g_usr_list_num,USR_LIST_MEM_SIZE,com_usrid); 
								}else if(g_usr_list_num == 0)
								{
									cur_usr_list_id = g_usr_list_id;
								}else
								{
									continue;
								}
								if(cur_usr_list_id !=NULL){
								if(usage_flag == 1)
								{
									*cur_usr_list_id = cur_usr_item;
									usage_flag = 0;
								}
								cur_usr_list_id->usr_status=0; //online
								printf("DC SERVER:usrid = %d,usr_name = %s,ip = %s,mac = %.2X%.2X%.2X%.2X%.2X%.2X offline\n", \
									cur_usr_list_id->iUsrId,cur_usr_list_id->strUsrName,inet_ntoa(cur_usr_list_id->ip),\
									cur_usr_list_id->strMac[0], cur_usr_list_id->strMac[1], cur_usr_list_id->strMac[2], \
									cur_usr_list_id->strMac[3], cur_usr_list_id->strMac[4], cur_usr_list_id->strMac[5]);
								//cur_len = sizeof(usr_name)>255?255:sizeof(usr_name);
								//memcpy(&(cur_usr_list_id->strUsrName),usr_name,cur_len);
								//printf("write usr list info table ok,usrid = %d usrname = %s offline\n",usrid,usr_name);
							}									
                                                        //printf("用户注销usrid = %u\n",usrid);
								//printf("用户注销完毕\n");
								/*进入发送回应信息*/
								offset = msgbuf;
								memcpy(offset,&pst->flag,4);
								offset+=4;
								memcpy(offset,&pst->version,2);
								offset+=2;
								pst->opt_code = 0x82;
								memcpy(offset,&pst->opt_code,1);
								offset+=2;
								pst->param_length = 5+usr_id_len;
								memcpy(offset,&pst->param_length,4);
								//printf("send to param len = %d\n",pst->param_length);
								offset+=4;
								num0=0;
								memcpy(offset,&num0,4);
								offset+=4;
								memcpy(offset,&usr_id_len,1);
								offset++;
								memcpy(offset,strusrid,usr_id_len);
								offset+=usr_id_len;
								crcnum = crc32(0,msgbuf,(PSRTA_HDR_SIZE+pst->param_length));
								memcpy(offset,&crcnum,4);
								//printf("crcnum zhuxiao = %u\n",crcnum);
						//printf("crcnum zhuxiao param len =%d\n",(PSRTA_HDR_SIZE+pst->param_length+4));
						sendto(udp_socket_fd,msgbuf,(PSRTA_HDR_SIZE+pst->param_length+4),0,&c_addr,sizeof(c_addr));
								goto next;
						}
						goto next1;
						
					}else{
					/*发送错误信息给动态身份认证服务器*/
next1:
								//printf("发送错误信息\n");
								offset+=PSRTA_HDR_SIZE;
								memcpy(one_byte,offset,1);
								usr_id_len = cur_len;
								offset++;
								memcpy(strusrid,offset,cur_len);
								/*开始发送错误信息*/
								offset = msgbuf;
								memcpy(offset,&pst->flag,4);
								offset+=4;
								memcpy(offset,&pst->version,2);
								offset+=2;
								pst->opt_code = 0x81;
								memcpy(offset,&pst->opt_code,1);
								offset+=2;
								pst->param_length = 5+usr_id_len;
								memcpy(offset,&pst->param_length,4);
								//printf("send to param len = %d\n",pst->param_length);
								offset+=4;
								num0=1;
								memcpy(offset,&num0,4);
								offset+=4;
								memcpy(offset,&usr_id_len,1);
								offset++;
								memcpy(offset,strusrid,usr_id_len);
								offset+=usr_id_len;
								crcnum = crc32(0,msgbuf,(PSRTA_HDR_SIZE+pst->param_length));
								memcpy(offset,&crcnum,4);
								//printf("crcnum zhuxiao = %u\n",crcnum);
						//printf("crcnum zhuxiao param len =%d\n",(PSRTA_HDR_SIZE+pst->param_length+4));
						sendto(udp_socket_fd,msgbuf,(PSRTA_HDR_SIZE+pst->param_length+4),0,&c_addr,sizeof(c_addr));
					}
next:
					 queue[i].flag=0;
					 cur_usr_list_id =NULL;
       			}
		}
}

/**********************************
*func name:得到参数接口
*function:
*parameters:
*call:
*called:
*return:
*/
static void get_itf_par (DC_INF_PARA_ID par_itf_id, char *p_par)
{
    register char *p = NULL;
    p=strtok (p_par, PAR_DELIM);
    par_itf_id->usr_list_key= strtoul (p, NULL, 10);
    p = strtok (NULL, PAR_DELIM);
    par_itf_id->usr_num = atoi (p);

    return;
}

/**********************************
*func name:比较两个数大小
*function:
*parameters:
*call:
*called:
*return:
*/
static int com_usrid (const void* a, const void *b)
{
    if((unsigned long)a == ((struct tagUSRLISTMEM *)b)->iUsrId)
        return 0;
    else if((unsigned long )a > ((struct tagUSRLISTMEM *)b)->iUsrId)
        return 1;
    else 
        return -1;
}
