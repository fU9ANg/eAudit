#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>
#include <sys/mman.h>

#include "ini_file_reader.h"

#define MAXBUF 700
#define MAXEPOLLSIZE 10000
#define THREAD_MAX  20  //100      线程池连接并发线程数
#define ERR 0
#define DAT 1

typedef struct tag_SRTA_HDR
{
    unsigned char   flag[4];
    unsigned short  version;       
    unsigned char   opt_code;        
    unsigned long   param_length;
}PSRTA_HDR,*PSRTA_HDR_ID;                /*sail regist to eAudit session's head define*/

typedef struct tag_SESSION_HDR
{
    unsigned char  flag[4];
    unsigned short  version;       
    unsigned long   serial;
    unsigned char  mode;             
    unsigned char  opt_code;         
    unsigned long  param_length;
    unsigned long  reserved;
    unsigned long  prt_crc;
}PSESSION_HDR,*PSESSION_HDR_ID;          /*session head define*/

typedef struct tag_SESSION_RGT_RSP
{
   unsigned int   result;
   u_int32_t        ip;
   u_int16_t        port;
   u_int16_t        time;
}PSESSION_RGT_RSP;                      /*session regist response*/

typedef struct tag_REGIST
{
  unsigned char flag;
  int user_id;
  char user_name[16];
  unsigned char count;
}REGIST_QUEUE;

typedef struct tag_EPOLL_ADDR
{
   char addr[16];
}EPOLL_ADDR;

typedef struct tag_THEMP
{
   int flag;
   int fd;
   char addr[16];
   int index;
}THREAD_PARAM;


static struct sockaddr_in s_addr;
static REGIST_QUEUE * rgst_queue;

char degree_ip[16], eAudit_ip[16];
char user_file[80];
int degree_port, eAudit_port;
int udp_sock,def_DEBUG=0,NO; 
int check_time,handshake_time;
int lisnum=1000, num_childs=20, u_port=5801,num_process=20,num_pthread=400;

int setnonblocking(int sockfd);
void handle_message(THREAD_PARAM * thread_param);
int in_usr_table(const int usrid, const char * usrname);
void check_online();
void sigroutine(int signo);
int read_user_file(const char * conf_filename);

extern int   BinarySearch(REGIST_QUEUE *a, int e,int left,int right);
extern void  writelog(int level , char logmsg[]);
extern int   udp_process(int port);
extern unsigned long crc32( unsigned long crc, const unsigned char *buf, unsigned int len );

//线程池参数
static THREAD_PARAM s_thread_para[THREAD_MAX];  //线程参数
static pthread_t s_tid[THREAD_MAX];             //线程ID
pthread_mutex_t s_mutex[THREAD_MAX];            //线程锁


//私有函数
static int init_thread_pool(void);

static int init_thread_pool(void)
{
  int i, rc;

  //初始化线程池参数
  for(i = 0; i < THREAD_MAX; i++) {
	s_thread_para[i].flag = 0;                //设置线程占用标志为"空闲"
	s_thread_para[i].index = i;               //线程池索引
        pthread_mutex_init(s_mutex + i,NULL);     // 用默认属性初始化互斥锁对象
	pthread_mutex_lock(s_mutex + i);          //线程锁
  }

  //创建线程池
  for(i = 0; i < THREAD_MAX; i++) {
	rc = pthread_create(s_tid + i, 0, (void *)handle_message, (void *)(s_thread_para + i));
	if (0 != rc) {
	  fprintf(stderr, "线程创建失败\n");
	  return(-1);
  	}
  }

  //成功返回
  return(0);
}

void sigroutine(int signo)
{
  switch (signo) {

    case SIGALRM:
      check_online();
      signal(SIGALRM, sigroutine);
      break;
  }
 return;
}

void DEBUG(const char *fmt, ...)
{

  if (def_DEBUG) {
    va_list ap;

    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
         if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
  }
}

int cmp( const void *a ,const void *b) 
{ 
      return ((REGIST_QUEUE *)a)->user_id > ((REGIST_QUEUE *)b)->user_id ? 1 : -1; 
} 


//设置句柄为非阻塞方式
int setnonblocking(int sockfd)
{
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1) {
        return -1;
    }
    return 0;
}

int in_usr_table(const int usrid, const char * usrname)
{
  int i,result=0;

  i=BinarySearch(rgst_queue,usrid,0,NO); 
 
  if (( i>=0 ) && (rgst_queue[i].flag==0) ) 
  {
     if (!strcmp(rgst_queue[i].user_name,usrname))
    {
       rgst_queue[i].flag=1;

       //msync(rgst_queue,sizeof(REGIST_QUEUE)*NO,MS_ASYNC);

       DEBUG("regist ok! userid ----%d  username -----%s  i=%d\n",rgst_queue[i].user_id, rgst_queue[i].user_name,i);
       result=1;
    }
  }
  return result;
}

void check_online()
{
  int i,people;
  char msg_record[80];
/*
  int lens,len,logout,i_recv;
  char buf_eA[80],bufx[80],tmp[80],user_id[32];
  PSRTA_HDR_ID pst;
  unsigned long parity,tail_crc;
  unsigned long *lp;
*/
  people=0;
  for (i=0;i<NO;i++)
    if (rgst_queue[i].flag==1) 
    {
       people++;
       rgst_queue[i].count+=1;
       if (rgst_queue[i].count>3) 
       {
	  rgst_queue[i].flag=0;
          rgst_queue[i].count=0;
          people--;
 
      sprintf(msg_record,"用户id = %d 已注销!\n",rgst_queue[i].user_id);
      writelog(DAT,msg_record);

     //msync(rgst_queue,sizeof(REGIST_QUEUE)*NO,MS_ASYNC);
 /*
       sprintf(user_id,"%d",regst_queue[i].user_id);
       lens = strlen(userid);

       do
       {
          logout=0;
          pst=malloc(sizeof(PSRTA_HDR));

          memcpy(pst->flag,"SRTA",4);
          pst->version      = 0x0100;
          pst->opt_code     = 0x02;
          pst->param_length = 1+lens;

          memset(buf_eA,0,80);
          memcpy(buf_eA, pst, sizeof(PSRTA_HDR));
          memcpy(buf_eA+sizeof(PSRTA_HDR), &lens, 1);
          memcpy(buf_eA+sizeof(PSRTA_HDR)+1,user_id,lens);

          parity = crc32(0,buf_eA,sizeof(PSRTA_HDR)+lens+1);

          memcpy(buf_eA+sizeof(PSRTA_HDR)+len+1,&parity,4);
          lens = sizeof(PSRTA_HDR)+1+lens+4;
          sendto(udp_sock, buf_eA, len, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));

          lens=sizeof(s_addr);
          i_recv=recvfrom(udp_sock, tmp, 128, 0, (struct sockaddr *)&s_addr, &lens);

         if (i_recv>4)
         {
            printf("i_recv ------------ %d\n",i_recv);
            bzero(bufx, 128);
            memcpy(bufx,tmp,i_recv-4);

            parity=crc32(0,bufx,i_recv-4);

            bzero(bufx,20);
            memcpy(bufx,(tmp+i_recv-4),4);
            lp=(unsigned long *)&bufx;
            tail_crc=*lp;
            memcpy(bufx,tmp,i_recv-4);

            parity=crc32(0,bufx,i_recv-4);

            bzero(bufx,20);
            memcpy(bufx,(tmp+i_recv-4),4);
            lp=(unsigned long *)&bufx;
            tail_crc=*lp;
 
            printf("parity: %u      tail_crc: %u\n",parity,tail_crc); 
           if ( parity==tail_crc)
           {
              bzero(bufx,50);
              memcpy(bufx,(tmp+sizeof(PSRTA_HDR)),4);
              lp=(unsigned long *)&bufx;
              parity=*lp;
              printf("return : %u\n",parity);
              if (parity==0)
              { 
                 len=tmp[sizeof(PSRTA_HDR)+4]; 
                 bzero(bufx,50);
                 memcpy(bufx,tmp+sizeof(PSRTA_HDR)+4+1,len);
                 bufx[len]='\0';
                 if (atoi(bufx)==atoi(user_id))
                 { 
                   logout=1;
                   sprintf(msg_record,"用户id = %s 注销成功!\n",bufx);
                   writelog(DAT,msg_record);
                   DEBUG("communicat to eAudit logout------ok!");
		 }
              }
           }
          }
       } while (logout==0);

       free(pst);
 */

        }
     }
  printf("people=%d\n",people);
}

/*
handle_message - 处理每个 socket 上的消息收发
*/
void handle_message(THREAD_PARAM * thread_param)
{
    int new_fd;
    char addr[16];
    struct in_addr ip_address;
    unsigned char buf[MAXBUF],bufx[256];
    char tmp[MAXBUF];
    char buff[MAXBUF],userid[10],username[30];
    char msg_record[MAXBUF];

    int len,pool_index;
    unsigned long crcnum1,crcnum2, tail_crc;
    PSESSION_HDR_ID ps;
    PSESSION_RGT_RSP * rsp;
    unsigned int rp;
    int offset,length ;
    unsigned long * lp;
    
    /*
     PSRTA_HDR_ID pst;
     int regist=0,i_recv,i,time,port;
     unsigned long parity,
    */

    //线程脱离创建者
    pthread_detach(pthread_self());
    pool_index=thread_param->index;

  wait_unlock:

    pthread_mutex_lock(s_mutex + pool_index);//等待线程解锁

  //线程变量内容复制
    new_fd=thread_param->fd;
    memcpy(addr, thread_param->addr,16);
        
    /* 开始处理每个新连接上的数据收发 */
    bzero(buf, MAXBUF);
    /* 接收客户端的消息 */
    len = recv(new_fd, buf, MAXBUF, 0);
    if (len > 0)
        DEBUG
            ("%d接收消息成功:'%s'，共%d个字节的数据\n", new_fd, buf, len);
    else {
        if (len < 0)
            printf
                ("消息接收失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
        close(new_fd);
        return ;
    }

     //ps=malloc(sizeof(PSESSION_HDR));

     ps=(PSESSION_HDR_ID)buf;

     ps->version=ntohs(ps->version);
     ps->serial=ntohl(ps->serial);
     ps->param_length=ntohl(ps->param_length);
     ps->prt_crc=ntohl(ps->prt_crc);

     bzero(bufx, 50);
     memcpy(bufx,ps,sizeof(PSESSION_HDR)-4);

     crcnum1=crc32(0,bufx,sizeof(PSESSION_HDR)-4);

     //printf("crcnum1=%x,  prt_crc=%x\n",crcnum1,ps->prt_crc);

     bzero(bufx, 256);
     memcpy(bufx,ps,sizeof(PSESSION_HDR));
     memcpy((bufx+28),(buf+28),ps->param_length);
  
     crcnum2=crc32(0,bufx,28+ps->param_length);
  
     bzero(bufx,4);
     memcpy(bufx,(buf+len-4),4);
     lp=(unsigned long *)&bufx;
     tail_crc=*lp;   

     //printf("crcnum2=%x,  tail_crc=%x\n",crcnum2,tail_crc);
     
   if ( crcnum1==ps->prt_crc  && crcnum2==tail_crc )
   {
     if ( (!strncmp((char *)ps->flag,"SNRP",4)) && ps->opt_code==0x01 && ps->version==0x0100 ){

       //printf("recev a correct regist message of SAIL\n");

       bzero(buff,256);

       if (ps->mode==0)      
         memcpy(buff,(buf+28),ps->param_length);
       else{
         if (ps->mode==2) {      //加密传输  DES_CBC  此版未加密，原样拷出
           memcpy(buff,buf+28,ps->param_length);
           //len=xl_des_decrypt("CDXLSNRP",buff,ps->param_length,tmp);   
         }
       }

       offset=0;
 
       length=buff[offset];
       offset+=1;

       memcpy(bufx,(buff+offset),length);
       bufx[length]='\0';
       sprintf(msg_record,"用户id = %s 登录成功!  用户信息如下:\n",bufx);
       memcpy(userid,bufx,length);
       userid[length]='\0';
       offset+=length;
       
       length=buff[offset];
       offset+=1;

       memcpy(bufx,(buff+offset),length);
       bufx[length]='\0';
       sprintf(tmp,"      用户名 = %s  ",bufx);
       memcpy(username,bufx,length);
       username[length]='\0';
       offset+=length;
       strcat(msg_record,tmp);
       
       length=6;
       memcpy(bufx,(buff+offset),length);
       sprintf(tmp,"MAC = %02X-%02X-%02X-%02X-%02X-%02X  ",bufx[0],bufx[1],bufx[2],bufx[3],bufx[4],bufx[5]);
       offset+=length;
       strcat(msg_record,tmp);

       length=buff[offset];
       offset+=1;

       memcpy(bufx,(buff+offset),length);
       bufx[length]='\0';
       sprintf(tmp,"用户本机IP地址 = %s  ",bufx);
       offset+=length;
       strcat(msg_record,tmp);

       length=buff[offset];
       offset+=1;

       memcpy(bufx,(buff+offset),length);
       bufx[length]='\0';
       sprintf(tmp,"操作系统 = %s  \n",bufx);
       offset+=length;
       strcat(msg_record,tmp);

       length=buff[offset];
       offset+=1;

       memcpy(bufx,(buff+offset),length);
       bufx[length]='\0';
       sprintf(tmp,"      计算机名 = %s  ",bufx);
       offset+=length;
       strcat(msg_record,tmp);

       sprintf(tmp,"令牌锁定标志 = %d  ",buff[offset]);
       offset+=1;
       strcat(msg_record,tmp);

       length=buff[offset];
       offset+=1;

       memcpy(bufx,(buff+offset),length);
       bufx[length]='\0';
       sprintf(tmp,"登录事由 = %s  ",bufx);
       offset+=length;
       strcat(msg_record,tmp);

       sprintf(tmp,"真实IP = %s  \n",addr);
       strcat(msg_record,tmp);

       if (in_usr_table(atoi(userid),username)) 
       {   
         rp=0;
         printf("find user   ########################## %s   %s\n",userid,username);


     writelog(DAT,msg_record);
/*
         pst=malloc(sizeof(PSRTA_HDR));
        do
        {
         memcpy(pst->flag,"SRTA",4);
         pst->version      = 0x0100;
         pst->opt_code     = 0x01;
         pst->param_length = ps->param_length+strlen(addr)+1;
         
         printf("param_length=============%d\n",ps->param_length+strlen(addr)+1);

         memset(bufx,0,256);
         memcpy(bufx,pst,sizeof(PSRTA_HDR));

         memcpy(bufx+sizeof(PSRTA_HDR),buff,ps->param_length);

         length=strlen(addr);
         memcpy(bufx+sizeof(PSRTA_HDR)+ps->param_length,&length,1);
         memcpy(bufx+sizeof(PSRTA_HDR)+ps->param_length+1,addr,length);

         parity=crc32(0,bufx,sizeof(PSRTA_HDR)+ps->param_length+1+length);

         printf("jiaoyan_leng--------%d    parity-------%u  \n",sizeof(PSRTA_HDR)+ps->param_length+strlen(addr)+1,parity);

         memcpy(bufx+sizeof(PSRTA_HDR)+ps->param_length+1+length,&parity,4);
         len=sizeof(PSRTA_HDR)+ps->param_length+1+length+4;
         sendto(udp_sock, bufx, len, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));    
    
         printf("send to eAudit ----%d\n",len);
         for (i=0;i<len;i++)
            printf("%02X",bufx[i]);
         printf("\n");

         regist=0;
         length=sizeof(s_addr);
         i_recv=recvfrom(udp_sock, tmp, 128, 0, (struct sockaddr *)&s_addr, &length);        
        
         if (i_recv>4)  
         {
            printf("i_recv  ------------- %d\n",i_recv);
            bzero(bufx, 128);
            memcpy(bufx,tmp,i_recv-4);

            parity=crc32(0,bufx,i_recv-4);           
            tail_crc=0;
            lp=&tail_crc;
            memcpy(lp,(tmp+i_recv-4),4);

            printf("parity : %u       tail_crc: %u\n",parity,tail_crc);

           if ( parity==tail_crc)
 	   { 
              bzero(bufx,50);
              memcpy(bufx,(tmp+sizeof(PSRTA_HDR)),4);
              lp=(unsigned long *)&bufx;
              parity=*lp;
              printf("return : %u\n",parity);
              if (parity==0)
              {
                 bzero(bufx,50);
                 len=tmp[sizeof(PSRTA_HDR)+4];
                 memcpy(bufx,tmp+sizeof(PSRTA_HDR)+4+1,len);
                 bufx[len]='\0';
                 if (atoi(bufx)==atoi(usrid))
                 {
		    regist=1;
		    writelog(DAT,msg_record);
                    printf("communicat to eAudit ------ok!");
		 }
              }
           }
	  }
 
        }while (regist==0);

         free(pst);
*/
       }
       else rp=88;

     } 
     else rp=77;
    

     ps->opt_code=0x81;
     ps->param_length=12;

     bzero(bufx, 50);
     memcpy(bufx,ps,sizeof(PSESSION_HDR)-4);

     ps->prt_crc=crc32(0,bufx,24);

     memcpy(bufx,ps,sizeof(PSESSION_HDR));

     //printf("rsp_size=%d\n",sizeof(PSESSION_RGT_RSP));
     rsp=malloc(sizeof(PSESSION_RGT_RSP));
     rsp->result=rp;
     
     //printf("degree_ip=%s\n",degree_ip);
     inet_aton(degree_ip,&ip_address);
     memcpy(&rsp->ip,&ip_address.s_addr,sizeof(struct in_addr));

     rsp->port = u_port;
     rsp->time = handshake_time;
 
     rsp->result = htonl(rsp->result);
     rsp->ip     = htonl(rsp->ip);
     rsp->port   = htons(rsp->port);
     rsp->time   = htons(rsp->time);

     memcpy(bufx+28,rsp,12);

     crcnum1=crc32(0,bufx,40);
     //printf("rsp_crcnum = %x\n",crcnum1);

     memcpy(bufx+40,&crcnum1,4);

     ps->version      = htons(ps->version);
     ps->serial       = htonl(ps->serial);
     ps->param_length = htonl(ps->param_length);
     ps->prt_crc      = htonl(ps->prt_crc);

     memcpy(bufx,ps,sizeof(PSESSION_HDR));

     send(new_fd,bufx,44,0);
     //printf("send response ok!\n"); 

     if (rp==0) u_port++;
  
     //if (u_port==5821) u_port=5801;
     if (u_port==(degree_port+1+num_process)) u_port=degree_port+1;

     shutdown(new_fd,SHUT_WR);
     close(new_fd);

   }

   //线程任务结束
   thread_param->flag = 0;//设置线程占用标志为"空闲"
   goto wait_unlock;

   pthread_exit(NULL);

    /* 处理每个新连接上的数据收发结束 */
}

int read_user_file(const char * conf_filename)
{
        IniItemInfo *items;
        int nItemCount;
        int i,j,result,lisnum,id,mode;
        char *str=NULL, *tmp=NULL;
        char tmpstr[20];

        if ((result=iniLoadItems(conf_filename, &items, &nItemCount)) != 0)
        {
                printf("file: "__FILE__", line: %d, " \
                        "load from ini file \"%s\" fail, " \
                        "error code: %d\n", \
                        __LINE__, conf_filename, result);
                return result;
        }
        printf("nItemCount-----%d\n",nItemCount);

        lisnum = iniGetIntValue("LIST_NUM", items, nItemCount,1);
        printf("user number------%d\n",lisnum);

        j=0;
        for (i=0;i<lisnum;i++)
        {
          sprintf(tmpstr,"INFO%d",i+1);
       //   printf("%s\n",tmpstr);
          str = NULL;
          tmp = NULL;
          str = iniGetStrValue(tmpstr, items, nItemCount);
          if (str == NULL)
          {       
             iniFreeItems(items);
             printf("file: "__FILE__", line: %d, " \
		"conf file \"%s\" must have item " \
		"\"end_ip_net1\"!", \
                    __LINE__, conf_filename);
             exit(-1);
           }
	 //  printf("str=%s\n",str);
           rgst_queue[i].flag=0;
        
	   tmp=strtok(str,"+");
           if (tmp) printf("tmp=%s\n",tmp);
           id=atoi(tmp);

           tmp=strtok(NULL,"+");
           if (tmp) printf("tmp=%s\n",tmp);
           tmp=strtok(NULL,"+");
           if (tmp) printf("tmp=%s\n",tmp);
           tmp=strtok(NULL,"+");
           if (tmp) printf("tmp=%s\n",tmp);
           strcpy(tmpstr,tmp);
           	   
           tmp=strtok(NULL,";");
           if (tmp) printf("tmp=%s\n",tmp);
           mode=atoi(tmp);

           //if (atoi(tmp)==0) break;
 
           if (mode==3) 
           {
	     strcpy(rgst_queue[i].user_name,tmpstr);
             rgst_queue[i].user_id=id;
             j++;

           }

         }

        NO= j;    
        iniFreeItems(items);

        return 0;
}

int read_ini_file(const char * path, const char * filename)
{
        IniItemInfo *items;
        int nItemCount;
        int result;
        char * str=NULL;
        char conf_filename[80];

        strcpy(conf_filename,"");
        sprintf(conf_filename,"%s/%s",path,filename);

        if ((result=iniLoadItems(conf_filename, &items, &nItemCount)) != 0)
        {
                printf("file: "__FILE__", line: %d, " \
                        "load from ini file \"%s\" fail, " \
                        "error code: %d\n", \
                        __LINE__, conf_filename, result);
                return result;
        }
        printf("nItemCount-----%d\n",nItemCount);

        lisnum = iniGetIntValue("num_connect", items, nItemCount,1);
        printf("num_connect------%d\n",lisnum);

        num_process = iniGetIntValue("num_process", items, nItemCount,1);
        printf("num_process------%d\n",num_process);
        num_childs=num_process;
 
        num_pthread = iniGetIntValue("num_pthread", items, nItemCount,1);
        printf("num_pthread------%d\n",num_pthread);


        str = iniGetStrValue("user_filename", items, nItemCount);
        if (str == NULL)
        {       
             iniFreeItems(items);
             printf("file: "__FILE__", line: %d, " \
		"conf file \"%s\" must have item " \
		"\"end_ip_net1\"!", \
                    __LINE__, conf_filename);
             exit(-1);
        }       
        strcpy(user_file,str);
        printf("user_file------%s\n",user_file);

        str = iniGetStrValue("ip_degree", items, nItemCount);
        if (str == NULL)
        {       
             iniFreeItems(items);
             printf("file: "__FILE__", line: %d, " \
		"conf file \"%s\" must have item " \
		"\"end_ip_net1\"!", \
                    __LINE__, conf_filename);
             exit(-1);
        }       
        strcpy(degree_ip,str);
        printf("degree_ip------%s\n",degree_ip);

        str=NULL;
        str = iniGetStrValue("ip_eAudit", items, nItemCount);
        if (str == NULL)
        {       
             iniFreeItems(items);
             printf("file: "__FILE__", line: %d, " \
		"conf file \"%s\" must have item " \
                    "\"begin_ip_net1\"!", \
                    __LINE__, conf_filename);
             exit(-1); 
        }      
        memcpy(eAudit_ip,str,strlen(str));
        printf("eAudit_ip------%s\n",eAudit_ip);
 
        degree_port = iniGetIntValue("port_degree", items, nItemCount,1);
        printf("degree_port------%d\n",degree_port);
        u_port=degree_port+1;
 
        eAudit_port = iniGetIntValue("port_eAudit", items, nItemCount,1);
        printf("eAudit_port------%d\n",eAudit_port);

        handshake_time = iniGetIntValue("time_handshake", items, nItemCount,1);
        printf("handshake_time------%d\n",handshake_time);
 
        check_time = iniGetIntValue("time_check", items, nItemCount,1);
        printf("check_time------%d\n",check_time);

        iniFreeItems(items);

        return 0;
}

int main(int argc, char **argv)
{
    int listener, new_fd, kdpfd, nfds, n, curfds,i=0,j,rc;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    struct epoll_event ev;
    struct epoll_event events[MAXEPOLLSIZE];
    EPOLL_ADDR connect_addr[MAXEPOLLSIZE];
    struct rlimit rt;
    char s[80];

    FILE * fp;
    //char tmp[32];
    //int ret,fd;

    unsigned int optval;
    struct linger optval1;

    pid_t pid; 
    key_t key;
    int shm_id;
    char* name = "/dev/shm/myshm2";

  sigset_t intmask;
  sigemptyset(&intmask); /* 将信号集合设置为空 */
  sigaddset(&intmask,SIGINT); /* 加入中断 Ctrl+C 信号*/

  sigprocmask(SIG_BLOCK,&intmask,NULL); //屏蔽Ctrl+C


    if (access(name,F_OK)!=0)
    {
        printf("File: %s is not exist! creating ...\n",name);

        if((fp=fopen(name,"w"))==NULL)//打开文件 没有就创建
        {
          printf("can not creat myshm2 file!\n");
          exit(-1);
        }

        fclose(fp);
    }
    
    key = ftok(name,0);
    if (key==-1)
	perror("ftok error");

    shm_id=shmget(key,409600,IPC_CREAT);	
    if(shm_id==-1)
    {
	perror("shmget error");
	exit(-1);
    }

    rgst_queue=(REGIST_QUEUE *)shmat(shm_id,NULL,0);

    getcwd(s,sizeof(s));

    //i=read_ini_file("/home/yz/degree","degree.conf");
    i=read_ini_file(s,"degree.conf");
    if (i)
    {
	printf("read_ini_file :degree.conf -----error code %d!\n",i);
	exit(-1);
    }

    if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
      perror("udp_socket");
      exit(errno);
    } else
      printf("create udp_socket for regit to eAudit\n\r");

    printf("eAudit_ip %s\n",eAudit_ip);
    /* 设置对方eAudit服务器 地址和端口信息 */
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(eAudit_port);
    s_addr.sin_addr.s_addr = inet_addr(eAudit_ip);



/*
    fp=fopen("user.conf","r"); 
    if (fp==NULL) printf("can not open user.conf !\n");

    i=0;
    while (fgets(s,80,fp)!=NULL)
    {
      rgst_queue[i].flag=0;
      sscanf(s,"%s %s",tmp,rgst_queue[i].user_name);

      if (atoi(tmp)==0) break;

      rgst_queue[i].user_id=atoi(tmp);
      i++;
    }
    fclose(fp);

    NO=i;
*/
    if ((i=read_user_file(user_file))!=0) 
    {
	printf("can not open file %s\n",user_file);
        exit(-1);
    }
    qsort(rgst_queue,NO,sizeof(rgst_queue[0]),cmp);

    for (i=0;i<NO;i++)
      printf("id=%d      name=%s\n",rgst_queue[i].user_id,rgst_queue[i].user_name);

    printf("NO=%d\n",NO);

/*
    fd=open("MEM",O_CREAT|O_RDWR|O_TRUNC,00777);
    //write(fd,rgst_queue,sizeof(rgst_queue[0])*NO);

    rgst_queue  = (REGIST_QUEUE *) mmap( NULL,sizeof(REGIST_QUEUE)*NO,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0 );
    if (rgst_queue==MAP_FAILED)
    {
       printf("mmap wrong");
       exit(0);
    }
  //  close(fd);
*/


    //线程池初始化
    rc = init_thread_pool();
    if (0 != rc) exit(-1);

//    int   Timer   = 2;   
//    signal(SIGALRM,check_online);   
//    alarm(Timer);   

    signal(SIGALRM,   sigroutine);

    struct itimerval value;

    value.it_value.tv_sec = check_time;
    value.it_value.tv_usec = 0;

    value.it_interval.tv_sec = check_time;
    value.it_interval.tv_usec = 0;

    setitimer(ITIMER_REAL, &value, 0);


    /* 设置每个进程允许打开的最大文件数 */
    rt.rlim_max = rt.rlim_cur = MAXEPOLLSIZE;
    if (setrlimit(RLIMIT_NOFILE, &rt) == -1) {
        perror("setrlimit");
        exit(1);
    }
    else printf("设置系统资源参数成功！\n");

    for (i=0;i<num_process;i++)
         if ((pid=fork())==0) {
            udp_process(5801+i);
    }

    /* 开启 socket 监听 */
    if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else
        printf("socket 创建成功！\n");

    setnonblocking(listener);

    //设置SO_REUSEADDR选项(服务器快速重起)
    optval = 0x1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &optval, 4);

    //设置SO_LINGER选项(防范CLOSE_WAIT挂住所有套接字)
    optval1.l_onoff = 1;
    optval1.l_linger = 60;
    setsockopt(listener, SOL_SOCKET, SO_LINGER, &optval1, sizeof(struct linger));

    printf("degree_ip %s\n",degree_ip);
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(degree_port);
    inet_pton(AF_INET, degree_ip, &(my_addr.sin_addr)); 
    //my_addr.sin_addr.s_addr = inet_addr(degree_ip);


    if (bind(listener, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind");
        exit(1);
    } else
        printf("IP 地址和端口绑定成功\n");

    if (listen(listener, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else
        printf("开启服务成功！\n");

    /* 创建 epoll 句柄，把监听 socket 加入到 epoll 集合里 */
    kdpfd = epoll_create(MAXEPOLLSIZE);
    len = sizeof(struct sockaddr_in);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listener;
    if (epoll_ctl(kdpfd, EPOLL_CTL_ADD, listener, &ev) < 0) {
        fprintf(stderr, "epoll set insertion error: fd=%d\n", listener);
        return -1;
    } else
        printf("监听 socket 加入 epoll 成功！\n");
    curfds = 1;
    
    while (1) {
        /* 等待有事件发生 */
        //nfds = epoll_wait(kdpfd, events, curfd, -1);
        nfds = epoll_wait(kdpfd, events, MAXEPOLLSIZE, -1);
        if (nfds == -1) {
            //perror("epoll_wait");
            //break;
            continue;
        }
        /* 处理所有事件 */
        for (n = 0; n < nfds; ++n) 
	{
            if (events[n].data.fd == listener) 
	    {
                new_fd = accept(listener, (struct sockaddr *) &their_addr,&len);

                if (new_fd < 0) 
		{
                    perror("accept");
                    continue;
                }
		else 
		{
                    DEBUG("有连接来自于： %s:%d， 分配的 socket 为:%d\n",
                            inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port), new_fd);
     		    memcpy(connect_addr[n].addr,inet_ntoa(their_addr.sin_addr),16);
                }   
                setnonblocking(new_fd);
                ev.events = EPOLLIN | EPOLLET; 
                ev.data.fd = new_fd; 
                if (epoll_ctl(kdpfd, EPOLL_CTL_ADD, new_fd, &ev) < 0) 
               	{ 
			fprintf(stderr, "把 socket '%d' 加入 epoll  失败！%s\n", new_fd, strerror(errno));
                	return -1;
                } 
                curfds++;
            } 
            else 
	    {
//	       if (num_childs>0){
//        	 if ((pid=fork())==0) {
//	            udp_process(5801+num_process-num_childs);
//	         }
//	         else
//	         {
//	           num_childs--;
//	         }
//	       }

	        //查询空闲线程池
	        for(j = 0; j < THREAD_MAX; j++) 
		{
	          if (0 == s_thread_para[j].flag) break;
	        }
	        if (j >= THREAD_MAX) 
		{
	          fprintf(stderr, "线程池已满, 连接将被放弃\r\n");
	          shutdown(events[n].data.fd, SHUT_RDWR);
	          close(events[n].data.fd);
	          continue;
	        }
	        //复制有关参数
	        s_thread_para[j].flag = 1;                                //设置活动标志为"活动"
	        s_thread_para[j].fd =events[n].data.fd ;                  //客户端连接描述符
                memcpy(s_thread_para[j].addr,connect_addr[n].addr,16);    //连接地址
	        s_thread_para[j].index = j;                               //服务索引
	        //线程解锁
	        pthread_mutex_unlock(s_mutex + j);

            }
          }
       }
    close(listener); 

    if (shmdt(rgst_queue) == -1)
	perror(" detach error ");

    return 0;
}

