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
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/sem.h>
#include <error.h>

#include "ini_file_reader.h"

#include "label.h"

#define MAXBUF 700
#define MAXEPOLLSIZE 10000
#define SEMKEY 0x1680
#define IPCKEY 0   //0x111
#define ERR 0
#define DAT 1
#define NON 30000
//#define NON 8000

union semun{
  int val;
  struct semid_ds *buf;
  unsigned short int *array;
};

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
  unsigned char mac[6];
  char ip[16];
  char os_name[40];
  char host_name[40];
  unsigned char tocken;
  char reg_detail[40];
  char real_ip[16];
  struct sockaddr_in cli_addr;
}REGIST_QUEUE;

typedef struct tag_COMM_FLAG
{
  int logout_flag;
  char addr[16];
  int udp_sock;
  struct sockaddr_in s_addr;
}COMM_FLAG;

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

typedef struct tag_PORT
{ 
  int count;
  char addr[16];
  int port;
}PORT;


struct sembuf lock_it;   
union semun options;   
int sem_id;


COMM_FLAG * p_map;

static REGIST_QUEUE * rgst_queue;

static int w_flag=0;

char degree_ip[16], eAudit_ip[16];
char user_file[80];

int degree_port, eAudit_port;
int is2h1=1,num_eAudit=1;  //authen_port;
int def_DEBUG=0,NO,exit_flag=0,tongzi=0; 
int check_time,handshake_time,THREAD_MAX=5;
int lisnum=1000, num_childs=20, u_port=5801,num_process=20,num_pthread=400;
//int exit_5799=0;

int setnonblocking(int sockfd);
void handle_message(THREAD_PARAM * thread_param);
void handle_self(int new_fd,const char *addr,pid_t parent);
int in_usr_table(const int usrid, const char * usrname);
void check_online();
void sigroutine(int signo);
int read_ini_file(const char * path, const char * filename);
int read_user_file(const char * conf_filename);
int read_eAudit_db_conf(const char * path, const char * filename);
void lock_sem();
void unlock_sem();
void resend_eAudit(struct sockaddr_in s_addr);
void write_harddisk();
void DEBUG(const char *fmt, ...);
void tell_eAudit_user_quit (int p,char * userid, int udp_sock,  struct sockaddr_in s_addr);
static int Socket_Commulication(char *serv_ip,unsigned short serv_port,int cmd);
static int socket_write(int sock_fd,void *buffer,int length); 

//extern int   BinarySearch(const REGIST_QUEUE * a, int e,int left,int right);
extern int conn_db(const char *host, const int port, const char *database,const char *user, const char *password);
extern int close_db(void);
extern int write_log_info(char * str);

extern int  udp_process(int port);
extern unsigned long crc32( unsigned long crc, const unsigned char *buf, unsigned int len );

//线程池参数
static THREAD_PARAM *s_thread_para;    //[THREAD_MAX];  //线程参数
static pthread_t *s_tid;               //[THREAD_MAX];             //线程ID
pthread_mutex_t *s_mutex;              //[THREAD_MAX];            //线程锁

//私有函数
static int init_thread_pool(void);

static int init_thread_pool(void)
{
  int i, rc;

  //初始化线程池参数
  s_thread_para =(THREAD_PARAM * ) malloc( sizeof(THREAD_PARAM)*THREAD_MAX );
  s_tid =(pthread_t *) malloc( sizeof(pthread_t)*THREAD_MAX );
  s_mutex =(pthread_mutex_t *) malloc( sizeof(pthread_mutex_t)*THREAD_MAX );

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


int write_time_dat()
{
  int fd_time = open("/eAudit/info/time.dat", O_WRONLY | O_CREAT);
  if (fd_time<0)
  {
	perror("open fd_time error:");
  }

  time_t t=time(NULL);
  int nLen = write(fd_time, &t, 4);
  if (nLen<4)
  {
	perror("write error:");
  }

  nLen=write(fd_time,&NO,4);
  if (nLen<4)
  {
	perror("write error:");
  }

  close(fd_time);

  return 0;
}

void write_harddisk()
{
  if (w_flag)
  {  
	if (-1 == msync(rgst_queue,sizeof(REGIST_QUEUE)*NON,MS_ASYNC))
	{
	  perror("msync");
	}
	write_time_dat();

	check_online();

	w_flag=0;
  }
}

void sigroutine(int signo)
{
  switch (signo) {
case SIGALRM:
  w_flag=1;        
  signal(SIGALRM, sigroutine);
  break;
case SIGTERM:
  printf("receve signal ----SIGTERM  \n");
  if (-1 == msync(rgst_queue,sizeof(REGIST_QUEUE)*NON,MS_ASYNC))
  {
	perror("msync");
  }
  if (-1 == munmap(rgst_queue,sizeof(REGIST_QUEUE)*NON))
  {
	perror("munmap");
  }
  exit_flag=1;
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
  int i,result=-1;

  i = usrid;
  //printf("serch i=%d\n",i);

  if (( rgst_queue[i].user_id == i ) && (rgst_queue[i].flag == 0) )
  {
	if (!strcmp(rgst_queue[i].user_name,usrname))
	{
	  lock_sem();
	  rgst_queue[i].flag=1;
	  unlock_sem();

	  DEBUG("regist ok! userid ----%d  username -----%s  i=%d\n",rgst_queue[i].user_id, rgst_queue[i].user_name,i);
	  result=i;
	}
  }
  return result;
}


void check_online()
{
  int i,j;
  int people;
  char msg_record[80],user_id[32];

  people=0;
  for (i=0;i<NON;i++)
	if  (rgst_queue[i].user_id == i) 
	{
	  if (1 == rgst_queue[i].flag)  
	  {
		people++;
		rgst_queue[i].count+=1;
		if (rgst_queue[i].count>3) 
		{
		  lock_sem();

		  rgst_queue[i].flag=0;
		  rgst_queue[i].count=0;

		  unlock_sem();

		  people--;

		  sprintf(msg_record,"用户名= %s  id = %d 已注销!\n",rgst_queue[i].user_name,rgst_queue[i].user_id);
		 // writelog(DAT,msg_record);

		  sprintf(user_id,"%d",rgst_queue[i].user_id);

		  for (j=0;j<num_eAudit;j++)
		  {
			DEBUG("[check_online] %s --- logout=%d\n",p_map[j].addr,p_map[j].logout_flag);

			if ( !is2h1 && !strncmp(p_map[j].addr,degree_ip,16)) continue;

			if (0 == p_map[j].logout_flag)
			  tell_eAudit_user_quit(j,user_id,p_map[j].udp_sock,p_map[j].s_addr);
		  }

		  write_log_info(msg_record);
		}
	  }
	} 
	DEBUG("people=%d\n",people);
}

void tell_eAudit_user_quit(int p,char * user_id,int udp_sock,  struct sockaddr_in s_addr)
{
  int j,k,l;

  int lens,len,logout,i_recv;
  unsigned char buf_eA[80], bufx[80];
  char tmp[80],buf[20];

  PSRTA_HDR_ID pst;
  unsigned long parity,tail_crc;
  unsigned long *lp;


  lens = strlen(user_id);

  j=0;

  do
  {
	logout=0;
	pst=(PSRTA_HDR *)malloc(sizeof(PSRTA_HDR));

	memcpy(pst->flag,"SRTA",4);
	pst->version      = 0x0100;
	pst->opt_code     = 0x02;
	pst->param_length = 1+lens;

	memset(buf_eA,0,80);
	memcpy(buf_eA, pst, sizeof(PSRTA_HDR));
	memcpy(buf_eA+sizeof(PSRTA_HDR), &lens, 1);
	memcpy(buf_eA+sizeof(PSRTA_HDR)+1,user_id,lens);

	parity = crc32(0,buf_eA,sizeof(PSRTA_HDR)+lens+1);

	memcpy(buf_eA+sizeof(PSRTA_HDR)+lens+1,&parity,4);
	len = sizeof(PSRTA_HDR)+1+lens+4;
	l=0;k=0;
	while (l<5)
	{
	  k=sendto(udp_sock, buf_eA, len, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
	  if (k<=0) l++;
	  else break;
	}

	if (l>=5) break;

	lens = sizeof(s_addr);

	//logout_flag = p_map[p].logout_flag;

	if (1 == p_map[p].logout_flag ) break;
	//printf("AAAAAAAAAAAAAAAAAAAAAAAAAA\n");

	i_recv=recvfrom(udp_sock, tmp, 128, 0, (struct sockaddr *)&s_addr, (socklen_t * )&lens);

	if (i_recv>4)
	{
	  //printf("i_recv ------------ %d\n",i_recv);
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

	  // printf("parity: %u      tail_crc: %u\n",parity,tail_crc); 
	  if ( parity == tail_crc)
	  {
		bzero(bufx,50);
		memcpy(bufx,(tmp+sizeof(PSRTA_HDR)),4);
		lp=(unsigned long *)&bufx;
		parity=*lp;
		// printf("return : %u\n",parity);
		if (0 == parity)
		{ 
		  len=tmp[sizeof(PSRTA_HDR)+4]; 

		  bzero(buf,0);
		  memcpy(buf,tmp+sizeof(PSRTA_HDR)+4+1,len);
		  buf[len]='\0';

		  if (atoi(buf) == atoi(user_id))
		  { 
			logout=1;
			DEBUG("communicat to eAudit logout ok!------%s",p_map[j].addr);
		  }
		}
	  }
	}
	j++;
	if (j>=3) break; 

  } while (logout == 0);

  free(pst);
}


int tcp_5799(pid_t parent)
{
  int sockfd, new_fd;
  socklen_t len;
  unsigned int optval;
  struct linger optval1;

  struct sockaddr_in my_addr, their_addr;
  unsigned int myport, listen_num;
  char addr[16];

  if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
	perror("socket");
	exit(1);
  }
  else 
	printf("new socket for 5799 created\n");

  //设置SO_REUSEADDR选项(服务器快速重起)
  optval = 0x1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, 4);

  //设置SO_LINGER选项(防范CLOSE_WAIT挂住所有套接字)
  optval1.l_onoff = 1;
  optval1.l_linger = 6;    
  setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &optval1, sizeof(struct linger));

  myport=degree_port-1;

  bzero(&my_addr, sizeof(my_addr));
  my_addr.sin_family = PF_INET;
  my_addr.sin_port = htons(myport);   //5799

  my_addr.sin_addr.s_addr = inet_addr(degree_ip);

  if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1) {
	perror("bind");
	exit(1);
  }
  else 
	printf("5799 binded sucess\n");


  if (listen(sockfd, listen_num) == -1) {
	perror("listen");
	exit(1);
  }
  else 
	DEBUG("begin listen 5799\n");

  while(1) {
	len = sizeof(struct sockaddr);
	if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &len)) == -1) {
	  perror("accept");
	  exit(errno);
	}
	else
	{
	  bzero(addr,16);
	  memcpy(addr,inet_ntoa(their_addr.sin_addr),16);

	  handle_self(new_fd,addr,parent);
	  close(new_fd);
	}
	//if (1==exit_5799) break;
  }

  close(sockfd);
  return 0;
}

void handle_self(int new_fd,const char *addr,pid_t parent)
{
  unsigned char buf[MAXBUF],bufx[256];

  int i,len;
  unsigned long crcnum1,crcnum2, tail_crc;
  PSESSION_HDR_ID ps;
  unsigned long * lp;


  /* 开始处理每个新连接上的数据收发 */
  bzero(buf, MAXBUF);
  /* 接收客户端的消息 */
  len = recv(new_fd, buf, MAXBUF, 0);
  if (len > 0)
	DEBUG
	("%d接收消息成功:'%s'，共%d个字节的数据\n", new_fd, buf, len);
  else {
	if (len < 0)
	  DEBUG
	  ("SELF: 消息接收失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
	close(new_fd);
	return ;
  }

  //ps=malloc(sizeof(PSESSION_HDR));

  ps=(PSESSION_HDR_ID)buf;

  if ((ps->opt_code == 0x84)||(ps->opt_code == 0x85))
	printf("this is my send message %x\n",ps->opt_code);

  ps->version      =  ntohs(ps->version);
  ps->serial       =  ntohl(ps->serial);
  ps->param_length =  ntohl(ps->param_length);
  ps->prt_crc      =  ntohl(ps->prt_crc);


  // printf("flag=%s  version=%d  serial=%d  length=%d opt_code=%x reserv=%x \n",ps->flag, ps->version,ps->serial,ps->param_length,ps->opt_code,ps->reserved);


  // printf("sizeof=%d\n",sizeof(PSESSION_HDR));

  bzero(bufx, 50);
  memcpy(bufx,(char *)ps,sizeof(PSESSION_HDR)-4);

  crcnum1=crc32(0,bufx,sizeof(PSESSION_HDR)-4);

  //printf("crcnum1=%u,  prt_crc=%u\n",crcnum1,ps->prt_crc);

  // printf("ps->parmlength=%d\n",ps->param_length);

  bzero(bufx, 256);
  memcpy(bufx,(char *)ps,sizeof(PSESSION_HDR));

  memcpy((bufx+sizeof(PSESSION_HDR)),(buf+sizeof(PSESSION_HDR)),ps->param_length);

  crcnum2=crc32(0,bufx,sizeof(PSESSION_HDR)+ps->param_length);

  bzero(bufx,4);
  memcpy(bufx,(buf+len-4),4);
  lp=(unsigned long *)&bufx;
  tail_crc=*lp;   

  //printf("crcnum2=%u,  tail_crc=%u\n",crcnum2,tail_crc);

  if ( crcnum1 == ps->prt_crc  && crcnum2 == tail_crc )
  {
	if  ( !strncmp((char *)ps->flag,"SRTA",4) )
	{  
	  if ( (ps->opt_code == 0x04) && (ps->version == 0x0100) )
	  {
		printf("recev online tongzi------------------------------\n");
		ps->version=ntohs(ps->version);
		ps->serial=ntohl(ps->serial);
		ps->param_length=4;
		ps->opt_code=0x84;

		bzero(bufx, 50);
		memcpy(bufx,ps,sizeof(PSESSION_HDR)-4);

		crcnum1=crc32(0,bufx,sizeof(PSESSION_HDR)-4);

		ps->prt_crc=crcnum1;

		bzero(bufx, 256);
		memcpy(bufx,ps,sizeof(PSESSION_HDR));

		bzero(buf,10);
		memcpy(bufx+sizeof(PSESSION_HDR),buf,ps->param_length);

		crcnum2=crc32(0,bufx,sizeof(PSESSION_HDR)+ps->param_length);

		memcpy(bufx+sizeof(PSESSION_HDR)+ps->param_length,&crcnum2,4);

		send(new_fd,bufx,sizeof(PSESSION_HDR)+ps->param_length+4,0);

		for (i=0;i<num_eAudit;i++) 
		{
		  if ( is2h1 && !strncmp(p_map[i].addr,addr,16) && !strncmp(addr,degree_ip,16) )
		  {
			tongzi=1;
			p_map[i].logout_flag=0;

			DEBUG("55555555555------------logout_flag=%d      %s\n",p_map[i].logout_flag, p_map[i].addr );

			read_user_file(user_file);		
		  }

		  if (!is2h1 && !strncmp(p_map[i].addr,addr,16) && strncmp(addr,degree_ip,16) )
		  {
			tongzi=1;
			p_map[i].logout_flag=0;

			DEBUG("11111111111------------logout_flag=%d      %s\n",p_map[i].logout_flag, p_map[i].addr );

			read_user_file(user_file);		
		  }
		}

	  }
	  else
	  {
		if ( (ps->opt_code == 0x05) && (ps->version == 0x0100) )
		{
		  DEBUG("recev outline tongzi----------------------%s \n",addr);
		  ps->version=ntohs(ps->version);
		  ps->serial=ntohl(ps->serial);
		  ps->param_length=8;
		  ps->opt_code=0x85;

		  bzero(bufx, 50);
		  memcpy(bufx,ps,sizeof(PSESSION_HDR)-4);

		  crcnum1=crc32(0,bufx,sizeof(PSESSION_HDR)-4);

		  ps->prt_crc=crcnum1;

		  bzero(bufx, 256);
		  memcpy(bufx,ps,sizeof(PSESSION_HDR));

		  bzero(buf,10);

		  memcpy(buf+4,&parent,4);

		  memcpy(bufx+sizeof(PSESSION_HDR),buf,ps->param_length);

		  crcnum2=crc32(0,bufx,sizeof(PSESSION_HDR)+ps->param_length);

		  memcpy(bufx+sizeof(PSESSION_HDR)+ps->param_length,&crcnum2,4);

		  send(new_fd,bufx,sizeof(PSESSION_HDR)+ps->param_length+4,0);

		  for (i=0;i<num_eAudit;i++) 
		  {
			if ( !strncmp(p_map[i].addr,addr,16) )
			{
			  p_map[i].logout_flag=1;

			  DEBUG("2222222222222------------logout_flag=%d      %s\n",p_map[i].logout_flag,p_map[i].addr);
			}
		  }
		  //if (!strncmp(addr,degree_ip,16))
		  //  exit_5799=1;

		}
	  } 
	}
  }
}

/*
handle_message - 处理每个 socket 上的消息收发
*/
void handle_message(THREAD_PARAM * thread_param)
{
  int new_fd,k=-1,l,kk,p;
  char addr[16];
  struct in_addr ip_address;
  unsigned char buf[MAXBUF],bufx[256];
  char tmp[MAXBUF],buf_id[20];
  char buff[MAXBUF],userid[10],username[30];
  char msg_record[1500];

  int len,pool_index;
  unsigned long crcnum1,crcnum2, tail_crc,parity;
  PSESSION_HDR_ID ps;
  PSESSION_RGT_RSP * rsp;
  unsigned int rp;
  int offset,length ,i_recv,regist=0;
  unsigned long * lp;

  PSRTA_HDR_ID pst;

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
	  DEBUG("消息接收失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
	close(new_fd);
	return ;
  }

  //ps=malloc(sizeof(PSESSION_HDR));

  ps=(PSESSION_HDR_ID)buf;

  if ((ps->opt_code==0x84)||(ps->opt_code==0x85))
	printf("this is my send message %x\n",ps->opt_code);

  ps->version      =  ntohs(ps->version);
  ps->serial       =  ntohl(ps->serial);
  ps->param_length =  ntohl(ps->param_length);
  ps->prt_crc      =  ntohl(ps->prt_crc);


  // printf("flag=%s  version=%d  serial=%d  length=%d opt_code=%x reserv=%x \n",ps->flag, ps->version,ps->serial,ps->param_length,ps->opt_code,ps->reserved);


  // printf("sizeof=%d\n",sizeof(PSESSION_HDR));

  bzero(bufx, 50);
  memcpy(bufx,(char *)ps,sizeof(PSESSION_HDR)-4);

  crcnum1=crc32(0,bufx,sizeof(PSESSION_HDR)-4);

  //printf("crcnum1=%u,  prt_crc=%u\n",crcnum1,ps->prt_crc);

  // printf("ps->parmlength=%d\n",ps->param_length);

  bzero(bufx, 256);
  memcpy(bufx,(char *)ps,sizeof(PSESSION_HDR));

  memcpy((bufx+sizeof(PSESSION_HDR)),(buf+sizeof(PSESSION_HDR)),ps->param_length);

  crcnum2=crc32(0,bufx,sizeof(PSESSION_HDR)+ps->param_length);

  bzero(bufx,4);
  memcpy(bufx,(buf+len-4),4);
  lp=(unsigned long *)&bufx;
  tail_crc=*lp;   

  //printf("crcnum2=%u,  tail_crc=%u\n",crcnum2,tail_crc);

  if ( crcnum1==ps->prt_crc  && crcnum2==tail_crc )
  {
	if ( !strncmp((char *)ps->flag,"SNRP",4) && (ps->opt_code==0x01) && (ps->version==0x0100) )
	{

	  // printf("recev a correct regist message of SAIL\n");

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

	  //sprintf(msg_record,"用户id = %s 登录成功!  用户信息如下:\n",bufx);
	  memcpy(userid,bufx,length);
	  userid[length]='\0';

	  offset+=length;

	  length=buff[offset];
	  offset+=1;

	  memcpy(bufx,(buff+offset),length);
	  bufx[length]='\0';
	  sprintf(tmp," 用户名 = %s  ",bufx);
	  memcpy(username,bufx,length);
	  username[length]='\0';
	  offset+=length;
	  
	  sprintf(msg_record,"用户名= %s  id = %s 登录成功! 用户信息如下:",username,userid);

	  if ((k=in_usr_table(atoi(userid),username))>=0) 
	  {
		DEBUG("k=%d\n",k); 
		length=6;
		memcpy(bufx,(buff+offset),length);
		bufx[6]='\0';
		sprintf(tmp,"MAC = %02X-%02X-%02X-%02X-%02X-%02X  ",bufx[0],bufx[1],bufx[2],bufx[3],bufx[4],bufx[5]);
		offset+=length;
		strcat(msg_record,tmp);

		memcpy(rgst_queue[k].mac,bufx,6);

		length=buff[offset];
		offset+=1;

		memcpy(bufx,(buff+offset),length);
		bufx[length]='\0';
		sprintf(tmp,"用户本机IP地址 = %s  ",bufx);
		offset+=length;
		strcat(msg_record,tmp);

		memcpy(rgst_queue[k].ip,bufx,length);

		length=buff[offset];
		offset+=1;

		memcpy(bufx,(buff+offset),length);
		bufx[length]='\0';
		sprintf(tmp,"操作系统 = %s  ",bufx);
		offset+=length;
		strcat(msg_record,tmp);

		memcpy(rgst_queue[k].os_name,bufx,length);

		length=buff[offset];
		offset+=1;

		memcpy(bufx,(buff+offset),length);
		bufx[length]='\0';
		sprintf(tmp," 计算机名 = %s  ",bufx);
		offset+=length;
		strcat(msg_record,tmp);

		memcpy(rgst_queue[k].host_name,bufx,length);

		sprintf(tmp,"令牌锁定标志 = %d  ",buff[offset]);
		offset+=1;
		strcat(msg_record,tmp);

		rgst_queue[k].tocken=buff[offset];

		length=buff[offset];
		offset+=1;

		memcpy(bufx,(buff+offset),length);
		bufx[length]='\0';
		sprintf(tmp,"登录事由 = %s  ",bufx);
		offset+=length;
		strcat(msg_record,tmp);

		memcpy(rgst_queue[k].reg_detail,bufx,length);

		sprintf(tmp,"真实IP = %s  ",addr);
		strcat(msg_record,tmp);

		strcpy(rgst_queue[k].real_ip,addr);

		rp=0;
		DEBUG("find user   ########################## %s   %s on pid:%d\n",userid,username, getpid());

		//writelog(msg_record);

		for (p=0;p<num_eAudit;p++)
		{
		  DEBUG("[hand_message] %s --- logout=%d\n",p_map[p].addr,p_map[p].logout_flag);

		  if ( !is2h1 && !strncmp(p_map[p].addr,degree_ip,16) ) continue;

		  if ( 0 == p_map[p].logout_flag )
		  {
			DEBUG("[handle_message]%d----%s-----logout_flag=%d\n",p,p_map[p].addr,p_map[p].logout_flag);

			pst=malloc(sizeof(PSRTA_HDR));

			do
			{
			  memcpy(pst->flag,"SRTA",4);
			  pst->version      = 0x0100;
			  pst->opt_code     = 0x01;
			  pst->param_length = ps->param_length+strlen(addr)+1;

			  // printf("param_length=============%d\n",ps->param_length+strlen(addr)+1);

			  memset(bufx,0,256);
			  memcpy(bufx,pst,sizeof(PSRTA_HDR));

			  memcpy(bufx+sizeof(PSRTA_HDR),buff,ps->param_length);

			  length=strlen(addr);
			  memcpy(bufx+sizeof(PSRTA_HDR)+ps->param_length,&length,1);
			  memcpy(bufx+sizeof(PSRTA_HDR)+ps->param_length+1,addr,length);

			  parity=crc32(0,bufx,sizeof(PSRTA_HDR)+ps->param_length+1+length);

			  //printf("jiaoyan_leng--------%d    parity-------%u  \n",sizeof(PSRTA_HDR)+ps->param_length+strlen(addr)+1,parity);

			  memcpy(bufx+sizeof(PSRTA_HDR)+ps->param_length+1+length,&parity,4);
			  len=sizeof(PSRTA_HDR)+ps->param_length+1+length+4;

			  l=0;kk=0;
			  while (l<5)
			  {
				kk=sendto(p_map[p].udp_sock, bufx, len, 0, (struct sockaddr *) &(p_map[p].s_addr), sizeof(p_map[p].s_addr));    
				if (kk<=0) l++;
				else break;
			  }
			  //printf("l==%d   kk=%d  while out\n",l,kk); 
			  if (l>=5)  break;

			  regist=0;
			  length=sizeof(p_map[p].s_addr);

			  if (1 == p_map[p].logout_flag) break;
			  //printf("wait for recv-----\n");

			  i_recv=recvfrom(p_map[p].udp_sock, tmp, 128, 0, (struct sockaddr *)&(p_map[p].s_addr), (socklen_t *)&length);        

			  if (i_recv>4)  
			  {
				//printf("i_recv  ------------- %d\n",i_recv);
				bzero(bufx, 128);
				memcpy(bufx,tmp,i_recv-4);

				parity=crc32(0,bufx,i_recv-4);           
				tail_crc=0;
				lp=&tail_crc;
				memcpy(lp,(tmp+i_recv-4),4);

				//printf("parity : %u       tail_crc: %u\n",parity,tail_crc);

				if ( parity==tail_crc)
				{ 
				  bzero(bufx,50);
				  memcpy(bufx,(tmp+sizeof(PSRTA_HDR)),4);
				  lp=(unsigned long *)&bufx;
				  parity=*lp;
				  //printf("return : %u\n",parity);
				  if (parity==0)
				  {
					bzero(buf_id,20);
					len=tmp[sizeof(PSRTA_HDR)+4];
					memcpy(buf_id,tmp+sizeof(PSRTA_HDR)+4+1,len);
					buf_id[len]='\0';
					if (atoi(buf_id)==atoi(userid))
					{
					  regist=1;
					  

					  //printf("communicat to eAudit ------ok!");
					}
				  }
				}
			  }

			}while (regist==0);


			free(pst);
		  }
		} 

		write_log_info(msg_record);
	  }
	  else 
	  {
		//printf("not in table///////////!\n");
		rp=88;
	  }

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

	free(rsp);
	shutdown(new_fd,SHUT_WR);
	close(new_fd);

  }

  //线程任务结束
  thread_param->flag = 0;//设置线程占用标志为"空闲"

  //printf("%d-------------------end pthread!..........\n",thread_param->index);

  goto wait_unlock;

  pthread_exit(NULL);

  /* 处理每个新连接上的数据收发结束 */
}


void lock_sem()
{
  lock_it.sem_num=0;
  lock_it.sem_op=-1;
  lock_it.sem_flg=IPC_NOWAIT;
  semop(sem_id,&lock_it,1);   /*信号量减一*/
}

void unlock_sem()
{
  lock_it.sem_num=0;
  lock_it.sem_op=1;
  lock_it.sem_flg=IPC_NOWAIT;
  semop(sem_id,&lock_it,1);   /*信号量加一*/
}

int read_user_file(const char * conf_filename)
{
  IniItemInfo *items;
  int nItemCount;
  int i,j,result,listnum,id,mode;
  char *str=NULL, *tmp=NULL;
  char tmpstr[20];
  REGIST_QUEUE * tgst_queue;

  if ((result=iniLoadItems(conf_filename, &items, &nItemCount)) != 0)
  {
	printf("file: "__FILE__", line: %d, " \
	  "load from ini file \"%s\" fail, " \
	  "error code: %d\n", \
	  __LINE__, conf_filename, result);
	return result;
  }
  printf("nItemCount-----%d\n",nItemCount);

  tgst_queue=(REGIST_QUEUE *)malloc(sizeof(REGIST_QUEUE)*NON);

  for (i=0;i<NON;i++)
	tgst_queue[i].user_id=-1;

  listnum = iniGetIntValue("LIST_NUM", items, nItemCount,1);
  printf("user number------%d\n",listnum);

  j=0;
  for (i=0;i<listnum;i++)
  {
	sprintf(tmpstr,"INFO%d",i);
	//printf("%s\n",tmpstr);
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
	tgst_queue[i].flag=0;

	tmp=strtok(str,"+");
	//  if (tmp) printf("tmp=%s\n",tmp);
	id=atoi(tmp);
	if (id>NON) {
	  printf("userid is too large!\n");
	  break;
	}

	tmp=strtok(NULL,"+");
	//  if (tmp) printf("tmp=%s\n",tmp);
	tmp=strtok(NULL,"+");
	//  if (tmp) printf("tmp=%s\n",tmp);
	tmp=strtok(NULL,"+");
	//   if (tmp) printf("tmp=%s\n",tmp);
	strcpy(tmpstr,tmp);

	tmp=strtok(NULL,";");
	// if (tmp) printf("tmp=%s\n",tmp);
	mode=atoi(tmp);

	if (mode==3) 
	{
	  tgst_queue[id].user_id=id;
	  strcpy(tgst_queue[id].user_name,tmpstr);
	  j++;
	  printf("read_user_table: user_name=%s  user_id=%d\n",tgst_queue[id].user_name,tgst_queue[id].user_id);
	}
  }

  NO= j;    
  iniFreeItems(items);


  if (tongzi)  
  {
	for (i=0;i<NON;i++)
	{
	  if ( (tgst_queue[i].user_id==rgst_queue[i].user_id) && (rgst_queue[i].flag==1) && !strcmp(tgst_queue[i].user_name,rgst_queue[i].user_name))
	  {
		DEBUG("[YZ]i=%d\n",i);
		DEBUG("[YZ]ip=%s\n", rgst_queue[i].ip);
		DEBUG("[YZ]real_ip=%s\n", rgst_queue[i].real_ip);

		tgst_queue[i].user_id  =  rgst_queue[i].user_id;
		tgst_queue[i].flag     =  rgst_queue[i].flag;
		tgst_queue[i].count    =  rgst_queue[i].count;
		tgst_queue[i].tocken   =  rgst_queue[i].tocken;
		tgst_queue[i].cli_addr =  rgst_queue[i].cli_addr;

		memcpy((char *)(tgst_queue[i].user_name), (char *)(rgst_queue[i].user_name),16);
		memcpy((char *)(tgst_queue[i].ip), (char *)(rgst_queue[i].ip),16);
		memcpy((char *)(tgst_queue[i].real_ip), (char *)(rgst_queue[i].real_ip),16);
		memcpy((unsigned char *)(tgst_queue[i].mac), (unsigned char *)(rgst_queue[i].mac),6);
		memcpy((char *)(tgst_queue[i].os_name), (char *)(rgst_queue[i].os_name),40);
		memcpy((char *)(tgst_queue[i].host_name), (char *)(rgst_queue[i].host_name),40);
		memcpy((char *)(tgst_queue[i].reg_detail), (char *)(rgst_queue[i].reg_detail),40);
	  }
	}
  }


  lock_sem();

  memcpy((REGIST_QUEUE *)rgst_queue,(REGIST_QUEUE *)tgst_queue,sizeof(REGIST_QUEUE)*NON);

  unlock_sem();

  free(tgst_queue);

  if (tongzi)  
  {	
	for (i=0;i<num_eAudit;i++)
	{
	  if (!is2h1 && !strncmp(p_map[i].addr,degree_ip,16)) continue; 

	  if (0 == p_map[i].logout_flag )
		resend_eAudit(p_map[i].s_addr);
	}
	tongzi=0;
  }

  return 0;
}

int read_ini_file(const char * path, const char * filename)
{
  IniItemInfo *items;
  int nItemCount, result,i;
  char * str=NULL;
  char conf_filename[80],tmpstr[40];

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


  degree_port = iniGetIntValue("port_degree", items, nItemCount,1);
  printf("degree_port------%d\n",degree_port);
  u_port=degree_port+1;

  handshake_time = iniGetIntValue("time_handshake", items, nItemCount,1);
  printf("handshake_time------%d\n",handshake_time);

  check_time = iniGetIntValue("time_check", items, nItemCount,1);
  printf("check_time------%d\n",check_time);

  THREAD_MAX = iniGetIntValue("num_pthread_pool",items,nItemCount,10);
  printf("num_pthread_pool-----------%d\n",THREAD_MAX);

  num_eAudit = iniGetIntValue("num_eAudit", items, nItemCount,1);
  printf("num_eAudit------%d\n",num_eAudit);

 
  def_DEBUG = iniGetIntValue("DEBUG", items, nItemCount,0);
  printf("def_DEBUG------%d\n",def_DEBUG);


  if (num_eAudit == 1) is2h1=1;
  else 
	if (num_eAudit>1) is2h1=0;

  eAudit_port = iniGetIntValue("port_eAudit", items, nItemCount,1);
  printf("eAudit_port------%d\n",eAudit_port);

  bzero(p_map, sizeof(COMM_FLAG)*10);

  for (i=0;i<num_eAudit;i++)
  {
	sprintf(tmpstr,"ip_eAudit%d",i+1);

	str=NULL;
	str = iniGetStrValue(tmpstr, items, nItemCount);
	if (str == NULL)
	{       
	  iniFreeItems(items);
	  printf("file: "__FILE__", line: %d, " \
		"conf file \"%s\" must have item " \
		"\"begin_ip_net1\"!", \
		__LINE__, conf_filename);
	  exit(-1); 
	}      
	memcpy(p_map[i].addr,str,strlen(str));
	printf("eAudit_ip%d------%s\n",i+1,str);

	if (!strncmp(str,degree_ip,16)) 
	  p_map[i].logout_flag=0;
	else
	  p_map[i].logout_flag=1; 
  }


  iniFreeItems(items);

  return 0;
}


int read_eAudit_db_conf(const char * path, const char * filename)
{
  IniItemInfo *items;
  int nItemCount, result;
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

  str = iniGetStrValue("IP", items, nItemCount);
  if (str == NULL)
  {       
	iniFreeItems(items);
	printf("file: "__FILE__", line: %d, " \
	  "conf file \"%s\" must have item " \
	  "\"end_ip_net1\"!", \
	  __LINE__, conf_filename);
	exit(-1);
  }       
  strcpy(eAudit_ip,str);

  iniFreeItems(items);

  return 0;

}

void resend_eAudit(struct sockaddr_in s_addr )
{
  int i,j,k,l,len,regist,udp_sock2,i_recv;
  unsigned long parity,tail_crc;
  unsigned long *lp;
  char userid[20],buf[20];
  unsigned char retchar[256], sendbuff[256],bufx[128],tmp[128];

  PSRTA_HDR *ps;

  memset(retchar,0,256);
  memset(sendbuff,0,256);
  int    nPos;               

  /////////////组合要发送的数据体////////////////
  DEBUG("[yz]begin  resend_eAudit\n");

  usleep(50000);

  if ((udp_sock2 = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
	perror("udp_socket");
	exit(errno);
  } 

  for (i=0;i<NON;i++)
  {
	bzero(sendbuff,256);
	nPos=sizeof(PSRTA_HDR);               //     数据包的开始位置

	if (!rgst_queue[i].flag) continue;

	sprintf(userid,"%d",rgst_queue[i].user_id);
	len=strlen(userid);
	sendbuff[nPos]=len;
	nPos+=1;
	DEBUG("[yz] userid=%d\n",rgst_queue[i].user_id);

	memcpy((char*)&sendbuff[nPos],userid,len);
	nPos+=len;

	len=strlen(rgst_queue[i].user_name);
	DEBUG("[yz] usename=%s\n",rgst_queue[i].user_name);

	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],rgst_queue[i].user_name,len);
	nPos+=len;

	memcpy((char*)&sendbuff[nPos],rgst_queue[i].mac,6);
	nPos+=6;

	len=strlen(rgst_queue[i].ip);
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],rgst_queue[i].ip,len);
	nPos+=len;

	len=strlen(rgst_queue[i].os_name);
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],rgst_queue[i].os_name,len);
	nPos+=len;

	len=strlen(rgst_queue[i].host_name);
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],rgst_queue[i].host_name,len);
	nPos+=len;

	sendbuff[nPos]=rgst_queue[i].tocken;             //令牌锁定标志 0 未锁定 1 锁定
	nPos+=1;

	len=strlen(rgst_queue[i].reg_detail);
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],rgst_queue[i].reg_detail,len);
	nPos+=len;

	len=strlen(rgst_queue[i].real_ip);
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],rgst_queue[i].real_ip,len);
	nPos+=len;

	//////////////组合要发送的数据头////////////////
	ps=(PSRTA_HDR *)malloc(sizeof(PSRTA_HDR));

	memcpy(&ps->flag,"SRTA",4);    //标志位
	ps->version      = 0x0100;     //版本

	ps->opt_code     = 0x01;       //注册
	ps->param_length = (unsigned long)( nPos-sizeof(PSRTA_HDR));   //数据体长度

	memcpy((char *)&sendbuff,ps,sizeof(PSRTA_HDR));

	free(ps);

	memset(retchar,0,256);
	memcpy((char *)&retchar,sendbuff,nPos);

	unsigned long crcval = crc32(0,retchar,(unsigned long) nPos);


	memcpy((char*)&sendbuff[nPos],&crcval,4);
	nPos+=4;
	regist=0;
	j=0;
	k=0;
	l=0;
	DEBUG("[yz]nPos=%d\n",nPos);
	do
	{
	  k=sendto(udp_sock2, sendbuff, nPos, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));

	  if (k<=0) 
	  {
		l++;

		if (l<5)
		  continue; 
		else
		{
		  printf("send to eAudit 5 times fail!\n");
		  break;
		}
	  }
	  DEBUG("[yz] j=%d  l=%d   k=%d\n",j,l,k);

	  len=sizeof(s_addr);
	  i_recv=recvfrom(udp_sock2, tmp, 128, 0, (struct sockaddr *)&s_addr, (socklen_t *)&len);        

	  DEBUG("[yz] i_recv  ------------- %d\n",i_recv);

	  if (i_recv>4)  
	  {
		bzero(bufx, 128);
		memcpy(bufx,tmp,i_recv-4);

		parity=crc32(0,bufx,i_recv-4);           
		tail_crc=0;
		lp=&tail_crc;
		memcpy(lp,(tmp+i_recv-4),4);

		DEBUG("[yz] parity : %u       tail_crc: %u\n",parity,tail_crc);

		if ( parity == tail_crc)
		{ 
		  bzero(bufx,50);
		  memcpy(bufx,(tmp+sizeof(PSRTA_HDR)),4);
		  lp=(unsigned long *)&bufx;
		  parity=*lp;
		  DEBUG("[yz]return value : %u\n",parity);
		  if (parity == 0)
		  {
			bzero(buf,20);
			len=tmp[sizeof(PSRTA_HDR)+4];
			memcpy(buf,tmp+sizeof(PSRTA_HDR)+4+1,len);
			buf[len]='\0';
			if (atoi(buf)==atoi(userid))
			{
			  regist=1;
			  //    writelog(DAT,msg_record);
			  DEBUG("[yz] communicat to eAudit ------ok!");
			}
		  }
		}
	  }
	  j++;

	}while (regist == 0 && j<3);

  }

  close(udp_sock2);

  DEBUG("[yz] resend to eAudit Ok!\n");      
}

int main(int argc, char **argv)
{
  int listener, new_fd, kdpfd, nfds, n, curfds,i=0,j,rc,fd;
  socklen_t len;
  struct sockaddr_in my_addr, their_addr;
  struct epoll_event ev;
  struct epoll_event events[MAXEPOLLSIZE];
  EPOLL_ADDR connect_addr[MAXEPOLLSIZE];
  struct rlimit rt;
  char s[80];

  FILE * fp;
  pid_t parent;

  int fd_mem,tm,io_flag=0;  

  unsigned int optval,listen_num;
  struct linger optval1;
  sigset_t intmask;

  char* name = "/dev/shm/myshm2";
  char* name1 = "/dev/shm/myshm1";

  if (access(name1,F_OK)!=0)
  {
	printf("File: %s is not exist! creating ...\n",name1);

	if((fp=fopen(name1,"w"))==NULL)//共享内存打开文件 没有就创建
	{
	  printf("can not creat myshm1 file!\n");
	  exit(-1);
	}

	fclose(fp);

	fd_mem=open("/eAudit/info/mem2.dat",O_CREAT|O_RDWR,00777);
	if (-1==fd_mem) 
	{
	  printf("can not open /eAudit/info/mem2.dat\n");
	  exit(-1);
	}
	ftruncate(fd_mem,sizeof(COMM_FLAG)*10);
  }
  else
  {
	fd_mem=open("/eAudit/info/mem2.dat",O_CREAT|O_RDWR,00777);
	if (-1==fd_mem) 
	{
	  printf("can not open /eAudit/info/mem2.dat\n");
	  exit(-1);
	}
	ftruncate(fd_mem,sizeof(COMM_FLAG)*10);
  }

  p_map  = (COMM_FLAG *) mmap( NULL,sizeof(COMM_FLAG)*10,PROT_READ|PROT_WRITE,MAP_SHARED,fd_mem,0 );
  if (p_map == MAP_FAILED)
  {
	printf("mmap wrong:can not mmap to MEM2 FILE!\n");
	exit(0);
  }
  close(fd_mem);

  sleep(1);

//  sigemptyset(&intmask); /* 将信号集合设置为空 */

//  sigaddset(&intmask,SIGINT); /* 加入中断 Ctrl+C 信号*/

//  sigprocmask(SIG_BLOCK,&intmask,NULL); //屏蔽Ctrl+C

  if (access(name,F_OK)!=0)
  {
	printf("File: %s is not exist! creating ...\n",name);

	if((fp=fopen(name,"w")) == NULL)//共享内存打开文件 没有就创建
	{
	  printf("can not creat myshm2 file!\n");
	  exit(-1);
	}

	fclose(fp);
	fd_mem=open("/eAudit/info/mem.dat",O_CREAT|O_RDWR,00777);
	ftruncate(fd_mem,sizeof(REGIST_QUEUE)*NON);
	//  ftruncate(fd_mem,1843200);
  }
  else 
  {
	fd=open("/eAudit/info/time.dat",O_RDONLY);
	if (fd<0) perror("open");
	read(fd,&tm,4);
	//      read(fd,&num,4);
	close(fd);

	printf("time_b=%f\n",difftime(time(NULL),tm));

	if (difftime(time(NULL),tm)<10) 
	{
	  //     printf("want tongzhi ------ \n");
	  fd_mem=open("/eAudit/info/mem.dat",O_RDWR,00777);
	  tongzi=1;
	}
	else
	{
	  fd_mem=open("/eAudit/info/mem.dat",O_CREAT|O_RDWR|O_TRUNC,00777);
	//  ftruncate(fd_mem,1843200);
	  ftruncate(fd_mem,sizeof(REGIST_QUEUE)*NON);
	  tongzi=0;
	}

  }

  rgst_queue  = (REGIST_QUEUE *) mmap( NULL,sizeof(REGIST_QUEUE)*NON,PROT_READ|PROT_WRITE,MAP_SHARED,fd_mem,0 );
  if (rgst_queue == MAP_FAILED)
  {
	printf("mmap wrong:can not mmap to MEM FILE!\n");
	exit(0);
  }

  close(fd_mem);


  if (access(name1,F_OK)!=0)
  {
	printf("File: %s is not exist! creating ...\n",name);

	if((fp=fopen(name1,"w"))==NULL)//共享内存打开文件 没有就创建
	{
	  printf("can not creat myshm1 file!\n");
	  exit(-1);
	}

	fclose(fp);
  }
  if((sem_id=semget((key_t)SEMKEY,1,IPC_CREAT))<0)  /*创建信号量*/  
	perror("semget");

  options.val=1;
  semctl(sem_id,0,SETVAL,options);                  /*设置信号量值*/


  strcpy(s,"/eAudit/conf");  //getcwd(s,sizeof(s));

  if (read_ini_file(s,"degree.conf"))
  {
	printf("read_ini_file :degree.conf -----error code %d!\n",i);
	exit(-1);
  }

  if (read_eAudit_db_conf(s,"eAudit_db_conn.conf"))
  {
	printf("read_ini_file :eAudit_db_conn.conf -----error code %d!\n",i);
	exit(-1);
  }

  for (i=0;i<num_eAudit;i++)
  {
	if ((p_map[i].udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
	  perror("udp_socket");
	  exit(errno);
	}
	else
	  DEBUG("create udp_socket sucess for regit to eAudit-------%s \n",p_map[i].addr);

	/* 设置对方eAudit服务器 地址和端口信息 */
	p_map[i].s_addr.sin_family = AF_INET;
	p_map[i].s_addr.sin_port = htons(eAudit_port);
	p_map[i].s_addr.sin_addr.s_addr = inet_addr(p_map[i].addr);

	if (strncmp(p_map[i].addr,degree_ip,16))
	{
	  if  (0 == Socket_Commulication(p_map[i].addr,5798,0x04))
		p_map[i].logout_flag=0;
	}
  }


  if ((i=read_user_file(user_file))!=0) 
  {
	printf("can not open file %s\n",user_file);
	exit(-1);
  }

  printf("NO=%d\n",NO);


  //线程池初始化
  rc = init_thread_pool();
  if (0 != rc) exit(-1);

  signal(SIGALRM,   sigroutine);
  signal(SIGTERM,   sigroutine);

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


  for (i=0;i<num_eAudit;i++)
  {
	printf("i=%d     addr=%s     logout_flag=%d \n",i,p_map[i].addr,p_map[i].logout_flag);
  }

  parent=getpid();

  for (i=0;i<(num_process+1);i++)
  {
	if (0==fork())
	{
	  if (i == 0)
	  {
		tcp_5799(parent);
	  }
	  else 
		udp_process(5800+i);
	}
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

  if (listen(listener, listen_num) == -1) {
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
  io_flag=0;



  if ( 1 == conn_db(eAudit_ip, 5432, "eAudit","snamdb_super_user", "Sailing-gfdDSR3425-d55fdgDFf"))
      printf("connect to db ok \n");
  else
      printf("connect to db fail \n");	


  while (1) {
	write_harddisk();
	if (exit_flag) break;

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
		//查询空闲线程池
		for(j = 0; j < THREAD_MAX; j++) 
		{
		  if (0 == s_thread_para[j].flag) break;
		}
		if (j >= THREAD_MAX) 
		{
		  DEBUG("线程池已满, 连接将被放弃\n");
		  shutdown(events[n].data.fd, SHUT_RDWR);
		  close(events[n].data.fd);
		  continue;
		}
		else
		{
		  //复制有关参数
		  //printf("thread j=%d\n",j);

		  s_thread_para[j].flag = 1;                                //设置活动标志为"活动"
		  s_thread_para[j].fd =events[n].data.fd ;                  //客户端连接描述符
		  memcpy(s_thread_para[j].addr,connect_addr[n].addr,16);    //连接地址
		  s_thread_para[j].index = j;                               //服务索引
		  //线程解锁
		  pthread_mutex_unlock(s_mutex + j);
		}
	  }
	}
  }
  close(listener); 

  close_db();
  if (-1==munmap( rgst_queue, sizeof(REGIST_QUEUE)*NON ))
	perror(" rgst_queue: detach error ");

  if (-1==munmap( p_map, sizeof(COMM_FLAG)*10 ))
	perror(" p_map: detach error ");

  free(s_thread_para);    
  free(s_tid);               
  free(s_mutex);             

  write_time_dat();

  return 0;
}

static int Socket_Commulication(char *serv_ip,unsigned short serv_port,int cmd)
{
  int sockfd,bytes_read=0;
  PSESSION_HDR pd_data,*pd_data_p=NULL;
  int flag,j,serials,*pserials=NULL;
  unsigned short num0,*pNum0=NULL; 
  struct sockaddr_in server_addr; 
  unsigned char szBuf[256];
  unsigned char *pBuf=NULL;
  char protect_mode,*ppro_mode=NULL;
  pNum0 = &num0;
  num0 = 0x0100;
  pserials = &serials;
  serials = 0;
  ppro_mode = &protect_mode;
  protect_mode =0;


  if((sockfd = socket(PF_INET,SOCK_STREAM,0)) == -1)
  { 
	DEBUG("[Err]Create connect client  socket server  err."); 
	return -1;
  }

  flag = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
  {
	DEBUG("[Err]setsockopt SO_REUSEADDR err.");
	close(sockfd);
	return -1;
  }
  //  printf(" serv_ip = %s serv_port = %d \n",serv_ip,serv_port);
  bzero(&server_addr,sizeof(server_addr));
  server_addr.sin_family = AF_INET; 
  if(serv_port == 0)
	server_addr.sin_port = htons(5799); 
  else 
	server_addr.sin_port = htons(serv_port);


  if(serv_ip ==NULL)
	server_addr.sin_addr.s_addr =inet_addr("127.0.0.1");
  else 
	server_addr.sin_addr.s_addr =inet_addr(serv_ip);

  if(connect(sockfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr)) != 0)
  { 
	DEBUG("[Err]connect  sever socket err."); 
	close(sockfd);
	return -1;
  }
  memset(szBuf,0,256);
  memset((unsigned char *)&pd_data,0,sizeof(PSESSION_HDR));
  pBuf =(unsigned char *)&pd_data;
  memcpy((unsigned char *)(&pd_data.flag),"SRTA",4);
  pd_data.version = 0x100;
  pd_data.serial=0;
  pd_data.mode = 0;
  pd_data.opt_code = cmd;
  pd_data.param_length = 8;
  pd_data.reserved =0;


  //printf("hdr crc32 = %u\n",crc32(0,pBuf,sizeof(PSESSION_HDR)-4));

  pd_data.prt_crc = crc32(0,pBuf,sizeof(PSESSION_HDR)-4);
  memcpy(szBuf,pBuf,sizeof(PSESSION_HDR));

  memcpy(szBuf+sizeof(PSESSION_HDR),"12345678",8);

  //  printf("all data crc32 = %u \n",crc32(0,szBuf,sizeof(PSESSION_HDR)+8));

  serials =crc32(0,szBuf,sizeof(PSESSION_HDR)+8);

  pd_data.version = htons(0x100);
  pd_data.param_length = htonl(8);
  pd_data.prt_crc = htonl(pd_data.prt_crc);

  memset(szBuf,0,256);
  memcpy(szBuf,pBuf,sizeof(PSESSION_HDR));
  memcpy(szBuf+sizeof(PSESSION_HDR),"12345678",8);
  memcpy(szBuf+sizeof(PSESSION_HDR)+8,&serials,4);

  /*发送通知*/
  if(-1 == socket_write(sockfd,szBuf,sizeof(PSESSION_HDR)+8+4)){
	DEBUG("[Err]Bind sever socket err."); 
	close(sockfd);
	return -1;
  }
  //printf("send success ok \n");
  /*接收确认报文*/
  j=5;
  while(j)
  {
	memset(szBuf,0x00,256);
	//printf("wait for rev data \n");
	bytes_read = recv(sockfd,szBuf,sizeof(szBuf),0); 
	if (bytes_read <= 0) {
	  j--;
	  continue; 
	}
	pd_data_p = (PSESSION_HDR *)szBuf;
	pBuf = szBuf;
	flag =pd_data_p->opt_code;
	// printf("pd_data_p->opt_code=%.2x\n",pd_data_p->opt_code);
	pBuf +=sizeof(PSESSION_HDR);
	memcpy(&serials,pBuf,4);
	//printf("serials = %u \n",serials);
	if(serials == 0){
	  //	printf("ok ok \n");

	  break;
	}
	j--;
  }
  close(sockfd);
  return 0;
}

static int socket_write(int sock_fd,void *buffer,int length) 
{ 
  int senden_bytes = -1; 
  int times = 5;

  errno = 0;

  while (times--)
  {
	senden_bytes = send(sock_fd,buffer,length,0); 
	if(senden_bytes <= 0) 
	{    
	  if(errno == EINTR)  
		continue;
	  else            
		return -1; 
	}
	else
	{
	  break;
	}
  } 
  return senden_bytes; 
}


