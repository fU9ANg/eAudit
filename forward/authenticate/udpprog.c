#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/ipc.h>
//#include <sys/shm.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/sem.h>
#include <unistd.h>


#define ERR 0
#define DAT 1
#define NON 30000
//#define NON 8000

typedef struct tag_SESSION_HDR
{
  unsigned char   flag[4];
  unsigned short  version;       //u_int16_t      version;
  unsigned int    serial;
  unsigned char   mode;             //u_int8_t       mode;
  unsigned char   opt_code;         //u_int8_t       opt_code;
  unsigned int    param_length;
  unsigned int    reserved;
  unsigned int    prt_crc;
}PSESSION_HDR,*PSESSION_HDR_ID;  /*session head define*/

typedef struct tag_COMM_FLAG
{
  int logout_flag;
  char addr[16];
  int udp_sock;  
  struct sockaddr_in s_addr;
}COMM_FLAG;

typedef struct tag_SET
{
  unsigned char flag;
  unsigned char length;
  unsigned char message[128];
  struct sockaddr_in addr;
}MESSAGE_QUEUE;

typedef struct tag_SESSION_HAND
{
  unsigned int   result;
  u_int32_t        ip;
  u_int16_t        port;
}PSESSION_HDSK;               /*session shakhands response*/


typedef struct tag_SRTA_HDR
{
  unsigned char   flag[4];
  unsigned short  version;
  unsigned char   opt_code;
  unsigned long   param_length;
}PSRTA_HDR,*PSRTA_HDR_ID;                /*sail regist to eAudit session's head define*/


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


static REGIST_QUEUE * rgst_queue;


static sem_t sem;

MESSAGE_QUEUE * queue;

static struct sockaddr_in  s_addr;  
static int sock;

PSRTA_HDR_ID pst;
//pthread_mutex_t mutex;

extern char degree_ip[16], eAudit_ip[16];  
extern int  degree_port, eAudit_port;
extern int  num_pthread, num_eAudit; 
extern struct sembuf lock_it;
extern int sem_id,is2h1;
//extern COMM_FLAG * p_map;
static COMM_FLAG * p_map;

int udp_process(int port);
void lock_sem2();
void unlock_sem2();
void clear_count(const int usrid);
void clear_flag(const int usrid);
void udp_recev(void);
void udp_anwser(void);

extern int conn_db(const char *host, const int port, const char *database,const char *user, const char *password);
extern int close_db(void);
extern void  write_log_info(char *msg);
extern unsigned long crc32( unsigned long crc, const unsigned char *buf, unsigned int len );
extern void DEBUG(const char *fmt, ...);

void lock_sem2()
{
  lock_it.sem_num=0;
  lock_it.sem_op=-1;
  lock_it.sem_flg=IPC_NOWAIT;
  semop(sem_id,&lock_it,1);   /*信号量减一*/
}

void unlock_sem2()
{
  lock_it.sem_num=0;
  lock_it.sem_op=1;
  lock_it.sem_flg=IPC_NOWAIT;
  semop(sem_id,&lock_it,1);   /*信号量加一*/
}


void clear_count(const int usrid)
{ 
  int i=usrid;

  if (i>=0)
  {
	if ( (rgst_queue[i].user_id==i) && ( rgst_queue[i].flag==1) )
	{
	  //   printf("find flag!   id= %d\n", usrid);
	  rgst_queue[i].count = 0;
	}
  } 
} 

void clear_flag(const int usrid)
{ 
  int i=usrid;

  if (i>=0)
  {
	if ( (rgst_queue[i].user_id==i) && (rgst_queue[i].flag==1) )
	{
	  lock_sem2();
	  rgst_queue[i].count = 0;
	  rgst_queue[i].flag  = 0;
	  unlock_sem2();
	} 
  } 
} 

void udp_recev(void)
{
  struct sockaddr_in c_addr;
  socklen_t addr_len;
  int len,i;
  char buff[128];

  /* 循环接收数据 */
  addr_len = sizeof(c_addr);

  while (1) {
	memset(buff,0,128);
	len = recvfrom(sock, buff, sizeof(buff) - 1, 0,
	  (struct sockaddr *) &c_addr, &addr_len);
	if (len < 0) {
	  perror("recvfrom");
	  exit(errno);
	}

	buff[len] = '\0';
	//printf("pthread udp_recev  ----size=%d\n",size);

	for (i=0;i<num_pthread;i++)
	{
	  if (queue[i].flag==0) break;
	}
	queue[i].length=len;
	memcpy(queue[i].message,buff,128);
	//memcpy(queue[i].addr,&c_addr,addr_len);
	queue[i].addr=c_addr;

	/* 锁定互斥锁*/
	//  pthread_mutex_lock (&mutex);
	//  ++size;
	//  pthread_mutex_unlock(&mutex);     

	queue[i].flag=1;
	sem_post(&sem);
  }
}

void udp_anwser(void)
{
  struct sockaddr_in c_addr;
  char buff[128],buf[80],buf_eA[80],userid[10],msg_record[80];
  unsigned char bufx[256],tmp[128];

  PSESSION_HDR_ID ps;
  PSESSION_HDSK *rsp;
  unsigned long * pl;
 
  int len,i,j,length,offset,i_recv,logout,ti;
  unsigned long ret,parity,crcnum1,crcnum2,tail_crc;
  unsigned long *lp;

  ps=malloc(sizeof(PSESSION_HDR));
  rsp=malloc(sizeof(PSESSION_HDSK));

  while (1) { 
	sem_wait(&sem);
	//printf("pthread udp_anwser ----size=%d\n",size);
	for (i=0;i<num_pthread;i++)
	  if (queue[i].flag==1) {
		c_addr=queue[i].addr;
		len=queue[i].length;
		memcpy(buff,queue[i].message,128);

		//printf("收到来自%s:%d的消息:%s        byte %d    flag=%d\n\r",
		//   inet_ntoa(c_addr.sin_addr), ntohs(c_addr.sin_port), buff,len,queue[i].flag);

		ps=(PSESSION_HDR_ID)buff;

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
		memcpy((bufx+28),(buff+28),ps->param_length);

		crcnum2=crc32(0,bufx,28+ps->param_length);

		bzero(bufx,4);
		memcpy(bufx,(buff+len-4),4);
		pl=(unsigned long *)bufx;
		tail_crc=*pl;

		//printf("crcnum2=%x,  tail_crc=%x\n",crcnum2,tail_crc);

		if ( (crcnum1==ps->prt_crc)  && (crcnum2==tail_crc) )
		{
		  if ( !strncmp((char *)(ps->flag),"SNRP",4) && (ps->opt_code==0x03) ) 
		  {
			DEBUG("recev a correct handshake message of SAIL\n");

			offset=sizeof(PSESSION_HDR);

			length=buff[offset];
			offset+=1;

			memcpy(userid,(buff+offset),length);
			userid[length]='\0';

			clear_count(atoi(userid));

			ps->opt_code=0x83;
			ps->param_length=sizeof(PSESSION_HDSK);

			memset(buf,0,80);
			memcpy(buf,ps,sizeof(PSESSION_HDR)-4);
			ps->prt_crc=crc32(0,(unsigned char *)buf,sizeof(PSESSION_HDR)-4);

			memset(buf,0,80);
			memcpy(buf,ps,sizeof(PSESSION_HDR));

			rsp->result = htonl(0);
			rsp->ip     = htonl(s_addr.sin_addr.s_addr);
			rsp->port   = htons(s_addr.sin_port);

			memcpy(buf+28,rsp,sizeof(PSESSION_HDSK));
			parity=crc32(0,(unsigned char *)buf,28+sizeof(PSESSION_HDSK));

			ps->version      = htons(ps->version);
			ps->serial       = htonl(ps->serial);
			ps->param_length = htonl(ps->param_length);
			ps->prt_crc      = htonl(ps->prt_crc);
			memcpy(buf,ps,sizeof(PSESSION_HDR));

			memcpy(buf+28+sizeof(PSESSION_HDSK),&parity,4);

			len=sizeof(PSESSION_HDR)+sizeof(PSESSION_HDSK)+4; 
			sendto(sock, buf, len, 0, (struct sockaddr *) &c_addr, sizeof(c_addr));

			DEBUG("server send handshake ok!\n");
		  }

		  if (!strncmp((char *)(ps->flag),"SNRP",4) && (ps->opt_code==0x02) ) 
		  {
			DEBUG("recev a correct  logout  message of SAIL\n");

			for (j=0;j<num_eAudit;j++)
			{  
			  DEBUG("is2h1=%d\n",is2h1);

			  if ( !is2h1 && !strncmp(p_map[j].addr,degree_ip,16)) continue;

			  DEBUG("[udp]%d----%s----logout_flag=%d\n",j,p_map[j].addr,p_map[j].logout_flag);
			  if ( 0 == p_map[j].logout_flag )                        
				do  
				{
				  offset=28;
				  length=buff[offset];
				  offset+=1;
				  memcpy(userid,(buff+offset),length);
				  userid[length]='\0';

				  logout=0;
				  memcpy(pst->flag,"SRTA",4);
				  pst->version=0x0100;
				  pst->opt_code=0x02;
				  pst->param_length = ps->param_length;

				  //printf("param_length=================%d\n",ps->param_length);

				  memset(buf_eA,0,80);
				  memcpy(buf_eA,pst,sizeof(PSRTA_HDR));
				  memcpy(buf_eA+sizeof(PSRTA_HDR),buff+28,ps->param_length);

				  memcpy(bufx,buff+28,ps->param_length);

				  parity=crc32(0,(unsigned char *)buf_eA,sizeof(PSRTA_HDR)+ps->param_length);

				  //printf("parity==%d          len----%d\n",parity,sizeof(PSRTA_HDR)+ps->param_length);

				  memcpy(buf_eA+sizeof(PSRTA_HDR)+ps->param_length,&parity,4);
				  len=sizeof(PSRTA_HDR)+ps->param_length+4; 

				  //sendto(Audp_sock, buf_eA, len, 0, (struct sockaddr *) &eA_addr, sizeof(eA_addr));
				  sendto(p_map[j].udp_sock, buf_eA, len, 0, (struct sockaddr *) &(p_map[j].s_addr), sizeof(p_map[j].s_addr));

				  length=sizeof(p_map[j].s_addr);  //eA_addr);

				  DEBUG("[udp]%d----%s----logout_flag=%d\n",j,p_map[j].addr,p_map[j].logout_flag);
				  if ( 1 == p_map[j].logout_flag ) break;

				  //i_recv=recvfrom(Audp_sock, tmp, 128, 0, (struct sockaddr *)&eA_addr, (socklen_t *)&length);
				  i_recv=recvfrom(p_map[j].udp_sock, tmp, 128, 0, (struct sockaddr *)&(p_map[j].s_addr), (socklen_t *)&length);

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

					//printf("parity: %u      tail_crc: %u\n",parity,tail_crc);  
					if ( parity==tail_crc)
					{
					  bzero(bufx,50);
					  memcpy(bufx,(tmp+sizeof(PSRTA_HDR)),4);
					  lp=(unsigned long *)&bufx;
					  parity=*lp;
					  //printf("return : %u\n",parity);
					  if (parity==0)
					  {  
						len=tmp[sizeof(PSRTA_HDR)+4];
						bzero(bufx,50);
						memcpy(bufx,tmp+sizeof(PSRTA_HDR)+4+1,len);
						bufx[len]='\0';
						if (atoi((char *)bufx)==atoi(userid))
						{
						  logout=1;
						  ti=atoi(userid);
						  sprintf(msg_record,"用户名= %s  ID = %d 注销成功!",
							  rgst_queue[ti].user_name,rgst_queue[ti].user_id);
						  write_log_info(msg_record);
						  DEBUG("communicat to eAudit logout------ok!");
						} 
					  }
					}
				  }
				} while (logout==0);
			}

			offset=28;


			length=buff[offset];
			offset+=1;

			memcpy(userid,(buff+offset),length);
			userid[length]='\0';

			//sprintf(msg_record,"用户ID %s 注销成功!",userid); 
			//write_log_info(msg_record);

			clear_flag(atoi(userid));

			ps->opt_code=0x82;
			ps->param_length=4;

			memset(buf,0,80);
			memcpy(buf,ps,sizeof(PSESSION_HDR)-4);
			ps->prt_crc=crc32(0,(unsigned char *)buf,sizeof(PSESSION_HDR)-4);

			memset(buf,0,80);
			memcpy(buf,ps,sizeof(PSESSION_HDR));

			ret= htonl(0);

			memcpy(buf+28,&ret,4);
			parity=crc32(0,(unsigned char *)buf,28+4);

			ps->version      = htons(ps->version);
			ps->serial       = htonl(ps->serial);
			ps->param_length = htonl(ps->param_length);
			ps->prt_crc      = htonl(ps->prt_crc);
			memcpy(buf,ps,sizeof(PSESSION_HDR));

			memcpy(buf+28+4,&parity,4);

			len=sizeof(PSESSION_HDR)+4+4; 
			sendto(sock, buf, len, 0, (struct sockaddr *) &c_addr, sizeof(c_addr));

		  }

		  queue[i].flag=0;

		  // pthread_mutex_lock(&mutex); //如果mutex已上锁，则阻塞直到锁被释放

		  // --size;

		  // pthread_mutex_unlock(&mutex);     
		}
	  }
  }


  free(rsp);
  free(ps);
}


int udp_process(int port)
{
  pthread_t t1,t2;
  int fd,i;
  unsigned int optval;
  struct linger optval1;


  if ( 1 == conn_db(eAudit_ip, 5432, "eAudit","snamdb_super_user", "Sailing-gfdDSR3425-d55fdgDFf"))
	      DEBUG("connect to db ok \n");
  else
	      DEBUG("connect to db fail \n");  

  fd=open( "/eAudit/info/mem2.dat",O_CREAT|O_RDWR,00777 );

  if (-1==fd)
  {
	printf("can not open /eAudit/info/mem2.dat\n");
	exit(-1);
  }

  p_map = (COMM_FLAG *)mmap(NULL,sizeof(COMM_FLAG)*10,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  if (p_map == MAP_FAILED)
  {
	printf("mmap wrong:can not mmap to MEM2 FILE!\n");
	close(fd);
	exit(-1);
  }
  close(fd);

  fd=open( "/eAudit/info/mem.dat",O_CREAT|O_RDWR,00777 );
  if (-1==fd)
  {
	printf("can not open /eAudit/info/mem.dat\n");
	exit(-1);
  }

  rgst_queue = (REGIST_QUEUE *)mmap(NULL,sizeof(REGIST_QUEUE)*NON,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  if (rgst_queue == MAP_FAILED)
  {
	printf("mmap wrong:can not mmap to MEM FILE!\n");
	close(fd);
	exit(-1);
  }
  close(fd);

  queue=(MESSAGE_QUEUE *)malloc(num_pthread*sizeof(MESSAGE_QUEUE));

  for (i=0;i<num_pthread;i++)
	queue[i].flag=0; 

  /* 用默认属性初始化一个互斥锁对象*/
  // pthread_mutex_init (&mutex,NULL);

  //printf("into udp_process!\n");

  pst=malloc(sizeof(PSRTA_HDR));
  memcpy(pst->flag,"SRTA",4);
  pst->version=0x0100;
  pst->opt_code=0x02;


  /* 创建 socket , 关键在于这个 SOCK_DGRAM */
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
	perror("socket");
	exit(errno);
  } else
	printf("create  socket for degree register  ok !  port= %d   \n\r",port);

  memset(&s_addr, 0, sizeof(struct sockaddr_in));
  /* 设置身份认证UDP服务器  地址和端口信息 */
  s_addr.sin_family = PF_INET;
  s_addr.sin_port = htons(port);
  s_addr.sin_addr.s_addr = inet_addr(degree_ip);


  //设置SO_REUSEADDR选项(服务器快速重起)
  optval = 0x1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, 4);

  //设置SO_LINGER选项(防范CLOSE_WAIT挂住所有套接字)
  optval1.l_onoff = 1;
  optval1.l_linger = 10;
  setsockopt(sock, SOL_SOCKET, SO_LINGER, &optval1, sizeof(struct linger));


  /* 绑定地址和端口信息 */
  if ((bind(sock, (struct sockaddr *) &s_addr, sizeof(s_addr))) == -1) {
	perror("bind");
	exit(errno);
  } else
	DEBUG("bind address to socket sucess!.\n");

  sem_init(&sem,0,0);

  pthread_create(&t1,NULL,(void *)udp_anwser,NULL);
  pthread_create(&t2,NULL,(void *)udp_recev,NULL);


  /* 防止程序过早退出，让它在此无限期等待*/

  pthread_join(t1,NULL);//只要t1结束进程即退出

  if (-1==munmap( rgst_queue, sizeof(REGIST_QUEUE)*NON ))
	perror(" detach rgst_queue error ");

  if (-1==munmap( p_map, sizeof(COMM_FLAG)*10 ))
	perror(" detach p_map error ");

  close_db();

  free(pst);
  return 0;
}

