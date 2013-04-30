#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h> 

//#include <time.h>
#include <sys/time.h>
#include "crc32.c"

#define MAXBUF 1024
#define TIME_OUT_TIME 6   //���ӳ�ʱʱ�� 6��

typedef enum bool_type { 
false,true 
} bool; 

typedef struct tag_SESSION_HDR
{
    unsigned char  flag[4];
    unsigned short version;       //u_int16_t      version;
    unsigned long  serial;
    unsigned char  mode;             //u_int8_t       mode;
    unsigned char  opt_code;         //u_int8_t       opt_code;
    unsigned long  param_length;
    unsigned long  reserved;
    unsigned long  prt_crc;
}PSESSION_HDR,*PSESSION_HDR_ID;  /*session head define*/


typedef struct tag_SESSION_RGT_RSP
{
   unsigned int   result;
   u_int32_t        ip;
   u_int16_t        port;
   u_int16_t        time;
}PSESSION_RGT_RSP;               /*session regist response*/

//int clientudp(struct in_addr ip_address,u_int16_t port,char * userid);

int clientudp(int sock,struct sockaddr_in s_addr,char * userid);

int clientudp(int sock,struct sockaddr_in s_addr,char * userid)
{
  int addr_len,lens;
  int len,n;
  char buff[128];
  char recvline[128];
  struct sockaddr * preply_addr;
  PSESSION_HDR_ID session;
  unsigned long parity;

  preply_addr=malloc(sizeof(struct sockaddr));

  session=malloc(sizeof(PSESSION_HDR));

  memcpy(&session->flag,"SNRP",4);
  session->version=0x0100;
  session->serial=8512;
  session->mode=0;
  session->opt_code=0x03;
 
  len=strlen(userid); 
  session->param_length=1+strlen(userid);
  session->reserved=0;

  memcpy(buff,session,sizeof(PSESSION_HDR)-4);

  session->prt_crc=crc32(0,buff,sizeof(PSESSION_HDR)-4);

  bzero(buff, 128);
  memcpy(buff,session,sizeof(PSESSION_HDR));

  buff[28]=strlen(userid);
  memcpy(buff+28+1,userid,strlen(userid));
 
  lens=sizeof(PSESSION_HDR)+1+strlen(userid);
  parity=crc32(0,buff,lens);
  memcpy(buff+lens,&parity,4);

  lens+=4;

  //�����ֽ���ת���������ֽ���
  session->version      = htons(session->version);          //�汾
  session->serial       = htonl(session->serial);           //���к�    
  session->param_length = htonl(session->param_length);     //�����峤��
  session->prt_crc      = htonl(session->prt_crc);          //У��λ

  memcpy(buff,session,sizeof(PSESSION_HDR));

  /* ����UDP��Ϣ */
  addr_len = sizeof(s_addr);
  len = sendto(sock, buff, lens, 0, (struct sockaddr *) &s_addr, addr_len);

  if (len < 0) {
    printf("\n\rsend error.\n\r");
    return 3;
  }
//  printf("send handshake success.\n\r");

  lens=addr_len;
  
  n=recvfrom(sock,recvline,128,0,preply_addr,&lens);
  if (n<=0)  printf("not recev -----------%d\n",n);

  if (lens!=addr_len || memcmp((struct sockaddr *)&s_addr,preply_addr,lens)!=0) {
 //  printf("reply from %s (ignored)\n",inet_ntoa((struct sockaddri_in *)&preply_addr->sin_addr));
  //   continue;
  }
  else {
     recvline[n]='\0';
    // printf("recev from sever message %s!\n",recvline);
  }  

  free(preply_addr);
  free(session);
  return 0;
}

int main(int argc, char **argv)
{
  int sockfd,udp_sock,buff_len,i,len,index,no,k;
  struct sockaddr_in s_addr;
  struct sockaddr_in dest;
  struct in_addr ip_address;
  u_int16_t port;
  char s[80],user_id[10],user_name[60];
  pid_t pid;
  //clock_t begin,end;
  struct timeval start, end;
  double timeuse;

  PSESSION_HDR_ID ps;  
  PSESSION_RGT_RSP *rsp;
  unsigned long crc_num;

  FILE * fp;
  unsigned char sendbuff[MAXBUF],buff[MAXBUF],buffer[MAXBUF];
  struct in_addr in;

  if (argc < 5) {
  printf("������ʽ������ȷ�÷����£�\n\t\t%s IP��ַ �˿�  �û�index  ����\n\t����:\t%s 127.0.0.1 5800 1 300\n�˳���������ĳ�� IP ��ַ�ķ�����ĳ���˿ڽ��������֤",  argv[0], argv[0]);
  exit(0);
  }

  index=atoi(argv[3]);
  no=atoi(argv[4]);
  
//  begin=clock();

gettimeofday( &start, NULL );

for (k=0;k<no;k++)
{
 if ((pid=fork())>0)
 {
   index++;
   //sleep(1);
 }
 else
 {
  /* ����һ�� socket ���� tcp ͨ�� */
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Socket");
    exit(errno);
  }

  /* ��ʼ���������ˣ��Է����ĵ�ַ�Ͷ˿���Ϣ */
  bzero(&dest, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(atoi(argv[2]));
  if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
    perror(argv[1]);
    exit(errno);
  }

  int error=-1, len; 
  len = sizeof(int); 
  struct timeval tm; 
  fd_set set; 
  unsigned long ul = 1; 

  ioctl(sockfd, FIONBIO, &ul); //����Ϊ������ģʽ 
  bool ret = false; 

  /* ���ӷ����� */
  if( connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) == -1) 
  { 
 	tm.tv_sec = TIME_OUT_TIME; 
  	tm.tv_usec = 0; 
  	FD_ZERO(&set); 
  	FD_SET(sockfd, &set); 
  	if( select(sockfd+1, NULL, &set, NULL, &tm) > 0) 
  	{ 
   	   getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len); 
     	   if(error == 0) ret = true; 
	   else 
             ret = false; 
  	}
	else 
	  ret = false; 
  } 
  else 
     ret = true; 

   ul = 0; 
   ioctl(sockfd, FIONBIO, &ul); //����Ϊ����ģʽ 
   if(!ret) 
   { 
     close( sockfd ); 
     fprintf(stderr , "���ӷ�����ʧ��!\n"); 
     exit(errno); 
   } 
   fprintf( stderr , "���ӳɹ�!\n"); 




//  /* ���ӷ����� */
//  if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
//    perror("Connect ");
//    exit(errno);
//  }
	unsigned char strmac[6];
	int nErrorcod =-1;
	unsigned char retchar[256];

	memset(retchar,0,256);
	memset(sendbuff,0,256);
	int    nPos=sizeof(PSESSION_HDR);		//28     ���ݰ��Ŀ�ʼλ��

	/////////////���Ҫ���͵�������////////////////

    fp=fopen("user.conf","r");
    if (fp==NULL) printf("can not open user.conf !\n");

    i=0;
    while (fgets(s,80,fp)!=NULL)
    {
      sscanf(s,"%s %s",user_id, user_name);
      i++;
      if (i==index) break;
    }
    fclose(fp);        

        len=strlen(user_id);  
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],user_id,len);
	nPos+=len;


        len=strlen(user_name);  
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],user_name,len);
	nPos+=len;

        strmac[0]=0x00;
        strmac[1]=0x30;
        strmac[2]=0x18;
        strmac[3]=0xa7;
        strmac[4]=0xaf;
        strmac[5]=0x5c;
        
	memcpy((char*)&sendbuff[nPos],strmac,6);
	nPos+=6;

	len=strlen("192.168.10.110");
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],"192.168.10.110",len);
	nPos+=len;

	len=strlen("WINDOWS XP 2.0");
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],"WINDOWS XP 2.0",len);
	nPos+=len;

	len=strlen("My workstation 110");
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],"My workstation 110",len);
	nPos+=len;

	sendbuff[nPos]=0;             //����������־ 0 δ���� 1 ����
	nPos+=1;

	len=strlen("���ģ����");
	sendbuff[nPos]=len;
	nPos+=1;
	memcpy((char*)&sendbuff[nPos],"���ģ����",len);
	nPos+=len;

	int ndatalen=nPos-sizeof(PSESSION_HDR);
	int nPosend=nPos;

	//////////////���Ҫ���͵�����ͷ////////////////
	ps=(PSESSION_HDR *)malloc(sizeof(PSESSION_HDR));

	memcpy(&ps->flag,"SNRP",4);    //��־λ 
	ps->version      = 0x0100;     //�汾

	ps->serial       = index;  //���к�
	ps->mode         = 0;          //����
	ps->opt_code     = 0x01;       //ע��
	ps->param_length = (unsigned long) ndatalen;   //�����峤��
	ps->reserved     = 0;          //������

	memcpy(retchar,ps,sizeof(PSESSION_HDR)-4);    
	unsigned long crcval1=crc32(0,retchar,sizeof(PSESSION_HDR)-4);
	ps->prt_crc      = crcval1;      //У��λ

	memcpy((char *)&sendbuff,ps,sizeof(PSESSION_HDR));    

	memset(retchar,0,256);
	memcpy((char *)&retchar,sendbuff,nPosend);    
	unsigned long crcval = crc32(0,retchar,(unsigned long) nPosend);

	//�����ֽ���ת���������ֽ���
	ps->version      = htons(0x0100);       //�汾
	ps->serial       = htonl(index);    //���к�
	ps->param_length = htonl((unsigned long) ndatalen);     //�����峤��
	ps->prt_crc      = htonl(crcval1);      //У��λ

	memcpy((char *)&sendbuff,ps,sizeof(PSESSION_HDR));    

	free(ps); 

	memcpy((char*)&sendbuff[nPosend],&crcval,4);
	nPosend+=4;

        send(sockfd, sendbuff, nPosend, 0);

  //printf("first send ok!\n");


  /* ���նԷ�����������Ϣ�������� MAXBUF ���ֽ� */
  bzero(buffer, MAXBUF);
  len=recv(sockfd, buffer, sizeof(buffer), 0);
//  printf("%s     len=%d\n", buffer,len);
//  for (i=0;i<len;i++) printf("%02x",buffer[i]);
//  printf("\n");

  /* �ر����� */
  close(sockfd);
 
  //printf("size of response   %d\n",sizeof(PSESSION_RGT_RSP));
 
  //rsp=malloc(sizeof(PSESSION_RGT_RSP));
  if (len>28)
 {
  rsp=(PSESSION_RGT_RSP *) (buffer+28);

  rsp->result = ntohl(rsp->result);
  rsp->ip     = ntohl(rsp->ip);
  rsp->port   = ntohs(rsp->port);
  rsp->time   = ntohs(rsp->time);

  memcpy((void *)&ip_address,(void *)&(rsp->ip),sizeof(struct in_addr));

//  printf("ip=%s      port=%d \n",inet_ntoa(ip_address), rsp->port );  
  port=rsp->port;

  //free(rsp);

  /* ���� socket , �ؼ�������� SOCK_DGRAM */
  if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(errno);
  }
// else
//      printf("create socket.\n\r");


  /* ���öԷ���ַ�Ͷ˿���Ϣ */
  s_addr.sin_family = AF_INET;
  s_addr.sin_port = htons(port);
  s_addr.sin_addr.s_addr = ip_address.s_addr;



  while (1) {
     clientudp(udp_sock,s_addr,user_id);
     sleep(2);
  }
 }
}
}

gettimeofday( &end, NULL );
timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;
timeuse /= 1000000;

//  end=clock();

  //printf("%6.4d\n",(end-begin)/CLOCKS_PER_SEC);
  printf("%6.4f\n",timeuse);
  return 0;
}

