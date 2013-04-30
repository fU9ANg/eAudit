#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#define ERR 0
#define DAT 1

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

/*
typedef struct tag_REGIST
{
  unsigned char flag;
  int user_id;
  char user_name[16];
  unsigned char count;
}REGIST_QUEUE;
*/

void writelog(int level , char logmsg[]); 
int  BinarySearch(const REGIST_QUEUE *a, int e,int left,int right);

void writelog(int level , char logmsg[]) 
{
        struct tm *timep ;                       /*definition struct var*/
        time_t time_log ;                        /*definition time_log var*/
 
        time(&time_log) ;                        /*getting system time and date*/
        timep = localtime(&time_log) ;           /*time_log transform string*/
        FILE *fd ;

   
        if(level == ERR)
        {
               fd = fopen("/log/Authenticate/LOG_error.log","a+") ;
                if(fd == NULL)
                {
                        perror("open LOG_error.log file  error") ;
                }
                else
                {
                 fprintf(fd,"时间: %04d-%02d-%02d  %02d:%02d:%02d      FILE=%s  LINE=%d   FUNCTION=%s  THE MEG=%s\n",timep->tm_year+1900,timep->tm_mon+1,timep->tm_mday,timep->tm_hour,timep->tm_min,timep->tm_sec ,__FILE__,__LINE__,__FUNCTION__,logmsg);
                 
            fclose(fd) ;
                }
         }
         else if(level == DAT)
         {
              fd = fopen("/log/Authenticate/LOG_degree.log","a+") ;
                if(fd == NULL)
                {
                    perror("open LOG_degree.log file  error") ;
                }
                else
                {
                 fprintf(fd,"时间: %04d-%02d-%02d  %02d:%02d:%02d     %s\n",timep->tm_year+1900,timep->tm_mon+1,timep->tm_mday,timep->tm_hour,timep->tm_min,timep->tm_sec ,logmsg);
//                printf("wirte log file ok!\n");
                fclose(fd) ;
                }
          }
}

int BinarySearch(const REGIST_QUEUE *a, int e,int left,int right)   //折半查找
{
        int flag=0,center;
        while(left<=right)
        {
           center=(left+right)/2;
           if(e==a[center].user_id)
           {
              flag=1;     //查找成功
              break;      //终止循环
           }
           else
             if(e<a[center].user_id)
                right=center-1;
             else
                left=center+1;
        }
        if (flag)
           return center;
        else
           return -1;
}

