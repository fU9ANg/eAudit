#include <sys/types.h>
#include <signal.h>

int main(int arc,char *argv[])
{
   pid_t i;

  for (i=atoi(argv[1]);i<=atoi(argv[2]);i++)
     kill(i,SIGKILL);
}
