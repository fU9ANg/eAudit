/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>
#include <sys/time.h>

#include "eAudit_pub.h"
#include "eAudit_timer.h"

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_sec_timer(int which,long sec,struct itimerval ovalue)
{
    TIMER_VAL value;

    value.it_value.tv_sec = sec;
    value.it_value.tv_usec = 0;

    value.it_interval.tv_sec = sec;
    value.it_interval.tv_usec = 0;

    setitimer(which,&value,&ovalue);
}

/*******************************************
*func name:
*function:
*parameters:
*call:
*called:
*return:
*/
void set_usec_timer(int which,long usec,struct itimerval ovalue)
{
    TIMER_VAL value;

    value.it_value.tv_sec = 0;
    value.it_value.tv_usec = usec;

    value.it_interval.tv_sec = 0;
    value.it_interval.tv_usec = usec;

    setitimer(which,&value,&ovalue);
}
