/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef _EAUDIT_TIMER_H
#define _EAUDIT_TIMER_H

typedef struct itimerval TIMER_VAL;

typedef enum
{
    SLEEP_MODE = 0,
    SIGNAL_MODE,
    TIMER_SIGNAL_MODEL,
    RTC_MODE
}   EN_TIMER_TYPE;

/*function declaration*/
extern void set_sec_timer(int which,long sec,struct itimerval ovalue);
extern void set_usec_timer(int which,long usec,struct itimerval ovalue);

#endif
