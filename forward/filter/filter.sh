#!/bin/sh
#
# capture        This starts and stops capture.
#
# chkconfig: 
# description: 
#
# processname: ./filter
# config: ./cfg/eAudit_init_cfg
# config: 
# pidfile: 

PATH=/sbin:/bin:/usr/bin:/usr/sbin

# Source function library.
. /etc/init.d/functions

RETVAL=0

prog="filter"

start(){
    echo -n "Starting filter packets"
    ./filter
    echo "Start Filter[0K]"
    return $RETVAL;
}

stop(){
    #echo -n "Stopping filter packets"
    #ps -ef |grep filter|grep -v grep|awk '{  print "kill -9 " $2}'|sh
    #echo  "Stop Filter[OK]"
    echo -n $"Stopping $prog: "
    killproc $prog
    RETVAL=$?
    echo
    rm -f ./filter.LOCK
    return $RETVAL
}

restart(){
    stop
    sleep 2
    start
}

case "$1" in
    start)
        start
        ;; 
    stop)
        stop
        ;; 
    restart)
        restart
        ;; 
    *)
    echo "Usage: $0 {start|stop|restart}"
    $RETVAL=1

esac 

exit $RETVAL
