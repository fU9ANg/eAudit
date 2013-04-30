#!/bin/sh
#
# eAudit        This starts and stops eAudit.
#
# chkconfig: 
# description: 
#
# processname: ./eAudit
# config: ./cfg/eAudit_init_cfg
# config: 
# pidfile: 

PATH=/sbin:/bin:/usr/bin:/usr/sbin

# Source function library.
. /etc/init.d/functions

RETVAL=0

prog="eAudit"

start(){
    echo -n "Starting SAIL eAudit System......"
    ./eAudit
    echo "Start SAIL eAudit System[0K]"
    return $RETVAL;
}

stop(){
    #echo -n "Stopping SAIL eAudit System......"
    #ps -ef |grep eAudit|grep -v grep|awk '{  print "kill -9 " $2}'|sh
    #echo  "Stop SAIL eAudit System[OK]"
    echo -n $"Stopping $prog: "
    killproc $prog
    RETVAL=$?
    echo
    rm -f ./eAudit.LOCK
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
