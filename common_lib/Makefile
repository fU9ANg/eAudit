OBJS=libeaudit_comm.a   
CC=gcc
INCDIRS = -I.	-I../inc	-I../interface
CFLAGS = -Wall -O2 $(INCDIRS)   
    
all:$(OBJS)   
$(OBJS):eAudit_config.o	eAudit_log.o	eAudit_mem.o	eAudit_string.o	eAudit_dir.o	eAudit_file_lock.o	eAudit_sem.o	eAudit_shm.o	eAudit_shm_que.o	eAudit_single_run.o	eAudit_res_callback.o	eAudit_list.o	eAudit_mem_map.o	eAudit_err.o	eAudit_timer.o	eAudit_pipe.o	eAudit_sys_msg_que.o	eAudit_sendtcp.o	eAudit_read_file_conf.o
	ar	ru	$@	$?   
.c.o:$(CC)	-c	-o	$@ $(CFLAGS)	$*.o	$*.c
.PHONY:install install_inc uninstall clean
install:install_inc
	cp -dpRf $(OBJS) /usr/lib/
install_inc:
	@(mkdir -p /usr/include/eaudit_comm; \
	cp *.h /usr/include/eaudit_comm)
uninstall:
	rm -f /usr/lib/$(OBJS)
	rm -fr /usr/include/eaudit_comm
clean:   
	rm   -rf   *.a
	rm   -rf   *.o
