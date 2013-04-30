MAIN = eAudit
OBJS = ctl_main.o	ctl_cmd.o	ctl_socket.o	ctl_filter_rule.o 	       ctl_config.o    ctl_pkt_file_info.o	ctl_support_pro.o	ctl_debug.o	ctl_pkt_shm_que.o	ctl_res_callback.o	ctl_sys_info.o	ctl_version_info.o	ctl_usr_list.o	ctl_sq_list.o	ctl_monitor.o	ctl_db.o	ctl_access_protected_resources_list.o	ctl_access_account_list.o	ctl_access_cmd_list.o	ctl_access_custom_list.o	ctl_access_protocol_feature_list.o	ctl_access_network_list.o	ctl_monitor_sysinfo_list.o

CC = gcc
ECPG = /data/database/bin/ecpg
INCDIRS = -I.	-I/usr/include/eaudit_comm -I/usr/include -I../interface -I/data/database/include -I../inc
CFLAGS =  -w -g $(INCDIRS)
#LIBSLINK=-lpcap  -leaudit_comm
LIBSLINK=-L/data/database/lib -lecpg	-lpcap	-leaudit_comm -lpthread -lsail_auth -lusb -lsail_crypto -lsense4

DEBUG_FLAG =
.SUFFIXES= .o .c


$(MAIN): ${OBJS}
	${CC} -o $@ $(CFLAGS) ${DEBUG_FLAG} ${OBJS} $(LIBSLINK)

.c.o:
	$(CC) $(CFLAGS) -c $<
%.c: %.pgc
	$(ECPG) $<

clean:
	/bin/rm -f core *.o
move:
	cp eAudit /eAudit/bin
