MAIN = capture
OBJS = capture_main.o capture_process.o	capture_signal.o	capture_debug.o	capture_stat.o capture_config.o capture_db.o capture_db_config.o

CC = gcc
INCDIRS = -I.	-I/usr/include/eaudit_comm	-I../interface	-I /data/database/include

CFLAGS = -w -g $(INCDIRS)

ECPG =  /data/database/bin/ecpg

LIBSLINK=-L /data/database/lib -lecpg -lpcap	-leaudit_comm -lpthread

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
	cp capture /eAudit/bin

