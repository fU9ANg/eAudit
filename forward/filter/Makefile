MAIN = filter
OBJS = filter_main.o filter_file.o  filter_packets.o	filter_signal.o	filter_debug.o	filter_pkt_file.o 

CC = gcc
INCDIRS = -I.	-I/usr/include/eaudit_comm -I../interface
CFLAGS = -g -Wall $(INCDIRS)

LIBSLINK=-lpcap	-leaudit_comm

DEBUG_FLAG =
.SUFFIXES= .o .c


$(MAIN): ${OBJS}
	${CC} -o $@ $(CFLAGS) ${DEBUG_FLAG} ${OBJS} $(LIBSLINK)

.c.o:
	$(CC) $(CFLAGS) -c $<
	
clean:
	/bin/rm -f core *.o
move:
	cp filter /eAudit/bin

