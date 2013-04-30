MAIN = CONNECT_server
OBJS = newserv.o crc32.o ini_file_reader.o log_opt.o udpprog.o 

CC = gcc
ECPG = /data/database/bin/ecpg
INCDIRS = -I.    -I/data/database/include

CFLAGS = -Wall -g  $(INCDIRS)

LIBSLINK=-L/data/database/lib -lecpg -lpthread

DEBUG_FLAG =
.SUFFIXES= .o .c


$(MAIN): ${OBJS}
	${CC} -o $@ $(CFLAGS) ${DEBUG_FLAG} ${OBJS} $(LIBSLINK)

.c.o:
	$(CC) $(CFLAGS) -c $<

%.c: %.pgc
	$(ECPG) $<
	
clean:
	/bin/rm -f CONNECT_server *.o

move:
	cp CONNECT_server /eAudit/bin

