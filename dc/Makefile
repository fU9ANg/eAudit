
#
# file: Makefile
# Written 2009-2013 by fU9ANg
# bb.newlife@gmail.com
#

MAIN        = DC_server
OBJS        = DC_server.o	DC_crc32.o
CC          = gcc
INCDIRS     = -I. -I../inc -I/usr/include/eaudit_comm -I../interface
CFLAGS      = -Wall -w -g -O2 $(INCDIRS)
LIBSLINK    = -leaudit_comm -lpthread

DEBUG_FLAG  =
.SUFFIXES= .o .c


$(MAIN):${OBJS}
	${CC} -o $@ $(CFLAGS) ${DEBUG_FLAG} ${OBJS} $(LIBSLINK)

.c.o:
	$(CC) $(CFLAGS) -c $<

%.c: %.pgc
	$(ECPG) $<

clean:
	/bin/rm -f core *.o

install:
	cp $(MAIN) /usr/eAudit/bin

uninstall:
	/bin/rm -f /usr/eAudit/bin/$(MAIN)
