
#
# file: Makefile
# Written 2009-2013 by fU9ANg
# bb.newlife@gmail.com
#

MAIN        = PMC_server
OBJS        = main.o debug.o

CC          = gcc
INCDIRS     = -I. -I/usr/include/eaudit_comm -I../inc -I../interface
CFLAGS      = -Wall -O2 $(INCDIRS)

LIBSLINK    = -leaudit_comm -lpthread

DEBUG_FLAG  =
.SUFFIXES   = .o .c


$(MAIN): ${OBJS}
	${CC} -o $@ $(CFLAGS) ${DEBUG_FLAG} ${OBJS} $(LIBSLINK)

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	/bin/rm -f core *.o $(MAIN)

install:
	cp $(MAIN) /usr/eAudit/bin

uninstall:
	/bin/rm -f /usr/eAudit/bin/$(MAIN)
