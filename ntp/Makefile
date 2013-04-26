
#
# Makefile
# by fU9ANg
# bb.newlife@gmail.com
#

MAIN        = ntpServer
OJBS        = main.o config.o

CC          = gcc
INCDIRS     = -I. -I/usr/include/eaudit_comm -I../inc -I../interface
CFLAGS      = -Wall -g -O0 $(INCDIRS)

LIBSLINK    = -leAuditCommon
DEBUG_FLAGS =
.SUFFIXES   = .o .c

$(MAIN) : $(OBJS)
	$(CC) -o $@ $(CFLAGS) ${DEBUG_FLAGS} ${OBJS} $(LIBSLINK)
.c.o:
	$(CC) $(CFLAGS) -c $<
clean:
	/bin/rm -f core *.o $(MAIN)
install:
	cp $(MAIN) /usr/eAudit/bin
uninstall:
	rm -rf /usr/eAudit/bin
