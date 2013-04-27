#
#  Author: fU9ANg
#  E-mail: bb.newlife@gmail.com
#
#  Written 2009
#

MAIN = analysisFTP
OBJS = analyze_authorize.o analyze_bmhs.o analyze_charset.o analyze_common.o analyze_config.o analyze_crc32.o \
	analyze_db_config.o analyze_debug.o analyze_decode.o analyze_file.o analyze_log.o analyze_param.o analyze_db.o\
	ftp_analyze_main.o ftp_analyze_config.o ftp_analyze_global.o ftp_analyze_db.o

CC = gcc

ECPG = /data/database/bin/ecpg
INCDIRS = -I. -I../interface -I/data/database/include -I/usr/include/eaudit_comm -I/usr/include
CFLAGS = $(INCDIRS)
LIBSLINK=-L/data/database/lib -lecpg -leaudit_comm


$(MAIN):${OBJS}
	${CC} -o $@ $(CFLAGS) ${OBJS} $(LIBSLINK)

.c.o:
	$(CC) $(CFLAGS) -c $<

%.c:%.pgc
	$(ECPG) $<

clean:
	/bin/rm -f core *.o

install:
	cp FTP_analysis /eAudit/bin -rf
