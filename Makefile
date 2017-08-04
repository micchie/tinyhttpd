CFLAGS += -Werror -Wall -O2 -g
LDFLAGS += -lpthread -lm -ldl -lrt # sqlite requires them
#LDFLAGS += -lrt # for clock_gettime()
EXTRA_CFLAGS += -I/usr/local/include -I../libsqlite/include
#EXTRA_LDFLAGS += ../libsqlite/lib/libsqlite3.a -lrt
CFLAGS += $(EXTRA_CFLAGS)
PROG = tinyhttpd-s
OBJS = tinyhttpd-s.o
#OPT = -DWITH_SQLITE
#SOPT = -DWITH_STACKMAP -DWITH_EXTMEM
SOPT = -DWITH_STACKMAP
SPATH ?= -I../netmap/sys/ -I../netmap/apps/include -DNETMAP_WITH_LIBS

all: $(PROG)

tinyhttpd-s: tinyhttpd-s.o
	$(CC) $(CFLAGS) -o tinyhttpd-s tinyhttpd-s.o $(LDFLAGS) $(EXTRA_LDFLAGS)
tinyhttpd-s.o: tinyhttpd.c nmlib.h
	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(SPATH) -c tinyhttpd.c -o tinyhttpd-s.o $(EXTRA_CFLAGS)
#tinyhttpd: tinyhttpd.o
#	$(CC) $(CFLAGS) -o tinyhttpd tinyhttpd.o $(LDFLAGS) $(EXTRA_LDFLAGS)
#tinyhttpd.o: tinyhttpd.c nmlib.h
#	$(CC) $(CFLAGS) $(OPT) -c tinyhttpd.c
clean:
	-@rm -f $(PROG) $(OBJS)
