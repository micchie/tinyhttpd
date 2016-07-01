CFLAGS += -Werror -Wall -O2
LDFLAGS += -lpthread -ldl # sqlite requires them
#LDFLAGS += -lrt # for clock_gettime()
EXTRA_CFLAGS += -I/usr/local/include -I../libsqlite/include
EXTRA_LDFLAGS += ../libsqlite/lib/libsqlite3.a
CFLAGS += $(EXTRA_CFLAGS)
PROG = tinyhttpd
OBJS = tinyhttpd.o
OPT = -DWITH_SQLITE

all: $(PROG)

tinyhttpd: tinyhttpd.o
	$(CC) $(CFLAGS) -o tinyhttpd tinyhttpd.o $(LDFLAGS) $(EXTRA_LDFLAGS)
tinyhttpd.o: tinyhttpd.c
	$(CC) $(CFLAGS) $(OPT) -c tinyhttpd.c
clean:
	-@rm -f $(PROG) $(OBJS)
