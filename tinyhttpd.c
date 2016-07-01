#include <stdio.h>
#include <inttypes.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <time.h>

#include <sys/ioctl.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif /* WITH_SQLITE */

struct dbinfo {
	int	type;
	char 	*path;
	union {
		sqlite3 *sql_conn;
		int	dumbfd;
	};
} dbi;

#define MAXCONNECTIONS 2048
#define MAXQUERYLEN 65535

enum { DT_NONE=0, DT_DUMB, DT_SQLITE};
const char *SQLDBTABLE = "tinytable";

#define D(fmt, ...) \
	printf(""fmt"\n", ##__VA_ARGS__)

static int do_abort = 0;
static u_int stat_nfds;
static u_int stat_eps;
static u_int stat_maxnfds;
static u_int stat_minnfds;
static uint64_t stat_vnfds;

void
close_db(struct dbinfo *dbip)
{
	struct stat st;
	const char *path = dbip->path;
	char path_wal[64], path_shm[64];

	/* close reference */
	if (dbip->type == DT_DUMB) {
		D("closing dumbfd");
		close(dbip->dumbfd);
	}
#ifdef WITH_SQLITE
	else if (dbip->type == DT_SQLITE) {
		D("closing sqlite3 obj");
		sqlite3_close_v2(dbip->sql_conn);
	}
#endif
	/* remove file */
	if (!path || !strncmp(path, ":memory:", 8)) {
		D("No dbfile to remove");
		return;
	}
	bzero(&st, sizeof(st));
	stat(path, &st);
	D("removing %s (%ld bytes)", path, st.st_size);
#ifdef WITH_SQLITE
	if (dbip->type == DT_SQLITE) {
		strncpy(path_wal, path, sizeof(path_wal));
		strcat(path_wal, "-wal");
		remove(path_wal);
		strncpy(path_shm, path, sizeof(path_wal));
		strcat(path_shm, "-shm");
		remove(path_shm);
	}
#endif
	remove(path);
}

int
print_resp(void *get_prm, int n, char **txts, char **col)
{
	printf("%s : %s\n", txts[0], txts[1]);
	return 0;
}

ssize_t
generate_httphdr(ssize_t content_length, char *buf, char *content)
{
	char *p = buf;
	/* From nginx */
	static char *lines[5] = {"HTTP/1.1 200 OK\r\n",
	 "Content-Length: ",
	 "Connection: keep-alive\r\n\r\n"};
	ssize_t l;


	memcpy(p, lines[0], strlen(lines[0]));
	p += strlen(lines[0]);
	memcpy(p, lines[1], strlen(lines[1]));
	p += strlen(lines[1]);
	l = sprintf(p, "%lu\r\n", content_length);
	p += l;
	memcpy(p, lines[2], strlen(lines[2]));
	p += strlen(lines[2]);

	if (content == NULL)
		memset(p, 'A', content_length);
	else
		memcpy(p, content, content_length);
	p += content_length;
	return p - buf;
}

static void
sig_h(int sig)
{
	//(void)sig;	/* UNUSED */
	D("got signal %d", sig);
	do_abort = 1;
	D("Stop process");
	if (sig == SIGINT)
		signal(SIGINT, SIG_DFL);
	else if (sig == SIGHUP)
		signal(SIGHUP, SIG_DFL);
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: tinyhttpd -p port -l msglen [-d dbname]\n");
	exit(1);
}

int do_accept(int fd, int epfd)
{
	struct epoll_event ev;
	struct sockaddr_in sin;
	socklen_t addrlen;
	int newfd;
	//int val = 1;
	while ((newfd = accept(fd, (struct sockaddr *)&sin, &addrlen)) != -1) {
		//if (ioctl(fd, FIONBIO, &val) < 0) {
		//	perror("ioctl");
		//}
		//int yes = 1;
		//setsockopt(newfd, SOL_SOCKET, SO_BUSY_POLL, &yes, sizeof(yes));
		memset(&ev, 0, sizeof(ev));
		ev.events = POLLIN;
		ev.data.fd = newfd;
		epoll_ctl(epfd, EPOLL_CTL_ADD, newfd, &ev);
	}
	return 0;
}

int do_established(int fd, ssize_t msglen, struct dbinfo *dbi)
{
	ssize_t len;
	static char buf[MAXQUERYLEN];
	static int seq = 0;
	len = read(fd, buf, sizeof(buf));

	if (len == 0) {
		close(fd);
		return 0;
	} else if (len < 0) {
		D("%lu", len);
		return -1;
	}

	if (strncmp(buf, "GET ", strlen("GET ")) == 0) {
		len = generate_httphdr(msglen, buf, NULL);
	} else if (strncmp(buf, "POST ", strlen("POST ")) == 0) {
		if (dbi->type == DT_DUMB) {
			char query[MAXQUERYLEN];
			/* create sql query for fair comparison with sqlite */
			snprintf(query, sizeof(query),
				"BEGIN TRANSACTION; insert into %s values (%d, '%s'); COMMIT;",
			       	SQLDBTABLE, seq++, buf);

			//len = write(dbi->dumbfd, buf, sizeof(len));
			len = write(dbi->dumbfd, query, sizeof(len));
			/* no need for fsync as O_SYNC */
		}
#if WITH_SQLITE
		else if (dbi->type == DT_SQLITE) {
			char query[MAXQUERYLEN];
			int ret;
			char *err_msg;

			snprintf(query, sizeof(query),
				"BEGIN TRANSACTION; insert into %s values (%d, '%s'); COMMIT;",
			       	SQLDBTABLE, seq++, buf);
			ret = sqlite3_exec(dbi->sql_conn, query, print_resp, 
					NULL, &err_msg);
			if (ret != SQLITE_OK) {
				D("%s", err_msg);
				sqlite3_close(dbi->sql_conn);
				sqlite3_free(err_msg);
				err_msg = NULL;
				return -1;
			}

		}
#endif /* SQLITE */
		len = generate_httphdr(msglen, buf, NULL);
	}
	write(fd, buf, len);
	return 0;
}

int
main(int argc, char **argv)
{
	int ch;
	int epfd, sd;
	struct sockaddr_in sin;
	const int on = 1;
	int port = 0;
	struct epoll_event ev;
	struct epoll_event evts[MAXCONNECTIONS];
	ssize_t msglen = 1;
	int eptimeout = 0;
	struct dbinfo dbi;
#ifdef WITH_SQLITE
	int ret = 0;
#endif /* WITH_SQLITE */

	bzero(&dbi, sizeof(dbi));
	dbi.type = DT_NONE;

	while ((ch = getopt(argc, argv, "p:l:bd:")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'p':	/* server port */
			port = atoi(optarg);
			break;
		case 'l': /* HTTP OK content length */
			msglen = atoi(optarg);
			break;
		case 'b': /* arg to epoll_wait() (-1 for blocking) */
			eptimeout = -1;
			break;
		case 'd':
			{
			char *p = strstr(optarg, "dumb");
			int ol = strlen(optarg);
		       	/* db file for SQL. :memory: means IMDB
			 * and any word ending with dumb means not using sql
			 */
			if (p && (p - optarg == ol - strlen("dumb")))
				dbi.type = DT_DUMB;
			else
				dbi.type = DT_SQLITE;
			dbi.path = optarg;
			}
			break;
		}

	}
	fprintf(stderr, "%s built %s %s db: %s\n",
		argv[0], __DATE__, __TIME__, dbi.path ? dbi.path : "none");
	usleep(1000);

	argc -= optind;
	argv += optind;

	if (!port || !msglen)
		usage();

	if (dbi.type == DT_DUMB) {
		dbi.dumbfd = open(dbi.path, O_RDWR | O_CREAT | O_SYNC, S_IRWXU);
		if (dbi.dumbfd < 0) {
			perror("open");
			goto close;
		}
	}
#ifdef WITH_SQLITE
       	else if (dbi.type == DT_SQLITE) {
		char *err_msg;
		char create_tbl_stmt[128];
		char *journal_wal_stmt = "PRAGMA journal_mode = WAL";
		char *excl_lock_stmt = "PRAGMA locking_mode = EXCLUSIVE";

		/* open db file and get handle */
		ret = sqlite3_open_v2(dbi.path, &dbi.sql_conn,
			SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | 
			SQLITE_OPEN_WAL, NULL);
		if (SQLITE_OK != ret) {
			D("sqlite3_open_v2 failed");
			goto close;
		}
		/* enable wal */
		ret = sqlite3_exec(dbi.sql_conn, journal_wal_stmt,
			       	NULL, NULL, &err_msg);
		if (SQLITE_OK != ret)
			goto error;
		/* avoiding shared memory cuts 4 us */
		ret = sqlite3_exec(dbi.sql_conn, excl_lock_stmt,
			       	NULL, NULL, &err_msg);
		if (SQLITE_OK != ret)
			goto error;

		/* create a table */
		snprintf(create_tbl_stmt, sizeof(create_tbl_stmt),
			       	"CREATE TABLE IF NOT EXISTS %s "
			       	"(id INTEGER, "
				"name BINARY(2048))", SQLDBTABLE);
		ret = sqlite3_exec(dbi.sql_conn, create_tbl_stmt,
				NULL, NULL, &err_msg);
		if (SQLITE_OK != ret ) {
error:
			D("%s", err_msg);
			sqlite3_free(err_msg);
			err_msg = NULL;
			goto close;
		}
	}
#endif /* WITH_SQLITE */
	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd == -1) {
		perror("epoll_create1");
		goto close;
	}

	sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sd < 0) {
		perror("socket");
		goto close_ep;
	}
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		goto close_socket;
	}
	if (setsockopt(sd, SOL_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		goto close_socket;
	}
	if (ioctl(sd, FIONBIO, &on) < 0) {
		perror("ioctl");
		goto close_socket;
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		goto close_socket;
	}

	if (listen(sd, SOMAXCONN) != 0) {
		perror("listen");
		goto close_socket;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = POLLIN;
	ev.data.fd = sd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, sd, &ev);

	signal(SIGINT, sig_h);
	signal(SIGHUP, sig_h);

	stat_eps = stat_nfds = stat_maxnfds = 0;
	stat_vnfds = 0;
	stat_minnfds = ~0;
	while (!do_abort) {
		int i, nfd;
		nfd = epoll_wait(epfd, evts, MAXCONNECTIONS, eptimeout);
#if 0
		if (nfd > 0) {
			stat_eps++;
			stat_nfds += nfd;
			stat_maxnfds = nfd > stat_maxnfds ? nfd : stat_maxnfds;
			stat_minnfds = nfd < stat_minnfds ? nfd : stat_minnfds;
			stat_vnfds += (uint64_t)nfd * nfd;
		}
		if (stat_eps > 20000 || stat_nfds > 200000) {
			double mean = (double)stat_nfds / stat_eps;
			double var = ((double)stat_vnfds / stat_eps) - (mean * mean);
			fprintf(stderr, "epfds: av %lf max %u min %u var %f, eps %u\n",
				       	mean, stat_maxnfds, stat_minnfds, var,
				       	stat_eps);
			stat_eps = stat_nfds = stat_maxnfds = 0;
			stat_vnfds = 0;
			stat_minnfds = ~0;
		}
#endif /* 0 */

		for (i = 0; i < nfd; i++) {
			if (evts[i].data.fd == sd) {
				if (do_accept(sd, epfd) < 0)
					goto close_socket;
			} else
				do_established(evts[i].data.fd, msglen, &dbi);
		}

	}

close_socket:
	close(sd);
close_ep:
	close(epfd);
close:
	close_db(&dbi);
	return (0);
}

