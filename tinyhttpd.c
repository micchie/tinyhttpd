#include <stdio.h>
#include <inttypes.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
#ifdef WITH_STACKMAP
#include <net/netmap.h>
#include <net/netmap_user.h>
#define STMNAME	"stack:0"
#define STMNAME_MAX	32
#endif /* WITH_STACKMAP */

struct dbinfo {
	int	type;
	char 	*path;
	union {
#ifdef WITH_SQLITE
		sqlite3 *sql_conn;
#endif
		int	dumbfd;
	};
	int mmap;
	char *paddr;
	int cur;
	union {
		int maplen;
		int maxlen;
	};
#define DBI_FLAGS_FDSYNC	0x1
#define DBI_FLAGS_READPMEM	0x2
#define DBI_FLAGS_PASTE		0x4
#define DBI_FLAGS_BATCH		0x8
	int flags;
	char ifname[IFNAMSIZ+8]; /* stackmap ifname (also used as indicator) */
#ifdef WITH_STACKMAP
	struct nm_desc *nmd;
	struct nm_ifreq ifreq;
	char *rxbuf;
	char *txbuf;
	uint64_t pst_ent; /* 32 bit buf_idx + 16 bit off + 16 bit len */
	uint16_t txlen; // slot length
	uint16_t rxlen;
	uint16_t voff; // virt_hdr_len
	uint16_t soff;
#endif /* WITH_STACKMAP */
} dbi;

//static struct timespec ts = {0, 0};
static inline void
clflush(volatile void *p)
{
	//nanosleep(&ts, NULL);
	asm volatile ("clflush (%0)" :: "r"(p));
}
static __inline void
mfence(void)
{
	__asm __volatile("mfence" : : : "memory");
}

#define CACHE_LINE_SIZE	64 /* XXX */

#define MAXCONNECTIONS 2048
#define MAXQUERYLEN 65535
#define MAXDUMBSIZE	204800
#ifdef WITH_STACKMAP
#define TCPIP_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) \
	+ sizeof(struct tcphdr) + 12)

struct paste_hdr {
	char ifname[IFNAMSIZ + 64];
	char path[256];
	uint32_t buf_ofs;
};
#endif /* WITH_STACKMAP */

enum { DT_NONE=0, DT_DUMB, DT_SQLITE};
const char *SQLDBTABLE = "tinytable";

#ifndef D
#define D(fmt, ...) \
	printf(""fmt"\n", ##__VA_ARGS__)
#endif

static int do_abort = 0;
#if 0
static u_int stat_nfds;
static u_int stat_eps;
static u_int stat_maxnfds;
static u_int stat_minnfds;
static uint64_t stat_vnfds;
#endif /* 0 */

void
close_db(struct dbinfo *dbip)
{
	struct stat st;
	const char *path = dbip->path;
#ifdef WITH_SQLITE
	char path_wal[64], path_shm[64];
#endif

	/* close reference */
	if (dbip->type == DT_DUMB) {
		if (dbip->mmap)
			if (munmap(dbip->paddr, dbip->maplen))
				perror("munmap");
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
	char buf[MAXQUERYLEN];
	char *rxbuf, *txbuf;
#ifdef WITH_SQLITE
	static u_int seq = 0;
#endif
	ssize_t len;
       
	rxbuf = txbuf = buf;
	if (dbi->flags & DBI_FLAGS_READPMEM) {
		len = dbi->mmap; /* page size */
		goto direct;
	}
#ifdef WITH_STACKMAP
	if (dbi->nmd) {
		rxbuf = dbi->rxbuf;
		txbuf = dbi->txbuf;
		len = dbi->rxlen;
	} else
#endif /* WITH_STACKMAP */
	{
	len = read(fd, rxbuf, sizeof(buf));
	if (len == 0) {
		close(fd);
		return 0;
	} else if (len < 0) {
		perror("read");
		return -1;
	}
	}

	if (strncmp(rxbuf, "GET ", strlen("GET ")) == 0) {
		len = generate_httphdr(msglen, txbuf, NULL);
	} else if (strncmp(rxbuf, "POST ", strlen("POST ")) == 0) {
		if (dbi->type == DT_DUMB) {
direct:
#ifdef WITH_STACKMAP
			if (dbi->flags & DBI_FLAGS_PASTE) {
				char *p;
				int i;

				if (dbi->cur + sizeof(dbi->pst_ent) > 
				    dbi->maplen - sizeof(struct paste_hdr))
					dbi->cur = 0;

				p = dbi->paddr + sizeof(struct paste_hdr) + 
					dbi->cur;
				if (!(dbi->flags & DBI_FLAGS_BATCH)) {
					*(uint64_t *)p = dbi->pst_ent;
					clflush(p);
				}
				/* also flush data buffer */
				for (i = 0; i < len; i += CACHE_LINE_SIZE) {
					clflush(rxbuf + i);
				}
				mfence();
				dbi->cur += sizeof(dbi->pst_ent);
			} else
#endif /* WITH_STACKMAP */
			if (dbi->mmap) {
				int d;
				char *p;

				d = (len & (dbi->mmap-1));
				if (d)
					len += dbi->mmap - d;
				if (dbi->cur + len  > dbi->maplen)
					dbi->cur = 0;
				p = dbi->paddr + dbi->cur;
				if (dbi->flags & DBI_FLAGS_READPMEM) {
					int alen;
					alen = read(fd, p, len);
					if (alen < 0) {
						perror("read");
						return -1;
					} else if (alen == 0) {
						close(fd);
						return 0;
					}
					if (strncmp(p, "GET ", 
					    strlen("GET ")) == 0)
						goto gen_httpok;
					else if (strncmp(p, "POST ",
					         strlen("POST ")))
						return -1; /* next pos stays */

				} else
					memcpy(p, rxbuf, len);
				if (!(dbi->flags & DBI_FLAGS_BATCH)) {
					int j;
				    	for (j=0;j<len;j+=CACHE_LINE_SIZE) {
					clflush(p + j);
				    	}
					mfence();
					//if (msync(p, len, MS_SYNC))
					//	perror("msync");
				}
				dbi->cur += len;
			} else {
				len = write(dbi->dumbfd, rxbuf, len);
				if (len < 0)
					perror("write");
				else if ((dbi->flags & DBI_FLAGS_FDSYNC ?
				    fdatasync(dbi->dumbfd) :
				    fsync(dbi->dumbfd)) < 0)
					fprintf(stderr, "failed in f(data)sync\n");
				dbi->cur += len;
				if (dbi->cur > dbi->maxlen) {
					lseek(dbi->dumbfd, 0, SEEK_SET);
					dbi->cur = 0;
				}
			}
		}
#if WITH_SQLITE
		else if (dbi->type == DT_SQLITE) {
			char query[MAXQUERYLEN];
			int ret;
			char *err_msg;

			snprintf(query, sizeof(query),
				"BEGIN TRANSACTION; insert into %s values (%d, '%s'); COMMIT;",
			       	SQLDBTABLE, seq++, rxbuf);
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
gen_httpok:
		len = generate_httphdr(msglen, txbuf, NULL);
	}
#ifdef WITH_STACKMAP
	if (!dbi->nmd)
#endif /* WITH_STACKMAP */
		write(fd, txbuf, len);
#ifdef WITH_STACKMAP
	else
		dbi->txlen = len;
#endif /* WITH_STACKMAP */
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
	int polltimeo = 0;
	struct dbinfo dbi;
#ifdef WITH_SQLITE
	int ret = 0;
#endif /* WITH_SQLITE */
	int i, nfd = 0; /* XXX initialize only to avoid warning  */

	bzero(&dbi, sizeof(dbi));
	dbi.type = DT_NONE;
	dbi.maxlen = MAXDUMBSIZE;

	while ((ch = getopt(argc, argv, "p:l:bmd:DNi:PB")) != -1) {
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
		case 'b': /* give the epoll_wait() timeo argument -1 */
			polltimeo = -1;
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
		case 'm':
			dbi.mmap = getpagesize();
			break;
		case 'D':
			dbi.flags |= DBI_FLAGS_FDSYNC;
			break;
		case 'N':
			dbi.flags |= DBI_FLAGS_READPMEM;
			break;
		case 'B':
			dbi.flags |= DBI_FLAGS_BATCH;
			break;
		case 'i':
			strncpy(dbi.ifname, optarg, sizeof(dbi.ifname));
			break;
		case 'P': /* PASTE */
			dbi.flags |= DBI_FLAGS_PASTE;
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

	if (dbi.flags & DBI_FLAGS_READPMEM) {
		if (!((dbi.type == DT_DUMB) && dbi.mmap)) {
			fprintf(stderr, "READPMEM must use dumb db and mmap\n");
			usage();
		}
	}
	if (dbi.type == DT_DUMB) {
		dbi.dumbfd = open(dbi.path, O_RDWR | O_CREAT, S_IRWXU);
		if (dbi.dumbfd < 0) {
			perror("open");
			goto close;
		}
		if (dbi.mmap) {
			dbi.maplen = MAXDUMBSIZE; /* XXX is size ok? */
			if (lseek(dbi.dumbfd, dbi.maplen - 1, SEEK_SET) < 0) {
				perror("lseek");
				goto close;
			}
			if (write(dbi.dumbfd, "", 1) != 1) {
				perror("write");
				goto close;
			}
			dbi.paddr = mmap(0, dbi.maplen, PROT_WRITE,
				       	MAP_SHARED | MAP_FILE, dbi.dumbfd, 0);
			if (dbi.paddr == MAP_FAILED) {
				perror("mmap");
				goto close;
			}
#ifdef WITH_STACKMAP
			if (dbi.flags & DBI_FLAGS_PASTE) {
				/* write WAL header */
				struct paste_hdr *ph;

				ph = (struct paste_hdr *)dbi.paddr;
				strncpy(ph->ifname, dbi.ifname,
						sizeof(dbi.ifname));
				strncpy(ph->path, dbi.ifname, strlen(dbi.path));
			}
#endif /* WITH_STACKMAP */
		}
	}
#ifdef WITH_SQLITE
       	else if (dbi.type == DT_SQLITE) {
		char *err_msg;
		char create_tbl_stmt[128];
		char *journal_wal_stmt = "PRAGMA journal_mode = WAL";
		char *excl_lock_stmt = "PRAGMA locking_mode = EXCLUSIVE";
		char *synchronous_stmt = "PRAGMA synchronous = FULL";

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
		/* flush every commit onto the disk */
		ret = sqlite3_exec(dbi.sql_conn, synchronous_stmt,
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
#ifdef WITH_STACKMAP
	if (dbi.ifname[0]) {
		char nm_name[STMNAME_MAX+1];
		//char *p;
		struct nmreq req;
		struct nm_ifreq *ifreq = &dbi.ifreq;

		if (strlen(STMNAME) + 1 + strlen(dbi.ifname) > STMNAME_MAX) {
			D("too long name %s", dbi.ifname);
			goto close_socket;
		}
		strcat(strcat(strcpy(nm_name, STMNAME), "+"), dbi.ifname);
		dbi.nmd = nm_open(nm_name, NULL, 0, NULL);
		if (!dbi.nmd) {
			D("Unable to open %s: %s", dbi.ifname, strerror(errno));
			goto close_socket;
		}

		/* pre-initialize ifreq for accept() */
		bzero(ifreq, sizeof(*ifreq));
		strncpy(ifreq->nifr_name, STMNAME, sizeof(ifreq->nifr_name));

		/* ask vnet_hdr_len */
		bzero(&req, sizeof(req));
		bcopy(dbi.nmd->req.nr_name, req.nr_name, sizeof(req.nr_name));
		req.nr_version = NETMAP_API;
		req.nr_cmd = NETMAP_VNET_HDR_GET;
		if (ioctl(dbi.nmd->fd, NIOCREGIF, &req)) {
			D("Unable to get header length");
			goto close_nmd;
		}
		dbi.voff = req.nr_arg1;
		dbi.soff = TCPIP_OFFSET;
		D("nm_open() %s done (offset %u)", nm_name, dbi.voff + dbi.soff);
	} else
#endif /* WITH_STACKMAP */
	{
	bzero(&ev, sizeof(ev));
	ev.events = POLLIN;
	ev.data.fd = sd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, sd, &ev);
	}

	signal(SIGINT, sig_h);
	signal(SIGHUP, sig_h);

#if 0
	stat_eps = stat_nfds = stat_maxnfds = 0;
	stat_vnfds = 0;
	stat_minnfds = ~0;
#endif /* 0 */
	while (!do_abort) {
		/* fetch events */
#ifdef WITH_STACKMAP
		if (dbi.ifname[0]) {
			struct nm_desc *nmd = dbi.nmd;
			struct netmap_if *nifp = nmd->nifp;
			struct pollfd pfd[2];
			u_int first_rx_ring = nmd->first_rx_ring;
			u_int last_rx_ring = nmd->last_rx_ring;

			pfd[0].fd = nmd->fd;
			pfd[0].events = POLLIN | POLLOUT;
			pfd[1].fd = sd;
			pfd[1].events = POLLIN | POLLOUT;

			i = poll(pfd, 2, polltimeo);
			if (i < 0) {
				perror("poll");
				goto close_nmd;
			}

			/*
			 * check the listen socket
			 */
			if (pfd[1].revents & POLLIN) {
				struct sockaddr_storage tmp;
				struct nm_ifreq *ifreq = &dbi.ifreq;
				int newfd;
				socklen_t len = sizeof(tmp);

				newfd = accept(pfd[1].fd, (struct sockaddr *)
					    &tmp, &len);
				if (newfd < 0) {
					perror("accept");
					/* ignore this socket */
					goto accepted;
				}
				memcpy(ifreq->data, &newfd, sizeof(newfd));
				if (ioctl(nmd->fd, NIOCCONFIG, ifreq)) {
					perror("ioctl");
					close(newfd);
					close(pfd[1].fd);
					/* be conservative to this error... */
					goto close_nmd;
				}
				D("new connection");
			}
accepted:
			/*
			 * check accepted sockets
			 */
			if (!(pfd[0].revents & POLLIN))
				continue;

			for (i = first_rx_ring; i <= last_rx_ring; i++) {
				struct netmap_ring *rxr, *txr;
				struct netmap_slot *rxs;
				u_int txcur, txlim, rxcur, rx;

				rxr = NETMAP_RXRING(nifp, i);
				txr = NETMAP_TXRING(nifp, i);

				txcur = txr->cur;
				rxcur = rxr->cur;
				/* XXX 1 reqequest triggers 1 response */
				txlim = nm_ring_space(txr);
				if (txlim > nm_ring_space(rxr)) {
					txlim = nm_ring_space(rxr);
				}
				for (rx = 0; rx < txlim; rx++) {
					struct netmap_slot *txs;
					char *p;

					rxs = &rxr->slot[rxcur];
					p = NETMAP_BUF(rxr, rxs->buf_idx);
					p += rxs->offset;

					dbi.rxbuf = p;
					dbi.rxlen = rxs->len;
					txs = &txr->slot[txcur];
					dbi.txbuf =
						NETMAP_BUF(txr, txs->buf_idx);
					dbi.txbuf += dbi.voff + dbi.soff;
					dbi.txlen = 0; // just initialize
					dbi.pst_ent = (uint64_t)
						rxs->buf_idx << 32 |
						dbi.voff << 16 | rxs->len;
					do_established(-1, msglen, &dbi);
					txs->len = dbi.txlen + dbi.voff + dbi.soff;
					txs->offset = TCPIP_OFFSET;
					txs->fd = rxs->fd;
					txcur = nm_ring_next(txr, txcur);
					txlim--;
					rxcur = nm_ring_next(rxr, rxcur);
				}
				txr->head = txr->cur = txcur;
				rxr->head = rxr->cur = rxcur;

				/* No batch support yet */
			}

		} else
#endif /* WITH_STACKMAP */
	       	{
			nfd = epoll_wait(epfd, evts, MAXCONNECTIONS, polltimeo);
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
		}
		/* process events */
		for (i = 0; i < nfd; i++) {
			if (evts[i].data.fd == sd) {
				if (do_accept(sd, epfd) < 0)
					goto close_socket;
			} else
				do_established(evts[i].data.fd, msglen, &dbi);
		}

	}

#ifdef WITH_STACKMAP
close_nmd:
	nm_close(dbi.nmd);
#endif /* WITH_STACKMAP */
close_socket:
	close(sd);
close_ep:
	if (dbi.ifname[0])
		close(epfd);
close:
	close_db(&dbi);
	return (0);
}

