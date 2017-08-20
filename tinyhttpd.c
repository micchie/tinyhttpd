/*
 * Copyright (C) 2016-2017 Michio Honda. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#define _GNU_SOURCE
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
#include <stddef.h>	// typeof
#include <x86intrin.h>
#include <time.h>

#include <sys/ioctl.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>	// clock_gettime()
#include <netinet/tcp.h>
#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif /* WITH_SQLITE */
#include <pthread.h>
#ifdef WITH_STACKMAP
#include <net/netmap.h>
#include <net/netmap_user.h>

#include<sched.h>
#include "nmlib.h"

#define container_of(ptr, type, member) ({          \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})

#define STMNAME	"stack:0"
#define STMNAME_MAX	64
#define DEFAULT_EXT_MEM         "/mnt/pmem/netmap_mem"
#define EXTRA_BUF_NUM	1000
//#define DEFAULT_EXT_MEM_SIZE    1000000000 /* approx. 1 GB */
#define DEFAULT_EXT_MEM_SIZE    400000000 /* approx. 400 MB */
#endif /* WITH_STACKMAP */

#define MAX_PAYLOAD	1400
#define min(a, b) (((a) < (b)) ? (a) : (b)) 

#ifndef D
#define D(fmt, ...) \
	printf(""fmt"\n", ##__VA_ARGS__)
#endif

#define MAXCONNECTIONS 2048
#define MAXQUERYLEN 32767
#define MAXDUMBSIZE	204800

#define MAX_HTTPLEN	65535
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
	int fdel;
	union {
		int maplen;
		int maxlen;
	};
#define DBI_FLAGS_FDSYNC	0x1
#define DBI_FLAGS_READPMEM	0x2
#define DBI_FLAGS_PASTE		0x4
	int flags;
	char ifname[IFNAMSIZ + 64]; /* stackmap ifname (also used as indicator) */
#ifdef WITH_STACKMAP
	struct nm_garg g;
	struct nm_ifreq ifreq;
	int extmem_fd;
#endif /* WITH_STACKMAP */
	int sd;
	char *http;
	int httplen;
	int msglen;
};

/* XXX DB-related info should also be moved here */
struct thpriv {
	struct nm_garg *g;
	char *rxbuf;
	char *txbuf;
	int cur;
	uint64_t pst_ent;
	uint16_t txlen;
	uint16_t rxlen;
	struct nm_ifreq ifreq;
	struct epoll_event evts[MAXCONNECTIONS];
	uint32_t extra[EXTRA_BUF_NUM];
	uint32_t extra_cur;
	uint32_t extra_num;
};

/* overflow some */
static inline void
set_rubbish(char *buf, int len)
{
	static char *r = "A sample content of the tiny HTTP server. Nothing is meaningful"; // 64 characters
	memcpy(buf, r, min(len, 64));
}

//static struct timespec ts = {0, 0};
#if 0
static inline void
clflush(volatile void *p)
{
	//nanosleep(&ts, NULL);
	asm volatile ("clflush (%0)" :: "r"(p));
}

/* need ctrs.h */
static inline void
clflushx(volatile void *p, long ns)
{
	if (ns) {
		struct timespec cur, w;

		if (unlikely(ns > 10000 || ns < 100)) {
			RD(1, "ns %ld may not be apprepriate", ns);
		}
		clock_gettime(CLOCK_REALTIME, &cur);
		for (;;) {
			clock_gettime(CLOCK_REALTIME, &w);
			w = timespec_sub(w, cur);
			if (unlikely(w.tv_sec < 0)) // maybe too short interval
				continue;
			else if (w.tv_nsec >= ns || w.tv_sec > 0)
				break;
		}
	}
	clflush(p);
	return;
}
#endif /* 0 */

/* taken from NOVA */
#define _mm_clflush(addr)\
		asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#ifndef NO_CLFLUSHOPT
#define _mm_clflushopt(addr)\
	asm volatile(".byte 0x66; clflush %0" : "+m" (*(volatile char *)(addr)))
#else
#define _mm_clflushopt _mm_clflush
#endif
	
#define _mm_clwb(addr)\
		asm volatile(".byte 0x66; xsaveopt %0" : "+m" (*(volatile char *)(addr)))

static inline void
wait_ns(long ns)
{
	struct timespec cur, w;

	if (unlikely(ns > 10000 || ns < 100)) {
		RD(1, "ns %ld may not be apprepriate", ns);
	}
	clock_gettime(CLOCK_REALTIME, &cur);
	for (;;) {
		clock_gettime(CLOCK_REALTIME, &w);
		w = timespec_sub(w, cur);
		if (unlikely(w.tv_sec < 0)) // maybe too short interval
			continue;
		else if (w.tv_nsec >= ns || w.tv_sec > 0)
			break;
	}
}

static __inline void
mfence(long delay)
{
	if (delay > 0)
		wait_ns(delay);
	//__asm __volatile("mfence" : : : "memory");
	_mm_mfence();
}

#define CACHE_LINE_SIZE	64 /* XXX */

#ifdef WITH_STACKMAP
struct paste_hdr {
	char ifname[IFNAMSIZ + 64];
	char path[256];
	uint32_t buf_ofs;
};
#endif /* WITH_STACKMAP */

enum { DT_NONE=0, DT_DUMB, DT_SQLITE};
const char *SQLDBTABLE = "tinytable";

#if 0
static u_int stat_nfds;
static u_int stat_eps;
static u_int stat_maxnfds;
static u_int stat_minnfds;
static uint64_t stat_vnfds;
#endif /* 0 */

static char *
_do_mmap(int fd, int len)
{
	char *p;

	if (lseek(fd, len -1, SEEK_SET) < 0) {
		perror("lseek");
		return NULL;
	}
	if (write(fd, "", 1) != 1) {
		perror("write");
		return NULL;
	}
	p = mmap(0, len, PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	return p;
}

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

/* fill rubbish if data is NULL */
static int
copy_to_nm(struct netmap_ring *ring, int virt_header, const char *data,
		int len, int off0, int off, int fd)
{
	u_int const tail = ring->tail;
	u_int cur = ring->cur;
	u_int copied = 0;
	int space = nm_ring_space(ring);

	if (unlikely(space * MAX_PAYLOAD < len)) {
		RD(1, "no space (%d slots)", space);
		return -1;
	}

	/* XXX adjust to real offset */
	off0 += virt_header;
	off += virt_header;

	while (likely(cur != tail) && copied < len) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF(ring, slot->buf_idx) + off0;
		int l = min(MAX_PAYLOAD, len - copied);

		if (data)
			nm_pkt_copy(data + copied, p, l);
		else
			set_rubbish(p, l);
		slot->len = off0 + l;
		slot->offset = off - virt_header; // XXX change API...
		slot->fd = fd;
		copied += l;
		off0 = off;
		cur = nm_ring_next(ring, cur);
	}
	ring->cur = ring->head = cur;
	return len;
}

ssize_t
generate_httphdr(ssize_t content_length, char *buf)
{
	char *p = buf;
	/* From nginx */
	static char *lines[5] = {"HTTP/1.1 200 OK\r\n",
	 "Content-Length: ",
	 "Connection: keep-alive\r\n\r\n"};
	ssize_t l, l0, l1, l2;

	l0 = strlen(lines[0]);
	p = mempcpy(p, lines[0], l0);
	l1 = strlen(lines[1]);
	p = mempcpy(p, lines[1], l1);
	l = sprintf(p, "%lu\r\n", content_length);
	p += l;
	l2 = strlen(lines[2]);
	p = mempcpy(p, lines[2], l2);
	return p - buf;
}

int
generate_http(int content_length, char *buf, char *content)
{
	int hlen;

	hlen = generate_httphdr(content_length, buf);
	if (content == NULL)
		set_rubbish(buf + hlen, content_length);
	else
		memcpy(buf + hlen, content, content_length);
	return hlen + content_length;

}

int
generate_http_nm(int content_length, struct netmap_ring *ring, int virt_header,
		int off, int fd, char *content)
{
	int hlen, len, cur = ring->cur;
	struct netmap_slot *slot = &ring->slot[cur];
	char *p = NETMAP_BUF(ring, slot->buf_idx) + virt_header + off;

	hlen = generate_httphdr(content_length, p);
	len = copy_to_nm(ring, virt_header, content, content_length,
			off + hlen, off, fd);
	return len < content_length ? -1 : hlen + len;
}

static int
parse_post(char *post, int *coff)
{
	int clen;
	char *pp, *p = strstr(post, "Content-Length: ");
	
	if (unlikely(!p))
		return -1;
	pp = p + 16; // "Content-Length: "
	clen = atoi(pp);
	if (unlikely(!clen))
		return -1;
	pp = strstr(pp, "\r\n\r\n");
	if (unlikely(!pp))
		return -1;
	pp += 4;
	*coff = pp - post;
	return clen;
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

/* We assume GET/POST appears in the beginning of netmap buffer */
int
process_nm_ring(struct nm_targ *targ, int ring_nr)
{
	struct nm_garg *g = targ->g;
	struct dbinfo *dbi = container_of(g, struct dbinfo, g);
	struct thpriv *tp = targ->td_private;
	ssize_t msglen = dbi->msglen;

	struct netmap_ring *rxr = NETMAP_RXRING(targ->nmd->nifp, ring_nr);
	struct netmap_ring *txr = NETMAP_TXRING(targ->nmd->nifp, ring_nr);
	u_int const rxtail = rxr->tail;
	u_int rxcur = rxr->cur;

	for (; rxcur != rxtail; rxcur = nm_ring_next(rxr, rxcur)) {
		struct netmap_slot *rxs = &rxr->slot[rxcur];
		char *rxbuf;
		int o = IPV4TCP_HDRLEN;
		int len = rxs->len;

		rxbuf = NETMAP_BUF(rxr, rxs->buf_idx)
			+ g->virt_header + rxs->offset;

		if (!strncmp(rxbuf, "POST ", strlen("POST "))) {
			int coff, clen = parse_post(rxbuf, &coff);

			if (clen < 0)
				continue;
			if (dbi->type == DT_DUMB) {
				if (dbi->flags & DBI_FLAGS_PASTE) {
					char *p;
					u_int i;
					int plen = sizeof(tp->pst_ent);
					int phdrlen = sizeof(struct paste_hdr);

					if (tp->cur + plen >
					    dbi->maplen - phdrlen)
						tp->cur = 0;

					/* log position */
					p = dbi->paddr + phdrlen + tp->cur;

					/* flush data buffer */
					for (i = 0; i < len;
					    i += CACHE_LINE_SIZE) {
						_mm_clflushopt(rxbuf + i);
					}
					mfence(dbi->fdel);

					/* flush log */
					*(uint64_t *)p = tp->pst_ent;
					_mm_clflushopt(p);
					mfence(dbi->fdel);

					/* swap out buffer */
					i = rxs->buf_idx;
					rxs->buf_idx = tp->extra[tp->extra_cur];
					rxs->flags |= NS_BUF_CHANGED;
					tp->extra[tp->extra_cur] = i;
					tp->extra_cur++;
					if (unlikely(tp->extra_cur ==
					    tp->extra_num)) {
						tp->extra_cur = 0;
					}
					tp->cur += plen;
				} else if (dbi->mmap) {
					int d, j = 0;
					char *p;

					d = (len & (dbi->mmap - 1));
					if (d)
						len += dbi->mmap - d;
					if (tp->cur + len > dbi->maplen)
						tp->cur = 0;
					p = dbi->paddr + dbi->cur;
					memcpy(p, rxbuf, len);

					for (; j < len; j += CACHE_LINE_SIZE) {
						_mm_clflushopt(p + j);
					}
					mfence(dbi->fdel);
					tp->cur += len;
				}
			}
			goto get;
		} else if (strncmp(rxbuf, "GET ", strlen("GET ")) == 0) {
get:
			if (dbi->httplen) { // use cache
				char *http = dbi->http;
				int len = dbi->httplen;

				if (copy_to_nm(txr, g->virt_header, http, len,
						o, o, rxs->fd) < len) {
					continue;
				}
			} else {
				if (generate_http_nm(msglen, txr,
				    g->virt_header, o, rxs->fd, NULL) < 0)
					continue;
			}
		}
	}
	rxr->head = rxr->cur = rxcur;
	return 0;
}

int do_established(int fd, ssize_t msglen, struct nm_targ *targ)
{
	struct dbinfo *dbi = container_of(targ->g, struct dbinfo, g);
	char buf[MAXQUERYLEN];
	char *rxbuf, *txbuf;
#ifdef WITH_SQLITE
	static u_int seq = 0;
#endif
	ssize_t len;
	struct thpriv *tp = targ->td_private;

	rxbuf = txbuf = buf;
	if (dbi->flags & DBI_FLAGS_READPMEM) {
		len = dbi->mmap; /* page size */
		goto direct;
	}
#ifdef WITH_STACKMAP
	if (dbi->g.nmd) {
		rxbuf = tp->rxbuf;
		txbuf = tp->txbuf;
		len = tp->rxlen;
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
		if (!dbi->httplen) {
			len = generate_http(msglen, txbuf, NULL);
		} else {
			len = dbi->httplen;
			memcpy(txbuf, dbi->http, len);
		}
	} else if (strncmp(rxbuf, "POST ", strlen("POST ")) == 0) {
		if (dbi->type == DT_DUMB) {
direct:
#ifdef WITH_STACKMAP
			if (dbi->flags & DBI_FLAGS_PASTE) {
				char *p;
				int i;

				if (tp->cur + sizeof(tp->pst_ent) > 
				    dbi->maplen - sizeof(struct paste_hdr))
					tp->cur = 0;

				p = dbi->paddr + sizeof(struct paste_hdr) + 
					tp->cur;
				*(uint64_t *)p = tp->pst_ent;
				_mm_clflushopt(p);
				mfence(dbi->fdel);
				/* also flush data buffer */
				for (i = 0; i < len; i += CACHE_LINE_SIZE) {
					_mm_clflushopt(rxbuf + i);
				}
				mfence(dbi->fdel);
				tp->cur += sizeof(tp->pst_ent);
			} else
#endif /* WITH_STACKMAP */
			if (dbi->mmap) {
				int d, j;
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

				} else {
					memcpy(p, rxbuf, len);
				}
				for (j=0;j<len;j+=CACHE_LINE_SIZE) {
					_mm_clflushopt(p + j);
				}
				mfence(dbi->fdel);
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
		len = generate_http(msglen, txbuf, NULL);
	} else {
		len = 0;
	}
#ifdef WITH_STACKMAP
	if (!dbi->g.nmd)
#endif /* WITH_STACKMAP */
		write(fd, txbuf, len);
#ifdef WITH_STACKMAP
	else
		tp->txlen = len;
#endif /* WITH_STACKMAP */
	return 0;
}

#define container_of(ptr, type, member) ({                      \
		      const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		      (type *)( (char *)__mptr - offsetof(type,member) );})

#ifdef WITH_STACKMAP
static void *
_worker(void *data)
{
	struct nm_targ *targ = (struct nm_targ *) data;
	struct nm_garg *g = targ->g;
	struct pollfd pfd[2] = {{ .fd = targ->fd }};
	struct dbinfo *dbip = container_of(g, struct dbinfo, g);
	int msglen = dbip->msglen;
	struct thpriv *tp = targ->td_private;

	/* import extra buffers */
	if (g->dev_type == DEV_NETMAP) {
		struct netmap_if *nifp = targ->nmd->nifp;
		struct netmap_ring *any_ring = NETMAP_RXRING(nifp, 0);
		uint32_t i, next = nifp->ni_bufs_head;

		for (i = 0; i < EXTRA_BUF_NUM && next; i++) {
			tp->extra[i] = next;
			next = *(uint32_t *)NETMAP_BUF(any_ring, next);
		}
		tp->extra_num = i;
		D("imported %d extra buffers", i);

		tp->ifreq = dbip->ifreq;
	}

	if (g->dev_type == DEV_SOCKET) {
		struct epoll_event ev;

		targ->fd = epoll_create1(EPOLL_CLOEXEC);
		if (targ->fd < 0) {
			perror("epoll_create1");
			targ->cancel = 1;
			goto quit;
		}

		bzero(&ev, sizeof(ev));
		ev.events = POLLIN;
		ev.data.fd = dbip->sd;
		if (epoll_ctl(targ->fd, EPOLL_CTL_ADD, ev.data.fd, &ev)) {
			perror("epoll_ctl");
			targ->cancel = 1;
			goto quit;
		}
	}

	while (!targ->cancel) {
		if (g->dev_type == DEV_NETMAP) {
			u_int first_rx_ring = targ->nmd->first_rx_ring;
			u_int last_rx_ring = targ->nmd->last_rx_ring;
			int i;

			pfd[0].fd = targ->fd;
			pfd[0].events = POLLIN;
			pfd[1].fd = dbip->sd;
			pfd[1].events = POLLIN;

			i = poll(pfd, 2, g->polltimeo);
			if (i < 0) {
				perror("poll");
				goto quit;
			}
			/*
			 * check the listen socket
			 */
			if (pfd[1].revents & POLLIN) {
				struct sockaddr_storage tmp;
				struct nm_ifreq *ifreq = &tp->ifreq;
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
				if (ioctl(targ->fd, NIOCCONFIG, ifreq)) {
					perror("ioctl");
					close(newfd);
					close(pfd[1].fd);
					/* be conservative to this error... */
					goto quit;
				}
			}
accepted:
			/*
			 * check accepted sockets
			 */
			if (!(pfd[0].revents & POLLIN)) {
				continue;
			}

			for (i = first_rx_ring; i <= last_rx_ring; i++) {

				process_nm_ring(targ, i);
#if 0
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
					int txoff;
				       
					txoff = g->virt_header + IPV4TCP_HDRLEN;

					rxs = &rxr->slot[rxcur];
					p = NETMAP_BUF(rxr, rxs->buf_idx);
					p += g->virt_header;
					p += rxs->offset;

					tp->rxbuf = p;
					tp->rxlen = rxs->len;
					txs = &txr->slot[txcur];
					tp->txbuf =
						NETMAP_BUF(txr, txs->buf_idx);
					tp->txbuf += txoff;
					tp->txlen = 0; // just initialize
					tp->pst_ent = (uint64_t)
					    rxs->buf_idx << 32 |
					    g->virt_header << 16 | rxs->len;
					do_established(-1, msglen, targ);
					if (tp->txlen) {
						txs->len = tp->txlen + txoff;
						txs->offset = IPV4TCP_HDRLEN;
						txs->fd = rxs->fd;
					} else {
						txs->len = 0;
					}
					txcur = nm_ring_next(txr, txcur);
					txlim--;
					rxcur = nm_ring_next(rxr, rxcur);
				}
				txr->head = txr->cur = txcur;
				rxr->head = rxr->cur = rxcur;
#endif /* 0 */

				/* No batch support yet */
			}
		} else if (g->dev_type == DEV_SOCKET) {
			int i, nfd, epfd = targ->fd;
			int timeo = g->polltimeo;
			int sd = dbip->sd;
			struct epoll_event *evts = tp->evts;

			nfd = epoll_wait(epfd, evts, MAXCONNECTIONS, timeo);
			if (nfd < 0) {
				perror("epoll_wait");
				goto quit;
			}
			for (i = 0; i < nfd; i++) {
				int fd = evts[i].data.fd;

				if (fd == sd) {
					if (do_accept(sd, epfd) < 0)
						goto quit;
				} else {
					do_established(fd, msglen, targ);
				}
			}
		}
	}
quit:
	return (NULL);
}
#endif /* WITH_STACKMAP */

int
main(int argc, char **argv)
{
	int ch;
	int sd;
	struct sockaddr_in sin;
	const int on = 1;
	int port = 0;
	struct dbinfo dbi;
#ifdef WITH_SQLITE
	int ret = 0;
#endif /* WITH_SQLITE */

	bzero(&dbi, sizeof(dbi));
	dbi.type = DT_NONE;
	dbi.maxlen = MAXDUMBSIZE;
	dbi.msglen = 0;
	dbi.fdel = 0;
#ifdef WITH_STACKMAP
	dbi.g.nmr_config = "";
	dbi.g.nthreads = 1;
	dbi.g.td_privbody = _worker;
	dbi.g.polltimeo = 2000;
	dbi.g.extra_bufs = EXTRA_BUF_NUM;
#endif

	signal(SIGPIPE, SIG_IGN); // XXX

	while ((ch = getopt(argc, argv, "P:l:b:md:DNi:PcC:a:p:xF:")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'P':	/* server port */
			port = atoi(optarg);
			break;
		case 'l': /* HTTP OK content length */
			dbi.msglen = atoi(optarg);
			break;
		case 'b': /* give the epoll_wait() timeo argument -1 */
			dbi.g.polltimeo = atoi(optarg);
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
		case 'i':
			strncpy(dbi.ifname, optarg, sizeof(dbi.ifname));
			break;
		case 'x': /* PASTE */
			dbi.flags |= DBI_FLAGS_PASTE;
			break;
		case 'c':
			dbi.httplen = 1;
			break;
		case 'a':
			dbi.g.affinity = atoi(optarg);
			break;
		case 'p':
			dbi.g.nthreads = atoi(optarg);
			break;
#ifdef WITH_STACKMAP
		case 'C':
			dbi.g.nmr_config = strdup(optarg);
			break;
#endif
		case 'F':
			dbi.fdel = atoi(optarg);
			break;
		}

	}

	if (dbi.httplen) { // preallocate HTTP header
		dbi.http = calloc(1, MAX_HTTPLEN);
		if (!dbi.http) {
			perror("calloc");
			usage();
		}
		dbi.httplen = generate_http(dbi.msglen, dbi.http, NULL);
		D("generated http %d", dbi.httplen);
	}

	fprintf(stderr, "%s built %s %s db: %s\n",
		argv[0], __DATE__, __TIME__, dbi.path ? dbi.path : "none");
	usleep(1000);

	argc -= optind;
	argv += optind;

	if (!port || !dbi.msglen)
		usage();

	if (dbi.flags & DBI_FLAGS_READPMEM) {
		if (!((dbi.type == DT_DUMB) && dbi.mmap)) {
			fprintf(stderr, "READPMEM must use dumb db and mmap\n");
			usage();
		}
	}
	if ((dbi.flags & DBI_FLAGS_PASTE) && !dbi.mmap) {
		D("PASTE must be used with mmap");
		usage();
	}

	if (dbi.type == DT_DUMB) {
		dbi.dumbfd = open(dbi.path, O_RDWR | O_CREAT, S_IRWXU);
		if (dbi.dumbfd < 0) {
			perror("open");
			goto close;
		}
		if (dbi.mmap) {
			dbi.maplen = MAXDUMBSIZE; /* XXX is size ok? */
			dbi.paddr = _do_mmap(dbi.dumbfd, dbi.maplen);
			if (dbi.paddr == NULL)
				goto close;
#ifdef WITH_STACKMAP
			if (dbi.flags & DBI_FLAGS_PASTE) {
				/* initialize WAL header */
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

	sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sd < 0) {
		perror("socket");
		goto close;
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
	dbi.sd = sd;

#ifdef WITH_STACKMAP
	if (dbi.ifname[0]) {
		char *p = dbi.g.ifname;
		struct nm_ifreq *ifreq = &dbi.ifreq;
#ifdef WITH_EXTMEM
		struct netmap_pools_info *pi;
#endif /* WITH_EXTMEM */

		if (strlen(STMNAME) + 1 + strlen(dbi.ifname) > STMNAME_MAX) {
			D("too long name %s", dbi.ifname);
			goto close_socket;
		}
		strcat(strcat(strcpy(p, STMNAME), "+"), dbi.ifname);

		/* pre-initialize ifreq for accept() */
		bzero(ifreq, sizeof(*ifreq));
		strncpy(ifreq->nifr_name, STMNAME, sizeof(ifreq->nifr_name));

		dbi.g.dev_type = DEV_NETMAP;
#ifdef WITH_EXTMEM
		dbi.extmem_fd = open(DEFAULT_EXT_MEM, O_RDWR|O_CREAT,
					S_IRWXU);
                if (dbi.extmem_fd < 0) {
                        perror("open");
                        goto close_socket;
                }
                dbi.g.extmem = _do_mmap(dbi.extmem_fd, DEFAULT_EXT_MEM_SIZE);
                if (dbi.g.extmem == NULL) {
			D("mmap failed");
                        goto close_socket;
                }
		pi = (struct netmap_pools_info *)dbi.g.extmem;
		pi->memsize = DEFAULT_EXT_MEM_SIZE;
#endif
	} else {
		dbi.g.dev_type = DEV_SOCKET;
	}
	dbi.g.td_type = TD_TYPE_OTHER;
	dbi.g.td_private_len = sizeof(struct thpriv);
	if (nm_start(&dbi.g) < 0)
		goto close_socket;
	ND("nm_open() %s done (offset %u ring_num %u)",
	    nm_name, IPV4TCP_HDRLEN, dbi.g.nmd->nifp->ni_tx_rings);
#endif /* WITH_STACKMAP */

close_socket:
#ifdef WITH_EXTMEM
	if (dbi.g.extmem) {
		if (dbi.g.extmem)
			munmap(dbi.g.extmem, DEFAULT_EXT_MEM_SIZE);
		close(dbi.extmem_fd);
		//free(dbi.g.extmem);
	}
#endif /* WITH_EXTMEM */

	if (sd > 0)
		close(sd);
close:
	close_db(&dbi);
	return (0);
}
