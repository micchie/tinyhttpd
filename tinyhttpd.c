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

#ifdef WITH_BPLUS
#include <bplus_support.h>
#include <bplus_common.h>
#endif /* WITH_BPLUS */


#define container_of(ptr, type, member) ({          \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})

//#define MYHZ	2400000000
#ifdef MYHZ
static __inline unsigned long long int rdtsc(void)
{
   //unsigned long long int x;
   unsigned a, d;

   __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));

   return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}

static inline void
user_clock_gettime(struct timespec *ts)
{
        unsigned long long now;

        now = rdtsc();
        ts->tv_sec = now/MYHZ;
        ts->tv_nsec = (now%MYHZ)*1000000000/MYHZ;
}
#endif /* MYHZ */

#define GET_LEN		4
#define POST_LEN	5
#define STMNAME	"stack:0"
#define STMNAME_MAX	64
//#define EXTRA_BUF_NUM	160000
//#define EXTRA_BUF_NUM	3000000
#define PMEMFILE         "/mnt/pmem/netmap_mem"
#define BPLUSFILE	"/mnt/pmem/bplus"
#endif /* WITH_STACKMAP */
#define IPV4TCP_HDRLEN	66
#define NETMAP_BUF_SIZE	2048

#define MAX_PAYLOAD	1400
#define min(a, b) (((a) < (b)) ? (a) : (b)) 
#define max(a, b) (((a) > (b)) ? (a) : (b)) 

#ifndef D
#define D(fmt, ...) \
	printf(""fmt"\n", ##__VA_ARGS__)
#endif

#define IF_OBJTOTAL	128
#define RING_OBJTOTAL	512
#define RING_OBJSIZE	33024

/* Taken from Linux */
#define NOP_DS_PREFIX 0x3e
#define X86_FEATURE_CLFLUSHOPT	( 9*32+23) /* CLFLUSHOPT instruction */
# define __force
#define b_replacement(num)	"664"#num
#define e_replacement(num)	"665"#num

#define alt_end_marker		"663"
#define alt_slen		"662b-661b"
#define alt_pad_len		alt_end_marker"b-662b"
#define alt_total_slen		alt_end_marker"b-661b"
#define alt_rlen(num)		e_replacement(num)"f-"b_replacement(num)"f"

#define __OLDINSTR(oldinstr, num)					\
		"661:\n\t" oldinstr "\n662:\n"					\
	".skip -(((" alt_rlen(num) ")-(" alt_slen ")) > 0) * "		\
		"((" alt_rlen(num) ")-(" alt_slen ")),0x90\n"

#define OLDINSTR(oldinstr, num)						\
		__OLDINSTR(oldinstr, num)					\
	alt_end_marker ":\n"

#define ALTINSTR_ENTRY(feature, num)					      \
		" .long 661b - .\n"				/* label           */ \
	" .long " b_replacement(num)"f - .\n"		/* new instruction */ \
	" .word " __stringify(feature) "\n"		/* feature bit     */ \
	" .byte " alt_total_slen "\n"			/* source len      */ \
	" .byte " alt_rlen(num) "\n"			/* replacement len */ \
	" .byte " alt_pad_len "\n"			/* pad len */

#define ALTINSTR_REPLACEMENT(newinstr, feature, num)	/* replacement */     \
	b_replacement(num)":\n\t" newinstr "\n" e_replacement(num) ":\n\t"

#define ALTERNATIVE(oldinstr, newinstr, feature)			\
		OLDINSTR(oldinstr, 1)					\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(feature, 1)					\
	".popsection\n"							\
	".pushsection .altinstr_replacement, \"ax\"\n"			\
	ALTINSTR_REPLACEMENT(newinstr, feature, 1)			\
	".popsection"

#define alternative_io(oldinstr, newinstr, feature, output, input...)	\
		asm volatile (ALTERNATIVE(oldinstr, newinstr, feature)		\
					: output : "i" (0), ## input)

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

static inline void clflush(volatile void *__p)
{
	asm volatile("clflush %0" : "+m" (*(volatile char __force *)__p));
}

// GCC < 5 doesn't compile _mm_clflushopt() well
#if 0
static inline void _mm_clflushopt(volatile void *__p)
{
	alternative_io(".byte " __stringify(NOP_DS_PREFIX) "; clflush %P0",
		       ".byte 0x66; clflush %P0", X86_FEATURE_CLFLUSHOPT,
			"+m" (*(volatile char __force *)__p));
}
#endif
/* End - Taken from Linux */

#define MAXCONNECTIONS 2048
#define MAXQUERYLEN 32767

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
	u_int pgsiz;
	char *paddr;
	void *vp; // gfile_t
	int fdel;
	int pm;
	size_t dbsiz;
#define DBI_FLAGS_FDSYNC	0x1
#define DBI_FLAGS_READMMAP	0x2
#define DBI_FLAGS_PASTE		0x4
#define DBI_FLAGS_BPLUS		0x8
#define DBI_FLAGS_KVS		0x10
	int flags;
	char ifname[IFNAMSIZ + 64]; /* stackmap ifname (also used as indicator) */
#ifdef WITH_STACKMAP
	struct nm_garg g;
	struct nm_ifreq ifreq;
	int extmemfd;
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
	size_t cur;
	uint64_t pst_ent;
	uint16_t txlen;
	uint16_t rxlen;
	struct nm_ifreq ifreq;
	struct epoll_event evts[MAXCONNECTIONS];
#ifdef WITH_KVS
	struct netmap_slot *extra;
#else
	uint32_t *extra;
#endif
	uint32_t extra_cur;
	uint32_t extra_num;
	int	*fds;
	int	nfds;
};
#define DEFAULT_NFDS	1024

static inline uint32_t
get_extra(struct thpriv *tp)
{
	uint32_t ret;

	ret = tp->extra_cur++;

	if (unlikely(tp->extra_cur == tp->extra_num)) {
		tp->extra_cur = 0;
		tp->cur = 0; //clear log too
	}
	return ret;
}

static inline size_t
get_aligned(size_t len, size_t align)
{
	size_t d = len & (align - 1);
	return d ? len + align - d : len;
}

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
#if 0
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
#endif /* 0 */

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

static __inline void
sfence(long delay)
{
	if (delay > 0)
		wait_ns(delay);
	//__asm __volatile("mfence" : : : "memory");
	_mm_sfence();
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
_do_mmap(int fd, size_t len)
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
close_db(const char *path, int type, char *map, size_t dbsiz, void *fd_or_sql)
{
	struct stat st;
#ifdef WITH_SQLITE
	char path_wal[64], path_shm[64];
#endif

	/* close reference */
	if (type == DT_DUMB) {
		int fd = *(int *)fd_or_sql;
		if (map)
			if (munmap(map, dbsiz))
				perror("munmap");
		if (fd > 0) {
			D("closing dumbfd");
			close(fd);
		}
	}
#ifdef WITH_SQLITE
	else if (type == DT_SQLITE) {
		D("closing sqlite3 obj");
		sqlite3_close_v2(*(sqlite3 *)fd_or_sql);
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
#if 0
static int
copy_to_nm(struct netmap_ring *ring, int virt_header, const char *data,
		int len, int off0, int off, int fd)
{
	u_int const tail = ring->tail;
	u_int cur = ring->cur;
	u_int copied = 0;
	int space = nm_ring_space(ring);
	struct netmap_slot *slot = &ring->slot[cur];
	char *p = NETMAP_BUF(ring, slot->buf_idx) + off0 + virt_header;

	__builtin_prefetch(p);

	if (unlikely(space * MAX_PAYLOAD < len)) {
		RD(1, "no space (%d slots)", space);
		return -1;
	}

	/* XXX adjust to real offset */
	off0 += virt_header;
	off += virt_header;

	do {
		u_int next_cur = nm_ring_next(ring, cur);
		struct netmap_slot *next_slot = &ring->slot[next_cur];
		char *next_buf = NETMAP_BUF(ring, next_slot->buf_idx) + off;
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
		cur = next_cur;

		if (copied >= len || unlikely(next_cur == tail))
			break;

		__builtin_prefetch(next_buf);

		p = next_buf;
		slot = next_slot;
	} while (1);
	ring->cur = ring->head = cur;
	return len;
}
#endif
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

#ifdef WITH_KVS
#if 0
ssize_t
generate_httphdr(ssize_t content_length, char *buf)
{
	char *p = buf;
	/* From nginx */
	static char *lines[5] = {
	 "HTTP/1.1 200 OK\r\n",
	 "Connection: keep-alive\r\n",
	 "Server: Apache/2.2.800\r\n",
	 "Content-Length: "};
	ssize_t l;
	const size_t l0 = 17, l1 = 24, l2 = 24, l3 = 16;

	//l0 = strlen(lines[0]);
	p = mempcpy(p, lines[0], l0);
	//l1 = strlen(lines[1]);
	p = mempcpy(p, lines[1], l1);
	//l2 = strlen(lines[2]);
	p = mempcpy(p, lines[2], l2);
	p = mempcpy(p, lines[3], l3);
	l = sprintf(p, "%lu\r\n\r", content_length);
	p += l;
	*p++ = '\n';
	return p - buf;
}
#endif /* 0 */

static char *HTTPHDR = "HTTP/1.1 200 OK\r\n"
		 "Connection: keep-alive\r\n"
		 "Server: Apache/2.2.800\r\n"
		 "Content-Length: ";
#define HTTPHDR_LEN 81

ssize_t
generate_httphdr(size_t content_length, char *buf)
{
	uint64_t *h = (uint64_t *)HTTPHDR;
	uint64_t *p = (uint64_t *)buf;
	char *c;

	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	c = (char *)p;
	*c++ = *(char *)h;
	c += sprintf(c, "%lu\r\n\r", content_length);
	*c++ = '\n';
	return c - buf;
}
#else
ssize_t
generate_httphdr(ssize_t content_length, char *buf)
{
	char *p = buf;
	/* From nginx */
	static char *lines[5] = {
	 "HTTP/1.1 200 OK\r\n",
	 "Connection: keep-alive\r\n",
	 "Content-Length: "};
	ssize_t l;
	const size_t l0 = 17, l1 = 24, l2 = 16;

	//l0 = strlen(lines[0]);
	p = mempcpy(p, lines[0], l0);
	//l1 = strlen(lines[1]);
	p = mempcpy(p, lines[1], l1);
	//l2 = strlen(lines[2]);
	p = mempcpy(p, lines[2], l2);
	l = sprintf(p, "%lu\r\n\r", content_length);
	p += l;
	*p++ = '\n';
	return p - buf;
}
#endif /* WITH_KVS */

static int
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

#define SKIP_POST	48
static int
parse_post(char *post, int *coff, uint64_t *key)
{
	int clen;
	char *pp, *p = strstr(post + SKIP_POST, "Content-Length: ");
	char *end;
	
	*key = 0;
	*coff = 0;
	if (unlikely(!p))
		return -1;
	pp = p + 16; // "Content-Length: "
	clen = strtol(pp, &end, 10);
	if (end == pp)
		return -1;
	pp = strstr(pp, "\r\n\r\n");
	if (unlikely(!pp))
		return -1;
	pp += 4;
	*key = *(uint64_t *)pp;
	*coff = pp - post;
	return clen;
}

static inline uint64_t
parse_get_key(char *get)
{
	return *(uint64_t *)(get + GET_LEN + 1); // jump '/'
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

static int
writesync(char *buf, size_t len, size_t space, int fd, size_t *pos, int fdsync)
{
	int error;
	size_t cur = *pos;

	if (cur + len > space){
		if (lseek(fd, 0, SEEK_SET) < 0) {
			perror("lseek");
			return -1;
		}
		cur = 0;
	}
	len = write(fd, buf, len);
	if (len < 0) {
		perror("write");
		return -1;
	}
	cur += len;
	error = fdsync ? fdatasync(fd) : fsync(fd);
	if (error) {
		fprintf(stderr, "failed in f%ssync\n", fdsync ? "data" : "");
		return -1;
	}
	*pos = cur;
	return 0;
}

static inline void
_to_tuple(uint64_t p, uint32_t *idx, uint16_t *off, uint16_t *len)
{
	*idx = p >> 32;
	*off = (p & 0x00000000ffff0000) >> 16;
	*len = p & 0x000000000000ffff;
}

static inline uint64_t
_from_tuple(uint32_t idx, uint16_t off, uint16_t len)
{
	return (uint64_t)idx << 32 | off<< 16 | len;
}


#ifdef WITH_KVS
static struct netmap_slot *
set_to_nm(struct netmap_ring *txr, struct netmap_slot *any_slot)
{
	struct netmap_slot *txs, tmp;

	if (unlikely(nm_ring_space(txr) == 0)) {
		return NULL;
	}
	txs = &txr->slot[txr->cur];
	if (unlikely(any_slot == txs)) {
		goto done;
	}
	tmp = *txs;
	*txs = *any_slot;
	txs->flags |= NS_BUF_CHANGED;
	*any_slot = tmp;
	any_slot->flags |= NS_BUF_CHANGED; // this might sit on the ring
done:
	txr->cur = txr->head = nm_ring_next(txr, txr->cur);
	return txs;
}

enum {SLOT_INVALID=0, SLOT_EXTRA, SLOT_USER, SLOT_KERNEL};
static inline int
_between(u_int x, u_int a, u_int b, u_int lim)
{
	if (a < b) {
		if (x >= a && x < b) {
			return SLOT_USER;
		} else {
			return SLOT_KERNEL;
		}
	} else if (a > b) {
		if (x >= b && x < a) {
			return SLOT_KERNEL;
		} else {
			return SLOT_USER;
		}
	}
	return SLOT_KERNEL; // a == b
}

static inline int
nm_where(struct netmap_ring *ring, struct netmap_slot *extra,
		u_int extra_num, struct netmap_slot *slot)
{
	if ((uintptr_t)slot > (uintptr_t)ring->slot && 
	    (uintptr_t)slot < (uintptr_t)(ring->slot + ring->num_slots)) {
		u_int i = slot - ring->slot;
		return _between(i, ring->head, ring->tail, ring->num_slots - 1);
	} else if ((uintptr_t)slot >= (uintptr_t)extra &&
	    (uintptr_t)slot < (uintptr_t)(extra + extra_num))
		return SLOT_EXTRA;
	return SLOT_INVALID;
}

//POST http://www.micchie.net/ HTTP/1.1\r\nHost: 192.168.11.3:60000\r\nContent-Length: 1280\r\n\r\n2
//HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nServer: //Apache/2.2.800\r\nContent-Length: 1280\r\n\r\n
#define KVS_SLOT_OFF 8
static inline void
_embed_slot(char *buf, u_int coff, struct netmap_slot *slot)
{
	*(struct netmap_slot **)(buf + coff + KVS_SLOT_OFF) = slot;
}

static inline struct netmap_slot*
_digout_slot(char *nmb, u_int coff)
{
	return *(struct netmap_slot **)(nmb + coff + KVS_SLOT_OFF);
}
#endif /* WITH_KVS */

static inline int
str_to_key(uint64_t *k)
{
	char c[8];
	strncpy(c, (char *)k, sizeof(c));
	return atoi(c);
}

static inline void
print_force(char *p, int len)
{
	int i;
	for (i = 0; i <len; i++) {
		printf("%c", p[i]);
	}
	printf("\n");
}

#ifdef WITH_BPLUS
static inline void
paste_bplus(gfile_t *vp, btree_key key, struct netmap_slot *slot, size_t off, size_t len)
{
	uint64_t pst_ent;
	//uint64_t datam;
	static int unique = 0;
	int rc;

	pst_ent = _from_tuple(slot->buf_idx, off, len);
	rc = btree_insert(vp, key, pst_ent);
	if (rc == 0)
		unique++;
	ND("key %lu val %lu idx %u off %lu len %lu", key, pst_ent, slot->buf_idx, off, len);
	//btree_lookup(vp, key, &datam);
	//if (datam != pst_ent)
	//	D("warning: pst_ent %lu but datam %lu",pst_ent, datam);
	//
}
#endif /* WITH_BPLUS */

static inline void
paste_wal(char *paddr, size_t *pos, size_t dbsiz, struct netmap_slot *slot,
		size_t off, size_t len)
{
	uint64_t pst_ent;
	size_t cur = *pos;
	int plen = sizeof(pst_ent);
	int phdrlen = sizeof(struct paste_hdr);
	char *p = paddr;

	/* make log */
	pst_ent = _from_tuple(slot->buf_idx, off, len);
	/* position log */
	if (unlikely(plen > dbsiz - phdrlen - cur))
		cur = 0;
	p += phdrlen + cur;
	*(uint64_t *)p = pst_ent;
	_mm_clflush(p);
	*pos = cur + plen;
}

static inline void
copy_and_log(char *paddr, size_t *pos, size_t dbsiz, char *buf, size_t len,
		u_int nowrap, size_t align, int pm, void *vp, uint64_t key)
{
	char *p;
	int mlen = vp ? 0 : sizeof(uint64_t);
	size_t cur = *pos;
	int phdrlen = vp || !pm ? 0 : sizeof(struct paste_hdr); // dummy header
	u_int i = 0;
	size_t aligned = len;

	ND("paddr %p pos %lu dbsiz %lu buf %p len %lu nowrap %u align %lu pm %d vp %p key %lu", paddr, *pos, dbsiz, buf, len, nowrap, align, pm, vp, key);
#ifdef WITH_BPLUS
	if (vp) {
		align = NETMAP_BUF_SIZE;
	}
#endif /* WITH_BPLUS */
	if (align) {
		aligned = get_aligned(len, align);
	}

	/* Do we have a space? */
	if (unlikely(phdrlen + cur + max(aligned, nowrap) + mlen > dbsiz)) {
		cur = 0;
	}
	p = paddr + phdrlen + cur;
	p += mlen; // leave a log entry space

	if (buf)
		memcpy(p, buf, len);
	if (pm) {
		for (; i < len; i += CACHE_LINE_SIZE) {
			_mm_clflush(p + i);
		}
	}
	p -= mlen;
       	if (!pm) {
		int error = msync(p, len + mlen, MS_SYNC);
		if (error)
			perror("msync");
	}
#ifdef WITH_BPLUS
	if (vp) {
		static int unique = 0;
		uint64_t pst_ent = _from_tuple(cur/NETMAP_BUF_SIZE, 0, len);
		int rc = btree_insert(vp, key, pst_ent);
		if (rc == 0)
			unique++;
	} else
#endif
	{
		*(uint64_t *)p = len;
		if (pm)
			_mm_clflush(p);
		//else {
		//	msync(p, sizeof(size_t), MS_SYNC);
		//}
	}
	*pos = cur + aligned + (align ? 0 : mlen);
}

/* We assume GET/POST appears in the beginning of netmap buffer */
int
do_nm_ring(struct nm_targ *targ, int ring_nr)
{
	struct nm_garg *g = targ->g;
	struct dbinfo *dbi = container_of(g, struct dbinfo, g);
	struct thpriv *tp = targ->td_private;
	ssize_t msglen = dbi->msglen;

	struct netmap_ring *rxr = NETMAP_RXRING(targ->nmd->nifp, ring_nr);
	struct netmap_ring *txr = NETMAP_TXRING(targ->nmd->nifp, ring_nr);
	u_int const rxtail = rxr->tail;
	u_int rxcur = rxr->cur;
	size_t dbsiz = dbi->dbsiz;
	char *paddr = dbi->paddr;

	for (; rxcur != rxtail; rxcur = nm_ring_next(rxr, rxcur)) {
		struct netmap_slot *rxs = &rxr->slot[rxcur];
		char *rxbuf;
		int o = IPV4TCP_HDRLEN;
		int off, len;
		int *fde = &tp->fds[rxs->fd];
		int thisclen = 0;
		char *content = NULL;
#ifdef MYHZ
		struct timespec ts1, ts2, ts3;
		user_clock_gettime(&ts1);
#endif
		off = g->virt_header + rxs->offset;
		rxbuf = NETMAP_BUF(rxr, rxs->buf_idx) + off;
	       	len = rxs->len - off;
		if (unlikely(len == 0)) {
			continue;
		}
		if (!strncmp(rxbuf, "POST ", POST_LEN)) {
			uint64_t key;
			int coff, clen = parse_post(rxbuf, &coff, &key);

			thisclen = len - coff;
			if (unlikely(thisclen < 0)) {
				D("thisclen %d len %d coff %d", thisclen, len, coff);
			}

			if (unlikely(clen < 0))
				continue;
			else if (clen > thisclen) {
				*fde = clen - thisclen;
			}
log:
			if (dbi->type == DT_DUMB) {
				if (dbi->flags & DBI_FLAGS_PASTE) {
					u_int i = 0;
#ifdef WITH_KVS
					struct netmap_slot tmp, *extra;
#endif
					uint32_t extra_i = get_extra(tp);

					/* flush data buffer */
					for (; i < len; i += CACHE_LINE_SIZE) {
						_mm_clflush(rxbuf + i);
					}
#ifdef WITH_BPLUS
					if (dbi->vp) {
						paste_bplus(dbi->vp, key, rxs,
							off + coff, thisclen);
					} else
#endif
				       	if (paddr) {
						paste_wal(paddr, &tp->cur,
						    dbsiz, rxs, off + coff,
						    thisclen);
					}

					/* swap out buffer */
#ifdef WITH_KVS
					extra = &tp->extra[extra_i];
					tmp = *rxs;
					rxs->buf_idx = extra->buf_idx;
					rxs->flags |= NS_BUF_CHANGED;
					*extra = tmp;
					extra->flags &= ~NS_BUF_CHANGED;

					/* record current slot */
					if (dbi->flags & DBI_FLAGS_KVS) {
						_embed_slot(rxbuf, coff, extra);
					}
#else
					i = rxs->buf_idx;
					rxs->buf_idx = tp->extra[extra_i];
					rxs->flags |= NS_BUF_CHANGED;
					tp->extra[extra_i] = i;
#endif

				} else if (paddr) {
					copy_and_log(paddr, &tp->cur,
					    dbsiz, rxbuf + coff, thisclen,
					    thisclen, dbi->pm ? 0 : dbi->pgsiz,
					    dbi->pm, dbi->vp, key);
				} else {
					if (writesync(rxbuf + coff, len, dbsiz,
					    dbi->dumbfd, &tp->cur,
					    dbi->flags & DBI_FLAGS_FDSYNC)) {
						return -1;
					}
				}
			}
			if (*fde == 0) {
				goto get;
			}

		} else if (strncmp(rxbuf, "GET ", GET_LEN) == 0) {
#ifdef WITH_KVS
			uint64_t key = parse_get_key(rxbuf);

			if (dbi->vp) {
				uint64_t datam = 0;
				int rc;
				uint32_t _idx;
				uint16_t _off, _len;
				struct netmap_slot *s;
				int t;

				rc = btree_lookup(dbi->vp, key, &datam);
				if (rc == ENOENT) {
					goto get;
				}
				_to_tuple(datam, &_idx, &_off, &_len);
				if (dbi->flags & DBI_FLAGS_PASTE) {
					char *_buf = NETMAP_BUF(rxr, _idx);

					s = _digout_slot(_buf, _off);
					t = nm_where(txr, tp->extra, tp->extra_num, s);
					if (t != SLOT_INVALID) {
						if (s->flags & NS_BUF_CHANGED) {
							content = _buf + _off;
							goto get;
						}
					}
					if (t == SLOT_EXTRA || t == SLOT_USER) {
						struct netmap_slot *txs;
						u_int hl;

						txs = set_to_nm(txr, s);
						txs->fd = rxs->fd;
						txs->len = _off + _len; // XXX
						_embed_slot(_buf, _off, txs);
						hl = generate_httphdr(_len,
								_buf + off);
						if (unlikely(hl != _off - off)) {
							RD(1, "mismatch");
						}
						goto update_ctr;
					} else if (t == SLOT_KERNEL) {
						content = _buf + off;
					} else { // SLOT_INVALID
						msglen = _len;
					}
				} else {
					content = paddr + NETMAP_BUF_SIZE*_idx;
					msglen = _len;
				}
			}
#endif /* WITH_KVS */

get:
			if (dbi->httplen && content == NULL) { // use cache
				char *http = dbi->http;
				int hlen = dbi->httplen;

				if (copy_to_nm(txr, g->virt_header, http, hlen,
						o, o, rxs->fd) < hlen) {
					continue;
				}
			} else {
				if (generate_http_nm(msglen, txr,
				    g->virt_header, o, rxs->fd, content) < 0)
					continue;
			}
		} else if (*fde > 0) {
			*fde -= len;
			if (*fde <= 0) {
				if (unlikely(*fde < 0)) {
					RD(1, "negative leftover to %d", *fde);
					*fde = 0;
				}
				thisclen = len;
				goto log;
			}
		}
#ifdef WITH_KVS
update_ctr:
#endif /* WITH_KVS */
		nm_update_ctr(targ, 1, len);
#ifdef MYHZ
		user_clock_gettime(&ts2);
		ts3 = timespec_sub(ts2, ts1);
		RD(1, "loop %lu.%lu", ts3.tv_sec, ts3.tv_nsec);
#endif /* MYHZ */
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
	ssize_t len = 0;
	struct thpriv *tp = targ->td_private;
	size_t max;
	char *paddr = dbi->paddr;
	int readmmap = !!(dbi->flags & DBI_FLAGS_READMMAP);
	char *content = NULL;

	rxbuf = txbuf = buf;
	if (readmmap) {
		size_t cur = tp->cur;
		max = dbi->dbsiz - sizeof(struct paste_hdr) - cur;
		if (unlikely(max < dbi->pgsiz)) {
			cur = 0;
			max = dbi->dbsiz;
		}
		rxbuf = paddr + tp->cur + sizeof(uint64_t); // metadata space
		max -= sizeof(uint64_t);
	} else {
		max = sizeof(buf);
	}
	len = read(fd, rxbuf, max);
	if (len == 0) {
		close(fd);
		return 0;
	} else if (unlikely(len < 0)) {
		//perror("read");
		close(fd);
		return -1;
	}

	if (strncmp(rxbuf, "POST ", POST_LEN) == 0) {
		uint64_t key;
		int coff, clen = parse_post(rxbuf, &coff, &key);

		if (unlikely(clen < 0)) {
			RD(1, "invalid clen");
			return 0;
		}
		if (dbi->type == DT_DUMB) {
			if (paddr) {
				copy_and_log(paddr, &tp->cur, dbi->dbsiz,
				    readmmap ? NULL : rxbuf + coff, clen,
				    dbi->pgsiz, dbi->pm ? 0 : dbi->pgsiz,
				    dbi->pm, dbi->vp, key);
			} else {
				if (writesync(rxbuf + coff, len, dbi->dbsiz,
				    dbi->dumbfd, &tp->cur,
				    dbi->flags & DBI_FLAGS_FDSYNC)) {
					return -1;
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
	} else if (strncmp(rxbuf, "GET ", GET_LEN) == 0) {
#ifdef WITH_KVS
		uint64_t key = parse_get_key(rxbuf);

		if (dbi->vp) {
			uint64_t datam = 0;
			int rc;
			uint32_t _idx;
			uint16_t _off, _len;

			rc = btree_lookup(dbi->vp, key, &datam);
			if (rc != ENOENT) {
				_to_tuple(datam, &_idx, &_off, &_len);
				content = paddr + NETMAP_BUF_SIZE * _idx;
				msglen = _len;
			}
		}
#endif
	} else {
		len = 0;
	}

	if (len) {
		if (dbi->httplen && content == NULL) {
			len = dbi->httplen;
			memcpy(txbuf, dbi->http, len);
		} else {
			len = generate_http(msglen, txbuf, content);
		}
	}
	len = write(fd, txbuf, len);
	if (unlikely(len < 0)) {
		perror("write");
	}
	return 0;
}

#define container_of(ptr, type, member) ({                      \
		      const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		      (type *)( (char *)__mptr - offsetof(type,member) );})
static int
create_db(u_int type, u_int flags, void **vp, char *path, void *fd_or_sql, char **map, size_t dbsiz, char *ifname, int ifnamelen)
{
	int fd = 0;
	char *paddr = NULL;

#ifdef WITH_SQLITE
       	if (dbi.type == DT_SQLITE) {
	    do {
		char *err_msg;
		char create_tbl_stmt[128];
		char *journal_wal_stmt = "PRAGMA journal_mode = WAL";
		char *excl_lock_stmt = "PRAGMA locking_mode = EXCLUSIVE";
		char *synchronous_stmt = "PRAGMA synchronous = FULL";
		sqlite3 *sql_conn = NULL;

		/* open db file and get handle */
		ret = sqlite3_open_v2(path, &sql_conn,
			SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | 
			SQLITE_OPEN_WAL, NULL);
		if (SQLITE_OK != ret) {
			D("sqlite3_open_v2 failed");
			break;
		}
		/* enable wal */
		ret = sqlite3_exec(sql_conn, journal_wal_stmt,
			       	NULL, NULL, &err_msg);
		if (SQLITE_OK != ret)
			goto error;
		/* avoiding shared memory cuts 4 us */
		ret = sqlite3_exec(sql_conn, excl_lock_stmt,
			       	NULL, NULL, &err_msg);
		if (SQLITE_OK != ret)
			goto error;
		/* flush every commit onto the disk */
		ret = sqlite3_exec(sql_conn, synchronous_stmt,
			       	NULL, NULL, &err_msg);
		if (SQLITE_OK != ret)
			goto error;

		/* create a table */
		snprintf(create_tbl_stmt, sizeof(create_tbl_stmt),
			       	"CREATE TABLE IF NOT EXISTS %s "
			       	"(id INTEGER, "
				"name BINARY(2048))", SQLDBTABLE);
		ret = sqlite3_exec(sql_conn, create_tbl_stmt,
				NULL, NULL, &err_msg);
		if (SQLITE_OK != ret ) {
error:
			D("%s", err_msg);
			sqlite3_free(err_msg);
			err_msg = NULL;
			break;
		}
		*(sqlite3 *)fd_or_sql = sql_conn;
	    } while (0);
	} else
#endif /* WITH_SQLITE */
#ifdef WITH_BPLUS
	/* B+tree ? */
	if (type == DT_DUMB && (flags & DBI_FLAGS_BPLUS)) {
		int rc;
		rc = btree_create_btree(path, ((gfile_t **)vp));
		D("btree_create_btree() done (%d)", rc);
		return rc != 0 ? -1 : 0;
	} else
#endif /* WITH_BPLUS */
	if (type == DT_DUMB &&
	    !(flags & DBI_FLAGS_BPLUS && flags & DBI_FLAGS_PASTE)) {
	    do {
		int fd;

		unlink(path);
		fd = open(path, O_RDWR | O_CREAT, S_IRWXU);
		if (fd < 0) {
			perror("open");
			break;
		}
		if (map) {
			if (fallocate(fd, 0, 0, dbsiz) < 0) {
				perror("fallocate");
				break;
			}
			paddr = _do_mmap(fd, dbsiz);
			if (paddr == NULL)
				break;
			*map = paddr;
#ifdef WITH_STACKMAP
			if (flags & DBI_FLAGS_PASTE) {
				/* initialize WAL header */
				struct paste_hdr *ph;

				ph = (struct paste_hdr *)paddr;
				strncpy(ph->ifname, ifname, sizeof(ifnamelen));
				strncpy(ph->path, ifname, strlen(path));
			}
#endif /* WITH_STACKMAP */
		}
		*(int *)fd_or_sql = fd;
		return 0;
	    } while (0);
	}
	if (paddr != NULL)
		munmap(paddr, dbsiz);
	if (fd > 0)
		close(fd);
	return -1;
}

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
		struct nmreq *req = &g->nmd->req;
		struct netmap_if *nifp = targ->nmd->nifp;
		struct netmap_ring *any_ring = NETMAP_RXRING(nifp, 0);
		uint32_t i, next = nifp->ni_bufs_head;
		int n = req->nr_arg3 ? req->nr_arg3 : req->nr_arg4; /* XXX */

		tp->extra = calloc(sizeof(*tp->extra), n);
		if (!tp->extra) {
			perror("calloc");
			goto quit;
		}
		for (i = 0; i < n && next; i++) {
#ifdef WITH_KVS
			tp->extra[i].buf_idx = next;
#else
			tp->extra[i] = next;
#endif
			next = *(uint32_t *)NETMAP_BUF(any_ring, next);
		}
		tp->extra_num = i;
		D("imported %u extra buffers", i);

		tp->ifreq = dbip->ifreq;

		/* allocate fd table */
		tp->fds =calloc(sizeof(*tp->fds), DEFAULT_NFDS);
		if (!tp->fds){
			perror("calloc");
			goto quit;
		}
		tp->nfds = DEFAULT_NFDS;
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
				if (unlikely(newfd >= tp->nfds)) {
				       int *newfds, fdsiz = sizeof(*tp->fds);
				       int curfds = tp->nfds;
				      
				       newfds = calloc(fdsiz, tp->nfds * 2);
				       if (!newfds) {
					       perror("calloc");
					       close(newfd);
					       goto quit;
				       }
				       memcpy(newfds, tp->fds, fdsiz * curfds);
				       free(tp->fds);
				       _mm_mfence();
				       tp->fds = newfds;
				       tp->nfds++;
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

				do_nm_ring(targ, i);
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
	if (tp->extra)
		free(tp->extra);
	if (tp->fds)
		free(tp->fds);
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
	int do_mmap = 0;
#ifdef WITH_SQLITE
	int ret = 0;
#endif /* WITH_SQLITE */

	bzero(&dbi, sizeof(dbi));
	dbi.type = DT_NONE;
	dbi.dbsiz = 0;
	dbi.msglen = 0;
	dbi.fdel = 0;
	dbi.pgsiz = getpagesize();
#ifdef WITH_STACKMAP
	dbi.g.nmr_config = "";
	dbi.g.nthreads = 1;
	dbi.g.td_privbody = _worker;
	dbi.g.polltimeo = 2000;
	dbi.g.extra_bufs = 0;
#endif

	signal(SIGPIPE, SIG_IGN); // XXX

	while ((ch = getopt(argc, argv, "P:l:b:md:DNi:PcC:a:p:x:F:L:Bk")) != -1) {
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
			dbi.pm = strstr(optarg, "pm") ? 1 : 0;
			}
			break;
		case 'L':
			//use 7680 for approx 8GB
			dbi.dbsiz = atol(optarg) * 1000000;
			break;
		case 'm':
			do_mmap = 1;
			break;
		case 'D':
			dbi.flags |= DBI_FLAGS_FDSYNC;
			break;
		case 'N':
			dbi.flags |= DBI_FLAGS_READMMAP;
			break;
		case 'i':
			strncpy(dbi.ifname, optarg, sizeof(dbi.ifname));
			break;
		case 'x': /* PASTE */
			dbi.flags |= DBI_FLAGS_PASTE;
			// use 7500 to fill up 8 GB mem
			dbi.g.extmem_siz = atol(optarg) * 1000000;
			// believe 90 % is available for bufs
			dbi.g.extra_bufs = (dbi.g.extmem_siz / 2048) / 10 * 9;
			dbi.dbsiz = dbi.g.extra_bufs * 8 * 2;
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
#ifdef WITH_BPLUS
		case 'B':
			dbi.flags |= DBI_FLAGS_BPLUS;
			break;
#endif /* WITH_BPLUS */
#ifdef WITH_KVS
		case 'k':
			dbi.flags |= DBI_FLAGS_KVS;
			break;
#endif /* WITH_KVS */
		}

	}

	fprintf(stderr, "%s built %s %s db: %s\n",
		argv[0], __DATE__, __TIME__, dbi.path ? dbi.path : "none");
	usleep(1000);

	argc -= optind;
	argv += optind;

	if (!port || !dbi.msglen)
		usage();
	else if (dbi.flags & DBI_FLAGS_PASTE && strlen(dbi.ifname) == 0)
		usage();

	/* Preallocate HTTP header ? */
	if (dbi.httplen) {
		dbi.http = calloc(1, MAX_HTTPLEN);
		if (!dbi.http) {
			perror("calloc");
			usage();
		}
		dbi.httplen = generate_http(dbi.msglen, dbi.http, NULL);
		D("preallocated http %d", dbi.httplen);
	}

	if (create_db(dbi.type, dbi.flags, &dbi.vp, dbi.path, &dbi.dumbfd,
			do_mmap ? &dbi.paddr : NULL, dbi.dbsiz,
			dbi.ifname, strlen(dbi.ifname))) {
		goto close;
	}

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
		if (dbi.flags & DBI_FLAGS_PASTE) {
			int fd;

			unlink(PMEMFILE);
			fd = dbi.extmemfd = open(PMEMFILE,
					O_RDWR|O_CREAT, S_IRWXU);
	                if (fd < 0) {
	                        perror("open");
	                        goto close_socket;
	                }
			if (fallocate(fd, 0, 0, dbi.g.extmem_siz) < 0) {
				perror("fallocate");
				goto close_socket;
			}
	                dbi.g.extmem = _do_mmap(fd, dbi.g.extmem_siz);
	                if (dbi.g.extmem == NULL) {
				D("mmap failed");
	                        goto close_socket;
	                }
			pi = (struct netmap_pools_info *)dbi.g.extmem;
			pi->memsize = dbi.g.extmem_siz;

			pi->if_pool_objtotal = IF_OBJTOTAL;
			pi->ring_pool_objtotal = RING_OBJTOTAL;
			pi->ring_pool_objsize = RING_OBJSIZE;
			pi->buf_pool_objtotal = dbi.g.extra_bufs + 800000;

			/*
			dbi.g.extmem = malloc(2152000000);
			if (dbi.g.extmem == NULL) {
				perror("malloc");
				goto close_socket;
			}
			*/
			D("mmap success");
		}
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
			munmap(dbi.g.extmem, dbi.g.extmem_siz);
		close(dbi.extmemfd);
		remove(PMEMFILE);
		//free(dbi.g.extmem);
	}
#endif /* WITH_EXTMEM */

	if (sd > 0)
		close(sd);
close:
	close_db(dbi.path, dbi.type, dbi.paddr, dbi.dbsiz, &dbi.dumbfd);
	return (0);
}
