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
close_db(struct dbinfo *dbip)
{
	struct stat st;
	const char *path = dbip->path;
#ifdef WITH_SQLITE
	char path_wal[64], path_shm[64];
#endif

	/* close reference */
	if (dbip->type == DT_DUMB) {
		if (dbip->paddr)
			if (munmap(dbip->paddr, dbip->dbsiz))
				perror("munmap");
		if (dbip->dumbfd > 0) {
			D("closing dumbfd");
			close(dbip->dumbfd);
		}
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
	l = sprintf(p, "%lu\r\n\r\n", content_length);
	p += l;
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
parse_post(char *post, int *coff, uint64_t *key)
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

#ifdef WITH_KVS
static struct netmap_slot *
set_to_nm(struct netmap_ring *txr, struct netmap_slot *any_slot)
{
	struct netmap_slot *txs, tmp;

	if (unlikely(nm_ring_space(txr) == 0)) {
		return NULL;
	}
	txs = &txr->slot[txr->cur];
	tmp = *txs;
	*txs = *any_slot;
	txs->flags |= NS_BUF_CHANGED;
	*any_slot = tmp;
	txr->cur = txr->head = nm_ring_next(txr, txr->cur);
	return txs;
}

enum {SLOT_INVALID=0, SLOT_EXTRA, SLOT_USER, SLOT_KERNEL};
static inline int
is_slot_extra(struct netmap_ring *ring, struct netmap_slot *extra,
		u_int extra_num, struct netmap_slot *slot)
{
	if ((uintptr_t)slot > (uintptr_t)ring->slot && 
	    (uintptr_t)slot < (uintptr_t)(ring->slot + ring->num_slots))
		return 0;
	else if ((uintptr_t)slot > (uintptr_t)extra &&
	    (uintptr_t)slot < (uintptr_t)(extra + extra_num))
		return 1;
	return -1;
}

//POST http://www.micchie.net/ HTTP/1.1\r\nHost: 192.168.11.3:60000\r\nContent-Length: 1280\r\n\r\n2
//HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nServer: //Apache/2.2.800\r\nContent-Length: 1280\r\n\r\n
#define KVS_SLOT_OFF 55
static inline void
kvs_embed_slot(char *buf, struct netmap_slot *slot)
{
	*(struct netmap_slot **)(buf + KVS_SLOT_OFF) = slot;
}

static inline struct netmap_slot*
kvs_extract_slot(struct netmap_ring *ring, uint32_t buf_idx, size_t off)
{
	char *buf = NETMAP_BUF(ring, buf_idx);
	return *(struct netmap_slot **)(buf + off + KVS_SLOT_OFF);
}

ssize_t
kvs_generate_httphdr(ssize_t content_length, char *buf)
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
	l = sprintf(p, "%lu\r\n\r\n", content_length);
	p += l;
	return p - buf;
}

#endif /* WITH_KVS */

#ifdef WITH_BPLUS
static inline void
paste_bplus(gfile_t *vp, btree_key key, struct netmap_slot *slot, size_t off, size_t len)
{
	uint64_t pst_ent;
	//uint64_t datam;
	static int unique = 0;
	int rc;

	pst_ent = (uint64_t)slot->buf_idx << 32 | off<< 16 | len;
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
	pst_ent = (uint64_t)slot->buf_idx << 32 | off<< 16 | len;
	/* position log */
	if (unlikely(plen > dbsiz - phdrlen - cur))
		cur = 0;
	p += phdrlen + cur;
	*(uint64_t *)p = pst_ent;
	_mm_clflush(p);
	*pos = cur + plen;
}

static inline void
copy_and_log(char *paddr, size_t *pos, size_t dbsiz, char *buf,
		size_t len, int nowrap, int align, int pm, void *vp, void *key_p)
{
	char *p;
	int mlen = vp ? 0 : sizeof(uint64_t);
	size_t cur = *pos;
	int phdrlen = sizeof(struct paste_hdr); // dummy common metadata header
	u_int i = 0;
	size_t aligned = len;

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
		for (; i < len; i += CACHE_LINE_SIZE){
			_mm_clflush(p + i);
		}
	} else {
		int error = msync(p, len, MS_SYNC);
		if (error)
			perror("msync");
	}
	p -= mlen;
#ifdef WITH_BPLUS
	if (vp) {
		static int unique = 0;
		int rc;

		rc = btree_insert(vp, *(btree_key *)key_p,
				(uint32_t)cur / NETMAP_BUF_SIZE);
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
	*pos = cur + aligned + mlen;
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

		off = g->virt_header + rxs->offset;
		rxbuf = NETMAP_BUF(rxr, rxs->buf_idx) + off;
	       	len = rxs->len - off;

		if (!strncmp(rxbuf, "POST ", POST_LEN)) {
			uint64_t key;
			int coff, clen = parse_post(rxbuf, &coff, &key);

			thisclen = len - coff;

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
					struct netmap_slot tmp;
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
					tmp = *rxs;
					rxs->buf_idx = tp->extra[extra_i].buf_idx;
					rxs->flags |= NS_BUF_CHANGED;
					tp->extra[extra_i] = tmp;

					/* record current slot */
					if (dbi->flags & DBI_FLAGS_KVS) {
						kvs_embed_slot(rxbuf,
							&tp->extra[extra_i]);
					}
#else
					i = rxs->buf_idx;
					rxs->buf_idx = tp->extra[extra_i];
					rxs->flags |= NS_BUF_CHANGED;
					tp->extra[extra_i] = i;
#endif

				} else if (paddr) {
					copy_and_log(paddr, &tp->cur,
					    dbsiz, rxbuf + off, len,
					    len, dbi->pm ? 0 : dbi->pgsiz,
					    dbi->pm, dbi->vp, &key);
				} else {
					if (writesync(rxbuf, len, dbsiz,
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
#ifdef WITH_BPLUS
			uint64_t key = parse_get_key(rxbuf);

			if (dbi->vp && dbi->flags & DBI_FLAGS_PASTE) {
				uint64_t datam = 0;
#ifdef WITH_KVS
				uint32_t idx;
				uint16_t _off, _len;
				struct netmap_slot *s;
				int slot_type;
#endif

				btree_lookup(dbi->vp, key, &datam);

#ifdef WITH_KVS
				idx = datam >> 32;
				_off = (datam & 0x00000000ffff0000) >> 16;
				_len = datam & 0x000000000000ffff;
				s = kvs_extract_slot(rxr, idx, off);
				slot_type = is_slot_extra(txr, tp->extra, tp->extra_num, s);

				if (slot_type == 1) { // on extra, swap in
					struct netmap_slot *txs;
					u_int hlen;
					char *_buf;

					ND("key %lu val %lu idx %u off %u len %u slot_type %d", key, datam, idx, _off, _len, slot_type);
					txs = set_to_nm(txr, s);
					_buf = NETMAP_BUF(txr, txs->buf_idx);
					hlen = kvs_generate_httphdr(_len, _buf + off);
					if (unlikely(hlen != _off - off)) {
						D("hlen %u _off %u off %u",
							hlen, _off, off);
					} else {
						D("zero copy done!");
					}
					kvs_embed_slot(_buf + off, txs);
					slot_type = is_slot_extra(txr, tp->extra, tp->extra_num, txs);
					D("afterembedded, slot type %d", slot_type);
				}
#endif
			}
#endif
get:
			if (dbi->httplen) { // use cache
				char *http = dbi->http;
				int hlen = dbi->httplen;

				if (copy_to_nm(txr, g->virt_header, http, hlen,
						o, o, rxs->fd) < hlen) {
					continue;
				}
			} else {
				if (generate_http_nm(msglen, txr,
				    g->virt_header, o, rxs->fd, NULL) < 0)
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
		nm_update_ctr(targ, 1, len);
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

	rxbuf = txbuf = buf;
	if (readmmap) {
		size_t cur = tp->cur;
		max = dbi->dbsiz - sizeof(struct paste_hdr) - cur;
		if (max < dbi->pgsiz) {
			cur = 0;
			max = dbi->dbsiz;
		}
		rxbuf = paddr + tp->cur + sizeof(uint64_t);
		max -= sizeof(uint64_t);
	} else {
		max = sizeof(buf);
	}
	len = read(fd, rxbuf, max);
	if (len == 0) {
		close(fd);
		return 0;
	} else if (len < 0) {
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
				    readmmap ? NULL : rxbuf, len,
				    dbi->pgsiz, dbi->pm ? 0 : dbi->pgsiz,
				    dbi->pm, dbi->vp, &key);
			} else {
				if (writesync(rxbuf, len, dbi->dbsiz,
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
gen_httpok:
		if (!dbi->httplen) {
			len = generate_http(msglen, txbuf, NULL);
		} else {
			len = dbi->httplen;
			memcpy(txbuf, dbi->http, len);
		}
	} else if (strncmp(rxbuf, "GET ", GET_LEN) == 0) {
		goto gen_httpok;
	} else {
		len = 0;
	}
	write(fd, txbuf, len);
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

#ifdef WITH_BPLUS
	/* B+tree ? */
	if (dbi.type == DT_DUMB && (dbi.flags & DBI_FLAGS_BPLUS)) {
		int rc;
		rc = btree_create_btree(BPLUSFILE, ((gfile_t **)&dbi.vp));
		D("btree_create_btree() done (%d)", rc);
	}
#endif /* WITH_BPLUS */
	if (dbi.type == DT_DUMB &&
	    !(dbi.flags & DBI_FLAGS_BPLUS && dbi.flags & DBI_FLAGS_PASTE)) {
		unlink(dbi.path);
		dbi.dumbfd = open(dbi.path, O_RDWR | O_CREAT, S_IRWXU);
		if (dbi.dumbfd < 0) {
			perror("open");
			goto close;
		}
		if (do_mmap) {
			if (fallocate(dbi.dumbfd, 0, 0, dbi.dbsiz) < 0) {
				perror("fallocate");
				goto close;
			}
			dbi.paddr = _do_mmap(dbi.dumbfd, dbi.dbsiz);
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
	close_db(&dbi);
	return (0);
}
