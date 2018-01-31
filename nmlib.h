#ifndef _NMLIB_H_
#define _NMLIB_H_
#include <math.h>
#ifdef __FreeBSD__
#include<sys/cpuset.h>
#include <pthread_np.h> /* pthread w/ affinity */
#endif
#include<net/netmap.h>
#include<net/netmap_user.h>
#include<ctrs.h>
#include<pthread.h>
#include<sys/sysctl.h>	/* sysctl */
#include <netinet/tcp.h>	/* SOL_TCP */

#ifndef D
#define D(fmt, ...) \
	printf(""fmt"\n", ##__VA_ARGS__)
#endif

#define MAX_IFNAMELEN	64
#define VIRT_HDR_1	10	/* length of a base vnet-hdr */
#define VIRT_HDR_2	12	/* length of the extenede vnet-hdr */
#define VIRT_HDR_MAX	VIRT_HDR_2
#define MAP_HUGETLB	0x40000

enum dev_type { DEV_NONE, DEV_NETMAP, DEV_SOCKET };
enum { TD_TYPE_SENDER = 1, TD_TYPE_RECEIVER, TD_TYPE_OTHER, TD_TYPE_DUMMY };

#ifdef linux
#define cpuset_t        cpu_set_t
#endif
/* set the thread affinity. */
static inline int
setaffinity(pthread_t me, int i)
{
	cpuset_t cpumask;

	if (i == -1)
		return 0;

	/* Set thread affinity affinity.*/
	CPU_ZERO(&cpumask);
	CPU_SET(i, &cpumask);

	if (pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0) {
		D("Unable to set affinity: %s", strerror(errno));
		return 1;
	}
	return 0;
}

static void
tx_output(struct my_ctrs *cur, double delta, const char *msg)
{
	double bw, raw_bw, pps, abs;
	char b1[40], b2[80], b3[80];
	int size;

	if (cur->pkts == 0) {
		printf("%s nothing.\n", msg);
		return;
	}

	size = (int)(cur->bytes / cur->pkts);

	printf("%s %llu packets %llu bytes %llu events %d bytes each in %.2f seconds.\n",
		msg,
		(unsigned long long)cur->pkts,
		(unsigned long long)cur->bytes,
		(unsigned long long)cur->events, size, delta);
	if (delta == 0)
		delta = 1e-6;
	if (size < 60)		/* correct for min packet size */
		size = 60;
	pps = cur->pkts / delta;
	bw = (8.0 * cur->bytes) / delta;
	/* raw packets have4 bytes crc + 20 bytes framing */
	raw_bw = (8.0 * (cur->pkts * 24 + cur->bytes)) / delta;
	abs = cur->pkts / (double)(cur->events);

	printf("Speed: %spps Bandwidth: %sbps (raw %sbps). Average batch: %.2f pkts\n",
		norm(b1, pps), norm(b2, bw), norm(b3, raw_bw), abs);
}

struct nm_msg {
	struct netmap_ring *rxring;
	struct netmap_ring *txring;
	struct netmap_slot *slot;
	struct nm_targ *targ;
};

struct nm_garg {
	char ifname[MAX_IFNAMELEN]; // must be here
	struct nm_desc *nmd;
	void *(*td_body)(void *);
	void *(*td_privbody)(void *);
	int nthreads;
	int affinity;
	int dev_type;
	int td_type;
	int main_fd;
	int system_cpus;
	int cpus;
	int virt_header;	/* send also the virt_header */
	int extra_bufs;		/* goes in nr_arg3 */
	uint64_t extmem_siz;
	int extra_pipes;	/* goes in nr_arg1 */
	char *nmr_config;
	char *extmem;		/* goes to nr_arg1+ */
#define	STATS_WIN	15
	int win_idx;
	int64_t win[STATS_WIN];
	int wait_link;
	int polltimeo;
#ifdef __FreeBSD__
	struct timespec *polltimeo_ts;
#endif
	int verbose;
	int report_interval;
#define OPT_PPS_STATS   2048
	int options;
	int td_private_len; // passed down to targ

	struct nm_ifreq ifreq;
	void (*data)(struct nm_msg *);
	void (*connection)(struct nm_msg *);
	int *fds;
	int fdnum;
};

struct nm_targ {
	struct nm_garg *g;
	struct nm_desc *nmd;
	/* these ought to be volatile, but they are
	 * only sampled and errors should not accumulate
	 */
	struct my_ctrs ctr;

	struct timespec tic, toc;
	int used;
	int completed;
	int cancel;
	int fd;
	int me;
	int affinity;
	pthread_t thread;
	struct netmap_slot *extra;
	uint32_t extra_cur;
	uint32_t extra_num;
	void *td_private;
	int *fdtable;
	int fdtable_siz;

};

static inline void
nm_update_ctr(struct nm_targ *targ, int npkts, int nbytes)
{
	targ->ctr.pkts += npkts;
	targ->ctr.bytes += nbytes;
}

static struct nm_targ *targs;
static int global_nthreads;

/* control-C handler */
static void
sigint_h(int sig)
{
	int i;

	(void)sig;	/* UNUSED */
	D("received control-C on thread %p", (void *)pthread_self());
	for (i = 0; i < global_nthreads; i++) {
		targs[i].cancel = 1;
	}
}


/* sysctl wrapper to return the number of active CPUs */
static int
system_ncpus(void)
{
	int ncpus;
#if defined (__FreeBSD__)
	int mib[2] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(mib);
	sysctl(mib, 2, &ncpus, &len, NULL, 0);
#elif defined(linux)
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(_WIN32)
	{
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		ncpus = sysinfo.dwNumberOfProcessors;
	}
#else /* others */
	ncpus = 1;
#endif /* others */
	return (ncpus);
}

static int
nm_parse_nmr_config(const char* conf, struct nmreq *nmr)
{
	char *w, *tok;
	int i, v;

	nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
	nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
	if (conf == NULL || ! *conf)
		return 0;
	w = strdup(conf);
	for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
		v = atoi(tok);
		switch (i) {
		case 0:
			nmr->nr_tx_slots = nmr->nr_rx_slots = v;
			break;
		case 1:
			nmr->nr_rx_slots = v;
			break;
		case 2:
			nmr->nr_tx_rings = nmr->nr_rx_rings = v;
			break;
		case 3:
			nmr->nr_rx_rings = v;
			break;
		default:
			D("ignored config: %s", tok);
			break;
		}
	}
	D("txr %d txd %d rxr %d rxd %d",
			nmr->nr_tx_rings, nmr->nr_tx_slots,
			nmr->nr_rx_rings, nmr->nr_rx_slots);
	free(w);
	return (nmr->nr_tx_rings || nmr->nr_tx_slots ||
                        nmr->nr_rx_rings || nmr->nr_rx_slots) ?
		NM_OPEN_RING_CFG : 0;
}

static void
get_vnet_hdr_len(struct nm_garg *g)
{
	struct nmreq req;
	int err;

	memset(&req, 0, sizeof(req));
	bcopy(g->nmd->req.nr_name, req.nr_name, sizeof(req.nr_name));
	req.nr_version = NETMAP_API;
	req.nr_cmd = NETMAP_VNET_HDR_GET;
	err = ioctl(g->main_fd, NIOCREGIF, &req);
	if (err) {
		D("Unable to get virtio-net header length");
		return;
	}

	g->virt_header = req.nr_arg1;
	if (g->virt_header) {
		D("Port requires virtio-net header, length = %d",
		  g->virt_header);
	}
}

static void
set_vnet_hdr_len(struct nm_garg *g)
{
	int err, l = g->virt_header;
	struct nmreq req;

	if (l == 0)
		return;

	memset(&req, 0, sizeof(req));
	bcopy(g->nmd->req.nr_name, req.nr_name, sizeof(req.nr_name));
	req.nr_version = NETMAP_API;
	req.nr_cmd = NETMAP_BDG_VNET_HDR;
	req.nr_arg1 = l;
	err = ioctl(g->main_fd, NIOCREGIF, &req);
	if (err) {
		D("Unable to set virtio-net header length %d", l);
	}
}

static void *
nm_thread(void *data)
{
	struct nm_targ *targ = (struct nm_targ *) data;
	struct nm_garg *g = targ->g;

	D("start, fd %d main_fd %d affinity %d",
			targ->fd, targ->g->main_fd, targ->affinity);
	if (setaffinity(targ->thread, targ->affinity))
		goto quit;
	g->td_privbody(data);

quit:
	targ->used = 0;
	return (NULL);
}

static int
nm_start_threads(struct nm_garg *g)
{
	int i;
	struct nm_targ *t;

	targs = calloc(g->nthreads, sizeof(*targs));
	if (!targs) {
		return -ENOMEM;
	}
	for (i = 0; i < g->nthreads; i++) {
		t = &targs[i];

		bzero(t, sizeof(*t));
		t->fd = -1;
		t->g = g;
		t->td_private = calloc(g->td_private_len, 1);
		if (t->td_private == NULL) {
			continue;
		}

		if (g->dev_type == DEV_NETMAP) {
			/* copy, we overwrite ringid */
			struct nm_desc nmd = *g->nmd;
			uint64_t nmd_flags = 0;
			nmd.self = &nmd;

			if (i > 0) {
				/* the first thread uses the fd opened by the
				 * main thread, the other threads re-open
				 * /dev/netmap
				 */
				if (g->nthreads > 1) {
					nmd.req.nr_flags =
					    nmd.req.nr_flags & ~NR_REG_MASK;
					nmd.req.nr_flags |= NR_REG_ONE_NIC;
					nmd.req.nr_ringid = i;
					if (nmd.req.nr_arg3) { /* extra buffers */
						D("setting nmd_flags NM_OPEN_ARG3 for %u", nmd.req.nr_arg3);
						nmd_flags |= NM_OPEN_ARG3;
					}
				}
				/* Only touch one of the rings
				 * (rx is already ok)
				 */
				if (g->td_type == TD_TYPE_RECEIVER)
					nmd_flags |= NETMAP_NO_TX_POLL;

				/* register interface. Override ifname and ringid etc. */
				t->nmd = nm_open(t->g->ifname, NULL, nmd_flags
						| NM_OPEN_IFNAME
						| NM_OPEN_NO_MMAP, &nmd);
				if (t->nmd == NULL) {
					D("Unable to open %s: %s", t->g->ifname,
						       	strerror(errno));
					continue;
				}
				D("got %u extra bufs at %u",
				    t->nmd->req.nr_arg3,
				    t->nmd->nifp->ni_bufs_head);
			} else {
				t->nmd = g->nmd;
			}
			t->fd = t->nmd->fd;

		}
		t->used = 1;
		t->me = i;
		if (g->affinity >= 0) {
			t->affinity = (g->affinity + i) % g->system_cpus;
		} else {
			t->affinity = -1;
		}
	}
	/* Wait for PHY reset. */
	D("Wait %d secs for phy reset", g->wait_link);
	sleep(g->wait_link);
	D("Ready...");

	D("nthreads %d", g->nthreads);
	for (i = 0; i < g->nthreads; i++) {
		t = &targs[i];
		if (pthread_create(&t->thread, NULL, &nm_thread, t) == -1) {
			D("Unable to create thread %d: %s", i, strerror(errno));
			t->used = 0;
		}
	}
	return 0;
}

static void
nm_main_thread(struct nm_garg *g)
{
	int i;

	struct my_ctrs prev, cur;
	double delta_t;
	struct timeval tic, toc;

	prev.pkts = prev.bytes = prev.events = 0;
	gettimeofday(&prev.t, NULL);
	for (;;) {
		char b1[40], b2[40], b3[40], b4[70];
		uint64_t pps, usec;
		struct my_ctrs x;
		double abs;
		int done = 0;

		usec = wait_for_next_report(&prev.t, &cur.t,
				g->report_interval);

		cur.pkts = cur.bytes = cur.events = 0;
		cur.min_space = 0;
		if (usec < 10000) /* too short to be meaningful */
			continue;
		/* accumulate counts for all threads */
		for (i = 0; i < g->nthreads; i++) {
			cur.pkts += targs[i].ctr.pkts;
			cur.bytes += targs[i].ctr.bytes;
			cur.events += targs[i].ctr.events;
			cur.min_space += targs[i].ctr.min_space;
			targs[i].ctr.min_space = 99999;
			if (targs[i].used == 0)
				done++;
		}
		x.pkts = cur.pkts - prev.pkts;
		x.bytes = cur.bytes - prev.bytes;
		x.events = cur.events - prev.events;
		pps = (x.pkts*1000000 + usec/2) / usec;
		abs = (x.events > 0) ? (x.pkts / (double) x.events) : 0;

		if (!(g->options & OPT_PPS_STATS)) {
			strcpy(b4, "");
		} else {
			/* Compute some pps stats using a sliding window. */
			double ppsavg = 0.0, ppsdev = 0.0;
			int nsamples = 0;

			g->win[g->win_idx] = pps;
			g->win_idx = (g->win_idx + 1) % STATS_WIN;

			for (i = 0; i < STATS_WIN; i++) {
				ppsavg += g->win[i];
				if (g->win[i]) {
					nsamples ++;
				}
			}
			ppsavg /= nsamples;

			for (i = 0; i < STATS_WIN; i++) {
				if (g->win[i] == 0) {
					continue;
				}
				ppsdev += (g->win[i] - ppsavg) * (g->win[i] - ppsavg);
			}
			ppsdev /= nsamples;
			ppsdev = sqrt(ppsdev);

			snprintf(b4, sizeof(b4), "[avg/std %s/%s pps]",
				 norm(b1, ppsavg), norm(b2, ppsdev));
		}

		D("%spps %s(%spkts %sbps in %llu usec) %.2f avg_batch %d min_space",
			norm(b1, pps), b4,
			norm(b2, (double)x.pkts),
			norm(b3, (double)x.bytes*8),
			(unsigned long long)usec,
			abs, (int)cur.min_space);
		prev = cur;

		if (done == g->nthreads)
			break;
	}

	timerclear(&tic);
	timerclear(&toc);
	cur.pkts = cur.bytes = cur.events = 0;
	/* final round */
	for (i = 0; i < g->nthreads; i++) {
		struct timespec t_tic, t_toc;
		/*
		 * Join active threads, unregister interfaces and close
		 * file descriptors.
		 */
		if (targs[i].used)
			pthread_join(targs[i].thread, NULL); /* blocking */
		if (g->dev_type == DEV_NETMAP) {
			nm_close(targs[i].nmd);
			targs[i].nmd = NULL;
		} else if (targs[i].fd > 2) {
			close(targs[i].fd);
		}
		if (targs[i].completed == 0)
			D("ouch, thread %d exited with error", i);
		/*
		 * Collect threads output and extract information about
		 * how long it took to send all the packets.
		 */
		cur.pkts += targs[i].ctr.pkts;
		cur.bytes += targs[i].ctr.bytes;
		cur.events += targs[i].ctr.events;
		/* collect the largest start (tic) and end (toc) times,
		 * XXX maybe we should do the earliest tic, or do a weighted
		 * average ?
		 */
		t_tic = timeval2spec(&tic);
		t_toc = timeval2spec(&toc);
		if (!timerisset(&tic) || timespec_ge(&targs[i].tic, &t_tic))
			tic = timespec2val(&targs[i].tic);
		if (!timerisset(&toc) || timespec_ge(&targs[i].toc, &t_toc))
			toc = timespec2val(&targs[i].toc);

	}
	/* print output. */
	timersub(&toc, &tic, &toc);
	delta_t = toc.tv_sec + 1e-6* toc.tv_usec;
	if (g->td_type == TD_TYPE_SENDER)
		tx_output(&cur, delta_t, "Sent");
	else if (g->td_type == TD_TYPE_RECEIVER)
		tx_output(&cur, delta_t, "Received");
}

static int
nm_start(struct nm_garg *g)
{
	int i, devqueues = 0;
	struct nm_desc base_nmd;
	struct sigaction sa;
	sigset_t ss;
	char *p;

	char errmsg[MAXERRMSG];
	u_int flags;
	struct nmreq req; // only for suffix and extmem

	bzero(&req, sizeof(req));
	g->main_fd = -1;
	g->wait_link = 3;
	g->report_interval = 2000;
	g->cpus = g->system_cpus = i = system_ncpus();
	if (g->nthreads == 0)
		g->nthreads = 1;
	if (g->cpus < 0 || g->cpus > i) {
		D("%d cpus is too high, have only %d cpus", g->cpus, i);
		return -EINVAL;
	}
	D("running on %d cpus (have %d)", g->cpus, i);
	if (g->cpus == 0)
		g->cpus = i;

	if (g->dev_type != DEV_NETMAP)
		goto nonetmap;

	if (g->virt_header != 0 && g->virt_header != VIRT_HDR_1
			&& g->virt_header != VIRT_HDR_2) {
		D("bad virtio-net-header length");
		return -EINVAL;
	}

	bzero(&base_nmd, sizeof(base_nmd));

	nm_parse_nmr_config(g->nmr_config, &base_nmd.req);
	if (g->extra_bufs) {
		base_nmd.req.nr_arg3 = g->extra_bufs / g->nthreads;
	}
	if (g->extra_pipes) {
		base_nmd.req.nr_arg1 = g->extra_pipes;
	}
#ifdef WITH_EXTMEM
	if (g->extmem) {
		req.nr_cmd2 = NETMAP_POOLS_CREATE;
                memcpy((void *)&req.nr_ptr, &g->extmem, sizeof(void *));
	}
#endif /* WITH_EXTMEM */
	base_nmd.req.nr_flags |= NR_ACCEPT_VNET_HDR;

	if (nm_parse(g->ifname, &base_nmd, errmsg) < 0) {
		D("Invalid name '%s': %s", g->ifname, errmsg);
		return -EINVAL;
	}
	if (strlen(base_nmd.req.nr_extname) > 0) {
		strncpy(req.nr_extname, base_nmd.req.nr_extname,
				sizeof(req.nr_extname));
		bzero(base_nmd.req.nr_extname, sizeof(base_nmd.req.nr_extname));
	}

	/*
	 * Open the netmap device using nm_open().
	 *
	 * protocol stack and may cause a reset of the card,
	 * which in turn may take some time for the PHY to
	 * reconfigure. We do the open here to have time to reset.
	 */
	flags = NM_OPEN_IFNAME | NM_OPEN_RING_CFG;
	flags |= NM_OPEN_ARG1 | NM_OPEN_ARG2 | NM_OPEN_ARG3;
	if (g->nthreads > 1) {
		base_nmd.req.nr_flags &= ~NR_REG_MASK;
		base_nmd.req.nr_flags |= NR_REG_ONE_NIC;
		base_nmd.req.nr_ringid = 0;
	}
	g->nmd = nm_open(g->ifname, &req, flags, &base_nmd);
	if (g->nmd == NULL) {
		D("Unable to open %s: %s", g->ifname, strerror(errno));
		goto out;
	}
	ND("got %u extra bufs at %u", g->nmd->req.nr_arg3,
			g->nmd->nifp->ni_bufs_head);

	/* XXX remove unnecessary suffix */
	if ((p = index(g->ifname, ','))) {
		*p = '\0';
	}
	if ((p = index(g->ifname, '+'))) {
		*p = '\0';
	}

	g->main_fd = g->nmd->fd;
	D("mapped %lu at %p", g->nmd->req.nr_memsize>>10, g->nmd->mem);

	if (g->virt_header) {
		/* Set the virtio-net header length, since the user asked
		 * for it explicitely. */
		set_vnet_hdr_len(g);
	} else {
		/* Check whether the netmap port we opened requires us to send
		 * and receive frames with virtio-net header. */
		get_vnet_hdr_len(g);
	}

	/* get num of queues in tx or rx */
	if (g->td_type == TD_TYPE_SENDER)
		devqueues = g->nmd->req.nr_tx_rings;
	else
		devqueues = g->nmd->req.nr_rx_rings;

	/* validate provided nthreads. */
	if (g->nthreads < 1 || g->nthreads > devqueues) {
		D("bad nthreads %d, have %d queues", g->nthreads, devqueues);
		// continue, fail later
	}

	if (g->verbose) {
		struct netmap_if *nifp = g->nmd->nifp;
		struct nmreq *req = &g->nmd->req;

		D("nifp at offset %d, %d tx %d rx region %d",
		    req->nr_offset, req->nr_tx_rings, req->nr_rx_rings,
		    req->nr_arg2);
		for (i = 0; i <= req->nr_tx_rings; i++) {
			struct netmap_ring *ring = NETMAP_TXRING(nifp, i);
			D("   TX%d at 0x%p slots %d", i,
			    (void *)((char *)ring - (char *)nifp), ring->num_slots);
		}
		for (i = 0; i <= req->nr_rx_rings; i++) {
			struct netmap_ring *ring = NETMAP_RXRING(nifp, i);
			D("   RX%d at 0x%p slots %d", i,
			    (void *)((char *)ring - (char *)nifp), ring->num_slots);
		}
	}

nonetmap:
	/* Print some debug information. */
	fprintf(stdout,
		"%s %s: %d queues, %d threads and %d cpus.\n", "Working on",
		g->ifname,
		devqueues,
		g->nthreads,
		g->cpus);
out:
	/* return -1 if something went wrong. */
	if (g->dev_type == DEV_NETMAP && g->main_fd < 0) {
		D("aborting");
		return -1;
	} else if (g->td_type == TD_TYPE_DUMMY) {
		D("this is dummy, %s and returning",
				g->main_fd < 0 ? "failed" : "success");
		return 0;
	}

	/* Install ^C handler. */
	global_nthreads = g->nthreads;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	/* block SIGINT now, so that all created threads will inherit the mask */
	if (pthread_sigmask(SIG_BLOCK, &ss, NULL) < 0) {
		D("failed to block SIGINT: %s", strerror(errno));
	}
	nm_start_threads(g);
	/* Install the handler and re-enable SIGINT for the main thread */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_h;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		D("failed to install ^C handler: %s", strerror(errno));
	}

	if (pthread_sigmask(SIG_UNBLOCK, &ss, NULL) < 0) {
		D("failed to re-enable SIGINT: %s", strerror(errno));
	}

	nm_main_thread(g);

	for (i = 0; i < g->nthreads; i++) {
		if (targs[i].td_private)
			free(targs[i].td_private);
	}
	free(targs);
	return 0;
}

#define ST_NAME "stack:0"
#define ST_NAME_MAX	64
static void
netmap_eventloop(void **ret, int *error,
	void (*data)(struct nm_msg *), void (*connection)(struct nm_msg *))
{
	struct nm_garg *g = calloc(1, sizeof(*g));
	char ifname[8] = "eth1"; /* XXX */

	*error = 0;
	if (!g) {
		perror("calloc");
		*error = -ENOMEM;
		return;
	}
	g->polltimeo = 1000;
	g->td_privbody = NULL; // TODO netmap_worker;
	g->dev_type = DEV_NETMAP;
	g->connection = connection;
	g->data = data;
	*ret = g;

	signal(SIGPIPE, SIG_IGN);

	if (strlen(ifname)) {
		char *p = g->ifname;
		struct nm_ifreq *ifreq = &g->ifreq;

		if (strlen(ST_NAME) + 1 + strlen(ifname) > ST_NAME_MAX) {
			D("too long name %s", ifname);
			*error = -EINVAL;
			return;
		}
		strcat(strcat(strcpy(p, ST_NAME), "+"), ifname);

		/* pre-initialize ifreq for accept() */
		bzero(ifreq, sizeof(*ifreq));
		strncpy(ifreq->nifr_name, ST_NAME, sizeof(ifreq->nifr_name));
	}
	*error = nm_start(g);
}

#define IPV4TCP_HDRLEN	66
static int
netmap_sendmsg (struct nm_msg *msgp, void *data, size_t len)
{
	struct nm_targ *t = msgp->targ;
	struct netmap_ring *ring = (struct netmap_ring *) msgp->txring;
	u_int cur = ring->cur;
	int virt_header = t->g->virt_header;
	struct netmap_slot *slot = &ring->slot[cur];
	char *p = NETMAP_BUF(ring, slot->buf_idx) + virt_header + IPV4TCP_HDRLEN;

	D ("Sending %lu bytes\n", len);
	memcpy (p, data, len);
	slot->len = virt_header + IPV4TCP_HDRLEN + len;
    	slot->fd = msgp->slot->fd;
    	slot->offset = IPV4TCP_HDRLEN;
	ring->cur = ring->head = nm_ring_next(ring, cur);
	return len;
}

/* XXX wrap */
static inline uint32_t
netmap_extra_next(struct nm_targ *t, size_t *curp)
{
	uint32_t ret = t->extra_cur++;

	if (unlikely(t->extra_cur == t->extra_num)) {
		t->extra_cur = 0;
		*curp = 0; //clear log too
	}
	return ret;
}

static void inline
netmap_copy_out(struct nm_msg *nmsg)
{
	struct netmap_ring *ring = nmsg->rxring;
	struct netmap_slot *slot = nmsg->slot;
	struct nm_targ *t = nmsg->targ;
	char *p, *ep;
	uint32_t i = slot->buf_idx;
	uint32_t extra_i = netmap_extra_next(t, &t->extra_cur);
	u_int off = t->g->virt_header + slot->offset;
	u_int len = slot->len - off;

	p = NETMAP_BUF(ring, i) + off;
	ep = NETMAP_BUF(ring, extra_i) + off;
	memcpy(ep, p, len);
	for (i = 0; i < len; i += 64) {
		_mm_clflush(ep, i);
	}
}

/* XXX should we update nmsg->slot to new one? */
static void inline
netmap_swap_out(struct nm_msg *nmsg)
{
	struct netmap_ring *ring = nmsg->rxring;
	struct netmap_slot *slot = nmsg->slot, *extra, tmp;
	struct nm_targ *t = nmsg->targ;
	uint32_t i = slot->buf_idx;
	uint32_t extra_i = netmap_extra_next(t, &t->extra_cur);

	tmp = *slot;
	extra = &t->extra[extra_i];
	slot->buf_idx = extra->buf_idx;
	slot->flags |= NS_BUF_CHANGED;
	*extra = tmp;
}

static void *
netmap_worker(void *data)
{
	struct nm_targ *t = (struct nm_targ *) data;
	struct nm_garg *g = t->g;
	struct nm_desc *nmd = t->nmd;
	struct pollfd pfd[2] = {{ .fd = targ->fd }}; // XXX make variable size

	/* allocate fd table */
	t->fdtable = calloc(sizeof(*t->fdtable), DEFAULT_NFDS);
	if (!t->fdtable) {
		perror("calloc");
		goto quit;
	}
	t->fdtable_siz = DEFAULT_NFDS;

	/* import extra buffers */
	if (g->dev_type == DEV_NETMAP) {
		const struct nmreq *req = &nmd->req;
		const struct netmap_if *nifp = nmd->nifp;
		const struct netmap_ring *any_ring = nmd->some_ring;
		uint32_t i, next = nifp->ni_bufs_head;
		const u_int n = req->nr_arg3;

		D("have %u extra buffers from %u ring %p", n, next, any_ring);
		tp->extra = calloc(sizeof(*tp->extra), n);
		if (!tp->extra) {
			perror("calloc");
			goto quit;
		}
		for (i = 0; i < n && next; i++) {
			char *p;
#ifdef WITH_EXTRA_SLOT
			t->extra[i].buf_idx = next;
#else
			t->extra[i] = next;
#endif
			p = NETMAP_BUF(any_ring, next);
			next = *(uint32_t *)p;
		}
		t->extra_num = i;
		D("imported %u extra buffers", i);
		t->ifreq = g->ifreq;
	} else if (g->dev_type == DEV_SOCKET) {
#ifdef linux
		struct epoll_event ev;

		t->fd = epoll_create1(EPOLL_CLOEXEC);
		if (t->fd < 0) {
			perror("epoll_create1");
			t->cancel = 1;
			goto quit;
		}

		/* XXX make variable ev num. */
		bzero(&ev, sizeof(ev));
		ev.events = POLLIN;
		ev.data.fd = g->fds[0];
		if (epoll_ctl(t->fd, EPOLL_CTL_ADD, ev.data.fd, &ev)) {
			perror("epoll_ctl");
			t->cancel = 1;
			goto quit;
		}
#else /* !linux */
		struct kevent ev;

		t->fd = kqueue();
		if (t->fd < 0) {
			perror("kqueue");
			t->cancel = 1;
			goto quit;
		}
		EV_SET(&ev, g->fds[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(t->fd, &ev, 1, NULL, 0, NULL)) {
			perror("kevent");
			t->cancel = 1;
			goto quit;
		}
#endif /* linux */
	}

	while (!targ->cancel) {
		if (g->dev_type == DEV_NETMAP) {
			u_int first_ring = nmd->first_rx_ring;
			u_int last_ring = nmd->last_rx_ring;
			int i;

			pfd[0].fd = t->fd;
			pfd[0].events = POLLIN;
			/* XXX make safer... */
			for (i = 0; i < t->g->fdnum; i++) {
				pfd[i+1].fd = t->g->fds[i];
			}
			if ((poll(pfd, i+1, t->g->polltimeo)) < 0) {
				perror("poll");
				goto quit;
			}
			/*
			 * check listen sockets
			 */
			for (i = 1; i <= t->g->fdnum; i++) {
				struct sockaddr_storage tmp;
				struct nm_ifreq *ifreq = &t->ifreq;
				int newfd;
				socklen_t len = sizeof(tmp);

				if (!(pfd[i].revents & POLLIN))
					continue;
				newfd = accept(pfd[i].fd,
						(struct sockaddr *)&tmp, &len);
				if (newfd < 0) {
					RD(1, "accept error");
					/* ignore this socket */
					goto accepted;
				}
				memcpy(ifreq->data, &newfd, sizeof(newfd));
				if (ioctl(t->fd, NIOCCONFIG, ifreq)) {
					perror("ioctl");
					close(newfd);
close_pfds:
					i = 1;
					for (i < t->g->fdnum; i++) {
						close(pfd[i].fd);
					}
					/* be conservative to this error... */
					goto quit;
				}
				if (unlikely(newfd >= t->fdtable_siz)) {
					if (fdtable_expand(t)) {
						goto close_pfds;
					}
				}
			}

			/* check the netmap fd */
			if (!(pfd[0].revents & POLLIN)) {
				continue;
			}



		}
	}

}
#endif /* _NMLIB_H_ */
