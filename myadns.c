#include "settings.h"

#include <ares.h>

#include "ext/xmalloc.h"
#include "ext/cidr.h"
#include "misc.h"
#include "myadns.h"
#include "dnspkt.h"

#if defined TRACK_REQUESTS == 1

static void myadns_track_request(int /* type */, int /* proto family */, const void * /* data */, void * /* cb data */);
static void myadns_track_rmrequest(unsigned int /* slot */, unsigned int /* seq */);

#endif /* TRACK_REQUESTS */

#define DO_IPV4_LOOKUPS	(s->ipv4_lookup == 1)
#define DO_IPV6_LOOKUPS	(s->ipv6_lookup == 1)
#define DO_EXACT	(s->exact == 1)

static struct dnsq_s {
	ares_channel c;
	void (*display)(int /* type */,  const void *, const void *);
	int empty;
	unsigned int slots_werefull;
	unsigned int dnsseq;
	unsigned int *slots;
#if defined TRACK_REQUESTS == 1
	struct track_s {
		unsigned int seq;
		int type;
		union {
			struct {
				int addrfam;
				uint8_t *addr;
			} a_s;
			char *hn;
		} t_u;
	} *track;
#endif
	unsigned int concurrency;
} dnsq;

static void myadns_fwd_cb(void *, int, int, struct hostent *);
static void myadns_rev_cb(void *, int, int, struct hostent *);
static void myadns_any_cb(void *, int, int, uint8_t *, int  );

int myadns_init(void (*cb)(int , const void *, const void *), unsigned int concurrency) {
	int ret=0;

	if (cb == NULL) {
		return -1;
	}

	dnsq.display=cb;

	dnsq.slots=(unsigned int *)xmalloc(sizeof(unsigned int *) * concurrency);
	memset(dnsq.slots, 0, sizeof(unsigned int *) * concurrency);

	dnsq.dnsseq=1; /* not 0 ;], seeing as how thats special */
	dnsq.empty=1;

	dnsq.concurrency=concurrency;

#if defined TRACK_REQUESTS == 1
	dnsq.track=xmalloc(sizeof(struct track_s) * concurrency);
	memset(dnsq.track, 0, sizeof(struct track_s) * concurrency);
#endif

	ret=ares_init(&dnsq.c);
	if (ret != ARES_SUCCESS) {
		ERR("ares_init fails: %s", ares_strerror(ret));
		return -1;
	}

	return 1;
}

void myadns_fini(void) {

	ares_destroy(dnsq.c);

	xfree(dnsq.slots);

#if defined TRACK_REQUESTS == 1
	xfree(dnsq.track);
#endif


	return;
}

int myadns_fwdlookup(const char *hostname) {
	unsigned int j=0, fidx[2]={0, 0}, *cbp=NULL, slots_req=0, slots_found=0;

	if (DO_IPV4_LOOKUPS) {
		slots_req++;
	}
	if (DO_IPV6_LOOKUPS) {
		slots_req++;
	}

	/* whats the point if we arent going to do anything? should have been caught already */
	assert(slots_req != 0);

	for (j=0; j < dnsq.concurrency && slots_found != slots_req; j++) {
		if (dnsq.slots[j] == 0) {
			fidx[slots_found++]=j;
		}
	}

	if (slots_found != slots_req) {
		dnsq.slots_werefull++;
		return 0;
	}

	if (DO_IPV4_LOOKUPS) {

		cbp=(unsigned int *)xmalloc(sizeof(unsigned int) * 2);

		cbp[0]=dnsq.dnsseq++;
		cbp[1]=fidx[0];

		dnsq.slots[cbp[1]]=cbp[0];

		DBG("ipv4 lookup `%s' into slot %u seq %u", hostname, cbp[1], cbp[0]);

#if defined TRACK_REQUESTS == 1
		myadns_track_request(TRACK_FWD, AF_INET, hostname, cbp);
#endif

		ares_gethostbyname(dnsq.c, hostname, AF_INET, myadns_fwd_cb, cbp);
	}

	if (DO_IPV6_LOOKUPS) {

		cbp=(unsigned int *)xmalloc(sizeof(unsigned int) * 2);

		cbp[0]=dnsq.dnsseq++;
		cbp[1]=fidx[DO_IPV4_LOOKUPS ? 1 : 0];

		dnsq.slots[cbp[1]]=cbp[0];

		DBG("ipv6 lookup `%s' into slot %u seq %u", hostname, cbp[1], cbp[0]);

#if defined TRACK_REQUESTS == 1
		myadns_track_request(TRACK_FWD, AF_INET6, hostname, cbp);
#endif

		ares_gethostbyname(dnsq.c, hostname, AF_INET6, myadns_fwd_cb, cbp);
	}

	dnsq.empty=0;

	return 1;
}

int myadns_alllookup(const char *hostname) {
	int qtype=0xff; /* should be ns_t_any */
	int qclass=0xff; /* should be ns_c_any */
	unsigned int j=0, good=0;
	unsigned int *cbp=NULL;

	for (j=0; j < dnsq.concurrency; j++) {
		if (dnsq.slots[j] == 0) {
			good=1;
			break;
		}
	}

	if (good == 0) {
		dnsq.slots_werefull++;
		return 0;
	}

	cbp=(unsigned int *)xmalloc(sizeof(unsigned int) * 2);
	cbp[0]=dnsq.dnsseq++;
	cbp[1]=j;

	dnsq.slots[cbp[1]]=cbp[0];
	dnsq.empty=0;

	DBG("all lookup on %s slot %u seq %u", hostname, cbp[1], cbp[0]);

	ares_query(dnsq.c, hostname, qclass, qtype, myadns_any_cb, cbp);

	return 1;
}

int myadns_revlookup(const struct sockaddr *sock) {
	union {
		const struct f_s *fs;
		const struct sockaddr *s;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
	} s_u;
	const void *p=NULL; /* points to the beginning of the address structure in sockaddr */
	socklen_t sl=0;
	unsigned int j=0, good=0;
	unsigned int *cbp=NULL;

	s_u.s=sock;

	for (j=0; j < dnsq.concurrency; j++) {
		if (dnsq.slots[j] == 0) {
			good=1;
			break;
		}
	}

	if (good == 0) {
		dnsq.slots_werefull++;
		return 0;
	}

	switch (s_u.fs->family) {
		case AF_INET:
			sl=(socklen_t )sizeof(struct in_addr);
			p=&s_u.sin->sin_addr;
			break;

		case AF_INET6:
			sl=(socklen_t )sizeof(struct in6_addr);
			p=&s_u.sin6->sin6_addr;
			break;

		default:
			ERR("unknown address family %d", s_u.fs->family);
			return -1;
	}

	cbp=(unsigned int *)xmalloc(sizeof(unsigned int) * 2);
	cbp[0]=dnsq.dnsseq++;
	cbp[1]=j;

	dnsq.slots[cbp[1]]=cbp[0];
	dnsq.empty=0;

	DBG("reverse lookup at address XXX slot %u seq %u", cbp[1], cbp[0]);

#if defined TRACK_REQUESTS == 1
	myadns_track_request(TRACK_REV, s_u.fs->family, p, cbp);
#endif

	ares_gethostbyaddr(dnsq.c, p, sl, s_u.fs->family, myadns_rev_cb, cbp);

	return 1;
}

int myadns_gather(void) {
	int n_fds=0, cnt=0;
	fd_set fd_read, fd_write;
	struct timeval mtv, tv, *tv_p=NULL;
	unsigned int j=0;

	if (dnsq.empty == 1) {
		DBG("empty!");
		return 2;
	}

	for (;;) {
		FD_ZERO(&fd_read);
		FD_ZERO(&fd_write);

		n_fds=ares_fds(dnsq.c, &fd_read, &fd_write);

		DBG("got %d dns fd's back", n_fds);
		myadns_track_dump();

		if (n_fds == 0) {
			break;
		}

		memset(&mtv, 0, sizeof(mtv));
		mtv.tv_sec=MYADNS_TIMEOUT;

		tv_p=ares_timeout(dnsq.c, &mtv, &tv);

		cnt=select(n_fds, &fd_read, &fd_write, NULL, tv_p);

		ares_process(dnsq.c, &fd_read, &fd_write);

		break;
	}

	for (j=0; j < dnsq.concurrency; j++) {
		if (dnsq.slots[j] != 0) {
			return 1;
		}
	}

	dnsq.empty=1;

	return 2;
}

#if defined TRACK_REQUESTS == 1

void myadns_track_dump(void) {
	unsigned int j=0;
	struct track_s *ts=NULL;
	char *astr=NULL;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr s;
	} s_u;

	for (j=0; j < dnsq.concurrency; j++) {
		ts=&dnsq.track[j];
		if (ts->seq == 0) {
			continue;
		}
		DBG("question %u is outstanding", ts->seq);

		switch (ts->type) {
			case TRACK_FWD:
				DBG("question %u for host `%s' is outstanding", ts->seq, ts->t_u.hn);
				break;

			case TRACK_REV:
				if (ts->t_u.a_s.addrfam == AF_INET6) {
					s_u.sin6.sin6_family=AF_INET6;
					memcpy(&s_u.sin6.sin6_addr.s6_addr[0], ts->t_u.a_s.addr, sizeof(s_u.sin6.sin6_addr.s6_addr[0]) * sizeof(s_u.sin6.sin6_addr.s6_addr));
				}
				else {
					s_u.sin.sin_family=AF_INET;
					memcpy(&s_u.sin.sin_addr.s_addr, ts->t_u.a_s.addr, sizeof(s_u.sin.sin_addr.s_addr));
				}
				astr=cidr_saddrstr(&s_u.s);
				DBG("question %u for address `%s' is outstanding", ts->seq, astr);
				break;

			default:
				PANIC("whoa, what sort of track request type is %d", ts->type);
				break; /* not reached */
		}
	}

	return;
}

int myadns_track_pending(int type, const void *data) {
	unsigned int j=0;
	struct track_s *ts=NULL;
	union {
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
		struct f_s *fs;
		const void *p;
	} s_u;

	s_u.p=data;

	for (j=0; j < dnsq.concurrency; j++) {
		ts=&dnsq.track[j];
		if (ts->seq == 0) {
			continue;
		}

		switch (ts->type) {
			case TRACK_FWD:
				if (strcmp(ts->t_u.hn, (const char *)data) == 0) {
					return 1;
				}
				break;

			case TRACK_REV:
				if (ts->t_u.a_s.addrfam == AF_INET6 && s_u.fs->family == AF_INET6) {
					if (memcmp(ts->t_u.a_s.addr, &s_u.sin6->sin6_addr, sizeof(struct in6_addr)) == 0) {
						return 1;
					}

				}
				else if (ts->t_u.a_s.addrfam == AF_INET && s_u.fs->family == AF_INET) {

					if (memcmp(ts->t_u.a_s.addr, &s_u.sin->sin_addr.s_addr, sizeof(s_u.sin->sin_addr.s_addr)) == 0) {
						return 1;
					}
				}
				else {
					PANIC("something is bad");
				}
				break;

			default:
				PANIC("whoa, what sort of track request type is %d", ts->type);
				break; /* not reached */
		}
	}

	return 0;
}

#else /* no tracking */

void myadns_track_dump(void) {
	ERR("no track support compiled in");
}

void myadns_track_pending(int type, const void *p) {
	ERR("no track support compiled in");
}

#endif
/*
 * private functions
 */

static void myadns_rev_cb(void *p, int status, int timeouts, struct hostent *he) {
	union {
		void *p;
		unsigned int *cbp;
	} cb_u;
	union {
		struct sockaddr s;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct f_s fs;
	} s_u;
	int good=0;

	assert(p != NULL);

	cb_u.p=p;

	DBG("resp for seq %u at slot %u", cb_u.cbp[0], cb_u.cbp[1]);

	assert(cb_u.cbp[1] < dnsq.concurrency);

	if (dnsq.slots[cb_u.cbp[1]] != cb_u.cbp[0]) {
		PANIC("gah! dnsseq for slot %u doesnt match my seq %u (it has %u)", cb_u.cbp[1], cb_u.cbp[0], dnsq.slots[cb_u.cbp[1]]);
	}

	dnsq.slots[cb_u.cbp[1]]=0; /* free the slot */

#if defined TRACK_REQUESTS == 1
	myadns_track_rmrequest(cb_u.cbp[1], cb_u.cbp[0]);
#endif

	xfree(cb_u.p);

	switch (status) {
		case ARES_SUCCESS:
			good=1;
			break;
		case ARES_ENOTFOUND:
			break;

		case ARES_ENOTIMP:
			DBG("reverse lookup not implemented");
			break;
		case ARES_EBADNAME:
			DBG("reverse lookup bad hostname");
			break;
		case ARES_ENOMEM:
			DBG("reverse lookup no memory");
			break;
		case ARES_EDESTRUCTION:
			DBG("reverse lookup shutdown in progress, not completed");
			break;
		default:
			DBG("reverse lookup unknown status `%d'", status);
			break;
	}

	if (good == 0) {
		return;
	}

	if (he == NULL) {
		ERR("whoa!, got back NULL hostent");
		return;
	}

	s_u.fs.family=he->h_addrtype;

	switch (he->h_addrtype) {
		case AF_INET:
			memcpy(&s_u.sin.sin_addr.s_addr, he->h_addr_list[0], sizeof(s_u.sin.sin_addr.s_addr));
			break;

		case AF_INET6:
			memcpy(&s_u.sin6.sin6_addr.s6_addr, he->h_addr_list[0], sizeof(s_u.sin6.sin6_addr.s6_addr) * sizeof(s_u.sin6.sin6_addr.s6_addr[0]));
			break;

		default:
			PANIC("nyi");
			break;
	}

	dnsq.display(OUTPUT_REVERSE, &s_u.s, he->h_name);

	return;
}

static void myadns_any_cb(void *p, int status, int timeouts, uint8_t *pkt, int pkt_len) {
	union {	
		void *p;
		unsigned int *cbp;
	} cb_u;
	union {
		uint8_t *p;
		dnshdr_t *hdr;
		dnsq_t *q;
		dnsrr_t *r;
	} dh_u;
	int good=0;
	unsigned int q_cnt=0, a_cnt=0, ns_cnt=0, o_cnt=0, j=0, d_len=0;
	size_t d_left=0;
	char *ename=NULL;
	long ename_len=0;

	cb_u.p=p;
	dh_u.p=pkt;

	switch (status) {
		case ARES_SUCCESS:
			good=1;
			break;
		case ARES_ENOTFOUND:
			break;

		case ARES_ENOTIMP:
			DBG("reverse lookup not implemented");
			break;
		case ARES_EBADNAME:
			DBG("reverse lookup bad hostname");
			break;
		case ARES_ENOMEM:
			DBG("reverse lookup no memory");
			break;
		case ARES_EDESTRUCTION:
			DBG("reverse lookup shutdown in progress, not completed");
			break;
		default:
			DBG("reverse lookup unknown status `%d'", status);
			break;
	}

	if (good == 0) {
		return;
	}

	if (pkt_len < 1 || (size_t )pkt_len < sizeof(dnshdr_t)) {
		ERR("got back short resp at %p", pkt);
		return;
	}

	d_left=(size_t )pkt_len;

	q_cnt=ntohs(dh_u.hdr->questions);
	a_cnt=ntohs(dh_u.hdr->answers);
	ns_cnt=ntohs(dh_u.hdr->nss);
	o_cnt=ntohs(dh_u.hdr->others);

	dh_u.hdr++;
	d_left -= sizeof(dnshdr_t);

	DBG("questions %u answers %u nameservers %u other records %u data left %zu", q_cnt, a_cnt, ns_cnt, o_cnt, d_left);

	//hexdump(dh_u.p, d_left);

	for (j=0; j < q_cnt && d_left > 0; j++) {
		ename=NULL; ename_len=0;
		if (ares_expand_name(dh_u.p, pkt, pkt_len, &ename, &ename_len) != ARES_SUCCESS) {
			return;
		}
		if (ename_len < 0 || (size_t )ename_len >= d_left) {
			return;
		}
		d_left -= (size_t )ename_len;
		dh_u.p += (size_t )ename_len;

		if (d_left < sizeof(dnsq_t)) {
			return;
		}
		DBG("Question name %s [len %ld] type %hx class %hx", ename, ename_len, ntohs(dh_u.q->type), ntohs(dh_u.q->qclass));
		dh_u.q++;
		d_left -= sizeof(dnsq_t);
	}

	hexdump(dh_u.p, d_left);

	for (j=0; j < a_cnt && d_left > 0; j++) {
		DBG("answer number %u", j);

		ename=NULL; ename_len=0;

		if (ares_expand_name(dh_u.p, pkt, pkt_len, &ename, &ename_len) != ARES_SUCCESS) {
			return;
		}

		if (ename_len < 0 || (size_t )ename_len >= d_left) {
			return;
		}

		if (ename == NULL) {
			return;
		}
		d_left -= (size_t )ename_len;
		dh_u.p += (size_t )ename_len;

		DBG("Answer name %s [len %ld] ", ename, ename_len);
		DBG("Answer type %hx class %hx ttl %u len %hu", ntohs(dh_u.r->type), ntohs(dh_u.r->qclass), ntohl(dh_u.r->ttl), ntohs(dh_u.r->len));

		dh_u.r++;
		d_len=0;

		d_len=ntohs(dh_u.r->len);

		if (d_len >= d_left) {
			return;
		}

		if (d_len > 0) {
			hexdump(dh_u.p, d_len);
			dh_u.p += d_len;
			d_left -= d_len;
		}
	}

	pause();
}

static void myadns_fwd_cb(void *p, int status, int timeouts, struct hostent *he) {
	union {
		void *p;
		unsigned int *cbp;
	} cb_u;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr s;
	} s_u;
	int good=0;
	unsigned int j=0, j1=0;

	assert(p != NULL);

	cb_u.p=p;

	DBG("resp for seq %u at slot %u", cb_u.cbp[0], cb_u.cbp[1]);

	assert(cb_u.cbp[1] < dnsq.concurrency);

	if (dnsq.slots[cb_u.cbp[1]] != cb_u.cbp[0]) {
		PANIC("gah! dnsseq for slot %u doesnt match my seq %u (it has %u)", cb_u.cbp[1], cb_u.cbp[0], dnsq.slots[cb_u.cbp[1]]);
	}

	dnsq.slots[cb_u.cbp[1]]=0; /* free the slot */

#if defined TRACK_REQUESTS == 1
	myadns_track_rmrequest(cb_u.cbp[1], cb_u.cbp[0]);
#endif

	xfree(cb_u.p);

	switch (status) {
		case ARES_SUCCESS:
			good=1;
			break;
		case ARES_ENOTFOUND:
			break;

		case ARES_ENOTIMP:
			DBG("forward lookup not implemented");
			break;
		case ARES_EBADNAME:
			DBG("forward lookup bad hostname");
			break;
		case ARES_ENOMEM:
			DBG("forward lookup no memory");
			break;
		case ARES_EDESTRUCTION:
			DBG("forward lookup shutdown in progress, not completed");
			break;
		default:
			DBG("forward lookup unknown status `%d'", status);
			break;
	}

	if (good == 0) {
		return;
	}

	if (he == NULL) {
		ERR("whoa, got back NULL hostent!");
		return;
	}

	for (j=0; he->h_addr_list[j] != NULL; j++) {

		memset(&s_u.s, 0, sizeof(s_u.s));

		switch (he->h_addrtype) {
			case AF_INET:
				s_u.sin.sin_family=AF_INET;
				memcpy(&s_u.sin.sin_addr.s_addr, he->h_addr_list[j], sizeof(s_u.sin.sin_addr.s_addr));
				break;
			case AF_INET6:
				s_u.sin6.sin6_family=AF_INET6;
				memcpy(&s_u.sin6.sin6_addr.s6_addr[0], he->h_addr_list[j], sizeof(s_u.sin6.sin6_addr.s6_addr[0]) * sizeof(s_u.sin6.sin6_addr.s6_addr));
				break;
			default:
				break;
		}
		if (he->h_aliases != NULL && DO_EXACT) {
			for (j1=0; he->h_aliases[j1] != NULL && strlen(he->h_aliases[j1]) > 0; j1++) {
				dnsq.display(OUTPUT_ALIAS, he->h_aliases[j1], he->h_name);
			}
			dnsq.display(OUTPUT_FORWARD, he->h_name, &s_u.s);
		}
		else {
			dnsq.display(OUTPUT_FORWARD, he->h_name, &s_u.s);
		}
	}

	return;
}

#if defined TRACK_REQUESTS == 1

static void myadns_track_request(int type, int addrfam, const void *data, void *cbp) {
	union {
		void *p;
		unsigned int *cbp;
	} cbp_u;
	union {
		const void *p;
		const char *hn;
	} d_u;
	struct track_s *ts=NULL;
	unsigned int len=0;

	cbp_u.p=cbp;
	d_u.p=data;

	DBG("Track for request %u addrfam %d", cbp_u.cbp[0], addrfam);

	ts=&dnsq.track[cbp_u.cbp[1]];

	if (ts->seq != 0) {
		PANIC("whoa");
	}

	ts->seq=cbp_u.cbp[0];
	ts->type=type;

	switch (type) {
		case TRACK_FWD:
			ts->t_u.hn=xstrdup(d_u.hn);
			break;

		case TRACK_REV:
			ts->t_u.a_s.addrfam=addrfam;
			if (addrfam == AF_INET) {
				len=sizeof(struct in_addr);
			}
			else if (addrfam == AF_INET6) {
				len=sizeof(struct in6_addr);
			}
			else {
				PANIC("unknown address family to track");
			}
			ts->t_u.a_s.addr=xmalloc(len);
			memcpy(ts->t_u.a_s.addr, d_u.p, len);
			break;

		default:
			PANIC("unknown type to track %d", type);
			break; /* not reached */
	}

	return;
}

static void myadns_track_rmrequest(unsigned int slot, unsigned int seq) {
	struct track_s *ts=NULL;

	assert(slot < dnsq.concurrency);

	ts=&dnsq.track[slot];

	ts->seq=0;

	switch (ts->type) {
		case TRACK_FWD:
			xfree(ts->t_u.hn);
			break;

		case TRACK_REV:
			xfree(ts->t_u.a_s.addr);
			break;

		default:
			PANIC("unknown type to rm track %d", ts->type);
			break; /* not reached */
	}

	ts->type=0;

	return;
}

#endif

#ifdef _WRAP_

settings_t *s=NULL;

static void display_forward(const char *, const struct sockaddr *);

static void display_cb(int type, const void *a, const void *b) {
	switch (type) {
		case OUTPUT_FORWARD:
			display_forward((const char *)a, (const struct sockaddr *)b);
			break;
		default:
			break;
	}
}

static void display_forward(const char *name, const struct sockaddr *si) {
	union {
		const struct sockaddr *s;
		const struct f_s *fs;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
	} s_u;
	char nbuf[256];

	s_u.s=si;


	nbuf[0]='\0';
	switch (s_u.fs->family) {
		case AF_INET:
			inet_ntop(AF_INET, &s_u.sin->sin_addr, nbuf, sizeof(nbuf) -1);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, &s_u.sin6->sin6_addr, nbuf, sizeof(nbuf) -1);
			break;
	}

	OUT("%s has address %s", name, nbuf);

	return;
}

int main(int argc, char ** argv) {
	int j=0;

	s=xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(*s));
	s->ipv6_lookup=1;
	s->ipv4_lookup=1;

	if (myadns_init(display_cb, 4) < 0) {
		exit(1);
	}

	for (j=1; j < argc; j++) {
		DBG("looking up `%s'", argv[j]);
		myadns_fwdlookup(argv[j]);
	}

	myadns_gather();

	myadns_fini();

	xfree(s);

	exit(0);
}

#endif
