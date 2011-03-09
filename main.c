#include "settings.h"

#include "main.h"
#include "getopts.h"
#include "ext/xmalloc.h"
#include "ext/fread.h"
#include "ext/cidr.h"
#include "ext/chtbl.h"
#include "ext/hash.h"
#include "ext/standard_dns.h"
#include "readconf.h"
#include "myadns.h"
#include "misc.h"

static void display_output(int /* family */, const char * /* hostname */, const char * /* addr string */);
static void display_routput(int /* family */, const char * /* address */, const char * /* hostname */);
static void display_alias(const char * /* cname */, const char * /* real hname */);
static void display_output_cb(int /* type */, const void *, const void *);

/*
 * for forward lookups, use this function to find a default host thats returned
 */
static void get_wildcard(void);
static char *get_sillyhostname(void);

static void do_brute(void);
static void do_dict(void);
static void do_reverse(void);
static void do_lookup(const char *);
static void do_revlookup(const struct sockaddr *);
static void do_gather(int /* wait for all = 1 otherwise 0 for free slot */);

/*
 * use during brute force
 */
static void init_charlist(void);
static int  inc_char(char *);

settings_t *s=NULL;
static void *sc=NULL;

int main(int argc, char **argv) {
	unsigned int j=0;
	int sd_flags=0;

	s=(struct settings_t *)xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(*s));

	set_addrfam("ipv46");
	set_mode("dict");
	set_allowed(DEF_BRUTECHARS);
#if HAVE_C_ARES == 1
	s->async=1;
#endif
	s->concurrency=DEF_CONCURRENCY;
	s->dictfile=xstrdup(SHAREDIR "/default");
	s->filter_unique=1;
	s->exact=0;

	readconf(DEF_CONFFILE);

	get_opts_argv(argc, argv);

	if (s->filter_unique) {
		s->uniq=chtinit(0xffff);
	}

	if (s->sillyhostname == NULL) {
		s->sillyhostname=xstrdup(get_sillyhostname());
	}

	if (s->mode == MODE_BRUTE) {
		DBG("brute length from %d to %d with allowed `%s'", s->brute_lenmin, s->brute_lenmax, s->allowed);
	}

	sd_flags=0;
	if (s->ipv6_lookup) {
		DBG("looking up ipv6 records");
		sd_flags |= STDDNS_FLG_IPV6;
	}
	if (s->ipv4_lookup) {
		DBG("Looking up ipv4 records");
		sd_flags |= STDDNS_FLG_IPV4;
	}
	if (s->exact) {
		DBG("exact mode enabled");
		sd_flags |= STDDNS_FLG_EXACT;
	}

	/*
	 * you never know ;]
	 */
	if (s->ipv4_lookup == s->ipv6_lookup && s->ipv4_lookup == 0) {
		ERR("well that was fast wasnt it? (no address families to look up)");
		exit(1);
	}

#if HAVE_C_ARES == 1
	if (s->async) {
		myadns_init(display_output_cb, s->concurrency);
	}
#endif

	sc=stddns_init(display_output_cb, sd_flags);

	s->start=time(NULL);

	for (j=0; s->targets[j] != NULL; j++) {

		s->cur_target=s->targets[j];

		if (s->mode == MODE_REVERSE) {
			int af=0;

			af=cidr_get(s->cur_target, (struct sockaddr *)&s->netid, (struct sockaddr *)&s->netmask, &s->cmask);
			if (af < 0) {
				ERR("sorry, i dont understand `%s' for reverse dns sweep", s->cur_target);
				continue;
			}
			else if (af == AF_INET) {
				s->ipv4_lookup=1; s->ipv6_lookup=0;
			}
			else if (af == AF_INET6) {
				s->ipv4_lookup=0; s->ipv6_lookup=1;
			}
			else {
				ERR("cidr is broken, this is a bug, skipping this sweep");
				continue;
			}
		}

		switch (s->mode) {
			case MODE_BRUTE:
				if (s->verbose) {
					OUT("brute force mode length %d to %d with characters `%s'", s->brute_lenmin, s->brute_lenmax, s->allowed);
				}
				do_lookup(s->cur_target);
				get_wildcard();
				do_brute();
				break;

			case MODE_REVERSE:
				if (s->verbose) {
					char *net=NULL;

					net=cidr_saddrstr((const struct sockaddr *)&s->netid);
					if (net == NULL) {
						ERR("cant convert network sockaddr to string");
						exit(1);
					}
					OUT("Reverse dns sweep mode on net %s/%u", net, s->cmask);
				}
				if (s->discover) {
					get_wildcard();
				}
				do_reverse();
				break;

			case MODE_DICT:
				if (s->verbose) {
					OUT("Dictionary mode using file `%s'", s->dictfile);
				}
				do_lookup(s->cur_target);
				get_wildcard();
				do_dict();
				break;

			default:
				ERR("unknown mode %d", s->mode);
				break;
		} /* mode switch */

#if HAVE_C_ARES == 1
		if (s->async) {
			do_gather(1);
		}

		xfree(s->targets[j]);
		s->targets[j]=NULL;
#endif
	} /* targets in list */

#if HAVE_C_ARES == 1
	if (s->async) {
		myadns_fini();
	}
#endif

	stddns_fini(&sc);

	if (s->uniq != NULL) {
		chtdestroy(s->uniq);
	}

	if (s->verbose) {
		int secs=0;
		float qps=0;

		secs=time(NULL) - s->start;

		qps=(float )s->lookups / (float )(secs != 0 ? secs : 1);

		OUT("%u lookups total in %d seconds (%.02f QPS) with %u replies", s->lookups, secs, qps, s->replies);

	}

	if (s->allowed != NULL) {
		xfree(s->allowed);
	}

	if (s->sillyhostname != NULL) {
		xfree(s->sillyhostname);
	}

	if (s->dictfile != NULL) {
		xfree(s->dictfile);
	}

	if (s->wc_list) {
		stddns_freeaddr(s->wc_sc, &s->wc_list);
	}

	xfree(s);

	exit(0);
}

static void do_brute(void) {
	char fqhn[NBUF_LEN];
	char str[MAX_BRUTELEN + 1];
	int j=0;

	init_charlist();

	assert(s->brute_lenmax < MAX_BRUTELEN && s->brute_lenmax > 0);
	assert(s->brute_lenmin < MAX_BRUTELEN && s->brute_lenmin > 0);

	memset(str, 0, sizeof(str));

	str[0]=s->allowed[0];
	if (s->brute_lenmin > 1) {
		memset(str, s->allowed[strlen(s->allowed) - 1], s->brute_lenmin - 1);
	}

	for (;;) {
		snprintf(fqhn, sizeof(fqhn) -1, "%s.%s.", str, s->cur_target);

		do_lookup(fqhn);

		for (j=0 ; j < s->brute_lenmax ; j++) {
			if (inc_char(&str[j]) == 0) {
				break;
			}
			DBG("ok, inc'ing to next char in string");
		}
		if (j == s->brute_lenmax) {
			break;
		}
	}

	return;
}

static void do_reverse(void) {
	struct sockaddr_storage mysin;

	memcpy(&mysin, &s->netid, sizeof(mysin));

#ifdef HAVE_STRUCT_SOCKADDR_LEN
	mysin.ss_len=s->netid.ss_len;
#endif

	for (;;) {
		do_revlookup((const struct sockaddr *)&mysin);
		if (cidr_inchost((struct sockaddr *)&mysin, (struct sockaddr *)&s->netid, (struct sockaddr *)&s->netmask) != 1) {
			break;
		}
		if (cidr_within((struct sockaddr *)&mysin, (struct sockaddr *)&s->netid, (struct sockaddr *)&s->netmask) != 1) {
			break;
		}
	}

	return;
}

static void do_revlookup(const struct sockaddr *si) {
	char *addr_str=NULL;
#if HAVE_C_ARES == 1
	int ret=0;
#endif

	s->lookups++;

	addr_str=cidr_saddrstr(si);

	DBG("Looking up `%s'", addr_str != NULL ? addr_str : "Error");

#if HAVE_C_ARES == 1
	if (s->async) {
		for (;;) {
			ret=myadns_revlookup(si);
			if (ret == 1 || ret < 0) {
				if (ret < 0) {
					ERR("adns forward lookup fails with code %d", ret);
				}
				break;
			}
			do_gather(0);
		}

		return;
	}
#endif

	(void )stddns_getname_cb(sc, si);

	return;
}

static void do_gather(int wait) {
#if HAVE_C_ARES == 1
	int ret=0;

	DBG("in do gather");
	for (;;) {
		if (s->verbose > 4) {
			myadns_track_dump();
		}

		ret=myadns_gather();
		if (wait == 0 && ret == 1) {
			break;
		}
		if (ret == 2 || ret < 0) {
			if (ret < 0) {
				ERR("adns_gather fails! error %d", ret);
			}
			break;
		}
	}
	DBG("out do gather");

	return;
#else
	ERR("gather called with no adns support");
#endif
}

static void do_dict(void) {
	void *d=NULL;
	char fqhn[NBUF_LEN];
	char *hostname=NULL;

	/*
	 * ok bob, throw the dictionary at 'em
	 */

	d=fread_create(s->dictfile, FREAD_NONL);

	if (d == NULL) {
		char nfname[PATH_MAX];

		snprintf(nfname, sizeof(nfname) - 1, "%s/%s", SHAREDIR, s->dictfile);

		d=fread_create(nfname, FREAD_NONL);
		if (d == NULL) {
			ERR("cant open `%s'", nfname);
			exit(1);
		}
	}

	for (; fread_getline(d, &hostname) > 0; ) {
		if (hostname == NULL || strlen(hostname) < 1) {
			continue;
		}

		if (hostname[0] == '#') {
			continue;
		}

		snprintf(fqhn, sizeof(fqhn) -1, "%s.%s.", hostname, s->cur_target);

		do_lookup(fqhn);
	}

	fread_destroy(d);

	return;
}

void get_wildcard(void) {
	char hostname[NBUF_LEN];

	memset(hostname, 0, sizeof(hostname));

	snprintf(hostname, sizeof(hostname) -1, "%s.%s.", s->sillyhostname, s->cur_target);

	s->wc_sc=stddns_init(NULL, 0);

	s->wc_list=stddns_getaddr(sc, hostname);

	if (s->wc_list == NULL) {
		if (s->verbose) {
			OUT("No Wildcard found inside domain `%s'", s->cur_target);
		}
		return;
	}

	if (s->verbose) {
		OUT("Wildcard Host Found [used `%s']", s->sillyhostname);
	}

	return;
}

int check_wildcard(const struct sockaddr *si) {
	unsigned int idx=0;
	union {
		const struct sockaddr *s;
		struct f_s *fs;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
	} s_u;

	assert(si != NULL);

	if (s->wc_list == NULL) {
		return 0;
	}

	s_u.s=si;

	for (idx=0; s->wc_list[idx] != NULL; idx++) {

		switch (s->wc_list[idx]->s_u.fs.family) {
			case AF_INET:
				if (s_u.fs->family != AF_INET) {
					break;
				}
				DBG("%08x Vs %08x", s_u.sin->sin_addr.s_addr, s->wc_list[idx]->s_u.sin.sin_addr.s_addr);

				if (s_u.sin->sin_addr.s_addr == s->wc_list[idx]->s_u.sin.sin_addr.s_addr) {
					return 1;
				}

				break;

			case AF_INET6:
				if (s_u.fs->family != AF_INET6) {
					break;
				}
				if (memcmp(&s->wc_list[idx]->s_u.sin6.sin6_addr.s6_addr[0], &s_u.sin6->sin6_addr.s6_addr[0], sizeof(s->wc_list[idx]->s_u.sin6.sin6_addr.s6_addr[0]) * sizeof(s->wc_list[idx]->s_u.sin6.sin6_addr.s6_addr)) == 0) {
					return 1;
				}
				break;

			default:
				break;
		}
	}

	return 0;
}

void do_lookup(const char *hn) {
#if HAVE_C_ARES == 1
	int ret=0;
#endif

	assert(hn != NULL && strlen(hn) > 0);
	DBG("looking up `%s'", hn);

	s->lookups++;

#if HAVE_C_ARES == 1

	if (s->async) {
		for (;;) {
			ret=myadns_fwdlookup(hn);
			if (ret == 1 || ret < 0) {
				if (ret < 0) {
					ERR("adns forward lookup fails with code %d", ret);
				}
				break;
			}
			do_gather(0);
		}

		return;
	}

#endif /* ! ASYNC DNS */

	(void )stddns_getaddr_cb(sc, hn);

	if (s->discover) {
		ERR("discover mode not yet implemented for sync dns lookups");
		s->discover=0;
	}

}

static void display_output_cb(int type, const void *a, const void *b) {
	union {
		const void *p;
		struct f_s *fs;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
		const struct sockaddr *s;
	} s_u;
	char *ret=NULL;

	assert(a != NULL && b != NULL);

	s->replies++;

	if (type == OUTPUT_FORWARD) {
		s_u.p=b;

		if (check_wildcard(s_u.s) == 1) {
			DBG("ignoring `%s' (due to wildcard address match)", (const char *)a);
			return;
		}

		ret=cidr_saddrstr(s_u.p);
		if (ret == NULL) {
			ERR("cant convert sockaddr into address string!");
			return;
		}

		display_output(s_u.fs->family, (const char *)a, (const char *)ret);
	}
	else if (type == OUTPUT_ALIAS) {
		display_alias((const char *)a, (const char *)b);
	}
	else if (type == OUTPUT_REVERSE) {
		char *o=NULL;

		s_u.p=a;
		o=cidr_saddrstr(s_u.s);

		if (o == NULL) {
			PANIC("conversion fails");
		}

		display_routput(s_u.fs->family, (const char *)o, (const char *)b);
	}
	else {
		ERR("unknown output type `%d'", type);
	}

	return;
}

#define escape(str) (str)

int check_output_unique(const char *a, const char *b) {
	uint64_t okey=0;

	assert(a != NULL && b != NULL);

	if (s->filter_unique == 0) {
		return 1;
	}

	okey=sdbmhash(a, strlen(a));
	okey=okey << 32;
	okey |= sdbmhash(b, strlen(b));

	if (chtinsert(s->uniq, okey, NULL) != 1) {
		return 0;
	}

	return 1;
}

void display_output(int family, const char *hostname, const char *addr_str) {


	if (check_output_unique(hostname, addr_str) != 1) {
		return;
	}

	if (s->output_sql) {
		OUTSQL("insert into hostname (host, addrfam, type, data) values('%s', %d, %u, '%s');",
				addr_str, family, 0, escape(hostname));
	}
	else {
		char fam[64];

		switch (family) {
			case AF_INET:
				fam[0]='A'; fam[1]='\0';
				break;

			case AF_INET6:
				memset(fam, 0x41, 4);
				fam[4]='\0';
				break;

			default:
				ERR("Unknown address family %d", family);
				fam[0]='?';
				fam[1]='\0';
				break;
		}

		OUT("%s\t%s %s", hostname, fam, addr_str);
	}

	return;
}

void display_alias(const char *cname, const char *hostname) {

	if (cname == NULL || hostname == NULL || strlen(cname) < 1 || strlen(hostname) < 1) {
		return;
	}
	if (strcasecmp(cname, hostname) == 0) {
		return;
	}

	if (check_output_unique(cname, hostname) != 1) {
		return;
	}

	if (s->output_sql) {
		OUTSQL("insert into hostname_alias (hostname, alias) values('%s', '%s');",
			escape(hostname), escape(cname)
		);
	}
	else {
		OUT("%s\tCNAME %s", cname, hostname);
	}
}

void display_routput(int family, const char *addr_str, const char *hostname) {

	if (check_output_unique(addr_str, hostname) != 1) {
		return;
	}

	if (s->output_sql) {
		OUTSQL("insert into hostname (host, addrfam, type, data) values('%s', %d, %u, '%s');",
				addr_str, family, 1, escape(hostname));
	}
	else {
		OUT("%s\tPTR %s", addr_str, hostname);
	}
	return;
}

static struct cl_s {
	char c;
	int p;
} *cl;

static void init_charlist(void) {
	int j=0;

	cl=(struct cl_s *)xmalloc(sizeof(struct cl_s) * (strlen(s->allowed) + 1));

	for (j=0; s->allowed[j] != '\0' ; j++) {
		cl[j].c=s->allowed[j];
		cl[j].p=j;
	}
	cl[j].c=0;
	cl[j].p=j;
}

/*
 * returns 1 for carry, incs its char arg
 */ 
static int inc_char(char *in) {
	int j=0;

	assert(in != NULL);

	if (*in == '\0') {
		*in=cl[0].c;
		return 0;
	}

	for (j=0 ; s->allowed[j] != '\0' ; j++) {
		if (cl[j].c == *in) {
			if (cl[j + 1].c == '\0') {
				*in=cl[0].c;

				return 1;
			}
			else {
				*in=cl[j + 1].c;

				return 0;
			}
		}
	}

	PANIC("cow %s", in);
}

static char *get_sillyhostname(void) {
	static char rhost[MAX_SHN_LEN + 1]; 
	unsigned int len=0, j=0;

	srand((unsigned int )getpid());

	do {
		len=(rand() % MAX_SHN_LEN);
	} while (len < MIN_SHN_LEN);

	rhost[len]='\0';

	for (j=0; j < len; j++) {
		rhost[j]=s->allowed[rand() % strlen(s->allowed)];
	}

	return rhost;
}
