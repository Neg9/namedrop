#ifndef _SETTINGS_H
# define _SETTINGS_H

#include "config.h"

#define DBG(msg, args...)\
	if (s->verbose > 4) {\
		fprintf(stderr, "%sDEBUG %s:%u: " msg "\n", s != NULL && s->output_sql ? SQL_COMMENT : "", __FILE__, __LINE__, ## args);\
	}

#define ERR(msg, args...)\
	fprintf(stderr, "%sERROR %s:%u: " msg "\n", s != NULL && s->output_sql ? SQL_COMMENT : "", __FILE__, __LINE__, ## args);

#define assert(f) \
	if (! ( f ) ) { \
		PANIC("Assertion `%s' fails", # f); \
	}

#define PANIC(fmt, args...) \
	do { \
		\
		fprintf(stderr, "PANIC at %s:%u " fmt "\n", __FILE__, __LINE__,  ## args); \
		if (s->verbose > 4) { \
			fprintf(stderr, "Attach to pid %d , called from %s() %s:%d\n", getpid(), __FUNCTION__, __FILE__, __LINE__); \
			pause(); \
		} \
		abort(); \
	} while (0)

#define OUT(fmt, args...) \
	do { \
		if (s->output_sql) { \
			fprintf(stdout, "--" fmt "\n", ## args); \
		} \
		else { \
			fprintf(stdout, fmt "\n",  ## args); \
		} \
	} while (0)

#define OUTSQL(fmt, args...) \
	do { \
		fprintf(stdout, fmt "\n", ## args); \
	} while(0)

#define OUT_FLUSH	fflush(stdout)

#define OUTPUT_FORWARD	1
#define OUTPUT_REVERSE	2
#define OUTPUT_ALIAS	3

typedef struct settings_t {
	char *dictfile;

	char *targets[MAX_TARGETS];
	char *cur_target;

	int verbose;

	char *allowed; /* for brute force mode */
	char *sillyhostname;

	int mode;
#define MODE_BRUTE	1
#define MODE_REVERSE	2
#define MODE_DICT	3

	int output_sql;
	int ipv6_lookup;
	int ipv4_lookup;
	int discover;
	int exact;
	int filter_unique;

	void *uniq;

	unsigned int concurrency;
	int async;

	struct sockaddr_list_t **wc_list;
	void *wc_sc;

	int brute_lenmin;
	int brute_lenmax;

	struct sockaddr_storage netid;
	struct sockaddr_storage netmask;
	unsigned int cmask;

	time_t start;
	unsigned int replies;
	unsigned int lookups;
} settings_t;

extern settings_t *s;

#endif
