#include "settings.h"

#include <adns.h>

#define SLOT_CNT	8U

struct {
	adns_state s;
	struct adns_slots {
		adns_query q;
		adns_answer *a;
	} slots[SLOT_CNT];
	struct adns_slots *free_slots[SLOT_CNT];
	unsigned int free;
	unsigned int resolved;
	unsigned int asked;
} dnsq;

void myadns_init(void) {
	int flags=0, ret=0;
	unsigned int j=0;

	if (s->verbose > 4) {
		flags |= adns_if_debug|adns_if_checkc_entex;
	}

	memset(&dnsq, 0, sizeof(dnsq));

	ret=adns_init(&dnsq.s, flags, 0);
	if (ret) {
		fprintf(stderr, "adns_init fails: %s", strerror(ret));
		return;
	}

	for (j=0; j < SLOT_CNT; j++) {
		dnsq.free_slots[j]=&dnsq.slots[j];
	}

	return;
}

void myadns_fini(void) {

	adns_finish(dnsq.s);

	return;
}

int myadns_fwdlookup(const char *host) {
	unsigned int idx=0;

	if (dnsq.free < 1) {
		DBG("returning 0 cause no free slots");
		return 0;
	}

	assert(dnsq.free <= SLOT_CNT);
	idx=SLOT_CNT - dnsq.free;
	dnsq.free_slots[idx]->

	return -1;
}

int myadns_revlookup(struct sockaddr *sock) {
	return -1;
}

int myadns_gather(void (*fp)(const char *, const char *)) {
	return -1;
}
