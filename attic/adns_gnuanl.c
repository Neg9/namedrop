#ifdef ASYNC

#define _GNU_SOURCE

#include "settings.h"

#include <pthread.h>

#include "adns.h"

static sig_atomic_t dns_present=0;

#define ADNS_SLOTS_COUNT	16U
#define ADNS_SIGNAL		(SIGRTMIN + 3)
#define ADNS_FINISHED		2

static void addr_avail(int sig, siginfo_t *si, void *ptr) {

	++dns_present;

	return;
}

int adns_gather(void (*)(const char *, const char *));

struct dnsq { 
	struct sigevent se;
	struct gaicb *slots[ADNS_SLOTS_COUNT];
	struct gaicb *free_slots[ADNS_SLOTS_COUNT];
	unsigned int slots_free;
	unsigned int slots_cnt;
	struct sigaction sa;
	struct sigaction sa_old;
	unsigned int requested;
	unsigned int resolved;
	pthread_mutex_t slot_lock;
} dnsq;

void adns_init(void) {
	unsigned int j=0;
	pthread_mutexattr_t ma;

	dnsq.slots_cnt=ADNS_SLOTS_COUNT;
	dnsq.slots_free=ADNS_SLOTS_COUNT;

	for (j=0; j < ADNS_SLOTS_COUNT; j++) {
		dnsq.slots[j]=(struct gaicb *)malloc(sizeof(struct gaicb));
		dnsq.free_slots[j]=dnsq.slots[j];
		memset(dnsq.slots[j], 0, sizeof(struct gaicb));
	}

	dnsq.sa.sa_sigaction=addr_avail;
	dnsq.sa.sa_flags=0;
	sigemptyset(&dnsq.sa.sa_mask);

	if (sigaction(ADNS_SIGNAL, &dnsq.sa, &dnsq.sa_old) < 0) {
		fprintf(stderr, "sigaction fails: %s", strerror(errno));
		return;
	}

	dnsq.se.sigev_notify=SIGEV_SIGNAL;
	dnsq.se.sigev_signo=ADNS_SIGNAL;

	dnsq.requested=0;
	dnsq.resolved=0;

	if (pthread_mutexattr_init(&ma) < 0) {
		fprintf(stderr, "cant initialize mutex attribute: %s\n", strerror(errno));
		return;
	}

	if (pthread_mutex_init(&dnsq.slot_lock, &ma) < 0) {
		fprintf(stderr, "cant init mutex lock: %s\n", strerror(errno));
		return;
	}

	return;
}

void adns_fini(void) {
	unsigned int j=0;

	for (j=0; j < dnsq.slots_cnt; j++) {
		if (dnsq.slots[j] != NULL) {
			free(dnsq.slots[j]);
			if (dnsq.slots[j]->ar_result != NULL) {
				freeaddrinfo(dnsq.slots[j]->ar_result);
				if (dnsq.slots[j]->ar_name != NULL) {
					//free(dnsq.slots[j]->ar_name);
					dnsq.slots[j]->ar_name=NULL;
				}
			}
		}
	}

	sigaction(ADNS_SIGNAL, &dnsq.sa_old, NULL);

	return;
}

void adns_dump(void) {
	unsigned int j=0;

	assert(pthread_mutex_lock(&dnsq.slot_lock) == 0);

	for (j=0; j < dnsq.slots_cnt; j++) {
		printf("Slot %u at %p: ", j, dnsq.slots[j]);
		if (dnsq.slots[j] != NULL && dnsq.slots[j]->ar_name != NULL) {
			printf("waiting still for `%s'\n", dnsq.slots[j]->ar_name);
		}
		else {
			printf("\n");
		}
	}

	assert(pthread_mutex_unlock(&dnsq.slot_lock) == 0);

}

int adns_lookup(const char *name) {
	unsigned int idx=0;

	assert(pthread_mutex_lock(&dnsq.slot_lock) == 0);

	if (dnsq.slots_free > 0) {

		assert(dnsq.slots_free <= dnsq.slots_cnt);

		idx=dnsq.slots_cnt - dnsq.slots_free;

		dnsq.free_slots[idx]->ar_name=strdup(name);
		assert(dnsq.free_slots[idx]->ar_name != NULL);

		dnsq.free_slots[idx]->ar_service=NULL;
		dnsq.free_slots[idx]->ar_request=NULL;
		//fprintf(stderr, "using slot at %p\n", dnsq.free_slots[idx]);

		if (getaddrinfo_a(GAI_NOWAIT, &dnsq.free_slots[idx], 1, &dnsq.se) < 0) {
			//free(dnsq.free_slots[idx]->ar_name);
			dnsq.free_slots[idx]->ar_name=NULL;

			assert(pthread_mutex_unlock(&dnsq.slot_lock) == 0);

			perror("getaddrinfo_a");
			DBG("returning -1 cause stuff is broken");
			return -1;
		}
		else {
			dnsq.requested++;
			--dnsq.slots_free;

			assert(pthread_mutex_unlock(&dnsq.slot_lock) == 0);

			//printf("Looking up `%s'\n", name);
			DBG("returning 1 cause filled slot");
			return 1;
		}
	}

	assert(pthread_mutex_unlock(&dnsq.slot_lock) == 0);

	DBG("returning 0 cause no slots");
	return 0;
}

int adns_gather(void (*fp)(const char *, const char *)) {
	unsigned int j=0, null=0;
	int ret=0;

	assert(pthread_mutex_lock(&dnsq.slot_lock) == 0);

	if (dnsq.resolved == dnsq.requested) {

		assert(pthread_mutex_unlock(&dnsq.slot_lock) == 0);

		return 2;
	}

	for (j=0; dns_present > 0 && j < dnsq.slots_cnt; j++) {

		if (dnsq.slots[j] != NULL && dnsq.slots[j]->ar_name != NULL) {
			struct addrinfo *walk=NULL;
			char *nret=0;
			int r=0, good=0;
			char addr_str[1024];
			union {
				void *p;
				struct sockaddr_in *in;
				struct sockaddr_in6 *in6;
				struct sockaddr *s;
			} s_u;

			r=gai_error(dnsq.slots[j]);

			//printf("Slot %u at %p for name `%s': ", j, dnsq.slots[j], dnsq.slots[j]->ar_name != NULL ? dnsq.slots[j]->ar_name : "None");

			switch (r) {
				case EAI_INPROGRESS:
					//printf("in progress!\n");
					break;
				case 0:
					good=1;
					break;
				case -2:
					good=-1;
					break;
				default:
					printf("Unknown status %d `%s'\n", r, gai_strerror(r));
					break;
			}

			if (good == 0) {
				continue;
			}

			assert(dnsq.slots_free < ADNS_SLOTS_COUNT);

			dnsq.free_slots[dnsq.slots_free]=dnsq.slots[j];
			if ((dnsq.slots_free + 1) < dnsq.slots_cnt) {
				dnsq.slots_free++;
			}
			ret++;

			for (walk=dnsq.slots[j]->ar_result; good == 1 && walk != NULL ; walk=walk->ai_next) {

				memset(addr_str, 0, sizeof(addr_str));

				if (walk->ai_socktype != 3) { /* XXX what does 3 mean? */
					continue;
				}

				s_u.p=walk->ai_addr;
				nret=NULL;
				nret=sockaddr_tostring(s_u.p);

				if (nret == NULL) {
					fprintf(stderr, "cant convert address family %d into string\n", walk->ai_family);
				}
				else {
					fp(dnsq.slots[j]->ar_name, nret);
				}
			}

			freeaddrinfo(dnsq.slots[j]->ar_result);
			dnsq.slots[j]->ar_result=NULL;

			if (dnsq.slots[j]->ar_name != NULL) {
				//free(dnsq.slots[j]->ar_name);
				dnsq.slots[j]->ar_name=NULL;
			}
			dns_present--;
			dnsq.resolved++;
		}
		else {
			//printf("Slot %u is %p with name %s\n", j, dnsq.slots[j], dnsq.slots[j] != NULL && dnsq.slots[j]->ar_name != NULL ? dnsq.slots[j]->ar_name : "Nothing");
			null++;
		}
	}

	if (null == dnsq.slots_cnt) {
		assert(pthread_mutex_unlock(&dnsq.slot_lock) == 0);
		return 2;
	}

	assert(pthread_mutex_unlock(&dnsq.slot_lock) == 0);

	return ret > 0 ? 1 : 0;
}

#ifdef _WRAP_

static void display(const char *name, const char *addr_str) {
	if (name != NULL && addr_str != NULL) {
		printf("%s has address %s\n", name, addr_str);
	}
}

int main(int argc, char **argv) {
	//struct sockaddr_in *sin=NULL;
	int j=0;

	adns_init();

	j=1;

	for (;;) {
		for (; j < argc; j++) {
			if (adns_lookup(argv[j]) < 1) {
				break;
			}
		}
		if (adns_gather(display) == ADNS_FINISHED) {
			break;
		}
	}

	adns_dump();

	//adns_fini();

	exit(0);
}

#endif

#endif
