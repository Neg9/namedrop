#include "settings.h"

#include "ext/hash.h"

inline uint32_t sdbmhash(const void *in, size_t len) {
	uint32_t hash=0;
	const uint8_t *str=NULL, *end=NULL;

	str=(const uint8_t *)in;
	end=str + len;

	for (; str < end; ++str) {
		hash=*str + (hash << 6) + (hash << 16) - hash;
	}

	return hash;
}

#if 0
#define SEED8   0x95U
#define SEED_ST 0x55555565U

uint32_t bkdrjhash(const void *in, size_t len) {
	uint32_t hash=SEED_ST;
	union {
		const uint32_t *w;
		const uint8_t *c;
		const void *p;
	} p_u;

	p_u.p=in;
	/*
	 * try and cheat for the 32 bit speed advantage
	 * unfortunately it isnt compatible with the original
	 * hash function
	 */
	for (; len > sizeof(*p_u.w); ) {
		hash *= SEED8;
		hash += (*p_u.w & 0xff000000) >> 24;

		hash *= SEED8;
		hash += (*p_u.w & 0x00ff0000) >> 16;

		hash *= SEED8;
		hash += (*p_u.w & 0x0000ff00) >> 8;

		hash *= SEED8;
		hash += (*p_u.w & 0x000000ff);

		p_u.w++;
		len -= sizeof(*p_u.w);
	}

	for (; len != 0; --len, ++p_u.c) {
		hash = (hash * SEED8) + *p_u.c;
	}

	return hash;
}

#endif

#ifdef _WRAP_
#include <stdlib.h>

inline uint64_t get_tsc(void) {
	uint64_t j;
	asm volatile (  "rdtsc;"
			: "=A" (j)
	);
	return j;
}


int main(int argc, char ** argv) {
	uint64_t a,b,c,d;
	uint32_t y,z;
	size_t slen=0;

	if (argc != 2) {
		printf("bad usage\n");
		exit(1);
	}

	slen=strlen(argv[1]);
	/* we really need to use this string first, to get it in cache */
	printf("hashing `%s'\n", argv[1]);

	a=get_tsc();
	y=bkdrhash(argv[1], slen);
	b=get_tsc();

	d=get_tsc();
	z=bkdrjhash(argv[1], slen);
	c=get_tsc();

	printf("hashes %08x and %08x (old %llu new %llu)\n", y, z, (b - a), (c - d));

	exit(0);
}

#endif
