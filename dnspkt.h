#ifndef _DNSPKT_H
# define _DNSPKT_H

typedef struct dnshdr_t {
	uint32_t notused;	/* 0  - 3  */
	uint16_t questions;	/* 4  - 5  */
	uint16_t answers;	/* 6  - 7  */
	uint16_t nss;		/* 8  - 9  */
	uint16_t others;	/* 10 - 11 */
} dnshdr_t;

/*
 * follows name
 */
typedef struct dnsq_t {
	uint16_t type;
	uint16_t qclass;
} dnsq_t;

/*
 * follows name
 */
typedef struct dnsrr_t {
	uint16_t type;
	uint16_t qclass;
	uint32_t ttl;
	uint16_t len;
} dnsrr_t;

#endif
