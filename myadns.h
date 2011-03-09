#ifndef _MYADNS_H
# define _MYADNS_H

#define TRACK_REQUESTS	1
#define TRACK_FWD	1
#define TRACK_REV	2

int myadns_init(void (* /* callback */)(int /* type */, const void *, const void *), unsigned int /* concurrency */);
void myadns_fini(void);
int myadns_fwdlookup(const char *);
int myadns_alllookup(const char *);
int myadns_revlookup(const struct sockaddr *);
int myadns_gather(void);
void myadns_track_dump(void);
int myadns_track_pending(int /* type */, const void * /* data */);

#endif
