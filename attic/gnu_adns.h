#ifndef _MYADNS_H
# define _MYADNS_H

void myadns_init(void);
void myadns_fini(void);
int myadns_fwdlookup(const char *);
int myadns_revlookup(struct sockaddr *);
int myadns_gather(void (*)(const char *, const char *));

#endif
