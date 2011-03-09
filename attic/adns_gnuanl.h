#ifndef _LIBC_ADNS_H
# define _LIBC_ADNS_H

void adns_init(void);
void adns_fini(void);
int adns_lookup(const char *);
int adns_gather(void (* /* function will get name and address */)(const char *, const char *));

#endif
