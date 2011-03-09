#ifndef _GET_OPTS_H
# define _GET_OPTS_H

void usage(void) __attribute__((noreturn));
int get_opts_argv(int , char **);

int set_sillyhostname(const char *);
int set_mode(const char *);
int set_allowed(const char *);
int set_async(const char *);
int set_addrfam(const char *);
int set_dictfile(const char *);

int set_exact(int );
int set_filter(int );
int set_discover(int );
int set_outsql(int );
int set_verbose(int );

#endif
