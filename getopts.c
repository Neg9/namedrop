#include "settings.h"

#include "ext/xmalloc.h"

#include "getopts.h"

#define GETOPT "4" "6" "a:" "b:" "c:" "d" "e" "D" "f:" "F" "h" "H:" "r" "s" "S" "v" "V"

static void display_version(void) __attribute__((noreturn));

int get_opts_argv(int argc, char **argv) {
	extern char *optarg;
	extern int optind;
	char bob[128];
	int ch=0, j=0;
	unsigned int idx=0;

	while ((ch=getopt(argc, argv, GETOPT)) != -1) {
		switch (ch) {
			case '4': /* XXX */
				if (set_addrfam("ipv4") != 1) {
					usage();
				}
				break;

			case '6': /* XXX */
				if (set_addrfam("ipv6") != 1) {
					usage();
				}
				break;

			case 'a':
#if HAVE_C_ARES == 1
				if (set_async(optarg) != 1) {
					usage();
				}
#else
				ERR("No async dns support compiled in");
				usage();
#endif
				break;

			case 'b':
				memset(bob, 0, sizeof(bob));
				strcat(bob, "brute-");
				strncat(bob, optarg, sizeof(bob) - 7 /* brute- + STR + \0 */);
				if (set_mode(bob) != 1) {
					usage();
				}
				break;

			case 'c':
				if (set_allowed(optarg) != 1) {
					usage();
				}
				break;

			case 'd':
				if (set_discover(1) != 1) {
					usage();
				}
				break;

			case 'D':
				if (set_mode("dict") != 1) {
					usage();
				}
				break;

			case 'e':
				if (set_exact(1) != 1) {
					usage();
				}
				break;

			case 'f':
				if (set_dictfile(optarg) != 1) {
					usage();
				}
				break;

			case 'F':
				if (set_filter(0) != 1) {
					usage();
				}
				break;

			case 'H':
				if (set_sillyhostname(optarg) != 1) {
					usage();
				}
				break;

			case 'r':
				if (set_mode("rev") != 1) {
					usage();
				}
				break;

			case 's':
				if (set_outsql(1) != 1) {
					usage();
				}
				break;

			case 'S':
				if (set_async("no") != 1) {
					usage();
				}
				break;

			case 'v':
				if (set_verbose(s->verbose + 1) != 1) {
					usage();
				}
				break;

			case 'V':
				display_version();
				break;

			case 'h':
				/* fall though */
			default:
				usage();
		} /* switch */
	}

	assert(argc >= optind);

	if (argc - optind == 0) {
		ERR("nothing to lookup! (-h for help)");
		exit(1);
	}

	memset(s->targets, 0, sizeof(char *) * MAX_TARGETS);

	assert(MAX_TARGETS > (argc - optind));

	for ( j=optind; j < argc; j++) {
		s->targets[idx++]=xstrdup(argv[j]);
	}

	s->targets[idx]=NULL;

	return 1;
}

static void display_version(void) {
	OUT("%s %s", PROGNAME, PACKAGE_VERSION);
	exit(0);
}

void usage(void) {

	OUT("Usage: %s (%s %s)\n"
	"\t-4\t  only scan ipv4 forward lookups\n"
	"\t-6\t  only scan ipv6 lookups\n"
	"\t-a\t* async mode (if compiled in) with a numeric argument of concurrency (%u default)\n"
	"\t-b\t* brute force hostnames from X to Y chars (x-y)\n"
	"\t-c\t* characters allowed in brute force mode\n"
	"\t-d\t  discover more information based upon found information\n"
	"\t-D\t  dictionary mode (default)\n"
	"\t-e\t  exact information returned is displayed, not asked for information\n"
	"\t-f\t* wordlist to lookup hosts from\n"
	"\t-F\t  do not filter output for unique results\n"
	"\t-h\t  help (you are here)\n"
	"\t-H\t* silly hostname to use to detect wildcards (otherwise itll be random)\n"
	"\t-r\t  reverse dns scan mode\n"
	"\t-s\t  SQL output mode\n"
	"\t-S\t  force SYNC scanning mode (if async mode is available, it is default)\n"
	"\t-v\t  verbose (more for more)\n"
	"\t-V\t  display program version\n"
	, GETOPT, PROGNAME, PACKAGE_VERSION, DEF_CONCURRENCY);

	exit(0);
}

int set_allowed(const char *str) {

	if (str == NULL || strlen(str) < 1) {
		return -1;
	}

	if (s->allowed != NULL) {
		xfree(s->allowed);
	}
	s->allowed=xstrdup(str);

	return 1;
}

int set_sillyhostname(const char *name) {

	if (name == NULL || strlen(name) < 1) {
		return -1;
	}

	if (s->sillyhostname != NULL) {
		xfree(s->sillyhostname);
	}
	s->sillyhostname=xstrdup(name);

	return 1;
}

int set_addrfam(const char *addrfams) {

	s->ipv4_lookup=0;
	s->ipv6_lookup=0;

	if (addrfams == NULL || strlen(addrfams) < 1) {
		ERR("no address family to set, use ipv4|ipv6|ipv46");
		return -1;
	}

	if (strcasecmp(addrfams, "ipv4") == 0) {
		s->ipv4_lookup=1;
	}
	else if (strcasecmp(addrfams, "ipv6") == 0) {
		s->ipv6_lookup=1;
	}
	else if (strcasecmp(addrfams, "ipv46") == 0 || strcasecmp(addrfams, "all") == 0) {
		s->ipv4_lookup=s->ipv6_lookup=1;
	}
	else {
		ERR("unknown address family `%s', try ipv4|ipv6|ipv46", addrfams);
		return -1;
	}

	return 1;
}

int set_mode(const char *bstr) {

	assert(bstr != NULL);

	if (sscanf(bstr, "brute-%d-%d", &s->brute_lenmin, &s->brute_lenmax) == 2) {
		if (s->brute_lenmin > s->brute_lenmax) {
			int tmp=0;

			tmp=s->brute_lenmax;
			s->brute_lenmax=s->brute_lenmin;
			s->brute_lenmin=tmp;
		}

		if (s->brute_lenmax < 1 || s->brute_lenmin < 1) {
			ERR("bad brute length parameters");
			return -1;
		}
		if (s->brute_lenmax > MAX_BRUTELEN) {
			ERR("who has that much time?");
			return -1;
		}
		s->mode=MODE_BRUTE;
	}
	else if (sscanf(bstr, "brute-%d", &s->brute_lenmax) == 1) {
		s->brute_lenmin=1;
		if (s->brute_lenmax < 1) {
			ERR("brute length is less than one");
			return -1;
		}

		/* else could be assumed ;] */
		if (s->brute_lenmax > MAX_BRUTELEN) {
			ERR("who has that much time?");
			return -1;
		}
		s->mode=MODE_BRUTE;
	}
	else if (strcmp(bstr, "dict") == 0 || strcmp(bstr, "dictionary") == 0) {
		s->mode=MODE_DICT;
	}
	else if (strcmp(bstr, "rev") == 0 || strcmp(bstr, "reverse") == 0) {
		s->mode=MODE_REVERSE;
	}
	else {
		ERR("unknown mode `%s'", bstr);
		return -1;
	}

	return 1;
}

int set_dictfile(const char *in) {

	if (in == NULL || strlen(in) < 1) {
		return -1;
	}

	if (s->dictfile != NULL) {
		xfree(s->dictfile);
	}

	s->dictfile=xstrdup(in);

	return 1;
}

int set_async(const char *str) {

	if (str == NULL || strlen(str) < 1) {
		ERR("bad sync|async input, try no|number");
		return -1;
	}

	if (strcasecmp(str, "no") == 0) {
		s->async=0;
	}
	else {
		if (sscanf(str, "%u", &s->concurrency) != 1) {
			ERR("bad number for async concurrency");
			return -1;
		}
		if (s->concurrency < 2) {
			ERR("concurrency should be > 1, otherwise dont use it");
			return -1;
		}
		if (s->concurrency > 256) {
			ERR("concurrency too large!");
			s->concurrency=DEF_CONCURRENCY;
			return -1;
		}
		s->async=1;
	}

	return 1;
}

int set_exact(int yesno) {

	s->exact=yesno;

	return 1;
}

int set_filter(int yesno) {

	s->filter_unique=yesno;

	return 1;
}

int set_discover(int yesno) {

	s->discover=1;

	return 1;
}

int set_outsql(int yesno) {

	s->output_sql=yesno;

	return 1;
}

int set_verbose(int level) {

	s->verbose=level;

	return 1;
}
