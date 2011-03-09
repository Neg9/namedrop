#include "settings.h"

#include "ext/fread.h"
#include "getopts.h"

static struct cfg_opts_s {
	const char *name;
	const char *alias;
	int fptype;
#define FPTYPE_NONE	0
#define FPTYPE_STR	1
#define FPTYPE_INT	2
	union {
		void *p;
		int (*sfp)(const char *);
		int (*ifp)(int );
	} f_u;
} cfg_opts[]={
{"mode",		NULL, FPTYPE_STR,	{ set_mode		}},
{"addrfam",		NULL, FPTYPE_STR,	{ set_addrfam		}},
{"allowed",		NULL, FPTYPE_STR,	{ set_allowed		}},
{"async",		NULL, FPTYPE_STR,	{ set_async		}},
{"dictfile",		NULL, FPTYPE_STR,	{ set_dictfile		}},
{"sillyhostname",	NULL, FPTYPE_STR,	{ set_sillyhostname	}},
{"verbose",		NULL, FPTYPE_INT,	{ set_verbose		}},
{"exact",		NULL, FPTYPE_INT,	{ set_exact		}},
{"outsql",		NULL, FPTYPE_INT,	{ set_outsql		}},
{"discover",		NULL, FPTYPE_INT,	{ set_discover		}},
{"filter",		NULL, FPTYPE_INT,	{ set_filter		}},
{NULL,			NULL, FPTYPE_NONE,	{ NULL			}}
};

void readconf(const char *file) {
	void *hand=NULL;
	char *buf=NULL, param[128], value[128];
	unsigned int j=0, found=0;

	/*
	 * not possible: (no settings yet) DBG("reading `%s'", file);
	 */

	hand=fread_create(file, FREAD_NONL);
	if (hand == NULL) {
		return;
	}

	for (;;) {
		if (fread_getline(hand, &buf) < 1) {
			break;
		}
		if (buf == NULL || strlen(buf) < 1) {
			continue;
		}
		if (buf[0] == '#') {
			continue;
		}
		if (sscanf(buf, "%127[^:]: %127s", param, value) != 2) {
			continue;
		}

		for (j=0, found=0; cfg_opts[j].name != NULL; j++) {

			if (strcasecmp(param, cfg_opts[j].name) == 0 ||
				(cfg_opts[j].alias != NULL && strcasecmp(param, cfg_opts[j].alias) == 0)
			) {
				int ret=0;

				found=1;
				if (cfg_opts[j].fptype == FPTYPE_STR) {
					ret=cfg_opts[j].f_u.sfp(value);
				}
				else if (cfg_opts[j].fptype == FPTYPE_INT) {
					ret=cfg_opts[j].f_u.ifp(atoi(value));
				}
				else {
					PANIC("bad function type");
				}

				if (ret != 1) {
					ERR("line `%s' is not valid at %s:%u", buf, fread_filename(hand), fread_lineno(hand));
					exit(1);
				}

			}
		}

		if (found == 0) {
			ERR("unknown setting `%s' at %s:%u", param, fread_filename(hand), fread_lineno(hand));
		}
	} /* for each line of file */

	fread_destroy(hand);
}
