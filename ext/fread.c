#include "settings.h"

#include "ext/xmalloc.h"
#include "ext/fread.h"

#include <zlib.h>

#define FREAD_MAGIC	0x46b03a19

typedef struct fread_t {
	uint32_t magic;
	char *fname;
	unsigned int lineno;
	unsigned int rtimes;
	int close;

	int flags;

	FILE *stream;
	gzFile *gdesc;

	char *buf;
} fread_t;

#define FREAD_BUFSZ	4096

void *fread_create (const char *filename, int flags) {
	union {
		void *p;
		fread_t *f;
	} f_u;
	char fname[PATH_MAX];

	f_u.p=NULL;

	if (filename == NULL || strlen(filename) < 1) {
		return NULL;
	}

	f_u.p=xmalloc(sizeof(fread_t));
	memset(f_u.p, 0, sizeof(fread_t));
	f_u.f->magic=FREAD_MAGIC;

	f_u.f->stream=fopen(filename, "r");
	if (f_u.f->stream == NULL) {
		snprintf(fname, sizeof(fname) -1, "%s.gz", filename);

		f_u.f->gdesc=gzopen(fname, "r");
		if (f_u.f->gdesc == NULL) {
			xfree(f_u.p);
			return NULL;
		}
		//gzclearerr(f_u.f->gdesc);
		f_u.f->fname=xstrdup(fname);
	}
	else {
		(void )clearerr(f_u.f->stream);
		f_u.f->fname=xstrdup(filename);
	}

	f_u.f->flags=flags;
	f_u.f->lineno=0;
	f_u.f->rtimes=0;
	f_u.f->close=1;

	return f_u.p;
}

void *fread_assoc (FILE *fhand, const char *filename, int flags, int iclose) {
	union {
		void *p;
		fread_t *f;
	} f_u;

	if (fhand == NULL) {
		return NULL;
	}

	f_u.p=NULL;

	f_u.p=xmalloc(sizeof(fread_t));
	memset(f_u.p, 0, sizeof(fread_t));
	f_u.f->magic=FREAD_MAGIC;

	if (filename == NULL || strlen(filename) < 1) {
		f_u.f->fname=xstrdup("None");
	}
	else {
		f_u.f->fname=xstrdup(filename);
	}

	f_u.f->stream=fhand;

	(void )clearerr(f_u.f->stream);

	f_u.f->flags=flags;
	f_u.f->lineno=0;
	f_u.f->rtimes=0;
	f_u.f->close=iclose;

	return f_u.p;
}

int	 fread_getline(void *p, char **buf) {
	union {
		void *p;
		fread_t *f;
	} f_u;

	if (p == NULL) {
		ERR("getline with null fread handle");
		return -1;
	}

	if (buf == NULL) {
		ERR("getline with null output pointer");
		return -1;
	}
	*buf=NULL;

	f_u.p=p;
	assert(f_u.f->magic == FREAD_MAGIC);

	if (f_u.f->stream == NULL && f_u.f->gdesc == NULL) {
		ERR("fread handle does not contain an open file, perhaps you need to fread_create first?");
		return -1;
	}

	if ((f_u.f->stream != NULL && feof(f_u.f->stream)) || (f_u.f->gdesc != NULL && gzeof(f_u.f->gdesc))) {
		return 0;
	}

	if (f_u.f->buf == NULL) {
		f_u.f->buf=xmalloc(FREAD_BUFSZ);
	}

	memset(f_u.f->buf, 0, FREAD_BUFSZ);

	if (f_u.f->stream != NULL) {
		if (fgets(f_u.f->buf, FREAD_BUFSZ - 1, f_u.f->stream) == NULL) {
			return 0;
		}
	}
	else if (f_u.f->gdesc != NULL) {
		if (gzgets(f_u.f->gdesc, f_u.f->buf, FREAD_BUFSZ - 1) == NULL) {
			return 0;
		}
	}
	else {
		PANIC("whoa");
	}
	f_u.f->lineno++;

	*buf=f_u.f->buf;

	if (strlen(f_u.f->buf) < 1) {
		return 1;
	}

	switch (f_u.f->flags) {
		case FREAD_NULL:
			break;

		case FREAD_NONL:
			if (f_u.f->buf[strlen(f_u.f->buf) - 1] == '\n') {
				f_u.f->buf[strlen(f_u.f->buf) - 1]='\0';
			}
			break;

		case FREAD_NOCRNL:
			if (strlen(f_u.f->buf) < 2) {
				return 1;
			}
			if (f_u.f->buf[strlen(f_u.f->buf) - 1] == '\n' && f_u.f->buf[strlen(f_u.f->buf) - 2] == '\r') {
				f_u.f->buf[strlen(f_u.f->buf) - 2]='\0';
			}
			break;

		case FREAD_NOCR:
			if (f_u.f->buf[strlen(f_u.f->buf) - 1] == '\r') {
				f_u.f->buf[strlen(f_u.f->buf) - 1]='\0';
			}
			break;

		default:
			ERR("unknown flags `%08x' for fread handle, resetting flags to NULL", f_u.f->flags);
			f_u.f->flags=FREAD_NULL;
			break;
	}

	return 2;
}

void	 fread_destroy(void *p) {
	union {
		void *p;
		fread_t *f;
	} f_u;

	if (p == NULL) {
		return;
	}

	f_u.p=p;

	assert(f_u.f->magic == FREAD_MAGIC);

	if (f_u.f->stream != NULL && f_u.f->close > 0) {
		fclose(f_u.f->stream);
	}
	if (f_u.f->gdesc != NULL && f_u.f->close > 0) {
		gzclose(f_u.f->gdesc);
	}

	if (f_u.f->buf != NULL) {
		xfree(f_u.f->buf);
	}

	if (f_u.f->fname) {
		xfree(f_u.f->fname);
	}

	xfree(f_u.p);

	return;
}

const char *fread_filename(void *p) {
	union {
		void *p;
		fread_t *f;
	} f_u;

	if (p == NULL) {
		return "NotOpen";
	}

	f_u.p=p;

	assert(f_u.f->magic == FREAD_MAGIC);

	return f_u.f->fname;
}

unsigned int fread_lineno(void *p) {
	union {
		void *p;
		fread_t *f;
	} f_u;

	if (p == NULL) {
		return 0U;
	}

	f_u.p=p;

	assert(f_u.f->magic == FREAD_MAGIC);

	return f_u.f->lineno;
}

#ifdef _WRAP_

#include <stdlib.h>
#include <settings.h>

settings_t *s=NULL;

int main(int argc, char ** argv) {
	int j=0;
	void *handle=NULL;
	char *buf=NULL;

	s=xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(settings_t));

	s->_stdout=stdout;
	s->_stderr=stderr;

	for (j=1 ; j < argc ; j++) {
		handle=fread_create(argv[j], FREAD_NONL);
		if (handle == NULL) {
			continue;
		}

		while (fread_getline(handle, &buf) > 0) {
			printf("Got line `%s' from %s:%u\n", buf, fread_filename(handle), fread_lineno(handle));
		}
		fread_destroy(handle);
	}

	xfree(s);
	exit(0);
}

#endif
