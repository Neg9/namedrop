#include "settings.h"

#include <ctype.h>

void hexdump(const void *in, size_t len) {
	const uint8_t *ptr=NULL;
	size_t psize=0, hsize=0;
	char hbuf[512];

	OUT("############################## buffer dump size is %zu ##############################", len);

	for (ptr=(const uint8_t *)in, psize=0; psize < len; psize++, ptr++) {
		if (psize != 0 && ((psize % 16) == 0)) {
			OUT("# %-40s #", hbuf);
			hbuf[0]='\0';
			hsize=0;
		}
		if (isalnum(*ptr)) {
			sprintf(hbuf + hsize, "  %c  ", *(const char *)ptr);
		}
		else {
			sprintf(hbuf + hsize, "0x%02x ", *ptr);
		}
		hsize += 5;
	}
	if (strlen(hbuf) > 0) {
		OUT("# %-40s #", hbuf);
	}

	OUT("####################################################################################");

	OUT_FLUSH;

	return;
}
