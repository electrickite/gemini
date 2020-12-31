#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500
#include "uriutil.h"

char *uridup(UriTextRangeA *range) {
	size_t len = urilen(range);
	char *dup = malloc(len + 1);
	strncat(dup, range->first, len);
	return dup;
}

int uricmp(UriTextRangeA *range, char *str) {
	return strncmp(str, range->first, urilen(range));
}

size_t urilen(UriTextRangeA *range) {
	return range->afterLast - range->first;
}

char *uripath(UriUriA *uri) {
	size_t sum = 0;
	size_t sep_len = strlen(PATH_SEPARATOR);
	size_t seg_len;
	UriPathSegmentA *segment = uri->pathHead;

	while (segment != NULL) {
		sum += sep_len + urilen(&segment->text);
		segment = segment->next;
	}
	segment = uri->pathHead;
	char *path = malloc(sum + 1);
	char *target = path;
	path[0] = '\0';

	while (segment != NULL) {
		strcat(target, PATH_SEPARATOR);
		target += sep_len;
		seg_len = urilen(&segment->text);
		strncat(target, segment->text.first, seg_len);
		target += seg_len;
		segment = segment->next;
	}
	return path;
}
