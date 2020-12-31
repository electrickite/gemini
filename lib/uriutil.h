#include <stdlib.h>
#include <string.h>
#include <uriparser/Uri.h>
#include "protocol.h"

char *uridup(UriTextRangeA *range);
int uricmp(UriTextRangeA *range, char *str);
size_t urilen(UriTextRangeA *range);
char *uripath(UriUriA *uri);
