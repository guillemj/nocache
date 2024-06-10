#ifndef NOCACHE_H
#define NOCACHE_H

#include <stdbool.h>

#define DEBUG(...) \
    debug("[nocache] DEBUG: " __VA_ARGS__)

void debug(const char *fmt, ...);

extern int nocache_EOF;
int nocache_fileno(FILE *fp);

void store_pageinfo(int fd);
void free_unclaimed_pages(int fd, bool block_signals);

#endif
