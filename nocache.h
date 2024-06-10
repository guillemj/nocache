#ifndef NOCACHE_H
#define NOCACHE_H

#define DEBUG(...) \
    debug("[nocache] DEBUG: " __VA_ARGS__)

void debug(const char *fmt, ...);

extern int nocache_EOF;
int nocache_fileno(FILE *fp);

#endif
