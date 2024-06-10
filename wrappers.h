#ifndef NOCACHE_WRAPPERS_H
#define NOCACHE_WRAPPERS_H

extern int (*_original_open)(const char *pathname, int flags, mode_t mode);
extern int (*_original_open64)(const char *pathname, int flags, mode_t mode);
extern int (*_original_creat)(const char *pathname, int flags, mode_t mode);
extern int (*_original_creat64)(const char *pathname, int flags, mode_t mode);
extern int (*_original_openat)(int dirfd, const char *pathname, int flags, mode_t mode);
extern int (*_original_openat64)(int dirfd, const char *pathname, int flags, mode_t mode);
extern int (*_original_dup)(int fd);
extern int (*_original_dup2)(int newfd, int oldfd);
extern int (*_original_close)(int fd);
extern FILE *(*_original_fopen)(const char *path, const char *mode);
extern FILE *(*_original_fopen64)(const char *path, const char *mode);
extern int (*_original_fclose)(FILE *fp);

#endif
