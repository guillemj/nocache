#define _GNU_SOURCE
#include <sys/types.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <dlfcn.h>

typedef struct FILE FILE;

#include "wrappers.h"
#include "pageinfo.h"
#include "fcntl_helpers.h"
#include "nocache.h"

int open(const char *pathname, int flags, mode_t mode);
int open64(const char *pathname, int flags, mode_t mode);
int creat(const char *pathname, int flags, mode_t mode);
int creat64(const char *pathname, int flags, mode_t mode);
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
int openat64(int dirfd, const char *pathname, int flags, mode_t mode);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int close(int fd);
FILE *fopen(const char *path, const char *mode);
FILE *fopen64(const char *path, const char *mode);
int fclose(FILE *fp);

int (*_original_open)(const char *pathname, int flags, mode_t mode);
int (*_original_open64)(const char *pathname, int flags, mode_t mode);
int (*_original_creat)(const char *pathname, int flags, mode_t mode);
int (*_original_creat64)(const char *pathname, int flags, mode_t mode);
int (*_original_openat)(int dirfd, const char *pathname, int flags, mode_t mode);
int (*_original_openat64)(int dirfd, const char *pathname, int flags, mode_t mode);
int (*_original_dup)(int fd);
int (*_original_dup2)(int newfd, int oldfd);
int (*_original_close)(int fd);
FILE *(*_original_fopen)(const char *path, const char *mode);
FILE *(*_original_fopen64)(const char *path, const char *mode);
int (*_original_fclose)(FILE *fp);

int open(const char *pathname, int flags, mode_t mode)
{
    int fd;

    if(!_original_open)
        _original_open = (int (*)(const char *, int, mode_t)) dlsym(RTLD_NEXT, "open");
    assert(_original_open != NULL);

    if((fd = _original_open(pathname, flags, mode)) != -1) {
        DEBUG("open(pathname=%s, flags=0x%x, mode=0%o) = %d\n",
            pathname, flags, mode, fd);
        store_pageinfo(fd);
    }
    return fd;
}

int open64(const char *pathname, int flags, mode_t mode)
{
    int fd;

    if(!_original_open64)
        _original_open64 = (int (*)(const char *, int, mode_t)) dlsym(RTLD_NEXT, "open64");
    assert(_original_open64 != NULL);

    DEBUG("open64(pathname=%s, flags=0x%x, mode=0%o)\n", pathname, flags, mode);

    if((fd = _original_open64(pathname, flags, mode)) != -1)
        store_pageinfo(fd);
    return fd;
}

int creat(const char *pathname, int flags, mode_t mode)
{
    int fd;

    if(!_original_creat)
        _original_creat = (int (*)(const char *, int, mode_t)) dlsym(RTLD_NEXT, "creat");
    assert(_original_creat != NULL);

    DEBUG("creat(pathname=%s, flags=0x%x, mode=0%o)\n", pathname, flags, mode);

    if((fd = _original_creat(pathname, flags, mode)) != -1)
        store_pageinfo(fd);
    return fd;
}

int creat64(const char *pathname, int flags, mode_t mode)
{
    int fd;

    if(!_original_creat64)
        _original_creat64 = (int (*)(const char *, int, mode_t)) dlsym(RTLD_NEXT, "creat64");
    assert(_original_creat64 != NULL);

    DEBUG("creat64(pathname=%s, flags=0x%x, mode=0%o)\n", pathname, flags, mode);

    if((fd = _original_creat64(pathname, flags, mode)) != -1)
        store_pageinfo(fd);
    return fd;
}

int openat(int dirfd, const char *pathname, int flags, mode_t mode)
{
    int fd;

    if(!_original_openat)
        _original_openat = (int (*)(int, const char *, int, mode_t)) dlsym(RTLD_NEXT, "openat");
    assert(_original_openat != NULL);

    DEBUG("openat(dirfd=%d, pathname=%s, flags=0x%x, mode=0%o)\n", dirfd, pathname, flags, mode);

    if((fd = _original_openat(dirfd, pathname, flags, mode)) != -1)
        store_pageinfo(fd);
    return fd;
}

int openat64(int dirfd, const char *pathname, int flags, mode_t mode)
{
    int fd;

    if(!_original_openat64)
        _original_openat64 = (int (*)(int, const char *, int, mode_t)) dlsym(RTLD_NEXT, "openat64");
    assert(_original_openat64 != NULL);

    DEBUG("openat64(dirfd=%d, pathname=%s, flags=0x%x, mode=0%o)\n", dirfd, pathname, flags, mode);

    if((fd = _original_openat64(dirfd, pathname, flags, mode)) != -1)
        store_pageinfo(fd);
    return fd;
}

int dup(int oldfd)
{
    int fd;

    if(!_original_dup)
        _original_dup = (int (*)(int)) dlsym(RTLD_NEXT, "dup");
    assert(_original_dup != NULL);

    DEBUG("dup(oldfd=%d)\n", oldfd);

    if((fd = _original_dup(oldfd)) != -1)
        store_pageinfo(fd);
    return fd;
}

int dup2(int oldfd, int newfd)
{
    int ret;

    /* if newfd is already opened, the kernel will close it directly
     * once dup2 is invoked. So now is the last chance to mark the
     * pages as "DONTNEED" */
    if(valid_fd(newfd))
        free_unclaimed_pages(newfd, true);

    if(!_original_dup2)
        _original_dup2 = (int (*)(int, int)) dlsym(RTLD_NEXT, "dup2");
    assert(_original_dup2 != NULL);

    DEBUG("dup2(oldfd=%d, newfd=%d)\n", oldfd, newfd);

    if((ret = _original_dup2(oldfd, newfd)) != -1)
        store_pageinfo(newfd);
    return ret;
}

int close(int fd)
{
    if(!_original_close)
        _original_close = (int (*)(int)) dlsym(RTLD_NEXT, "close");
    assert(_original_close != NULL);

    free_unclaimed_pages(fd, true);

    DEBUG("close(%d)\n", fd);
    return _original_close(fd);
}

FILE *fopen(const char *path, const char *mode)
{
    int fd;
    FILE *fp = NULL;

    if(!_original_fopen)
       _original_fopen = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");
    assert(_original_fopen != NULL);

    DEBUG("fopen(path=%s, mode=%s)\n", path, mode);

    if((fp = _original_fopen(path, mode)) != NULL)
        if((fd = nocache_fileno(fp)) != -1)
            store_pageinfo(fd);

    return fp;
}

FILE *fopen64(const char *path, const char *mode)
{
    int fd;
    FILE *fp;
    fp = NULL;

    if(!_original_fopen64)
        _original_fopen64 = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen64");
    assert(_original_fopen64 != NULL);

    DEBUG("fopen64(path=%s, mode=%s)\n", path, mode);

    if((fp = _original_fopen64(path, mode)) != NULL)
        if((fd = nocache_fileno(fp)) != -1)
            store_pageinfo(fd);

    return fp;
}

int fclose(FILE *fp)
{
    if(!_original_fclose)
        _original_fclose = (int (*)(FILE *)) dlsym(RTLD_NEXT, "fclose");
    assert(_original_fclose != NULL);

    if(_original_fclose) {
        free_unclaimed_pages(nocache_fileno(fp), true);
        return _original_fclose(fp);
    }

    errno = EFAULT;
    return nocache_EOF;
}

/* vim:set et sw=4 ts=4: */
