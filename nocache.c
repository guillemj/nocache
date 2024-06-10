#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>
#include <signal.h>

#include "wrappers.h"
#include "pageinfo.h"
#include "fcntl_helpers.h"
#include "nocache.h"

static void init(void) __attribute__((constructor));
static void destroy(void) __attribute__((destructor));
static void init_mutexes(void);
static void init_debugging(void);
static void handle_stdout(void);

/* Info about a file descriptor 'fd' is stored in fds[fd]. Before accessing an
 * element, callers MUST both check fds_lock != NULL and then acquire
 * fds_lock[fd] while holding the fds_iter_lock. While any mutex in fds_lock is
 * held, fds_lock will not be freed and set to NULL. */
static int max_fds;
static struct file_pageinfo *fds;
static pthread_mutex_t *fds_lock;
static pthread_mutex_t fds_iter_lock;
static int max_fd_observed;  /* guarded by fds_iter_lock */
static size_t PAGESIZE;

static char *env_nr_fadvise = "NOCACHE_NR_FADVISE";
static int nr_fadvise;

int nocache_EOF;

static char *env_debugfd = "NOCACHE_DEBUGFD";
static int debugfd = -1;
static FILE *debugfp;

static char *env_flushall = "NOCACHE_FLUSHALL";
static char flushall;

static char *env_max_fds = "NOCACHE_MAX_FDS";
static rlim_t max_fd_limit = 1 << 20;

int nocache_fileno(FILE *fp)
{
    return fileno(fp);
}

void debug(const char *fmt, ...)
{
    if(debugfp != NULL) {
        va_list args;

        va_start(args, fmt);
        vfprintf(debugfp, fmt, args);
        va_end(args);
    }
}

static void init(void)
{
    int i;
    char *s;
    char *error;
    struct rlimit rlim;

    if((s = getenv(env_nr_fadvise)) != NULL)
        nr_fadvise = atoi(s);
    if(nr_fadvise <= 0)
        nr_fadvise = 1;

    if((s = getenv(env_flushall)) != NULL)
        flushall = atoi(s);
    if(flushall <= 0)
        flushall = 0;

    if((s = getenv(env_max_fds)) != NULL)
        max_fd_limit = atoll(s);

    getrlimit(RLIMIT_NOFILE, &rlim);
    max_fds = rlim.rlim_max;
    if(max_fds > max_fd_limit)
        max_fds = max_fd_limit;

    if(max_fds == 0)
        return;  /* There's nothing to do for us here. */

    init_mutexes();
    /* make sure to re-initialize mutex if forked */
    pthread_atfork(NULL, NULL, init_mutexes);

    fds = malloc(max_fds * sizeof(*fds));
    assert(fds != NULL);

    _original_open = (int (*)(const char *, int, mode_t)) dlsym(RTLD_NEXT, "open");
    _original_open64 = (int (*)(const char *, int, mode_t)) dlsym(RTLD_NEXT, "open64");
    _original_creat = (int (*)(const char *, int, mode_t)) dlsym(RTLD_NEXT, "creat");
    _original_creat64 = (int (*)(const char *, int, mode_t)) dlsym(RTLD_NEXT, "creat64");
    _original_openat = (int (*)(int, const char *, int, mode_t)) dlsym(RTLD_NEXT, "openat");
    _original_openat64 = (int (*)(int, const char *, int, mode_t)) dlsym(RTLD_NEXT, "openat64");
    _original_dup = (int (*)(int)) dlsym(RTLD_NEXT, "dup");
    _original_dup2 = (int (*)(int, int)) dlsym(RTLD_NEXT, "dup2");
    _original_close = (int (*)(int)) dlsym(RTLD_NEXT, "close");
    _original_fopen = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");
    _original_fopen64 = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen64");
    _original_fclose = (int (*)(FILE *)) dlsym(RTLD_NEXT, "fclose");

    if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }

    PAGESIZE = getpagesize();
    nocache_EOF = EOF;
    pthread_mutex_lock(&fds_iter_lock);
    for(i = 0; i < max_fds; i++) {
        pthread_mutex_lock(&fds_lock[i]);
        fds[i].fd = -1;
        pthread_mutex_unlock(&fds_lock[i]);
    }
    max_fd_observed = 0;
    pthread_mutex_unlock(&fds_iter_lock);
    init_debugging();
    handle_stdout();
}

static void init_mutexes(void)
{
    int i;
    pthread_mutex_init(&fds_iter_lock, NULL);
    pthread_mutex_lock(&fds_iter_lock);
    fds_lock = malloc(max_fds * sizeof(*fds_lock));
    assert(fds_lock != NULL);
    for(i = 0; i < max_fds; i++) {
        pthread_mutex_init(&fds_lock[i], NULL);
    }
    pthread_mutex_unlock(&fds_iter_lock);
}

static void init_debugging(void)
{
    char *s = getenv(env_debugfd);
    if(!s)
        return;
    debugfd = atoi(s);
    debugfp = fdopen(debugfd, "a");
}

/* duplicate stdout if it is a regular file. We will use this later to
 * fadvise(DONTNEED) on it, although the real stdout was already
 * closed. This makes "nocache tar cfz" work properly. */
static void handle_stdout(void)
{
    int fd;
    struct stat st;

    if(fstat(STDOUT_FILENO, &st) == -1 || !S_ISREG(st.st_mode))
        return;

    fd = fcntl_dupfd(STDOUT_FILENO, 23);
    if(fd == -1)
        return;
    store_pageinfo(fd);
}

/* try to advise fds that were not manually closed */
static void destroy(void)
{
    int i;
    int max_fd_to_clear;
    sigset_t mask, old_mask;

    /* There is a race condition here: If something opens files after
     * extracting max_fd_observed, then it is possible we miss cleaning it up
     * in the shutdown path. */
    pthread_mutex_lock(&fds_iter_lock);
    max_fd_to_clear = max_fd_observed;
    pthread_mutex_unlock(&fds_iter_lock);

    /* We block signals here, and then call free_unclaimed_pages in a loop. As
     * max_fds may be high (millions), it's very wasteful to block signals
     * repeatedly, so it's done once here. */
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);
    for(i = 0; i < max_fd_to_clear; i++) {
        free_unclaimed_pages(i, false);
    }
    sigprocmask(SIG_SETMASK, &old_mask, NULL);

    pthread_mutex_lock(&fds_iter_lock);
    if(fds_lock == NULL) {
        pthread_mutex_unlock(&fds_iter_lock);
        return;
    }
    for(i = 0; i < max_fds; i++) {
        pthread_mutex_lock(&fds_lock[i]);
    }
    /* We have acquired all locks. It is now safe to delete and free the list. */
    free(fds);
    fds = NULL;
    free(fds_lock);
    fds_lock = NULL;
    pthread_mutex_unlock(&fds_iter_lock);
}

void store_pageinfo(int fd)
{
    sigset_t mask, old_mask;

    if(fd >= max_fds)
        return;

    /* We might know something about this fd already, so assume we have missed
     * it being closed. */
    free_unclaimed_pages(fd, true);

    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);

    pthread_mutex_lock(&fds_iter_lock);
    if(fds_lock == NULL) {
        pthread_mutex_unlock(&fds_iter_lock);
        return;
    }
    pthread_mutex_lock(&fds_lock[fd]);
    if(fd > max_fd_observed)
        max_fd_observed = fd;
    pthread_mutex_unlock(&fds_iter_lock);

    /* Hint we'll be using this file only once;
     * the Linux kernel will currently ignore this */
    fadv_noreuse(fd, 0, 0);

    fds[fd].fd = fd;
    if(flushall)
        goto out;

    if(!fd_get_pageinfo(fd, &fds[fd])) {
        fds[fd].fd = -1;
        goto out;
    }

    DEBUG("store_pageinfo(fd=%d): pages in cache: %zd/%zd (%.1f%%)  [filesize=%.1fK, "
            "pagesize=%dK]\n", fd, fds[fd].nr_pages_cached, fds[fd].nr_pages,
             fds[fd].nr_pages == 0 ? 0 : (100.0 * fds[fd].nr_pages_cached / fds[fd].nr_pages),
             1.0 * fds[fd].size / 1024, (int) PAGESIZE / 1024);

    out:
    pthread_mutex_unlock(&fds_lock[fd]);
    sigprocmask(SIG_SETMASK, &old_mask, NULL);

    return;
}

void free_unclaimed_pages(int fd, bool block_signals)
{
    struct stat st;
    sigset_t mask, old_mask;

    if(fd == -1 || fd >= max_fds)
        return;

    if(block_signals) {
        sigfillset(&mask);
        sigprocmask(SIG_BLOCK, &mask, &old_mask);
    }

    pthread_mutex_lock(&fds_iter_lock);
    if(fds_lock == NULL) {
        pthread_mutex_unlock(&fds_iter_lock);
        return;
    }
    pthread_mutex_lock(&fds_lock[fd]);
    if(fd > max_fd_observed)
        max_fd_observed = fd;
    pthread_mutex_unlock(&fds_iter_lock);

    if(fds[fd].fd == -1)
        goto out;

    sync_if_writable(fd);

    if(flushall) {
        DEBUG("fadv_dontneed(fd=%d, from=0, len=0 [till end])\n", fd);
        fadv_dontneed(fd, 0, 0, nr_fadvise);
        fds[fd].fd = -1;
        goto out;
    }

    if(fstat(fd, &st) == -1)
        goto out;

    struct byterange *br;
    for(br = fds[fd].unmapped; br; br = br->next) {
        DEBUG("fadv_dontneed(fd=%d, from=%zd, len=%zd)\n", fd, br->pos, br->len);
        fadv_dontneed(fd, br->pos, br->len, nr_fadvise);
    }

    /* Has the file grown bigger? */
    if(st.st_size > fds[fd].size) {
        DEBUG("fadv_dontneed(fd=%d, from=%lld, len=0 [till new end, file has grown])\n",
              fd, (long long)fds[fd].size);
        fadv_dontneed(fd, fds[fd].size, 0, nr_fadvise);
    }

    free_br_list(&fds[fd].unmapped);
    fds[fd].fd = -1;

    out:
    pthread_mutex_unlock(&fds_lock[fd]);
    if(block_signals)
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
}

/* vim:set et sw=4 ts=4: */
