#define PS5DRIVE_PS4_COMPAT_IMPL 1
#include "ps4_compat.h"

#if !defined(PS5DRIVE_PS4_BUILD)

void ps4_sdk_init(void) {
}

#else

#include "config.h"

extern int libc;

typedef int (*ps4_vsnprintf_fn)(char *str, size_t size, const char *format, va_list ap);

static int g_ps4_sdk_ready = 0;
static int g_fd_flags[1024];
static ps4_vsnprintf_fn g_vsnprintf_fn = NULL;

static int ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

void ps4_sdk_init(void) {
    if (g_ps4_sdk_ready) return;
    initKernel();
    initLibc();
    initNetwork();
    initPthread();
    g_ps4_sdk_ready = 1;
}

static void resolve_vsnprintf(void) {
    if (g_vsnprintf_fn) return;
    ps4_sdk_init();
    if (libc <= 0) return;
    ps4_vsnprintf_fn fn = NULL;
    if (getFunctionAddressByName(libc, "vsnprintf", &fn) == 0 && fn) {
        g_vsnprintf_fn = fn;
    }
}

int ps4_close(int fd) {
    ps4_sdk_init();
    if (sceNetSocketClose) {
        int rc = sceNetSocketClose(fd);
        if (rc == 0) return 0;
    }
    return close(fd);
}

int ps4_kill(pid_t pid, int sig) {
    int rc = (int)syscall(37, pid, sig);
    if (rc == 0) return 0;
    if (errno == ENOSYS) return kill(pid, sig);
    return rc;
}

int ps4_socket(int domain, int type, int protocol) {
    ps4_sdk_init();
    if (!sceNetSocket) return -1;
    return sceNetSocket(PS5DRIVE_BRAND_LOWER, domain, type, protocol);
}

int ps4_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    ps4_sdk_init();
    if (!sceNetConnect) return -1;
    return sceNetConnect(fd, (struct sockaddr *)addr, (int)len);
}

int ps4_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    ps4_sdk_init();
    if (!sceNetBind) return -1;
    return sceNetBind(fd, (struct sockaddr *)addr, (int)len);
}

int ps4_listen(int fd, int backlog) {
    ps4_sdk_init();
    if (!sceNetListen) return -1;
    return sceNetListen(fd, backlog);
}

int ps4_accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    ps4_sdk_init();
    if (!sceNetAccept) return -1;
    unsigned int n = addrlen ? (unsigned int)(*addrlen) : 0;
    int client = sceNetAccept(fd, addr, addrlen ? &n : NULL);
    if (addrlen) *addrlen = (socklen_t)n;
    return client;
}

ssize_t ps4_send(int fd, const void *buf, size_t len, int flags) {
    ps4_sdk_init();
    if (!sceNetSend) return -1;
    return (ssize_t)sceNetSend(fd, buf, len, flags);
}

ssize_t ps4_recv(int fd, void *buf, size_t len, int flags) {
    ps4_sdk_init();
    if (!sceNetRecv) return -1;
    return (ssize_t)sceNetRecv(fd, buf, len, flags);
}

int ps4_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    ps4_sdk_init();
    if (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO || optname == SO_NOSIGPIPE ||
        optname == SO_RCVBUF || optname == SO_SNDBUF) {
        return 0;
    }
    if (!sceNetSetsockopt) return -1;
    return sceNetSetsockopt(fd, level, optname, optval, optlen);
}

int ps4_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    ps4_sdk_init();
    if (!sceNetGetsockopt) return -1;
    return sceNetGetsockopt(fd, level, optname, optval, optlen);
}

int ps4_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    ps4_sdk_init();
    if (!sceNetGetsockname) return -1;
    unsigned int n = addrlen ? (unsigned int)(*addrlen) : 0;
    int rc = sceNetGetsockname(fd, addr, addrlen ? &n : NULL);
    if (addrlen) *addrlen = (socklen_t)n;
    return rc;
}

int ps4_shutdown(int fd, int how) {
    ps4_sdk_init();
    if (!sceNetSocketAbort) return 0;
    int flags = 0;
    if (how == SHUT_RDWR) {
        flags = SCE_NET_SOCKET_ABORT_FLAG_RCV_PRESERVATION | SCE_NET_SOCKET_ABORT_FLAG_SND_PRESERVATION;
    } else {
        flags = SCE_NET_SOCKET_ABORT_FLAG_SND_PRESERVATION;
    }
    return sceNetSocketAbort(fd, flags);
}

int ps4_fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    int arg = va_arg(ap, int);
    va_end(ap);

    if (cmd == F_GETFL) {
        if (fd >= 0 && fd < (int)(sizeof(g_fd_flags) / sizeof(g_fd_flags[0]))) {
            return g_fd_flags[fd];
        }
        return 0;
    }

    if (cmd == F_SETFL) {
        if (fd >= 0 && fd < (int)(sizeof(g_fd_flags) / sizeof(g_fd_flags[0]))) {
            g_fd_flags[fd] = arg;
        }
        ps4_sdk_init();
        if (sceNetSetsockopt) {
            int nbio = (arg & O_NONBLOCK) ? 1 : 0;
            (void)sceNetSetsockopt(fd, SOL_SOCKET, SO_NBIO, &nbio, sizeof(nbio));
        }
        return 0;
    }

    return 0;
}

unsigned int ps4_sleep(unsigned int seconds) {
    ps4_sdk_init();
    if (!usleep) return seconds;
    while (seconds-- > 0) (void)usleep(1000 * 1000);
    return 0;
}

char *ps4_getenv(const char *name) {
    (void)name;
    return NULL;
}

int ps4_access(const char *path, int mode) {
    int rc = (int)syscall(33, path, mode);
    if (rc == 0) return 0;
    if (errno != ENOSYS) return -1;
    struct stat st;
    return stat(path, &st) == 0 ? 0 : -1;
}

char *ps4_realpath(const char *path, char *resolved_path) {
    if (!path || !resolved_path) return NULL;
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    ps4_sdk_init();
    if (!strncpy) return NULL;
    strncpy(resolved_path, path, PATH_MAX - 1);
    resolved_path[PATH_MAX - 1] = '\0';
    return resolved_path;
}

int ps4_strcasecmp(const char *a, const char *b) {
    if (a == b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (*a && *b) {
        int ca = ascii_tolower((unsigned char)*a);
        int cb = ascii_tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        ++a;
        ++b;
    }
    return ascii_tolower((unsigned char)*a) - ascii_tolower((unsigned char)*b);
}

int ps4_strncasecmp(const char *a, const char *b, size_t n) {
    if (n == 0) return 0;
    if (a == b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (n-- > 0 && *a && *b) {
        int ca = ascii_tolower((unsigned char)*a);
        int cb = ascii_tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        if (n == 0) return 0;
        ++a;
        ++b;
    }
    if (n == (size_t)-1) return 0;
    return ascii_tolower((unsigned char)*a) - ascii_tolower((unsigned char)*b);
}

long long ps4_strtoll(const char *nptr, char **endptr, int base) {
    return (long long)strtol(nptr, endptr, base);
}

int ps4_isalnum(int c) {
    if (c >= '0' && c <= '9') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    return 0;
}

void *ps4_memchr(const void *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    unsigned char needle = (unsigned char)c;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] == needle) return (void *)(p + i);
    }
    return NULL;
}

char *ps4_strtok_r(char *str, const char *delim, char **saveptr) {
    char *cur = str ? str : (saveptr ? *saveptr : NULL);
    if (!cur || !delim || !saveptr) return NULL;

    while (*cur) {
        int is_delim = 0;
        for (const char *d = delim; *d; ++d) {
            if (*cur == *d) {
                is_delim = 1;
                break;
            }
        }
        if (!is_delim) break;
        ++cur;
    }
    if (*cur == '\0') {
        *saveptr = cur;
        return NULL;
    }

    char *start = cur;
    while (*cur) {
        int is_delim = 0;
        for (const char *d = delim; *d; ++d) {
            if (*cur == *d) {
                is_delim = 1;
                break;
            }
        }
        if (is_delim) break;
        ++cur;
    }
    if (*cur) {
        *cur = '\0';
        ++cur;
    }
    *saveptr = cur;
    return start;
}

int ps4_chmod(const char *path, int mode) {
    return (int)syscall(15, path, mode);
}

int ps4_fsync(int fd) {
    return (int)syscall(95, fd);
}

pid_t ps4_getppid(void) {
    return (pid_t)syscall(39);
}

void ps4_exit(int status) {
    syscall(1, status);
    for (;;) {
    }
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    resolve_vsnprintf();
    if (!g_vsnprintf_fn) return -1;
    return g_vsnprintf_fn(str, size, format, ap);
}

#endif
