#ifndef PS5DRIVE_PS4_COMPAT_H
#define PS5DRIVE_PS4_COMPAT_H

#if defined(PS5DRIVE_PS4_BUILD)

#include <stdarg.h>

#include "ps4.h"

typedef int pid_t;

#ifndef __BEGIN_DECLS
#define __BEGIN_DECLS
#define __END_DECLS
#endif

#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

#ifndef INADDR_ANY
#define INADDR_ANY IN_ADDR_ANY
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7F000001U
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO 0x1006
#endif

#ifndef SO_SNDTIMEO
#define SO_SNDTIMEO 0x1005
#endif

#ifndef SO_RCVBUF
#define SO_RCVBUF 0x1002
#endif

#ifndef SO_SNDBUF
#define SO_SNDBUF 0x1001
#endif

#ifndef SO_NOSIGPIPE
#define SO_NOSIGPIPE 0x1022
#endif

#ifndef SO_REUSEADDR
#define SO_REUSEADDR SCE_NET_SO_REUSEADDR
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

#ifndef F_GETFL
#define F_GETFL 3
#endif

#ifndef F_SETFL
#define F_SETFL 4
#endif

#ifndef R_OK
#define R_OK 4
#endif

#ifndef W_OK
#define W_OK 2
#endif

#ifndef X_OK
#define X_OK 1
#endif

#ifndef SIGINT
#define SIGINT 2
#endif

#ifndef SIGKILL
#define SIGKILL 9
#endif

#ifndef SIGPIPE
#define SIGPIPE 13
#endif

#ifndef SIGTERM
#define SIGTERM 15
#endif

#ifndef EINTR
#define EINTR 4
#endif

#ifndef EIO
#define EIO 5
#endif

#ifndef EBADF
#define EBADF 9
#endif

#ifndef EAGAIN
#define EAGAIN 11
#endif

#ifndef ENOMEM
#define ENOMEM 12
#endif

#ifndef EACCES
#define EACCES 13
#endif

#ifndef EFAULT
#define EFAULT 14
#endif

#ifndef EBUSY
#define EBUSY 16
#endif

#ifndef EEXIST
#define EEXIST 17
#endif

#ifndef EXDEV
#define EXDEV 18
#endif

#ifndef ENODEV
#define ENODEV 19
#endif

#ifndef ENOTDIR
#define ENOTDIR 20
#endif

#ifndef EISDIR
#define EISDIR 21
#endif

#ifndef EINVAL
#define EINVAL 22
#endif

#ifndef ENFILE
#define ENFILE 23
#endif

#ifndef EMFILE
#define EMFILE 24
#endif

#ifndef ENOSPC
#define ENOSPC 28
#endif

#ifndef EROFS
#define EROFS 30
#endif

#ifndef EPIPE
#define EPIPE 32
#endif

#ifndef ERANGE
#define ERANGE 34
#endif

#ifndef ENAMETOOLONG
#define ENAMETOOLONG 63
#endif

#ifndef ENOTEMPTY
#define ENOTEMPTY 66
#endif

#ifndef ENOSYS
#define ENOSYS 78
#endif

#ifndef EOVERFLOW
#define EOVERFLOW 84
#endif

#ifndef EILSEQ
#define EILSEQ 86
#endif

#ifndef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT 94
#endif

#ifndef EOPNOTSUPP
#define EOPNOTSUPP 45
#endif

#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT 47
#endif

#ifndef EADDRINUSE
#define EADDRINUSE 48
#endif

#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL 49
#endif

#ifndef ENETDOWN
#define ENETDOWN 50
#endif

#ifndef ENETUNREACH
#define ENETUNREACH 51
#endif

#ifndef ECONNABORTED
#define ECONNABORTED 53
#endif

#ifndef ECONNRESET
#define ECONNRESET 54
#endif

#ifndef ENOBUFS
#define ENOBUFS 55
#endif

#ifndef ENOTCONN
#define ENOTCONN 57
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT 60
#endif

#ifndef ECONNREFUSED
#define ECONNREFUSED 61
#endif

#ifndef EHOSTUNREACH
#define EHOSTUNREACH 65
#endif

#ifndef EALREADY
#define EALREADY 37
#endif

#ifndef EINPROGRESS
#define EINPROGRESS 36
#endif

#ifndef EPERM
#define EPERM 1
#endif

#ifndef ESRCH
#define ESRCH 3
#endif

#ifndef ENOENT
#define ENOENT 2
#endif

#ifndef ENOTSUP
#define ENOTSUP EOPNOTSUPP
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#define st_mtime st_mtim.tv_sec

#ifndef htonl
#define htonl(v) sceNetHtonl((uint32_t)(v))
#endif

#ifndef htons
#define htons(v) sceNetHtons((uint16_t)(v))
#endif

#ifndef ntohl
#define ntohl(v) sceNetNtohl((uint32_t)(v))
#endif

#ifndef ntohs
#define ntohs(v) sceNetNtohs((uint16_t)(v))
#endif

__BEGIN_DECLS

void ps4_sdk_init(void);

int ps4_close(int fd);
int ps4_socket(int domain, int type, int protocol);
int ps4_connect(int fd, const struct sockaddr *addr, socklen_t len);
int ps4_bind(int fd, const struct sockaddr *addr, socklen_t len);
int ps4_listen(int fd, int backlog);
int ps4_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t ps4_send(int fd, const void *buf, size_t len, int flags);
ssize_t ps4_recv(int fd, void *buf, size_t len, int flags);
int ps4_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
int ps4_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
int ps4_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);
int ps4_shutdown(int fd, int how);
int ps4_fcntl(int fd, int cmd, ...);

unsigned int ps4_sleep(unsigned int seconds);
char *ps4_getenv(const char *name);
int ps4_access(const char *path, int mode);
char *ps4_realpath(const char *path, char *resolved_path);
int ps4_strcasecmp(const char *a, const char *b);
int ps4_strncasecmp(const char *a, const char *b, size_t n);
long long ps4_strtoll(const char *nptr, char **endptr, int base);
int ps4_isalnum(int c);
char *ps4_strtok_r(char *str, const char *delim, char **saveptr);
void *ps4_memchr(const void *s, int c, size_t n);
int ps4_chmod(const char *path, int mode);
int ps4_fsync(int fd);
pid_t ps4_getppid(void);
void ps4_exit(int status) __attribute__((noreturn));
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

__END_DECLS

#if !defined(PS5DRIVE_PS4_COMPAT_IMPL)
#define close ps4_close
#define socket ps4_socket
#define connect ps4_connect
#define bind ps4_bind
#define listen ps4_listen
#define accept ps4_accept
#define send ps4_send
#define recv ps4_recv
#define setsockopt ps4_setsockopt
#define getsockopt ps4_getsockopt
#define getsockname ps4_getsockname
#define shutdown ps4_shutdown
#define fcntl ps4_fcntl
#define sleep ps4_sleep
#define getenv ps4_getenv
#define access ps4_access
#define realpath ps4_realpath
#define strcasecmp ps4_strcasecmp
#define strncasecmp ps4_strncasecmp
#define strtoll ps4_strtoll
#define isalnum ps4_isalnum
#define strtok_r ps4_strtok_r
#define memchr ps4_memchr
#define chmod ps4_chmod
#define fsync ps4_fsync
#define getppid ps4_getppid
#define _exit ps4_exit
#define atexit(fn) (0)
#endif

#endif /* PS5DRIVE_PS4_BUILD */

#endif /* PS5DRIVE_PS4_COMPAT_H */
