#include "server.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PS5DRIVE_REQ_HEADER_MAX 65536
#define PS5DRIVE_RW_CHUNK (1024 * 1024)
#define PS5DRIVE_SOCKET_BUFFER (2 * 1024 * 1024)
#define PS5DRIVE_JSON_INIT_CAP 4096
#define PS5DRIVE_HTTP_TIMEOUT_SEC 30
#define PS5DRIVE_LOG_LINES 256
#define PS5DRIVE_LOG_LINE_MAX 256
#if defined(MSG_NOSIGNAL)
#define PS5DRIVE_SEND_FLAGS MSG_NOSIGNAL
#else
#define PS5DRIVE_SEND_FLAGS 0
#endif

typedef enum listener_kind {
    LISTENER_KIND_WEB = 0,
    LISTENER_KIND_API = 1,
    LISTENER_KIND_DEBUG = 2
} listener_kind_t;

typedef struct server_ctx {
    ps5drive_server_config_t cfg;
    char root_abs[PATH_MAX];
    int active_clients;
    int web_listener_fd;
    int api_listener_fd;
    int debug_listener_fd;
    int debug_enabled;
    char log_lines[PS5DRIVE_LOG_LINES][PS5DRIVE_LOG_LINE_MAX];
    size_t log_next;
    size_t log_count;
    volatile sig_atomic_t *running_flag;
} server_ctx_t;

typedef struct http_request {
    char method[16];
    char target[2048];
    char path[2048];
    char query[4096];
    long long content_length;
    size_t body_offset;
    size_t bytes_read;
    char buffer[PS5DRIVE_REQ_HEADER_MAX];
} http_request_t;

typedef struct strbuf {
    char *data;
    size_t len;
    size_t cap;
} strbuf_t;

static int env_truthy(const char *name) {
    const char *raw = getenv(name);
    if (!raw || !*raw) return 0;
    if (strcmp(raw, "1") == 0) return 1;
    if (strcasecmp(raw, "true") == 0) return 1;
    if (strcasecmp(raw, "yes") == 0) return 1;
    if (strcasecmp(raw, "on") == 0) return 1;
    return 0;
}

static int upload_sync_enabled(void) {
    static int initialized = 0;
    static int enabled = 0;
    if (!initialized) {
        enabled = env_truthy("PS5DRIVE_UPLOAD_SYNC");
        initialized = 1;
    }
    return enabled;
}

static int write_all_fd(int fd, const void *buf, size_t len) {
    const char *ptr = (const char *)buf;
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, ptr + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        written += (size_t)n;
    }
    return 0;
}

static void tune_socket_buffers(int fd) {
    if (fd < 0) return;
    int buf = PS5DRIVE_SOCKET_BUFFER;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
#if defined(TCP_NODELAY)
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
}

static int send_all(int fd, const void *buf, size_t len) {
    const char *ptr = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, ptr + sent, len - sent, PS5DRIVE_SEND_FLAGS);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int send_fmt(int fd, const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    size_t len = (size_t)n;
    if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
    return send_all(fd, tmp, len);
}

static const char *http_reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 411: return "Length Required";
        case 413: return "Payload Too Large";
        case 415: return "Unsupported Media Type";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default: return "Error";
    }
}

static int send_bytes_response(int fd, int status, const char *content_type, const void *data, size_t len) {
    if (!content_type) content_type = "application/octet-stream";
    if (send_fmt(fd,
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 status, http_reason(status), content_type, len) != 0) {
        return -1;
    }
    if (len == 0) return 0;
    return send_all(fd, data, len);
}

static int send_json_response(int fd, int status, const char *json) {
    if (!json) json = "{}";
    return send_bytes_response(fd, status, "application/json; charset=utf-8", json, strlen(json));
}

static int send_json_error(int fd, int status, const char *message) {
    char escaped[512];
    size_t out = 0;
    const char *m = message ? message : "error";
    for (size_t i = 0; m[i] != '\0' && out + 2 < sizeof(escaped); ++i) {
        unsigned char c = (unsigned char)m[i];
        if (c == '"' || c == '\\') {
            escaped[out++] = '\\';
            escaped[out++] = (char)c;
        } else if (c >= 0x20) {
            escaped[out++] = (char)c;
        }
    }
    escaped[out] = '\0';
    char body[640];
    snprintf(body, sizeof(body), "{\"ok\":false,\"error\":\"%s\"}", escaped);
    return send_json_response(fd, status, body);
}

static int send_json_errno_error(int fd, int status, const char *prefix) {
    char msg[512];
    int err = errno;
    const char *base = prefix ? prefix : "operation failed";
    const char *detail = strerror(err);
    snprintf(msg, sizeof(msg), "%s (errno=%d: %s)", base, err, detail ? detail : "unknown");
    return send_json_error(fd, status, msg);
}

static int strbuf_init(strbuf_t *sb, size_t initial_cap) {
    if (!sb) return -1;
    if (initial_cap == 0) initial_cap = PS5DRIVE_JSON_INIT_CAP;
    sb->data = (char *)malloc(initial_cap);
    if (!sb->data) return -1;
    sb->len = 0;
    sb->cap = initial_cap;
    sb->data[0] = '\0';
    return 0;
}

static void strbuf_free(strbuf_t *sb) {
    if (!sb) return;
    free(sb->data);
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
}

static int strbuf_reserve(strbuf_t *sb, size_t needed_extra) {
    if (!sb) return -1;
    if (sb->len + needed_extra + 1 <= sb->cap) return 0;
    size_t new_cap = sb->cap;
    while (sb->len + needed_extra + 1 > new_cap) {
        new_cap = new_cap < (SIZE_MAX / 2) ? new_cap * 2 : SIZE_MAX;
        if (new_cap == SIZE_MAX) break;
    }
    if (new_cap < sb->len + needed_extra + 1) return -1;
    char *next = (char *)realloc(sb->data, new_cap);
    if (!next) return -1;
    sb->data = next;
    sb->cap = new_cap;
    return 0;
}

static int strbuf_append_raw(strbuf_t *sb, const char *src, size_t n) {
    if (!sb || !src) return -1;
    if (strbuf_reserve(sb, n) != 0) return -1;
    memcpy(sb->data + sb->len, src, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
    return 0;
}

static int strbuf_append(strbuf_t *sb, const char *src) {
    if (!src) src = "";
    return strbuf_append_raw(sb, src, strlen(src));
}

static int strbuf_appendf(strbuf_t *sb, const char *fmt, ...) {
    char stack[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n < sizeof(stack)) {
        return strbuf_append_raw(sb, stack, (size_t)n);
    }
    size_t need = (size_t)n + 1;
    char *dyn = (char *)malloc(need);
    if (!dyn) return -1;
    va_start(ap, fmt);
    vsnprintf(dyn, need, fmt, ap);
    va_end(ap);
    int rc = strbuf_append_raw(sb, dyn, (size_t)n);
    free(dyn);
    return rc;
}

static int strbuf_append_json_escaped(strbuf_t *sb, const char *src) {
    if (!src) return strbuf_append(sb, "");
    for (size_t i = 0; src[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '\\':
                if (strbuf_append(sb, "\\\\") != 0) return -1;
                break;
            case '"':
                if (strbuf_append(sb, "\\\"") != 0) return -1;
                break;
            case '\n':
                if (strbuf_append(sb, "\\n") != 0) return -1;
                break;
            case '\r':
                if (strbuf_append(sb, "\\r") != 0) return -1;
                break;
            case '\t':
                if (strbuf_append(sb, "\\t") != 0) return -1;
                break;
            default:
                if (c < 0x20) {
                    if (strbuf_appendf(sb, "\\u%04x", (unsigned)c) != 0) return -1;
                } else {
                    if (strbuf_append_raw(sb, (const char *)&src[i], 1) != 0) return -1;
                }
                break;
        }
    }
    return 0;
}

static const char *listener_kind_name(listener_kind_t kind) {
    switch (kind) {
        case LISTENER_KIND_WEB:
            return "web";
        case LISTENER_KIND_API:
            return "api";
        case LISTENER_KIND_DEBUG:
            return "debug";
        default:
            return "unknown";
    }
}

static void server_log(server_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) return;

    char msg[PS5DRIVE_LOG_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    char line[PS5DRIVE_LOG_LINE_MAX];
    time_t now = time(NULL);
    snprintf(line, sizeof(line), "%ld pid=%d %.200s", (long)now, (int)getpid(), msg);

    snprintf(ctx->log_lines[ctx->log_next], PS5DRIVE_LOG_LINE_MAX, "%s", line);
    ctx->log_next = (ctx->log_next + 1) % PS5DRIVE_LOG_LINES;
    if (ctx->log_count < PS5DRIVE_LOG_LINES) ctx->log_count++;
}

static int build_log_snapshot_text(server_ctx_t *ctx, strbuf_t *out) {
    if (!ctx || !out) return -1;
    size_t count = ctx->log_count;
    size_t start = (count < PS5DRIVE_LOG_LINES) ? 0 : ctx->log_next;
    for (size_t i = 0; i < count; ++i) {
        size_t idx = (start + i) % PS5DRIVE_LOG_LINES;
        if (strbuf_append(out, ctx->log_lines[idx]) != 0 || strbuf_append(out, "\n") != 0) {
            return -1;
        }
    }
    return 0;
}

static int mkdir_recursive(const char *path) {
    if (!path || !*path) return -1;
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) return -1;
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, 0777) != 0 && errno != EEXIST && errno != EISDIR) return -1;
        *p = '/';
    }
    if (mkdir(tmp, 0777) != 0 && errno != EEXIST && errno != EISDIR) return -1;
    return 0;
}

static void split_target(const char *target, char *path_out, size_t path_len, char *query_out, size_t query_len) {
    if (!path_out || path_len == 0 || !query_out || query_len == 0) return;
    path_out[0] = '\0';
    query_out[0] = '\0';
    if (!target || !*target) {
        snprintf(path_out, path_len, "/");
        return;
    }
    const char *q = strchr(target, '?');
    if (!q) {
        snprintf(path_out, path_len, "%s", target);
        return;
    }
    size_t p_len = (size_t)(q - target);
    if (p_len >= path_len) p_len = path_len - 1;
    memcpy(path_out, target, p_len);
    path_out[p_len] = '\0';
    snprintf(query_out, query_len, "%s", q + 1);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int url_decode(const char *src, char *dst, size_t dst_len) {
    if (!src || !dst || dst_len == 0) return -1;
    size_t out = 0;
    for (size_t i = 0; src[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '%') {
            int hi = hex_value(src[i + 1]);
            int lo = hex_value(src[i + 2]);
            if (hi < 0 || lo < 0) return -1;
            c = (unsigned char)((hi << 4) | lo);
            i += 2;
        } else if (c == '+') {
            c = ' ';
        }
        if (out + 1 >= dst_len) return -1;
        dst[out++] = (char)c;
    }
    dst[out] = '\0';
    return 0;
}

static int query_get_param(const char *query, const char *key, char *out, size_t out_len) {
    if (!out || out_len == 0) return -1;
    out[0] = '\0';
    if (!query || !*query || !key || !*key) return -1;

    size_t key_len = strlen(key);
    const char *p = query;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t pair_len = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', pair_len);
        size_t lhs_len = eq ? (size_t)(eq - p) : pair_len;
        if (lhs_len == key_len && strncmp(p, key, key_len) == 0) {
            if (!eq) {
                out[0] = '\0';
                return 0;
            }
            const char *val = eq + 1;
            size_t val_len = pair_len - (size_t)(val - p);
            char enc[4096];
            if (val_len >= sizeof(enc)) return -1;
            memcpy(enc, val, val_len);
            enc[val_len] = '\0';
            return url_decode(enc, out, out_len);
        }
        p += pair_len;
        if (*p == '&') ++p;
    }
    return -1;
}

static int sanitize_virtual_path(const char *input, char *out, size_t out_len) {
    if (!out || out_len == 0) return -1;
    const char *src = (input && *input) ? input : "/";
    char work[PATH_MAX];
    if (*src != '/') {
        if (snprintf(work, sizeof(work), "/%s", src) >= (int)sizeof(work)) return -1;
    } else {
        if (snprintf(work, sizeof(work), "%s", src) >= (int)sizeof(work)) return -1;
    }

    char clean[PATH_MAX];
    size_t used = 0;
    clean[used++] = '/';
    clean[used] = '\0';

    char *save = NULL;
    char *token = strtok_r(work, "/", &save);
    while (token) {
        if (strcmp(token, ".") == 0 || strcmp(token, "") == 0) {
            token = strtok_r(NULL, "/", &save);
            continue;
        }
        if (strcmp(token, "..") == 0) return -1;
        size_t seg_len = strlen(token);
        if (used + (used > 1 ? 1 : 0) + seg_len + 1 > sizeof(clean)) return -1;
        if (used > 1) clean[used++] = '/';
        memcpy(clean + used, token, seg_len);
        used += seg_len;
        clean[used] = '\0';
        token = strtok_r(NULL, "/", &save);
    }

    if (used == 1) clean[1] = '\0';
    if (snprintf(out, out_len, "%s", clean) >= (int)out_len) return -1;
    return 0;
}

static int build_full_path(server_ctx_t *ctx, const char *virtual_path, char *out, size_t out_len) {
    if (!ctx || !virtual_path || !out || out_len == 0) return -1;
    if (strcmp(virtual_path, "/") == 0) {
        if (snprintf(out, out_len, "%s", ctx->root_abs) >= (int)out_len) return -1;
        return 0;
    }
    if (snprintf(out, out_len, "%s%s", ctx->root_abs, virtual_path) >= (int)out_len) return -1;
    return 0;
}

static int ensure_parent_dirs(const char *filepath) {
    if (!filepath) return -1;
    char parent[PATH_MAX];
    if (snprintf(parent, sizeof(parent), "%s", filepath) >= (int)sizeof(parent)) return -1;
    char *slash = strrchr(parent, '/');
    if (!slash) return -1;
    if (slash == parent) return 0;
    *slash = '\0';
    return mkdir_recursive(parent);
}

static int remove_path_recursive(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) return -1;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            char child[PATH_MAX];
            if (snprintf(child, sizeof(child), "%s/%s", path, ent->d_name) >= (int)sizeof(child)) {
                closedir(dir);
                return -1;
            }
            if (remove_path_recursive(child) != 0) {
                closedir(dir);
                return -1;
            }
        }
        closedir(dir);
        return rmdir(path);
    }
    return unlink(path);
}

static int copy_path_recursive(const char *src, const char *dst);

static int copy_regular_file(const char *src, const char *dst, mode_t mode) {
    if (ensure_parent_dirs(dst) != 0) return -1;

    int in = open(src, O_RDONLY);
    if (in < 0) return -1;

    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.copy.%d.%ld", dst, (int)getpid(), (long)time(NULL)) >= (int)sizeof(tmp)) {
        close(in);
        errno = ENAMETOOLONG;
        return -1;
    }

    mode_t file_mode = mode & 0777;
    if (file_mode == 0) file_mode = 0666;
    int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, file_mode);
    if (out < 0) {
        close(in);
        return -1;
    }

    char *buf = (char *)malloc(PS5DRIVE_RW_CHUNK);
    if (!buf) {
        close(in);
        close(out);
        unlink(tmp);
        errno = ENOMEM;
        return -1;
    }

    int rc = 0;
    while (1) {
        ssize_t n = read(in, buf, PS5DRIVE_RW_CHUNK);
        if (n < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }
        if (n == 0) break;
        if (write_all_fd(out, buf, (size_t)n) != 0) {
            rc = -1;
            break;
        }
    }

    free(buf);
    close(in);
    if (upload_sync_enabled()) (void)fsync(out);
    close(out);

    if (rc != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, dst) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int copy_directory_recursive(const char *src, const char *dst) {
    if (mkdir_recursive(dst) != 0) return -1;
    DIR *dir = opendir(src);
    if (!dir) return -1;

    int rc = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char src_child[PATH_MAX];
        char dst_child[PATH_MAX];
        if (snprintf(src_child, sizeof(src_child), "%s/%s", src, ent->d_name) >= (int)sizeof(src_child) ||
            snprintf(dst_child, sizeof(dst_child), "%s/%s", dst, ent->d_name) >= (int)sizeof(dst_child)) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }
        if (copy_path_recursive(src_child, dst_child) != 0) {
            rc = -1;
            break;
        }
    }

    closedir(dir);
    return rc;
}

static int copy_path_recursive(const char *src, const char *dst) {
    struct stat st;
    if (lstat(src, &st) != 0) return -1;
    if (S_ISDIR(st.st_mode)) return copy_directory_recursive(src, dst);
    if (S_ISREG(st.st_mode)) return copy_regular_file(src, dst, st.st_mode);
    errno = ENOTSUP;
    return -1;
}

static int chmod_path_recursive_777(const char *path, size_t *touched) {
    struct stat st;
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    if (lstat(path, &st) != 0) return -1;

    /* Do not follow symlinks to avoid mutating paths outside virtual root. */
    if (S_ISLNK(st.st_mode)) return 0;

    if (chmod(path, 0777) != 0) return -1;
    if (touched) (*touched)++;

    if (!S_ISDIR(st.st_mode)) return 0;

    DIR *dir = opendir(path);
    if (!dir) return -1;

    int rc = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char child[PATH_MAX];
        if (snprintf(child, sizeof(child), "%s/%s", path, ent->d_name) >= (int)sizeof(child)) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }
        if (chmod_path_recursive_777(child, touched) != 0) {
            rc = -1;
            break;
        }
    }

    closedir(dir);
    return rc;
}

static const char *basename_ptr(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    if (!slash) return path;
    return slash[1] ? slash + 1 : slash;
}

static int parse_http_request(int client_fd, http_request_t *req) {
    if (!req) return -1;
    memset(req, 0, sizeof(*req));
    req->content_length = 0;

    size_t used = 0;
    size_t header_end = 0;
    while (used < sizeof(req->buffer) - 1) {
        ssize_t n = recv(client_fd, req->buffer + used, sizeof(req->buffer) - 1 - used, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        used += (size_t)n;
        req->buffer[used] = '\0';
        char *end = strstr(req->buffer, "\r\n\r\n");
        if (end) {
            header_end = (size_t)(end - req->buffer) + 4;
            break;
        }
    }
    if (header_end == 0) return -1;

    req->bytes_read = used;
    req->body_offset = header_end;

    char *line_end = strstr(req->buffer, "\r\n");
    if (!line_end) return -1;
    *line_end = '\0';

    char version[16];
    if (sscanf(req->buffer, "%15s %2047s %15s", req->method, req->target, version) != 3) return -1;
    if (strncmp(version, "HTTP/", 5) != 0) return -1;
    split_target(req->target, req->path, sizeof(req->path), req->query, sizeof(req->query));
    if (req->path[0] == '\0') snprintf(req->path, sizeof(req->path), "/");

    char *cursor = line_end + 2;
    while (cursor < req->buffer + header_end - 2) {
        char *next = strstr(cursor, "\r\n");
        if (!next) break;
        if (next == cursor) break;
        *next = '\0';
        char *colon = strchr(cursor, ':');
        if (colon) {
            *colon = '\0';
            char *name = cursor;
            char *value = colon + 1;
            while (*value == ' ' || *value == '\t') ++value;
            if (strcasecmp(name, "Content-Length") == 0) {
                errno = 0;
                long long cl = strtoll(value, NULL, 10);
                if (errno != 0 || cl < 0) return -1;
                req->content_length = cl;
            }
        }
        cursor = next + 2;
    }
    return 0;
}

static int stream_file_download(int client_fd, const char *path, const char *download_name) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return send_json_error(client_fd, 404, "not found");

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return send_json_error(client_fd, 404, "not a regular file");
    }

    if (send_fmt(client_fd,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/octet-stream\r\n"
                 "Content-Length: %lld\r\n"
                 "Content-Disposition: attachment; filename=\"%s\"\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 (long long)st.st_size,
                 download_name && *download_name ? download_name : "download.bin") != 0) {
        close(fd);
        return -1;
    }

    char *buf = (char *)malloc(PS5DRIVE_RW_CHUNK);
    if (!buf) {
        close(fd);
        return -1;
    }

    int rc = 0;
    while (1) {
        ssize_t n = read(fd, buf, PS5DRIVE_RW_CHUNK);
        if (n < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }
        if (n == 0) break;
        if (send_all(client_fd, buf, (size_t)n) != 0) {
            rc = -1;
            break;
        }
    }

    free(buf);
    close(fd);
    return rc;
}

struct tar_header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};

static void tar_octal(char *dst, size_t len, unsigned long long value) {
    if (!dst || len == 0) return;
    memset(dst, '0', len);
    dst[len - 1] = '\0';
    if (len < 2) return;

    size_t pos = len - 2;
    while (value > 0) {
        dst[pos] = (char)('0' + (value & 7ULL));
        value >>= 3;
        if (pos == 0) break;
        --pos;
    }
}

static int tar_write_header(int out_fd, const char *name, const struct stat *st, char typeflag, unsigned long long file_size) {
    if (!name || !st) return -1;
    if (strlen(name) >= 100) return -1;

    struct tar_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    snprintf(hdr.name, sizeof(hdr.name), "%s", name);
    tar_octal(hdr.mode, sizeof(hdr.mode), (unsigned long long)(st->st_mode & 0777));
    tar_octal(hdr.uid, sizeof(hdr.uid), (unsigned long long)st->st_uid);
    tar_octal(hdr.gid, sizeof(hdr.gid), (unsigned long long)st->st_gid);
    tar_octal(hdr.size, sizeof(hdr.size), file_size);
    tar_octal(hdr.mtime, sizeof(hdr.mtime), (unsigned long long)st->st_mtime);
    memset(hdr.chksum, ' ', sizeof(hdr.chksum));
    hdr.typeflag = typeflag;
    memcpy(hdr.magic, "ustar", 5);
    memcpy(hdr.version, "00", 2);

    unsigned int sum = 0;
    const unsigned char *raw = (const unsigned char *)&hdr;
    for (size_t i = 0; i < sizeof(hdr); ++i) sum += raw[i];
    snprintf(hdr.chksum, sizeof(hdr.chksum), "%06o", sum);
    hdr.chksum[6] = '\0';
    hdr.chksum[7] = ' ';

    return send_all(out_fd, &hdr, sizeof(hdr));
}

static int tar_write_padding(int out_fd, unsigned long long data_len) {
    size_t pad = (size_t)((512 - (data_len % 512)) % 512);
    if (pad == 0) return 0;
    char zeros[512];
    memset(zeros, 0, sizeof(zeros));
    return send_all(out_fd, zeros, pad);
}

static int tar_stream_path(int out_fd, const char *fs_path, const char *tar_path) {
    struct stat st;
    if (lstat(fs_path, &st) != 0) return -1;

    if (S_ISDIR(st.st_mode)) {
        char dir_name[PATH_MAX];
        if (snprintf(dir_name, sizeof(dir_name), "%s/", tar_path) >= (int)sizeof(dir_name)) return -1;
        if (tar_write_header(out_fd, dir_name, &st, '5', 0) != 0) return -1;

        DIR *dir = opendir(fs_path);
        if (!dir) return -1;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            char child_fs[PATH_MAX];
            char child_tar[PATH_MAX];
            if (snprintf(child_fs, sizeof(child_fs), "%s/%s", fs_path, ent->d_name) >= (int)sizeof(child_fs) ||
                snprintf(child_tar, sizeof(child_tar), "%s/%s", tar_path, ent->d_name) >= (int)sizeof(child_tar)) {
                closedir(dir);
                return -1;
            }
            if (tar_stream_path(out_fd, child_fs, child_tar) != 0) {
                closedir(dir);
                return -1;
            }
        }
        closedir(dir);
        return 0;
    }

    if (!S_ISREG(st.st_mode)) return 0;
    if (tar_write_header(out_fd, tar_path, &st, '0', (unsigned long long)st.st_size) != 0) return -1;

    int fd = open(fs_path, O_RDONLY);
    if (fd < 0) return -1;
    char *buf = (char *)malloc(PS5DRIVE_RW_CHUNK);
    if (!buf) {
        close(fd);
        return -1;
    }

    unsigned long long total = 0;
    int rc = 0;
    while (1) {
        ssize_t n = read(fd, buf, PS5DRIVE_RW_CHUNK);
        if (n < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }
        if (n == 0) break;
        if (send_all(out_fd, buf, (size_t)n) != 0) {
            rc = -1;
            break;
        }
        total += (unsigned long long)n;
    }

    free(buf);
    close(fd);
    if (rc != 0) return -1;
    return tar_write_padding(out_fd, total);
}

static int stream_directory_tar(int client_fd, const char *dir_path, const char *download_name) {
    struct stat st;
    if (stat(dir_path, &st) != 0 || !S_ISDIR(st.st_mode)) return send_json_error(client_fd, 404, "directory not found");
    if (send_fmt(client_fd,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/x-tar\r\n"
                 "Content-Disposition: attachment; filename=\"%s.tar\"\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 download_name && *download_name ? download_name : "folder") != 0) {
        return -1;
    }

    int rc = tar_stream_path(client_fd, dir_path, download_name && *download_name ? download_name : "folder");
    char zeros[1024];
    memset(zeros, 0, sizeof(zeros));
    if (rc == 0) rc = send_all(client_fd, zeros, sizeof(zeros));
    return rc;
}

static int handle_api_list(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) snprintf(requested, sizeof(requested), "/");

    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0) return send_json_error(client_fd, 400, "invalid path");

    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");

    DIR *dir = opendir(full);
    if (!dir) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "path not found");
        return send_json_error(client_fd, 500, "failed to list path");
    }

    strbuf_t sb;
    if (strbuf_init(&sb, PS5DRIVE_JSON_INIT_CAP) != 0) {
        closedir(dir);
        return send_json_error(client_fd, 500, "oom");
    }

    int ok = 0;
    if (strbuf_append(&sb, "{\"ok\":true,\"path\":\"") != 0 ||
        strbuf_append_json_escaped(&sb, virt) != 0 ||
        strbuf_append(&sb, "\",\"entries\":[") != 0) {
        ok = -1;
    }

    struct dirent *ent;
    int first = 1;
    while (ok == 0 && (ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char child[PATH_MAX];
        if (snprintf(child, sizeof(child), "%s/%s", full, ent->d_name) >= (int)sizeof(child)) continue;
        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (!first) {
            if (strbuf_append(&sb, ",") != 0) {
                ok = -1;
                break;
            }
        }
        first = 0;
        if (strbuf_append(&sb, "{\"name\":\"") != 0 ||
            strbuf_append_json_escaped(&sb, ent->d_name) != 0 ||
            strbuf_appendf(&sb, "\",\"is_dir\":%s,\"size\":%lld,\"mtime\":%lld}",
                           S_ISDIR(st.st_mode) ? "true" : "false",
                           (long long)st.st_size, (long long)st.st_mtime) != 0) {
            ok = -1;
            break;
        }
    }

    if (ok == 0 && strbuf_append(&sb, "]}") != 0) ok = -1;

    closedir(dir);
    int rc = (ok == 0) ? send_json_response(client_fd, 200, sb.data) : send_json_error(client_fd, 500, "oom");
    strbuf_free(&sb);
    return rc;
}

static int handle_api_upload(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    if (req->content_length < 0) return send_json_error(client_fd, 411, "content-length required");

    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) return send_json_error(client_fd, 400, "missing path");

    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0 || strcmp(virt, "/") == 0) {
        return send_json_error(client_fd, 400, "invalid upload path");
    }

    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");
    if (ensure_parent_dirs(full) != 0) return send_json_errno_error(client_fd, 500, "failed to create parent directory");

    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.upload.%d.%ld", full, (int)getpid(), (long)time(NULL)) >= (int)sizeof(tmp)) {
        return send_json_error(client_fd, 400, "path too long");
    }

    int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) return send_json_errno_error(client_fd, 500, "failed to open destination");

    long long remaining = req->content_length;
    size_t have = 0;
    if (req->bytes_read > req->body_offset) have = req->bytes_read - req->body_offset;
    if ((long long)have > remaining) have = (size_t)remaining;

    if (have > 0) {
        if (write_all_fd(out, req->buffer + req->body_offset, have) != 0) {
            close(out);
            unlink(tmp);
            return send_json_error(client_fd, 500, "write failed");
        }
        remaining -= (long long)have;
    }

    char *buf = (char *)malloc(PS5DRIVE_RW_CHUNK);
    if (!buf) {
        close(out);
        unlink(tmp);
        return send_json_error(client_fd, 500, "oom");
    }

    while (remaining > 0) {
        size_t want = remaining > (long long)PS5DRIVE_RW_CHUNK ? PS5DRIVE_RW_CHUNK : (size_t)remaining;
        ssize_t n = recv(client_fd, buf, want, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(out);
            unlink(tmp);
            return send_json_error(client_fd, 500, "read body failed");
        }
        if (n == 0) {
            free(buf);
            close(out);
            unlink(tmp);
            return send_json_error(client_fd, 400, "unexpected end of body");
        }
        if (write_all_fd(out, buf, (size_t)n) != 0) {
            free(buf);
            close(out);
            unlink(tmp);
            return send_json_error(client_fd, 500, "write failed");
        }
        remaining -= (long long)n;
    }

    free(buf);
    if (upload_sync_enabled()) (void)fsync(out);
    close(out);

    if (rename(tmp, full) != 0) {
        unlink(tmp);
        return send_json_errno_error(client_fd, 500, "rename failed");
    }

    char body[PATH_MAX + 128];
    snprintf(body, sizeof(body), "{\"ok\":true,\"path\":\"%s\",\"bytes\":%lld}", virt, req->content_length);
    return send_json_response(client_fd, 200, body);
}

static int handle_api_download(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) return send_json_error(client_fd, 400, "missing path");
    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0 || strcmp(virt, "/") == 0) return send_json_error(client_fd, 400, "invalid path");

    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");
    return stream_file_download(client_fd, full, basename_ptr(virt));
}

static int handle_api_download_folder(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) return send_json_error(client_fd, 400, "missing path");
    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0 || strcmp(virt, "/") == 0) return send_json_error(client_fd, 400, "invalid path");

    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");
    return stream_directory_tar(client_fd, full, basename_ptr(virt));
}

static int handle_api_mkdir(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) return send_json_error(client_fd, 400, "missing path");
    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0 || strcmp(virt, "/") == 0) return send_json_error(client_fd, 400, "invalid path");
    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");
    if (mkdir_recursive(full) != 0) return send_json_errno_error(client_fd, 500, "mkdir failed");
    return send_json_response(client_fd, 200, "{\"ok\":true}");
}

static int handle_api_stat(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) return send_json_error(client_fd, 400, "missing path");
    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0) return send_json_error(client_fd, 400, "invalid path");
    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");

    struct stat st;
    if (lstat(full, &st) != 0) {
        if (errno == ENOENT) {
            strbuf_t sb;
            if (strbuf_init(&sb, 256) != 0) return send_json_error(client_fd, 500, "oom");
            int rc = 0;
            rc |= strbuf_append(&sb, "{\"ok\":true,\"path\":\"");
            rc |= strbuf_append_json_escaped(&sb, virt);
            rc |= strbuf_append(&sb, "\",\"exists\":false}");
            if (rc != 0) {
                strbuf_free(&sb);
                return send_json_error(client_fd, 500, "oom");
            }
            rc = send_json_response(client_fd, 200, sb.data);
            strbuf_free(&sb);
            return rc;
        }
        return send_json_errno_error(client_fd, 500, "stat failed");
    }

    strbuf_t sb;
    if (strbuf_init(&sb, 256) != 0) return send_json_error(client_fd, 500, "oom");
    int rc = 0;
    rc |= strbuf_append(&sb, "{\"ok\":true,\"path\":\"");
    rc |= strbuf_append_json_escaped(&sb, virt);
    rc |= strbuf_appendf(&sb, "\",\"exists\":true,\"is_dir\":%s,\"size\":%lld,\"mtime\":%lld,\"mode\":%u}",
                         S_ISDIR(st.st_mode) ? "true" : "false",
                         (long long)st.st_size,
                         (long long)st.st_mtime,
                         (unsigned)(st.st_mode & 07777));
    if (rc != 0) {
        strbuf_free(&sb);
        return send_json_error(client_fd, 500, "oom");
    }
    rc = send_json_response(client_fd, 200, sb.data);
    strbuf_free(&sb);
    return rc;
}

static int handle_api_move(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char src_req[PATH_MAX];
    char dst_req[PATH_MAX];
    if (query_get_param(req->query, "src", src_req, sizeof(src_req)) != 0 ||
        query_get_param(req->query, "dst", dst_req, sizeof(dst_req)) != 0) {
        return send_json_error(client_fd, 400, "missing src/dst");
    }

    char src_virt[PATH_MAX];
    char dst_virt[PATH_MAX];
    if (sanitize_virtual_path(src_req, src_virt, sizeof(src_virt)) != 0 ||
        sanitize_virtual_path(dst_req, dst_virt, sizeof(dst_virt)) != 0 ||
        strcmp(src_virt, "/") == 0 || strcmp(dst_virt, "/") == 0) {
        return send_json_error(client_fd, 400, "invalid src/dst");
    }

    char src_full[PATH_MAX];
    char dst_full[PATH_MAX];
    if (build_full_path(ctx, src_virt, src_full, sizeof(src_full)) != 0 ||
        build_full_path(ctx, dst_virt, dst_full, sizeof(dst_full)) != 0) {
        return send_json_error(client_fd, 400, "path too long");
    }

    struct stat src_st;
    if (lstat(src_full, &src_st) != 0) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "source not found");
        return send_json_errno_error(client_fd, 500, "failed to stat source");
    }

    char final_dst[PATH_MAX];
    if (snprintf(final_dst, sizeof(final_dst), "%s", dst_full) >= (int)sizeof(final_dst)) {
        return send_json_error(client_fd, 400, "path too long");
    }

    struct stat dst_st;
    if (lstat(dst_full, &dst_st) == 0 && S_ISDIR(dst_st.st_mode)) {
        const char *name = basename_ptr(src_virt);
        if (!name || !*name || strcmp(name, "/") == 0) return send_json_error(client_fd, 400, "invalid source name");
        if (snprintf(final_dst, sizeof(final_dst), "%s/%s", dst_full, name) >= (int)sizeof(final_dst)) {
            return send_json_error(client_fd, 400, "path too long");
        }
    } else if (errno != ENOENT) {
        return send_json_errno_error(client_fd, 500, "failed to stat destination");
    }

    if (ensure_parent_dirs(final_dst) != 0) return send_json_errno_error(client_fd, 500, "failed to create destination dir");
    if (rename(src_full, final_dst) != 0) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "source not found");
        if (errno == EEXIST || errno == ENOTEMPTY) return send_json_error(client_fd, 409, "destination already exists");
        return send_json_errno_error(client_fd, 500, "move failed");
    }
    return send_json_response(client_fd, 200, "{\"ok\":true}");
}

static int handle_api_copy(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char src_req[PATH_MAX];
    char dst_req[PATH_MAX];
    if (query_get_param(req->query, "src", src_req, sizeof(src_req)) != 0 ||
        query_get_param(req->query, "dst", dst_req, sizeof(dst_req)) != 0) {
        return send_json_error(client_fd, 400, "missing src/dst");
    }

    char src_virt[PATH_MAX];
    char dst_virt[PATH_MAX];
    if (sanitize_virtual_path(src_req, src_virt, sizeof(src_virt)) != 0 ||
        sanitize_virtual_path(dst_req, dst_virt, sizeof(dst_virt)) != 0 ||
        strcmp(src_virt, "/") == 0 || strcmp(dst_virt, "/") == 0) {
        return send_json_error(client_fd, 400, "invalid src/dst");
    }

    char src_full[PATH_MAX];
    char dst_full[PATH_MAX];
    if (build_full_path(ctx, src_virt, src_full, sizeof(src_full)) != 0 ||
        build_full_path(ctx, dst_virt, dst_full, sizeof(dst_full)) != 0) {
        return send_json_error(client_fd, 400, "path too long");
    }

    struct stat src_st;
    if (lstat(src_full, &src_st) != 0) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "source not found");
        return send_json_errno_error(client_fd, 500, "failed to stat source");
    }

    char final_dst[PATH_MAX];
    if (snprintf(final_dst, sizeof(final_dst), "%s", dst_full) >= (int)sizeof(final_dst)) {
        return send_json_error(client_fd, 400, "path too long");
    }

    struct stat dst_st;
    if (lstat(dst_full, &dst_st) == 0 && S_ISDIR(dst_st.st_mode)) {
        const char *name = basename_ptr(src_virt);
        if (!name || !*name || strcmp(name, "/") == 0) return send_json_error(client_fd, 400, "invalid source name");
        if (snprintf(final_dst, sizeof(final_dst), "%s/%s", dst_full, name) >= (int)sizeof(final_dst)) {
            return send_json_error(client_fd, 400, "path too long");
        }
    } else if (errno != ENOENT) {
        return send_json_errno_error(client_fd, 500, "failed to stat destination");
    }

    if (strcmp(src_full, final_dst) == 0) return send_json_error(client_fd, 400, "source and destination are the same");
    if (S_ISDIR(src_st.st_mode)) {
        size_t src_len = strlen(src_full);
        if (strncmp(final_dst, src_full, src_len) == 0 &&
            (final_dst[src_len] == '/' || final_dst[src_len] == '\0')) {
            return send_json_error(client_fd, 400, "cannot copy a directory into itself");
        }
    }

    if (copy_path_recursive(src_full, final_dst) != 0) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "source not found");
        return send_json_errno_error(client_fd, 500, "copy failed");
    }
    return send_json_response(client_fd, 200, "{\"ok\":true}");
}

static int handle_api_chmod777(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) return send_json_error(client_fd, 400, "missing path");
    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0 || strcmp(virt, "/") == 0) return send_json_error(client_fd, 400, "invalid path");
    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");

    size_t touched = 0;
    if (chmod_path_recursive_777(full, &touched) != 0) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "path not found");
        return send_json_errno_error(client_fd, 500, "chmod failed");
    }

    char body[256];
    snprintf(body, sizeof(body), "{\"ok\":true,\"touched\":%zu}", touched);
    return send_json_response(client_fd, 200, body);
}

static int handle_api_delete(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) return send_json_error(client_fd, 400, "missing path");
    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0 || strcmp(virt, "/") == 0) {
        return send_json_error(client_fd, 400, "invalid path");
    }
    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");
    if (remove_path_recursive(full) != 0) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "not found");
        return send_json_errno_error(client_fd, 500, "delete failed");
    }
    return send_json_response(client_fd, 200, "{\"ok\":true}");
}

static int handle_api_health(server_ctx_t *ctx, int client_fd) {
    strbuf_t sb;
    if (strbuf_init(&sb, 256) != 0) return send_json_error(client_fd, 500, "oom");
    int rc = 0;
    rc |= strbuf_appendf(&sb, "{\"ok\":true,\"pid\":%d,\"version\":\"", (int)getpid());
    rc |= strbuf_append_json_escaped(&sb, ctx->cfg.version ? ctx->cfg.version : "dev");
    rc |= strbuf_append(&sb, "\",\"root\":\"");
    rc |= strbuf_append_json_escaped(&sb, ctx->root_abs);
    rc |= strbuf_appendf(&sb, "\",\"web_port\":%d,\"api_port\":%d,\"debug_port\":%d,\"debug_enabled\":%s,\"active_clients\":%d}",
                         ctx->cfg.web_port, ctx->cfg.api_port, ctx->cfg.debug_port,
                         ctx->debug_enabled ? "true" : "false",
                         ctx->active_clients);
    if (rc != 0) {
        strbuf_free(&sb);
        return send_json_error(client_fd, 500, "oom");
    }
    rc = send_json_response(client_fd, 200, sb.data);
    strbuf_free(&sb);
    return rc;
}

static int handle_api_stop(server_ctx_t *ctx, int client_fd) {
    int rc = send_json_response(client_fd, 200, "{\"ok\":true,\"stopping\":true}");
    if (ctx && ctx->running_flag) *(ctx->running_flag) = 0;
    pid_t parent = getppid();
    if (parent > 1) (void)kill(parent, SIGTERM);
    return rc;
}

static int serve_web_index(server_ctx_t *ctx, int client_fd) {
    strbuf_t html;
    if (strbuf_init(&html, 16384) != 0) return send_json_error(client_fd, 500, "oom");

    int rc = 0;
    rc |= strbuf_append(&html, "<!doctype html><html><head><meta charset=\"utf-8\"><title>PS5Drive</title>"
                              "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                              "<style>"
                              ":root{--sloth-bg:#f4f7fc;--sloth-bg2:#ffffff;--sloth-card:#ffffff;--sloth-line:#d9e2f0;--sloth-ink:#0f172a;"
                              "--sloth-muted:#475569;--sloth-accent:#2563eb;--sloth-accent-2:#1d4ed8;--sloth-danger:#dc2626;--sloth-good:#16a34a;"
                              "--sloth-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--muted:var(--sloth-muted);--panel-bg:#ffffff;"
                              "--panel-soft:#f8fbff;--chip-bg:#eef4ff;--btn-bg:#f8fafc;--btn-border:#cbd5e1;--btn-ink:#0f172a;--btn-hover:#eef2f7;"
                              "--toolbar-a:#ffffff;--toolbar-b:#f7faff;--table-head:#f1f6ff;--table-line:#e6edf7;--row-hover:#f2f7ff;--row-selected:#e8f0ff;"
                              "--log-bg:#f8fbff;--drop-bg:#f8fbff;--drop-over:#eaf2ff;--drop-border:#93b4e8;--kind-bg:#ffffff;--kind-dir-bg:#e9f1ff;--kind-dir-line:#b9cff5;"
                              "--kind-dir-ink:#1d4ed8;--kind-file-bg:#f5f7fa;--input-bg:#ffffff;--ghost-bg:#ffffff;--danger-bg:#fff1f2;--danger-border:#fecdd3;--card-shadow:rgba(15,23,42,.08)}"
                              "body[data-theme='dark']{--sloth-bg:#0b1220;--sloth-bg2:#111827;--sloth-card:#0f172a;--sloth-line:#253247;--sloth-ink:#e5ecf7;"
                              "--sloth-muted:#9fb0c6;--sloth-accent:#3b82f6;--sloth-accent-2:#2563eb;--sloth-danger:#f87171;--sloth-good:#34d399;"
                              "--muted:var(--sloth-muted);--panel-bg:#0f172a;--panel-soft:#111c31;--chip-bg:#182338;--btn-bg:#182338;--btn-border:#31415c;"
                              "--btn-ink:#e5ecf7;--btn-hover:#22314a;--toolbar-a:#111b2f;--toolbar-b:#0f172a;--table-head:#14213a;--table-line:#223149;"
                              "--row-hover:#1b2b44;--row-selected:#223a5f;--log-bg:#0d1525;--drop-bg:#17233a;--drop-over:#223653;--drop-border:#3e5d89;--kind-bg:#162338;"
                              "--kind-dir-bg:#1f3354;--kind-dir-line:#355985;--kind-dir-ink:#bfdbfe;--kind-file-bg:#152033;--input-bg:#121d32;--ghost-bg:#162338;"
                              "--danger-bg:#3c1f29;--danger-border:#7f3044;--card-shadow:rgba(0,0,0,.45)}"
                              "*{box-sizing:border-box}html,body{height:100%}body{margin:0;font-family:ui-rounded,'Trebuchet MS','Segoe UI',sans-serif;color:var(--sloth-ink);"
                              "background:linear-gradient(180deg,var(--sloth-bg),var(--sloth-bg2));min-height:100dvh;overflow:hidden}"
                              ".shell,.sloth-shell{width:100%;max-width:none;min-height:100dvh;margin:0;padding:clamp(.55rem,1.4vw,1rem);display:grid;gap:clamp(.55rem,1.2vw,1rem)}"
                              ".card,.sloth-card{background:var(--panel-bg);border:1px solid var(--sloth-line);border-radius:18px;box-shadow:0 10px 26px var(--card-shadow);overflow:hidden}"
                              ".top,.sloth-top{padding:1rem;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:.75rem}"
                              ".top-left,.sloth-top-left{display:grid;gap:.2rem}"
                              ".top-right,.sloth-top-right{display:grid;gap:.45rem;justify-items:end;align-items:end}"
                              ".header-actions,.sloth-header-actions{display:flex;gap:.45rem;flex-wrap:wrap;justify-content:flex-end}"
                              ".brand,.sloth-brand{font-size:1.5rem;font-weight:900;letter-spacing:.4px}"
                              ".brand-sub,.sloth-brand-sub{font-size:.9rem;font-weight:700;color:var(--sloth-muted)}"
                              ".chips,.sloth-chips{display:flex;gap:.5rem;flex-wrap:wrap}"
                              ".chip,.sloth-chip{font-size:.8rem;background:var(--chip-bg);border:1px solid var(--sloth-line);border-radius:999px;padding:.35rem .7rem}"
                              ".grid,.sloth-grid{display:grid;grid-template-columns:minmax(260px,340px) minmax(0,1fr) minmax(260px,340px);gap:clamp(.55rem,1.2vw,1rem);min-height:0;height:calc(100dvh - 96px)}.panel,.sloth-panel{padding:1rem;overflow:auto}"
                              ".table-card,.sloth-table-card,.log-card,.sloth-log-card{display:flex;flex-direction:column;min-height:0}"
                              ".section,.sloth-section{padding:1rem;border:1px solid var(--sloth-line);border-radius:12px;background:var(--panel-soft)}"
                              ".section h3,.sloth-section h3{margin:.1rem 0 .6rem 0;font-size:.95rem}"
                              ".stack,.sloth-stack{display:grid;gap:.5rem}.row,.sloth-row{display:flex;gap:.5rem;flex-wrap:wrap}.mono{font-family:var(--sloth-mono)}"
                              "input{min-width:0;width:100%;padding:.58rem .68rem;min-height:40px;border:1px solid var(--sloth-line);border-radius:10px;background:var(--input-bg);color:var(--sloth-ink)}"
                              "button{border:1px solid var(--btn-border);background:var(--btn-bg);color:var(--btn-ink);padding:.5rem .78rem;min-height:40px;border-radius:10px;cursor:pointer;font-weight:600;touch-action:manipulation}"
                              "button:hover{background:var(--btn-hover)}button:disabled{opacity:.45;cursor:not-allowed}"
                              ".btn-main,.sloth-btn-main{background:var(--sloth-accent);border-color:var(--sloth-accent-2);color:#fff}"
                              ".btn-main:hover,.sloth-btn-main:hover{background:var(--sloth-accent-2)}"
                              ".btn-ghost,.sloth-btn-ghost{background:var(--ghost-bg)}.btn-danger,.sloth-btn-danger{border-color:var(--danger-border);background:var(--danger-bg);color:var(--sloth-danger)}"
                              ".drop,.sloth-drop{border:2px dashed var(--drop-border);background:var(--drop-bg);padding:.72rem;border-radius:12px;color:var(--sloth-muted);font-size:.88rem;text-align:center}"
                              ".drop.dragover,.sloth-drop.dragover{border-color:var(--sloth-accent);background:var(--drop-over);color:var(--btn-ink)}"
                              ".progress,.sloth-progress{display:grid;gap:.3rem}progress{width:100%;height:12px;accent-color:var(--sloth-good)}"
                              ".toolbar,.sloth-toolbar{padding:1rem;display:grid;gap:.6rem;border-bottom:1px solid var(--sloth-line);background:linear-gradient(180deg,var(--toolbar-a),var(--toolbar-b));flex-shrink:0}"
                              ".pathline,.sloth-pathline{display:flex;gap:.5rem;align-items:center}.pathline input,.sloth-pathline input{flex:1}"
                              ".statusline,.sloth-status{display:flex;justify-content:space-between;gap:.5rem;color:var(--sloth-muted);font-size:.9rem;flex-wrap:wrap}"
                              ".tablewrap,.sloth-tablewrap{overflow:auto;flex:1 1 auto;min-height:260px;max-height:none}.table,.sloth-table{width:100%;border-collapse:collapse;font-size:.92rem}"
                              ".table th,.sloth-table th{position:sticky;top:0;background:var(--table-head);border-bottom:1px solid var(--sloth-line);text-align:left;padding:.6rem}"
                              ".table td,.sloth-table td{padding:.55rem;border-bottom:1px solid var(--table-line)}.entry-row{cursor:pointer}"
                              ".entry-row:hover{background:var(--row-hover)}.entry-row.selected{background:var(--row-selected)}"
                              ".name{display:flex;align-items:center;gap:.5rem}"
                              ".kind{display:inline-block;min-width:44px;text-align:center;font-size:.72rem;padding:.2rem .4rem;border-radius:999px;border:1px solid var(--sloth-line);background:var(--kind-bg)}"
                              ".kind.dir{background:var(--kind-dir-bg);border-color:var(--kind-dir-line);color:var(--kind-dir-ink)}.kind.file{background:var(--kind-file-bg)}.mini{padding:.28rem .55rem;font-size:.78rem;border-radius:8px}"
                              ".log-wrap,.sloth-log-wrap{display:flex;flex-direction:column;gap:.6rem;min-height:0;flex:1 1 auto}"
                              ".log,.sloth-log{margin:0;overflow:auto;padding:.72rem;border:1px solid var(--sloth-line);border-radius:10px;background:var(--log-bg);white-space:pre-wrap;font-size:.84rem;min-height:280px;flex:1 1 auto}"
                              ".meta,.sloth-meta{font-size:.84rem;color:var(--sloth-muted)}"
                              ".btn-link,.sloth-link{display:inline-flex;align-items:center;justify-content:center;text-decoration:none}"
                              ".coffee-btn{gap:.35rem;min-height:40px;padding:.5rem .78rem;border:1px solid #e04b4b;border-radius:10px;font-weight:600;"
                              "background:linear-gradient(135deg,#ff6b6b 0%,#ee5a5a 100%);color:#fff;box-shadow:0 2px 8px rgba(255,107,107,.3)}"
                              ".coffee-btn:hover{background:linear-gradient(135deg,#ff5252 0%,#e53935 100%);box-shadow:0 4px 12px rgba(255,107,107,.4)}"
                              ".icon-coffee{display:inline-block;font-size:.95em;line-height:1}"
                              "@media (max-width:1280px){.grid,.sloth-grid{grid-template-columns:minmax(280px,360px) minmax(0,1fr);height:auto}.log-card,.sloth-log-card{grid-column:1 / -1}.log,.sloth-log{min-height:220px;max-height:34vh}}"
                              "@media (max-width:920px){body{overflow:auto}.shell,.sloth-shell{min-height:100dvh;padding:.6rem;gap:.6rem}.top,.sloth-top{padding:.75rem}.top-right,.sloth-top-right{width:100%;justify-items:stretch}.header-actions,.sloth-header-actions{justify-content:flex-start}.header-actions button,.header-actions a,.sloth-header-actions button,.sloth-header-actions a{flex:1 1 calc(50% - .3rem)}.grid,.sloth-grid{grid-template-columns:1fr;height:auto}.panel,.sloth-panel{padding:.75rem;overflow:visible}.toolbar,.sloth-toolbar{padding:.75rem}.pathline,.sloth-pathline{flex-wrap:wrap}.pathline input,.sloth-pathline input{flex:1 1 100%}.pathline button,.sloth-pathline button{flex:1 1 calc(33.33% - .35rem)}.row button,.sloth-row button{flex:1 1 calc(50% - .3rem)}.statusline,.sloth-status{align-items:flex-start;flex-direction:column}.tablewrap,.sloth-tablewrap{max-height:48vh;min-height:220px}.table,.sloth-table{font-size:.86rem}.table th,.sloth-table th,.table td,.sloth-table td{padding:.48rem}.log,.sloth-log{max-height:28vh}}"
                              "@media (max-width:560px){.header-actions button,.header-actions a,.sloth-header-actions button,.sloth-header-actions a,.row button,.sloth-row button,.pathline button,.sloth-pathline button{flex:1 1 100%}.brand,.sloth-brand{font-size:1.25rem}.chip,.sloth-chip{font-size:.74rem}}"
                              "</style></head><body>");
    rc |= strbuf_appendf(&html,
                         "<div class=\"shell sloth-shell\"><div class=\"card sloth-card top sloth-top\">"
                         "<div class=\"top-left sloth-top-left\"><div class=\"brand sloth-brand\">PS5Drive</div>"
                         "<div id=\"versionText\" class=\"brand-sub sloth-brand-sub mono\">v%s</div>"
                         "<div class=\"meta sloth-meta\">Created by PhantomPtr</div></div>"
                         "<div class=\"top-right sloth-top-right\"><div class=\"chips sloth-chips\">"
                         "<div class=\"chip sloth-chip mono\">API Port: %d</div><div class=\"chip sloth-chip mono\">Debug Port: %d</div></div>"
                         "<div class=\"header-actions sloth-header-actions\"><button id=\"themeToggleBtn\" class=\"btn-ghost sloth-btn-ghost\">Dark Mode</button>"
                         "<a class=\"btn-link sloth-link coffee-btn\" href=\"https://ko-fi.com/B0B81S0WUA\" target=\"_blank\" rel=\"noopener noreferrer\"><span class=\"icon-coffee\">♥</span><span>Buy Me a Coffee</span></a>"
                         "<button id=\"stopBtn\" class=\"btn-danger sloth-btn-danger\">Stop PS5Drive</button></div></div></div>",
                         ctx->cfg.version ? ctx->cfg.version : "dev", ctx->cfg.api_port, ctx->cfg.debug_port);
    rc |= strbuf_append(&html,
                        "<div class=\"grid sloth-grid\">"
                        "<div class=\"card sloth-card panel sloth-panel\">"
                        "<div class=\"section sloth-section stack sloth-stack\"><h3>Upload</h3>"
                        "<div class=\"row sloth-row\"><button id=\"pickFilesBtn\" class=\"btn-ghost sloth-btn-ghost\">Browse Files</button>"
                        "<button id=\"pickFolderBtn\" class=\"btn-ghost sloth-btn-ghost\">Browse Folder</button></div>"
                        "<div id=\"dropZone\" class=\"drop sloth-drop\">Drop files/folders here</div>"
                        "<div id=\"queueInfo\" class=\"mono\" style=\"font-size:.85rem;color:var(--muted)\">No selection</div>"
                        "<div class=\"progress sloth-progress\"><progress id=\"uploadProgress\" value=\"0\" max=\"100\"></progress>"
                        "<div id=\"uploadStatus\" class=\"mono\" style=\"font-size:.82rem;color:var(--muted)\">Idle</div></div>"
                        "<div class=\"row sloth-row\"><button id=\"uploadStartBtn\" class=\"btn-main sloth-btn-main\">Upload Selected</button>"
                        "<button id=\"uploadStopBtn\" class=\"btn-ghost sloth-btn-ghost\" disabled>Stop Upload</button></div>"
                        "<input id=\"uploadFiles\" type=\"file\" multiple style=\"display:none\">"
                        "<input id=\"uploadFolder\" type=\"file\" webkitdirectory directory multiple style=\"display:none\">"
                        "</div>"
                        "<div class=\"section sloth-section stack sloth-stack\" style=\"margin-top:.8rem\"><h3>Create Folder</h3>"
                        "<div class=\"row sloth-row\"><input id=\"mkdirInput\" placeholder=\"new-folder\">"
                        "<button id=\"mkdirBtn\">Create</button></div></div>"
                        "<div class=\"section sloth-section stack sloth-stack\" style=\"margin-top:.8rem\"><h3>Selected Item</h3>"
                        "<div id=\"selectionInfo\" class=\"mono\" style=\"font-size:.85rem;color:var(--muted)\">Nothing selected</div>"
                        "<div class=\"row sloth-row\"><button id=\"goSelectedBtn\">Go To</button><button id=\"downloadSelectedBtn\">Download</button>"
                        "<button id=\"deleteSelectedBtn\" class=\"btn-danger sloth-btn-danger\">Delete</button></div>"
                        "<div class=\"row sloth-row\"><input id=\"renameInput\" placeholder=\"new-name (same folder)\">"
                        "<button id=\"renameBtn\">Rename</button></div>"
                        "<div class=\"row sloth-row\"><input id=\"moveInput\" class=\"mono\" placeholder=\"example: /data/ps5drive\">"
                        "<button id=\"moveBtn\">Move To</button><button id=\"copyBtn\">Copy To</button><button id=\"chmodBtn\">CHMOD 777</button></div>"
                        "<div class=\"progress sloth-progress\" style=\"margin-top:.2rem\"><progress id=\"selectedOpProgress\" value=\"0\" max=\"100\"></progress>"
                        "<div id=\"selectedOpStatus\" class=\"mono\" style=\"font-size:.82rem;color:var(--muted)\">Selected action: idle</div></div>"
                        "<div class=\"meta sloth-meta\">Move/Copy tip: use absolute path (example: <span class=\"mono\">/data/ps5drive</span>). If destination is an existing folder, item name is kept.</div>"
                        "</div>"
                        "</div>"
                        "<div class=\"card sloth-card table-card sloth-table-card\">"
                        "<div class=\"toolbar sloth-toolbar\">"
                        "<div class=\"pathline sloth-pathline\"><input id=\"pathInput\" class=\"mono\" value=\"/\">"
                        "<button id=\"refreshBtn\">Refresh</button><button id=\"upBtn\">Up</button><button id=\"rootBtn\">Root</button></div>"
                        "<div class=\"statusline sloth-status\"><div>Current Path: <span id=\"pathLabel\" class=\"mono\">/</span></div>"
                        "<div id=\"countLabel\" class=\"mono\">0 entries</div></div>"
                        "</div>"
                        "<div class=\"tablewrap sloth-tablewrap\"><table class=\"table sloth-table\"><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>MTime</th><th>Action</th></tr></thead><tbody id=\"rows\"></tbody></table></div>"
                        "</div>"
                        "<div class=\"card sloth-card panel sloth-panel log-card sloth-log-card\">"
                        "<div class=\"log-wrap sloth-log-wrap\"><div class=\"row sloth-row\" style=\"justify-content:space-between;align-items:center\">"
                        "<h3 style=\"margin:0\">Activity Log</h3><button id=\"clearLogBtn\" class=\"btn-ghost sloth-btn-ghost\">Clear</button></div>"
                        "<pre id=\"log\" class=\"log sloth-log\"></pre></div>"
                        "</div></div></div>");
    rc |= strbuf_append(&html,
                        "<script>"
                        "const api='';"
                        "const state={path:'/',entries:[],selected:'',queueFiles:[],queueIsFolder:false,uploading:false,cancelUpload:false,currentXhr:null,selectedBusy:false};"
                        "function qs(id){return document.getElementById(id);}"
                        "function detectTheme(){try{return window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}catch(e){return 'light';}}"
                        "function applyTheme(theme){const t=(theme==='dark'||theme==='light')?theme:detectTheme();document.body.setAttribute('data-theme',t);const btn=qs('themeToggleBtn');if(btn)btn.textContent=t==='dark'?'Light Mode':'Dark Mode';try{localStorage.setItem('ps5drive_theme',t);}catch(e){}}"
                        "function initTheme(){let saved='';try{saved=localStorage.getItem('ps5drive_theme')||'';}catch(e){}applyTheme(saved);}"
                        "function toggleTheme(){const cur=document.body.getAttribute('data-theme')==='dark'?'dark':'light';applyTheme(cur==='dark'?'light':'dark');}"
                        "function qp(p){return encodeURIComponent(p);}"
                        "function normPath(p){if(!p)return '/';let n=String(p);if(n[0]!=='/')n='/'+n;n=n.replace(/\\/+/g,'/');if(n.length>1&&n.endsWith('/'))n=n.slice(0,-1);return n||'/';}"
                        "function join(base,name){const b=normPath(base);if(b==='/')return '/'+name;return b.replace(/\\/$/,'')+'/'+name;}"
                        "function basenameOf(p){const n=normPath(p);if(n==='/')return '';const i=n.lastIndexOf('/');return i<0?n:n.slice(i+1);}"
                        "function parentOf(p){const n=normPath(p);if(n==='/')return '/';const i=n.lastIndexOf('/');return i<=0?'/':n.slice(0,i);}"
                        "function cleanRelPath(p){let s=String(p||'');s=s.replace(/\\\\/g,'/');s=s.replace(/^\\/+/, '');s=s.replace(/\\/+/g,'/');return s;}"
                        "function relPathOf(file){if(!file)return '';return cleanRelPath(file.__rel_path||file.webkitRelativePath||file.name||'');}"
                        "async function readAllEntries(reader){return await new Promise((resolve)=>{const out=[];const pump=()=>{reader.readEntries((batch)=>{if(!batch||!batch.length){resolve(out);return;}out.push(...batch);pump();},()=>resolve(out));};pump();});}"
                        "async function filesFromEntry(entry,prefix){if(!entry)return [];if(entry.isFile){return await new Promise((resolve)=>{entry.file((f)=>{try{f.__rel_path=cleanRelPath((prefix||'')+f.name);}catch(e){}resolve([f]);},()=>resolve([]));});}if(entry.isDirectory){const dirPrefix=cleanRelPath((prefix||'')+String(entry.name||'')+'/');const reader=entry.createReader();const children=await readAllEntries(reader);let out=[];for(const child of children){const more=await filesFromEntry(child,dirPrefix);if(more&&more.length)out=out.concat(more);}return out;}return [];}"
                        "async function collectDropFiles(dt){if(!dt)return [];const items=dt.items?[...dt.items]:[];if(items.length){let out=[];for(const it of items){if(!it||it.kind!=='file')continue;const entry=it.webkitGetAsEntry?it.webkitGetAsEntry():null;if(entry){const more=await filesFromEntry(entry,'');if(more&&more.length)out=out.concat(more);continue;}const f=it.getAsFile?it.getAsFile():null;if(f){try{if(!f.__rel_path)f.__rel_path=cleanRelPath(f.name);}catch(e){}out.push(f);}}if(out.length)return out;}const files=dt.files?[...dt.files]:[];for(const f of files){try{if(f&&!f.__rel_path)f.__rel_path=cleanRelPath(f.webkitRelativePath||f.name);}catch(e){}}return files;}"
                        "function selectedEntry(){if(!state.selected)return null;for(const e of state.entries){if(join(state.path,e.name)===state.selected)return e;}return null;}"
                        "function log(msg){const el=qs('log');if(!el)return;const time=new Date().toLocaleTimeString();const line='['+time+'] '+msg;const lines=(el.textContent?el.textContent.split('\\n').filter(Boolean):[]);lines.unshift(line);el.textContent=lines.slice(0,200).join('\\n');}"
                        "async function apiJson(path,opt){const r=await fetch(api+path,opt||{});if(!r.ok){throw new Error(await r.text());}return r.json();}"
                        "async function keepAlive(){try{const h=await apiJson('/api/health');const vc=qs('versionText');if(vc&&h&&h.version)vc.textContent='v'+h.version;}catch(err){}}"
                        "async function stopPayload(){if(!confirm('Stop PS5Drive now? You can reload payload after this.'))return;const btn=qs('stopBtn');if(btn)btn.disabled=true;try{await fetch(api+'/api/stop',{method:'POST'});log('Stop requested. Payload shutting down...');}catch(err){log('Stop requested. Connection closed while shutting down.');}setUploadProgress(0,'Stopping payload...');}"
                        "function setPath(p){state.path=normPath(p||'/');qs('pathInput').value=state.path;qs('pathLabel').textContent=state.path;}"
                        "function formatSize(n){const v=Number(n)||0;const u=['B','KB','MB','GB','TB'];let i=0;let x=v;while(x>=1024&&i<u.length-1){x/=1024;i++;}return (i===0?String(v):x.toFixed(x>=10?1:2))+' '+u[i];}"
                        "function formatRate(bps){const n=Number(bps)||0;if(!n||n<0)return '-';return formatSize(n)+'/s';}"
                        "function formatEta(sec){const s=Math.max(0,Math.ceil(Number(sec)||0));if(!Number.isFinite(s))return '--';if(s<60)return String(s)+'s';const m=Math.floor(s/60);const r=s%60;if(m<60)return String(m)+'m '+String(r)+'s';const h=Math.floor(m/60);const mm=m%60;return String(h)+'h '+String(mm)+'m';}"
                        "function formatTime(sec){const d=new Date((Number(sec)||0)*1000);if(!Number.isFinite(d.getTime()))return '-';return d.toLocaleString();}"
                        "function makeBtn(label,cls,onClick){const b=document.createElement('button');b.textContent=label;b.className='mini '+(cls||'');b.onclick=onClick;return b;}"
                        "function updateSelectionUI(){const info=qs('selectionInfo');const goBtn=qs('goSelectedBtn');const downBtn=qs('downloadSelectedBtn');const delBtn=qs('deleteSelectedBtn');const renBtn=qs('renameBtn');const moveBtn=qs('moveBtn');const copyBtn=qs('copyBtn');const chmodBtn=qs('chmodBtn');const ent=selectedEntry();const busy=!!state.selectedBusy;if(!state.selected||!ent){info.textContent='Nothing selected';goBtn.disabled=true;downBtn.disabled=true;delBtn.disabled=true;renBtn.disabled=true;moveBtn.disabled=true;copyBtn.disabled=true;chmodBtn.disabled=true;return;}info.textContent=state.selected;goBtn.disabled=busy||!ent.is_dir;downBtn.disabled=busy?true:false;delBtn.disabled=busy;renBtn.disabled=busy;moveBtn.disabled=busy;copyBtn.disabled=busy;chmodBtn.disabled=busy;}"
                        "function selectPath(path){state.selected=path||'';updateSelectionUI();renderRows();}"
                        "function renderRows(){const rows=qs('rows');rows.innerHTML='';const frag=document.createDocumentFragment();if(state.path!=='/'){const tr=document.createElement('tr');tr.className='entry-row';const td1=document.createElement('td');td1.className='mono';td1.textContent='..';const td2=document.createElement('td');td2.textContent='dir';const td3=document.createElement('td');td3.textContent='-';const td4=document.createElement('td');td4.textContent='-';const td5=document.createElement('td');td5.appendChild(makeBtn('Go To','',()=>goUp()));tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);tr.appendChild(td4);tr.appendChild(td5);frag.appendChild(tr);}if(state.entries.length===0){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=5;td.style.color='var(--muted)';td.textContent='(empty directory)';tr.appendChild(td);frag.appendChild(tr);}for(const e of state.entries){const full=join(state.path,e.name);const tr=document.createElement('tr');tr.className='entry-row'+(state.selected===full?' selected':'');tr.onclick=()=>selectPath(full);tr.ondblclick=()=>{if(e.is_dir){setPath(full);refreshList();}else{downloadPath(full,false);}};const tdName=document.createElement('td');const nameWrap=document.createElement('div');nameWrap.className='name';const icon=document.createElement('span');icon.className='kind '+(e.is_dir?'dir':'file');icon.textContent=e.is_dir?'DIR':'FILE';const name=document.createElement('span');name.className='mono';name.textContent=e.name;nameWrap.appendChild(icon);nameWrap.appendChild(name);tdName.appendChild(nameWrap);const tdType=document.createElement('td');tdType.textContent=e.is_dir?'dir':'file';const tdSize=document.createElement('td');tdSize.textContent=e.is_dir?'-':formatSize(e.size);const tdMtime=document.createElement('td');tdMtime.textContent=formatTime(e.mtime);const tdAct=document.createElement('td');if(e.is_dir){tdAct.appendChild(makeBtn('Go To','',()=>{setPath(full);refreshList();}));tdAct.appendChild(makeBtn('Download','',()=>downloadPath(full,true)));}else{tdAct.appendChild(makeBtn('Download','',()=>downloadPath(full,false)));}tdAct.appendChild(makeBtn('Delete','btn-danger',()=>deletePath(full)));tr.appendChild(tdName);tr.appendChild(tdType);tr.appendChild(tdSize);tr.appendChild(tdMtime);tr.appendChild(tdAct);frag.appendChild(tr);}rows.appendChild(frag);qs('countLabel').textContent=String(state.entries.length)+' entries';}"
                        "async function refreshList(){try{const reqPath=normPath(qs('pathInput').value||state.path);setPath(reqPath);const d=await apiJson('/api/list?path='+qp(reqPath));const realPath=normPath(d.path||reqPath);setPath(realPath);state.entries=[...(d.entries||[])];state.entries.sort((a,b)=>{if(!!a.is_dir!==!!b.is_dir)return a.is_dir?-1:1;return String(a.name).localeCompare(String(b.name));});state.selected='';updateSelectionUI();renderRows();}catch(err){log('List failed: '+err.message);}}"
                        "function goUp(){const p=normPath(state.path);if(p==='/'||!p)return;setPath(parentOf(p));refreshList();}"
                        "async function mkdirPath(){const name=(qs('mkdirInput').value||'').trim();if(!name){log('Folder name is required');return;}if(name.indexOf('/')>=0){log('Folder name cannot contain /');return;}const p=join(state.path,name);try{await apiJson('/api/mkdir?path='+qp(p),{method:'POST'});qs('mkdirInput').value='';log('Created '+p);refreshList();}catch(err){log('Create folder failed: '+err.message);}}"
                        "async function deletePath(path){if(!path)return;if(!confirm('Delete '+path+' ?'))return;try{await apiJson('/api/delete?path='+qp(path),{method:'DELETE'});log('Deleted '+path);if(state.selected===path)state.selected='';refreshList();}catch(err){log('Delete failed: '+err.message);}}"
                        "function downloadPath(path,isDir){if(!path)return;window.location=api+(isDir?'/api/download-folder?path=':'/api/download?path=')+qp(path);}"
                        "function goSelected(){const ent=selectedEntry();if(!ent||!ent.is_dir)return;setPath(state.selected);refreshList();}"
                        "function downloadSelected(){const ent=selectedEntry();if(!ent)return;downloadPath(state.selected,!!ent.is_dir);}"
                        "function setSelectedOpProgress(percent,msg){const bar=qs('selectedOpProgress');const status=qs('selectedOpStatus');if(bar)bar.value=Math.max(0,Math.min(100,Math.floor(Number(percent)||0)));if(status&&msg!==undefined)status.textContent=msg;}"
                        "function beginSelectedOp(label){state.selectedBusy=true;updateSelectionUI();let pct=6;setSelectedOpProgress(pct,label+'...');const timer=setInterval(()=>{pct=Math.min(92,pct+Math.max(1,Math.floor((92-pct)/5)));setSelectedOpProgress(pct,label+'...');},150);return function finish(ok,msg){clearInterval(timer);state.selectedBusy=false;updateSelectionUI();if(ok){setSelectedOpProgress(100,msg||'Done');}else{setSelectedOpProgress(Math.max(0,pct),msg||'Failed');}};}"
                        "async function renameSelected(){const ent=selectedEntry();if(!ent){log('Select a file or folder first');return;}const name=(qs('renameInput').value||'').trim();if(!name){log('Enter a new name');return;}if(name.indexOf('/')>=0){log('Rename only accepts a name, no /');return;}const src=state.selected;const dst=join(parentOf(src),name);if(src===dst){log('Source and destination are the same');return;}try{await apiJson('/api/move?src='+qp(src)+'&dst='+qp(dst),{method:'POST'});qs('renameInput').value='';state.selected=dst;log('Renamed to '+dst);refreshList();}catch(err){log('Rename failed: '+err.message);}}"
                        "function buildMoveDestination(raw,src){let p=String(raw||'').trim();if(!p)return '';const keepName=/\\/$/.test(p);if(p[0]!=='/')p=join(state.path,p);let dst=normPath(p);if(dst==='/')return '';if(keepName)dst=join(dst,basenameOf(src));return dst;}"
                        "async function moveSelected(){const ent=selectedEntry();if(!ent){log('Select a file or folder first');return;}const raw=(qs('moveInput').value||'').trim();if(!raw){log('Enter a destination path');return;}const src=state.selected;const dst=buildMoveDestination(raw,src);if(!dst){log('Invalid destination path');return;}if(src===dst){log('Source and destination are the same');return;}const finish=beginSelectedOp('Moving');try{await apiJson('/api/move?src='+qp(src)+'&dst='+qp(dst),{method:'POST'});qs('moveInput').value='';state.selected=dst;log('Moved to '+dst);finish(true,'Move completed');refreshList();}catch(err){finish(false,'Move failed');log('Move failed: '+err.message);}}"
                        "async function copySelected(){const ent=selectedEntry();if(!ent){log('Select a file or folder first');return;}const raw=(qs('moveInput').value||'').trim();if(!raw){log('Enter a destination path');return;}const src=state.selected;const dst=buildMoveDestination(raw,src);if(!dst){log('Invalid destination path');return;}if(src===dst){log('Source and destination are the same');return;}const finish=beginSelectedOp('Copying');try{await apiJson('/api/copy?src='+qp(src)+'&dst='+qp(dst),{method:'POST'});log('Copied to '+dst);finish(true,'Copy completed');refreshList();}catch(err){finish(false,'Copy failed');log('Copy failed: '+err.message);}}"
                        "async function chmodSelected(){const ent=selectedEntry();if(!ent){log('Select a file or folder first');return;}const p=state.selected;const ask=ent.is_dir?('Apply CHMOD 777 recursively to\\n'+p+' ?'):('Apply CHMOD 777 to\\n'+p+' ?');if(!confirm(ask))return;const finish=beginSelectedOp('Applying CHMOD 777');try{const r=await apiJson('/api/chmod777?path='+qp(p),{method:'POST'});const touched=(r&&typeof r.touched==='number')?r.touched:0;log('CHMOD 777 applied '+p+' (touched '+touched+')');finish(true,'CHMOD 777 completed');refreshList();}catch(err){finish(false,'CHMOD 777 failed');log('CHMOD failed: '+err.message);}}"
                        "function setUploadProgress(percent,msg){const bar=qs('uploadProgress');const status=qs('uploadStatus');if(bar)bar.value=Math.max(0,Math.min(100,Math.floor(Number(percent)||0)));if(status&&msg!==undefined)status.textContent=msg;}"
                        "function setUploadUIState(){const uploading=!!state.uploading;const start=qs('uploadStartBtn');const stop=qs('uploadStopBtn');const pickFilesBtn=qs('pickFilesBtn');const pickFolderBtn=qs('pickFolderBtn');if(start)start.disabled=uploading||!state.queueFiles.length;if(stop)stop.disabled=!uploading;if(pickFilesBtn)pickFilesBtn.disabled=uploading;if(pickFolderBtn)pickFolderBtn.disabled=uploading;}"
                        "function renderQueueInfo(){const info=qs('queueInfo');if(!info)return;if(!state.queueFiles.length){info.textContent='No selection';setUploadUIState();return;}const total=state.queueFiles.reduce((acc,f)=>acc+(Number(f.size)||0),0);const mode=state.queueIsFolder?'files/folders':'files';info.textContent='Selected '+state.queueFiles.length+' '+mode+' ('+formatSize(total)+')';setUploadUIState();}"
                        "function setQueue(files,isFolder){if(state.uploading){log('Cannot change queue while upload is running');return;}state.queueFiles=[...(files||[])].filter((f)=>f&&typeof f.size==='number'&&relPathOf(f));const hasNested=state.queueFiles.some((f)=>relPathOf(f).indexOf('/')>=0);state.queueIsFolder=!!isFolder||hasNested;renderQueueInfo();setUploadProgress(0,state.queueFiles.length?'Ready':'Idle');}"
                        "function pickFiles(){if(state.uploading){log('Stop current upload first');return;}qs('uploadFiles').click();}"
                        "function pickFolder(){if(state.uploading){log('Stop current upload first');return;}qs('uploadFolder').click();}"
                        "function stopUpload(){if(!state.uploading){log('No active upload');return;}state.cancelUpload=true;const xhr=state.currentXhr;if(xhr){try{xhr.abort();}catch(e){}}setUploadProgress(qs('uploadProgress')?qs('uploadProgress').value:0,'Stopping upload...');log('Stop upload requested');}"
                        "function uploadOne(dest,file,onProgress){return new Promise((resolve,reject)=>{const xhr=new XMLHttpRequest();state.currentXhr=xhr;xhr.open('PUT',api+'/api/upload?path='+qp(dest));xhr.setRequestHeader('Content-Type','application/octet-stream');xhr.upload.onprogress=(ev)=>{if(ev.lengthComputable&&onProgress)onProgress(ev.loaded,ev.total);};xhr.onerror=()=>{if(state.currentXhr===xhr)state.currentXhr=null;reject(new Error('network error'));};xhr.onabort=()=>{if(state.currentXhr===xhr)state.currentXhr=null;reject(new Error('upload canceled'));};xhr.onload=()=>{if(state.currentXhr===xhr)state.currentXhr=null;if(xhr.status>=200&&xhr.status<300)resolve();else reject(new Error(xhr.responseText||('HTTP '+xhr.status)));};xhr.send(file);});}"
                        "async function shouldUploadToPath(dst){const st=await apiJson('/api/stat?path='+qp(dst));if(!st||!st.exists)return true;if(st.is_dir){const ok=confirm('Target exists as folder:\\n'+dst+'\\nOK: skip this item\\nCancel: stop upload');if(ok){log('Skipped existing folder '+dst);return false;}throw new Error('upload canceled');}if(!confirm('Overwrite existing file?\\n'+dst)){log('Skipped existing '+dst);return false;}return true;}"
                        "async function startUpload(){if(state.uploading){log('Upload already running');return;}if(!state.queueFiles.length){log('No files selected. Use Browse Files or Browse Folder.');return;}state.uploading=true;state.cancelUpload=false;setUploadUIState();const files=state.queueFiles.slice();const base=state.path;const totalBytes=files.reduce((acc,f)=>acc+(Number(f.size)||0),0);let doneBytes=0;let uploaded=0;let speedBps=0;let canceled=false;let failed=false;const startTs=Date.now();let lastTs=startTs;let lastBytes=0;setUploadProgress(0,'Uploading 0/'+files.length);for(let i=0;i<files.length;i++){const f=files[i];if(state.cancelUpload){canceled=true;state.queueFiles=files.slice(i);break;}const rel=relPathOf(f);if(!rel)continue;const dst=join(base,rel);let allow=false;try{allow=await shouldUploadToPath(dst);}catch(err){if(state.cancelUpload||/canceled/i.test(String(err&&err.message||''))){canceled=true;state.queueFiles=files.slice(i);break;}failed=true;state.queueFiles=files.slice(i);setUploadProgress((doneBytes/Math.max(totalBytes,1))*100,'Upload failed');log('Pre-check failed '+dst+': '+err.message);break;}if(!allow){doneBytes+=Number(f.size)||0;setUploadProgress((doneBytes/Math.max(totalBytes,1))*100,'Skipped '+rel);continue;}try{await uploadOne(dst,f,(loaded,total)=>{const t=Number(total)||1;const now=Date.now();const doneNow=doneBytes+loaded;const dt=(now-lastTs)/1000;if(dt>=0.2){const inst=(doneNow-lastBytes)/Math.max(dt,0.001);speedBps=speedBps>0?(speedBps*0.7+inst*0.3):inst;lastTs=now;lastBytes=doneNow;}const avgBps=doneNow/Math.max((now-startTs)/1000,0.001);const showBps=speedBps>0?speedBps:avgBps;const remain=Math.max(0,totalBytes-doneNow);const eta=remain/Math.max(avgBps,1);const pct=(doneNow/Math.max(totalBytes,t))*100;setUploadProgress(pct,'Uploading '+(uploaded+1)+'/'+files.length+': '+rel+' | '+formatRate(showBps)+' | ETA '+formatEta(eta));});doneBytes+=Number(f.size)||0;uploaded+=1;const avgDoneBps=doneBytes/Math.max((Date.now()-startTs)/1000,0.001);setUploadProgress((doneBytes/Math.max(totalBytes,1))*100,'Uploaded '+uploaded+'/'+files.length+' | '+formatRate(avgDoneBps));log('Uploaded '+dst);}catch(err){if(state.cancelUpload||/canceled/i.test(String(err&&err.message||''))){canceled=true;state.queueFiles=files.slice(i);break;}failed=true;state.queueFiles=files.slice(i);setUploadProgress((doneBytes/Math.max(totalBytes,1))*100,'Upload failed');log('Upload failed '+dst+': '+err.message);break;}}if(!canceled&&!failed&&uploaded===files.length){state.queueFiles=[];state.queueIsFolder=false;const totalSec=Math.max((Date.now()-startTs)/1000,0.001);setUploadProgress(100,'Done '+uploaded+'/'+files.length+' | Avg '+formatRate(doneBytes/totalSec));}if(canceled){const remainCount=state.queueFiles.length;const pct=(doneBytes/Math.max(totalBytes,1))*100;setUploadProgress(pct,'Upload stopped ('+remainCount+' remaining)');log('Upload stopped. Remaining '+remainCount+' file(s).');}state.uploading=false;state.cancelUpload=false;state.currentXhr=null;qs('uploadFiles').value='';qs('uploadFolder').value='';const hasNested=state.queueFiles.some((f)=>relPathOf(f).indexOf('/')>=0);state.queueIsFolder=hasNested;renderQueueInfo();setUploadUIState();if(uploaded>0)refreshList();}"
                        "async function onDrop(ev){ev.preventDefault();qs('dropZone').classList.remove('dragover');if(state.uploading){log('Stop current upload before adding more files');return;}try{const files=await collectDropFiles(ev.dataTransfer);if(!files.length){log('No files detected from drop.');return;}setQueue(files,false);}catch(err){log('Drop parse failed: '+err.message);}}"
                        "qs('refreshBtn').addEventListener('click',refreshList);qs('upBtn').addEventListener('click',goUp);qs('rootBtn').addEventListener('click',()=>{setPath('/');refreshList();});"
                        "qs('mkdirBtn').addEventListener('click',mkdirPath);qs('deleteSelectedBtn').addEventListener('click',()=>deletePath(state.selected));qs('renameBtn').addEventListener('click',renameSelected);qs('moveBtn').addEventListener('click',moveSelected);qs('copyBtn').addEventListener('click',copySelected);qs('chmodBtn').addEventListener('click',chmodSelected);qs('goSelectedBtn').addEventListener('click',goSelected);qs('downloadSelectedBtn').addEventListener('click',downloadSelected);"
                        "qs('clearLogBtn').addEventListener('click',()=>{const el=qs('log');if(el)el.textContent='';});"
                        "qs('themeToggleBtn').addEventListener('click',toggleTheme);qs('stopBtn').addEventListener('click',stopPayload);"
                        "qs('pickFilesBtn').addEventListener('click',pickFiles);qs('pickFolderBtn').addEventListener('click',pickFolder);qs('uploadStartBtn').addEventListener('click',startUpload);qs('uploadStopBtn').addEventListener('click',stopUpload);"
                        "qs('uploadFiles').addEventListener('change',()=>setQueue(qs('uploadFiles').files,false));"
                        "qs('uploadFolder').addEventListener('change',()=>setQueue(qs('uploadFolder').files,true));"
                        "qs('dropZone').addEventListener('dragover',(ev)=>{ev.preventDefault();if(!state.uploading)qs('dropZone').classList.add('dragover');});"
                        "qs('dropZone').addEventListener('dragleave',()=>qs('dropZone').classList.remove('dragover'));"
                        "qs('dropZone').addEventListener('drop',onDrop);"
                        "qs('pathInput').addEventListener('keydown',(ev)=>{if(ev.key==='Enter'){ev.preventDefault();refreshList();}});"
                        "qs('renameInput').addEventListener('keydown',(ev)=>{if(ev.key==='Enter'){ev.preventDefault();renameSelected();}});"
                        "qs('moveInput').addEventListener('keydown',(ev)=>{if(ev.key==='Enter'){ev.preventDefault();moveSelected();}});"
                        "initTheme();setPath('/');updateSelectionUI();setSelectedOpProgress(0,'Selected action: idle');renderQueueInfo();setUploadUIState();refreshList();keepAlive();setInterval(keepAlive,15000);"
                        "</script></body></html>");
    if (rc != 0) {
        strbuf_free(&html);
        return send_json_error(client_fd, 500, "oom");
    }
    rc = send_bytes_response(client_fd, 200, "text/html; charset=utf-8", html.data, html.len);
    strbuf_free(&html);
    return rc;
}

static int handle_debug_request(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    if (strcmp(req->method, "GET") != 0) return send_json_error(client_fd, 405, "method not allowed");

    if (strcmp(req->path, "/") == 0) {
        const char *msg =
            "ps5drive debug\n"
            "GET /health\n"
            "GET /logs\n";
        return send_bytes_response(client_fd, 200, "text/plain; charset=utf-8", msg, strlen(msg));
    }

    if (strcmp(req->path, "/health") == 0) {
        strbuf_t sb;
        if (strbuf_init(&sb, 256) != 0) return send_json_error(client_fd, 500, "oom");
        int rc = 0;
        rc |= strbuf_appendf(&sb, "{\"ok\":true,\"pid\":%d,\"web_port\":%d,\"api_port\":%d,\"debug_port\":%d,\"debug_enabled\":%s,",
                             (int)getpid(), ctx->cfg.web_port, ctx->cfg.api_port, ctx->cfg.debug_port,
                             ctx->debug_enabled ? "true" : "false");
        rc |= strbuf_appendf(&sb, "\"active_clients\":%d,\"log_count\":%zu}",
                             ctx->active_clients, ctx->log_count);
        if (rc != 0) {
            strbuf_free(&sb);
            return send_json_error(client_fd, 500, "oom");
        }
        rc = send_json_response(client_fd, 200, sb.data);
        strbuf_free(&sb);
        return rc;
    }

    if (strcmp(req->path, "/logs") == 0) {
        strbuf_t sb;
        if (strbuf_init(&sb, 4096) != 0) return send_json_error(client_fd, 500, "oom");
        if (build_log_snapshot_text(ctx, &sb) != 0) {
            strbuf_free(&sb);
            return send_json_error(client_fd, 500, "oom");
        }
        int rc = send_bytes_response(client_fd, 200, "text/plain; charset=utf-8", sb.data, sb.len);
        strbuf_free(&sb);
        return rc;
    }

    return send_json_error(client_fd, 404, "not found");
}

static int handle_api_request(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/health") == 0) return handle_api_health(ctx, client_fd);
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/stop") == 0) return handle_api_stop(ctx, client_fd);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/stat") == 0) return handle_api_stat(ctx, client_fd, req);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/list") == 0) return handle_api_list(ctx, client_fd, req);
    if (strcmp(req->method, "PUT") == 0 && strcmp(req->path, "/api/upload") == 0) return handle_api_upload(ctx, client_fd, req);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/download") == 0) return handle_api_download(ctx, client_fd, req);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/download-folder") == 0) return handle_api_download_folder(ctx, client_fd, req);
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/mkdir") == 0) return handle_api_mkdir(ctx, client_fd, req);
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/move") == 0) return handle_api_move(ctx, client_fd, req);
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/copy") == 0) return handle_api_copy(ctx, client_fd, req);
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/chmod777") == 0) return handle_api_chmod777(ctx, client_fd, req);
    if (strcmp(req->method, "DELETE") == 0 && strcmp(req->path, "/api/delete") == 0) return handle_api_delete(ctx, client_fd, req);

    if (ctx->cfg.enable_test_admin) {
        if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/admin/pid") == 0) {
            char body[64];
            snprintf(body, sizeof(body), "{\"ok\":true,\"pid\":%d}", (int)getpid());
            return send_json_response(client_fd, 200, body);
        }
        if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/admin/exit") == 0) {
            int rc = send_json_response(client_fd, 200, "{\"ok\":true,\"exiting\":true}");
            _exit(17);
            return rc;
        }
    }

    return send_json_error(client_fd, 404, "not found");
}

static int handle_web_request(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    if (strncmp(req->path, "/api/", 5) == 0) {
        return handle_api_request(ctx, client_fd, req);
    }
    if (strcmp(req->method, "GET") == 0 && (strcmp(req->path, "/") == 0 || strcmp(req->path, "/index.html") == 0)) {
        return serve_web_index(ctx, client_fd);
    }
    return send_json_error(client_fd, 404, "not found");
}

static void handle_client_session(server_ctx_t *ctx, int client_fd, listener_kind_t kind) {
    struct timeval tv;
    tv.tv_sec = PS5DRIVE_HTTP_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    tune_socket_buffers(client_fd);
#if defined(SO_NOSIGPIPE)
    int one = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    http_request_t req;
    if (parse_http_request(client_fd, &req) != 0) {
        send_json_error(client_fd, 400, "invalid http request");
    } else {
        server_log(ctx, "%s %s via %s", req.method, req.path, listener_kind_name(kind));
        if (kind == LISTENER_KIND_API) {
            handle_api_request(ctx, client_fd, &req);
        } else if (kind == LISTENER_KIND_WEB) {
            handle_web_request(ctx, client_fd, &req);
        } else {
            handle_debug_request(ctx, client_fd, &req);
        }
    }

    close(client_fd);
    if (ctx->active_clients > 0) ctx->active_clients--;
}

static void send_busy_and_close(int fd) {
    const char *msg =
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 45\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"ok\":false,\"error\":\"too many concurrent clients\"}";
    (void)send_all(fd, msg, strlen(msg));
    close(fd);
}

static void accept_ready_clients(server_ctx_t *ctx, int listener_fd, listener_kind_t kind) {
    if (!ctx || listener_fd < 0) return;
    while (*(ctx->running_flag)) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int client = accept(listener_fd, (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EBADF || errno == EINVAL) break;
            break;
        }

        int cflags = fcntl(client, F_GETFL, 0);
        if (cflags >= 0 && (cflags & O_NONBLOCK)) {
            (void)fcntl(client, F_SETFL, cflags & ~O_NONBLOCK);
        }

        if (ctx->active_clients >= ctx->cfg.max_clients) {
            send_busy_and_close(client);
            continue;
        }
        ctx->active_clients++;
        handle_client_session(ctx, client, kind);
    }
}

static int run_single_thread_loop(server_ctx_t *ctx) {
    if (!ctx) return -1;
    server_log(ctx, "single-thread loop ready");

    while (*(ctx->running_flag)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;

        if (ctx->web_listener_fd >= 0) {
            FD_SET(ctx->web_listener_fd, &rfds);
            if (ctx->web_listener_fd > maxfd) maxfd = ctx->web_listener_fd;
        }
        if (ctx->api_listener_fd >= 0) {
            FD_SET(ctx->api_listener_fd, &rfds);
            if (ctx->api_listener_fd > maxfd) maxfd = ctx->api_listener_fd;
        }
        if (ctx->debug_listener_fd >= 0) {
            FD_SET(ctx->debug_listener_fd, &rfds);
            if (ctx->debug_listener_fd > maxfd) maxfd = ctx->debug_listener_fd;
        }
        if (maxfd < 0) return -1;

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ready = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            usleep(20 * 1000);
            continue;
        }
        if (ready == 0) continue;

        if (ctx->web_listener_fd >= 0 && FD_ISSET(ctx->web_listener_fd, &rfds)) {
            accept_ready_clients(ctx, ctx->web_listener_fd, LISTENER_KIND_WEB);
        }
        if (ctx->api_listener_fd >= 0 && FD_ISSET(ctx->api_listener_fd, &rfds)) {
            accept_ready_clients(ctx, ctx->api_listener_fd, LISTENER_KIND_API);
        }
        if (ctx->debug_listener_fd >= 0 && FD_ISSET(ctx->debug_listener_fd, &rfds)) {
            accept_ready_clients(ctx, ctx->debug_listener_fd, LISTENER_KIND_DEBUG);
        }
    }
    return 0;
}

static int make_listener_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    tune_socket_buffers(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 128) != 0) {
        close(fd);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return fd;
}

int ps5drive_server_run(const ps5drive_server_config_t *cfg, volatile sig_atomic_t *running_flag) {
    if (!cfg || !cfg->root_dir || !running_flag) {
        errno = EINVAL;
        return -1;
    }
    if (cfg->web_port <= 0 || cfg->api_port <= 0 || cfg->debug_port <= 0) {
        errno = EINVAL;
        return -1;
    }
    if (cfg->max_clients <= 0) {
        errno = EINVAL;
        return -1;
    }

    server_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cfg = *cfg;
    ctx.running_flag = running_flag;
    ctx.web_listener_fd = -1;
    ctx.api_listener_fd = -1;
    ctx.debug_listener_fd = -1;
    ctx.debug_enabled = 0;
    ctx.active_clients = 0;
    ctx.log_next = 0;
    ctx.log_count = 0;

    if (!realpath(cfg->root_dir, ctx.root_abs)) return -1;
    server_log(&ctx, "root=%s", ctx.root_abs);

    ctx.web_listener_fd = make_listener_socket(cfg->web_port);
    if (ctx.web_listener_fd < 0) return -1;
    ctx.api_listener_fd = make_listener_socket(cfg->api_port);
    if (ctx.api_listener_fd < 0) {
        close(ctx.web_listener_fd);
        return -1;
    }
    ctx.debug_listener_fd = make_listener_socket(cfg->debug_port);
    if (ctx.debug_listener_fd >= 0) {
        ctx.debug_enabled = 1;
    } else {
        ctx.debug_enabled = 0;
        server_log(&ctx, "debug listener disabled: bind failed on port %d (errno=%d)", cfg->debug_port, errno);
    }

    server_log(&ctx, "server ready web=%d api=%d debug=%d enabled=%d",
               cfg->web_port, cfg->api_port, cfg->debug_port, ctx.debug_enabled);
    int run_rc = run_single_thread_loop(&ctx);

    close(ctx.web_listener_fd);
    close(ctx.api_listener_fd);
    if (ctx.debug_listener_fd >= 0) close(ctx.debug_listener_fd);
    return run_rc;
}
