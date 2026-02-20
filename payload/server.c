#include "server.h"

#if defined(PS5DRIVE_PS4_BUILD)
#include <stdarg.h>
#include <stdint.h>
#include "ps4_compat.h"
#else
#include <arpa/inet.h>
#include <ctype.h>
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
#if defined(__linux__)
#include <sys/statvfs.h>
#else
#include <sys/mount.h>
#endif
#include <time.h>
#include <unistd.h>
#endif

#define PS5DRIVE_REQ_HEADER_MAX 65536
#define PS5DRIVE_RW_CHUNK (1024 * 1024)
#define PS5DRIVE_SOCKET_BUFFER (2 * 1024 * 1024)
#define PS5DRIVE_LIST_DEFAULT_LIMIT 500
#define PS5DRIVE_LIST_MAX_LIMIT 2000
#define PS5DRIVE_JSON_INIT_CAP 4096
#define PS5DRIVE_HTTP_TIMEOUT_SEC 30
#define PS5DRIVE_LOG_LINES 256
#define PS5DRIVE_LOG_LINE_MAX 256
#define PS5DRIVE_CONFIG_MAX_BYTES (64 * 1024)
#define PS5DRIVE_GAMES_SCAN_DEFAULT_DEPTH 5
#define PS5DRIVE_GAMES_SCAN_MAX_DEPTH 16
#define PS5DRIVE_GAMES_SCAN_DEFAULT_MAX_DIRS 8000
#define PS5DRIVE_GAMES_SCAN_MAX_DIRS 50000
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
    char config_path[PATH_MAX];
    int secure_mode;
    char auth_username[128];
    char auth_password[128];
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
    char authorization[1024];
    char reset_user[128];
    char reset_pass[128];
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

typedef struct games_scan_ctx {
    strbuf_t *sb;
    int first;
    size_t scanned_dirs;
    size_t found;
    int max_depth;
    size_t max_dirs;
    int truncated;
} games_scan_ctx_t;

#if defined(PS5DRIVE_PS4_BUILD)
static const char k_logo_light_svg[] =
    "<svg width=\"256\" height=\"60\" viewBox=\"0 0 256 60\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n"
    "  <g stroke=\"#0B1220\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\n"
    "    <!-- Chip body -->\n"
    "    <rect x=\"4\" y=\"10\" width=\"40\" height=\"40\" rx=\"8\"></rect>\n"
    "    <rect x=\"16\" y=\"22\" width=\"16\" height=\"16\" rx=\"2\"></rect>\n"
    "    \n"
    "    <!-- Pins -->\n"
    "    <line x1=\"14\" y1=\"4\" x2=\"14\" y2=\"10\"></line>\n"
    "    <line x1=\"24\" y1=\"4\" x2=\"24\" y2=\"10\"></line>\n"
    "    <line x1=\"34\" y1=\"4\" x2=\"34\" y2=\"10\"></line>\n"
    "\n"
    "    <line x1=\"14\" y1=\"50\" x2=\"14\" y2=\"56\"></line>\n"
    "    <line x1=\"24\" y1=\"50\" x2=\"24\" y2=\"56\"></line>\n"
    "    <line x1=\"34\" y1=\"50\" x2=\"34\" y2=\"56\"></line>\n"
    "\n"
    "    <line x1=\"0\" y1=\"24\" x2=\"4\" y2=\"24\"></line>\n"
    "    <line x1=\"0\" y1=\"34\" x2=\"4\" y2=\"34\"></line>\n"
    "\n"
    "    <line x1=\"44\" y1=\"24\" x2=\"48\" y2=\"24\"></line>\n"
    "    <line x1=\"44\" y1=\"34\" x2=\"48\" y2=\"34\"></line>\n"
    "  </g>\n"
    "\n"
    "  <text x=\"60\" y=\"38\" fill=\"#0B1220\" font-family=\"Inter, Helvetica, Arial, sans-serif\" font-size=\"28\" font-weight=\"600\">\n"
    "    PS4Drive\n"
    "  </text>\n"
    "</svg>\n";

static const char k_logo_dark_svg[] =
    "<svg width=\"256\" height=\"60\" viewBox=\"0 0 256 60\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n"
    "  <g stroke=\"#FFFFFF\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\n"
    "    <!-- Chip body -->\n"
    "    <rect x=\"4\" y=\"10\" width=\"40\" height=\"40\" rx=\"8\"></rect>\n"
    "    <rect x=\"16\" y=\"22\" width=\"16\" height=\"16\" rx=\"2\"></rect>\n"
    "    \n"
    "    <!-- Pins -->\n"
    "    <line x1=\"14\" y1=\"4\" x2=\"14\" y2=\"10\"></line>\n"
    "    <line x1=\"24\" y1=\"4\" x2=\"24\" y2=\"10\"></line>\n"
    "    <line x1=\"34\" y1=\"4\" x2=\"34\" y2=\"10\"></line>\n"
    "\n"
    "    <line x1=\"14\" y1=\"50\" x2=\"14\" y2=\"56\"></line>\n"
    "    <line x1=\"24\" y1=\"50\" x2=\"24\" y2=\"56\"></line>\n"
    "    <line x1=\"34\" y1=\"50\" x2=\"34\" y2=\"56\"></line>\n"
    "\n"
    "    <line x1=\"0\" y1=\"24\" x2=\"4\" y2=\"24\"></line>\n"
    "    <line x1=\"0\" y1=\"34\" x2=\"4\" y2=\"34\"></line>\n"
    "\n"
    "    <line x1=\"44\" y1=\"24\" x2=\"48\" y2=\"24\"></line>\n"
    "    <line x1=\"44\" y1=\"34\" x2=\"48\" y2=\"34\"></line>\n"
    "  </g>\n"
    "\n"
    "  <text x=\"60\" y=\"38\" fill=\"#FFFFFF\" font-family=\"Inter, Helvetica, Arial, sans-serif\" font-size=\"28\" font-weight=\"600\">\n"
    "    PS4Drive\n"
    "  </text>\n"
    "</svg>\n";
#else
static const char k_logo_light_svg[] =
    "<svg width=\"256\" height=\"60\" viewBox=\"0 0 256 60\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n"
    "  <g stroke=\"#0B1220\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\n"
    "    <!-- Chip body -->\n"
    "    <rect x=\"4\" y=\"10\" width=\"40\" height=\"40\" rx=\"8\"></rect>\n"
    "    <rect x=\"16\" y=\"22\" width=\"16\" height=\"16\" rx=\"2\"></rect>\n"
    "    \n"
    "    <!-- Pins -->\n"
    "    <line x1=\"14\" y1=\"4\" x2=\"14\" y2=\"10\"></line>\n"
    "    <line x1=\"24\" y1=\"4\" x2=\"24\" y2=\"10\"></line>\n"
    "    <line x1=\"34\" y1=\"4\" x2=\"34\" y2=\"10\"></line>\n"
    "\n"
    "    <line x1=\"14\" y1=\"50\" x2=\"14\" y2=\"56\"></line>\n"
    "    <line x1=\"24\" y1=\"50\" x2=\"24\" y2=\"56\"></line>\n"
    "    <line x1=\"34\" y1=\"50\" x2=\"34\" y2=\"56\"></line>\n"
    "\n"
    "    <line x1=\"0\" y1=\"24\" x2=\"4\" y2=\"24\"></line>\n"
    "    <line x1=\"0\" y1=\"34\" x2=\"4\" y2=\"34\"></line>\n"
    "\n"
    "    <line x1=\"44\" y1=\"24\" x2=\"48\" y2=\"24\"></line>\n"
    "    <line x1=\"44\" y1=\"34\" x2=\"48\" y2=\"34\"></line>\n"
    "  </g>\n"
    "\n"
    "  <text x=\"60\" y=\"38\" fill=\"#0B1220\" font-family=\"Inter, Helvetica, Arial, sans-serif\" font-size=\"28\" font-weight=\"600\">\n"
    "    PS5Drive\n"
    "  </text>\n"
    "</svg>\n";

static const char k_logo_dark_svg[] =
    "<svg width=\"256\" height=\"60\" viewBox=\"0 0 256 60\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\n"
    "  <g stroke=\"#FFFFFF\" stroke-width=\"3\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\n"
    "    <!-- Chip body -->\n"
    "    <rect x=\"4\" y=\"10\" width=\"40\" height=\"40\" rx=\"8\"></rect>\n"
    "    <rect x=\"16\" y=\"22\" width=\"16\" height=\"16\" rx=\"2\"></rect>\n"
    "    \n"
    "    <!-- Pins -->\n"
    "    <line x1=\"14\" y1=\"4\" x2=\"14\" y2=\"10\"></line>\n"
    "    <line x1=\"24\" y1=\"4\" x2=\"24\" y2=\"10\"></line>\n"
    "    <line x1=\"34\" y1=\"4\" x2=\"34\" y2=\"10\"></line>\n"
    "\n"
    "    <line x1=\"14\" y1=\"50\" x2=\"14\" y2=\"56\"></line>\n"
    "    <line x1=\"24\" y1=\"50\" x2=\"24\" y2=\"56\"></line>\n"
    "    <line x1=\"34\" y1=\"50\" x2=\"34\" y2=\"56\"></line>\n"
    "\n"
    "    <line x1=\"0\" y1=\"24\" x2=\"4\" y2=\"24\"></line>\n"
    "    <line x1=\"0\" y1=\"34\" x2=\"4\" y2=\"34\"></line>\n"
    "\n"
    "    <line x1=\"44\" y1=\"24\" x2=\"48\" y2=\"24\"></line>\n"
    "    <line x1=\"44\" y1=\"34\" x2=\"48\" y2=\"34\"></line>\n"
    "  </g>\n"
    "\n"
    "  <text x=\"60\" y=\"38\" fill=\"#FFFFFF\" font-family=\"Inter, Helvetica, Arial, sans-serif\" font-size=\"28\" font-weight=\"600\">\n"
    "    PS5Drive\n"
    "  </text>\n"
    "</svg>\n";
#endif

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

static char *trim_inplace(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

static void set_security_runtime(server_ctx_t *ctx, int secure_mode, const char *username, const char *password) {
    if (!ctx) return;
    ctx->secure_mode = secure_mode ? 1 : 0;
    snprintf(ctx->auth_username, sizeof(ctx->auth_username), "%s", username ? username : "");
    snprintf(ctx->auth_password, sizeof(ctx->auth_password), "%s", password ? password : "");
}

static int parse_security_config_blob(const char *blob, size_t blob_len,
                                      int *secure_mode_out,
                                      char *user_out, size_t user_len,
                                      char *pass_out, size_t pass_len,
                                      char *err_out, size_t err_len) {
    if (err_out && err_len > 0) err_out[0] = '\0';
    if (!blob || blob_len == 0 || !secure_mode_out || !user_out || !pass_out || user_len == 0 || pass_len == 0) {
        if (err_out && err_len > 0) snprintf(err_out, err_len, "invalid config body");
        return -1;
    }

    char *work = (char *)malloc(blob_len + 1);
    if (!work) {
        if (err_out && err_len > 0) snprintf(err_out, err_len, "out of memory");
        return -1;
    }
    memcpy(work, blob, blob_len);
    work[blob_len] = '\0';

    char mode[32];
    snprintf(mode, sizeof(mode), "%s", "unsecure");
    user_out[0] = '\0';
    pass_out[0] = '\0';

    char *save = NULL;
    for (char *line = strtok_r(work, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *cur = trim_inplace(line);
        size_t cur_len = strlen(cur);
        while (cur_len > 0 && cur[cur_len - 1] == '\r') {
            cur[cur_len - 1] = '\0';
            cur_len--;
        }
        cur = trim_inplace(cur);
        if (*cur == '\0' || *cur == '#' || *cur == ';' || *cur == '[') continue;
        char *eq = strchr(cur, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim_inplace(cur);
        char *val = trim_inplace(eq + 1);
        if (strcasecmp(key, "mode") == 0) {
            snprintf(mode, sizeof(mode), "%s", val);
        } else if (strcasecmp(key, "username") == 0) {
            snprintf(user_out, user_len, "%s", val);
        } else if (strcasecmp(key, "password") == 0) {
            snprintf(pass_out, pass_len, "%s", val);
        }
    }

    int secure_mode = 0;
    if (strcasecmp(mode, "secure") == 0) {
        if (user_out[0] == '\0' || pass_out[0] == '\0') {
            if (err_out && err_len > 0) {
                snprintf(err_out, err_len, "secure mode requires non-empty username and password");
            }
            free(work);
            return -1;
        }
        secure_mode = 1;
    } else if (strcasecmp(mode, "unsecure") == 0 || strcasecmp(mode, "insecure") == 0) {
        secure_mode = 0;
    } else {
        if (err_out && err_len > 0) snprintf(err_out, err_len, "mode must be secure or unsecure");
        free(work);
        return -1;
    }

    *secure_mode_out = secure_mode;
    free(work);
    return 0;
}

static int write_config_blob_file(const char *path, const char *data, size_t data_len) {
    if (!path || !*path || !data) {
        errno = EINVAL;
        return -1;
    }

    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.upload.%d.%ld", path, (int)getpid(), (long)time(NULL)) >= (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) return -1;

    if (data_len > 0 && write_all_fd(fd, data, data_len) != 0) {
        int err = errno;
        close(fd);
        unlink(tmp);
        errno = err;
        return -1;
    }

    if (upload_sync_enabled()) (void)fsync(fd);
    if (close(fd) != 0) {
        int err = errno;
        unlink(tmp);
        errno = err;
        return -1;
    }

    if (rename(tmp, path) != 0) {
        int err = errno;
        unlink(tmp);
        errno = err;
        return -1;
    }
    return 0;
}

static int write_default_config_file(const char *path) {
    if (!path || !*path) return -1;
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fprintf(fp,
            "# PS5Drive persistent config\n"
            "[security]\n"
            "mode=unsecure\n"
            "username=\n"
            "password=\n");
    fclose(fp);
    return 0;
}

static int auth_is_enabled(const server_ctx_t *ctx) {
    if (!ctx) return 0;
    return ctx->secure_mode && ctx->auth_username[0] != '\0' && ctx->auth_password[0] != '\0';
}

static const char *security_mode_name(const server_ctx_t *ctx) {
    return auth_is_enabled(ctx) ? "secure" : "unsecure";
}

static int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int ps5drive_base64_decode(const char *src, unsigned char *out, size_t out_len, size_t *out_written) {
    if (!src || !out || out_len == 0) return -1;
    unsigned int acc = 0;
    int bits = 0;
    size_t written = 0;
    for (size_t i = 0; src[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '=') break;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = base64_value((char)c);
        if (v < 0) return -1;
        acc = (acc << 6) | (unsigned int)v;
        bits += 6;
        while (bits >= 8) {
            bits -= 8;
            if (written >= out_len) return -1;
            out[written++] = (unsigned char)((acc >> bits) & 0xFFU);
        }
    }
    if (out_written) *out_written = written;
    return 0;
}

static int parse_basic_auth(const char *authorization, char *user, size_t user_len, char *pass, size_t pass_len) {
    if (!authorization || !user || !pass || user_len == 0 || pass_len == 0) return -1;
    user[0] = '\0';
    pass[0] = '\0';

    while (*authorization == ' ' || *authorization == '\t') authorization++;
    if (strncasecmp(authorization, "Basic ", 6) != 0) return -1;
    const char *encoded = authorization + 6;
    while (*encoded == ' ' || *encoded == '\t') encoded++;
    if (*encoded == '\0') return -1;

    unsigned char decoded[512];
    size_t decoded_len = 0;
    if (ps5drive_base64_decode(encoded, decoded, sizeof(decoded) - 1, &decoded_len) != 0) return -1;
    decoded[decoded_len] = '\0';

    char *cred = (char *)decoded;
    char *colon = strchr(cred, ':');
    if (!colon) return -1;
    *colon = '\0';
    size_t ulen = strlen(cred);
    size_t plen = strlen(colon + 1);
    if (ulen + 1 > user_len || plen + 1 > pass_len) return -1;
    memcpy(user, cred, ulen + 1);
    memcpy(pass, colon + 1, plen + 1);
    return 0;
}

static int auth_credentials_match(const server_ctx_t *ctx, const char *user, const char *pass) {
    if (!ctx || !user || !pass) return 0;
    return strcmp(user, ctx->auth_username) == 0 && strcmp(pass, ctx->auth_password) == 0;
}

static int authorization_matches(const server_ctx_t *ctx, const char *authorization) {
    if (!auth_is_enabled(ctx)) return 1;
    char user[128];
    char pass[128];
    if (parse_basic_auth(authorization, user, sizeof(user), pass, sizeof(pass)) != 0) return 0;
    return auth_credentials_match(ctx, user, pass);
}

static int send_auth_required(int fd) {
    static const char body[] = "{\"ok\":false,\"error\":\"authentication required\"}";
    if (send_fmt(fd,
                 "HTTP/1.1 401 Unauthorized\r\n"
                 "WWW-Authenticate: Basic realm=\"PS5Drive\"\r\n"
                 "Content-Type: application/json; charset=utf-8\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 strlen(body)) != 0) {
        return -1;
    }
    return send_all(fd, body, strlen(body));
}

static int require_authorized(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    if (!auth_is_enabled(ctx)) return 1;
    if (authorization_matches(ctx, req ? req->authorization : NULL)) return 1;
    (void)send_auth_required(client_fd);
    return 0;
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

    int in = open(src, O_RDONLY, 0);
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

static int path_is_regular_file(const char *path) {
    if (!path || !*path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode) ? 1 : 0;
}

static int dir_has_non_dot_entries(const char *path) {
    if (!path || !*path) return 0;
    DIR *dir = opendir(path);
    if (!dir) return 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        closedir(dir);
        return 1;
    }
    closedir(dir);
    return 0;
}

static int path_is_writable_dir(const char *path) {
    if (!path || !*path) return 0;
    char probe[PATH_MAX];
    long long stamp = (long long)time(NULL);
    if (snprintf(probe, sizeof(probe), "%s/.ps5drive_probe_%d_%lld", path, (int)getpid(), stamp) >= (int)sizeof(probe)) {
        return 0;
    }
    int fd = open(probe, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return 0;
    const char marker[] = "ok";
    (void)write_all_fd(fd, marker, sizeof(marker) - 1);
    close(fd);
    (void)unlink(probe);
    return 1;
}

static void query_storage_space_gb(const char *path, double *free_gb, double *total_gb) {
    if (free_gb) *free_gb = 0.0;
    if (total_gb) *total_gb = 0.0;
    if (!path || !*path) return;

#if defined(PS5DRIVE_PS4_BUILD)
    unsigned long long free_bytes = 0;
    unsigned long long total_bytes = 0;
#elif defined(__linux__)
    struct statvfs vfs;
    if (statvfs(path, &vfs) != 0) return;
    unsigned long long free_bytes = (unsigned long long)vfs.f_bavail * (unsigned long long)vfs.f_frsize;
    unsigned long long total_bytes = (unsigned long long)vfs.f_blocks * (unsigned long long)vfs.f_frsize;
#else
    struct statfs vfs;
    if (statfs(path, &vfs) != 0) return;
    unsigned long long free_bytes = (unsigned long long)vfs.f_bavail * (unsigned long long)vfs.f_bsize;
    unsigned long long total_bytes = (unsigned long long)vfs.f_blocks * (unsigned long long)vfs.f_bsize;
#endif

    if (free_gb) *free_gb = (double)free_bytes / (1024.0 * 1024.0 * 1024.0);
    if (total_gb) *total_gb = (double)total_bytes / (1024.0 * 1024.0 * 1024.0);
}

static const char *mime_type_from_path(const char *path) {
    if (!path) return "application/octet-stream";
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcasecmp(dot, ".png") == 0) return "image/png";
    if (strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcasecmp(dot, ".webp") == 0) return "image/webp";
    return "application/octet-stream";
}

static int find_game_cover_file(const char *dir_full, char *out_path, size_t out_len) {
    if (!dir_full || !*dir_full) return 0;
    const char *candidates[] = {
        "sce_sys/icon0.png",
        "sce_sys/icon0.jpg",
        "sce_sys/icon0.jpeg",
        "sce_sys/icon0.webp",
        "icon0.png",
        "icon0.jpg",
        "icon0.jpeg",
        "icon0.webp",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        char full[PATH_MAX];
        if (snprintf(full, sizeof(full), "%s/%s", dir_full, candidates[i]) >= (int)sizeof(full)) continue;
        if (!path_is_regular_file(full)) continue;
        if (out_path && out_len > 0) snprintf(out_path, out_len, "%s", full);
        return 1;
    }
    return 0;
}

static int dir_has_param_sfo(const char *dir_full) {
    if (!dir_full || !*dir_full) return 0;
    char p1[PATH_MAX];
    char p2[PATH_MAX];
    if (snprintf(p1, sizeof(p1), "%s/param.sfo", dir_full) < (int)sizeof(p1) && path_is_regular_file(p1)) {
        return 1;
    }
    if (snprintf(p2, sizeof(p2), "%s/sce_sys/param.sfo", dir_full) < (int)sizeof(p2) && path_is_regular_file(p2)) {
        return 1;
    }
    return 0;
}

static int detect_game_title_id(const char *name, char *title_id, size_t title_id_len, char *platform, size_t platform_len) {
    if (!name || !*name) return 0;

    char upper[64];
    size_t used = 0;
    for (size_t i = 0; name[i] != '\0' && used + 1 < sizeof(upper); ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c)) break;
        upper[used++] = (char)toupper(c);
    }
    upper[used] = '\0';
    if (used < 8) return 0;

    const char *detected_platform = NULL;
    if (strncmp(upper, "CUSA", 4) == 0) {
        detected_platform = "PS4";
    } else if (strncmp(upper, "PPSA", 4) == 0 || strncmp(upper, "PPXA", 4) == 0) {
        detected_platform = "PS5";
    } else if (strncmp(upper, "PCAS", 4) == 0 || strncmp(upper, "PCJS", 4) == 0) {
        detected_platform = "PS4";
    } else {
        return 0;
    }

    if (title_id && title_id_len > 0) snprintf(title_id, title_id_len, "%s", upper);
    if (platform && platform_len > 0) snprintf(platform, platform_len, "%s", detected_platform);
    return 1;
}

static int append_game_scan_entry(games_scan_ctx_t *scan,
                                  const char *virt_path,
                                  const char *name,
                                  const char *title_id,
                                  const char *platform,
                                  int has_param_sfo,
                                  int has_cover) {
    if (!scan || !scan->sb) return -1;
    int rc = 0;
    if (!scan->first) rc |= strbuf_append(scan->sb, ",");
    scan->first = 0;
    rc |= strbuf_append(scan->sb, "{\"path\":\"");
    rc |= strbuf_append_json_escaped(scan->sb, virt_path ? virt_path : "/");
    rc |= strbuf_append(scan->sb, "\",\"name\":\"");
    rc |= strbuf_append_json_escaped(scan->sb, name ? name : "");
    rc |= strbuf_append(scan->sb, "\",\"title_id\":\"");
    rc |= strbuf_append_json_escaped(scan->sb, title_id ? title_id : "");
    rc |= strbuf_append(scan->sb, "\",\"platform\":\"");
    rc |= strbuf_append_json_escaped(scan->sb, platform ? platform : "");
    rc |= strbuf_appendf(scan->sb, "\",\"has_param_sfo\":%s,\"has_cover\":%s}",
                         has_param_sfo ? "true" : "false",
                         has_cover ? "true" : "false");
    if (rc != 0) return -1;
    scan->found++;
    return 0;
}

static int scan_games_recursive(const char *virt_dir, const char *full_dir, int depth, games_scan_ctx_t *scan) {
    if (!virt_dir || !full_dir || !scan) return -1;
    if (scan->truncated) return 0;
    if (depth > scan->max_depth) return 0;

    DIR *dir = opendir(full_dir);
    if (!dir) return 0;

    int rc = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char child_full[PATH_MAX];
        char child_virt[PATH_MAX];
        if (snprintf(child_full, sizeof(child_full), "%s/%s", full_dir, ent->d_name) >= (int)sizeof(child_full) ||
            snprintf(child_virt, sizeof(child_virt), "%s/%s",
                     strcmp(virt_dir, "/") == 0 ? "" : virt_dir, ent->d_name) >= (int)sizeof(child_virt)) {
            continue;
        }

        struct stat st;
        if (lstat(child_full, &st) != 0) continue;
        if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) continue;

        scan->scanned_dirs++;
        if (scan->scanned_dirs > scan->max_dirs) {
            scan->truncated = 1;
            break;
        }

        char title_id[64];
        char platform[16];
        title_id[0] = '\0';
        platform[0] = '\0';
        int is_sce_sys = (strcasecmp(ent->d_name, "sce_sys") == 0);
        int is_title_dir = detect_game_title_id(ent->d_name, title_id, sizeof(title_id), platform, sizeof(platform));
        int has_param_sfo = dir_has_param_sfo(child_full);
        int has_cover = find_game_cover_file(child_full, NULL, 0);
        if (!is_sce_sys && (is_title_dir || has_param_sfo)) {
            if (append_game_scan_entry(scan, child_virt, ent->d_name, title_id, platform, has_param_sfo, has_cover) != 0) {
                rc = -1;
                break;
            }
        }

        if (depth < scan->max_depth) {
            if (scan_games_recursive(child_virt, child_full, depth + 1, scan) != 0) {
                rc = -1;
                break;
            }
            if (scan->truncated) break;
        }
    }

    closedir(dir);
    return rc;
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
            } else if (strcasecmp(name, "Authorization") == 0) {
                snprintf(req->authorization, sizeof(req->authorization), "%s", value);
            } else if (strcasecmp(name, "X-PS5Drive-Reset-User") == 0) {
                snprintf(req->reset_user, sizeof(req->reset_user), "%s", value);
            } else if (strcasecmp(name, "X-PS5Drive-Reset-Pass") == 0) {
                snprintf(req->reset_pass, sizeof(req->reset_pass), "%s", value);
            }
        }
        cursor = next + 2;
    }
    return 0;
}

static int stream_file_download(int client_fd, const char *path, const char *download_name) {
    int fd = open(path, O_RDONLY, 0);
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

static int stream_file_inline(int client_fd, const char *path, const char *content_type) {
    int fd = open(path, O_RDONLY, 0);
    if (fd < 0) return send_json_error(client_fd, 404, "not found");

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return send_json_error(client_fd, 404, "not a regular file");
    }

    if (send_fmt(client_fd,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %lld\r\n"
                 "Cache-Control: no-store\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 content_type ? content_type : "application/octet-stream",
                 (long long)st.st_size) != 0) {
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

    int fd = open(fs_path, O_RDONLY, 0);
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

    int limit = PS5DRIVE_LIST_DEFAULT_LIMIT;
    long long offset = 0;

    char limit_raw[64];
    if (query_get_param(req->query, "limit", limit_raw, sizeof(limit_raw)) == 0 && limit_raw[0] != '\0') {
        char *end = NULL;
        errno = 0;
        long parsed = strtol(limit_raw, &end, 10);
        if (errno != 0 || !end || *end != '\0' || parsed <= 0 || parsed > PS5DRIVE_LIST_MAX_LIMIT) {
            return send_json_error(client_fd, 400, "invalid limit");
        }
        limit = (int)parsed;
    }

    char offset_raw[64];
    if (query_get_param(req->query, "offset", offset_raw, sizeof(offset_raw)) == 0 && offset_raw[0] != '\0') {
        char *end = NULL;
        errno = 0;
        long long parsed = strtoll(offset_raw, &end, 10);
        if (errno != 0 || !end || *end != '\0' || parsed < 0) {
            return send_json_error(client_fd, 400, "invalid offset");
        }
        offset = parsed;
    }

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
    int returned = 0;
    int has_more = 0;
    long long seen = 0;
    while (ok == 0 && (ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        if (seen < offset) {
            seen++;
            continue;
        }
        if (returned >= limit) {
            has_more = 1;
            break;
        }
        seen++;

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
        returned++;
    }

    if (ok == 0) {
        if (strbuf_appendf(&sb,
                           "],\"offset\":%lld,\"limit\":%d,\"returned\":%d,\"next_offset\":%lld,\"has_more\":%s}",
                           offset, limit, returned, seen, has_more ? "true" : "false") != 0) {
            ok = -1;
        }
    }

    closedir(dir);
    int rc = (ok == 0) ? send_json_response(client_fd, 200, sb.data) : send_json_error(client_fd, 500, "oom");
    strbuf_free(&sb);
    return rc;
}

static int handle_api_games_scan(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) snprintf(requested, sizeof(requested), "/");

    int max_depth = PS5DRIVE_GAMES_SCAN_DEFAULT_DEPTH;
    char max_depth_raw[64];
    if (query_get_param(req->query, "max_depth", max_depth_raw, sizeof(max_depth_raw)) == 0 && max_depth_raw[0] != '\0') {
        char *end = NULL;
        errno = 0;
        long parsed = strtol(max_depth_raw, &end, 10);
        if (errno != 0 || !end || *end != '\0' || parsed < 0 || parsed > PS5DRIVE_GAMES_SCAN_MAX_DEPTH) {
            return send_json_error(client_fd, 400, "invalid max_depth");
        }
        max_depth = (int)parsed;
    }

    int max_dirs = PS5DRIVE_GAMES_SCAN_DEFAULT_MAX_DIRS;
    char max_dirs_raw[64];
    if (query_get_param(req->query, "max_dirs", max_dirs_raw, sizeof(max_dirs_raw)) == 0 && max_dirs_raw[0] != '\0') {
        char *end = NULL;
        errno = 0;
        long parsed = strtol(max_dirs_raw, &end, 10);
        if (errno != 0 || !end || *end != '\0' || parsed <= 0 || parsed > PS5DRIVE_GAMES_SCAN_MAX_DIRS) {
            return send_json_error(client_fd, 400, "invalid max_dirs");
        }
        max_dirs = (int)parsed;
    }

    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0) return send_json_error(client_fd, 400, "invalid path");

    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");

    struct stat st;
    if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "path not found");
        return send_json_error(client_fd, 400, "path is not a directory");
    }

    strbuf_t sb;
    if (strbuf_init(&sb, PS5DRIVE_JSON_INIT_CAP) != 0) return send_json_error(client_fd, 500, "oom");

    games_scan_ctx_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.sb = &sb;
    scan.first = 1;
    scan.max_depth = max_depth;
    scan.max_dirs = (size_t)max_dirs;
    scan.truncated = 0;

    int rc = 0;
    rc |= strbuf_append(&sb, "{\"ok\":true,\"path\":\"");
    rc |= strbuf_append_json_escaped(&sb, virt);
    rc |= strbuf_appendf(&sb, "\",\"max_depth\":%d,\"max_dirs\":%d,\"games\":[", max_depth, max_dirs);
    if (rc == 0) rc = scan_games_recursive(virt, full, 0, &scan);
    if (rc == 0) {
        rc |= strbuf_appendf(&sb, "],\"scanned_dirs\":%zu,\"found\":%zu,\"truncated\":%s}",
                             scan.scanned_dirs, scan.found, scan.truncated ? "true" : "false");
    }

    int send_rc = (rc == 0) ? send_json_response(client_fd, 200, sb.data) : send_json_error(client_fd, 500, "oom");
    strbuf_free(&sb);
    return send_rc;
}

static int handle_api_storage_list(server_ctx_t *ctx, int client_fd) {
    if (!ctx) return send_json_error(client_fd, 500, "invalid server context");

    const char *candidates[] = {
        "/data",
        "/mnt/ext0",
        "/mnt/ext1",
        "/mnt/usb0",
        "/mnt/usb1",
        "/mnt/usb2",
        "/mnt/usb3",
        "/mnt/usb4",
        "/mnt/usb5",
        "/mnt/usb6",
        "/mnt/usb7",
        "/user",
        "/system_ex",
        "/preinst",
    };

    strbuf_t sb;
    if (strbuf_init(&sb, 1024) != 0) return send_json_error(client_fd, 500, "oom");
    int rc = 0;
    int first = 1;

    rc |= strbuf_append(&sb, "{\"ok\":true,\"storage\":[");

    {
        double free_gb = 0.0;
        double total_gb = 0.0;
        int writable = 0;
        char root_virt[PATH_MAX];
        char root_full[PATH_MAX];
        if (sanitize_virtual_path("/", root_virt, sizeof(root_virt)) == 0 &&
            build_full_path(ctx, root_virt, root_full, sizeof(root_full)) == 0) {
            query_storage_space_gb(root_full, &free_gb, &total_gb);
            writable = path_is_writable_dir(root_full);
        }
        rc |= strbuf_appendf(&sb,
                             "{\"path\":\"/\",\"free_gb\":%.1f,\"total_gb\":%.1f,\"writable\":%s}",
                             free_gb, total_gb, writable ? "true" : "false");
        first = 0;
    }

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        const char *virt = candidates[i];
        char clean[PATH_MAX];
        char full[PATH_MAX];
        struct stat st;
        if (sanitize_virtual_path(virt, clean, sizeof(clean)) != 0) continue;
        if (build_full_path(ctx, clean, full, sizeof(full)) != 0) continue;
        if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (strncmp(clean, "/mnt/usb", 8) == 0 && !dir_has_non_dot_entries(full)) continue;

        double free_gb = 0.0;
        double total_gb = 0.0;
        int writable = path_is_writable_dir(full);
        query_storage_space_gb(full, &free_gb, &total_gb);

        if (strbuf_append(&sb, first ? "" : ",") != 0) {
            rc = -1;
            break;
        }
        first = 0;
        rc |= strbuf_append(&sb, "{\"path\":\"");
        rc |= strbuf_append_json_escaped(&sb, clean);
        rc |= strbuf_appendf(&sb, "\",\"free_gb\":%.1f,\"total_gb\":%.1f,\"writable\":%s}",
                             free_gb, total_gb, writable ? "true" : "false");
        if (rc != 0) break;
    }

    if (rc == 0) rc |= strbuf_append(&sb, "]}");
    int send_rc = (rc == 0) ? send_json_response(client_fd, 200, sb.data) : send_json_error(client_fd, 500, "oom");
    strbuf_free(&sb);
    return send_rc;
}

static int handle_api_games_cover(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    char requested[PATH_MAX];
    if (query_get_param(req->query, "path", requested, sizeof(requested)) != 0) return send_json_error(client_fd, 400, "missing path");

    char virt[PATH_MAX];
    if (sanitize_virtual_path(requested, virt, sizeof(virt)) != 0 || strcmp(virt, "/") == 0) {
        return send_json_error(client_fd, 400, "invalid path");
    }

    char full[PATH_MAX];
    if (build_full_path(ctx, virt, full, sizeof(full)) != 0) return send_json_error(client_fd, 400, "path too long");

    struct stat st;
    if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (errno == ENOENT) return send_json_error(client_fd, 404, "path not found");
        return send_json_error(client_fd, 400, "path is not a directory");
    }

    char cover_path[PATH_MAX];
    if (!find_game_cover_file(full, cover_path, sizeof(cover_path))) {
        return send_json_error(client_fd, 404, "cover not found");
    }
    return stream_file_inline(client_fd, cover_path, mime_type_from_path(cover_path));
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
    int dst_lstat_rc = lstat(dst_full, &dst_st);
    if (dst_lstat_rc == 0 && S_ISDIR(dst_st.st_mode)) {
        const char *name = basename_ptr(src_virt);
        if (!name || !*name || strcmp(name, "/") == 0) return send_json_error(client_fd, 400, "invalid source name");
        if (snprintf(final_dst, sizeof(final_dst), "%s/%s", dst_full, name) >= (int)sizeof(final_dst)) {
            return send_json_error(client_fd, 400, "path too long");
        }
    } else if (dst_lstat_rc != 0 && errno != ENOENT) {
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
    int dst_lstat_rc = lstat(dst_full, &dst_st);
    if (dst_lstat_rc == 0 && S_ISDIR(dst_st.st_mode)) {
        const char *name = basename_ptr(src_virt);
        if (!name || !*name || strcmp(name, "/") == 0) return send_json_error(client_fd, 400, "invalid source name");
        if (snprintf(final_dst, sizeof(final_dst), "%s/%s", dst_full, name) >= (int)sizeof(final_dst)) {
            return send_json_error(client_fd, 400, "path too long");
        }
    } else if (dst_lstat_rc != 0 && errno != ENOENT) {
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
    rc |= strbuf_appendf(&sb, "{\"ok\":true,\"pid\":%d,\"ppid\":%d,\"version\":\"", (int)getpid(), (int)getppid());
    rc |= strbuf_append_json_escaped(&sb, ctx->cfg.version ? ctx->cfg.version : "dev");
    rc |= strbuf_append(&sb, "\",\"root\":\"");
    rc |= strbuf_append_json_escaped(&sb, ctx->root_abs);
    rc |= strbuf_appendf(&sb, "\",\"web_port\":%d,\"api_port\":%d,\"debug_port\":%d,\"debug_enabled\":%s,\"active_clients\":%d,\"security_mode\":\"%s\",\"auth_enabled\":%s}",
                         ctx->cfg.web_port, ctx->cfg.api_port, ctx->cfg.debug_port,
                         ctx->debug_enabled ? "true" : "false",
                         ctx->active_clients,
                         security_mode_name(ctx),
                         auth_is_enabled(ctx) ? "true" : "false");
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

static int handle_api_config_download(server_ctx_t *ctx, int client_fd) {
    if (!ctx || !ctx->config_path[0]) return send_json_error(client_fd, 404, "config not found");
    struct stat st;
    if (stat(ctx->config_path, &st) != 0) {
        if (errno != ENOENT) return send_json_errno_error(client_fd, 500, "failed to stat config");
        if (write_default_config_file(ctx->config_path) != 0) {
            return send_json_errno_error(client_fd, 500, "failed to create default config");
        }
    }
    return stream_file_download(client_fd, ctx->config_path, "config.ini");
}

static int handle_api_config_upload(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    if (!ctx || !ctx->config_path[0]) return send_json_error(client_fd, 404, "config not found");
    if (!req) return send_json_error(client_fd, 400, "missing request");
    if (req->content_length <= 0) return send_json_error(client_fd, 400, "config body required");
    if (req->content_length > PS5DRIVE_CONFIG_MAX_BYTES) {
        return send_json_error(client_fd, 413, "config too large");
    }

    size_t body_len = (size_t)req->content_length;
    char *body = (char *)malloc(body_len + 1);
    if (!body) return send_json_error(client_fd, 500, "oom");

    size_t have = 0;
    if (req->bytes_read > req->body_offset) have = req->bytes_read - req->body_offset;
    if (have > body_len) have = body_len;
    if (have > 0) memcpy(body, req->buffer + req->body_offset, have);

    size_t used = have;
    while (used < body_len) {
        ssize_t n = recv(client_fd, body + used, body_len - used, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(body);
            return send_json_error(client_fd, 500, "read body failed");
        }
        if (n == 0) {
            free(body);
            return send_json_error(client_fd, 400, "unexpected end of body");
        }
        used += (size_t)n;
    }
    body[body_len] = '\0';

    int secure_mode = 0;
    char username[128];
    char password[128];
    char parse_err[192];
    if (parse_security_config_blob(body, body_len, &secure_mode,
                                   username, sizeof(username),
                                   password, sizeof(password),
                                   parse_err, sizeof(parse_err)) != 0) {
        const char *msg = parse_err[0] ? parse_err : "invalid config";
        free(body);
        return send_json_error(client_fd, 400, msg);
    }

    if (ensure_parent_dirs(ctx->config_path) != 0) {
        free(body);
        return send_json_errno_error(client_fd, 500, "failed to create config directory");
    }
    if (write_config_blob_file(ctx->config_path, body, body_len) != 0) {
        free(body);
        return send_json_errno_error(client_fd, 500, "failed to write config");
    }

    set_security_runtime(ctx, secure_mode, username, password);
    free(body);

    char resp[192];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"security_mode\":\"%s\",\"auth_enabled\":%s}",
             security_mode_name(ctx), auth_is_enabled(ctx) ? "true" : "false");
    return send_json_response(client_fd, 200, resp);
}

static int handle_api_config_reset(server_ctx_t *ctx, int client_fd, const http_request_t *req) {
    if (!ctx || !ctx->config_path[0]) return send_json_error(client_fd, 404, "config not found");
    if (auth_is_enabled(ctx)) {
        if (!req || !auth_credentials_match(ctx, req->reset_user, req->reset_pass)) {
            return send_json_error(client_fd, 401, "invalid reset credentials");
        }
    }
    if (write_default_config_file(ctx->config_path) != 0) {
        return send_json_errno_error(client_fd, 500, "failed to reset config");
    }
    set_security_runtime(ctx, 0, "", "");
    return send_json_response(client_fd, 200, "{\"ok\":true,\"security_mode\":\"unsecure\"}");
}

static int serve_web_index(server_ctx_t *ctx, int client_fd) {
    strbuf_t html;
    if (strbuf_init(&html, 16384) != 0) return send_json_error(client_fd, 500, "oom");

    int rc = 0;
    rc |= strbuf_append(&html, "<!doctype html><html><head><meta charset=\"utf-8\"><title>PS5Drive</title>"
                              "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                              "<style>"
                              ":root{--sloth-bg:#eef3f8;--sloth-bg2:#f8fbff;--sloth-card:#ffffff;--sloth-line:#d6e1ef;--sloth-ink:#102135;"
                              "--sloth-muted:#4d6077;--sloth-accent:#1f6feb;--sloth-accent-2:#1a56c3;--sloth-danger:#b4232d;--sloth-good:#1f9d57;--sloth-warn:#a35f00;--sloth-info:#0f8a9d;"
                              "--sloth-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--muted:var(--sloth-muted);--panel-bg:#ffffff;"
                              "--panel-soft:#f6fafe;--chip-bg:#eaf2fb;--btn-bg:#f7fafd;--btn-border:#c7d5e4;--btn-ink:#102135;--btn-hover:#ecf2f9;"
                              "--toolbar-a:#ffffff;--toolbar-b:#f3f8fe;--table-head:#eef4fb;--table-line:#e3ebf5;--row-hover:#eff5fd;--row-selected:#e3eefc;"
                              "--log-bg:#f7fbff;--drop-bg:#f8fbff;--drop-over:#e9f3ff;--drop-border:#8fb1de;--kind-bg:#ffffff;--kind-dir-bg:#e8f1ff;--kind-dir-line:#b3ccf2;"
                              "--kind-dir-ink:#1c4da2;--kind-file-bg:#f4f8fc;--input-bg:#ffffff;--ghost-bg:#ffffff;--danger-bg:#fff0f2;--danger-border:#f2b7c2;"
                              "--btn-primary-bg:#1f6feb;--btn-primary-border:#1a56c3;--btn-primary-hover:#174ea8;"
                              "--btn-success-bg:#1f9d57;--btn-success-border:#167a42;--btn-success-hover:#146a3a;"
                              "--btn-info-bg:#0f8a9d;--btn-info-border:#0d6f7f;--btn-info-hover:#0b5e6c;"
                              "--btn-warn-bg:#f1b448;--btn-warn-border:#cf922d;--btn-warn-hover:#e5a134;--btn-warn-ink:#3b2a03;"
                              "--btn-coffee-bg:#d29b52;--btn-coffee-border:#b57b30;--btn-coffee-hover:#c0893c;--btn-coffee-ink:#2f1d08;"
                              "--btn-danger-bg:#fff0f2;--btn-danger-border:#f2b7c2;--card-shadow:rgba(10,28,52,.12)}"
                              "body[data-theme='dark']{--sloth-bg:#081320;--sloth-bg2:#0f1d2d;--sloth-card:#0f1b2c;--sloth-line:#253851;--sloth-ink:#e7edf7;"
                              "--sloth-muted:#9fb0c8;--sloth-accent:#4d98ff;--sloth-accent-2:#2f7de8;--sloth-danger:#ff8c99;--sloth-good:#47d18a;--sloth-warn:#f2be5b;--sloth-info:#5ac2d4;"
                              "--muted:var(--sloth-muted);--panel-bg:#0f1b2c;--panel-soft:#132439;--chip-bg:#17273d;--btn-bg:#17283d;--btn-border:#314764;"
                              "--btn-ink:#e7edf7;--btn-hover:#213653;--toolbar-a:#132237;--toolbar-b:#0f1b2c;--table-head:#16273f;--table-line:#23374f;"
                              "--row-hover:#1a2d48;--row-selected:#244167;--log-bg:#0b1626;--drop-bg:#16273f;--drop-over:#213a5a;--drop-border:#3f628f;--kind-bg:#16263c;"
                              "--kind-dir-bg:#20375a;--kind-dir-line:#3a5f8d;--kind-dir-ink:#c6dcff;--kind-file-bg:#152336;--input-bg:#121f33;--ghost-bg:#16263d;"
                              "--danger-bg:#4b2631;--danger-border:#8e3c50;--btn-primary-bg:#2f7de8;--btn-primary-border:#286bcc;--btn-primary-hover:#2668c4;"
                              "--btn-success-bg:#1d8f55;--btn-success-border:#197447;--btn-success-hover:#167a42;"
                              "--btn-info-bg:#0f8c9f;--btn-info-border:#0d7080;--btn-info-hover:#0c6a79;"
                              "--btn-warn-bg:#d29a35;--btn-warn-border:#b98528;--btn-warn-hover:#bf8626;--btn-warn-ink:#18120a;"
                              "--btn-coffee-bg:#a67031;--btn-coffee-border:#8e5c24;--btn-coffee-hover:#915f28;--btn-coffee-ink:#f9ebd8;"
                              "--btn-danger-bg:#4b2631;--btn-danger-border:#8e3c50;--card-shadow:rgba(0,0,0,.5)}"
                              "*{box-sizing:border-box}html,body{height:100%}body{margin:0;font-family:ui-rounded,'Trebuchet MS','Segoe UI',sans-serif;color:var(--sloth-ink);"
                              "background:linear-gradient(180deg,var(--sloth-bg),var(--sloth-bg2));min-height:100dvh;overflow:hidden}"
                              ".shell,.sloth-shell{width:100%;max-width:none;min-height:100dvh;margin:0;padding:clamp(.55rem,1.4vw,1rem);display:grid;gap:clamp(.55rem,1.2vw,1rem)}"
                              ".card,.sloth-card{background:var(--panel-bg);border:1px solid var(--sloth-line);border-radius:18px;box-shadow:0 10px 26px var(--card-shadow);overflow:hidden}"
                              ".top,.sloth-top{padding:1rem;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:.75rem}"
                              ".top-left,.sloth-top-left{display:grid;gap:.2rem}"
                              ".top-right,.sloth-top-right{display:grid;gap:.45rem;justify-items:end;align-items:end}"
                              ".header-actions,.sloth-header-actions{display:flex;gap:.45rem;flex-wrap:wrap;justify-content:flex-end}"
                              ".brand-wrap,.sloth-brand-wrap{display:flex;align-items:center;min-height:40px}"
                              ".brand-logo,.sloth-brand-logo{display:block;height:40px;width:auto;max-width:min(320px,75vw)}"
                              ".brand-logo.logo-dark,.sloth-brand-logo.logo-dark{display:none}"
                              "body[data-theme='dark'] .brand-logo.logo-light,body[data-theme='dark'] .sloth-brand-logo.logo-light{display:none}"
                              "body[data-theme='dark'] .brand-logo.logo-dark,body[data-theme='dark'] .sloth-brand-logo.logo-dark{display:block}"
                              ".brand-sub,.sloth-brand-sub{font-size:.9rem;font-weight:700;color:var(--sloth-muted)}"
                              ".chips,.sloth-chips{display:flex;gap:.5rem;flex-wrap:wrap}"
                              ".chip,.sloth-chip{font-size:.8rem;background:var(--chip-bg);border:1px solid var(--sloth-line);border-radius:999px;padding:.35rem .7rem}"
                              ".mode-chip-secure{background:rgba(31,157,87,.14);border-color:rgba(31,157,87,.42);color:#196d44}"
                              ".mode-chip-insecure{background:rgba(180,35,45,.14);border-color:rgba(180,35,45,.38);color:#9f2430}"
                              "body[data-theme='dark'] .mode-chip-secure{background:rgba(71,209,138,.22);border-color:rgba(71,209,138,.45);color:#8df0bb}"
                              "body[data-theme='dark'] .mode-chip-insecure{background:rgba(255,140,153,.18);border-color:rgba(255,140,153,.42);color:#ffc1c9}"
                              ".grid,.sloth-grid{display:grid;grid-template-columns:minmax(260px,340px) minmax(0,1fr) minmax(260px,340px);gap:clamp(.55rem,1.2vw,1rem);min-height:0;height:calc(100dvh - 96px)}.panel,.sloth-panel{padding:1rem;overflow:auto}"
                              ".table-card,.sloth-table-card,.log-card,.sloth-log-card{display:flex;flex-direction:column;min-height:0}"
                              ".section,.sloth-section{padding:1rem;border:1px solid var(--sloth-line);border-radius:12px;background:var(--panel-soft)}"
                              ".section h3,.sloth-section h3{margin:.1rem 0 .6rem 0;font-size:.95rem}"
                              ".stack,.sloth-stack{display:grid;gap:.5rem}.row,.sloth-row{display:flex;gap:.5rem;flex-wrap:wrap}.mono{font-family:var(--sloth-mono)}"
                              "input{min-width:0;width:100%;padding:.58rem .68rem;min-height:40px;border:1px solid var(--sloth-line);border-radius:10px;background:var(--input-bg);color:var(--sloth-ink)}"
                              "button{border:1px solid var(--btn-border);background:var(--btn-bg);color:var(--btn-ink);padding:.5rem .78rem;min-height:40px;border-radius:10px;cursor:pointer;font-weight:600;touch-action:manipulation;transition:background .18s ease,border-color .18s ease,color .18s ease}"
                              "button:hover{background:var(--btn-hover)}button:disabled{opacity:.45;cursor:not-allowed}"
                              ".btn-main,.sloth-btn-main{background:var(--btn-primary-bg);border-color:var(--btn-primary-border);color:#fff}"
                              ".btn-main:hover,.sloth-btn-main:hover{background:var(--btn-primary-hover)}"
                              ".btn-success,.sloth-btn-success{background:var(--btn-success-bg);border-color:var(--btn-success-border);color:#fff}"
                              ".btn-success:hover,.sloth-btn-success:hover{background:var(--btn-success-hover)}"
                              ".btn-info,.sloth-btn-info{background:var(--btn-info-bg);border-color:var(--btn-info-border);color:#fff}"
                              ".btn-info:hover,.sloth-btn-info:hover{background:var(--btn-info-hover)}"
                              ".btn-warn,.sloth-btn-warn{background:var(--btn-warn-bg);border-color:var(--btn-warn-border);color:var(--btn-warn-ink)}"
                              ".btn-warn:hover,.sloth-btn-warn:hover{background:var(--btn-warn-hover)}"
                              ".btn-coffee,.sloth-btn-coffee{background:var(--btn-coffee-bg);border-color:var(--btn-coffee-border);color:var(--btn-coffee-ink)}"
                              ".btn-coffee:hover,.sloth-btn-coffee:hover{background:var(--btn-coffee-hover)}"
                              ".btn-ghost,.sloth-btn-ghost{background:var(--ghost-bg)}.btn-danger,.sloth-btn-danger{border-color:var(--btn-danger-border);background:var(--btn-danger-bg);color:var(--sloth-danger)}"
                              ".theme-toggle,.sloth-theme-toggle{width:40px;min-width:40px;padding:.45rem;display:inline-flex;align-items:center;justify-content:center}"
                              ".theme-toggle svg,.sloth-theme-toggle svg{width:18px;height:18px;display:none;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}"
                              "body[data-theme='light'] .theme-toggle .icon-moon,body[data-theme='light'] .sloth-theme-toggle .icon-moon{display:block}"
                              "body[data-theme='dark'] .theme-toggle .icon-sun,body[data-theme='dark'] .sloth-theme-toggle .icon-sun{display:block}"
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
                              ".meta a,.sloth-meta a{color:var(--sloth-accent);text-decoration:none;font-weight:700}"
                              ".meta a:hover,.sloth-meta a:hover{text-decoration:underline}"
                              ".btn-link,.sloth-link{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;border:1px solid var(--btn-border);background:var(--btn-bg);color:var(--btn-ink);padding:.5rem .78rem;min-height:40px;border-radius:10px;font-weight:600;touch-action:manipulation;transition:background .18s ease,border-color .18s ease,color .18s ease;gap:.35rem}"
                              ".btn-link:hover,.sloth-link:hover{background:var(--btn-hover)}"
                              "@media (max-width:1280px){.grid,.sloth-grid{grid-template-columns:minmax(280px,360px) minmax(0,1fr);height:auto}.log-card,.sloth-log-card{grid-column:1 / -1}.log,.sloth-log{min-height:220px;max-height:34vh}}"
                              "@media (max-width:920px){body{overflow:auto}.shell,.sloth-shell{min-height:100dvh;padding:.6rem;gap:.6rem}.top,.sloth-top{padding:.75rem}.top-right,.sloth-top-right{width:100%;justify-items:stretch}.header-actions,.sloth-header-actions{justify-content:flex-start}.header-actions button,.header-actions a,.sloth-header-actions button,.sloth-header-actions a{flex:1 1 calc(50% - .3rem)}.grid,.sloth-grid{grid-template-columns:1fr;height:auto}.panel,.sloth-panel{padding:.75rem;overflow:visible}.toolbar,.sloth-toolbar{padding:.75rem}.pathline,.sloth-pathline{flex-wrap:wrap}.pathline input,.sloth-pathline input{flex:1 1 100%}.pathline button,.sloth-pathline button{flex:1 1 calc(25% - .4rem)}.row button,.sloth-row button{flex:1 1 calc(50% - .3rem)}.statusline,.sloth-status{align-items:flex-start;flex-direction:column}.tablewrap,.sloth-tablewrap{max-height:48vh;min-height:220px}.table,.sloth-table{font-size:.86rem}.table th,.sloth-table th,.table td,.sloth-table td{padding:.48rem}.log,.sloth-log{max-height:28vh}}"
                              "@media (max-width:560px){.header-actions button,.header-actions a,.sloth-header-actions button,.sloth-header-actions a,.row button,.sloth-row button,.pathline button,.sloth-pathline button{flex:1 1 100%}.brand-logo,.sloth-brand-logo{height:32px}.chip,.sloth-chip{font-size:.74rem}}"
                              "</style></head><body>");
    rc |= strbuf_appendf(&html,
                         "<div class=\"shell sloth-shell\"><div class=\"card sloth-card top sloth-top\">"
                         "<div class=\"top-left sloth-top-left\"><div class=\"brand-wrap sloth-brand-wrap\"><img class=\"brand-logo sloth-brand-logo logo-light\" src=\"/assets/logo-light.svg\" alt=\"PS5Drive logo\">"
                         "<img class=\"brand-logo sloth-brand-logo logo-dark\" src=\"/assets/logo-dark.svg\" alt=\"PS5Drive logo\"></div>"
                         "<div id=\"versionText\" class=\"brand-sub sloth-brand-sub mono\">v%s</div>"
                         "<div id=\"createdByText\" class=\"meta sloth-meta\">Created by <a href=\"https://github.com/phantomptr\" target=\"_blank\" rel=\"noopener noreferrer\">PhantomPtr</a></div></div>"
                         "<div class=\"top-right sloth-top-right\"><div class=\"chips sloth-chips\">"
                         "<div id=\"apiPortChip\" class=\"chip sloth-chip mono\">API Port: %d</div><div id=\"debugPortChip\" class=\"chip sloth-chip mono\">Debug Port: %d</div><div id=\"modeChip\" class=\"chip sloth-chip mono %s\">Mode: %s</div></div>"
                         "<div class=\"header-actions sloth-header-actions\"><select id=\"langSelect\" class=\"mono\" style=\"min-width:168px;max-width:220px\"><option value=\"en\">English</option><option value=\"zh-cn\">简体中文</option><option value=\"zh-tw\">繁體中文</option><option value=\"hi\">हिन्दी</option><option value=\"es\">Español</option><option value=\"ar\">العربية</option><option value=\"bn\">বাংলা</option><option value=\"pt-br\">Português (Brasil)</option><option value=\"ru\">Русский</option><option value=\"ja\">日本語</option><option value=\"de\">Deutsch</option><option value=\"fr\">Français</option><option value=\"ko\">한국어</option><option value=\"tr\">Türkçe</option><option value=\"vi\">Tiếng Việt</option><option value=\"id\">Bahasa Indonesia</option><option value=\"it\">Italiano</option><option value=\"th\">ไทย</option></select><button id=\"themeToggleBtn\" class=\"btn-ghost sloth-btn-ghost theme-toggle sloth-theme-toggle\" aria-label=\"Toggle theme\" title=\"Toggle theme\">"
                         "<svg class=\"icon-moon\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M20 14.5A8.5 8.5 0 0 1 9.5 4 9 9 0 1 0 20 14.5Z\"></path></svg>"
                         "<svg class=\"icon-sun\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"4\"></circle><path d=\"M12 2V4\"></path><path d=\"M12 20V22\"></path><path d=\"M4.93 4.93L6.34 6.34\"></path><path d=\"M17.66 17.66L19.07 19.07\"></path><path d=\"M2 12H4\"></path><path d=\"M20 12H22\"></path><path d=\"M4.93 19.07L6.34 17.66\"></path><path d=\"M17.66 6.34L19.07 4.93\"></path></svg>"
                         "</button>"
                         "<button id=\"downloadConfigBtn\" class=\"btn-info sloth-btn-info\">Download Config</button>"
                         "<button id=\"uploadConfigBtn\" class=\"btn-main sloth-btn-main\">Upload Config</button>"
                         "<button id=\"resetConfigBtn\" class=\"btn-warn sloth-btn-warn\">Reset Config</button>"
                         "<a class=\"btn-link sloth-link btn-coffee sloth-btn-coffee\" href=\"https://ko-fi.com/B0B81S0WUA\" target=\"_blank\" rel=\"noopener noreferrer\"><span id=\"coffeeText\">Buy Me a Coffee</span></a>"
                         "<a class=\"btn-link sloth-link btn-info sloth-btn-info\" href=\"https://discord.com/invite/fzK3xddtrM\" target=\"_blank\" rel=\"noopener noreferrer\"><span id=\"discordText\">Discord</span></a>"
                         "<button id=\"stopBtn\" class=\"btn-danger sloth-btn-danger\">Stop PS5Drive</button></div></div></div>",
                         ctx->cfg.version ? ctx->cfg.version : "dev", ctx->cfg.api_port, ctx->cfg.debug_port,
                         auth_is_enabled(ctx) ? "mode-chip-secure" : "mode-chip-insecure",
                         auth_is_enabled(ctx) ? "Secure" : "Insecure");
    rc |= strbuf_append(&html,
                        "<div class=\"grid sloth-grid\">"
                        "<div class=\"card sloth-card panel sloth-panel\">"
                        "<div class=\"section sloth-section stack sloth-stack\"><h3 id=\"uploadTitle\">Upload</h3>"
                        "<div class=\"row sloth-row\"><button id=\"pickFilesBtn\" class=\"btn-ghost sloth-btn-ghost\">Browse Files</button>"
                        "<button id=\"pickFolderBtn\" class=\"btn-ghost sloth-btn-ghost\">Browse Folder</button></div>"
                        "<div id=\"dropZone\" class=\"drop sloth-drop\">Drop files/folders here</div>"
                        "<div id=\"queueInfo\" class=\"mono\" style=\"font-size:.85rem;color:var(--muted)\">No selection</div>"
                        "<div id=\"queueList\" class=\"mono\" style=\"display:none;font-size:.78rem;color:var(--muted);max-height:8.4em;overflow:auto;border:1px solid var(--sloth-line);border-radius:12px;padding:.45rem;background:linear-gradient(180deg,var(--panel-bg),var(--panel-soft));box-shadow:inset 0 1px 0 rgba(255,255,255,.12);gap:.42rem;flex-wrap:wrap;align-content:flex-start\"></div>"
                        "<div class=\"progress sloth-progress\"><progress id=\"uploadProgress\" value=\"0\" max=\"100\"></progress>"
                        "<div id=\"uploadStatus\" class=\"mono\" style=\"font-size:.82rem;color:var(--muted);display:grid;gap:.1rem;min-height:3.9em;line-height:1.25;white-space:normal;overflow-wrap:anywhere;word-break:break-word\"><div id=\"uploadStatusMain\">Idle</div><div id=\"uploadStatusDetail\"></div><div id=\"uploadStatusFile\" style=\"opacity:.9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis\"></div></div></div>"
                        "<div class=\"row sloth-row\"><button id=\"uploadStartBtn\" class=\"btn-success sloth-btn-success\">Upload</button>"
                        "<button id=\"resumeUploadBtn\" class=\"btn-info sloth-btn-info\">Resume</button>"
                        "<button id=\"uploadStopBtn\" class=\"btn-warn sloth-btn-warn\" disabled>Stop</button>"
                        "<button id=\"overwriteAllBtn\" class=\"btn-ghost sloth-btn-ghost\">Overwrite: Ask</button></div>"
                        "<div id=\"uploadNote\" class=\"meta sloth-meta\">Uploads go to the current directory shown in <span class=\"mono\">Current Path</span>.</div>"
                        "<div id=\"uploadPathHint\" class=\"meta sloth-meta mono\">Upload target: /</div>"
                        "<input id=\"uploadFiles\" type=\"file\" multiple style=\"display:none\">"
                        "<input id=\"uploadFolder\" type=\"file\" webkitdirectory directory multiple style=\"display:none\">"
                        "<input id=\"uploadConfigInput\" type=\"file\" accept=\".ini,text/plain\" style=\"display:none\">"
                        "</div>"
                        "<div class=\"section sloth-section stack sloth-stack\" style=\"margin-top:.8rem\"><h3 id=\"createFolderTitle\">Create Folder</h3>"
                        "<div class=\"row sloth-row\"><input id=\"mkdirInput\" placeholder=\"new-folder\">"
                        "<button id=\"mkdirBtn\">Create</button></div></div>"
                        "<div class=\"section sloth-section stack sloth-stack\" style=\"margin-top:.8rem\"><h3 id=\"selectedTitle\">Selected Item</h3>"
                        "<div id=\"selectionInfo\" class=\"mono\" style=\"font-size:.85rem;color:var(--muted)\">Nothing selected</div>"
                        "<div class=\"row sloth-row\"><button id=\"goSelectedBtn\">Go To</button><button id=\"downloadSelectedBtn\">Download</button>"
                        "<button id=\"deleteSelectedBtn\" class=\"btn-danger sloth-btn-danger\">Delete</button></div>"
                        "<div class=\"row sloth-row\"><input id=\"renameInput\" placeholder=\"new-name (same folder)\">"
                        "<button id=\"renameBtn\">Rename</button></div>"
                        "<div class=\"row sloth-row\"><input id=\"moveInput\" class=\"mono\" placeholder=\"example: /data/ps5drive\">"
                        "<button id=\"moveBtn\">Move To</button><button id=\"copyBtn\">Copy To</button><button id=\"chmodBtn\">CHMOD 777 -R</button></div>"
                        "<div class=\"progress sloth-progress\" style=\"margin-top:.2rem\"><progress id=\"selectedOpProgress\" value=\"0\" max=\"100\"></progress>"
                        "<div id=\"selectedOpStatus\" class=\"mono\" style=\"font-size:.82rem;color:var(--muted);display:block;min-height:2.4em;line-height:1.25;white-space:normal;overflow-wrap:anywhere;word-break:break-word\">Selected action: idle</div></div>"
                        "<div id=\"moveTip\" class=\"meta sloth-meta\">Move/Copy tip: use absolute path (example: <span class=\"mono\">/data/ps5drive</span>). If destination is an existing folder, item name is kept.</div>"
                        "</div>"
                        "</div>"
                        "<div class=\"card sloth-card table-card sloth-table-card\">"
                        "<div class=\"toolbar sloth-toolbar\" style=\"padding:.7rem 1rem\"><div class=\"row sloth-row\">"
                        "<button id=\"tabFilesBtn\" class=\"btn-main sloth-btn-main\">Files</button>"
                        "<button id=\"tabGamesBtn\" class=\"btn-ghost sloth-btn-ghost\">Games</button></div></div>"
                        "<div id=\"filesPane\">"
                        "<div class=\"toolbar sloth-toolbar\">"
                        "<div class=\"pathline sloth-pathline\"><input id=\"pathInput\" class=\"mono\" value=\"/\">"
                        "<button id=\"refreshBtn\">Refresh</button><button id=\"upBtn\">Up</button><button id=\"rootBtn\">Root</button><button id=\"loadMoreBtn\" class=\"btn-ghost sloth-btn-ghost\" disabled>Load More</button></div>"
                        "<div class=\"statusline sloth-status\"><div id=\"currentPathLabel\">Current Path: <span id=\"pathLabel\" class=\"mono\">/</span></div>"
                        "<div id=\"countLabel\" class=\"mono\">0 entries</div></div>"
                        "</div>"
                        "<div class=\"tablewrap sloth-tablewrap\"><table class=\"table sloth-table\"><thead><tr><th id=\"thName\">Name</th><th id=\"thSize\">Size</th><th id=\"thMTime\">MTime</th><th id=\"thAction\">Action</th></tr></thead><tbody id=\"rows\"></tbody></table></div>"
                        "</div>"
                        "<div id=\"gamesPane\" style=\"display:none;padding:1rem;overflow:auto\">"
                        "<div class=\"section sloth-section stack sloth-stack\"><h3 id=\"gamesTitle\">Games Scanner</h3>"
                        "<div id=\"gamesPresetInfo\" class=\"meta sloth-meta\">Preset scan paths: etaHEN/games, etaHEN/homebrew, games, homebrew</div>"
                        "<div class=\"row sloth-row\"><input id=\"gamesPathInput\" class=\"mono\" placeholder=\"Optional extra absolute path (example: /data/games)\">"
                        "<button id=\"gamesScanBtn\" class=\"btn-main sloth-btn-main\">Scan</button></div>"
                        "<div id=\"gamesStatus\" class=\"meta sloth-meta\">Ready to scan.</div>"
                        "<div id=\"gamesStorageFilters\" class=\"row sloth-row\" style=\"margin-top:.35rem\"></div>"
                        "</div>"
                        "<div class=\"section sloth-section stack sloth-stack\" style=\"margin-top:.8rem\"><div id=\"gamesCount\" class=\"mono\" style=\"font-size:.85rem;color:var(--muted)\">0 games</div>"
                        "<div class=\"tablewrap sloth-tablewrap\" style=\"max-height:48vh\"><table class=\"table sloth-table\"><thead><tr><th id=\"gamesThCover\">Cover</th><th id=\"gamesThMeta\">Metadata</th><th id=\"gamesThPath\">Path</th><th id=\"gamesThAction\">Action</th></tr></thead><tbody id=\"gamesRows\"></tbody></table></div>"
                        "</div>"
                        "</div>"
                        "</div>"
                        "<div class=\"card sloth-card panel sloth-panel log-card sloth-log-card\">"
                        "<div class=\"log-wrap sloth-log-wrap\"><div class=\"row sloth-row\" style=\"justify-content:space-between;align-items:center\">"
                        "<h3 id=\"logTitle\" style=\"margin:0\">Activity Log</h3><button id=\"clearLogBtn\" class=\"btn-ghost sloth-btn-ghost\">Clear</button></div>"
                        "<pre id=\"log\" class=\"log sloth-log\"></pre></div>"
                        "</div></div></div>");
    rc |= strbuf_append(&html,
                        "<script>"
                        "const api='';"
                        "const state={path:'/',entries:[],selected:'',queueFiles:[],queueBytes:0,queueTopItems:[],queuePreparing:false,queuePreparedCount:0,queuePrepToken:0,uploading:false,cancelUpload:false,currentXhr:null,selectedBusy:false,listOffset:0,listLimit:500,hasMore:false,listLoadingMore:false,uploadUiTs:0,uploadUiPct:-1,uploadUiMsg:'',securityMode:'unsecure',overwriteAll:false};"
                        "function qs(id){return document.getElementById(id);}"
                        "function detectTheme(){try{return window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}catch(e){return 'light';}}"
                        "function applyTheme(theme){const t=(theme==='dark'||theme==='light')?theme:detectTheme();document.body.setAttribute('data-theme',t);const btn=qs('themeToggleBtn');if(btn){const target=t==='dark'?'light':'dark';btn.setAttribute('aria-label','Switch to '+target+' mode');btn.title='Switch to '+target+' mode';}try{localStorage.setItem('ps5drive_theme',t);}catch(e){}}"
                        "function initTheme(){let saved='';try{saved=localStorage.getItem('ps5drive_theme')||'';}catch(e){}applyTheme(saved);}"
                        "function toggleTheme(){const cur=document.body.getAttribute('data-theme')==='dark'?'dark':'light';applyTheme(cur==='dark'?'light':'dark');}"
                        "function qp(p){return encodeURIComponent(p);}"
                        "function normPath(p){if(!p)return '/';let n=String(p);if(n[0]!=='/')n='/'+n;n=n.replace(/\\/+/g,'/');if(n.length>1&&n.endsWith('/'))n=n.slice(0,-1);return n||'/';}"
                        "function join(base,name){const b=normPath(base);if(b==='/')return '/'+name;return b.replace(/\\/$/,'')+'/'+name;}"
                        "function basenameOf(p){const n=normPath(p);if(n==='/')return '';const i=n.lastIndexOf('/');return i<0?n:n.slice(i+1);}"
                        "function parentOf(p){const n=normPath(p);if(n==='/')return '/';const i=n.lastIndexOf('/');return i<=0?'/':n.slice(0,i);}"
                        "function cleanRelPath(p){let s=String(p||'');s=s.replace(/\\\\/g,'/');s=s.replace(/^\\/+/, '');s=s.replace(/\\/+/g,'/');return s;}"
                        "function relPathOf(file){if(!file)return '';return cleanRelPath(file.__rel_path||file.webkitRelativePath||file.name||'');}"
                        "function computeQueueBytes(files){let bytes=0;for(const f of (files||[])){if(!f||typeof f.size!=='number')continue;bytes+=Number(f.size)||0;}return bytes;}"
                        "async function readAllEntries(reader){return await new Promise((resolve)=>{const out=[];const pump=()=>{reader.readEntries((batch)=>{if(!batch||!batch.length){resolve(out);return;}out.push(...batch);pump();},()=>resolve(out));};pump();});}"
                        "async function filesFromEntry(entry,prefix){if(!entry)return [];if(entry.isFile){return await new Promise((resolve)=>{entry.file((f)=>{try{f.__rel_path=cleanRelPath((prefix||'')+f.name);}catch(e){}resolve([f]);},()=>resolve([]));});}if(entry.isDirectory){const dirPrefix=cleanRelPath((prefix||'')+String(entry.name||'')+'/');const reader=entry.createReader();const children=await readAllEntries(reader);let out=[];for(const child of children){const more=await filesFromEntry(child,dirPrefix);if(more&&more.length)out=out.concat(more);}return out;}return [];}"
                        "async function collectDropFiles(dt){if(!dt)return [];const items=dt.items?[...dt.items]:[];if(items.length){let out=[];for(const it of items){if(!it||it.kind!=='file')continue;const entry=it.webkitGetAsEntry?it.webkitGetAsEntry():null;if(entry){const more=await filesFromEntry(entry,'');if(more&&more.length)out=out.concat(more);continue;}const f=it.getAsFile?it.getAsFile():null;if(f){try{if(!f.__rel_path)f.__rel_path=cleanRelPath(f.name);}catch(e){}out.push(f);}}if(out.length)return out;}const files=dt.files?[...dt.files]:[];for(const f of files){try{if(f&&!f.__rel_path)f.__rel_path=cleanRelPath(f.webkitRelativePath||f.name);}catch(e){}}return files;}"
                        "function selectedEntry(){if(!state.selected)return null;for(const e of state.entries){if(join(state.path,e.name)===state.selected)return e;}return null;}"
                        "function log(msg){const el=qs('log');if(!el)return;const time=new Date().toLocaleTimeString();const line='['+time+'] '+msg;const lines=(el.textContent?el.textContent.split('\\n').filter(Boolean):[]);lines.unshift(line);el.textContent=lines.slice(0,200).join('\\n');}"
                        "async function apiJson(path,opt){const r=await fetch(api+path,opt||{});if(!r.ok){throw new Error(await r.text());}return r.json();}"
                        "function updateSecurityMode(mode){const raw=String(mode||'').toLowerCase();const m=raw==='secure'?'secure':'unsecure';state.securityMode=m;const chip=qs('modeChip');if(chip){chip.textContent='Mode: '+(m==='secure'?'Secure':'Insecure');chip.classList.remove('mode-chip-secure','mode-chip-insecure');chip.classList.add(m==='secure'?'mode-chip-secure':'mode-chip-insecure');}}"
                        "async function keepAlive(){try{const h=await apiJson('/api/health');const vc=qs('versionText');if(vc&&h&&h.version)vc.textContent='v'+h.version;if(h&&h.security_mode)updateSecurityMode(h.security_mode);}catch(err){}}"
                        "async function stopPayload(){if(!confirm('Stop PS5Drive now? You can reload payload after this.'))return;const btn=qs('stopBtn');if(btn)btn.disabled=true;try{await fetch(api+'/api/stop',{method:'POST'});log('Stop requested. Payload shutting down...');}catch(err){log('Stop requested. Connection closed while shutting down.');}setUploadProgress(0,'Stopping payload...');}"
                        "function downloadConfig(){window.location=api+'/api/config/download';}"
                        "function pickConfigUpload(){if(state.uploading){log('Stop current upload first');return;}const input=qs('uploadConfigInput');if(!input)return;input.value='';input.click();}"
                        "async function uploadConfig(){const input=qs('uploadConfigInput');if(!input||!input.files||!input.files.length)return;const file=input.files[0];try{const text=await file.text();const r=await apiJson('/api/config/upload',{method:'POST',headers:{'Content-Type':'text/plain; charset=utf-8'},body:text});updateSecurityMode((r&&r.security_mode)||'unsecure');log('Config uploaded: '+file.name+' -> '+(state.securityMode==='secure'?'Secure':'Insecure'));if(state.securityMode==='secure'){log('Secure mode enabled. Browser may ask for Basic Auth on next request.');}}catch(err){log('Config upload failed: '+err.message);}finally{input.value='';}}"
                        "async function resetConfig(){if(!confirm('Reset config.ini to default and disable secure mode?'))return;const headers={};if(state.securityMode==='secure'){const user=prompt('Enter username to confirm reset:','');if(user===null)return;const pass=prompt('Enter password to confirm reset:','');if(pass===null)return;headers['X-PS5Drive-Reset-User']=user;headers['X-PS5Drive-Reset-Pass']=pass;}try{const r=await apiJson('/api/config/reset',{method:'POST',headers:headers});updateSecurityMode((r&&r.security_mode)||'unsecure');log('Config reset to defaults.');}catch(err){log('Config reset failed: '+err.message);}}"
                        "function setPath(p){state.path=normPath(p||'/');qs('pathInput').value=state.path;qs('pathLabel').textContent=state.path;const hint=qs('uploadPathHint');if(hint)hint.textContent='Upload target: '+state.path;}"
                        "function formatSize(n){const v=Number(n)||0;const u=['B','KB','MB','GB','TB'];let i=0;let x=v;while(x>=1024&&i<u.length-1){x/=1024;i++;}return (i===0?String(v):x.toFixed(x>=10?1:2))+' '+u[i];}"
                        "function formatRate(bps){const n=Number(bps)||0;if(!n||n<0)return '-';return formatSize(n)+'/s';}"
                        "function formatEta(sec){const s=Math.max(0,Math.ceil(Number(sec)||0));if(!Number.isFinite(s))return '--';if(s<60)return String(s)+'s';const m=Math.floor(s/60);const r=s%60;if(m<60)return String(m)+'m '+String(r)+'s';const h=Math.floor(m/60);const mm=m%60;return String(h)+'h '+String(mm)+'m';}"
                        "function formatTime(sec){const d=new Date((Number(sec)||0)*1000);if(!Number.isFinite(d.getTime()))return '-';return d.toLocaleString();}"
                        "function makeBtn(label,cls,onClick){const b=document.createElement('button');b.textContent=label;b.className='mini '+(cls||'');b.onclick=onClick;return b;}"
                        "function uiTr(key,fallback){try{if(typeof window!=='undefined'&&typeof window.ps5driveTr==='function'){const v=window.ps5driveTr(key);if(v!==undefined&&v!==null&&v!=='')return v;}}catch(e){}return fallback||key;}"
                        "function updateSelectionUI(){const info=qs('selectionInfo');const goBtn=qs('goSelectedBtn');const downBtn=qs('downloadSelectedBtn');const delBtn=qs('deleteSelectedBtn');const renBtn=qs('renameBtn');const moveBtn=qs('moveBtn');const copyBtn=qs('copyBtn');const chmodBtn=qs('chmodBtn');const ent=selectedEntry();const busy=!!state.selectedBusy;if(!state.selected||!ent){info.textContent=uiTr('nothing_selected','Nothing selected');goBtn.disabled=true;downBtn.disabled=true;delBtn.disabled=true;renBtn.disabled=true;moveBtn.disabled=true;copyBtn.disabled=true;chmodBtn.disabled=true;return;}info.textContent=state.selected;goBtn.disabled=busy||!ent.is_dir;downBtn.disabled=busy?true:false;delBtn.disabled=busy;renBtn.disabled=busy;moveBtn.disabled=busy;copyBtn.disabled=busy;chmodBtn.disabled=busy;}"
                        "function selectPath(path){state.selected=path||'';updateSelectionUI();renderRows();}"
                        "function renderRows(){const rows=qs('rows');rows.innerHTML='';const frag=document.createDocumentFragment();if(state.path!=='/'){const row=document.createElement('tr');row.className='entry-row';const td1=document.createElement('td');td1.className='mono';td1.textContent='..';const td2=document.createElement('td');td2.textContent='-';const td3=document.createElement('td');td3.textContent='-';const td4=document.createElement('td');td4.appendChild(makeBtn(uiTr('go_to','Go To'),'',()=>goUp()));row.appendChild(td1);row.appendChild(td2);row.appendChild(td3);row.appendChild(td4);frag.appendChild(row);}if(state.entries.length===0){const row=document.createElement('tr');const td=document.createElement('td');td.colSpan=4;td.style.color='var(--muted)';td.textContent=uiTr('empty_directory','(empty directory)');row.appendChild(td);frag.appendChild(row);}for(const e of state.entries){const full=join(state.path,e.name);const row=document.createElement('tr');row.className='entry-row'+(state.selected===full?' selected':'');row.onclick=()=>selectPath(full);row.ondblclick=()=>{if(e.is_dir){setPath(full);refreshList();}else{downloadPath(full,false);}};const tdName=document.createElement('td');const nameWrap=document.createElement('div');nameWrap.className='name';const icon=document.createElement('span');icon.className='kind '+(e.is_dir?'dir':'file');icon.textContent=e.is_dir?uiTr('dir','DIR'):uiTr('file','FILE');const name=document.createElement('span');name.className='mono';name.textContent=e.name;nameWrap.appendChild(icon);nameWrap.appendChild(name);tdName.appendChild(nameWrap);const tdSize=document.createElement('td');tdSize.textContent=e.is_dir?'-':formatSize(e.size);const tdMtime=document.createElement('td');tdMtime.textContent=formatTime(e.mtime);const tdAct=document.createElement('td');if(e.is_dir){tdAct.appendChild(makeBtn(uiTr('go_to','Go To'),'',()=>{setPath(full);refreshList();}));tdAct.appendChild(makeBtn(uiTr('download','Download'),'',()=>downloadPath(full,true)));}else{tdAct.appendChild(makeBtn(uiTr('download','Download'),'',()=>downloadPath(full,false)));}tdAct.appendChild(makeBtn(uiTr('delete','Delete'),'btn-danger',()=>deletePath(full)));row.appendChild(tdName);row.appendChild(tdSize);row.appendChild(tdMtime);row.appendChild(tdAct);frag.appendChild(row);}rows.appendChild(frag);qs('countLabel').textContent=String(state.entries.length)+' '+uiTr('entries','entries')+(state.hasMore?' ('+uiTr('more','more')+')':'');}"
                        "function setListUIState(){const btn=qs('loadMoreBtn');if(!btn)return;btn.disabled=!!state.listLoadingMore||!state.hasMore;btn.textContent=state.listLoadingMore?'Loading...':'Load More';}"
                        "async function refreshList(append){const isAppend=!!append;try{let reqPath=normPath(qs('pathInput').value||state.path);if(isAppend){if(!state.hasMore||state.listLoadingMore)return;reqPath=state.path;state.listLoadingMore=true;setListUIState();}else{state.listOffset=0;state.hasMore=false;state.listLoadingMore=false;setPath(reqPath);}const off=isAppend?state.listOffset:0;const d=await apiJson('/api/list?path='+qp(reqPath)+'&offset='+String(off)+'&limit='+String(state.listLimit));const realPath=normPath(d.path||reqPath);setPath(realPath);const incoming=[...(d.entries||[])];incoming.sort((a,b)=>{if(!!a.is_dir!==!!b.is_dir)return a.is_dir?-1:1;return String(a.name).localeCompare(String(b.name));});if(isAppend&&realPath===state.path){state.entries=state.entries.concat(incoming);}else{state.entries=incoming;state.selected='';updateSelectionUI();}const next=Number(d.next_offset);state.listOffset=(Number.isFinite(next)&&next>=0)?next:(off+incoming.length);state.hasMore=!!d.has_more;renderRows();}catch(err){log('List failed: '+err.message);}finally{if(state.listLoadingMore)state.listLoadingMore=false;setListUIState();}}"
                        "function loadMore(){refreshList(true);}"
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
                        "async function chmodSelected(){const ent=selectedEntry();if(!ent){log('Select a file or folder first');return;}const p=state.selected;const ask=ent.is_dir?('Apply CHMOD 777 -R recursively to\\n'+p+' ?'):('Apply CHMOD 777 -R to\\n'+p+' ?');if(!confirm(ask))return;const finish=beginSelectedOp('Applying CHMOD 777 -R');try{const r=await apiJson('/api/chmod777?path='+qp(p),{method:'POST'});const touched=(r&&typeof r.touched==='number')?r.touched:0;log('CHMOD 777 -R applied '+p+' (touched '+touched+')');finish(true,'CHMOD 777 -R completed');refreshList();}catch(err){finish(false,'CHMOD 777 -R failed');log('CHMOD failed: '+err.message);}}"
                        "function splitUploadStatus(text){const s=String(text||'');const out={main:s,detail:'',file:''};if(s.startsWith('Uploading ')){const c=s.indexOf(': ');if(c>0){out.main=s.slice(0,c);const rest=s.slice(c+2);const parts=rest.split(' | ');if(parts.length>=3){out.file=parts[0];out.detail=parts.slice(1).join(' | ');}else{out.file=rest;}return out;}}if(s.startsWith('Uploaded ')||s.startsWith('Done ')){const parts=s.split(' | ');if(parts.length>=2){out.main=parts[0];out.detail=parts.slice(1).join(' | ');return out;}}if(s.startsWith('Skipped ')){out.main='Skipped';out.file=s.slice(8);return out;}return out;}"
                        "function setUploadProgress(percent,msg,force){const bar=qs('uploadProgress');const status=qs('uploadStatus');const mainEl=qs('uploadStatusMain')||status;const detailEl=qs('uploadStatusDetail');const fileEl=qs('uploadStatusFile');const pct=Math.max(0,Math.min(100,Math.floor(Number(percent)||0)));const now=Date.now();if(bar&&(force||pct!==state.uploadUiPct))bar.value=pct;if(msg!==undefined&&mainEl){let parts=(msg&&typeof msg==='object')?{main:String(msg.main||''),detail:String(msg.detail||''),file:String(msg.file||'')}:splitUploadStatus(msg);if(!parts.main)parts.main=String(msg);const key=parts.main+'\\n'+parts.detail+'\\n'+parts.file;const low=key.toLowerCase();if(force||now-state.uploadUiTs>=120||pct===0||pct===100||low.indexOf('failed')>=0||low.indexOf('done')>=0||low.indexOf('stopped')>=0){mainEl.textContent=parts.main;if(detailEl)detailEl.textContent=parts.detail||'';if(fileEl)fileEl.textContent=parts.file||'';state.uploadUiTs=now;state.uploadUiMsg=key;}}state.uploadUiPct=pct;}"
                        "function renderOverwriteMode(){const btn=qs('overwriteAllBtn');if(!btn)return;const all=!!state.overwriteAll;btn.textContent=all?'Overwrite: All':'Overwrite: Ask';btn.classList.remove('btn-ghost','sloth-btn-ghost','btn-danger','sloth-btn-danger');btn.classList.add(all?'btn-danger':'btn-ghost');btn.classList.add(all?'sloth-btn-danger':'sloth-btn-ghost');}"
                        "function toggleOverwriteMode(){if(state.uploading)return;state.overwriteAll=!state.overwriteAll;renderOverwriteMode();log('Overwrite mode: '+(state.overwriteAll?'all existing files':'ask per file'));}"
                        "function setUploadUIState(){const uploading=!!state.uploading;const busy=uploading;const start=qs('uploadStartBtn');const resume=qs('resumeUploadBtn');const stop=qs('uploadStopBtn');const over=qs('overwriteAllBtn');const pickFilesBtn=qs('pickFilesBtn');const pickFolderBtn=qs('pickFolderBtn');if(start)start.disabled=busy||!state.queueFiles.length;if(resume)resume.disabled=busy||!state.queueFiles.length;if(stop)stop.disabled=!uploading;if(over)over.disabled=busy;if(pickFilesBtn)pickFilesBtn.disabled=busy;if(pickFolderBtn)pickFolderBtn.disabled=busy;}"
                        "function queueTopLevelItems(){return Array.isArray(state.queueTopItems)?state.queueTopItems:[];}"
                        "function queueTopPush(rel,topMap,topItems){const s=cleanRelPath(rel||'');if(!s)return;const slash=s.indexOf('/');const top=slash>=0?s.slice(0,slash):s;if(!top)return;const isDir=slash>=0;const prev=topMap[top];if(prev){if(isDir)prev.is_dir=true;return;}const it={name:top,is_dir:isDir};topMap[top]=it;topItems.push(it);}"
                        "function queueChip(item,isMore){const chip=document.createElement('span');chip.className='mono';chip.style.display='inline-flex';chip.style.alignItems='center';chip.style.gap='.36rem';chip.style.maxWidth='100%';chip.style.padding='.22rem .52rem';chip.style.border='1px solid var(--sloth-line)';chip.style.borderRadius='999px';chip.style.background=isMore?'var(--panel-soft)':'linear-gradient(180deg,var(--panel-bg),var(--chip-bg))';chip.style.color='var(--sloth-ink)';chip.style.fontSize='.76rem';chip.style.fontWeight='600';chip.style.boxShadow='0 1px 0 rgba(255,255,255,.1)';if(isMore){chip.textContent=String(item||'');return chip;}const badge=document.createElement('span');badge.className='mono';badge.style.display='inline-flex';badge.style.alignItems='center';badge.style.justifyContent='center';badge.style.minWidth='3.2em';badge.style.padding='0 .34rem';badge.style.fontSize='.64rem';badge.style.border='1px solid var(--sloth-line)';badge.style.borderRadius='999px';badge.style.background=(item&&item.is_dir)?'var(--kind-dir-bg)':'var(--kind-file-bg)';badge.style.color=(item&&item.is_dir)?'var(--kind-dir-ink)':'var(--sloth-muted)';badge.textContent=(item&&item.is_dir)?uiTr('dir','DIR'):uiTr('file','FILE');const name=document.createElement('span');name.style.minWidth='0';name.style.overflow='hidden';name.style.textOverflow='ellipsis';name.style.whiteSpace='nowrap';name.textContent=String((item&&item.name)||'');chip.appendChild(badge);chip.appendChild(name);return chip;}"
                        "function renderQueueList(){const list=qs('queueList');if(!list)return;const items=queueTopLevelItems();list.textContent='';if(!items.length){list.style.display='none';return;}const maxRows=12;const total=items.length;for(let i=0;i<total&&i<maxRows;i++)list.appendChild(queueChip(items[i],false));if(total>maxRows)list.appendChild(queueChip('+'+String(total-maxRows)+' more',true));list.style.display='flex';}"
                        "function renderQueueInfo(){const info=qs('queueInfo');if(!info)return;if(!state.queueFiles.length){info.textContent='No selection';renderQueueList();setUploadUIState();return;}if(state.queuePreparing){info.textContent='Processing selection... '+String(state.queuePreparedCount)+'/'+String(state.queueFiles.length);}else{const fileWord=state.queueFiles.length===1?'file':'files';info.textContent='Selected '+state.queueFiles.length+' '+fileWord+' ('+formatSize(state.queueBytes)+')';}renderQueueList();setUploadUIState();}"
                        "function setQueue(files,_isFolder){if(state.uploading){log('Cannot change queue while upload is running');return;}const src=files?[...files]:[];state.queuePrepToken=(Number(state.queuePrepToken)||0)+1;const token=state.queuePrepToken;state.queueFiles=src;state.queueBytes=0;state.queueTopItems=[];state.queuePreparing=false;state.queuePreparedCount=0;state.uploadUiTs=0;state.uploadUiPct=-1;if(!src.length){renderQueueInfo();setUploadProgress(0,'Idle',true);return;}state.queuePreparing=true;renderQueueInfo();setUploadProgress(0,'Processing selection...',true);const topMap={};const topItems=[];const total=src.length;const step=()=>{if(token!==state.queuePrepToken)return;const start=state.queuePreparedCount;const end=Math.min(total,start+3000);for(let i=start;i<end;i++){if(token!==state.queuePrepToken)return;const f=src[i];if(!f||typeof f.size!=='number')continue;const rel=relPathOf(f);if(!rel)continue;try{if(!f.__rel_path)f.__rel_path=rel;}catch(e){}state.queueBytes+=Number(f.size)||0;queueTopPush(rel,topMap,topItems);}state.queuePreparedCount=end;state.queueTopItems=topItems.slice();renderQueueInfo();if(end<total){setTimeout(step,0);return;}state.queuePreparing=false;renderQueueInfo();if(!state.uploading)setUploadProgress(0,'Ready',true);log('Selected '+state.queueFiles.length+' file(s), '+formatSize(state.queueBytes));};setTimeout(step,0);}"
                        "function pickFiles(){if(state.uploading){log('Stop current upload first');return;}const info=qs('queueInfo');if(info)info.textContent='Waiting for file selection...';setUploadProgress(0,'Waiting for file selection...',true);qs('uploadFiles').click();}"
                        "function pickFolder(){if(state.uploading){log('Stop current upload first');return;}const info=qs('queueInfo');if(info)info.textContent='Waiting for folder selection...';setUploadProgress(0,'Waiting for folder selection...',true);qs('uploadFolder').click();}"
                        "function stopUpload(){if(!state.uploading){log('No active upload');return;}state.cancelUpload=true;const xhr=state.currentXhr;if(xhr){try{xhr.abort();}catch(e){}}setUploadProgress(qs('uploadProgress')?qs('uploadProgress').value:0,'Stopping upload...',true);log('Stop upload requested');}"
                        "function uploadOne(dest,file,onProgress){return new Promise((resolve,reject)=>{const xhr=new XMLHttpRequest();state.currentXhr=xhr;xhr.open('PUT',api+'/api/upload?path='+qp(dest));xhr.setRequestHeader('Content-Type','application/octet-stream');xhr.upload.onprogress=(ev)=>{if(ev.lengthComputable&&onProgress)onProgress(ev.loaded,ev.total);};xhr.onerror=()=>{if(state.currentXhr===xhr)state.currentXhr=null;reject(new Error('network error'));};xhr.onabort=()=>{if(state.currentXhr===xhr)state.currentXhr=null;reject(new Error('upload canceled'));};xhr.onload=()=>{if(state.currentXhr===xhr)state.currentXhr=null;if(xhr.status>=200&&xhr.status<300)resolve();else reject(new Error(xhr.responseText||('HTTP '+xhr.status)));};xhr.send(file);});}"
                        "async function shouldUploadToPath(dst,fileSize,resumeMode){const st=await apiJson('/api/stat?path='+qp(dst));if(!st||!st.exists)return true;if(st.is_dir){const ok=confirm('Target exists as folder:\\n'+dst+'\\nOK: skip this item\\nCancel: stop upload');if(ok){log('Skipped existing folder '+dst);return false;}throw new Error('upload canceled');}const remoteSize=Number(st.size)||0;const localSize=Number(fileSize)||0;if(resumeMode&&remoteSize===localSize){log('Resume skipped same-size file '+dst);return false;}if(resumeMode)return true;if(state.overwriteAll)return true;if(!confirm('Overwrite existing file?\\n'+dst)){log('Skipped existing '+dst);return false;}return true;}"
                        "async function runUpload(resumeMode){if(state.uploading){log('Upload already running');return;}if(!state.queueFiles.length){log('No files selected. Use Browse Files or Browse Folder.');return;}state.uploading=true;state.cancelUpload=false;setUploadUIState();const files=state.queueFiles.slice();const base=state.path;const totalBytes=Math.max(1,files.reduce((acc,f)=>acc+(Number(f&&f.size)||0),0));let doneBytes=0;let uploaded=0;let skipped=0;let speedBps=0;let canceled=false;let failed=false;const startTs=Date.now();let lastTs=startTs;let lastBytes=0;setUploadProgress(0,(resumeMode?'Resuming ':'Uploading ')+'0/'+files.length,true);for(let i=0;i<files.length;i++){const f=files[i];if(state.cancelUpload){canceled=true;state.queueFiles=files.slice(i);break;}const rel=relPathOf(f);if(!rel)continue;const fileSize=Number(f.size)||0;const dst=join(base,rel);let allow=false;try{allow=await shouldUploadToPath(dst,fileSize,resumeMode);}catch(err){if(state.cancelUpload||/canceled/i.test(String(err&&err.message||''))){canceled=true;state.queueFiles=files.slice(i);break;}failed=true;state.queueFiles=files.slice(i);setUploadProgress((doneBytes/totalBytes)*100,'Upload failed',true);log('Pre-check failed '+dst+': '+err.message);break;}if(!allow){skipped+=1;doneBytes+=fileSize;setUploadProgress((doneBytes/totalBytes)*100,'Skipped '+rel,false);continue;}try{await uploadOne(dst,f,(loaded,total)=>{const t=Number(total)||1;const now=Date.now();const doneNow=doneBytes+loaded;const dt=(now-lastTs)/1000;if(dt>=0.2){const inst=(doneNow-lastBytes)/Math.max(dt,0.001);speedBps=speedBps>0?(speedBps*0.7+inst*0.3):inst;lastTs=now;lastBytes=doneNow;}const avgBps=doneNow/Math.max((now-startTs)/1000,0.001);const showBps=speedBps>0?speedBps:avgBps;const remain=Math.max(0,totalBytes-doneNow);const eta=remain/Math.max(avgBps,1);const pct=(doneNow/Math.max(totalBytes,t))*100;setUploadProgress(pct,'Uploading '+(uploaded+1)+'/'+files.length+': '+rel+' | '+formatRate(showBps)+' | ETA '+formatEta(eta),false);});doneBytes+=fileSize;uploaded+=1;const avgDoneBps=doneBytes/Math.max((Date.now()-startTs)/1000,0.001);setUploadProgress((doneBytes/totalBytes)*100,'Uploaded '+uploaded+'/'+files.length+' | '+formatRate(avgDoneBps),true);log('Uploaded '+dst);}catch(err){if(state.cancelUpload||/canceled/i.test(String(err&&err.message||''))){canceled=true;state.queueFiles=files.slice(i);break;}failed=true;state.queueFiles=files.slice(i);setUploadProgress((doneBytes/totalBytes)*100,'Upload failed',true);log('Upload failed '+dst+': '+err.message);break;}}if(!canceled&&!failed){state.queueFiles=[];state.queueBytes=0;state.queueTopItems=[];state.queuePreparing=false;state.queuePreparedCount=0;state.queuePrepToken=(Number(state.queuePrepToken)||0)+1;const totalSec=Math.max((Date.now()-startTs)/1000,0.001);let doneMsg='Done '+uploaded+'/'+files.length;if(skipped>0)doneMsg+=' (skipped '+skipped+')';doneMsg+=' | Avg '+formatRate(doneBytes/totalSec);setUploadProgress(100,doneMsg,true);}if(canceled){const remainCount=state.queueFiles.length;const pct=(doneBytes/totalBytes)*100;setUploadProgress(pct,'Upload stopped ('+remainCount+' remaining)',true);log('Upload stopped. Remaining '+remainCount+' file(s).');}state.uploading=false;state.cancelUpload=false;state.currentXhr=null;qs('uploadFiles').value='';qs('uploadFolder').value='';state.queueBytes=computeQueueBytes(state.queueFiles);renderQueueInfo();setUploadUIState();if(uploaded>0||skipped>0)refreshList(false);}"
                        "async function startUpload(){return runUpload(false);}"
                        "async function resumeUpload(){return runUpload(true);}"
                        "async function onDrop(ev){ev.preventDefault();qs('dropZone').classList.remove('dragover');if(state.uploading){log('Stop current upload before adding more files');return;}const info=qs('queueInfo');if(info)info.textContent='Reading dropped items...';setUploadProgress(0,'Reading dropped items...',true);try{const files=await collectDropFiles(ev.dataTransfer);if(!files.length){log('No files detected from drop.');setUploadProgress(0,'Idle',true);return;}setQueue(files,false);}catch(err){log('Drop parse failed: '+err.message);setUploadProgress(0,'Idle',true);}}"
                        "qs('refreshBtn').addEventListener('click',()=>refreshList(false));qs('upBtn').addEventListener('click',goUp);qs('rootBtn').addEventListener('click',()=>{setPath('/');refreshList(false);});qs('loadMoreBtn').addEventListener('click',loadMore);"
                        "qs('mkdirBtn').addEventListener('click',mkdirPath);qs('deleteSelectedBtn').addEventListener('click',()=>deletePath(state.selected));qs('renameBtn').addEventListener('click',renameSelected);qs('moveBtn').addEventListener('click',moveSelected);qs('copyBtn').addEventListener('click',copySelected);qs('chmodBtn').addEventListener('click',chmodSelected);qs('goSelectedBtn').addEventListener('click',goSelected);qs('downloadSelectedBtn').addEventListener('click',downloadSelected);"
                        "qs('clearLogBtn').addEventListener('click',()=>{const el=qs('log');if(el)el.textContent='';});"
                        "qs('themeToggleBtn').addEventListener('click',toggleTheme);qs('downloadConfigBtn').addEventListener('click',downloadConfig);qs('uploadConfigBtn').addEventListener('click',pickConfigUpload);qs('resetConfigBtn').addEventListener('click',resetConfig);qs('stopBtn').addEventListener('click',stopPayload);"
                        "qs('pickFilesBtn').addEventListener('click',pickFiles);qs('pickFolderBtn').addEventListener('click',pickFolder);qs('uploadStartBtn').addEventListener('click',startUpload);qs('resumeUploadBtn').addEventListener('click',resumeUpload);qs('uploadStopBtn').addEventListener('click',stopUpload);qs('overwriteAllBtn').addEventListener('click',toggleOverwriteMode);"
                        "qs('uploadFiles').addEventListener('change',()=>setQueue(qs('uploadFiles').files,false));"
                        "qs('uploadFolder').addEventListener('change',()=>setQueue(qs('uploadFolder').files,true));"
                        "qs('uploadConfigInput').addEventListener('change',uploadConfig);"
                        "qs('dropZone').addEventListener('dragover',(ev)=>{ev.preventDefault();if(!state.uploading)qs('dropZone').classList.add('dragover');});"
                        "qs('dropZone').addEventListener('dragleave',()=>qs('dropZone').classList.remove('dragover'));"
                        "qs('dropZone').addEventListener('drop',onDrop);"
                        "qs('pathInput').addEventListener('keydown',(ev)=>{if(ev.key==='Enter'){ev.preventDefault();refreshList();}});"
                        "qs('renameInput').addEventListener('keydown',(ev)=>{if(ev.key==='Enter'){ev.preventDefault();renameSelected();}});"
                        "qs('moveInput').addEventListener('keydown',(ev)=>{if(ev.key==='Enter'){ev.preventDefault();moveSelected();}});"
                        "initTheme();setPath('/');updateSelectionUI();setSelectedOpProgress(0,uiTr('selected_action_idle','Selected action: idle'));renderQueueInfo();renderOverwriteMode();setUploadUIState();setListUIState();refreshList(false);keepAlive();setInterval(keepAlive,15000);"
                        "</script>");
    rc |= strbuf_append(&html,
                        "<script>"
                        "(function(){"
                        "const I18N={"
                        "en:{api_port:'API Port',debug_port:'Debug Port',mode:'Mode',secure:'Secure',insecure:'Insecure',download_config:'Download Config',upload_config:'Upload Config',reset_config:'Reset Config',buy_me_coffee:'Buy Me a Coffee',stop_payload:'Stop PS5Drive',upload:'Upload',browse_files:'Browse Files',browse_folder:'Browse Folder',drop_hint:'Drop files/folders here',no_selection:'No selection',idle:'Idle',resume:'Resume',stop:'Stop',upload_note:'Uploads go to the current directory shown in Current Path.',upload_target:'Upload target',create_folder:'Create Folder',create:'Create',selected_item:'Selected Item',nothing_selected:'Nothing selected',go_to:'Go To',download:'Download',delete:'Delete',rename:'Rename',move_to:'Move To',copy_to:'Copy To',chmod:'CHMOD 777 -R',move_tip:'Move/Copy tip: use absolute path (example: /data/ps5drive). If destination is an existing folder, item name is kept.',files:'Files',games:'Games',refresh:'Refresh',up:'Up',root:'Root',load_more:'Load More',loading:'Loading...',current_path:'Current Path',name:'Name',size:'Size',mtime:'MTime',action:'Action',activity_log:'Activity Log',clear:'Clear',entries:'entries',more:'more',selected_prefix:'Selected',selected_action_idle:'Selected action: idle',games_scanner:'Games Scanner',scan:'Scan',scan_ready:'Ready to scan.',games_none:'No games found.',games_count_suffix:'games',games_scan_failed:'Games scan failed',title_id:'Title ID',path:'Path',open:'Open',scanning:'Scanning',games_found_suffix:'game(s) found',truncated:'(truncated)',cover:'Cover',metadata:'Metadata',param_sfo:'param.sfo',games_preset_info:'Preset scan paths: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Storage filter',all:'All',yes:'Yes',no:'No',storage:'Storage',empty_directory:'(empty directory)',dir:'DIR',file:'FILE'},"
                        "es:{api_port:'Puerto API',debug_port:'Puerto debug',mode:'Modo',secure:'Seguro',insecure:'Inseguro',download_config:'Descargar config',upload_config:'Subir config',reset_config:'Restablecer config',buy_me_coffee:'Invítame un café',stop_payload:'Detener PS5Drive',upload:'Subir',browse_files:'Elegir archivos',browse_folder:'Elegir carpeta',drop_hint:'Suelta archivos/carpetas aquí',no_selection:'Sin selección',idle:'Inactivo',resume:'Reanudar',stop:'Detener',upload_note:'Las subidas van al directorio actual mostrado en Ruta actual.',upload_target:'Destino de subida',create_folder:'Crear carpeta',create:'Crear',selected_item:'Elemento seleccionado',nothing_selected:'Nada seleccionado',go_to:'Ir',download:'Descargar',delete:'Eliminar',rename:'Renombrar',move_to:'Mover a',copy_to:'Copiar a',chmod:'CHMOD 777 -R',move_tip:'Consejo mover/copiar: usa ruta absoluta (ejemplo: /data/ps5drive). Si el destino existe como carpeta, se mantiene el nombre.',files:'Archivos',games:'Juegos',refresh:'Actualizar',up:'Arriba',root:'Raíz',load_more:'Cargar más',loading:'Cargando...',current_path:'Ruta actual',name:'Nombre',size:'Tamaño',mtime:'Modificado',action:'Acción',activity_log:'Registro',clear:'Limpiar',entries:'entradas',more:'más',selected_prefix:'Seleccionado',selected_action_idle:'Acción seleccionada: inactiva',games_scanner:'Escáner de juegos',scan:'Escanear',scan_ready:'Listo para escanear.',games_none:'No se encontraron juegos.',games_count_suffix:'juegos',games_scan_failed:'Error de escaneo',title_id:'Title ID',path:'Ruta',open:'Abrir',scanning:'Escaneando',games_found_suffix:'juego(s) encontrados',truncated:'(truncado)',cover:'Portada',metadata:'Metadatos',param_sfo:'param.sfo',games_preset_info:'Rutas predefinidas: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Filtro de almacenamiento',all:'Todo',yes:'Sí',no:'No',storage:'Almacenamiento',empty_directory:'(directorio vacío)',dir:'DIR',file:'ARCH'},"
                        "fr:{api_port:'Port API',debug_port:'Port debug',mode:'Mode',secure:'Sécurisé',insecure:'Non sécurisé',download_config:'Télécharger config',upload_config:'Envoyer config',reset_config:'Réinitialiser config',buy_me_coffee:'Offrez-moi un café',stop_payload:'Arrêter PS5Drive',upload:'Envoyer',browse_files:'Choisir fichiers',browse_folder:'Choisir dossier',drop_hint:'Déposez des fichiers/dossiers ici',no_selection:'Aucune sélection',idle:'Inactif',resume:'Reprendre',stop:'Arrêter',upload_note:'Les uploads vont vers le dossier courant affiché dans Chemin actuel.',upload_target:'Destination upload',create_folder:'Créer dossier',create:'Créer',selected_item:'Élément sélectionné',nothing_selected:'Rien de sélectionné',go_to:'Ouvrir',download:'Télécharger',delete:'Supprimer',rename:'Renommer',move_to:'Déplacer vers',copy_to:'Copier vers',chmod:'CHMOD 777 -R',move_tip:'Astuce déplacer/copier: utilisez un chemin absolu (ex: /data/ps5drive). Si destination est un dossier existant, le nom est conservé.',files:'Fichiers',games:'Jeux',refresh:'Actualiser',up:'Parent',root:'Racine',load_more:'Charger plus',loading:'Chargement...',current_path:'Chemin actuel',name:'Nom',size:'Taille',mtime:'Date',action:'Action',activity_log:'Journal',clear:'Effacer',entries:'entrées',more:'plus',selected_prefix:'Sélectionné',selected_action_idle:'Action sélectionnée : inactive',games_scanner:'Scanner de jeux',scan:'Scanner',scan_ready:'Prêt à scanner.',games_none:'Aucun jeu trouvé.',games_count_suffix:'jeux',games_scan_failed:'Échec du scan',title_id:'Title ID',path:'Chemin',open:'Ouvrir',scanning:'Scan en cours',games_found_suffix:'jeu(x) trouvé(s)',truncated:'(tronqué)',cover:'Jaquette',metadata:'Métadonnées',param_sfo:'param.sfo',games_preset_info:'Chemins de scan prédéfinis : etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Filtre de stockage',all:'Tous',yes:'Oui',no:'Non',storage:'Stockage',empty_directory:'(dossier vide)',dir:'DIR',file:'FICH'},"
                        "de:{api_port:'API-Port',debug_port:'Debug-Port',mode:'Modus',secure:'Sicher',insecure:'Unsicher',download_config:'Config herunterladen',upload_config:'Config hochladen',reset_config:'Config zurücksetzen',buy_me_coffee:'Kauf mir einen Kaffee',stop_payload:'PS5Drive stoppen',upload:'Hochladen',browse_files:'Dateien wählen',browse_folder:'Ordner wählen',drop_hint:'Dateien/Ordner hier ablegen',no_selection:'Keine Auswahl',idle:'Leerlauf',resume:'Fortsetzen',stop:'Stop',upload_note:'Uploads gehen in den aktuellen Ordner aus Aktueller Pfad.',upload_target:'Upload-Ziel',create_folder:'Ordner erstellen',create:'Erstellen',selected_item:'Ausgewähltes Element',nothing_selected:'Nichts ausgewählt',go_to:'Öffnen',download:'Download',delete:'Löschen',rename:'Umbenennen',move_to:'Verschieben nach',copy_to:'Kopieren nach',chmod:'CHMOD 777 -R',move_tip:'Tipp: absoluten Pfad nutzen (z.B. /data/ps5drive). Wenn Ziel ein vorhandener Ordner ist, bleibt der Name gleich.',files:'Dateien',games:'Spiele',refresh:'Aktualisieren',up:'Hoch',root:'Root',load_more:'Mehr laden',loading:'Lädt...',current_path:'Aktueller Pfad',name:'Name',size:'Größe',mtime:'Zeit',action:'Aktion',activity_log:'Aktivitätsprotokoll',clear:'Leeren',entries:'Einträge',more:'mehr',selected_prefix:'Ausgewählt',selected_action_idle:'Ausgewählte Aktion: Leerlauf',games_scanner:'Spiele-Scanner',scan:'Scannen',scan_ready:'Bereit zum Scannen.',games_none:'Keine Spiele gefunden.',games_count_suffix:'Spiele',games_scan_failed:'Spiele-Scan fehlgeschlagen',title_id:'Title ID',path:'Pfad',open:'Öffnen',scanning:'Scanne',games_found_suffix:'Spiel(e) gefunden',truncated:'(gekürzt)',cover:'Cover',metadata:'Metadaten',param_sfo:'param.sfo',games_preset_info:'Voreingestellte Scan-Pfade: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Speicherfilter',all:'Alle',yes:'Ja',no:'Nein',storage:'Speicher',empty_directory:'(leeres Verzeichnis)',dir:'DIR',file:'DATEI'},"
                        "ja:{api_port:'APIポート',debug_port:'デバッグポート',mode:'モード',secure:'セキュア',insecure:'インセキュア',download_config:'設定をダウンロード',upload_config:'設定をアップロード',reset_config:'設定をリセット',buy_me_coffee:'コーヒーをおごる',stop_payload:'PS5Driveを停止',upload:'アップロード',browse_files:'ファイルを選択',browse_folder:'フォルダーを選択',drop_hint:'ここにファイル/フォルダーをドロップ',no_selection:'未選択',idle:'待機中',resume:'再開',stop:'停止',upload_note:'アップロード先は「現在のパス」です。',upload_target:'アップロード先',create_folder:'フォルダー作成',create:'作成',selected_item:'選択中',nothing_selected:'何も選択されていません',go_to:'移動',download:'ダウンロード',delete:'削除',rename:'名前変更',move_to:'移動先',copy_to:'コピー先',chmod:'CHMOD 777 -R',move_tip:'ヒント: 絶対パスを使用してください（例: /data/ps5drive）。既存フォルダーを指定すると名前を維持します。',files:'ファイル',games:'ゲーム',refresh:'更新',up:'上へ',root:'ルート',load_more:'さらに読み込む',loading:'読み込み中...',current_path:'現在のパス',name:'名前',size:'サイズ',mtime:'更新時刻',action:'操作',activity_log:'アクティビティログ',clear:'クリア',entries:'件',more:'続きあり',selected_prefix:'選択',selected_action_idle:'選択アクション: 待機中',games_scanner:'ゲームスキャナー',scan:'スキャン',scan_ready:'スキャン待機中。',games_none:'ゲームが見つかりません。',games_count_suffix:'件',games_scan_failed:'ゲームスキャン失敗',title_id:'Title ID',path:'パス',open:'開く',scanning:'スキャン中',games_found_suffix:'件見つかりました',truncated:'(省略あり)',cover:'カバー',metadata:'メタデータ',param_sfo:'param.sfo',games_preset_info:'プリセットスキャンパス: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'ストレージフィルター',all:'すべて',yes:'はい',no:'いいえ',storage:'ストレージ',empty_directory:'(空のフォルダー)',dir:'DIR',file:'FILE'},"
                        "'zh-cn':{api_port:'API端口',debug_port:'调试端口',mode:'模式',secure:'安全',insecure:'不安全',download_config:'下载配置',upload_config:'上传配置',reset_config:'重置配置',buy_me_coffee:'请我喝咖啡',stop_payload:'停止 PS5Drive',upload:'上传',browse_files:'选择文件',browse_folder:'选择文件夹',drop_hint:'拖放文件/文件夹到这里',no_selection:'未选择',idle:'空闲',resume:'续传',stop:'停止',upload_note:'上传目标为“当前路径”显示的目录。',upload_target:'上传目标',create_folder:'创建文件夹',create:'创建',selected_item:'已选项目',nothing_selected:'未选择任何项目',go_to:'进入',download:'下载',delete:'删除',rename:'重命名',move_to:'移动到',copy_to:'复制到',chmod:'CHMOD 777 -R',move_tip:'提示：使用绝对路径（例如 /data/ps5drive）。若目标是已存在目录，则保留原名称。',files:'文件',games:'游戏',refresh:'刷新',up:'上级',root:'根目录',load_more:'加载更多',loading:'加载中...',current_path:'当前路径',name:'名称',size:'大小',mtime:'修改时间',action:'操作',activity_log:'活动日志',clear:'清空',entries:'项',more:'更多',selected_prefix:'已选择',selected_action_idle:'已选操作：空闲',games_scanner:'游戏扫描',scan:'扫描',scan_ready:'准备扫描。',games_none:'未找到游戏。',games_count_suffix:'个游戏',games_scan_failed:'游戏扫描失败',title_id:'Title ID',path:'路径',open:'打开',scanning:'扫描中',games_found_suffix:'个匹配',truncated:'(已截断)',cover:'封面',metadata:'元数据',param_sfo:'param.sfo',games_preset_info:'预设扫描路径：etaHEN/games，etaHEN/homebrew，games，homebrew',storage_filter:'存储筛选',all:'全部',yes:'是',no:'否',storage:'存储',empty_directory:'（空目录）',dir:'目录',file:'文件'},"
                        "'zh-tw':{api_port:'API 連接埠',debug_port:'偵錯連接埠',mode:'模式',secure:'安全',insecure:'不安全',download_config:'下載設定',upload_config:'上傳設定',reset_config:'重設設定',buy_me_coffee:'請我喝咖啡',stop_payload:'停止 PS5Drive',upload:'上傳',browse_files:'選擇檔案',browse_folder:'選擇資料夾',drop_hint:'將檔案/資料夾拖放到這裡',no_selection:'未選擇',idle:'閒置',resume:'續傳',stop:'停止',upload_note:'上傳目標為「目前路徑」顯示的目錄。',upload_target:'上傳目標',create_folder:'建立資料夾',create:'建立',selected_item:'已選項目',nothing_selected:'未選擇任何項目',go_to:'前往',download:'下載',delete:'刪除',rename:'重新命名',move_to:'移動到',copy_to:'複製到',chmod:'CHMOD 777 -R',move_tip:'提示：使用絕對路徑（例如 /data/ps5drive）。若目標為既有資料夾，將保留原名稱。',files:'檔案',games:'遊戲',refresh:'重新整理',up:'上層',root:'根目錄',load_more:'載入更多',loading:'載入中...',current_path:'目前路徑',name:'名稱',size:'大小',mtime:'修改時間',action:'操作',activity_log:'活動記錄',clear:'清空',entries:'項',more:'更多',selected_prefix:'已選擇',selected_action_idle:'已選操作：閒置',games_scanner:'遊戲掃描',scan:'掃描',scan_ready:'準備掃描。',games_none:'未找到遊戲。',games_count_suffix:'個遊戲',games_scan_failed:'遊戲掃描失敗',title_id:'Title ID',path:'路徑',open:'開啟',scanning:'掃描中',games_found_suffix:'個符合',truncated:'（已截斷）',cover:'封面',metadata:'中繼資料',param_sfo:'param.sfo',games_preset_info:'預設掃描路徑：etaHEN/games，etaHEN/homebrew，games，homebrew',storage_filter:'儲存裝置篩選',all:'全部',yes:'是',no:'否',storage:'儲存裝置',empty_directory:'（空資料夾）',dir:'目錄',file:'檔案'},"
                        "hi:{api_port:'API पोर्ट',debug_port:'डिबग पोर्ट',mode:'मोड',secure:'सुरक्षित',insecure:'असुरक्षित',download_config:'कॉन्फिग डाउनलोड',upload_config:'कॉन्फिग अपलोड',reset_config:'कॉन्फिग रीसेट',buy_me_coffee:'मुझे कॉफी पिलाएं',stop_payload:'PS5Drive रोकें',upload:'अपलोड',browse_files:'फाइलें चुनें',browse_folder:'फोल्डर चुनें',drop_hint:'फाइलें या फोल्डर यहां छोड़ें',no_selection:'कोई चयन नहीं',idle:'खाली',resume:'जारी रखें',stop:'रोकें',upload_note:'अपलोड वर्तमान पथ में दिखाए गए फोल्डर में जाएगा।',upload_target:'अपलोड लक्ष्य',create_folder:'फोल्डर बनाएं',create:'बनाएं',selected_item:'चयनित आइटम',nothing_selected:'कुछ चयनित नहीं',go_to:'खोलें',download:'डाउनलोड',delete:'हटाएं',rename:'नाम बदलें',move_to:'स्थानांतरित करें',copy_to:'कॉपी करें',chmod:'CHMOD 777 -R',move_tip:'मूव या कॉपी टिप: पूर्ण पथ उपयोग करें (उदाहरण: /data/ps5drive)। यदि गंतव्य फोल्डर मौजूद है तो नाम वही रहेगा।',files:'फाइलें',games:'गेम्स',refresh:'रिफ्रेश',up:'ऊपर',root:'रूट',load_more:'और लोड करें',loading:'लोड हो रहा है...',current_path:'वर्तमान पथ',name:'नाम',size:'आकार',mtime:'समय',action:'क्रिया',activity_log:'गतिविधि लॉग',clear:'साफ करें',entries:'एंट्री',more:'और',selected_prefix:'चयनित',selected_action_idle:'चयनित क्रिया: खाली',games_scanner:'गेम स्कैनर',scan:'स्कैन',scan_ready:'स्कैन के लिए तैयार।',games_none:'कोई गेम नहीं मिला।',games_count_suffix:'गेम',games_scan_failed:'गेम स्कैन विफल',title_id:'Title ID',path:'पथ',open:'खोलें',scanning:'स्कैन हो रहा है',games_found_suffix:'गेम मिले',truncated:'(संक्षिप्त)',cover:'कवर',metadata:'मेटाडेटा',param_sfo:'param.sfo',games_preset_info:'प्रीसेट स्कैन पथ: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'स्टोरेज फिल्टर',all:'सभी',yes:'हाँ',no:'नहीं',storage:'स्टोरेज',empty_directory:'(खाली डायरेक्टरी)',dir:'DIR',file:'FILE'},"
                        "ar:{api_port:'منفذ API',debug_port:'منفذ التصحيح',mode:'الوضع',secure:'آمن',insecure:'غير آمن',download_config:'تنزيل الإعدادات',upload_config:'رفع الإعدادات',reset_config:'إعادة ضبط الإعدادات',buy_me_coffee:'اشتر لي قهوة',stop_payload:'إيقاف PS5Drive',upload:'رفع',browse_files:'اختيار الملفات',browse_folder:'اختيار المجلد',drop_hint:'أسقط الملفات أو المجلدات هنا',no_selection:'لا يوجد تحديد',idle:'خامل',resume:'استئناف',stop:'إيقاف',upload_note:'سيتم الرفع إلى الدليل الحالي الظاهر في المسار الحالي.',upload_target:'هدف الرفع',create_folder:'إنشاء مجلد',create:'إنشاء',selected_item:'العنصر المحدد',nothing_selected:'لم يتم تحديد شيء',go_to:'فتح',download:'تنزيل',delete:'حذف',rename:'إعادة تسمية',move_to:'نقل إلى',copy_to:'نسخ إلى',chmod:'CHMOD 777 -R',move_tip:'نصيحة نقل أو نسخ: استخدم مسارا مطلقا مثل /data/ps5drive. إذا كانت الوجهة مجلدا موجودا فسيبقى الاسم كما هو.',files:'ملفات',games:'ألعاب',refresh:'تحديث',up:'أعلى',root:'الجذر',load_more:'تحميل المزيد',loading:'جار التحميل...',current_path:'المسار الحالي',name:'الاسم',size:'الحجم',mtime:'وقت التعديل',action:'إجراء',activity_log:'سجل النشاط',clear:'مسح',entries:'عناصر',more:'المزيد',selected_prefix:'المحدد',selected_action_idle:'الإجراء المحدد: خامل',games_scanner:'ماسح الألعاب',scan:'فحص',scan_ready:'جاهز للفحص.',games_none:'لم يتم العثور على ألعاب.',games_count_suffix:'ألعاب',games_scan_failed:'فشل فحص الألعاب',title_id:'Title ID',path:'المسار',open:'فتح',scanning:'جار الفحص',games_found_suffix:'تم العثور على ألعاب',truncated:'(مقتطع)',cover:'غلاف',metadata:'بيانات وصفية',param_sfo:'param.sfo',games_preset_info:'مسارات الفحص المسبقة: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'فلتر التخزين',all:'الكل',yes:'نعم',no:'لا',storage:'التخزين',empty_directory:'(مجلد فارغ)',dir:'DIR',file:'FILE'},"
                        "bn:{api_port:'API পোর্ট',debug_port:'ডিবাগ পোর্ট',mode:'মোড',secure:'সুরক্ষিত',insecure:'অসুরক্ষিত',download_config:'কনফিগ ডাউনলোড',upload_config:'কনফিগ আপলোড',reset_config:'কনফিগ রিসেট',buy_me_coffee:'আমাকে কফি কিনে দিন',stop_payload:'PS5Drive বন্ধ করুন',upload:'আপলোড',browse_files:'ফাইল বাছাই',browse_folder:'ফোল্ডার বাছাই',drop_hint:'ফাইল বা ফোল্ডার এখানে ড্রপ করুন',no_selection:'কোনো নির্বাচন নেই',idle:'নিষ্ক্রিয়',resume:'চালিয়ে যান',stop:'বন্ধ',upload_note:'আপলোড বর্তমান পাথে দেখানো ডিরেক্টরিতে যাবে।',upload_target:'আপলোড গন্তব্য',create_folder:'ফোল্ডার তৈরি',create:'তৈরি',selected_item:'নির্বাচিত আইটেম',nothing_selected:'কিছুই নির্বাচিত নয়',go_to:'খুলুন',download:'ডাউনলোড',delete:'মুছুন',rename:'নাম বদলান',move_to:'সরান',copy_to:'কপি করুন',chmod:'CHMOD 777 -R',move_tip:'মুভ বা কপি টিপ: পূর্ণ পাথ ব্যবহার করুন (যেমন /data/ps5drive)। গন্তব্যে ফোল্ডার থাকলে নাম একই থাকবে।',files:'ফাইল',games:'গেম',refresh:'রিফ্রেশ',up:'উপরে',root:'রুট',load_more:'আরও লোড করুন',loading:'লোড হচ্ছে...',current_path:'বর্তমান পাথ',name:'নাম',size:'সাইজ',mtime:'সময়',action:'অ্যাকশন',activity_log:'অ্যাক্টিভিটি লগ',clear:'মুছুন',entries:'এন্ট্রি',more:'আরও',selected_prefix:'নির্বাচিত',selected_action_idle:'নির্বাচিত অ্যাকশন: নিষ্ক্রিয়',games_scanner:'গেম স্ক্যানার',scan:'স্ক্যান',scan_ready:'স্ক্যানের জন্য প্রস্তুত।',games_none:'কোনো গেম পাওয়া যায়নি।',games_count_suffix:'গেম',games_scan_failed:'গেম স্ক্যান ব্যর্থ',title_id:'Title ID',path:'পাথ',open:'খুলুন',scanning:'স্ক্যান হচ্ছে',games_found_suffix:'গেম পাওয়া গেছে',truncated:'(সংক্ষিপ্ত)',cover:'কভার',metadata:'মেটাডেটা',param_sfo:'param.sfo',games_preset_info:'প্রিসেট স্ক্যান পাথ: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'স্টোরেজ ফিল্টার',all:'সব',yes:'হ্যাঁ',no:'না',storage:'স্টোরেজ',empty_directory:'(খালি ডিরেক্টরি)',dir:'DIR',file:'FILE'},"
                        "'pt-br':{api_port:'Porta da API',debug_port:'Porta de debug',mode:'Modo',secure:'Seguro',insecure:'Inseguro',download_config:'Baixar config',upload_config:'Enviar config',reset_config:'Redefinir config',buy_me_coffee:'Pague um café para mim',stop_payload:'Parar PS5Drive',upload:'Enviar',browse_files:'Escolher arquivos',browse_folder:'Escolher pasta',drop_hint:'Solte arquivos ou pastas aqui',no_selection:'Sem seleção',idle:'Ocioso',resume:'Retomar',stop:'Parar',upload_note:'Os uploads vão para o diretório atual mostrado em Caminho atual.',upload_target:'Destino do upload',create_folder:'Criar pasta',create:'Criar',selected_item:'Item selecionado',nothing_selected:'Nada selecionado',go_to:'Abrir',download:'Baixar',delete:'Excluir',rename:'Renomear',move_to:'Mover para',copy_to:'Copiar para',chmod:'CHMOD 777 -R',move_tip:'Dica de mover ou copiar: use caminho absoluto (exemplo: /data/ps5drive). Se o destino for uma pasta existente, o nome é mantido.',files:'Arquivos',games:'Jogos',refresh:'Atualizar',up:'Acima',root:'Raiz',load_more:'Carregar mais',loading:'Carregando...',current_path:'Caminho atual',name:'Nome',size:'Tamanho',mtime:'Data',action:'Ação',activity_log:'Log de atividade',clear:'Limpar',entries:'entradas',more:'mais',selected_prefix:'Selecionado',selected_action_idle:'Ação selecionada: ociosa',games_scanner:'Scanner de jogos',scan:'Escanear',scan_ready:'Pronto para escanear.',games_none:'Nenhum jogo encontrado.',games_count_suffix:'jogos',games_scan_failed:'Falha no escaneamento',title_id:'Title ID',path:'Caminho',open:'Abrir',scanning:'Escaneando',games_found_suffix:'jogo(s) encontrado(s)',truncated:'(truncado)',cover:'Capa',metadata:'Metadados',param_sfo:'param.sfo',games_preset_info:'Caminhos predefinidos: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Filtro de armazenamento',all:'Todos',yes:'Sim',no:'Não',storage:'Armazenamento',empty_directory:'(diretório vazio)',dir:'DIR',file:'ARQ'},"
                        "ru:{api_port:'Порт API',debug_port:'Порт отладки',mode:'Режим',secure:'Защищенный',insecure:'Незащищенный',download_config:'Скачать config',upload_config:'Загрузить config',reset_config:'Сбросить config',buy_me_coffee:'Купить мне кофе',stop_payload:'Остановить PS5Drive',upload:'Загрузить',browse_files:'Выбрать файлы',browse_folder:'Выбрать папку',drop_hint:'Перетащите файлы или папки сюда',no_selection:'Нет выбора',idle:'Ожидание',resume:'Продолжить',stop:'Стоп',upload_note:'Загрузка идет в текущую папку из Текущий путь.',upload_target:'Цель загрузки',create_folder:'Создать папку',create:'Создать',selected_item:'Выбранный элемент',nothing_selected:'Ничего не выбрано',go_to:'Открыть',download:'Скачать',delete:'Удалить',rename:'Переименовать',move_to:'Переместить в',copy_to:'Копировать в',chmod:'CHMOD 777 -R',move_tip:'Совет: используйте абсолютный путь (например, /data/ps5drive). Если цель существующая папка, имя сохранится.',files:'Файлы',games:'Игры',refresh:'Обновить',up:'Вверх',root:'Корень',load_more:'Загрузить еще',loading:'Загрузка...',current_path:'Текущий путь',name:'Имя',size:'Размер',mtime:'Время',action:'Действие',activity_log:'Журнал активности',clear:'Очистить',entries:'записей',more:'еще',selected_prefix:'Выбрано',selected_action_idle:'Выбранное действие: ожидание',games_scanner:'Сканер игр',scan:'Сканировать',scan_ready:'Готово к сканированию.',games_none:'Игры не найдены.',games_count_suffix:'игр',games_scan_failed:'Сканирование игр не удалось',title_id:'Title ID',path:'Путь',open:'Открыть',scanning:'Сканирование',games_found_suffix:'игр найдено',truncated:'(обрезано)',cover:'Обложка',metadata:'Метаданные',param_sfo:'param.sfo',games_preset_info:'Предустановленные пути сканирования: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Фильтр хранилища',all:'Все',yes:'Да',no:'Нет',storage:'Хранилище',empty_directory:'(пустая папка)',dir:'DIR',file:'ФАЙЛ'},"
                        "ko:{api_port:'API 포트',debug_port:'디버그 포트',mode:'모드',secure:'보안',insecure:'비보안',download_config:'설정 다운로드',upload_config:'설정 업로드',reset_config:'설정 초기화',buy_me_coffee:'커피 사주기',stop_payload:'PS5Drive 중지',upload:'업로드',browse_files:'파일 선택',browse_folder:'폴더 선택',drop_hint:'파일 또는 폴더를 여기에 놓으세요',no_selection:'선택 없음',idle:'대기',resume:'재개',stop:'중지',upload_note:'업로드는 현재 경로에 표시된 폴더로 진행됩니다.',upload_target:'업로드 대상',create_folder:'폴더 만들기',create:'만들기',selected_item:'선택된 항목',nothing_selected:'선택된 항목 없음',go_to:'열기',download:'다운로드',delete:'삭제',rename:'이름 변경',move_to:'이동',copy_to:'복사',chmod:'CHMOD 777 -R',move_tip:'이동 또는 복사 팁: 절대 경로를 사용하세요 (예: /data/ps5drive). 대상이 기존 폴더면 이름이 유지됩니다.',files:'파일',games:'게임',refresh:'새로고침',up:'위로',root:'루트',load_more:'더 보기',loading:'로딩 중...',current_path:'현재 경로',name:'이름',size:'크기',mtime:'시간',action:'작업',activity_log:'활동 로그',clear:'지우기',entries:'항목',more:'더',selected_prefix:'선택됨',selected_action_idle:'선택 작업: 대기',games_scanner:'게임 스캐너',scan:'스캔',scan_ready:'스캔 준비 완료.',games_none:'게임을 찾지 못했습니다.',games_count_suffix:'게임',games_scan_failed:'게임 스캔 실패',title_id:'Title ID',path:'경로',open:'열기',scanning:'스캔 중',games_found_suffix:'게임 찾음',truncated:'(잘림)',cover:'커버',metadata:'메타데이터',param_sfo:'param.sfo',games_preset_info:'프리셋 스캔 경로: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'저장소 필터',all:'전체',yes:'예',no:'아니오',storage:'저장소',empty_directory:'(빈 디렉터리)',dir:'DIR',file:'FILE'},"
                        "tr:{api_port:'API Portu',debug_port:'Debug Portu',mode:'Mod',secure:'Güvenli',insecure:'Güvensiz',download_config:'Yapılandırmayı indir',upload_config:'Yapılandırmayı yükle',reset_config:'Yapılandırmayı sıfırla',buy_me_coffee:'Bana kahve ısmarla',stop_payload:'PS5Drive durdur',upload:'Yükle',browse_files:'Dosya seç',browse_folder:'Klasör seç',drop_hint:'Dosyaları veya klasörleri buraya bırakın',no_selection:'Seçim yok',idle:'Boşta',resume:'Sürdür',stop:'Durdur',upload_note:'Yüklemeler Geçerli Yol bölümünde görünen dizine yapılır.',upload_target:'Yükleme hedefi',create_folder:'Klasör oluştur',create:'Oluştur',selected_item:'Seçili öğe',nothing_selected:'Hiçbir şey seçilmedi',go_to:'Aç',download:'İndir',delete:'Sil',rename:'Yeniden adlandır',move_to:'Şuraya taşı',copy_to:'Şuraya kopyala',chmod:'CHMOD 777 -R',move_tip:'Taşıma veya kopyalama ipucu: mutlak yol kullanın (örnek: /data/ps5drive). Hedef mevcut klasörse ad korunur.',files:'Dosyalar',games:'Oyunlar',refresh:'Yenile',up:'Yukarı',root:'Kök',load_more:'Daha fazla yükle',loading:'Yükleniyor...',current_path:'Geçerli yol',name:'Ad',size:'Boyut',mtime:'Zaman',action:'İşlem',activity_log:'Etkinlik günlüğü',clear:'Temizle',entries:'kayıt',more:'daha fazla',selected_prefix:'Seçili',selected_action_idle:'Seçili işlem: boşta',games_scanner:'Oyun tarayıcı',scan:'Tara',scan_ready:'Taramaya hazır.',games_none:'Oyun bulunamadı.',games_count_suffix:'oyun',games_scan_failed:'Oyun taraması başarısız',title_id:'Title ID',path:'Yol',open:'Aç',scanning:'Taranıyor',games_found_suffix:'oyun bulundu',truncated:'(kısaltıldı)',cover:'Kapak',metadata:'Meta veri',param_sfo:'param.sfo',games_preset_info:'Hazır tarama yolları: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Depolama filtresi',all:'Tümü',yes:'Evet',no:'Hayır',storage:'Depolama',empty_directory:'(boş dizin)',dir:'DIR',file:'DOSYA'},"
                        "vi:{api_port:'Cổng API',debug_port:'Cổng debug',mode:'Chế độ',secure:'Bảo mật',insecure:'Không bảo mật',download_config:'Tải config',upload_config:'Tải lên config',reset_config:'Đặt lại config',buy_me_coffee:'Mời tôi cà phê',stop_payload:'Dừng PS5Drive',upload:'Tải lên',browse_files:'Chọn tệp',browse_folder:'Chọn thư mục',drop_hint:'Thả tệp hoặc thư mục vào đây',no_selection:'Chưa chọn',idle:'Nhàn rỗi',resume:'Tiếp tục',stop:'Dừng',upload_note:'Tệp sẽ được tải lên thư mục hiện tại trong Đường dẫn hiện tại.',upload_target:'Đích tải lên',create_folder:'Tạo thư mục',create:'Tạo',selected_item:'Mục đã chọn',nothing_selected:'Không có mục nào được chọn',go_to:'Mở',download:'Tải xuống',delete:'Xóa',rename:'Đổi tên',move_to:'Di chuyển đến',copy_to:'Sao chép đến',chmod:'CHMOD 777 -R',move_tip:'Mẹo di chuyển hoặc sao chép: dùng đường dẫn tuyệt đối (ví dụ /data/ps5drive). Nếu đích là thư mục có sẵn thì giữ nguyên tên.',files:'Tệp',games:'Trò chơi',refresh:'Làm mới',up:'Lên',root:'Gốc',load_more:'Tải thêm',loading:'Đang tải...',current_path:'Đường dẫn hiện tại',name:'Tên',size:'Kích thước',mtime:'Thời gian',action:'Hành động',activity_log:'Nhật ký hoạt động',clear:'Xóa',entries:'mục',more:'thêm',selected_prefix:'Đã chọn',selected_action_idle:'Hành động đã chọn: nhàn rỗi',games_scanner:'Trình quét trò chơi',scan:'Quét',scan_ready:'Sẵn sàng quét.',games_none:'Không tìm thấy trò chơi.',games_count_suffix:'trò chơi',games_scan_failed:'Quét trò chơi thất bại',title_id:'Title ID',path:'Đường dẫn',open:'Mở',scanning:'Đang quét',games_found_suffix:'đã tìm thấy',truncated:'(rút gọn)',cover:'Bìa',metadata:'Siêu dữ liệu',param_sfo:'param.sfo',games_preset_info:'Đường dẫn quét sẵn có: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Bộ lọc lưu trữ',all:'Tất cả',yes:'Có',no:'Không',storage:'Lưu trữ',empty_directory:'(thư mục trống)',dir:'DIR',file:'FILE'},"
                        "id:{api_port:'Port API',debug_port:'Port debug',mode:'Mode',secure:'Aman',insecure:'Tidak aman',download_config:'Unduh config',upload_config:'Unggah config',reset_config:'Reset config',buy_me_coffee:'Traktir saya kopi',stop_payload:'Hentikan PS5Drive',upload:'Unggah',browse_files:'Pilih file',browse_folder:'Pilih folder',drop_hint:'Lepas file atau folder di sini',no_selection:'Tidak ada pilihan',idle:'Idle',resume:'Lanjutkan',stop:'Berhenti',upload_note:'Unggahan masuk ke direktori saat ini pada Jalur saat ini.',upload_target:'Tujuan unggah',create_folder:'Buat folder',create:'Buat',selected_item:'Item terpilih',nothing_selected:'Tidak ada yang dipilih',go_to:'Buka',download:'Unduh',delete:'Hapus',rename:'Ganti nama',move_to:'Pindah ke',copy_to:'Salin ke',chmod:'CHMOD 777 -R',move_tip:'Tips pindah atau salin: gunakan jalur absolut (contoh /data/ps5drive). Jika tujuan folder sudah ada, nama item dipertahankan.',files:'File',games:'Game',refresh:'Segarkan',up:'Naik',root:'Root',load_more:'Muat lebih banyak',loading:'Memuat...',current_path:'Jalur saat ini',name:'Nama',size:'Ukuran',mtime:'Waktu',action:'Aksi',activity_log:'Log aktivitas',clear:'Bersihkan',entries:'entri',more:'lebih',selected_prefix:'Terpilih',selected_action_idle:'Aksi terpilih: idle',games_scanner:'Pemindai game',scan:'Pindai',scan_ready:'Siap memindai.',games_none:'Tidak ada game ditemukan.',games_count_suffix:'game',games_scan_failed:'Pemindaian game gagal',title_id:'Title ID',path:'Jalur',open:'Buka',scanning:'Memindai',games_found_suffix:'game ditemukan',truncated:'(dipotong)',cover:'Sampul',metadata:'Metadata',param_sfo:'param.sfo',games_preset_info:'Jalur preset pemindaian: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Filter penyimpanan',all:'Semua',yes:'Ya',no:'Tidak',storage:'Penyimpanan',empty_directory:'(direktori kosong)',dir:'DIR',file:'FILE'},"
                        "it:{api_port:'Porta API',debug_port:'Porta debug',mode:'Modalità',secure:'Sicuro',insecure:'Non sicuro',download_config:'Scarica config',upload_config:'Carica config',reset_config:'Reimposta config',buy_me_coffee:'Offrimi un caffè',stop_payload:'Ferma PS5Drive',upload:'Carica',browse_files:'Scegli file',browse_folder:'Scegli cartella',drop_hint:'Trascina file o cartelle qui',no_selection:'Nessuna selezione',idle:'Inattivo',resume:'Riprendi',stop:'Ferma',upload_note:'I caricamenti vanno nella directory corrente mostrata in Percorso corrente.',upload_target:'Destinazione upload',create_folder:'Crea cartella',create:'Crea',selected_item:'Elemento selezionato',nothing_selected:'Niente selezionato',go_to:'Apri',download:'Scarica',delete:'Elimina',rename:'Rinomina',move_to:'Sposta in',copy_to:'Copia in',chmod:'CHMOD 777 -R',move_tip:'Suggerimento sposta o copia: usa un percorso assoluto (esempio /data/ps5drive). Se la destinazione è una cartella esistente il nome viene mantenuto.',files:'File',games:'Giochi',refresh:'Aggiorna',up:'Su',root:'Root',load_more:'Carica altro',loading:'Caricamento...',current_path:'Percorso corrente',name:'Nome',size:'Dimensione',mtime:'Ora',action:'Azione',activity_log:'Registro attività',clear:'Pulisci',entries:'voci',more:'altro',selected_prefix:'Selezionato',selected_action_idle:'Azione selezionata: inattiva',games_scanner:'Scanner giochi',scan:'Scansiona',scan_ready:'Pronto per la scansione.',games_none:'Nessun gioco trovato.',games_count_suffix:'giochi',games_scan_failed:'Scansione giochi non riuscita',title_id:'Title ID',path:'Percorso',open:'Apri',scanning:'Scansione in corso',games_found_suffix:'gioco trovato',truncated:'(troncato)',cover:'Copertina',metadata:'Metadati',param_sfo:'param.sfo',games_preset_info:'Percorsi preset: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'Filtro archiviazione',all:'Tutti',yes:'Sì',no:'No',storage:'Archiviazione',empty_directory:'(directory vuota)',dir:'DIR',file:'FILE'},"
                        "th:{api_port:'พอร์ต API',debug_port:'พอร์ตดีบัก',mode:'โหมด',secure:'ปลอดภัย',insecure:'ไม่ปลอดภัย',download_config:'ดาวน์โหลด config',upload_config:'อัปโหลด config',reset_config:'รีเซ็ต config',buy_me_coffee:'เลี้ยงกาแฟฉัน',stop_payload:'หยุด PS5Drive',upload:'อัปโหลด',browse_files:'เลือกไฟล์',browse_folder:'เลือกโฟลเดอร์',drop_hint:'ลากไฟล์หรือโฟลเดอร์มาวางที่นี่',no_selection:'ไม่มีการเลือก',idle:'ว่าง',resume:'ทำต่อ',stop:'หยุด',upload_note:'การอัปโหลดจะไปยังโฟลเดอร์ปัจจุบันที่แสดงในเส้นทางปัจจุบัน',upload_target:'ปลายทางอัปโหลด',create_folder:'สร้างโฟลเดอร์',create:'สร้าง',selected_item:'รายการที่เลือก',nothing_selected:'ยังไม่ได้เลือกรายการ',go_to:'เปิด',download:'ดาวน์โหลด',delete:'ลบ',rename:'เปลี่ยนชื่อ',move_to:'ย้ายไป',copy_to:'คัดลอกไป',chmod:'CHMOD 777 -R',move_tip:'เคล็ดลับย้ายหรือคัดลอก: ใช้พาธแบบเต็ม (ตัวอย่าง /data/ps5drive) หากปลายทางเป็นโฟลเดอร์ที่มีอยู่จะคงชื่อเดิมไว้',files:'ไฟล์',games:'เกม',refresh:'รีเฟรช',up:'ขึ้น',root:'ราก',load_more:'โหลดเพิ่ม',loading:'กำลังโหลด...',current_path:'เส้นทางปัจจุบัน',name:'ชื่อ',size:'ขนาด',mtime:'เวลา',action:'การทำงาน',activity_log:'บันทึกกิจกรรม',clear:'ล้าง',entries:'รายการ',more:'เพิ่มเติม',selected_prefix:'ที่เลือก',selected_action_idle:'การทำงานที่เลือก: ว่าง',games_scanner:'ตัวสแกนเกม',scan:'สแกน',scan_ready:'พร้อมสแกน',games_none:'ไม่พบเกม',games_count_suffix:'เกม',games_scan_failed:'สแกนเกมล้มเหลว',title_id:'Title ID',path:'เส้นทาง',open:'เปิด',scanning:'กำลังสแกน',games_found_suffix:'พบเกม',truncated:'(ตัดทอน)',cover:'ปก',metadata:'เมทาดาทา',param_sfo:'param.sfo',games_preset_info:'พาธสแกนแบบตั้งค่าไว้: etaHEN/games, etaHEN/homebrew, games, homebrew',storage_filter:'ตัวกรองที่เก็บข้อมูล',all:'ทั้งหมด',yes:'ใช่',no:'ไม่',storage:'ที่เก็บข้อมูล',empty_directory:'(โฟลเดอร์ว่าง)',dir:'DIR',file:'FILE'}"
                        "};"
                        "const SUPPORTED=['en','zh-cn','zh-tw','hi','es','ar','bn','pt-br','ru','ja','de','fr','ko','tr','vi','id','it','th'];"
                        "let currentLang='en';"
                        "let gamesItems=[];"
                        "let gamesStorageRoots=[];"
                        "let gamesVisibleStorage=[];"
                        "const gamesPresetScanPaths=['etaHEN/games','etaHEN/homebrew','games','homebrew'];"
                        "function q(id){return document.getElementById(id);}"
                        "function tr(key){const base=I18N.en||{};const dict=I18N[currentLang]||base;return dict[key]||base[key]||key;}"
                        "window.ps5driveTr=tr;"
                        "function tl(key,fallback){try{const v=tr(key);return (v===undefined||v===null||v==='')?(fallback||key):v;}catch(e){return fallback||key;}}"
                        "function setText(id,key){const el=q(id);if(el)el.textContent=tr(key);}"
                        "function chooseLang(raw){const v=String(raw||'').toLowerCase().replace('_','-');if(SUPPORTED.indexOf(v)>=0)return v;if(v==='pt')return 'pt-br';if(v==='zh')return 'zh-cn';const short=v.slice(0,2);if(short==='pt')return 'pt-br';if(short==='zh')return 'zh-cn';if(SUPPORTED.indexOf(short)>=0)return short;return 'en';}"
                        "function setLang(lang){currentLang=chooseLang(lang);try{localStorage.setItem('ps5drive_lang',currentLang);}catch(e){}document.documentElement.lang=currentLang;const sel=q('langSelect');if(sel)sel.value=currentLang;applyStaticText();applyDynamicText();if(typeof renderRows==='function')renderRows();if(typeof setListUIState==='function')setListUIState();if(typeof updateSelectionUI==='function')updateSelectionUI();renderGamesStorageFilters();renderGames();}"
                        "function applyStaticText(){setText('downloadConfigBtn','download_config');setText('uploadConfigBtn','upload_config');setText('resetConfigBtn','reset_config');setText('stopBtn','stop_payload');setText('coffeeText','buy_me_coffee');setText('uploadTitle','upload');setText('pickFilesBtn','browse_files');setText('pickFolderBtn','browse_folder');setText('dropZone','drop_hint');setText('uploadStartBtn','upload');setText('resumeUploadBtn','resume');setText('uploadStopBtn','stop');setText('createFolderTitle','create_folder');setText('mkdirBtn','create');setText('selectedTitle','selected_item');setText('goSelectedBtn','go_to');setText('downloadSelectedBtn','download');setText('deleteSelectedBtn','delete');setText('renameBtn','rename');setText('moveBtn','move_to');setText('copyBtn','copy_to');setText('chmodBtn','chmod');setText('tabFilesBtn','files');setText('tabGamesBtn','games');setText('refreshBtn','refresh');setText('upBtn','up');setText('rootBtn','root');setText('thName','name');setText('thSize','size');setText('thMTime','mtime');setText('thAction','action');setText('logTitle','activity_log');setText('clearLogBtn','clear');setText('gamesTitle','games_scanner');setText('gamesPresetInfo','games_preset_info');setText('gamesScanBtn','scan');setText('gamesThCover','cover');setText('gamesThMeta','metadata');setText('gamesThPath','path');setText('gamesThAction','action');const uploadNote=q('uploadNote');if(uploadNote)uploadNote.textContent=tr('upload_note');const moveTip=q('moveTip');if(moveTip)moveTip.textContent=tr('move_tip');const mk=q('mkdirInput');if(mk)mk.placeholder='new-folder';const rn=q('renameInput');if(rn)rn.placeholder='new-name (same folder)';const mv=q('moveInput');if(mv)mv.placeholder='example: /data/ps5drive';}"
                        "function applyDynamicText(){const st=(typeof state==='object'&&state)?state:null;const apiChip=q('apiPortChip');if(apiChip){const raw=apiChip.getAttribute('data-port')||((apiChip.textContent||'').split(':').pop()||'').trim();if(raw)apiChip.setAttribute('data-port',raw);apiChip.textContent=tr('api_port')+': '+raw;}const dbgChip=q('debugPortChip');if(dbgChip){const raw=dbgChip.getAttribute('data-port')||((dbgChip.textContent||'').split(':').pop()||'').trim();if(raw)dbgChip.setAttribute('data-port',raw);dbgChip.textContent=tr('debug_port')+': '+raw;}const mode=q('modeChip');if(mode){const secure=!!(st&&st.securityMode==='secure');mode.textContent=tr('mode')+': '+tr(secure?'secure':'insecure');mode.classList.remove('mode-chip-secure','mode-chip-insecure');mode.classList.add(secure?'mode-chip-secure':'mode-chip-insecure');}const hint=q('uploadPathHint');if(hint&&st)hint.textContent=tr('upload_target')+': '+(st.path||'/');const info=q('queueInfo');if(info&&st){if(!st.queueFiles||!st.queueFiles.length){info.textContent=tr('no_selection');}else{const sz=(typeof formatSize==='function')?formatSize(st.queueBytes||0):String(st.queueBytes||0);const word=(st.queueFiles.length===1)?tr('selected_prefix'):(tr('selected_prefix'));info.textContent=tr('selected_prefix')+' '+st.queueFiles.length+' ('+sz+')';}}const count=q('countLabel');if(count&&st){count.textContent=String((st.entries||[]).length)+' '+tr('entries')+(st.hasMore?' ('+tr('more')+')':'');}const loadBtn=q('loadMoreBtn');if(loadBtn&&st){loadBtn.textContent=st.listLoadingMore?tr('loading'):tr('load_more');}const cp=q('currentPathLabel');const path=q('pathLabel');if(cp&&path){const textNode=document.createTextNode(tr('current_path')+': ');cp.textContent='';cp.appendChild(textNode);cp.appendChild(path);}const sel=q('selectionInfo');if(sel&&st&&!st.selected){sel.textContent=tr('nothing_selected');}const sop=q('selectedOpStatus');const sopBar=q('selectedOpProgress');if(sop&&sopBar&&Number(sopBar.value||0)===0){sop.textContent=tr('selected_action_idle');}}"
                        "function wrap(name,after){const orig=window[name];if(typeof orig!=='function')return;window[name]=function(){const out=orig.apply(this,arguments);try{after();}catch(e){}return out;};}"
                        "function setActiveTab(tab){const filesPane=q('filesPane');const gamesPane=q('gamesPane');const filesBtn=q('tabFilesBtn');const gamesBtn=q('tabGamesBtn');const useGames=tab==='games';if(filesPane)filesPane.style.display=useGames?'none':'';if(gamesPane)gamesPane.style.display=useGames?'':'none';if(filesBtn){filesBtn.className=(useGames?'btn-ghost sloth-btn-ghost':'btn-main sloth-btn-main');}if(gamesBtn){gamesBtn.className=(useGames?'btn-main sloth-btn-main':'btn-ghost sloth-btn-ghost');}}"
                        "function normStorageRoots(list){const out=[];for(const raw of (list||[])){if(typeof raw!=='string')continue;const n=(typeof normPath==='function')?normPath(raw):String(raw||'/');if(out.indexOf(n)<0)out.push(n);}out.sort((a,b)=>{if(a==='/'&&b!=='/')return -1;if(b==='/'&&a!=='/')return 1;return String(a).localeCompare(String(b));});return out;}"
                        "function joinScanPath(root,subpath){const r=(typeof normPath==='function')?normPath(root||'/'):String(root||'/');const s=String(subpath||'').replace(/\\\\/g,'/').replace(/^\\/+/, '').replace(/\\/+$/, '');if(!s)return r;if(r==='/')return '/'+s;return r+'/'+s;}"
                        "function inferStorageRoot(pathValue){const p=(typeof normPath==='function')?normPath(pathValue||'/'):String(pathValue||'/');let best='';for(const raw of gamesStorageRoots){const root=(typeof normPath==='function')?normPath(raw||'/'):String(raw||'/');if(p===root||p.startsWith(root+'/')){if(root.length>best.length)best=root;}}if(best)return best;if(p==='/data'||p.startsWith('/data/'))return '/data';if(p==='/user'||p.startsWith('/user/'))return '/user';if(p.startsWith('/mnt/')){const parts=p.split('/').filter(Boolean);if(parts.length>=2)return '/'+parts[0]+'/'+parts[1];}return '/';}"
                        "function syncVisibleStorage(){gamesStorageRoots=normStorageRoots(gamesStorageRoots);if(!gamesStorageRoots.length)gamesStorageRoots=['/'];const keep=[];for(const root of gamesVisibleStorage){if(gamesStorageRoots.indexOf(root)>=0&&keep.indexOf(root)<0)keep.push(root);}gamesVisibleStorage=keep.length?keep:gamesStorageRoots.slice();}"
                        "function renderGamesStorageFilters(){const box=q('gamesStorageFilters');if(!box)return;syncVisibleStorage();box.innerHTML='';if(!gamesStorageRoots.length)return;const label=document.createElement('span');label.className='meta sloth-meta';label.style.alignSelf='center';label.textContent=tr('storage_filter')+':';box.appendChild(label);const allBtn=document.createElement('button');const allSelected=gamesVisibleStorage.length===gamesStorageRoots.length;allBtn.className=(allSelected?'btn-main sloth-btn-main':'btn-ghost sloth-btn-ghost')+' mini';allBtn.textContent=tr('all');allBtn.onclick=()=>{gamesVisibleStorage=gamesStorageRoots.slice();renderGamesStorageFilters();renderGames();};box.appendChild(allBtn);for(const root of gamesStorageRoots){const count=gamesItems.filter((it)=>(it.storage_path||inferStorageRoot(it.path||'/'))===root).length;const active=gamesVisibleStorage.indexOf(root)>=0;const btn=document.createElement('button');btn.className=(active?'btn-main sloth-btn-main':'btn-ghost sloth-btn-ghost')+' mini';btn.textContent=root+(count>0?' ('+count+')':'');btn.onclick=()=>{if(active){if(gamesVisibleStorage.length<=1)return;gamesVisibleStorage=gamesVisibleStorage.filter((v)=>v!==root);}else{gamesVisibleStorage.push(root);}syncVisibleStorage();renderGamesStorageFilters();renderGames();};box.appendChild(btn);}}"
                        "async function fetchStorageRoots(){try{const data=await apiJson('/api/storage/list');const rows=Array.isArray(data&&data.storage)?data.storage:[];const roots=[];for(const row of rows){const raw=(row&&typeof row==='object')?row.path:row;const txt=String(raw||'').trim();if(!txt)continue;const n=(typeof normPath==='function')?normPath(txt):txt;if(roots.indexOf(n)<0)roots.push(n);}if(roots.indexOf('/')<0)roots.unshift('/');return normStorageRoots(roots);}catch(err){if(typeof log==='function')log('Storage list failed: '+(err&&err.message?err.message:String(err)));return ['/'];}}"
                        "async function scanGamesPath(pathValue){const url='/api/games/scan?path='+(typeof qp==='function'?qp(pathValue):encodeURIComponent(pathValue))+'&max_depth=6&max_dirs=8000';const resp=await fetch(api+url);const text=await resp.text();let data={};try{data=text?JSON.parse(text):{};}catch(e){data={};}if(!resp.ok){const msg=(data&&data.error)?data.error:(text||('HTTP '+resp.status));return {ok:false,status:resp.status,error:msg,data:data};}return {ok:true,status:resp.status,data:data};}"
                        "function renderGames(){const rows=q('gamesRows');const count=q('gamesCount');syncVisibleStorage();const visible=gamesItems.filter((item)=>gamesVisibleStorage.indexOf(item.storage_path||inferStorageRoot(item.path||'/'))>=0);if(count)count.textContent=String(visible.length)+' '+tr('games_count_suffix');if(!rows)return;rows.innerHTML='';if(!visible.length){const trEl=document.createElement('tr');const td=document.createElement('td');td.colSpan=4;td.style.color='var(--muted)';td.textContent=tr('games_none');trEl.appendChild(td);rows.appendChild(trEl);return;}for(const item of visible){const trEl=document.createElement('tr');const storage=item.storage_path||inferStorageRoot(item.path||'/');const tdCover=document.createElement('td');if(item&&item.has_cover&&item.path){const img=document.createElement('img');img.alt='cover';img.style.width='64px';img.style.height='64px';img.style.objectFit='cover';img.style.borderRadius='8px';img.style.border='1px solid var(--sloth-line)';img.src=api+'/api/games/cover?path='+qp(item.path);tdCover.appendChild(img);}else{tdCover.textContent='-';}const tdMeta=document.createElement('td');const title=document.createElement('div');title.className='mono';title.style.fontWeight='700';title.textContent=item.title||item.name||item.title_id||'-';const detail=document.createElement('div');detail.className='meta sloth-meta';detail.textContent=(item.title_id||'-')+' · '+(item.platform||'-')+' · '+tr('param_sfo')+': '+tr(item.has_param_sfo?'yes':'no')+' · '+tr('storage')+': '+storage;tdMeta.appendChild(title);tdMeta.appendChild(detail);const tdPath=document.createElement('td');tdPath.className='mono';tdPath.textContent=item.path||'/';const tdAct=document.createElement('td');const b=document.createElement('button');b.className='mini';b.textContent=tr('open');b.onclick=()=>{setActiveTab('files');if(typeof setPath==='function')setPath(item.path||'/');if(typeof refreshList==='function')refreshList(false);};tdAct.appendChild(b);trEl.appendChild(tdCover);trEl.appendChild(tdMeta);trEl.appendChild(tdPath);trEl.appendChild(tdAct);rows.appendChild(trEl);}}"
                        "async function scanGames(){const input=q('gamesPathInput');const status=q('gamesStatus');const rawExtra=input?String(input.value||'').trim():'';const extraPath=rawExtra?((typeof normPath==='function')?normPath(rawExtra):rawExtra):'';if(input&&extraPath)input.value=extraPath;if(status)status.textContent=tr('scanning')+'...';try{gamesStorageRoots=await fetchStorageRoots();syncVisibleStorage();const targets=[];for(const root of gamesStorageRoots){for(const sub of gamesPresetScanPaths){targets.push({storage_path:root,games_path:joinScanPath(root,sub)});}}if(extraPath)targets.push({storage_path:inferStorageRoot(extraPath),games_path:extraPath});const dedupTargets=[];const seen={};for(const target of targets){const key=target.games_path||'';if(!key||seen[key])continue;seen[key]=1;dedupTargets.push(target);}const merged=[];let truncated=false;for(const target of dedupTargets){const result=await scanGamesPath(target.games_path);if(!result.ok){if(result.status===404)continue;if(typeof log==='function')log('Games scan skipped '+target.games_path+': '+result.error);continue;}const rows=Array.isArray(result.data&&result.data.games)?result.data.games:[];for(const row of rows){const item=Object.assign({},row);item.games_path=target.games_path;item.storage_path=item.storage_path||target.storage_path||inferStorageRoot(item.path||'/');if(item.path)merged.push(item);}if(result.data&&result.data.truncated)truncated=true;}const byPath={};for(const item of merged){const key=item.path||'';if(!key)continue;const prev=byPath[key];if(!prev||(!prev.has_cover&&item.has_cover)||(!prev.has_param_sfo&&item.has_param_sfo))byPath[key]=item;}gamesItems=Object.keys(byPath).map((k)=>byPath[k]);gamesItems.sort((a,b)=>String(a.path||'').localeCompare(String(b.path||'')));renderGamesStorageFilters();renderGames();let msg=String(gamesItems.length)+' '+tr('games_found_suffix');if(truncated)msg+=' '+tr('truncated');if(status)status.textContent=msg;}catch(err){if(status)status.textContent=tr('games_scan_failed')+': '+(err&&err.message?err.message:String(err));if(typeof log==='function')log('Games scan failed: '+(err&&err.message?err.message:String(err)));}}"
                        "function bind(){const saved=(()=>{try{return localStorage.getItem('ps5drive_lang')||'';}catch(e){return '';}})();const nav=(navigator.language||'en');setLang(saved||nav);const sel=q('langSelect');if(sel)sel.addEventListener('change',()=>setLang(sel.value));const filesBtn=q('tabFilesBtn');const gamesBtn=q('tabGamesBtn');if(filesBtn)filesBtn.addEventListener('click',()=>setActiveTab('files'));if(gamesBtn)gamesBtn.addEventListener('click',()=>setActiveTab('games'));const scanBtn=q('gamesScanBtn');if(scanBtn)scanBtn.addEventListener('click',scanGames);const gamesPath=q('gamesPathInput');if(gamesPath)gamesPath.addEventListener('keydown',(ev)=>{if(ev.key==='Enter'){ev.preventDefault();scanGames();}});wrap('updateSecurityMode',applyDynamicText);wrap('setPath',applyDynamicText);wrap('renderQueueInfo',applyDynamicText);wrap('renderRows',applyDynamicText);wrap('setListUIState',applyDynamicText);wrap('updateSelectionUI',applyDynamicText);setActiveTab('files');if(q('gamesStatus'))q('gamesStatus').textContent=tr('scan_ready');applyDynamicText();(async()=>{gamesStorageRoots=await fetchStorageRoots();syncVisibleStorage();renderGamesStorageFilters();renderGames();})();}"
                        "bind();"
                        "})();"
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
        rc |= strbuf_appendf(&sb, "{\"ok\":true,\"pid\":%d,\"ppid\":%d,\"web_port\":%d,\"api_port\":%d,\"debug_port\":%d,\"debug_enabled\":%s,",
                             (int)getpid(), (int)getppid(), ctx->cfg.web_port, ctx->cfg.api_port, ctx->cfg.debug_port,
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
    if (!require_authorized(ctx, client_fd, req)) return 0;
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/health") == 0) return handle_api_health(ctx, client_fd);
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/stop") == 0) return handle_api_stop(ctx, client_fd);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/config/download") == 0) return handle_api_config_download(ctx, client_fd);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/storage/list") == 0) return handle_api_storage_list(ctx, client_fd);
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/config/upload") == 0) return handle_api_config_upload(ctx, client_fd, req);
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/api/config/reset") == 0) return handle_api_config_reset(ctx, client_fd, req);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/stat") == 0) return handle_api_stat(ctx, client_fd, req);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/list") == 0) return handle_api_list(ctx, client_fd, req);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/games/scan") == 0) return handle_api_games_scan(ctx, client_fd, req);
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/api/games/cover") == 0) return handle_api_games_cover(ctx, client_fd, req);
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
    if (!require_authorized(ctx, client_fd, req)) return 0;
    if (strncmp(req->path, "/api/", 5) == 0) {
        return handle_api_request(ctx, client_fd, req);
    }
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/assets/logo-light.svg") == 0) {
        return send_bytes_response(client_fd, 200, "image/svg+xml; charset=utf-8",
                                   k_logo_light_svg, strlen(k_logo_light_svg));
    }
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/assets/logo-dark.svg") == 0) {
        return send_bytes_response(client_fd, 200, "image/svg+xml; charset=utf-8",
                                   k_logo_dark_svg, strlen(k_logo_dark_svg));
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

#if defined(PS5DRIVE_PS4_BUILD)
    while (*(ctx->running_flag)) {
        int has_listener = 0;
        if (ctx->web_listener_fd >= 0) {
            has_listener = 1;
            accept_ready_clients(ctx, ctx->web_listener_fd, LISTENER_KIND_WEB);
        }
        if (ctx->api_listener_fd >= 0) {
            has_listener = 1;
            accept_ready_clients(ctx, ctx->api_listener_fd, LISTENER_KIND_API);
        }
        if (ctx->debug_listener_fd >= 0) {
            has_listener = 1;
            accept_ready_clients(ctx, ctx->debug_listener_fd, LISTENER_KIND_DEBUG);
        }
        if (!has_listener) return -1;
        usleep(20 * 1000);
    }
    return 0;
#else
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
#endif
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
    ctx.secure_mode = cfg->secure_mode ? 1 : 0;
    snprintf(ctx.auth_username, sizeof(ctx.auth_username), "%s", cfg->auth_username ? cfg->auth_username : "");
    snprintf(ctx.auth_password, sizeof(ctx.auth_password), "%s", cfg->auth_password ? cfg->auth_password : "");
    snprintf(ctx.config_path, sizeof(ctx.config_path), "%s", cfg->config_path ? cfg->config_path : "");

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

    server_log(&ctx, "server ready web=%d api=%d debug=%d enabled=%d mode=%s",
               cfg->web_port, cfg->api_port, cfg->debug_port, ctx.debug_enabled, security_mode_name(&ctx));
    int run_rc = run_single_thread_loop(&ctx);

    close(ctx.web_listener_fd);
    close(ctx.api_listener_fd);
    if (ctx.debug_listener_fd >= 0) close(ctx.debug_listener_fd);
    return run_rc;
}
