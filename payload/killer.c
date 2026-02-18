#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "notify.h"

static void resolve_pid_paths(char *payload_pid, size_t payload_len, char *server_pid, size_t server_len) {
    const char *state_dir = getenv("PS5DRIVE_STATE_DIR");
    if (!state_dir || !*state_dir) state_dir = PS5DRIVE_STATE_DIR;
    snprintf(payload_pid, payload_len, "%s/payload.pid", state_dir);
    snprintf(server_pid, server_len, "%s/server.pid", state_dir);
}

static pid_t read_pid_file(const char *path) {
    FILE *fp = fopen(path, "r");
    long parsed = 0;
    if (!fp) return -1;
    if (fscanf(fp, "%ld", &parsed) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if (parsed <= 0 || parsed > INT_MAX) return -1;
    return (pid_t)parsed;
}

static pid_t read_first_pid_file(const char *const *paths, size_t count) {
    if (!paths) return -1;
    for (size_t i = 0; i < count; ++i) {
        if (!paths[i] || !paths[i][0]) continue;
        pid_t pid = read_pid_file(paths[i]);
        if (pid > 0) return pid;
    }
    return -1;
}

static int is_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

static int terminate_pid(pid_t pid) {
    if (pid <= 0) return 0;
    if (!is_alive(pid)) return 0;
    if (kill(pid, SIGTERM) != 0 && errno != ESRCH) return -1;

    for (int i = 0; i < 30; ++i) {
        if (!is_alive(pid)) return 0;
        usleep(100 * 1000);
    }

    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) return -1;
    for (int i = 0; i < 20; ++i) {
        if (!is_alive(pid)) return 0;
        usleep(50 * 1000);
    }

    return is_alive(pid) ? -1 : 0;
}

static pid_t parse_pid_from_text(const char *text) {
    if (!text) return -1;
    const char *key = "\"pid\":";
    const char *p = strstr(text, key);
    if (!p) return -1;
    p += strlen(key);
    while (*p == ' ' || *p == '\t') ++p;
    errno = 0;
    long val = strtol(p, NULL, 10);
    if (errno != 0 || val <= 0 || val > INT_MAX) return -1;
    return (pid_t)val;
}

static pid_t query_pid_from_health_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    const char *req =
        "GET /api/health HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    if (send(fd, req, strlen(req), 0) < 0) {
        close(fd);
        return -1;
    }

    char buf[8192];
    size_t used = 0;
    while (used + 1 < sizeof(buf)) {
        ssize_t n = recv(fd, buf + used, sizeof(buf) - 1 - used, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        used += (size_t)n;
    }
    buf[used] = '\0';
    close(fd);
    return parse_pid_from_text(buf);
}

static pid_t query_pid_from_health(void) {
    int ports[] = {PS5DRIVE_API_PORT, PS5DRIVE_WEB_PORT, 8904, 8903};
    for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); ++i) {
        pid_t pid = query_pid_from_health_port(ports[i]);
        if (pid > 0) return pid;
    }
    return -1;
}

int main(void) {
    char payload_pid_path[PATH_MAX];
    char server_pid_path[PATH_MAX];
    resolve_pid_paths(payload_pid_path, sizeof(payload_pid_path), server_pid_path, sizeof(server_pid_path));

    notify_info("PS5 Drive Killer", "Attempting to stop ps5drive...");

    pid_t payload_pid = read_pid_file(payload_pid_path);
    pid_t server_pid = read_pid_file(server_pid_path);

    if (payload_pid <= 0) {
        static const char *legacy_payload_pid_paths[] = {
            "/tmp/ps5drive_payload.pid",
            "/data/ps5upload/payload.pid",
            "/data/ps5drive/payload.pid",
        };
        payload_pid = read_first_pid_file(
            legacy_payload_pid_paths,
            sizeof(legacy_payload_pid_paths) / sizeof(legacy_payload_pid_paths[0]));
    }
    if (server_pid <= 0) {
        static const char *legacy_server_pid_paths[] = {
            "/tmp/ps5drive_server.pid",
            "/data/ps5upload/server.pid",
            "/data/ps5drive/server.pid",
        };
        server_pid = read_first_pid_file(
            legacy_server_pid_paths,
            sizeof(legacy_server_pid_paths) / sizeof(legacy_server_pid_paths[0]));
    }

    /* Fallback for legacy/foreign instances that do not maintain our pid files. */
    pid_t health_pid = query_pid_from_health();
    if (payload_pid <= 0 && health_pid > 0) payload_pid = health_pid;
    if (server_pid <= 0 && health_pid > 0) server_pid = health_pid;

    int payload_rc = terminate_pid(payload_pid);
    int server_rc = terminate_pid(server_pid);

    unlink(payload_pid_path);
    unlink(server_pid_path);

    if (payload_rc == 0 && server_rc == 0) {
        notify_success("PS5 Drive Killer", "ps5drive stopped.");
        return 0;
    }

    notify_error("PS5 Drive Killer", "Failed to stop one or more processes.");
    return 1;
}
