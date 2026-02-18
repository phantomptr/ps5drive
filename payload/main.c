#include <errno.h>
#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "notify.h"
#include "server.h"

#ifndef PS5DRIVE_VERSION
#define PS5DRIVE_VERSION "dev"
#endif

typedef struct runtime_cfg {
    char state_dir[PATH_MAX];
    char pid_file[PATH_MAX];
    char server_pid_file[PATH_MAX];
    char root_dir[PATH_MAX];
    int web_port;
    int api_port;
    int debug_port;
    int max_clients;
    int enable_test_admin;
} runtime_cfg_t;

static volatile sig_atomic_t g_running = 1;
static pid_t g_self_pid = -1;
static pid_t g_child_pid = -1;
static int g_pid_tracking_enabled = 1;
static runtime_cfg_t g_cfg;

typedef struct health_info {
    pid_t pid;
    pid_t ppid;
} health_info_t;

static int parse_env_int(const char *name, int fallback) {
    const char *raw = getenv(name);
    if (!raw || !*raw) return fallback;
    char *end = NULL;
    long val = strtol(raw, &end, 10);
    if (!end || *end != '\0') return fallback;
    if (val < 1 || val > INT_MAX) return fallback;
    return (int)val;
}

static void copy_env_string(const char *name, const char *fallback, char *dst, size_t dst_len) {
    const char *src = getenv(name);
    if (!src || !*src) src = fallback;
    snprintf(dst, dst_len, "%s", src);
}

static void load_runtime_cfg(runtime_cfg_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    copy_env_string("PS5DRIVE_STATE_DIR", PS5DRIVE_STATE_DIR, cfg->state_dir, sizeof(cfg->state_dir));
    /* Avoid inheriting generic PS5DRIVE_ROOT from other payload ecosystems by default. */
    copy_env_string("PS5DRIVE_ROOT_OVERRIDE", PS5DRIVE_ROOT_DIR, cfg->root_dir, sizeof(cfg->root_dir));
    snprintf(cfg->pid_file, sizeof(cfg->pid_file), "%s/payload.pid", cfg->state_dir);
    snprintf(cfg->server_pid_file, sizeof(cfg->server_pid_file), "%s/server.pid", cfg->state_dir);
    cfg->web_port = parse_env_int("PS5DRIVE_WEB_PORT", PS5DRIVE_WEB_PORT);
    cfg->api_port = parse_env_int("PS5DRIVE_API_PORT", PS5DRIVE_API_PORT);
    cfg->debug_port = parse_env_int("PS5DRIVE_DEBUG_PORT", PS5DRIVE_DEBUG_PORT);
    cfg->max_clients = parse_env_int("PS5DRIVE_MAX_CLIENTS", PS5DRIVE_MAX_CLIENTS);
    cfg->enable_test_admin = parse_env_int("PS5DRIVE_ENABLE_TEST_ADMIN", 0) != 0;
}

static int state_dir_usable(const char *path) {
    if (!path || !*path) return 0;
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode)) return 0;
    return access(path, R_OK | W_OK | X_OK) == 0;
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

static int write_pid_file(const char *path, pid_t pid) {
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fprintf(fp, "%d\n", (int)pid);
    fclose(fp);
    return 0;
}

static pid_t parse_pid_field(const char *text, const char *field) {
    if (!text || !field || !*field) return -1;
    char key[64];
    if (snprintf(key, sizeof(key), "\"%s\":", field) >= (int)sizeof(key)) return -1;
    const char *p = strstr(text, key);
    if (!p) return -1;
    p += strlen(key);
    while (*p == ' ' || *p == '\t') ++p;
    errno = 0;
    long val = strtol(p, NULL, 10);
    if (errno != 0 || val <= 0 || val > INT_MAX) return -1;
    return (pid_t)val;
}

static int query_health_info_from_port(int port, health_info_t *out) {
    if (!out) return -1;
    out->pid = -1;
    out->ppid = -1;

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

    out->pid = parse_pid_field(buf, "pid");
    out->ppid = parse_pid_field(buf, "ppid");
    return out->pid > 0 ? 0 : -1;
}

static int query_health_info(health_info_t *out) {
    if (!out) return -1;
    out->pid = -1;
    out->ppid = -1;

    int ports[] = {
        g_cfg.api_port,
        g_cfg.web_port,
        PS5DRIVE_API_PORT,
        PS5DRIVE_WEB_PORT,
        8904,
        8903
    };
    for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); ++i) {
        if (ports[i] <= 0) continue;
        if (query_health_info_from_port(ports[i], out) == 0 && out->pid > 0) return 0;
    }
    return -1;
}

static int request_stop_on_port(int port) {
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
        "POST /api/stop HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    if (send(fd, req, strlen(req), 0) < 0) {
        close(fd);
        return -1;
    }

    char sink[256];
    (void)recv(fd, sink, sizeof(sink), 0);
    close(fd);
    return 0;
}

static void request_stop_existing_instances(void) {
    int ports[] = {
        g_cfg.api_port,
        g_cfg.web_port,
        PS5DRIVE_API_PORT,
        PS5DRIVE_WEB_PORT,
        8904,
        8903
    };
    for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); ++i) {
        if (ports[i] <= 0) continue;
        (void)request_stop_on_port(ports[i]);
    }
    usleep(250 * 1000);
}

static int is_process_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

static int terminate_pid(pid_t pid, int timeout_ms) {
    if (pid <= 0) return 0;
    if (!is_process_alive(pid)) return 0;

    if (kill(pid, SIGTERM) != 0 && errno != ESRCH) return -1;
    int ticks = timeout_ms / 100;
    for (int i = 0; i < ticks; ++i) {
        if (!is_process_alive(pid)) return 0;
        usleep(100 * 1000);
    }

    if (is_process_alive(pid)) {
        if (kill(pid, SIGKILL) != 0 && errno != ESRCH) return -1;
        for (int i = 0; i < 20; ++i) {
            if (!is_process_alive(pid)) return 0;
            usleep(50 * 1000);
        }
    }
    return is_process_alive(pid) ? -1 : 0;
}

static void cleanup_pid_files(void) {
    if (!g_pid_tracking_enabled) return;
    pid_t current_payload = read_pid_file(g_cfg.pid_file);
    if (current_payload == g_self_pid) unlink(g_cfg.pid_file);

    pid_t current_server = read_pid_file(g_cfg.server_pid_file);
    if (current_server == g_child_pid || !is_process_alive(current_server)) {
        unlink(g_cfg.server_pid_file);
    }
}

static void handle_parent_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static void install_parent_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_parent_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static void kill_previous_instances(void) {
    request_stop_existing_instances();

    pid_t old_parent = -1;
    pid_t old_server = -1;

    if (g_pid_tracking_enabled) {
        old_parent = read_pid_file(g_cfg.pid_file);
        old_server = read_pid_file(g_cfg.server_pid_file);
    }

    /* Fallback when pid files are missing/unusable: ask existing API health for PID. */
    if (old_parent <= 0 || old_server <= 0) {
        health_info_t info;
        if (query_health_info(&info) == 0) {
            if (old_server <= 0) old_server = info.pid;
            if (old_parent <= 0) old_parent = info.ppid;
            if (old_parent <= 0) old_parent = info.pid;
        }
    }

    if (old_parent > 0 && old_parent != g_self_pid) {
        (void)terminate_pid(old_parent, 3000);
    }
    if (old_server > 0 && old_server != g_self_pid) {
        (void)terminate_pid(old_server, 3000);
    }
}

static volatile sig_atomic_t g_child_running = 1;

static void handle_child_signal(int sig) {
    (void)sig;
    g_child_running = 0;
}

static void install_child_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_child_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static int run_server_child(void) {
    g_child_running = 1;
    install_child_signals();

    int child_pid_written = 0;
    if (g_pid_tracking_enabled && write_pid_file(g_cfg.server_pid_file, getpid()) == 0) {
        child_pid_written = 1;
    } else if (g_pid_tracking_enabled) {
        notify_error(PS5DRIVE_TITLE, "Server PID file write failed; continuing.");
    }

    ps5drive_server_config_t server_cfg;
    memset(&server_cfg, 0, sizeof(server_cfg));
    server_cfg.root_dir = g_cfg.root_dir;
    server_cfg.state_dir = g_cfg.state_dir;
    server_cfg.web_port = g_cfg.web_port;
    server_cfg.api_port = g_cfg.api_port;
    server_cfg.debug_port = g_cfg.debug_port;
    server_cfg.max_clients = g_cfg.max_clients;
    server_cfg.enable_test_admin = g_cfg.enable_test_admin;
    server_cfg.version = PS5DRIVE_VERSION;

    char msg[256];
    snprintf(msg, sizeof(msg), "WEB %d / API %d / DBG %d (v%s)",
             g_cfg.web_port, g_cfg.api_port, g_cfg.debug_port, PS5DRIVE_VERSION);
    notify_info(PS5DRIVE_TITLE, msg);

    errno = 0;
    int rc = ps5drive_server_run(&server_cfg, &g_child_running);
    if (rc != 0) {
        char emsg[256];
        int err = errno;
        const char *detail = strerror(err);
        snprintf(emsg, sizeof(emsg), "Server start failed (errno=%d: %s)", err, detail ? detail : "unknown");
        notify_error(PS5DRIVE_TITLE, emsg);
    }
    if (child_pid_written) unlink(g_cfg.server_pid_file);
    return rc == 0 ? 0 : 1;
}

static int spawn_server_child(void) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int rc = run_server_child();
        _exit(rc);
    }
    g_child_pid = pid;
    return 0;
}

static void stop_child_if_running(void) {
    if (g_child_pid <= 0) return;
    (void)terminate_pid(g_child_pid, 3000);
    (void)waitpid(g_child_pid, NULL, 0);
    g_child_pid = -1;
}

static void format_exit_reason(int status, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    if (WIFEXITED(status)) {
        snprintf(out, out_len, "exit=%d", WEXITSTATUS(status));
        return;
    }
    if (WIFSIGNALED(status)) {
        snprintf(out, out_len, "signal=%d", WTERMSIG(status));
        return;
    }
    snprintf(out, out_len, "status=%d", status);
}

int main(void) {
    g_self_pid = getpid();
    load_runtime_cfg(&g_cfg);
    install_parent_signals();

    g_pid_tracking_enabled = state_dir_usable(g_cfg.state_dir);
    if (!g_pid_tracking_enabled) {
        if (access("/tmp", R_OK | W_OK | X_OK) == 0) {
            snprintf(g_cfg.pid_file, sizeof(g_cfg.pid_file), "/tmp/ps5drive_payload.pid");
            snprintf(g_cfg.server_pid_file, sizeof(g_cfg.server_pid_file), "/tmp/ps5drive_server.pid");
            g_pid_tracking_enabled = 1;
            notify_info(PS5DRIVE_TITLE, "State dir unavailable; using /tmp PID files.");
        } else {
            notify_info(PS5DRIVE_TITLE, "State dir unavailable; PID tracking disabled.");
        }
    }

    kill_previous_instances();
    if (g_pid_tracking_enabled) {
        if (write_pid_file(g_cfg.pid_file, g_self_pid) != 0) {
            notify_error(PS5DRIVE_TITLE, "Payload PID file write failed; continuing.");
            g_pid_tracking_enabled = 0;
        } else {
            atexit(cleanup_pid_files);
        }
    }

    int backoff = PS5DRIVE_RESTART_BACKOFF_SEC;
    int consecutive_child_failures = 0;
    int over_limit_failures = 0;
    time_t child_started_at = 0;
    while (g_running) {
        if (g_child_pid <= 0) {
            if (spawn_server_child() != 0) {
                notify_error(PS5DRIVE_TITLE, "Failed to start server child.");
                sleep(backoff);
                if (backoff < PS5DRIVE_RESTART_MAX_BACKOFF_SEC) backoff *= 2;
                continue;
            }
            child_started_at = time(NULL);
            backoff = PS5DRIVE_RESTART_BACKOFF_SEC;
        }

        int status = 0;
        pid_t rc = waitpid(g_child_pid, &status, WNOHANG);
        if (rc == 0) {
            sleep(1);
            continue;
        }
        if (rc == g_child_pid) {
            if (!g_running) break;
            time_t now = time(NULL);
            int ran_secs = (child_started_at > 0 && now >= child_started_at) ? (int)(now - child_started_at) : 0;
            char reason[64];
            format_exit_reason(status, reason, sizeof(reason));

            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                consecutive_child_failures = 0;
                over_limit_failures = 0;
            } else if (ran_secs <= PS5DRIVE_CHILD_FAIL_FAST_SEC) {
                consecutive_child_failures += 1;
            } else {
                consecutive_child_failures = 1;
                over_limit_failures = 0;
            }

            g_child_pid = -1;
            if (consecutive_child_failures >= PS5DRIVE_MAX_CONSECUTIVE_CHILD_FAILS) {
                over_limit_failures += 1;
                if (over_limit_failures == 1 || (over_limit_failures % 3) == 0) {
                    char msg[256];
                    snprintf(msg, sizeof(msg),
                             "Server child keeps exiting (%s). Retrying in %d sec.",
                             reason, backoff);
                    notify_error(PS5DRIVE_TITLE, msg);
                }
            } else {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "Server child exited (%s). Restarting %d/%d...",
                         reason,
                         consecutive_child_failures,
                         PS5DRIVE_MAX_CONSECUTIVE_CHILD_FAILS);
                notify_error(PS5DRIVE_TITLE, msg);
                over_limit_failures = 0;
            }
            sleep(backoff);
            if (backoff < PS5DRIVE_RESTART_MAX_BACKOFF_SEC) backoff *= 2;
            continue;
        }
        sleep(1);
    }

    stop_child_if_running();
    notify_success(PS5DRIVE_TITLE, "Stopped.");
    return 0;
}
