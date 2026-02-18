#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "notify.h"

#ifndef PS5DRIVE_VERSION
#define PS5DRIVE_VERSION "dev"
#endif

static volatile sig_atomic_t g_running = 1;
static pid_t g_self_pid = -1;

static int ensure_state_dir(void) {
    if (mkdir(PS5DRIVE_STATE_DIR, 0777) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static pid_t read_pid_file(void) {
    FILE *fp = fopen(PS5DRIVE_PID_FILE, "r");
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

static int write_pid_file(pid_t pid) {
    FILE *fp = fopen(PS5DRIVE_PID_FILE, "w");
    if (!fp) return -1;
    fprintf(fp, "%d\n", (int)pid);
    fclose(fp);
    return 0;
}

static int is_process_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

static void cleanup_pid_file(void) {
    pid_t recorded = read_pid_file();
    if (recorded == g_self_pid) unlink(PS5DRIVE_PID_FILE);
}

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}

static void stop_previous_instance_if_any(void) {
    pid_t old_pid = read_pid_file();
    if (old_pid <= 0 || old_pid == g_self_pid) return;

    if (!is_process_alive(old_pid)) {
        unlink(PS5DRIVE_PID_FILE);
        return;
    }

    if (kill(old_pid, SIGTERM) != 0 && errno != ESRCH) return;

    for (int i = 0; i < 20; ++i) {
        if (!is_process_alive(old_pid)) return;
        usleep(100 * 1000);
    }

    if (is_process_alive(old_pid)) {
        (void)kill(old_pid, SIGKILL);
        for (int i = 0; i < 10; ++i) {
            if (!is_process_alive(old_pid)) return;
            usleep(50 * 1000);
        }
    }
}

int main(void) {
    char msg[256];

    g_self_pid = getpid();
    install_signal_handlers();

    if (ensure_state_dir() != 0) {
        notify_error(PS5DRIVE_TITLE, "Failed to create state directory.");
        return 1;
    }

    stop_previous_instance_if_any();

    if (write_pid_file(g_self_pid) != 0) {
        notify_error(PS5DRIVE_TITLE, "Failed to write PID file.");
        return 1;
    }
    atexit(cleanup_pid_file);

    snprintf(msg, sizeof(msg), "Hello world (v%s)", PS5DRIVE_VERSION);
    notify_info(PS5DRIVE_TITLE, msg);

    while (g_running) sleep(1);

    notify_success(PS5DRIVE_TITLE, "Stopped.");
    return 0;
}
