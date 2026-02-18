#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "notify.h"

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

static int is_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

static int terminate_pid(pid_t pid) {
    if (pid <= 0) return -1;

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

int main(void) {
    pid_t pid = read_pid_file();

    notify_info("PS5 Drive Killer", "Attempting to stop ps5drive...");

    if (pid <= 0) {
        notify_error("PS5 Drive Killer", "No valid PID found.");
        unlink(PS5DRIVE_PID_FILE);
        return 1;
    }

    if (terminate_pid(pid) != 0) {
        notify_error("PS5 Drive Killer", "Failed to stop ps5drive.");
        return 1;
    }

    unlink(PS5DRIVE_PID_FILE);
    notify_success("PS5 Drive Killer", "ps5drive stopped.");
    return 0;
}
