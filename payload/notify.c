#include <stdio.h>
#include <string.h>

#include "notify.h"

typedef struct notify_request {
    char reserved[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

static void send_notification(const char *message) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, message, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

void notify_info(const char *title, const char *message) {
    char full[256];
    snprintf(full, sizeof(full), "%s: %s", title, message);
    send_notification(full);
}

void notify_success(const char *title, const char *message) {
    char full[256];
    snprintf(full, sizeof(full), "[OK] %s: %s", title, message);
    send_notification(full);
}

void notify_error(const char *title, const char *message) {
    char full[256];
    snprintf(full, sizeof(full), "[ERR] %s: %s", title, message);
    send_notification(full);
}
