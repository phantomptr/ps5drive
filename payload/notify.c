#if defined(PS5DRIVE_PS4_BUILD)
#include "ps4_compat.h"
#else
#include <stdio.h>
#include <string.h>
#endif

#include "notify.h"

typedef struct notify_request {
    char reserved[45];
    char message[3075];
} notify_request_t;

#if !defined(PS5DRIVE_PS4_BUILD)
int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);
#endif

static void send_notification(const char *message) {
#if defined(PS5DRIVE_PS4_BUILD)
    ps4_sdk_init();
#endif
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, message, sizeof(req.message) - 1);
#if defined(PS5DRIVE_PS4_BUILD)
    sceKernelSendNotificationRequest(0, (SceNotificationRequest *)&req, sizeof(req), 0);
#else
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
#endif
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
