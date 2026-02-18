#include <stdio.h>

#include "notify.h"

void notify_info(const char *title, const char *message) {
    fprintf(stderr, "[INFO] %s: %s\n", title ? title : "ps5drive", message ? message : "");
}

void notify_success(const char *title, const char *message) {
    fprintf(stderr, "[OK] %s: %s\n", title ? title : "ps5drive", message ? message : "");
}

void notify_error(const char *title, const char *message) {
    fprintf(stderr, "[ERR] %s: %s\n", title ? title : "ps5drive", message ? message : "");
}
