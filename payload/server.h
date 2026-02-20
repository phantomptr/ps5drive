#ifndef PS5DRIVE_SERVER_H
#define PS5DRIVE_SERVER_H

#if defined(PS5DRIVE_PS4_BUILD)
typedef int sig_atomic_t;
#else
#include <signal.h>
#endif

typedef struct ps5drive_server_config {
    const char *root_dir;
    const char *state_dir;
    const char *config_path;
    int web_port;
    int api_port;
    int debug_port;
    int max_clients;
    int enable_test_admin;
    int secure_mode;
    const char *auth_username;
    const char *auth_password;
    const char *version;
} ps5drive_server_config_t;

int ps5drive_server_run(const ps5drive_server_config_t *cfg, volatile sig_atomic_t *running_flag);

#endif /* PS5DRIVE_SERVER_H */
