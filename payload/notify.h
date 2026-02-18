#ifndef PS5DRIVE_NOTIFY_H
#define PS5DRIVE_NOTIFY_H

#include <sys/cdefs.h>

__BEGIN_DECLS

void notify_info(const char *title, const char *message);
void notify_success(const char *title, const char *message);
void notify_error(const char *title, const char *message);

__END_DECLS

#endif /* PS5DRIVE_NOTIFY_H */
