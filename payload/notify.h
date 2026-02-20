#ifndef PS5DRIVE_NOTIFY_H
#define PS5DRIVE_NOTIFY_H

#if defined(PS5DRIVE_PS4_BUILD)
#ifndef __BEGIN_DECLS
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#else
#include <sys/cdefs.h>
#endif

__BEGIN_DECLS

void notify_info(const char *title, const char *message);
void notify_success(const char *title, const char *message);
void notify_error(const char *title, const char *message);

__END_DECLS

#endif /* PS5DRIVE_NOTIFY_H */
