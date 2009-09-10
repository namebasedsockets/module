#ifndef NAMESTACK_PRIV_H
#define NAMESTACK_PRIV_H

#include <linux/types.h>

/* Registration/unregistration functions */
extern int name_af_init(void);
extern void name_af_exit(void);

/* Name resolution functions */
typedef void (*query_resolv_cb)(const __u8 *response, int len, void *data);
int name_send_query(const char *name, query_resolv_cb cb, void *data);
void name_cancel_query(void *data);

/* Name registration (bind()/DNS update) functions */
typedef void (*register_cb)(int result, void *data);
int name_send_registration(const char *name, register_cb cb, void *data);
void name_delete_registration(const char *name);

#endif /* NAMESTACK_PRIV_H */
