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

#endif /* NAMESTACK_PRIV_H */