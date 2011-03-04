#ifndef HAPPY_EYEBALLS_H_
#define HAPPY_EYEBALLS_H_

#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/inname.h>
#include <linux/math64.h>

void happy_eyeballs_init(void);
int happy_eyeballs_af_pref(void);
void happy_eyeballs_v6_success(void);
void happy_eyeballs_v4_success(void);

#endif /*HAPPY_EYEBALLS_H_*/