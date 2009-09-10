#ifndef NAMESTACKNL_H
#define NAMESTACKNL_H

/* Message types */
enum {
    NAME_STACK_REGISTER,
    /* FIXME: a QUERY is sent by the kernel to the daemon, and never
     * vice-versa.  Should I separate message types by the direction they're
     * sent?
     */
    NAME_STACK_QUERY,
    NAME_STACK_REPLY
};

#endif
