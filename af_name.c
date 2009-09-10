#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/inname.h>
#include "namestack_priv.h"

struct name_sock
{
	struct sock sk;
	struct name_addr sname;
	struct name_addr dname;
};

static int name_stream_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		goto out;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	sock_put(sk);
out:
	return 0;
}

enum {
	NAME_RESOLVING = 1,
	NAME_CONNECTING,
	NAME_LISTEN,
	NAME_ESTABLISHED,
};

enum {
	NAMEF_RESOLVING   = (1 << NAME_RESOLVING),
	NAMEF_CONNECTING  = (1 << NAME_CONNECTING),
	NAMEF_LISTEN      = (1 << NAME_LISTEN),
	NAMEF_ESTABLISHED = (1 << NAME_ESTABLISHED),
};

static long name_wait_for_connect(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	while ((1 << sk->sk_state) & (NAMEF_RESOLVING | NAMEF_CONNECTING)) {
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	}
	finish_wait(sk->sk_sleep, &wait);
	return timeo;
}

static void name_stream_query_resolve(const u_char *response, int len,
				      void *data)
{
	struct socket *sock = data;
	struct sock *sk = sock->sk;

	sk->sk_state = NAME_CONNECTING;
	/* FIXME: send off connect request here */
}

static int name_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			       int addr_len, int flags)
{
	struct sockaddr_name *sname = (struct sockaddr_name *)uaddr;
	int err;
	struct sock *sk;
	long timeo;

	if (addr_len < sizeof(struct sockaddr_name))
		return -EINVAL;
	if (uaddr->sa_family != AF_NAME)
		return -EAFNOSUPPORT;

	printk(KERN_INFO "name_stream_connect requested to %s\n",
	       sname->sname_addr.name);

	sk = sock->sk;
	lock_sock(sk);

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;

		sock->state = SS_CONNECTING;
		sk->sk_state = NAME_RESOLVING;
		err = name_send_query(sname->sname_addr.name,
				      name_stream_query_resolve, sock);
		if (err)
			goto out;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	if ((1 << sk->sk_state) & (NAMEF_RESOLVING | NAMEF_CONNECTING)) {
		if (!timeo || !name_wait_for_connect(sk, timeo)) {
			/* err set above */
			goto out;
		}
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	/* FIXME: connection may have been closed externally, need to check
	 * state.
	 */
	sock->state = SS_CONNECTED;
	err = 0;

out:
	release_sock(sk);
	return err;
}

static const struct proto_ops name_stream_ops = {
	.family = PF_NAME,
	.owner = THIS_MODULE,
	.release = name_stream_release,
	.bind = sock_no_bind,
	.connect = name_stream_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = sock_no_poll,
	.ioctl = sock_no_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = sock_no_compat_ioctl,
#endif
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = sock_no_sendmsg,
	.recvmsg = sock_no_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto name_stream_proto = {
	.name = "NAME_STREAM",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct name_sock),
};

static int name_dgram_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		goto out;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	sock_put(sk);
out:
	return 0;
}

static const struct proto_ops name_dgram_ops = {
	.family = PF_NAME,
	.owner = THIS_MODULE,
	.release = name_dgram_release,
	.bind = sock_no_bind,
	.connect = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = sock_no_poll,
	.ioctl = sock_no_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = sock_no_compat_ioctl,
#endif
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = sock_no_sendmsg,
	.recvmsg = sock_no_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto name_dgram_proto = {
	.name = "NAME_DGRAM",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct name_sock),
};

static inline struct name_sock *name_sk(const struct sock *sk)
{
	return (struct name_sock *)sk;
}

static struct sock *name_alloc_socket(struct net *net, struct proto *proto)
{
	struct sock *sk = sk_alloc(net, AF_NAME, GFP_ATOMIC, proto);
	struct name_sock *name;

	if (!sk)
		goto out;

	sock_init_data(NULL, sk);

	name = name_sk(sk);
	name->sname.name[0] = 0;
	name->dname.name[0] = 0;
out:
	return sk;
}

static int name_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	struct name_sock *name;
	struct proto *proto;
	const struct proto_ops *proto_ops;
	int rc;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	rc = 0;
	switch (sock->type)
	{
	case SOCK_STREAM:
		proto = &name_stream_proto;
		proto_ops = &name_stream_ops;
		break;
	case SOCK_DGRAM:
		proto = &name_dgram_proto;
		proto_ops = &name_dgram_ops;
		break;
	default:
		rc = -EPROTONOSUPPORT;
	}
	if (rc)
		goto out;

	sock->ops = proto_ops;

	rc = -ENOMEM;
	if (!(sk = name_alloc_socket(net, proto)))
		goto out;

	name = name_sk(sk);

	sock_init_data(sock, sk);

	rc = 0;
out:
	return rc;
}

static struct net_proto_family name_family_ops = {
	.family = PF_NAME,
	.create = name_create,
	.owner = THIS_MODULE,
};

int name_af_init(void)
{
	int rc;

	rc = proto_register(&name_stream_proto, 1);
	if (rc)
		goto out;

	rc = proto_register(&name_dgram_proto, 1);
	if (rc)
		goto out;

	rc = sock_register(&name_family_ops);
out:
	return rc;
}

void name_af_exit(void)
{
	proto_unregister(&name_stream_proto);
	proto_unregister(&name_dgram_proto);
	sock_unregister(name_family_ops.family);
}

EXPORT_SYMBOL(name_af_init);
EXPORT_SYMBOL(name_af_exit);
