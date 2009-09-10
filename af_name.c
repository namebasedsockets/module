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

static const struct proto_ops name_stream_ops = {
	.family = PF_NAME,
	.owner = THIS_MODULE,
	.release = name_stream_release,
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

EXPORT_SYMBOL(name_af_init);
