#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/inname.h>
#include "dns.h"
#include "nameser.h"
#include "namestack_priv.h"

struct name_stream_sock
{
	struct sock sk;
	struct name_addr sname;
	struct name_addr dname;
	u_char *dname_answer;
	int dname_answer_len;
};

static inline struct name_stream_sock *name_stream_sk(const struct sock *sk)
{
	return (struct name_stream_sock *)sk;
}

static int name_stream_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);

	if (!sk)
		goto out;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);

	if (name->dname_answer) {
		kfree(name->dname_answer);
		name->dname_answer = NULL;
		name->dname_answer_len = 0;
	}

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	sock_put(sk);
out:
	return 0;
}

enum {
	NAME_CLOSED = 1,
	NAME_RESOLVING,
	NAME_CONNECTING,
	NAME_LISTEN,
	NAME_ESTABLISHED,
};

enum {
	NAMEF_CLOSED      = (1 << NAME_CLOSED),
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

static void name_stream_connect_to_resolved_name(struct sock *sk)
{
	struct name_stream_sock *name = name_stream_sk(sk);
	uint16_t rdlength;
	const u_char *rdata;

	if (!find_answer_of_type(name->dname_answer, name->dname_answer_len,
				 T_AAAA, 0, &rdlength, &rdata)) {
		/* FIXME: placeholder */
		printk(KERN_INFO "connect to IPv6 address\n");
	}
	else if (!find_answer_of_type(name->dname_answer,
				      name->dname_answer_len,
				      T_A, 0, &rdlength, &rdata)) {
		/* FIXME: placeholder */
		printk(KERN_INFO "connect to IPv4 address\n");
	}
	else {
		printk(KERN_WARNING "no supported address type found\n");
		sk->sk_state = NAME_CLOSED;
		sk->sk_state_change(sk);
	}
}

static void name_stream_query_resolve(const u_char *response, int len,
				      void *data)
{
	struct socket *sock = data;
	struct sock *sk = sock->sk;

	if (len > 0)
	{
		struct name_stream_sock *name = name_stream_sk(sk);

		name->dname_answer = kmalloc(len, GFP_ATOMIC);
		if (!name->dname_answer)
		{
			/* Allocation failure, close request */
			sk->sk_state = NAME_CLOSED;
			sk->sk_state_change(sk);
		}
		else
		{
			name->dname_answer_len = len;
			memcpy(name->dname_answer, response, len);
			sk->sk_state = NAME_CONNECTING;
			sk->sk_state_change(sk);
			name_stream_connect_to_resolved_name(sk);
		}
	}
	else
	{
		/* Name resolution failure, close request */
		sk->sk_state = NAME_CLOSED;
		sk->sk_state_change(sk);
	}
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

	if ((1 << sk->sk_state) & (NAMEF_CLOSED)) {
		sock->state = SOCK_DEAD;
		err = -EHOSTUNREACH;
	}
	else {
		sock->state = SS_CONNECTED;
		err = 0;
	}

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
	.obj_size = sizeof(struct name_stream_sock),
};

static struct sock *name_alloc_stream_socket(struct net *net,
					     struct socket *sock)
{
	struct sock *sk = sk_alloc(net, AF_NAME, GFP_ATOMIC,
				   &name_stream_proto);
	struct name_stream_sock *name;

	if (!sk)
		goto out;

	sock->ops = &name_stream_ops;
	sock_init_data(sock, sk);

	name = name_stream_sk(sk);
	name->sname.name[0] = 0;
	name->dname.name[0] = 0;
	name->dname_answer = NULL;
	name->dname_answer_len = 0;
out:
	return sk;
}

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

struct name_dgram_sock
{
	struct sock sk;
	struct name_addr sname;
	struct name_addr dname;
};

static struct proto name_dgram_proto = {
	.name = "NAME_DGRAM",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct name_dgram_sock),
};

static inline struct name_dgram_sock *name_dgram_sk(const struct sock *sk)
{
	return (struct name_dgram_sock *)sk;
}

static struct sock *name_alloc_dgram_socket(struct net *net,
					    struct socket *sock)
{
	struct sock *sk = sk_alloc(net, AF_NAME, GFP_ATOMIC, &name_dgram_proto);
	struct name_dgram_sock *name;

	if (!sk)
		goto out;

	sock->ops = &name_dgram_ops;
	sock_init_data(sock, sk);

	name = name_dgram_sk(sk);
	name->sname.name[0] = 0;
	name->dname.name[0] = 0;
out:
	return sk;
}

static int name_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	rc = 0;
	switch (sock->type)
	{
	case SOCK_STREAM:
		rc = -ENOMEM;
		if ((sk = name_alloc_stream_socket(net, sock)))
			rc = 0;
		break;
	case SOCK_DGRAM:
		rc = -ENOMEM;
		if ((sk = name_alloc_dgram_socket(net, sock)))
			rc = 0;
		break;
	default:
		rc = -EPROTONOSUPPORT;
	}

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
