#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <linux/inname.h>
#include "dns.h"
#include "nameser.h"
#include "namestack_priv.h"

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

struct name_stream_sock
{
	struct sock sk;
	struct sockaddr_name sname;
	struct sockaddr_name dname;
	u_char *dname_answer;
	int dname_answer_len;
	uint16_t dname_answer_index;
	int async_error;
	struct socket *transport_sock;
};

static inline struct name_stream_sock *name_stream_sk(const struct sock *sk)
{
	return (struct name_stream_sock *)sk;
}

static void name_stream_state_change(struct sock *sk)
{
	struct name_stream_sock *name;

	read_lock(&sk->sk_callback_lock);
	if (!(name = sk->sk_user_data))
		goto out;

	printk(KERN_INFO "sk_state is %d\n", sk->sk_state);
	switch (sk->sk_state) {
	case TCP_ESTABLISHED:
		name->sk.sk_state = NAME_ESTABLISHED;
		name->sk.sk_state_change(&name->sk);
		break;
	case TCP_FIN_WAIT1:
		/* The client initiated a shutdown of the socket */
		break;
	case TCP_CLOSE_WAIT:
		/* The server initiated a shutdown of the socket */
	case TCP_SYN_SENT:
	case TCP_CLOSING:
		/*
		 * If the server closed down the connection, make sure that
		 * we back off before reconnecting
		 */
		break;
	case TCP_LAST_ACK:
		break;
	case TCP_CLOSE:
		break;
	}
 out:
	read_unlock(&sk->sk_callback_lock);
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
		name->dname_answer_index = 0;
	}
	if (name->transport_sock) {
		kernel_sock_shutdown(name->transport_sock, SHUT_WR);
		sock_release(name->transport_sock);
		name->transport_sock = NULL;
	}

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	sock_put(sk);
out:
	return 0;
}

static int
name_stream_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_name *addr = (struct sockaddr_name *)uaddr;
	int err;

	if (addr_len < sizeof(struct sockaddr_name)) {
		err = -EINVAL;
		goto out;
	}
	printk(KERN_INFO "requesting bind to %s\n", addr->sname_addr.name);
	/* FIXME: need to:
	 * 1. Attempt to claim the name (in DNS).  Can't continue until this
	 *    succeeds.  This should block the caller until this process
	 *    completes, perhaps with another wait loop?
	 * 2. Attempt to bind to the specified port on each transport socket.
	 *    Unfortunately none may exist at the moment, because they're not
	 *    created until connect.  That needs to be fixed too.
	 * 3. Copy the name into the source name (easy.)
	 */
	err = 0;
out:
	return err;
}

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

static int name_stream_connect_to_v6_address(struct sock *sk, uint16_t rdlength,
					     const u_char *rdata)
{
	struct name_stream_sock *name = name_stream_sk(sk);
	struct sockaddr_in6 sin6;
	struct in6_addr *addr;
	char address[46], *p;
	int i, in_zero = 0, err;

	if (rdlength != sizeof(struct in6_addr)) {
		printk(KERN_WARNING
		       "address record %d has invalid length %d\n",
		       name->dname_answer_index, rdlength);
		return -EHOSTUNREACH;
	}
	addr = (struct in6_addr *)rdata;
	p = address;
	for (i = 0; i < 7; i++)
	{
		if (!addr->s6_addr16[i])
		{
			if (!in_zero)
			{
				*p++ = ':';
				in_zero = 1;
			}
		}
		else
		{
			int n;

			sprintf(p, "%x:%n", ntohs(addr->s6_addr16[i]), &n);
			p += n;
			in_zero = 0;
		}
	}
	sprintf(p, "%x", ntohs(addr->s6_addr16[7]));
	printk(KERN_INFO "connect to IPv6 address %s:%d\n", address,
	       ntohs(name->dname.sname_port));
	err = sock_create_kern(PF_INET6, SOCK_STREAM, 0, &name->transport_sock);
	if (err)
		goto out;
	name->transport_sock->sk->sk_user_data = name;
	name->transport_sock->sk->sk_state_change = name_stream_state_change;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = name->dname.sname_port;
	memcpy(&sin6.sin6_addr, addr, sizeof(*addr));
	/* FIXME: need to set name options in socket */
	err = kernel_connect(name->transport_sock, (struct sockaddr *)&sin6,
			     sizeof(sin6), O_NONBLOCK);
	/* The expected error is EINPROGRESS, as the socket connection kicks
	 * off.  Return success in this case.
	 */
	if (err == -EINPROGRESS)
		err = 0;
out:
	return err;
}

static int name_stream_connect_to_v4_address(struct sock *sk, uint16_t rdlength,
					     const u_char *rdata)
{
	struct name_stream_sock *name = name_stream_sk(sk);
	int err;
	struct sockaddr_in sin;
	uint32_t addr;
	char address[16], *p;
	const u_char *addrp;

	if (rdlength != sizeof(uint32_t)) {
		printk(KERN_WARNING
		       "address record %d has invalid length %d\n",
		       name->dname_answer_index, rdlength);
		return -EHOSTUNREACH;
	}
	addr = *(uint32_t *)rdata;
	p = address;
	for (addrp = (u_char *)&addr;
	     addrp - (u_char *)&addr < sizeof(uint32_t);
	     addrp++)
	{
		int n;

		sprintf(p, "%d%n", *addrp, &n);
		p += n;
		if (addrp < (u_char *)&addr + sizeof(uint32_t) - 1)
			*p++ = '.';
	}
	printk(KERN_INFO "connect to IPv4 address %s:%d\n", address,
	       ntohs(name->dname.sname_port));
	err = sock_create_kern(PF_INET, SOCK_STREAM, 0, &name->transport_sock);
	if (err)
		goto out;
	name->transport_sock->sk->sk_user_data = name;
	name->transport_sock->sk->sk_state_change = name_stream_state_change;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = name->dname.sname_port;
	sin.sin_addr.s_addr = *(uint32_t *)rdata;
	err = kernel_connect(name->transport_sock, (struct sockaddr *)&sin,
			     sizeof(sin), O_NONBLOCK);
	/* The expected error is EINPROGRESS, as the socket connection kicks
	 * off.  Return success in this case.
	 */
	if (err == -EINPROGRESS)
		err = 0;
out:
	return err;
}

static void name_stream_connect_to_resolved_name(struct sock *sk)
{
	struct name_stream_sock *name = name_stream_sk(sk);
	uint16_t rdlength;
	const u_char *rdata;
	int err;

	if (!find_answer_of_type(name->dname_answer, name->dname_answer_len,
				 T_AAAA, name->dname_answer_index, &rdlength,
				 &rdata)) {
		err = name_stream_connect_to_v6_address(sk, rdlength,
							    rdata);
		if (err) {
			/* FIXME: get next address rather than closing the
			 * connection request.
			 */
			sk->sk_state = NAME_CLOSED;
			sk->sk_state_change(sk);
		}
	}
	else if (!find_answer_of_type(name->dname_answer,
				      name->dname_answer_len,
				      T_A, name->dname_answer_index, &rdlength,
				      &rdata)) {
		err = name_stream_connect_to_v4_address(sk, rdlength,
							    rdata);
		if (err) {
			/* FIXME: get next address rather than closing the
			 * connection request.
			 */
			sk->sk_state = NAME_CLOSED;
			sk->sk_state_change(sk);
		}
	}
	else {
		printk(KERN_WARNING "no supported address type found\n");
		sk->sk_state = NAME_CLOSED;
		sk->sk_state_change(sk);
		err = -EHOSTUNREACH;
	}
	name->async_error = err;
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
			name->dname_answer_index = 0;
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
	struct name_stream_sock *name;
	long timeo;

	if (addr_len < sizeof(struct sockaddr_name))
		return -EINVAL;
	if (uaddr->sa_family != AF_NAME)
		return -EAFNOSUPPORT;

	printk(KERN_INFO "name_stream_connect requested to %s:%d\n",
	       sname->sname_addr.name, ntohs(sname->sname_port));

	sk = sock->sk;
	name = name_stream_sk(sk);
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
		memcpy(&name->dname, uaddr, addr_len);
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
		struct name_stream_sock *name = name_stream_sk(sk);

		sock->state = SOCK_DEAD;
		if (name->async_error)
			err = name->async_error;
		else
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
	.bind = name_stream_bind,
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
	memset(&name->sname, 0, sizeof(name->sname));
	memset(&name->dname, 0, sizeof(name->dname));
	name->dname_answer = NULL;
	name->dname_answer_len = 0;
	name->dname_answer_index = 0;
	name->async_error = 0;
	name->transport_sock = NULL;
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
	struct sockaddr_name sname;
	struct sockaddr_name dname;
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
	memset(&name->sname, 0, sizeof(name->sname));
	memset(&name->dname, 0, sizeof(name->dname));
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
