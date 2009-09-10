#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/tcp_states.h>
#include <linux/inname.h>
#include "dns.h"
#include "nameser.h"
#include "namestack_priv.h"

enum {
	NAME_CLOSED = 1,
	NAME_RESOLVING,
	NAME_BINDING,
	NAME_CONNECTING,
	NAME_LISTEN,
	NAME_ESTABLISHED,
};

enum {
	NAMEF_CLOSED      = (1 << NAME_CLOSED),
	NAMEF_RESOLVING   = (1 << NAME_RESOLVING),
	NAMEF_BINDING     = (1 << NAME_BINDING),
	NAMEF_CONNECTING  = (1 << NAME_CONNECTING),
	NAMEF_LISTEN      = (1 << NAME_LISTEN),
	NAMEF_ESTABLISHED = (1 << NAME_ESTABLISHED),
};

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
	if (name->sname.sname_addr.name[0]) {
		name_cache_delete(name->sname.sname_addr.name);
		name_delete_registration(name->sname.sname_addr.name);
	}
	if (name->ipv6_sock) {
		kernel_sock_shutdown(name->ipv6_sock, SHUT_WR);
		sock_release(name->ipv6_sock);
		name->ipv6_sock = NULL;
	}
	if (name->ipv4_sock) {
		kernel_sock_shutdown(name->ipv4_sock, SHUT_WR);
		sock_release(name->ipv4_sock);
		name->ipv4_sock = NULL;
	}

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	sock_put(sk);
out:
	return 0;
}

static int name_bind_ipv4(struct socket *sock, __be16 port, int local)
{
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	if (local)
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = port;
	return kernel_bind(sock, (struct sockaddr *)&sin, sizeof(sin));
}

static int name_bind_ipv6(struct socket *sock, const char *fqdn, __be16 port,
			  int local)
{
	struct sockaddr_in6 sin;

	memset(&sin, 0, sizeof(sin));
	if (local) {
		__u8 loopback[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };

		memcpy(&sin.sin6_addr, &loopback, sizeof(sin.sin6_addr));
	}
	sin.sin6_port = port;
	/* FIXME: need to tie the fqdn to the socket somehow, but how? */
	return kernel_bind(sock, (struct sockaddr *)&sin, sizeof(sin));
}

static int name_create_v6_sock(int type, int protocol, struct socket **sock,
			       struct name_stream_sock *name)
{
	int err = sock_create_kern(PF_INET6, type, protocol, sock);

	if (!err) {
		int on = 1;

		err = kernel_setsockopt(*sock, IPPROTO_IPV6, IPV6_V6ONLY,
					(char *)&on, sizeof(on));
	}
	if (!err) {
		(*sock)->sk->sk_user_data = name;
		(*sock)->sk->sk_state_change = name_stream_state_change;
	}
	return err;
}

static int name_create_v4_sock(int type, int protocol, struct socket **sock,
			       struct name_stream_sock *name)
{
	int err = sock_create_kern(PF_INET, type, protocol, sock);

	if (!err) {
		(*sock)->sk->sk_user_data = name;
		(*sock)->sk->sk_state_change = name_stream_state_change;
	}
	return err;
}

static int name_bind_to_fqdn(struct name_stream_sock *name, const char *fqdn,
			     int local)
{
	int err;

	printk(KERN_INFO "bound to %s\n", fqdn);
	/* If a particular port is specified, bind() must fail if the port is
	 * unavailable, hence we must create the transport sockets if they
	 * don't already exist so we may attempt to bind to the specified port.
	 * If no port is specified, name_register() has already checked that
	 * the name is available, so bind() succeeds without needing to create
	 * the sockets yet.  (The sockets will be created as necessary during
	 * connect() or listen().)
	 */
	if (name->sname.sname_port) {
		if (!name->ipv6_sock) {
			err = name_create_v6_sock(SOCK_STREAM, 0,
						  &name->ipv6_sock, name);
			if (err)
				goto out;
		}
		if (!name->ipv4_sock) {
			err = name_create_v4_sock(SOCK_STREAM, 0,
						  &name->ipv4_sock, name);
			if (err)
				goto out;
		}
		err = name_bind_ipv6(name->ipv6_sock, fqdn,
				     name->sname.sname_port, local);
		if (!err)
			err = name_bind_ipv4(name->ipv4_sock,
					     name->sname.sname_port, local);
	}
	else
		err = 0;
out:
	return err;
}

static void name_register_cb(int result, const char *bound_name, void *data)
{
	struct socket *sock = data;
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);

	if (!result)
		result = name_bind_to_fqdn(name, bound_name, 0);
	sk->sk_state &= ~NAMEF_BINDING;
	name->async_error = -result;
}

static int name_is_local(const char *name)
{
	const char *p;

	//assert(strlen(name) > 1);
	p = name + strlen(name) - 1;
	if (*p != '.')
		return 0;
	for (p = p - 1; *p != '.' && p >= name; p--)
		;
	if (p == name)
		return 0;
	return !strcasecmp(p + 1, "localhost.");
}

static int name_register(struct socket *sock, const char *fully_qualified_name,
			__be16 port)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	int err;

	printk(KERN_INFO "name qualified as %s\n", fully_qualified_name);
	strcpy(name->sname.sname_addr.name, fully_qualified_name);
	name->sname.sname_port = port;
	err = name_cache_add(fully_qualified_name, sock);
	if (err)
		goto out;
	//assert(strlen(fully_qualified_name) > 1);
	if (!strchr(fully_qualified_name, '.')) {
		/* FIXME: name doesn't exist in any domain.  Do I need to make
		 * a canonical name out of it?
		 */
		name_cache_delete(fully_qualified_name);
		err = -EINVAL;
		goto out;
	}
	if (name_is_local(fully_qualified_name))
		err = name_bind_to_fqdn(name, fully_qualified_name, 1);
	else {
		struct in6_addr *v6_addresses;
		__be32 *v4_addresses;
		int num_v6_addresses;
		int num_v4_addresses;

		err = choose_addresses(&num_v6_addresses, &v6_addresses,
				       &num_v4_addresses, &v4_addresses);
		if (!err) {
			/* FIXME: send addresses to register with name */
			err = name_send_registration(fully_qualified_name,
						     name_register_cb, sock);
			kfree(v6_addresses);
			kfree(v4_addresses);
		}
	}
	if (err)
		name_cache_delete(fully_qualified_name);

out:
	if (err) {
		name->async_error = -err;
		sk->sk_state &= ~NAMEF_BINDING;
		sk->sk_state_change(sk);
	}
	return err;
}

static void name_qualify_cb(const char *fully_qualified_name, void *data)
{
	struct socket *sock = data;
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);

	name_register(sock, fully_qualified_name, name->sname.sname_port);
}

static long name_wait_for_bind(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	while ((1 << sk->sk_state) & NAMEF_BINDING) {
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

static int name_qualify_and_register(struct sockaddr_name *addr,
				     struct socket *sock)
{
	int err, len;
	long timeo;
	struct sock *sk;
	struct name_stream_sock *name;

	len = strlen(addr->sname_addr.name);
	if (addr->sname_addr.name[len - 1] == '.') {
		/* Name is already fully qualified, register it directly */
		err = name_register(sock, addr->sname_addr.name,
				    addr->sname_port);
	}
	else {
		sk = sock->sk;
		name = name_stream_sk(sk);

		/* Copy the port to the socket's source name, it'll be used
		 * in name_qualify_cb.
		 */
		name->sname.sname_port = addr->sname_port;
		err = name_fully_qualify(addr->sname_addr.name,
					 name_qualify_cb, sock);
		if (err)
			goto out;

		timeo = sock_sndtimeo(sk, 0);
		if ((1 << sk->sk_state) & NAMEF_BINDING) {
			if (!timeo || !name_wait_for_bind(sk, timeo))
				goto out;
			err = sock_intr_errno(timeo);
			if (signal_pending(current))
				goto out;
		}
		if (name->async_error)
			err = name->async_error;
		else
			err = 0;
	}

out:
	return err;
}
static int
name_stream_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_name *addr = (struct sockaddr_name *)uaddr;
	struct sock *sk;
	struct name_stream_sock *name;
	int err;

	if (addr_len < sizeof(struct sockaddr_name))
		return -EINVAL;
	printk(KERN_INFO "requesting bind to %s\n", addr->sname_addr.name);

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
	case SS_UNCONNECTED:
		sk->sk_state |= NAMEF_BINDING;
		break;
	};

	if (name->sname.sname_addr.name[0]) {
		/* This socket is already bound. */
		err = -EINVAL;
		goto out;
	}

	err = name_qualify_and_register(addr, sock);

out:
	release_sock(sk);
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
	err = sock_create_kern(PF_INET6, SOCK_STREAM, 0, &name->ipv6_sock);
	if (err)
		goto out;
	name->ipv6_sock->sk->sk_user_data = name;
	name->ipv6_sock->sk->sk_state_change = name_stream_state_change;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = name->dname.sname_port;
	memcpy(&sin6.sin6_addr, addr, sizeof(*addr));
	/* FIXME: need to set name options in socket */
	err = kernel_connect(name->ipv6_sock, (struct sockaddr *)&sin6,
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
	err = sock_create_kern(PF_INET, SOCK_STREAM, 0, &name->ipv4_sock);
	if (err)
		goto out;
	name->ipv4_sock->sk->sk_user_data = name;
	name->ipv4_sock->sk->sk_state_change = name_stream_state_change;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = name->dname.sname_port;
	sin.sin_addr.s_addr = *(uint32_t *)rdata;
	err = kernel_connect(name->ipv4_sock, (struct sockaddr *)&sin,
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
		if (name_is_local(name->dname.sname_addr.name)) {
			__u8 loopback[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
			struct in6_addr in6;

			memcpy(&in6.s6_addr, &loopback, sizeof(in6.s6_addr));
			err = name_stream_connect_to_v6_address(sk, sizeof(in6),
								(const u_char *)&in6);
		}
		else
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

static int name_stream_wait_for_accept(struct socket *sock, long timeo)
{
	struct sock *sk = sock->sk;
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	while ((1 << sk->sk_state) & NAMEF_LISTEN) {
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

static struct sock *name_alloc_stream_socket(struct net *net,
					     struct socket *sock);

static struct socket *create_stream_sock_from_sk(int pf, struct sock *sk)
{
	int err;
	struct socket *sock = NULL;

	err = sock_create_kern(pf, SOCK_STREAM, 0, &sock);
	if (err)
		goto out;
	sock_orphan(sock->sk);
	sock_graft(sk, sock);
out:
	return sock;
}

static int get_name_from_v6_sock(struct sockaddr_name *name,
				 struct socket *sock)
{
	struct sockaddr_in6 addr;
	int err, len = sizeof(addr);

	name->sname_family = AF_NAME;
	/* FIXME: get name from options if they're present */
	/* FIXME: what's the real domain? */
	err = sock->ops->getname(sock, (struct sockaddr *)&addr, &len, 1);
	if (err)
		goto out;
	sprintf(name->sname_addr.name,
		"\\[x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x/128].ip6.arpa",
		addr.sin6_addr.s6_addr[0],
		addr.sin6_addr.s6_addr[1],
		addr.sin6_addr.s6_addr[2],
		addr.sin6_addr.s6_addr[3],
		addr.sin6_addr.s6_addr[4],
		addr.sin6_addr.s6_addr[5],
		addr.sin6_addr.s6_addr[6],
		addr.sin6_addr.s6_addr[7],
		addr.sin6_addr.s6_addr[8],
		addr.sin6_addr.s6_addr[9],
		addr.sin6_addr.s6_addr[10],
		addr.sin6_addr.s6_addr[11],
		addr.sin6_addr.s6_addr[12],
		addr.sin6_addr.s6_addr[13],
		addr.sin6_addr.s6_addr[14],
		addr.sin6_addr.s6_addr[15]);
	name->sname_port = addr.sin6_port;
out:
	return err;
}

static int get_name_from_v4_sock(struct sockaddr_name *name,
				 struct socket *sock)
{
	/* FIXME: what's the real domain? */
	static const char domain[] = ".in-addr.arpa";
	struct sockaddr_in addr;
	int err, len = sizeof(addr);
	char *p;
	const u_char *addrp;

	name->sname_family = AF_NAME;
	/* Create a canonical name for the legacy peer.
	 * FIXME: should I attempt a reverse DNS lookup of the peer address?
	 */
	err = sock->ops->getname(sock, (struct sockaddr *)&addr, &len, 1);
	if (err)
		goto out;
	p = name->sname_addr.name;
	for (addrp = (u_char *)&addr.sin_addr.s_addr +
	     sizeof(addr.sin_addr.s_addr) - 1;
	     addrp - (u_char *)&addr.sin_addr.s_addr >= 0;
	     addrp--)
	{
		int n;

		sprintf(p, "%d%n", *addrp, &n);
		p += n;
		if (addrp > (u_char *)&addr.sin_addr.s_addr)
			*p++ = '.';
	}
	strcat(p, domain);
	name->sname_port = addr.sin_port;
out:
	return err;
}

static int name_stream_accept(struct socket *sock, struct socket *newsock,
			      int flags)
{
	struct sock *sk = sock->sk, *v6_sk, *v4_sk;
	struct sock *new_v6_sk = NULL, *new_v4_sk = NULL, *incoming_sock;
	struct inet_connection_sock *v6_icsk, *v4_icsk;
	struct name_stream_sock *name = name_stream_sk(sk), *new_name;
	int err;

	lock_sock(sk);
	/* This handles accepting connections on two incoming sockets, the IPv6
	 * and the IPv4 socket.  Rather than call kernel_accept on each one,
	 * call each one's sk_prot->accept in non-blocking mode, and wait until
	 * one of them has accepted.
	 * We "know" that each of them has an sk_prot->accept method, because
	 * they are one of AF_INET or AF_INET6 sockets:  see inet_accept, used
	 * by both, in ipv4/af_inet.c.
	 */
	err = -EINVAL;
	if (!name->ipv6_sock || !name->ipv6_sock->sk->sk_prot->accept)
		goto out_err;
	if (!name->ipv4_sock || !name->ipv4_sock->sk->sk_prot->accept)
		goto out_err;

	err = -EAGAIN;
	new_v6_sk = name->ipv6_sock->sk->sk_prot->accept(name->ipv6_sock->sk,
							 O_NONBLOCK, &err);
	if (unlikely(new_v6_sk))
		goto handle_incoming;
	if (err != -EAGAIN)
		goto out_err;
	new_v4_sk = name->ipv4_sock->sk->sk_prot->accept(name->ipv4_sock->sk,
							 O_NONBLOCK, &err);
	if (unlikely(new_v4_sk))
		goto handle_incoming;
	if (err != -EAGAIN)
		goto out_err;

	sk->sk_state = NAME_LISTEN;

	v6_sk = name->ipv6_sock->sk;
	v6_icsk = inet_csk(v6_sk);
	v4_sk = name->ipv4_sock->sk;
	v4_icsk = inet_csk(v4_sk);

	if (reqsk_queue_empty(&v6_icsk->icsk_accept_queue) &&
	    reqsk_queue_empty(&v4_icsk->icsk_accept_queue)) {
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		err = -EAGAIN;
		if (!timeo)
			goto out_wait_err;
		release_sock(sk);
		err = name_stream_wait_for_accept(sock, timeo);
		if (err)
			goto out_wait_err;
	}
	if (!reqsk_queue_empty(&v6_icsk->icsk_accept_queue))
		new_v6_sk = reqsk_queue_get_child(&v6_icsk->icsk_accept_queue,
						  v6_sk);
	else if (!reqsk_queue_empty(&v4_icsk->icsk_accept_queue))
		new_v4_sk = reqsk_queue_get_child(&v4_icsk->icsk_accept_queue,
						  v4_sk);
	release_sock(sk);

handle_incoming:
	err = -ENOMEM;
	incoming_sock = name_alloc_stream_socket(&init_net, newsock);
	if (!incoming_sock) {
		if (new_v6_sk)
			sock_put(new_v6_sk);
		if (new_v4_sk)
			sock_put(new_v4_sk);
		goto out_err;
	}
	new_name = name_stream_sk(incoming_sock);
	memcpy(&new_name->sname, &name->sname, sizeof(name->sname));
	if (new_v6_sk) {
		new_name->ipv6_sock = create_stream_sock_from_sk(PF_INET6,
								 new_v6_sk);
		if (!new_name->ipv6_sock) {
			sock_put(incoming_sock);
			goto out_err;
		}
		get_name_from_v6_sock(&new_name->dname, new_name->ipv6_sock);
	}
	if (new_v4_sk) {
		new_name->ipv4_sock = create_stream_sock_from_sk(PF_INET,
								 new_v4_sk);
		if (!new_name->ipv4_sock) {
			sock_put(incoming_sock);
			goto out_err;
		}
		get_name_from_v4_sock(&new_name->dname, new_name->ipv4_sock);
	}
	printk(KERN_INFO "connection accepted from %s\n",
	       new_name->dname.sname_addr.name);
	sock_graft(incoming_sock, newsock);
	newsock->state = SS_CONNECTED;
	err = 0;
	release_sock(sk);
	return err;

out_wait_err:
	release_sock(sk);

out_err:
	release_sock(sk);
	return err;
}

static int name_stream_getname(struct socket *sock, struct sockaddr *uaddr,
			       int *uaddr_len, int peer)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	struct sockaddr_name *sname = (struct sockaddr_name *)uaddr;

	if (peer) {
		if (sock->state != SS_CONNECTED)
			return -ENOTCONN;
		memcpy(sname, &name->dname, sizeof(struct sockaddr_name));
	}
	else {
		memcpy(sname, &name->sname, sizeof(struct sockaddr_name));
	}
	*uaddr_len = sizeof(struct sockaddr_name);
	return 0;
}

static int name_stream_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	int err = -EINVAL;

	lock_sock(sk);
	if (sock->state != SS_UNCONNECTED)
		goto out;

	/* FIXME: what does it mean to listen on more than one socket?  And
	 * what does backlog mean?
	 */
	if (!name->ipv6_sock) {
		err = name_create_v6_sock(SOCK_STREAM, 0, &name->ipv6_sock,
					  name);
		if (err)
			goto out;
	}
	if (!name->ipv4_sock) {
		err = name_create_v4_sock(SOCK_STREAM, 0, &name->ipv4_sock,
					  name);
		if (err)
			goto out;
	}
	err = kernel_listen(name->ipv6_sock, backlog);
	if (!err)
		err = kernel_listen(name->ipv4_sock, backlog);

out:
	release_sock(sk);
	return err;
}

static int name_stream_sendmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	struct socket *connected_sock;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;
	if (name->ipv6_sock)
		connected_sock = name->ipv6_sock;
	else if (name->ipv4_sock)
		connected_sock = name->ipv4_sock;
	else
		return -ENOTCONN;
	return connected_sock->ops->sendmsg(iocb, connected_sock, msg, len);
}

static int name_stream_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	struct socket *connected_sock;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;
	if (name->ipv6_sock)
		connected_sock = name->ipv6_sock;
	else if (name->ipv4_sock)
		connected_sock = name->ipv4_sock;
	else
		return -ENOTCONN;
	return connected_sock->ops->recvmsg(iocb, connected_sock, msg, len,
					    flags);
}

static const struct proto_ops name_stream_ops = {
	.family = PF_NAME,
	.owner = THIS_MODULE,
	.release = name_stream_release,
	.bind = name_stream_bind,
	.connect = name_stream_connect,
	.socketpair = sock_no_socketpair,
	.accept = name_stream_accept,
	.getname = name_stream_getname,
	.poll = sock_no_poll,
	.ioctl = sock_no_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = sock_no_compat_ioctl,
#endif
	.listen = name_stream_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = name_stream_sendmsg,
	.recvmsg = name_stream_recvmsg,
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
	name->ipv4_sock = NULL;
	name->ipv6_sock = NULL;
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
