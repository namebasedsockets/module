#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/inname.h>

struct name_sock
{
	struct sock sk;
	struct name_addr sname;
	struct name_addr dname;
};

static struct proto name_stream_proto = {
	.name = "NAME_STREAM",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct name_sock),
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
	int rc;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	rc = 0;
	switch (sock->type)
	{
	case SOCK_STREAM:
		proto = &name_stream_proto;
		break;
	case SOCK_DGRAM:
		proto = &name_dgram_proto;
		break;
	default:
		rc = -EPROTONOSUPPORT;
	}
	if (rc)
		goto out;

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

static int __init name_init(void)
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

fs_initcall(name_init);
