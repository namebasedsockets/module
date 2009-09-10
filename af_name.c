#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/module.h>

static int name_create(struct net *net, struct socket *sock, int protocol)
{
	return 0;
}

static struct net_proto_family name_family_ops = {
	.family = PF_NAME,
	.create = name_create,
	.owner = THIS_MODULE,
};

static int __init name_init(void)
{
	(void)sock_register(&name_family_ops);
	return 0;
}

fs_initcall(name_init);
