#include <linux/kernel.h>
#include <linux/module.h>  
#include <net/sock.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include "namestacknl.h"

static DEFINE_MUTEX(nos_mutex);
static struct sock *nls = NULL;
static int daemon_pid;

static int
namestack_send_message(int pid, int type, const void *payload, int size)
{
	struct sk_buff *skb;
	int len = NLMSG_SPACE(size);
	struct nlmsghdr *nlh;

	skb = alloc_skb(len, GFP_ATOMIC);
	if (!skb) {
		printk(KERN_ERR "Could not allocate skb to send message\n");
		return -ENOMEM;
	}
	nlh = __nlmsg_put(skb, pid, 0, type, (len - sizeof(*nlh)), 0);
	nlh->nlmsg_flags = 0;
	memcpy(NLMSG_DATA(nlh), payload, size);
	return netlink_unicast(nls, skb, pid, MSG_DONTWAIT);
}

static int
handle_register(const struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	printk("received register message from user %d, process %d\n",
		NETLINK_CREDS(skb)->uid,
		NETLINK_CREDS(skb)->pid);
	/* FIXME: should check whether user is root first.  Not doing for now
	 * to simplify testing.
	 */
	daemon_pid = NETLINK_CREDS(skb)->pid;
	return namestack_send_message(daemon_pid, NAME_STACK_REGISTER, NULL, 0);
}

static int
handle_reply(const struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	printk("received reply message from user %d, process %d\n",
		NETLINK_CREDS(skb)->uid,
		NETLINK_CREDS(skb)->pid);
	/* Send an empty REPLY as an ack */
	return namestack_send_message(NETLINK_CREDS(skb)->pid, NAME_STACK_REPLY,
		NULL, 0);
}

static int
nos_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;

	switch (nlh->nlmsg_type) {
	case NAME_STACK_REGISTER:
		err = handle_register(skb, nlh);
		break;
	case NAME_STACK_REPLY:
		err = handle_reply(skb, nlh);
		break;
	default:
		err = -ENOSYS;
	}

	return err;
}

static void
nos_rcv_skb(struct sk_buff *skb)
{
	mutex_lock(&nos_mutex);
	while (skb->len >= NLMSG_SPACE(0)) {
		int err;
		uint32_t rlen;
		struct nlmsghdr *nlh;

		nlh = nlmsg_hdr(skb);
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len)
			break;

		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;

		err = nos_rcv_msg(skb, nlh);
		skb_pull(skb, rlen);
	}
	mutex_unlock(&nos_mutex);
}

static __init int namestack_init(void)
{
	printk(KERN_INFO "name-oriented stack module loading\n");

	nls = netlink_kernel_create(&init_net, NETLINK_NAME_ORIENTED_STACK,
		0, nos_rcv_skb, NULL, THIS_MODULE);
	if (!nls) {
		printk(KERN_ERR "namestackmod: failed to create netlink socket\n");
		return -ENOMEM;
	}
	return 0;
}

static void __exit namestack_exit(void)
{
	netlink_kernel_release(nls);
	printk(KERN_INFO "name-oriented stack module unloading\n");
}

module_init(namestack_init);
module_exit(namestack_exit);
