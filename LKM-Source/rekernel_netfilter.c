/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_netfilter.c
 * Description: Re:Kernel inbound-network monitor. Netfilter LOCAL_IN hooks fire
 *              for every inbound packet but only emit an event for uids the
 *              userspace daemon opted in via MONITOR_NET (RCU hashmap below).
 */
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <linux/udp.h>
#include <net/rtnetlink.h>
#include "rekernel_internal.h"

/* hashmap for net monitor uids */
#define REKERNEL_NET_UID_HASH_BITS 6
static DEFINE_HASHTABLE(rekernel_net_uid_map, REKERNEL_NET_UID_HASH_BITS);
struct uid_info {
	uid_t uid;
	unsigned int min_payload;      /* 0 = 用模块默认 */
	unsigned int min_payload_udp;  /* 0 = 用模块默认 */
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_MUTEX(rekernel_net_uid_mutex);

static struct uid_info *net_uid_find(uid_t uid)
{
	struct uid_info *entry;

	hash_for_each_possible_rcu(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid)
			return entry;
	}
	return NULL;
}

static bool net_uid_monitored(uid_t uid)
{
	return net_uid_find(uid) != NULL;
}

/* 取某个 uid 的阈值；未订阅返回 false。0 表示用模块默认值。 */
bool net_uid_thresholds(uid_t uid, unsigned int *min_payload, unsigned int *min_payload_udp)
{
	struct uid_info *entry;
	bool found = false;

	rcu_read_lock();
	entry = net_uid_find(uid);
	if (entry) {
		if (min_payload)
			*min_payload = READ_ONCE(entry->min_payload);
		if (min_payload_udp)
			*min_payload_udp = READ_ONCE(entry->min_payload_udp);
		found = true;
	}
	rcu_read_unlock();
	return found;
}

/* add a uid to the monitor map. 已存在时更新阈值（重复订阅即更新语义）。 */
void net_uid_add(uid_t uid, unsigned int min_payload, unsigned int min_payload_udp)
{
	struct uid_info *entry;

	mutex_lock(&rekernel_net_uid_mutex);
	entry = net_uid_find(uid);
	if (entry) {
		WRITE_ONCE(entry->min_payload, min_payload);
		WRITE_ONCE(entry->min_payload_udp, min_payload_udp);
	} else {
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (entry) {
			entry->uid = uid;
			entry->min_payload = min_payload;
			entry->min_payload_udp = min_payload_udp;
			hash_add_rcu(rekernel_net_uid_map, &entry->hnode, uid);
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}

/* remove a uid from the monitor map. Caller must NOT hold the mutex. */
void net_uid_del(uid_t uid)
{
	struct uid_info *entry;

	mutex_lock(&rekernel_net_uid_mutex);
	hash_for_each_possible(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->hnode);
			kfree_rcu(entry, rcu);
			break;
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}

static inline uid_t line_sock2uid(struct sock *sk)
{
	if (sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;
	else
		return 0;
}

static bool monitor_all = false;
module_param(monitor_all, bool, 0644);
MODULE_PARM_DESC(monitor_all, "Report events for every app uid without MONITOR_NET subscription");

static unsigned int min_payload = 1024;
module_param(min_payload, uint, 0644);
MODULE_PARM_DESC(min_payload, "Minimum TCP payload bytes to report; 0 reports every TCP packet");

/* UDP 单独阈值：视频通话的 RTC 私有协议单包普遍 600~1200B，用 TCP 的 1KB
 * 会漏掉大部分上行包，所以默认放到 512。 */
static unsigned int min_payload_udp = 512;
module_param(min_payload_udp, uint, 0644);
MODULE_PARM_DESC(min_payload_udp, "Minimum UDP payload bytes to report; 0 reports every UDP packet");

static unsigned int rekernel_pkg_ipv4_ipv6(void *priv, struct sk_buff *socket_buffer,
   const struct nf_hook_state *state)
{
  struct sock *sk;
  unsigned int thoff = 0;
  unsigned short frag_off = 0;
  uid_t uid;
  struct net_device *dev = NULL;
  const char *dir;
  int data_len;
  int l4proto;
  bool monitored = false;
  unsigned int uid_min_payload = 0;
  unsigned int uid_min_payload_udp = 0;

  if (!socket_buffer || !socket_buffer->len || !state)
   return NF_ACCEPT;

  if (NF_INET_LOCAL_IN == state->hook) {
   dev = state->in;
   dir = "in";
  } else if (NF_INET_LOCAL_OUT == state->hook) {
   dev = state->out;
   dir = "out";
  } else {
   return NF_ACCEPT;
  }

  if (NULL == dev)
   return NF_ACCEPT;

  sk = skb_to_full_sk(socket_buffer);
  if (sk == NULL || !sk_fullsock(sk))
   return NF_ACCEPT;

  uid = line_sock2uid(sk);
  if (uid < MIN_USERAPP_UID) return NF_ACCEPT;

  /* 每个 uid 可以由订阅携带各自的阈值；未携带(0)时回落到模块参数 */
  if (!monitor_all) {
   monitored = net_uid_thresholds(uid, &uid_min_payload, &uid_min_payload_udp);
   if (!monitored) return NF_ACCEPT;
  }

  if (ip_hdr(socket_buffer)->version == 4) {
   struct iphdr *iph4;
   unsigned int ip_hdr_len;

   if (!pskb_may_pull(socket_buffer, sizeof(struct iphdr))) {
    return NF_ACCEPT;
   }

   iph4 = ip_hdr(socket_buffer);
   l4proto = iph4->protocol;
   if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP) {
    return NF_ACCEPT;
   }

   ip_hdr_len = iph4->ihl << 2;
   if (l4proto == IPPROTO_TCP) {
    struct tcphdr *th;
    if (!pskb_may_pull(socket_buffer, ip_hdr_len + sizeof(struct tcphdr))) {
     return NF_ACCEPT;
    }
    iph4 = ip_hdr(socket_buffer);
    th = (struct tcphdr *)((unsigned char *)iph4 + ip_hdr_len);
    data_len = ntohs(iph4->tot_len) - ip_hdr_len - (th->doff << 2);
   } else {
    struct udphdr *uh;
    if (!pskb_may_pull(socket_buffer, ip_hdr_len + sizeof(struct udphdr))) {
     return NF_ACCEPT;
    }
    iph4 = ip_hdr(socket_buffer);
    uh = (struct udphdr *)((unsigned char *)iph4 + ip_hdr_len);
    data_len = ntohs(uh->len) - sizeof(struct udphdr);
   }

#if IS_ENABLED(CONFIG_IPV6)
  } else if (ip_hdr(socket_buffer)->version == 6) {
   struct ipv6hdr *iph6;

   if (!pskb_may_pull(socket_buffer, sizeof(struct ipv6hdr))) {
    return NF_ACCEPT;
   }

   l4proto = ipv6_find_hdr(socket_buffer, &thoff, -1, &frag_off, NULL);
   if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP) {
    return NF_ACCEPT;
   }

   iph6 = ipv6_hdr(socket_buffer);
   if (l4proto == IPPROTO_TCP) {
    struct tcphdr *th;
    if (!pskb_may_pull(socket_buffer, thoff + sizeof(struct tcphdr))) {
     return NF_ACCEPT;
    }
    th = (struct tcphdr *)(skb_network_header(socket_buffer) + thoff);
    data_len = ntohs(iph6->payload_len) - (thoff - sizeof(struct ipv6hdr)) - (th->doff << 2);
   } else {
    struct udphdr *uh;
    if (!pskb_may_pull(socket_buffer, thoff + sizeof(struct udphdr))) {
     return NF_ACCEPT;
    }
    uh = (struct udphdr *)(skb_network_header(socket_buffer) + thoff);
    data_len = ntohs(uh->len) - sizeof(struct udphdr);
   }
#endif
  } else {
   return NF_ACCEPT;
  }

  /* 纯 ACK/握手（无 payload）不报；同时按协议各自的阈值过滤小包，避免刷屏 */
  {
   unsigned int minp = (l4proto == IPPROTO_UDP)
       ? (uid_min_payload_udp ? uid_min_payload_udp : min_payload_udp)
       : (uid_min_payload ? uid_min_payload : min_payload);
   if (data_len <= 0 || (minp && (unsigned int)data_len < minp))
    return NF_ACCEPT;
  }

#ifdef DEBUG
  pr_info("[Re-Kernel LKM] net %s uid=%d proto=%d len=%d\n", dir, uid, l4proto, data_len);
#endif
  if (rekernel_netlink_ready()) {
   char binder_kmsg[PACKET_SIZE];
   int len;

   len = scnprintf(binder_kmsg, sizeof(binder_kmsg),
     "type=Network,target=%d,proto=ipv%d,dir=%s,l4=%s,data_len=%d;",
     uid, ip_hdr(socket_buffer)->version == 4 ? 4 : 6, dir,
     l4proto == IPPROTO_TCP ? "tcp" : "udp", data_len);
   sendMessage(binder_kmsg, len);
  }

  return NF_ACCEPT;
}

/* Monitor both directions (LOCAL_IN / LOCAL_OUT), TCP and UDP */
static struct nf_hook_ops rekernel_nf_ops[] = {
	{
		.hook     = rekernel_pkg_ipv4_ipv6,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
	{
		.hook     = rekernel_pkg_ipv4_ipv6,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook     = rekernel_pkg_ipv4_ipv6,
		.pf       = NFPROTO_IPV6,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	},
	{
		.hook     = rekernel_pkg_ipv4_ipv6,
		.pf       = NFPROTO_IPV6,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	}
#endif
};

void unregister_netfilter(void)
{
	struct net *net;
	struct uid_info *entry;
	struct hlist_node *tmp;
	int bkt;

	rtnl_lock();
	for_each_net(net) {
		nf_unregister_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
	}
	rtnl_unlock();

	synchronize_rcu();
	hash_for_each_safe(rekernel_net_uid_map, bkt, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
}

int register_netfilter(void)
{
	int rc = LINE_SUCCESS;
	struct net *net = NULL;

	hash_init(rekernel_net_uid_map);

	rtnl_lock();
	for_each_net(net) {
		rc = nf_register_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
		if (rc != LINE_SUCCESS) {
			pr_err("register netfilter hooks failed, rc=%d\n", rc);
			break;
		}
	}
	rtnl_unlock();

	if (rc != LINE_SUCCESS) {
		unregister_netfilter();
		return LINE_ERROR;
	}

	return LINE_SUCCESS;
}
