/* WlStckD.h */
#ifndef WLSTCKD_H
#define WLSTCKD_H

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/time.h>
#include <linux/types.h>

enum { CONN_NEW,CONN_ESTABLISHED,CONN_RELATED,CONN_INVALID} e_Conn;
#define PORT_SCAN_THRESHOLD 10


struct Conn_entry {
    __be32 src_ip,dst_ip; 
    __be16 src_port,dst_port;
    u8 protocol,state;
    unsigned long last_seen;
    u32 packet_count,syn_count;
    struct hlist_node node;
    struct rcu_head rcu;
} ;

struct FW_Stat {
    u64 total_packets;
    u64 allowed_packets;
    u64 blocked_packets;
    u64 syn_flood_blocked;
    u64 port_scan_blocked;
    u64 invalid_state_blocked;
};

struct IpTrack {
    __be32 ip;
    u32 syn_count;
    u32 port_count;
    unsigned long last_update;
    u16 ports_seen[PORT_SCAN_THRESHOLD];
    struct hlist_node node;
};


/* Function Signatures */
unsigned int packet_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int __init firewall_init(void);
void __exit firewall_exit(void);
struct connection_entry *find_or_create_entry(struct iphdr *iph, struct tcphdr *tcph,u8 protocol);
void cleanup_old_entries(void);
bool under_syn_flood(__be32 src_ip);
bool under_port_scan(__be32 src_ip, __be16 dst_port);
bool is_valid_transition(u8 old_state, u8 new_state, struct tcphdr *tcph);
static inline u32 hash_conn(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, u8 proto);
static inline u32 hash_ip(__be32 ip);
static void cleanup_timer_callback(struct timer_list *t);
#endif
