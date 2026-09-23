#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "../include/WlStckD.h"
#include <linux/types.h>

#define PROC_ENTRY "WlStckD"
#define CONN_HASH_SIZE 1024
#define SYN_RATE_THRESH 100 // For handking syn flood attacks 
#define PORT_SCAN_THRESHOLD 10 // Avoid port scan attacts

struct FW_Stat stats;
static struct nf_hook_ops nf_hk;
static struct timer_list cleanup_timer;

static struct hlist_head conn_table[CONN_HASH_SIZE];
static struct hlist_head ip_tracker_table[CONN_HASH_SIZE];
static spinlock_t conn_lock;
static spinlock_t tracker_lock;

/* Freeing RCU conns*/
static void conn_rcu_free(struct rcu_head *rcu) {
  struct Conn_entry *entry = container_of(rcu, struct Conn_entry, rcu);
  kfree(entry);
}


// Expose stats api via the proc entry 
static int stats_show(struct seq_file *m, void *v) {
    seq_printf(m, "WlStckD Stats\n");
    seq_printf(m, "=========================\n");
    seq_printf(m, "Tot pkts: %llu\n", stats.total_packets);
    seq_printf(m, "Allowed: %llu\n", stats.allowed_packets);
    seq_printf(m, "Blocked: %llu\n", stats.blocked_packets);
    seq_printf(m, "SYN floods blocked: %llu\n", stats.syn_flood_blocked);
    seq_printf(m, "Port scans blocked: %llu\n", stats.port_scan_blocked);
    seq_printf(m, "Invalid states blocked: %llu\n", stats.invalid_state_blocked);
    return 0;
}

static int stats_open(struct inode *inode, struct file *file){
    return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_fops = {
    .proc_open = stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};


/* Main packet hook function */
unsigned int packet_hook(void * _, struct sk_buff *skb, const struct nf_hook_state *state){

    return NF_ACCEPT;
}



int __init firewall_init(void) {
    printk(KERN_INFO "WlStckD initialising\n");

    memset(&stats, 0, sizeof(stats));
    spin_lock_init(&conn_lock);
    spin_lock_init(&tracker_lock);

    for (int i = 0; i < CONN_HASH_SIZE; i++) {  
        INIT_HLIST_HEAD(&conn_table[i]);
        INIT_HLIST_HEAD(&ip_tracker_table[i]);
    }

    // Setup netfilter
    nf_hk.hook = packet_hook;
    nf_hk.hooknum = NF_INET_PRE_ROUTING;
    nf_hk.pf = PF_INET;
    nf_hk.priority = NF_IP_PRI_FIRST;
    int ret = nf_register_net_hook(&init_net, &nf_hk);
    if (ret) {
        printk(KERN_ERR "Failed to reg netfilter hook\n");
        return ret;
    }

    if (!proc_create(PROC_ENTRY, 0444, NULL, &stats_fops)) {
        printk(KERN_WARNING "Failed to create proc entry\n");
    }

    printk(KERN_INFO "WlStckD initialized\n");
    
    timer_setup(&cleanup_timer, cleanup_timer_callback, 0);
    mod_timer(&cleanup_timer, jiffies + secs_to_jiffies(60));  
    return 0;
}

void __exit firewall_exit(void){
    printk(KERN_INFO "Shutting down WlStckD\n");
    struct Conn_entry *entry;
    struct hlist_node *tmp;
    struct IpTrack *tracker;
    
    remove_proc_entry(PROC_ENTRY, NULL); // remove proc entry
    timer_delete_sync(&cleanup_timer); 
    nf_unregister_net_hook(&init_net, &nf_hk); // Remove net hook
   
    // Deinit the conn and ip lists
    spin_lock_bh(&conn_lock);
    spin_lock_bh(&tracker_lock);
    for (int i = 0; i < CONN_HASH_SIZE; i++) {
        hlist_for_each_entry_safe(entry, tmp, &conn_table[i], node) {
            hlist_del(&entry->node);
            kfree(entry);
        }
        hlist_for_each_entry_safe(tracker, tmp, &ip_tracker_table[i], node) {
            hlist_del(&tracker->node);
            kfree(tracker);
        }
    }
    spin_unlock_bh(&conn_lock);
    spin_unlock_bh(&tracker_lock);

    printk(KERN_INFO "WlStckD Stats:\n");
    printk(KERN_INFO "Total pckts(%llu) -> Allowed(%llu) Blocked(%llu)\n", stats.total_packets,stats.allowed_packets, stats.blocked_packets);
    printk(KERN_INFO "Shutdown complete\n");
}

module_init(firewall_init);
module_exit(firewall_exit);


// Cleanup conn & ip table timer callback
static void cleanup_timer_callback(struct timer_list *t){
    struct Conn_entry *entry;
    struct hlist_node *tmp;
    struct IpTrack *tracker;
    
    spin_lock_bh(&conn_lock);
    spin_lock_bh(&tracker_lock);

    for (int i = 0; i < CONN_HASH_SIZE; i++) {
        hlist_for_each_entry_safe(entry, tmp, &conn_table[i], node) {
            if (time_after(jiffies, entry->last_seen + secs_to_jiffies(300))) {
                hlist_del_rcu(&entry->node);
                call_rcu(&entry->rcu, conn_rcu_free);
            }
        }
        hlist_for_each_entry_safe(tracker, tmp, &ip_tracker_table[i], node) {
            if (time_after(jiffies, tracker->last_update + secs_to_jiffies(60))) {
                hlist_del(&tracker->node);
                kfree(tracker);
            }
        }
    }
    spin_unlock_bh(&conn_lock);
    spin_unlock_bh(&tracker_lock);

    // Reset timer for cqallback
    mod_timer(&cleanup_timer, jiffies + 60 * HZ); 
}




// Hash Buckets for ip packets and ip
static inline u32 hash_conn(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, u8 proto){
    return jhash_3words(src_ip, dst_ip, ((u32)src_port << 16) | dst_port, proto) & (CONN_HASH_SIZE - 1);
}

static inline u32 hash_ip(__be32 ip){
    return jhash_1word(ip, 0) & (CONN_HASH_SIZE - 1);
}





MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ihit Acharya");
MODULE_DESCRIPTION("Stateful Wifi firewall Linux Device Driver");
MODULE_VERSION("1.0");