#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CT_TIMEOUT 120000000000ULL        /* 120 s */

struct flow {                             /* local host's perspective */
    __u32 local_ip, remote_ip;
    __u16 local_port, remote_port;
    __u8  proto, pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow);
    __type(value, __u64);                 /* last seen (ns) */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack SEC(".maps");

static __always_inline int get_ports(void *l4, void *end, __u8 proto,
                                     __u16 *sp, __u16 *dp)
{
    if (proto == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        if ((void *)(t + 1) > end) return -1;
        *sp = t->source; *dp = t->dest;
        return 0;
    }
    if (proto == IPPROTO_UDP) {
        struct udphdr *u = l4;
        if ((void *)(u + 1) > end) return -1;
        *sp = u->source; *dp = u->dest;
        return 0;
    }
    return -1;
}

/* Ingress: allow only replies to flows we started */
SEC("xdp")
int xdp_l4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;  /* ARP etc. */

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_PASS;
    if (ip->ihl != 5) return XDP_DROP;

    __u16 sp, dp;
    if (get_ports((void *)(ip + 1), end, ip->protocol, &sp, &dp) < 0)
        return XDP_DROP;                  /* unsolicited non-TCP/UDP */

    struct flow k = {
        .local_ip = ip->daddr,  .remote_ip = ip->saddr,
        .local_port = dp,       .remote_port = sp,
        .proto = ip->protocol,
    };
    __u64 now = bpf_ktime_get_ns();
    __u64 *seen = bpf_map_lookup_elem(&conntrack, &k);

    if (!seen || now - *seen > CT_TIMEOUT) {
        __u32 src = ip->saddr;
        bpf_printk("DROP unsolicited from %pI4", &src);
        return XDP_DROP;
    }
    *seen = now;
    return XDP_PASS;
}

/* Egress: record locally initiated flows */
SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end || ip->ihl != 5) return TC_ACT_OK;

    __u16 sp, dp;
    if (get_ports((void *)(ip + 1), end, ip->protocol, &sp, &dp) < 0)
        return TC_ACT_OK;

    struct flow k = {
        .local_ip = ip->saddr,  .remote_ip = ip->daddr,
        .local_port = sp,       .remote_port = dp,
        .proto = ip->protocol,
    };
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&conntrack, &k, &now, BPF_ANY);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";