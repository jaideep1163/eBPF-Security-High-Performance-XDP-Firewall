#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define RATE_LIMIT 100                    /* packets per window */
#define WINDOW_NS  1000000000ULL          /* 1 second */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist SEC(".maps");

struct rate {
    __u64 window_start;                   /* timestamp per source IP */
    __u64 count;                          /* packets in current window */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate);
} rate_map SEC(".maps");

SEC("xdp")
int xdp_l3(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_PASS;

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    if (bpf_map_lookup_elem(&blocklist, &src))
        return XDP_DROP;

    /* Optional: count only SYNs (no ACK) to target SYN floods */
    if (ip->protocol == IPPROTO_TCP && ip->ihl == 5) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > end) return XDP_PASS;
        if (!(tcp->syn && !tcp->ack))
            return XDP_PASS;              /* not a SYN: skip rate check */
    }

    struct rate *r = bpf_map_lookup_elem(&rate_map, &src);
    if (!r) {
        struct rate nr = { .window_start = now, .count = 1 };
        bpf_map_update_elem(&rate_map, &src, &nr, BPF_ANY);
        return XDP_PASS;
    }

    if (now - r->window_start > WINDOW_NS) {   /* new window */
        r->window_start = now;
        r->count = 1;
        return XDP_PASS;
    }

    if (__sync_fetch_and_add(&r->count, 1) >= RATE_LIMIT) {
        bpf_printk("DROP rate-limit %pI4", &src);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";