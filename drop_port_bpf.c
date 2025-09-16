// drop_port_bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DROP_PORT 4040  // Default port to drop
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

SEC("xdp")
int drop_port_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (struct tcphdr *)((__u32 *)ip + ip->ihl);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Drop packets with destination port = DROP_PORT
    if (bpf_ntohs(tcp->dest) == DROP_PORT) {
        bpf_printk("Dropping TCP packet on port %d\n", DROP_PORT);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

