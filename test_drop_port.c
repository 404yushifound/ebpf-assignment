#include <stdio.h>
#include <stdint.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Declare the BPF program as extern
extern int drop_port_prog(struct xdp_md *ctx);

int main() {
    // Fake packet buffer (Ethernet + IPv4 + TCP)
    uint8_t packet[64] = {0};
    
    // Setup Ethernet header
    struct ethhdr *eth = (struct ethhdr *)packet;
    eth->h_proto = bpf_htons(0x0800); // ETH_P_IP

    // Setup IP header
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    ip->ihl = 5;
    ip->protocol = 6; // TCP

    // Setup TCP header
    struct tcphdr *tcp = (struct tcphdr *)((__u32 *)ip + ip->ihl);
    tcp->dest = bpf_htons(4040); // TCP dest port to drop

    // Setup fake xdp_md
    struct xdp_md ctx;
    ctx.data = (uint64_t)packet;
    ctx.data_end = (uint64_t)(packet + sizeof(packet));
    ctx.data_meta = 0;

    // Call the eBPF program
    int ret = drop_port_prog(&ctx);

    printf("drop_port_prog returned: %d\n", ret);
    printf("Check trace_pipe for bpf_printk messages\n");
    return 0;
}
