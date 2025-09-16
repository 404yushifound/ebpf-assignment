#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Change this to your process name
const char target_process[] = "myprocess";

// Default TCP port to allow
const __u16 allowed_port = 4040;

SEC("cgroup_skb/ingress")
int drop_other_ports(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Get process info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[16];
    bpf_probe_read_kernel_str(&comm, sizeof(comm), task->comm);

    // If not target process, allow everything
    int i;
    for(i=0;i<16;i++){
        if(comm[i]!=target_process[i]) break;
    }
    if(i!=16 && comm[i]!=0 && target_process[i]!=0) {
        return BPF_OK; // allow packet
    }

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return BPF_OK;

    if (bpf_ntohs(eth->h_proto) != 0x0800) // ETH_P_IP
        return BPF_OK;

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end)
        return BPF_OK;

    if (ip->protocol != 6) // TCP
        return BPF_OK;

    // Parse TCP header
    struct tcphdr *tcp = (void*)ip + ip->ihl*4;
    if ((void*)(tcp + 1) > data_end)
        return BPF_OK;

    if (bpf_ntohs(tcp->dest) != allowed_port) {
        bpf_printk("Dropping packet from process %s on port %d\n", comm, bpf_ntohs(tcp->dest));
        return BPF_DROP;
    }

    return BPF_OK; // allow packet
}
