#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <strings.h>
#include <string.h>
#include "../siphash.h"
#include "../common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct keys); 
  } secrets SEC(".maps");

  struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 1000);
    __type(key, struct flow);
    __type(value, __u32);   
  } legitimate_flows SEC(".maps");


__attribute__((always_inline)) static inline bool extract_spa_opt(struct tcphdr* tcph, void* data_end, struct tcp_opt_spa** spa_opt)
{
    void* opt_ptr = (__u8*)tcph + sizeof(struct tcphdr);
    void* opt_end = (__u8*)tcph + (tcph->doff * 4);

    if (unlikely(opt_end > data_end)) {
        return false;
    }

    #pragma unroll
    for (int i = 0; i < MAX_TCP_OPTIONS; i++) {
        if (unlikely(opt_ptr >= data_end)) {
            return false; // No options present
        }
        __u8 kind = *(__u8*)opt_ptr;
        bpf_printk("kind: %d\n", kind);
        if (kind == 253) {
            bpf_printk("found spa opt\n");
            *spa_opt = (struct tcp_opt_spa*)opt_ptr;
            if (unlikely((__u8*)opt_ptr + sizeof(struct tcp_opt_spa) > (__u8*)data_end)) {
                return false;
            }
            return true;
        }
        if(kind == 1) {
            opt_ptr += 1;
            continue;
        }
        if(kind == 0) {
            return false;
        }
        if (unlikely(opt_ptr + 1 >= data_end)) {
            return false;
        }
        __u8 len = *(__u8*)(opt_ptr + 1);
        bpf_printk("len: %d\n", len);
        opt_ptr += len;
    }
    return false;
}

__attribute__((always_inline)) static inline bool
authenticate_client(struct tcphdr* tcph, void* data_end, __u32 src_ip)
{
    struct tcp_opt_spa* spa_opt = NULL;
    if (!extract_spa_opt(tcph, data_end, &spa_opt)) {
        return false;
    }
    
    // Prepare input for SipHash calculation
    struct spa_input input;
    memset(&input, 0, sizeof(input));
    input.exid = spa_opt->exid;           // 2B, network order
    input.ver = spa_opt->ver;            // 1B
    input.key_id = spa_opt->key_id;      // 2B
    input.time_step = spa_opt->time_step; // 4B, network order
    input.tcp_seq = tcph->seq;           // 4B, TCP seq (client ISN)
    
   // Get secret key based on key_id
    struct keys* secret_ptr = bpf_map_lookup_elem(&secrets, &spa_opt->key_id);
    if (!secret_ptr) {
        return false; // Unknown key_id
    }
    
    // Calculate SipHash-2-4
    __u64 k0 = secret_ptr->key1;
    __u64 k1 = secret_ptr->key2;
    __u64 hash = siphash_2_4(k0, k1, &input);
    
    // Compare with received tag (first 8 bytes)
    __u64 received_tag = *(__u64*)spa_opt->tag;
    return (hash == received_tag);
}

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;
    int pkt_len = sizeof(*eth);
    u8 proto = 0;

    if (unlikely(data + pkt_len > data_end))
    {
        bpf_printk("malformed packet\n");
        return XDP_DROP;
    }
    if (eth->h_proto == 0xa888 || eth->h_proto == 0x0081)
    {
        struct vlan_hdr* vlan_hdr = data + pkt_len;
        if (unlikely(((void*)(vlan_hdr + sizeof(struct vlan_hdr)) > data_end)))
        {
            bpf_printk("malformed packet\n");
            return XDP_DROP;
        }
        pkt_len += sizeof(struct vlan_hdr);

        eth->h_proto = vlan_hdr->h_vlan_encapsulated_proto;
    }
    struct iphdr* iph = NULL;
    struct ipv6hdr* ip6h = NULL;

    bool is_fragment = false;
    struct flow current_flow;
    memset(&current_flow, 0, sizeof(current_flow));
    current_flow.proto = eth->h_proto;
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        iph = data + pkt_len;
        pkt_len += (iph->ihl * 4);
        if (unlikely((void*)iph + sizeof(struct iphdr) > data_end))
        {
            bpf_printk("malformed packet\n");
            return XDP_DROP;
        }
        current_flow.src_ip = iph->saddr;
        current_flow.dst_ip = iph->daddr;
        proto = iph->protocol;
        is_fragment = (bool)(u16)(iph->frag_off & bpf_htons(IP_MF));
    }
    else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6)
    {
        ip6h = data + pkt_len;
        pkt_len += sizeof(struct ipv6hdr);
        if (unlikely(data + pkt_len > data_end))
        {
            bpf_printk("malformed packet\n");
            return XDP_DROP;
        }
        memcpy(&current_flow.src_ipv6, &ip6h->saddr, 16);
        memcpy(&current_flow.dst_ipv6, &ip6h->daddr, 16);
        proto = ip6h->nexthdr;
        if (ip6h->nexthdr == IPPROTO_FRAGMENT)
        {
            is_fragment = true;
            struct ipv6_frag_header* ip6_fragh = data + pkt_len;
            pkt_len += sizeof(struct ipv6_frag_header);
            if (unlikely(data + pkt_len > data_end))
            {
                bpf_printk("malformed packet\n");
                return XDP_DROP;
            }
            proto = ip6_fragh->nexthdr;
        }
    }
    if(is_fragment)
    {
        bpf_printk("fragmented packet\n");
        return XDP_PASS;
    }
    if(proto != IPPROTO_TCP)
    {
        return XDP_PASS;
    }
    struct tcphdr* tcp_hdr = data + pkt_len;
    if (unlikely((void*)tcp_hdr + sizeof(struct tcphdr) > data_end))
    {
        bpf_printk("malformed packet\n");
        return XDP_DROP;
    }
    current_flow.dst_port = tcp_hdr->dest;
    current_flow.src_port = tcp_hdr->source;
    if (tcp_hdr->syn && !tcp_hdr->ack) {
        // This is a SYN packet - check for auth option
        if (tcp_hdr->dest == bpf_htons(22)) { 
            // Look for your auth option in TCP options
            if (authenticate_client(tcp_hdr, data_end, current_flow.src_ip)) {
                __u32 auth_time = bpf_ktime_get_ns() / 1000000000; // Current time in seconds
                bpf_map_update_elem(&legitimate_flows, &current_flow, &auth_time, BPF_ANY);
                return XDP_PASS; 
            } else {
                bpf_printk("authentication failed\n");
                return XDP_DROP; 
            }
        }
    }
    
    //check if flow is already authenticated
    if (current_flow.dst_port == bpf_htons(22)) {
        __u32* auth_time = bpf_map_lookup_elem(&legitimate_flows, &current_flow);
        if (!auth_time) {
            bpf_printk("not authenticated\n");
            return XDP_DROP; // Not authenticated
        }
    }
    
    return XDP_PASS;

}
