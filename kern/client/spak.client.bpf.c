#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../siphash.h"
#include <string.h>

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#define IPPROTO_FRAGMENT 44

struct flow
{
    union
    {
        uint32_t src_ip;
        char src_ipv6[16];
    };
    union
    {
        uint32_t dst_ip;
        char dst_ipv6[16];
    };
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short proto;
};

struct ipv6_frag_header
{
    uint8_t nexthdr;
    uint8_t len;
    uint16_t frag_offset_flags;
    uint32_t id;
};


SEC("classifier/egress")
int tc_egress(struct __sk_buff *ctx)
{
    // Simple TC egress program that passes all traffic
    // You can add packet inspection/modification logic here
    
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr* eth = data;
    int pkt_len = sizeof(*eth);
    u8 proto = 0;
    if (unlikely(data + pkt_len > data_end))
    {
        bpf_printk("malformed packet\n");
        return TC_ACT_SHOT;
    }
    if (eth->h_proto == 0xa888 || eth->h_proto == 0x0081)
    {
        struct vlan_hdr* vlan_hdr = data + pkt_len;
        if (unlikely(((void*)(vlan_hdr + sizeof(struct vlan_hdr)) > data_end)))
        {
            bpf_printk("malformed packet\n");
            return TC_ACT_SHOT;
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
            return TC_ACT_SHOT;
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
            return TC_ACT_SHOT;
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
                return TC_ACT_SHOT;
            }
            proto = ip6_fragh->nexthdr;
        }
    }
    // Example: Log that we're processing egress traffic
    // (In production, you'd use perf events or other mechanisms)
    
    // Allow packet to continue
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
