#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <strings.h>
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
    /** Next header type */
    uint8_t nexthdr;
    /** Fragmentation header size is fixed 8 bytes, so len is always zero */
    uint8_t len;
    /** Offset, in 8-octet units, relative to the start of the fragmentable part
     * of the original packet plus 1-bit indicating if more fragments will follow
     */
    uint16_t frag_offset_flags;
    /** packet identification value. Needed for reassembly of the original packet
     */
    uint32_t id;
};

struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __type(value, __u16);
    __uint(max_entries, 100);
    __uint(map_extra, 3);
} bloom_filter_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u16);
    __type(value, __u32); //later add keys(key1, key2)
  } secrets SEC(".maps");

  struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 1000);
    __type(key, struct flow);
    __type(value, struct flow_policy);
  } policy_enforcement_map SEC(".maps");

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    uint32_t size = data_end - data;
    struct ethhdr* eth = data;
    int pkt_len = sizeof(*eth);
    u8 proto = 0;

    if (unlikely(data + pkt_len > data_end))
    {
        return XDP_DROP;
    }
    if (eth->h_proto == 0xa888 || eth->h_proto == 0x0081)
    {
        struct vlan_hdr* vlan_hdr = data + pkt_len;
        if (unlikely(((void*)(vlan_hdr + sizeof(struct vlan_hdr)) > data_end)))
        {
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
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        iph = data + pkt_len;
        pkt_len += (iph->ihl * 4);
        if (unlikely((void*)iph + sizeof(struct iphdr) > data_end))
        {
            // malformed packet
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
            // malformed packet
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
                return XDP_DROP;
            }
            proto = ip6_fragh->nexthdr;
        }
    }
    if(is_fragment)
    {
        return XDP_PASS;
    }
    return XDP_PASS;
}


