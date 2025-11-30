#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <strings.h>
#include <string.h>
#include "../siphash.h"


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
#define MAX_OPTIONS_SIZE 64

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

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

struct tcp_opt_spa {
    uint8_t  kind;        // 253 or 254
    uint8_t  len;         // e.g., 18
    uint16_t exid;        // network order
    uint8_t  ver;         // 1
    uint8_t  key_id;      // selects secret
    uint32_t time_step;   // network order
    uint8_t  tag[8];      // SipHash output bytes
} __attribute__((packed));



__attribute__((always_inline)) static inline void add_digest(int ip_header_offset, bool is_ipv6, int tcp_header_offset, struct __sk_buff *ctx)
{
    // Add your digest logic here
    bpf_printk("adding digest\n");

   // struct tcp_opt_spa* spa_opt = (struct tcp_opt_spa*)opt_ptr;
    // Grow the packet by the size of struct tcp_opt_spa at the tail
    void* data_end = (void*)(__u64)ctx->data_end;
    struct tcphdr* tcph = (struct tcphdr*)((void *)(__u64)ctx->data + tcp_header_offset);
    if (unlikely((void*)tcph + sizeof(struct tcphdr) > data_end))
    {
        bpf_printk("malformed packet1\n");
        return ;
    }
    void* opt_ptr = (__u8*)tcph + sizeof(struct tcphdr);
    void* opt_end = (__u8*)tcph + (tcph->doff * 4);
   
    int spa_opt_size = sizeof(struct tcp_opt_spa) + 2; //two nop for alignment
    __u32 current_options_len = opt_end - opt_ptr;
    int ret = bpf_skb_change_tail(ctx, ctx->len + spa_opt_size, 0);
    if (ret < 0) {
        bpf_printk("failed to grow skb: %d\n", ret);
        return ;
    }
    tcph = (struct tcphdr*)((void *)(__u64)ctx->data + tcp_header_offset);
    data_end = (void*)(__u64)ctx->data_end;
    if (unlikely((void*)tcph + sizeof(struct tcphdr) > data_end))
    {
        bpf_printk("malformed packet1\n");
        return ;
    }
   
    opt_ptr = (__u8*)tcph + sizeof(struct tcphdr);
    opt_end = (__u8*)tcph + (tcph->doff * 4);
    if (unlikely(opt_end > data_end)) {
        bpf_printk("malformed packet2\n");
        return ;
    }

    __u32 rem_size = opt_end - opt_ptr;
    if (rem_size > MAX_OPTIONS_SIZE) {
        bpf_printk("options size too large\n");
        return;
    }
    #pragma unroll
    for(int i = MAX_OPTIONS_SIZE; i >= 0; i--) {
        if (i > rem_size)
            continue;
        asm volatile("%[i] &= 63\n" : [i] "+&r"(i));
        if (unlikely(opt_ptr + i + spa_opt_size >= data_end )) {
            bpf_printk("malformed packet3\n");
            continue;
        }
        *(__u8*)(opt_ptr + i + spa_opt_size) = *(__u8*)(opt_ptr + i);
    }
   
    struct tcp_opt_spa* spa_opt = (struct tcp_opt_spa*)opt_ptr;
    if (unlikely(opt_ptr + sizeof(struct tcp_opt_spa) > data_end)) {
        bpf_printk("malformed packet4\n");
        return;
    }
    spa_opt->kind = 253;
    spa_opt->len = sizeof(struct tcp_opt_spa);
    spa_opt->exid = bpf_htons(1);
    spa_opt->ver = 1;

    __u8* nop_ptr1 = opt_ptr + sizeof(struct tcp_opt_spa);
    __u8* nop_ptr2 = opt_ptr + sizeof(struct tcp_opt_spa) + 1;

    if(unlikely(nop_ptr1 + 3 > data_end)){
        bpf_printk("malformed packet5\n");
        return;
    }
    *nop_ptr1 = 1;
    *nop_ptr2 = 1;


    //recalculate checksums
    tcph->doff+= spa_opt_size / 4;
    struct iphdr* iph = NULL;
    struct ipv6hdr* ip6h = NULL;
    if(is_ipv6) {
        ip6h = (struct ipv6hdr*)((void *)(__u64)ctx->data + ip_header_offset);
        if(unlikely((void*)ip6h + sizeof(struct ipv6hdr) > data_end)) {
            bpf_printk("malformed packet6\n");
            return;
        }
        ip6h->payload_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + spa_opt_size);
        bpf_l3_csum_replace(ctx, ip_header_offset, 0, 0, sizeof(struct ipv6hdr));
    }
    else {
        iph = (struct iphdr*)((void *)(__u64)ctx->data + ip_header_offset);
        if(unlikely((void*)iph + sizeof(struct iphdr) > data_end)) {
            bpf_printk("malformed packet6\n");
            return;
        }
        iph->tot_len =  bpf_htons(bpf_ntohs(iph->tot_len) + spa_opt_size);
        bpf_l3_csum_replace(ctx, ip_header_offset, 0, 0, sizeof(struct iphdr));
    }

    bpf_l4_csum_replace(ctx, tcp_header_offset, 0, 0, sizeof(struct tcphdr));

    bpf_printk("end");

}
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
    int ip_header_offset = pkt_len;
    bool is_ipv6 = false;
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
        is_ipv6 = true;
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
    bpf_printk("packet: %d", proto);
    if(proto != IPPROTO_TCP)
    {
        return TC_ACT_OK;
    }
    struct tcphdr* tcp_hdr = data + pkt_len;
    if (unlikely((void*)tcp_hdr + sizeof(struct tcphdr) > data_end))
    {
        bpf_printk("malformed packet\n");
        return TC_ACT_SHOT;
    }

    // current_flow.dst_port = tcp_hdr->dest;
    // current_flow.src_port = tcp_hdr->source;
    if (tcp_hdr->syn && !tcp_hdr->ack) {
        add_digest(ip_header_offset, is_ipv6, pkt_len, ctx);
        return TC_ACT_OK;
    }
    // Example: Log that we're processing egress traffic
    // (In production, you'd use perf events or other mechanisms)
    
    // Allow packet to continue
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
