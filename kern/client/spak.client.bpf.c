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

static __always_inline __sum16 csum_fold(__wsum csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__sum16)~csum;
  }

  __attribute__((__always_inline__)) static inline __u16
  csum_fold_helper(__u64 csum) {
    int i;
  #pragma unroll
    for (i = 0; i < 4; i++) {
      if (csum >> 16)
        csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
  }

static __always_inline __u16 csum_tcpudp_ip(__u32 saddr, __u32 daddr,
    __u32 len, __u8 proto,
    __u32 csum) {
        __u64 s = csum;

        s += (__u32)saddr;
        s += (__u32)daddr;
      #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        s += proto + len;
      #elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        s += (proto + len) << 8;
      #else
      #error Unknown endian
      #endif
        s = (s & 0xffffffff) + (s >> 32);
        s = (s & 0xffffffff) + (s >> 32);
      
        return csum_fold((__u32)s);
}

static __always_inline __u16 csum_tcpudp_ipv6(const struct in6_addr *saddr,
  const struct in6_addr *daddr,
  __u32 len, __u8 proto,
  __u32 csum) {
    __u64 sum = csum;
    int i;

    #pragma unroll
    for (i = 0; i < 4; i++)
    sum += (__u32)saddr->in6_u.u6_addr32[i];

    #pragma unroll
    for (i = 0; i < 4; i++)
    sum += (__u32)daddr->in6_u.u6_addr32[i];

    /* Don't combine additions to avoid 32-bit overflow. */
    sum += bpf_htonl(len);
    sum += bpf_htonl(proto);

    sum = (sum & 0xffffffff) + (sum >> 32);
    sum = (sum & 0xffffffff) + (sum >> 32);

    return csum_fold((__u32)sum);
}

__attribute__((__always_inline__)) static inline void
ipv4_csum_inline(void *iph, __u64 *csum) {
  __u16 *next_iph_u16 = (__u16 *)iph;
#pragma unroll
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
    *csum += *next_iph_u16++;
  }
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv4_csum(void* data_start, int data_size, __u64* csum) {
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

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
    u32 actual_packet_size = ctx->len + spa_opt_size;
    int ret = bpf_skb_change_tail(ctx, ctx->len + MAX_OPTIONS_SIZE, 0);
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
        if (i > rem_size-1)
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

    tcph->doff += spa_opt_size / 4;
    tcph->check = 0;
   
    __u32 tcp_len = tcph->doff * 4;
    bpf_printk("tcp_len: %d\n", tcp_len);
    if(unlikely((void*)tcph + tcp_len > data_end )) {
        bpf_printk("malformed packet7\n");
        return;
    }
 

   __u32 value = bpf_csum_diff(0, 0, (void*)tcph, sizeof(struct tcphdr), 0);
   if(unlikely(opt_ptr + MAX_OPTIONS_SIZE > data_end)) {
    bpf_printk("malformed packet8\n");
    return;
   }
  // asm volatile("%[rem_size] &= 31\n" : [rem_size] "+&r"(rem_size));
   value = bpf_csum_diff(0, 0, (void*)opt_ptr, MAX_OPTIONS_SIZE, value);


    if(is_ipv6) {
        struct ipv6hdr* ip6h = (struct ipv6hdr*)((void *)(__u64)ctx->data + ip_header_offset);
        if(unlikely((void*)ip6h + sizeof(struct ipv6hdr) > data_end)) {
            bpf_printk("malformed packet6\n");
            return;
        }
     tcph->check = csum_tcpudp_ipv6(&ip6h->saddr, &ip6h->daddr, tcp_len, IPPROTO_TCP, value);
    } 
    else {
        struct iphdr* iph = (struct iphdr*)((void *)(__u64)ctx->data + ip_header_offset);
        if(unlikely((void*)iph + sizeof(struct iphdr) > data_end)) {
            bpf_printk("malformed packet4\n");
            return;
        }
        bpf_printk("tcp->check: %d\n", tcph->check);
        iph->tot_len =  bpf_htons(bpf_ntohs(iph->tot_len) + spa_opt_size);
        u64 csum = 0;
        iph->check = 0;
        ipv4_csum((void*)iph, sizeof(struct iphdr), &csum);
        iph->check = csum;
        tcph->check = csum_tcpudp_ip(iph->saddr, iph->daddr, tcp_len, IPPROTO_TCP, value);
        bpf_printk("after: tcp->check: %d\n", tcph->check);
    }

    ret = bpf_skb_change_tail(ctx, actual_packet_size, 0);
    if (ret < 0) {
        bpf_printk("failed to change tail: %d\n", ret);
        return; 
    }
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
