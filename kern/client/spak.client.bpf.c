#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <strings.h>
#include <string.h>
#include "../siphash.h"
#include "../common.h"

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7

#define MAX_OPTIONS_SIZE 64



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct destination);
    __type(value, struct target_keys); 
} secrets SEC(".maps");

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

__attribute__((always_inline)) static inline void add_digest(int ip_header_offset, bool is_ipv6, int tcp_header_offset, struct __sk_buff *ctx, struct target_keys* keys)
{

    void* data_end = (void*)(__u64)ctx->data_end;
    struct tcphdr* tcph = (struct tcphdr*)((void *)(__u64)ctx->data + tcp_header_offset);
    if (unlikely((void*)tcph + sizeof(struct tcphdr) > data_end))
    {
        bpf_printk("malformed packet1\n");
        return ;
    }
    void* opt_ptr = (__u8*)tcph + sizeof(struct tcphdr);
    void* opt_end = (__u8*)tcph + (tcph->doff * 4);
   
    int spa_opt_size = sizeof(struct tcp_opt_spa); 
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
    spa_opt->key_id = keys->key_id;
    struct spa_input input;
    memset(&input, 0, sizeof(input));
    input.exid = spa_opt->exid;           
    input.ver = spa_opt->ver;            
    input.key_id = spa_opt->key_id;     
    input.time_step = spa_opt->time_step; 
    input.tcp_seq = tcph->seq;           
    __u64 k0 = keys->keys.key1;
    __u64 k1 = keys->keys.key2;
    __u64 hash = siphash_2_4(k0, k1, &input);
    memcpy(spa_opt->tag, &hash, 8);
    

    tcph->doff += spa_opt_size / 4;
    tcph->check = 0;
   
    __u32 tcp_len = tcph->doff * 4;
    if(unlikely((void*)tcph + tcp_len > data_end )) {
        bpf_printk("malformed packet7\n");
        return;
    }
 

   __u32 value = bpf_csum_diff(0, 0, (void*)tcph, sizeof(struct tcphdr), 0);
   if(unlikely(opt_ptr + MAX_OPTIONS_SIZE > data_end)) {
    bpf_printk("malformed packet8\n");
    return;
   }
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
}

SEC("classifier/egress")
int tc_egress(struct __sk_buff *ctx)
{
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
    struct destination dest;
    memset(&dest, 0, sizeof(dest));
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        iph = data + pkt_len;
        pkt_len += (iph->ihl * 4);
        if (unlikely((void*)iph + sizeof(struct iphdr) > data_end))
        {
            bpf_printk("malformed packet\n");
            return TC_ACT_SHOT;
        }
        memcpy(&dest.ip, &iph->daddr, 4);
        is_fragment = (bool)(u16)(iph->frag_off & bpf_htons(IP_MF));
        proto = iph->protocol;
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
        memcpy(&dest.ip, &ip6h->daddr, 16);
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
    dest.port = bpf_ntohs(tcp_hdr->dest);
    bpf_printk("dest.port: %d, dest.ip: %d\n", dest.port, *(__u32*)dest.ip);
    struct target_keys* keys = bpf_map_lookup_elem(&secrets, &dest);
    if (!keys) {
        return TC_ACT_OK;
    }
    if (tcp_hdr->syn && !tcp_hdr->ack) {
        add_digest(ip_header_offset, is_ipv6, pkt_len, ctx, keys);
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
