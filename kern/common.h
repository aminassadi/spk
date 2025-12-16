#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#define IPPROTO_FRAGMENT 44
#define MAX_TCP_OPTIONS 10

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

struct keys {
    __u64 key1;
    __u64 key2;
} __attribute__((packed));

struct destination
{
    char ip[16];
    __u16 port;
};

struct target_keys{
    struct keys keys;
    __u16 key_id;
};

struct tcp_opt_spa {
    uint8_t  kind;        // 253 or 254
    uint8_t  len;         // e.g., 18
    uint16_t exid;        // network order
    uint16_t  ver;         // 1
    uint16_t  key_id;      // selects secret
    uint32_t time_step;   // network order
    uint8_t  tag[8];      // SipHash output bytes
} __attribute__((packed));
