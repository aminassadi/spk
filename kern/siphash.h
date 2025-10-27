#ifndef SIPHASH_H
#define SIPHASH_H

struct spa_input {
    __u16 exid;        // 2B, network order
    __u8  ver;         // 1B
    __u8  key_id;      // 1B
    __u32 time_step;   // 4B, network order
    __u32 tcp_seq;     // 4B, TCP sequence number (client ISN)
} __attribute__((packed));

#define SIPROUND do { \
    v0 += v1; \
    v1 = (v1 << 13) | (v1 >> 51); \
    v1 ^= v0; \
    v0 = (v0 << 32) | (v0 >> 32); \
    v2 += v3; \
    v3 = (v3 << 16) | (v3 >> 48); \
    v3 ^= v2; \
    v0 += v3; \
    v3 = (v3 << 21) | (v3 >> 43); \
    v3 ^= v0; \
    v2 += v1; \
    v1 = (v1 << 17) | (v1 >> 47); \
    v1 ^= v2; \
    v2 = (v2 << 32) | (v2 >> 32); \
} while (0)

static inline __u64
read_le64(const __u8* p)
{
    return ((__u64)p[0]) | ((__u64)p[1] << 8) | ((__u64)p[2] << 16) | ((__u64)p[3] << 24) |
           ((__u64)p[4] << 32) | ((__u64)p[5] << 40) | ((__u64)p[6] << 48) | ((__u64)p[7] << 56);
}

__attribute__((always_inline)) static inline __u64
siphash_2_4(__u64 k0, __u64 k1, const struct spa_input* data)
{
    __u64 v0 = 0x736f6d6570736575ULL;
    __u64 v1 = 0x646f72616e646f6dULL;
    __u64 v2 = 0x6c7967656e657261ULL;
    __u64 v3 = 0x7465646279746573ULL;
    
    __u64 m;
    __u64 b;
    const __u8* p = (const __u8*)data;
    size_t len = sizeof(struct spa_input);
    
    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;
    
    m = read_le64(p);
    v3 ^= m;
    SIPROUND;
    SIPROUND;
    v0 ^= m;
    
    b = ((__u64)len) << 56;
    const int left = len & 7;  // 12 & 7 = 4
    const __u8* ni = p + (len - left);  // ni points to start of remaining bytes
    switch (left) {
        case 7: b |= ((__u64)ni[6]) << 48;
        case 6: b |= ((__u64)ni[5]) << 40;
        case 5: b |= ((__u64)ni[4]) << 32;
        case 4: b |= ((__u64)ni[3]) << 24;
        case 3: b |= ((__u64)ni[2]) << 16;
        case 2: b |= ((__u64)ni[1]) << 8;
        case 1: b |= ((__u64)ni[0]);
        case 0: break;
    }
    
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    
    return v0 ^ v1 ^ v2 ^ v3;
}


#endif 

