#ifndef SIPHASH_H
#define SIPHASH_H

struct spa_input {
    union {
        struct {
            __u16 exid;        // 2B, network order
            __u8  ver;         // 1B
            __u8  key_id;      // 1B
            __u32 time_step;   // 4B, network order
            __u32 tcp_seq;     // 4B, TCP sequence number (client ISN)
            __u32 pad:32;     // 4B, padding to make the structure to align 8 bytes
        };
        struct {
            __u64 __1;
            __u64 __2;
        };
    };

} __attribute__((packed));

__attribute__((always_inline)) static inline __u64
siphash_round(__u64 v0, __u64 v1, __u64 v2, __u64 v3)
{
    v0 += v1;
    v1 = (v1 << 13) | (v1 >> 51);
    v1 ^= v0;
    v0 = (v0 << 32) | (v0 >> 32);
    v2 += v3;
    v3 = (v3 << 16) | (v3 >> 48);
    v3 ^= v2;
    v0 += v3;
    v3 = (v3 << 21) | (v3 >> 43);
    v3 ^= v0;
    v2 += v1;
    v1 = (v1 << 17) | (v1 >> 47);
    v1 ^= v2;
    v2 = (v2 << 32) | (v2 >> 32);
    return v0 ^ v1 ^ v2 ^ v3;
}


// SipHash-2-4 implementation
__attribute__((always_inline)) static inline __u64
siphash_2_4(__u64 k0, __u64 k1, const struct spa_input* data)
{
    
    __u64 v0 = k0 ^ 0x736f6d6570736575ULL;
    __u64 v1 = k1 ^ 0x646f72616e646f6dULL;
    __u64 v2 = k0 ^ 0x6c7967656e657261ULL;
    __u64 v3 = k1 ^ 0x7465646279746573ULL;
    
    __u64 b = ((__u64)len) << 56;
    
    const int left = len & 7;
    const __u8* end = m + len - left;
    __u64 mi = data->__1;
    v3 ^= mi;
    v0 = siphash_round(v0, v1, v2, v3);
    v2 ^= v0;
    v0 = siphash_round(v0, v1, v2, v3);
    v2 ^= v0;
    
    mi = data->__2;
    v3 ^= mi;
    v0 = siphash_round(v0, v1, v2, v3);
    v2 ^= v0;
    v0 = siphash_round(v0, v1, v2, v3);
    
    v3 ^= b;
    v0 = siphash_round(v0, v1, v2, v3);
    v2 ^= v0;
    v0 = siphash_round(v0, v1, v2, v3);
    v2 ^= v0;
    
    return v0 ^ v1 ^ v2 ^ v3;
}


#endif 

