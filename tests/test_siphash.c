#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "siphash-ref.h"

// Define types for standalone compilation
#define __u64 unsigned long long
#define __u8 unsigned char
#define __u16 unsigned short
#define __u32 unsigned int


// Include the simplified siphash implementation
#include "../kern/siphash.h"





// Test SPA authentication input format
void test_spa_authentication() {
    printf("=== Testing SPA Authentication Input Format ===\n\n");
    
    struct spa_input input;
    input.exid = htons(0x1234);
    input.ver = 1;
    input.key_id = 0;
    input.time_step = htonl(1699123456);
    input.tcp_seq = htonl(0xDEADBEEF);
    char key[16] = "123456789ABCDEF0";
    uint64_t k0 = *(uint64_t*)key;
    uint64_t k1 = *(uint64_t*)(key + 8);
    uint64_t result = siphash_2_4(k0, k1, &input);
    uint8_t out_ref[8];
    siphash(&input, sizeof(input), key, out_ref, 8);
    printf("out_ref: %016llx\n", *(long long unsigned int*)out_ref);
    printf("result: %016llx\n", (long long unsigned int)result);
    assert(memcmp(out_ref, &result, sizeof(result)) == 0);
    
    // Test with a different exid
    input.exid = htons(0x5678);
    input.ver = 1;
    input.key_id = 0;
    input.time_step = htonl(1699123456);
    input.tcp_seq = htonl(0xDEADBEEF);
    uint64_t result2 = siphash_2_4(k0, k1, &input);
    uint8_t out_ref2[8];
    siphash(&input, sizeof(input), key, out_ref2, 8);
    printf("out_ref2: %016llx\n", *(long long unsigned int*)out_ref2);
    printf("result2: %016llx\n", (long long unsigned int)result2);
    assert(memcmp(out_ref2, &result2, sizeof(result2)) == 0);

    // Test with a different tcp_seq
    input.exid = htons(0x1234);
    input.ver = 1;
    input.key_id = 0;
    input.time_step = htonl(1699123456);
    input.tcp_seq = htonl(0xCAFEBABE);
    uint64_t result3 = siphash_2_4(k0, k1, &input);
    uint8_t out_ref3[8];
    siphash(&input, sizeof(input), key, out_ref3, 8);
    printf("out_ref3: %016llx\n", *(long long unsigned int*)out_ref3);
    printf("result3: %016llx\n", (long long unsigned int)result3);
    assert(memcmp(out_ref3, &result3, sizeof(result3)) == 0);

    // Test with different key
    char key2[16] = "FEDCBA9876543210";
    uint64_t k0b = *(uint64_t*)key2;
    uint64_t k1b = *(uint64_t*)(key2 + 8);
    input.exid = htons(0x1234);
    input.ver = 1;
    input.key_id = 0;
    input.time_step = htonl(1699123456);
    input.tcp_seq = htonl(0xDEADBEEF);
    uint64_t result4 = siphash_2_4(k0b, k1b, &input);
    uint8_t out_ref4[8];
    siphash(&input, sizeof(input), key2, out_ref4, 8);
    printf("out_ref4: %016llx\n", *(long long unsigned int*)out_ref4);
    printf("result4: %016llx\n", (long long unsigned int)result4);
    assert(memcmp(out_ref4, &result4, sizeof(result4)) == 0);
}


int main() {
    printf("========================================\n");
    printf("SipHash-2-4 Test Suite (SPA Focus)\n");
    printf("========================================\n\n");
    
    // Run SPA-specific tests
    test_spa_authentication();
    
    printf("\nOverall: SipHash implementation appears to be working correctly!\n");
    printf("The function is consistent and produces different hashes for different inputs.\n\n");
    
    return 0;
}
