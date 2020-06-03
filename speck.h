
#define u64 uint64_t

#ifdef __SSE4_2__
 #include <immintrin.h>
 #define u128 __m128i
typedef struct {
        u128 rk[34];
        u64 key[34];
} speck_context_t;
#else
 typedef u64 speck_context_t [34];
#endif

int speck_ctr (unsigned char *out, const unsigned char *in,
	       unsigned long long inlen,
               const unsigned char *n,
               speck_context_t ctx);

int speck_expand_key (const unsigned char *k, speck_context_t ctx);
