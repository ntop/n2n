// cipher SPECK -- 128 bit block size -- 256 bit key size
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/


#ifndef SPECK_H
#define SPECK_H

#include <stdint.h>
#define u32 uint32_t
#define u64 uint64_t

#if defined (__AVX2__)

#define SPECK_ALIGNED_CTX	32
#include <immintrin.h>
#define u256 __m256i
typedef struct {
  u256 rk[34];
  u64 key[34];
} speck_context_t;

#elif defined (__SSE4_2__)

#define SPECK_ALIGNED_CTX	16
#define SPECK_CTX_BYVAL		 1
#include <immintrin.h>
#define u128 __m128i
typedef struct {
  u128 rk[34];
  u64 key[34];
} speck_context_t;

#elif defined (__ARM_NEON)

#include <arm_neon.h>
#define u128 uint64x2_t
typedef struct {
  u128 rk[34];
  u64 key[34];
} speck_context_t;

#else

typedef struct {
  u64 key[34];
} speck_context_t;

#endif


int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
               const unsigned char *n,
#if defined (SPECK_CTX_BYVAL)
	       speck_context_t ctx);
#else
speck_context_t *ctx);
#endif


int speck_expand_key (const unsigned char *k, speck_context_t *ctx);


int speck_he (unsigned char *out, const unsigned char *in, unsigned long long inlen,
              const unsigned char *n, speck_context_t *ctx);


int speck_expand_key_he (const unsigned char *k, speck_context_t *ctx);


int speck_he_iv_encrypt (unsigned char *inout, speck_context_t *ctx);


int speck_he_iv_decrypt (unsigned char *inout, speck_context_t *ctx);


int speck_expand_key_he_iv (const unsigned char *k, speck_context_t *ctx);


#endif
