/**
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


// cipher SPECK -- 128 bit block size -- 128 and 256 bit key size -- CTR mode
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/


#ifndef SPECK_H
#define SPECK_H


#include <stdint.h>     // for uint64_t, uint32_t


#define u32 uint32_t
#define u64 uint64_t

#define N2N_SPECK_IVEC_SIZE     16
#define SPECK_KEY_BYTES       (256/8)


#if defined (__AVX512F__) // AVX512 support -----------------------------------------------------------------------


#include <immintrin.h>
#include <string.h>    /* memcpy() */

#define u512 __m512i

#define SPECK_ALIGNED_CTX       64

typedef struct {
    u512 rk[34];
    u64 key[34];
    u32 keysize;
} speck_context_t;


#elif defined (__AVX2__) // AVX2 support --------------------------------------------------------------------------


#include <immintrin.h>

#define u256 __m256i

#define SPECK_ALIGNED_CTX       32

typedef struct {
    u256 rk[34];
    u64 key[34];
    u32 keysize;
} speck_context_t;


#elif defined (__SSE2__) // SSE support ---------------------------------------------------------------------------


#include <immintrin.h>

#define u128 __m128i

#define SPECK_ALIGNED_CTX       16
#define SPECK_CTX_BYVAL          1

typedef struct {
    u128 rk[34];
    u64 key[34];
    u32 keysize;
} speck_context_t;


#elif defined (__ARM_NEON) && defined (SPECK_ARM_NEON)      // NEON support ---------------------------------------


#include <arm_neon.h>

#define u128 uint64x2_t

typedef struct {
    u128 rk[34];
    u64 key[34];
    u32 keysize;
} speck_context_t;


#else // plain C --------------------------------------------------------------------------------------------------


typedef struct {
    u64 key[34];
    u32 keysize;
} speck_context_t;


#endif // ---------------------------------------------------------------------------------------------------------


int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
               const unsigned char *n,
               speck_context_t *ctx);

int speck_init (speck_context_t **ctx, const unsigned char *k, int keysize);

int speck_deinit (speck_context_t *ctx);


// ----------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------------------


// cipher SPECK -- 128 bit block size -- 128 bit key size -- ECB mode
// follows endianess rules as used in official implementation guide and NOT as in original 2013 cipher presentation
// used for IV in header encryption (one block) and challenge encryption (user/password)
// for now: just plain C -- probably no need for AVX, SSE, NEON


int speck_128_decrypt (unsigned char *inout, speck_context_t *ctx);

int speck_128_encrypt (unsigned char *inout, speck_context_t *ctx);


#endif // SPECK_H
