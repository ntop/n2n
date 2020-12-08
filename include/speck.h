/**
 * (C) 2007-20 - ntop.org and contributors
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


// cipher SPECK -- 128 bit block size -- 256 bit key size -- CTR mode
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/


#ifndef SPECK_H
#define SPECK_H


#include <stdint.h>
#include <stdlib.h>

#include "portable_endian.h"


#define u32 uint32_t
#define u64 uint64_t

#define N2N_SPECK_IVEC_SIZE     16
#define SPECK_KEY_BYTES       (256/8)


#if defined (__AVX2__) // AVX support -----------------------------------------------------------------------------


#include <immintrin.h>

#define u256 __m256i

#define SPECK_ALIGNED_CTX	32

typedef struct {
    u256 rk[34];
    u64 key[34];
} speck_context_t;


#elif defined (__SSE2__) // SSE support ---------------------------------------------------------------------------


#include <immintrin.h>

#define u128 __m128i

#define SPECK_ALIGNED_CTX	16
#define SPECK_CTX_BYVAL		 1

typedef struct {
    u128 rk[34];
    u64 key[34];
} speck_context_t;


#elif defined (__ARM_NEON) // NEON support ------------------------------------------------------------------------


#include <arm_neon.h>

#define u128 uint64x2_t

typedef struct {
   u128 rk[34];
   u64 key[34];
} speck_context_t;


#else // plain C --------------------------------------------------------------------------------------------------


typedef struct {
    u64 key[34];
} speck_context_t;


#endif // ---------------------------------------------------------------------------------------------------------


int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
               const unsigned char *n,
	       speck_context_t *ctx);

int speck_init (const unsigned char *k, speck_context_t **ctx);

int speck_deinit (speck_context_t *ctx);


// ----------------------------------------------------------------------------------------------------------------


// cipher SPECK -- 128 bit block size -- 128 bit key size -- CTR mode
// used for header encryption, thus the postfix '_he'
// for now: just plain C -- AVX, SSE, NEON do not make sense for short header


int speck_he (unsigned char *out, const unsigned char *in, unsigned long long inlen,
              const unsigned char *n, speck_context_t *ctx);

int speck_expand_key_he (const unsigned char *k, speck_context_t *ctx);


// ----------------------------------------------------------------------------------------------------------------


// cipher SPECK -- 96 bit block size -- 96 bit key size -- ECB mode
// follows endianess rules as used in official implementation guide and NOT as in original 2013 cipher presentation
// used for IV in header encryption, thus the in/postfix 'he_iv'
// for now: just plain C -- probably no need for AVX, SSE, NEON


int speck_he_iv_encrypt (unsigned char *inout, speck_context_t *ctx);

int speck_he_iv_decrypt (unsigned char *inout, speck_context_t *ctx);

int speck_expand_key_he_iv (const unsigned char *k, speck_context_t *ctx);


#endif // SPECK_H
