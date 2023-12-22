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


#ifndef AES_H
#define AES_H


#include <stdint.h>
#include <stdlib.h>

#include "portable_endian.h"

#define AES_BLOCK_SIZE           16
#define AES_IV_SIZE             (AES_BLOCK_SIZE)

#define AES256_KEY_BYTES        (256/8)
#define AES192_KEY_BYTES        (192/8)
#define AES128_KEY_BYTES        (128/8)


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ---------------------------------------------------------------------

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef struct aes_context_t {
    EVP_CIPHER_CTX      *enc_ctx;                /* openssl's reusable evp_* en/de-cryption context */
    EVP_CIPHER_CTX      *dec_ctx;                /* openssl's reusable evp_* en/de-cryption context */
    const EVP_CIPHER    *cipher;                 /* cipher to use: e.g. EVP_aes_128_cbc */
    uint8_t             key[AES256_KEY_BYTES];   /* the pure key data for payload encryption & decryption */
    AES_KEY             ecb_dec_key;             /* one step ecb decryption key */
} aes_context_t;

#elif defined (__AES__) && defined (__SSE2__) // Intel's AES-NI ---------------------------------------------------

#include <immintrin.h>

typedef struct aes_context_t {
    __m128i rk_enc[15];
    __m128i rk_dec[15];
    int     Nr;
} aes_context_t;

#else // plain C --------------------------------------------------------------------------------------------------

typedef struct aes_context_t {
    uint32_t enc_rk[60];    // round keys for encryption
    uint32_t dec_rk[60];    // round keys for decryption
    int      Nr;            // number of rounds
} aes_context_t;

#endif // ---------------------------------------------------------------------------------------------------------


int aes_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx);

int aes_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx);

int aes_ecb_decrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx);

int aes_init (const unsigned char *key, size_t key_size, aes_context_t **ctx);

int aes_deinit (aes_context_t *ctx);


#endif // AES_H
