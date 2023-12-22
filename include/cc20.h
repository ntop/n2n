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


#ifndef CC20_H
#define CC20_H


#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint32_t, uint8_t
#include "config.h"  // HAVE_LIBCRYPTO


#define CC20_IV_SIZE           16
#define CC20_KEY_BYTES       (256/8)


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ----------------------------------------------------------------------------


#include <openssl/evp.h>
#include <openssl/err.h>

typedef struct cc20_context_t {
    EVP_CIPHER_CTX      *ctx;                    /* openssl's reusable evp_* en/de-cryption context */
    const EVP_CIPHER    *cipher;                 /* cipher to use: e.g. EVP_chacha20() */
    uint8_t             key[CC20_KEY_BYTES];     /* the pure key data for payload encryption & decryption */
} cc20_context_t;


#elif defined (__SSE2__)  // SSE2 ---------------------------------------------------------------------------------


typedef struct cc20_context {
    uint32_t keystream32[16];
    uint8_t key[CC20_KEY_BYTES];
} cc20_context_t;


#else // plain C --------------------------------------------------------------------------------------------------


typedef struct cc20_context {
    uint32_t keystream32[16];
    uint32_t state[16];
    uint8_t key[CC20_KEY_BYTES];
} cc20_context_t;


#endif // openSSL 1.1, plain C ------------------------------------------------------------------------------------


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx);

int cc20_init (const unsigned char *key, cc20_context_t **ctx);

int cc20_deinit (cc20_context_t *ctx);


#endif // CC20_H
