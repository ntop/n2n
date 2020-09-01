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


#ifndef CC20_H
#define CC20_H

#include "n2n.h"               // HAVE_OPENSSL_1_1, traceEvent ...


#ifdef HAVE_OPENSSL_1_1


#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define CC20_IV_SIZE           16
#define CC20_KEY_BYTES       (256/8)


typedef struct cc20_context_t {
  EVP_CIPHER_CTX      *ctx;                    /* openssl's reusable evp_* en/de-cryption context */
  const EVP_CIPHER    *cipher;                 /* cipher to use: e.g. EVP_chacha20() */
  uint8_t             key[CC20_KEY_BYTES];     /* the pure key data for payload encryption & decryption */
} cc20_context_t;


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx);


int cc20_init (const unsigned char *key, cc20_context_t **ctx);


int cc20_deinit (cc20_context_t *ctx);


#endif // HAVE_OPENSSL_1_1


#endif // CC20_H
