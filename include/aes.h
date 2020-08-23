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


#ifdef N2N_HAVE_AES

#ifndef AES_H
#define AES_H

#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define AES256_KEY_BYTES (256/8)
#define AES192_KEY_BYTES (192/8)
#define AES128_KEY_BYTES (128/8)


typedef struct aes_context_t {
#ifdef HAVE_OPENSSL_1_1
  EVP_CIPHER_CTX      *enc_ctx;                /* openssl's reusable evp_* en/de-cryption context */
  EVP_CIPHER_CTX      *dec_ctx;                /* openssl's reusable evp_* en/de-cryption context */
  const EVP_CIPHER    *cipher;                 /* cipher to use: e.g. EVP_aes_128_cbc */
  uint8_t             key[AES256_KEY_BYTES];   /* the pure key data for payload encryption & decryption */
  AES_KEY             ecb_dec_key;             /* one step ecb decryption key */
#else
  AES_KEY             enc_key;                 /* tx key */
  AES_KEY             dec_key;                 /* tx key */
#endif
} aes_context_t;


int aes_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     unsigned char *iv, aes_context_t *ctx);

int aes_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     unsigned char *iv, aes_context_t *ctx);

int aes_ecb_decrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx);

int aes_init (const unsigned char *key, size_t key_size, aes_context_t **ctx);


#endif // AES_H

#endif // N2N_HAVE_AES
