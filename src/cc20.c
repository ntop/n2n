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


#include "cc20.h"


#ifdef HAVE_OPENSSL_1_1


/* ****************************************************** */

/* get any erorr message out of openssl
   taken from https://en.wikibooks.org/wiki/OpenSSL/Error_handling */
static char *openssl_err_as_string (void) {
  BIO *bio = BIO_new (BIO_s_mem ());
  ERR_print_errors (bio);
  char *buf = NULL;
  size_t len = BIO_get_mem_data (bio, &buf);
  char *ret = (char *) calloc (1, 1 + len);

  if(ret)
    memcpy (ret, buf, len);

  BIO_free (bio);
  return ret;
}

/* ****************************************************** */

// encryption == decryption
int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

  int evp_len;
  int evp_ciphertext_len;

  if(1 == EVP_EncryptInit_ex(ctx->ctx, ctx->cipher, NULL, ctx->key, iv)) {
    if(1 == EVP_CIPHER_CTX_set_padding(ctx->ctx, 0)) {
      if(1 == EVP_EncryptUpdate(ctx->ctx, out, &evp_len, in, in_len)) {
        evp_ciphertext_len = evp_len;
        if(1 == EVP_EncryptFinal_ex(ctx->ctx, out + evp_len, &evp_len)) {
          evp_ciphertext_len += evp_len;
          if(evp_ciphertext_len != in_len)
            traceEvent(TRACE_ERROR, "cc20_crypt openssl encryption: encrypted %u bytes where %u were expected",
                                    evp_ciphertext_len, in_len);
        } else
          traceEvent(TRACE_ERROR, "cc20_crypt openssl final encryption: %s",
                                  openssl_err_as_string());
      } else
        traceEvent(TRACE_ERROR, "cc20_encrypt openssl encrpytion: %s",
                                openssl_err_as_string());
    } else
      traceEvent(TRACE_ERROR, "cc20_encrypt openssl padding setup: %s",
                              openssl_err_as_string());
  } else
    traceEvent(TRACE_ERROR, "cc20_encrypt openssl init: %s",
                            openssl_err_as_string());

  EVP_CIPHER_CTX_reset(ctx->ctx);

  return 0;
}


int cc20_init (const unsigned char *key, cc20_context_t **ctx) {

 // allocate context...
  *ctx = (cc20_context_t*) calloc(1, sizeof(cc20_context_t));
  if (!(*ctx))
    return -1;

  if(!((*ctx)->ctx = EVP_CIPHER_CTX_new())) {
    traceEvent(TRACE_ERROR, "cc20_init openssl's evp_* encryption context creation failed: %s",
                            openssl_err_as_string());
    return -1;
  }

  (*ctx)->cipher = EVP_chacha20();

  memcpy((*ctx)->key, key, CC20_KEY_BYTES);

  return 0;
}


int cc20_deinit (cc20_context_t *ctx) {

  if (ctx->ctx) EVP_CIPHER_CTX_free(ctx->ctx);

  return 0;
}


#endif // HAVE_OPENSSL_1_1
