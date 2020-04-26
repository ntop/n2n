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

#include "n2n.h"
#include "n2n_transforms.h"

#ifdef HAVE_OPENSSL_1_1

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define N2N_CC20_TRANSFORM_VERSION       1  /* version of the transform encoding */
#define N2N_CC20_IVEC_SIZE               16

#define CC20_KEY_BYTES (256/8)

/* ChaCha20 plaintext preamble */
#define TRANSOP_CC20_VER_SIZE     1       /* Support minor variants in encoding in one module. */
#define TRANSOP_CC20_PREAMBLE_SIZE (TRANSOP_CC20_VER_SIZE + N2N_CC20_IVEC_SIZE)

typedef unsigned char n2n_cc20_ivec_t[N2N_CC20_IVEC_SIZE];

typedef struct transop_cc20 {
  EVP_CIPHER_CTX      *enc_ctx;	      /* openssl's reusable evp_* encryption context */
  EVP_CIPHER_CTX      *dec_ctx;	      /* openssl's reusable evp_* decryption context */
  const EVP_CIPHER    *cipher;	      /* cipher to use: EVP_chacha20() */
  uint8_t  	      key[32];	      /* the pure key data for payload encryption & decryption */
} transop_cc20_t;

/* ****************************************************** */

static int transop_deinit_cc20(n2n_trans_op_t *arg) {
  transop_cc20_t *priv = (transop_cc20_t *)arg->priv;

  EVP_CIPHER_CTX_free(priv->enc_ctx);
  EVP_CIPHER_CTX_free(priv->dec_ctx);

  if(priv)
    free(priv);

  return 0;
}

/* ****************************************************** */

/* get any erorr message out of openssl
   taken from https://en.wikibooks.org/wiki/OpenSSL/Error_handling */
char *openssl_err_as_string (void) {
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

static void set_cc20_iv(transop_cc20_t *priv, n2n_cc20_ivec_t ivec) {
  // keep in mind the following condition: N2N_CC20_IVEC_SIZE % sizeof(rand_value) == 0 !
  uint32_t rand_value;
  for (uint8_t i = 0; i < N2N_CC20_IVEC_SIZE; i += sizeof(rand_value)) {
    rand_value = rand(); // CONCERN: rand() is not consideren cryptographicly secure, REPLACE later
    memcpy(ivec + i, &rand_value, sizeof(rand_value));
  }
}

/* ****************************************************** */

/** The ChaCha20 packet format consists of:
 *
 *  - a 8-bit cc20 encoding version in clear text
 *  - a 128-bit random IV
 *  - encrypted payload.
 *
 *  [V|IIII|DDDDDDDDDDDDDDDDDDDDD]
 *         |<---- encrypted ---->|
 */
static int transop_encode_cc20(n2n_trans_op_t * arg,
			       uint8_t * outbuf,
			       size_t out_len,
			       const uint8_t * inbuf,
			       size_t in_len,
			       const uint8_t * peer_mac) {
  int len=-1;
  transop_cc20_t * priv = (transop_cc20_t *)arg->priv;
  uint8_t assembly[N2N_PKT_BUF_SIZE] = {0};

  if(in_len <= N2N_PKT_BUF_SIZE) {
    if((in_len + TRANSOP_CC20_PREAMBLE_SIZE) <= out_len) {
      size_t idx=0;
      n2n_cc20_ivec_t enc_ivec = {0};

      traceEvent(TRACE_DEBUG, "encode_cc20 %lu bytes", in_len);

      /* Encode the ChaCha20 format version. */
      encode_uint8(outbuf, &idx, N2N_CC20_TRANSFORM_VERSION);

      /* Generate and encode the IV. */
      set_cc20_iv(priv, enc_ivec);
      encode_buf(outbuf, &idx, &enc_ivec, N2N_CC20_IVEC_SIZE);
      traceEvent(TRACE_DEBUG, "encode_cc20 iv=%016llx:%016llx",
                               htobe64(*(uint64_t*)&enc_ivec[0]),
                               htobe64(*(uint64_t*)&enc_ivec[8]) );

      /* Encrypt the assembly contents and write the ciphertext after the iv. */
      /* len is set to the length of the cipher plain text to be encrpyted
	 which is (in this case) identical to original packet lentgh */
      len = in_len;

      /* The assembly buffer is a source for encrypting data.
       * The whole contents of assembly are encrypted. */
      memcpy(assembly, inbuf, in_len);

      EVP_CIPHER_CTX *ctx = priv->enc_ctx;
      int evp_len;
      int evp_ciphertext_len;

      if(1 == EVP_EncryptInit_ex(ctx, priv->cipher, NULL, priv->key, enc_ivec)) {
	if(1 == EVP_CIPHER_CTX_set_padding(ctx, 0)) {
	  if(1 == EVP_EncryptUpdate(ctx, outbuf + TRANSOP_CC20_PREAMBLE_SIZE, &evp_len, assembly, len)) {
	    evp_ciphertext_len = evp_len;
	    if(1 == EVP_EncryptFinal_ex(ctx, outbuf + TRANSOP_CC20_PREAMBLE_SIZE + evp_len, &evp_len)) {
	      evp_ciphertext_len += evp_len;

	      if(evp_ciphertext_len != len)
		traceEvent(TRACE_ERROR, "encode_cc20 openssl encryption: encrypted %u bytes where %u were expected.\n",
			   evp_ciphertext_len, len);
	    } else
	      traceEvent(TRACE_ERROR, "encode_cc20 openssl final encryption: %s\n", openssl_err_as_string());
	  } else
	    traceEvent(TRACE_ERROR, "encode_cc20 openssl encrpytion: %s\n", openssl_err_as_string());
	} else
	  traceEvent(TRACE_ERROR, "encode_cc20 openssl padding setup: %s\n", openssl_err_as_string());
      } else
	traceEvent(TRACE_ERROR, "encode_cc20 openssl init: %s\n", openssl_err_as_string());

      EVP_CIPHER_CTX_reset(ctx);

      len += TRANSOP_CC20_PREAMBLE_SIZE; /* size of data carried in UDP. */
    } else
      traceEvent(TRACE_ERROR, "encode_cc20 outbuf too small.");
  } else
    traceEvent(TRACE_ERROR, "encode_cc20 inbuf too big to encrypt.");

  return len;
}

/* ****************************************************** */

/* See transop_encode_cc20 for packet format */
static int transop_decode_cc20(n2n_trans_op_t * arg,
			       uint8_t * outbuf,
			       size_t out_len,
			       const uint8_t * inbuf,
			       size_t in_len,
			       const uint8_t * peer_mac) {
  int len=0;
  transop_cc20_t * priv = (transop_cc20_t *)arg->priv;
  uint8_t assembly[N2N_PKT_BUF_SIZE];

  if(((in_len - TRANSOP_CC20_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* Cipher text fits in assembly */
     && (in_len >= TRANSOP_CC20_PREAMBLE_SIZE) /* Has at least version, iv */
  )
  {
    size_t rem=in_len;
    size_t idx=0;
    uint8_t cc20_enc_ver=0;
    n2n_cc20_ivec_t dec_ivec = {0};

    /* Get the encoding version to make sure it is supported */
    decode_uint8(&cc20_enc_ver, inbuf, &rem, &idx );

    if(N2N_CC20_TRANSFORM_VERSION == cc20_enc_ver) {
      traceEvent(TRACE_DEBUG, "decode_cc20 %lu bytes", in_len);
      len = (in_len - TRANSOP_CC20_PREAMBLE_SIZE);

      /* Get the IV */
      decode_buf((uint8_t *)&dec_ivec, N2N_CC20_IVEC_SIZE, inbuf, &rem, &idx);
      traceEvent(TRACE_DEBUG, "decode_cc20 iv=%016llx:%016llx",
                               htobe64(*(uint64_t*)&dec_ivec[0]),
                               htobe64(*(uint64_t*)&dec_ivec[8]) );

      EVP_CIPHER_CTX *ctx = priv->dec_ctx;
      int evp_len;
      int evp_plaintext_len;

      if(1 == EVP_DecryptInit_ex(ctx, priv->cipher, NULL, priv->key, dec_ivec)) {
	if(1 == EVP_CIPHER_CTX_set_padding(ctx, 0)) {
	  if(1 == EVP_DecryptUpdate(ctx, assembly, &evp_len, inbuf + TRANSOP_CC20_PREAMBLE_SIZE, len)) {
	    evp_plaintext_len = evp_len;
	    if(1 == EVP_DecryptFinal_ex(ctx, assembly + evp_len, &evp_len)) {
	      evp_plaintext_len += evp_len;

	      if(evp_plaintext_len != len)
		traceEvent(TRACE_ERROR, "decode_cc20 openssl decryption: decrypted %u bytes where %u were expected.\n",
		           evp_plaintext_len, len);
	    } else
	      traceEvent(TRACE_ERROR, "decode_cc20 openssl final decryption: %s\n", openssl_err_as_string());
	  } else
	    traceEvent(TRACE_ERROR, "decode_cc20 openssl decrpytion: %s\n", openssl_err_as_string());
	} else
	  traceEvent(TRACE_ERROR, "decode_cc20 openssl padding setup: %s\n", openssl_err_as_string());
      } else
        traceEvent(TRACE_ERROR, "decode_cc20 openssl init: %s\n", openssl_err_as_string());

      EVP_CIPHER_CTX_reset(ctx);

      memcpy(outbuf, assembly, len);
    } else
      traceEvent(TRACE_ERROR, "decode_cc20 unsupported ChaCha20 version %u.", cc20_enc_ver);
  } else
  traceEvent(TRACE_ERROR, "decode_cc20 inbuf wrong size (%ul) to decrypt.", in_len);

  return len;
}

/* ****************************************************** */

static int setup_cc20_key(transop_cc20_t *priv, const uint8_t *key, ssize_t key_size) {
  uint8_t key_mat_buf[SHA256_DIGEST_LENGTH];

  priv->cipher = EVP_chacha20();

  /* Clear out any old possibly longer key matter. */
  memset(&(priv->key), 0, sizeof(priv->key) );
  /* The input key always gets hashed to make a more unpredictable and more complete use of the key space */
  SHA256(key, key_size, key_mat_buf);
  memcpy (priv->key, key_mat_buf, SHA256_DIGEST_LENGTH);

  traceEvent(TRACE_DEBUG, "ChaCha20 key setup completed\n");

  return(0);
}

/* ****************************************************** */

static void transop_tick_cc20(n2n_trans_op_t * arg, time_t now) { ; }

/* ****************************************************** */

/* ChaCha20 initialization function */
int n2n_transop_cc20_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {
  transop_cc20_t *priv;
  const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
  size_t encrypt_key_len = strlen(conf->encrypt_key);

  memset(ttt, 0, sizeof(*ttt));
  ttt->transform_id = N2N_TRANSFORM_ID_CHACHA20;

  ttt->tick = transop_tick_cc20;
  ttt->deinit = transop_deinit_cc20;
  ttt->fwd = transop_encode_cc20;
  ttt->rev = transop_decode_cc20;

  priv = (transop_cc20_t*) calloc(1, sizeof(transop_cc20_t));
  if(!priv) {
    traceEvent(TRACE_ERROR, "cannot allocate transop_cc20_t memory");
    return(-1);
  }
  ttt->priv = priv;

  /* Setup openssl's reusable evp_* contexts for encryption and decryption*/
  if(!(priv->enc_ctx = EVP_CIPHER_CTX_new())) {
    traceEvent(TRACE_ERROR, "openssl's evp_* encryption context creation: %s\n", openssl_err_as_string());
    return(-1);
  }

  if(!(priv->dec_ctx = EVP_CIPHER_CTX_new())) {
    traceEvent(TRACE_ERROR, "openssl's evp_* decryption context creation: %s\n", openssl_err_as_string());
    return(-1);
  }

  /* Setup the cipher and key */
  return(setup_cc20_key(priv, encrypt_key, encrypt_key_len));
}

#endif /* HAVE_OPENSSL_1_1 */
