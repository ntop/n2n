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

#ifdef N2N_HAVE_AES

#include <bearssl.h>

#define SHA256_DIGEST_LENGTH	(256/8)
#define SHA384_DIGEST_LENGTH	(384/8)
#define SHA512_DIGEST_LENGTH	(512/8)
#define AES_BLOCK_SIZE		br_aes_big_BLOCK_SIZE

#define N2N_AES_TRANSFORM_VERSION       1  /* version of the transform encoding */
#define N2N_AES_IVEC_SIZE               (AES_BLOCK_SIZE)

#define AES256_KEY_BYTES (256/8)
#define AES192_KEY_BYTES (192/8)
#define AES128_KEY_BYTES (128/8)

/* AES plaintext preamble */
#define TRANSOP_AES_VER_SIZE     1       /* Support minor variants in encoding in one module. */
#define TRANSOP_AES_IV_SEED_SIZE 8    /* size of transmitted random part of IV in bytes; could range
				       * from 0=lowest security (constant IV)  to  16=higest security
				       * (fully random IV); default=8 */
#define TRANSOP_AES_IV_PADDING_SIZE (N2N_AES_IVEC_SIZE - TRANSOP_AES_IV_SEED_SIZE)
#define TRANSOP_AES_IV_KEY_BYTES (AES128_KEY_BYTES) /* use AES128 for IV encryption */
#define TRANSOP_AES_PREAMBLE_SIZE (TRANSOP_AES_VER_SIZE + TRANSOP_AES_IV_SEED_SIZE)

typedef unsigned char n2n_aes_ivec_t[N2N_AES_IVEC_SIZE];

typedef struct transop_aes {
  const br_block_cbcenc_class	**enc;		/* 'object' for AES encryption */
  br_aes_gen_cbcenc_keys	enc_ctx;	/*   context to hold data for the above */
  const br_block_cbcdec_class	**dec;		/* 'object' for AES decryption */
  br_aes_gen_cbcdec_keys	dec_ctx;	/*   context to hold data for the above */
  const br_block_cbcenc_class 	**enc_ivec;	/* 'object' for IV encryption */
  br_aes_gen_cbcenc_keys	enc_ivec_ctx;	/*   context to hold data for the above */
  uint8_t             		iv_pad_val[TRANSOP_AES_IV_PADDING_SIZE]; /* data used to pad the random IV seed to full block size */
} transop_aes_t;

/* ****************************************************** */

static int transop_deinit_aes(n2n_trans_op_t *arg) {
  transop_aes_t *priv = (transop_aes_t *)arg->priv;

  if(priv)
    free(priv);

  return 0;
}

/* ****************************************************** */

size_t hash_data(const br_hash_class *hf, const void *data, size_t len, void *dst) {

        br_hash_compat_context sc;

        hf->init(&sc.vtable);
        sc.vtable->update(&sc.vtable, data, len);
        sc.vtable->out(&sc.vtable, dst);

        return (hf->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
}

/* ****************************************************** */

/* convert a given number of bytes from memory to hex string; taken (and modified) from
   https://stackoverflow.com/questions/6357031/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-in-c */
const char* to_hex(unsigned char * in, size_t insz, char * out, size_t outsz)
{
  unsigned char * pin = in;
  const char * hex = "0123456789abcdef";
  char * pout = out;
  for(; pin < in+insz; pout +=2, pin++){
    pout[0] = hex[(*pin>>4) & 0xF];
    pout[1] = hex[ *pin     & 0xF];
    if (pout + 2 - out > outsz){
      /* Better to truncate output string than overflow buffer */
      /* it would be still better to either return a status */
      /* or ensure the target buffer is large enough and it never happen */
      break;
      }
    }
    pout[2] = 0;
    return out;
}

/* ****************************************************** */

static void set_aes_cbc_iv(transop_aes_t *priv, n2n_aes_ivec_t ivec, uint8_t * iv_seed) {
  uint8_t iv_full[N2N_AES_IVEC_SIZE];

  /* Extend the seed to full block size with padding value */
  memcpy(iv_full, priv->iv_pad_val, TRANSOP_AES_IV_PADDING_SIZE);
  memcpy(iv_full + TRANSOP_AES_IV_PADDING_SIZE, iv_seed, TRANSOP_AES_IV_SEED_SIZE);

  /* Encrypt the IV with secret key to make it unpredictable.
   * As discussed in https://github.com/ntop/n2n/issues/72, it's important to
   * have an unpredictable IV since the initial part of the packet plaintext
   * can be easily reconstructed from plaintext headers and used by an attacker
   * to perform differential analysis.
   */
  uint8_t iv[16] = {0};
  (**priv->enc_ivec).run(priv->enc_ivec, iv, iv_full, AES_BLOCK_SIZE);
  memcpy (ivec, iv_full, AES_BLOCK_SIZE);

}

/* ****************************************************** */

/** The aes packet format consists of:
 *
 *  - a 8-bit aes encoding version in clear text
 *  - a TRANSOP_AES_IV_SEED_SIZE-sized [bytes] random IV seed
 *  - encrypted payload.
 *
 *  [V|II|DDDDDDDDDDDDDDDDDDDDD]
 *       |<---- encrypted ---->|
 */
static int transop_encode_aes(n2n_trans_op_t * arg,
			      uint8_t * outbuf,
			      size_t out_len,
			      const uint8_t * inbuf,
			      size_t in_len,
			      const uint8_t * peer_mac) {
  int len2=-1;
  transop_aes_t * priv = (transop_aes_t *)arg->priv;

  if(in_len <= N2N_PKT_BUF_SIZE) {
    if((in_len + TRANSOP_AES_PREAMBLE_SIZE) <= out_len) {
      int len=-1;
      size_t idx=0;
      uint8_t iv_seed[TRANSOP_AES_IV_SEED_SIZE];
      uint8_t padding = 0;
      n2n_aes_ivec_t enc_ivec = {0};

      traceEvent(TRACE_DEBUG, "encode_aes %lu", in_len);

      /* Encode the aes format version. */
      encode_uint8(outbuf, &idx, N2N_AES_TRANSFORM_VERSION);

      /* Generate and encode the IV seed using as many calls to rand() as neccessary.
       * Note: ( N2N_AES_IV_SEED_SIZE % sizeof(rand_value) ) not neccessarily equals 0. */
      uint32_t rand_value;
      int8_t i;
      for (i = TRANSOP_AES_IV_SEED_SIZE; i >= sizeof(rand_value); i -= sizeof(rand_value)) {
        rand_value = rand(); // CONCERN: rand() is not considered cryptographicly secure, REPLACE later
        memcpy(iv_seed + TRANSOP_AES_IV_SEED_SIZE - i, &rand_value, sizeof(rand_value));
      }
      /* Are there bytes left to fill? */
      if (i != 0) {
        rand_value = rand(); // CONCERN: rand() is not considered cryptographicly secure, REPLACE later
        memcpy(iv_seed, &rand_value, i);
      }
      encode_buf(outbuf, &idx, iv_seed, TRANSOP_AES_IV_SEED_SIZE);

      /* Encrypt the payload and write the ciphertext after the iv seed. */
      /* len is set to the length of the cipher plain text to be encrpyted
	 which is (in this case) identical to original packet lentgh */
      len = in_len;

      memcpy(outbuf + TRANSOP_AES_PREAMBLE_SIZE, inbuf, in_len);

      /* Need at least one encrypted byte at the end for the padding. */
      len2 = ((len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE; /* Round up to next whole AES adding at least one byte. */
      padding = (len2-len);
      outbuf[TRANSOP_AES_PREAMBLE_SIZE + len2 - 1] = padding;

      char iv_seed_hex[2 * N2N_AES_IVEC_SIZE + 1];
      traceEvent(TRACE_DEBUG, "padding = %u, seed = 0x%s", padding, to_hex (iv_seed, TRANSOP_AES_IV_SEED_SIZE, iv_seed_hex, 2 * N2N_AES_IVEC_SIZE + 1) );

      set_aes_cbc_iv(priv, enc_ivec, iv_seed);

      (**priv->enc).run(priv->enc, enc_ivec, outbuf + TRANSOP_AES_PREAMBLE_SIZE, len2);

      len2 += TRANSOP_AES_PREAMBLE_SIZE; /* size of data carried in UDP. */
    } else
      traceEvent(TRACE_ERROR, "encode_aes outbuf too small.");
  } else
    traceEvent(TRACE_ERROR, "encode_aes inbuf too big to encrypt.");

  return len2;
}

/* ****************************************************** */

/* See transop_encode_aes for packet format */
static int transop_decode_aes(n2n_trans_op_t * arg,
			      uint8_t * outbuf,
			      size_t out_len,
			      const uint8_t * inbuf,
			      size_t in_len,
			      const uint8_t * peer_mac) {
  int len=0;
  transop_aes_t * priv = (transop_aes_t *)arg->priv;
  if(((in_len - TRANSOP_AES_PREAMBLE_SIZE) <= out_len) /* Cipher text fits in outbuf */
     && (in_len >= TRANSOP_AES_PREAMBLE_SIZE) /* Has at least version, iv seed */
     )
    {
      size_t rem=in_len;
      size_t idx=0;
      uint8_t aes_enc_ver=0;
      uint8_t iv_seed[TRANSOP_AES_IV_SEED_SIZE];

      /* Get the encoding version to make sure it is supported */
      decode_uint8(&aes_enc_ver, inbuf, &rem, &idx );

      if(N2N_AES_TRANSFORM_VERSION == aes_enc_ver) {
	/* Get the IV seed */
	decode_buf((uint8_t *)&iv_seed, TRANSOP_AES_IV_SEED_SIZE, inbuf, &rem, &idx);

        char iv_seed_hex[2 * N2N_AES_IVEC_SIZE + 1];
        traceEvent(TRACE_DEBUG, "decode_aes %lu with seed 0x%s", in_len, to_hex (iv_seed, TRANSOP_AES_IV_SEED_SIZE, iv_seed_hex, 2 * N2N_AES_IVEC_SIZE + 1) );

	len = (in_len - TRANSOP_AES_PREAMBLE_SIZE);

	if(0 == (len % AES_BLOCK_SIZE)) {
	  uint8_t padding;
	  n2n_aes_ivec_t dec_ivec = {0};

	  set_aes_cbc_iv(priv, dec_ivec, iv_seed);

	  memcpy (outbuf, inbuf + TRANSOP_AES_PREAMBLE_SIZE, len);
          (**priv->dec).run(priv->dec, dec_ivec, outbuf, len);

	  /* last byte is how much was padding: max value should be
	   * AES_BLOCKSIZE-1 */
	  padding = outbuf[ len-1 ] & 0xff;

	  if(len >= padding) {
	    /* strictly speaking for this to be an ethernet packet
	     * it is going to need to be even bigger; but this is
	     * enough to prevent segfaults. */
	    traceEvent(TRACE_DEBUG, "padding = %u", padding);
	    len -= padding;
	  } else
	    traceEvent(TRACE_WARNING, "UDP payload decryption failed.");
	} else {
	  traceEvent(TRACE_WARNING, "Encrypted length %d is not a multiple of AES_BLOCK_SIZE (%d)", len, AES_BLOCK_SIZE);
	  len = 0;
	}
      } else
	traceEvent(TRACE_ERROR, "decode_aes unsupported aes version %u.", aes_enc_ver);
    } else
    traceEvent(TRACE_ERROR, "decode_aes inbuf wrong size (%ul) to decrypt.", in_len);

  return len;
}

/* ****************************************************** */

static int setup_aes_key(transop_aes_t *priv, const uint8_t *key, ssize_t key_size) {
  size_t aes_key_size_bytes;
  size_t aes_key_size_bits;

  uint8_t key_mat_buf[SHA512_DIGEST_LENGTH + SHA256_DIGEST_LENGTH];
  size_t key_mat_buf_length;

  /* Let the user choose the degree of encryption:
   * Long input keys will pick AES192 or AES256 with more robust but expensive encryption.
   *
   * The input key always gets hashed to make a more unpredictable use of the key space and
   * also to derive some additional material (key for IV encrpytion, IV padding).
   *
   * The following scheme for key setup was discussed on github:
   * https://github.com/ntop/n2n/issues/101
   */

  /* create a working buffer of maximal occuring hashes' size and generate
   * the hashes for the aes key material, key_mat_buf_lengh indicates the
   * actual "filling level" of that buffer
   */

  if(key_size >= 65) {
    aes_key_size_bytes = AES256_KEY_BYTES;
    hash_data (&br_sha512_vtable, key, key_size, key_mat_buf);
    key_mat_buf_length = SHA512_DIGEST_LENGTH;
  } else if(key_size >= 44) {
    aes_key_size_bytes = AES192_KEY_BYTES;
    hash_data (&br_sha384_vtable, key, key_size, key_mat_buf);
    /* append a hash of the first hash to create enough material for IV padding */
    hash_data (&br_sha256_vtable, key_mat_buf, SHA384_DIGEST_LENGTH, key_mat_buf + SHA384_DIGEST_LENGTH);
    key_mat_buf_length = SHA384_DIGEST_LENGTH + SHA256_DIGEST_LENGTH;
  } else {
    aes_key_size_bytes = AES128_KEY_BYTES;
    hash_data (&br_sha256_vtable, key, key_size, key_mat_buf);
    /* append a hash of the first hash to create enough material for IV padding */
    hash_data (&br_sha256_vtable, key_mat_buf, SHA256_DIGEST_LENGTH, key_mat_buf + SHA256_DIGEST_LENGTH);
    key_mat_buf_length = 2 * SHA256_DIGEST_LENGTH;
  }

  /* is there enough material available? */
  if(key_mat_buf_length < (aes_key_size_bytes + TRANSOP_AES_IV_KEY_BYTES + TRANSOP_AES_IV_PADDING_SIZE)) {
    /* this should never happen */
    traceEvent(TRACE_ERROR, "AES missing %u bits hashed key material\n",
	       (aes_key_size_bytes + TRANSOP_AES_IV_KEY_BYTES + TRANSOP_AES_IV_PADDING_SIZE - key_mat_buf_length) * 8);
    return(1);
  }

  /* setup of key, used for the CBC encryption */
  aes_key_size_bits = 8 * aes_key_size_bytes;

  (**priv->enc).init(priv->enc, key_mat_buf, aes_key_size_bytes);
  (**priv->dec).init(priv->dec, key_mat_buf, aes_key_size_bytes);

  /* setup of iv_enc_key (AES128 key) and iv_pad_val, used for generating the CBC IV */
  (**priv->enc_ivec).init(priv->enc_ivec, key_mat_buf + aes_key_size_bytes, TRANSOP_AES_IV_KEY_BYTES);
  memcpy(priv->iv_pad_val, key_mat_buf + aes_key_size_bytes + TRANSOP_AES_IV_KEY_BYTES, TRANSOP_AES_IV_PADDING_SIZE);

  traceEvent(TRACE_DEBUG, "AES %u bits setup completed\n",
	     aes_key_size_bits);

  return(0);
}

/* ****************************************************** */

static void transop_tick_aes(n2n_trans_op_t * arg, time_t now) { ; }

/* ****************************************************** */

/* AES initialization function */
int n2n_transop_aes_cbc_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {
  transop_aes_t *priv;
  const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
  size_t encrypt_key_len = strlen(conf->encrypt_key);

  memset(ttt, 0, sizeof(*ttt));
  ttt->transform_id = N2N_TRANSFORM_ID_AESCBC;

  ttt->tick = transop_tick_aes;
  ttt->deinit = transop_deinit_aes;
  ttt->fwd = transop_encode_aes;
  ttt->rev = transop_decode_aes;

  priv = (transop_aes_t*) calloc(1, sizeof(transop_aes_t));
  if(!priv) {
    traceEvent(TRACE_ERROR, "cannot allocate transop_aes_t memory");
    return(-1);
  }
  ttt->priv = priv;

  const br_block_cbcenc_class *vtable_enc;
  if ( (NULL == (vtable_enc =  br_aes_pwr8_cbcenc_get_vtable())) &&
       (NULL == (vtable_enc =  br_aes_x86ni_cbcenc_get_vtable())) )
                 vtable_enc = &br_aes_big_cbcenc_vtable;
  priv->enc = &priv->enc_ctx.vtable;
  vtable_enc->init(priv->enc, 0, 0);

  const br_block_cbcdec_class *vtable_dec;
  if ( (NULL == (vtable_dec =  br_aes_pwr8_cbcdec_get_vtable())) &&
       (NULL == (vtable_dec =  br_aes_x86ni_cbcdec_get_vtable())) )
               vtable_dec = &br_aes_big_cbcdec_vtable;
  priv->dec = &priv->dec_ctx.vtable;
  vtable_dec->init(priv->dec, 0, 0);

  const br_block_cbcenc_class *vtable_enc_ivec;
  if ( (NULL == (vtable_enc_ivec =  br_aes_pwr8_cbcenc_get_vtable())) &&
       (NULL == (vtable_enc_ivec =  br_aes_x86ni_cbcenc_get_vtable())) )
               vtable_enc_ivec = &br_aes_big_cbcenc_vtable;
  priv->enc_ivec = &priv->enc_ivec_ctx.vtable;
  vtable_enc_ivec->init(priv->enc_ivec, 0, 0);

  /* Setup the cipher and key */
  return(setup_aes_key(priv, encrypt_key, encrypt_key_len));
}

#endif /* N2N_HAVE_AES */
