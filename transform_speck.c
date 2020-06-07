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
#include "speck.h"

#define N2N_SPECK_TRANSFORM_VERSION       1  /* version of the transform encoding */
#define N2N_SPECK_IVEC_SIZE               16

#define SPECK_KEY_BYTES (256/8)

/* Speck plaintext preamble */
#define TRANSOP_SPECK_VER_SIZE     1       /* Support minor variants in encoding in one module. */
#define TRANSOP_SPECK_PREAMBLE_SIZE (TRANSOP_SPECK_VER_SIZE + N2N_SPECK_IVEC_SIZE)

typedef unsigned char n2n_speck_ivec_t[N2N_SPECK_IVEC_SIZE];

typedef struct transop_speck {
  speck_context_t      ctx;	      /* the round keys for payload encryption & decryption */
} transop_speck_t;

/* ****************************************************** */

static int transop_deinit_speck(n2n_trans_op_t *arg) {
  transop_speck_t *priv = (transop_speck_t *)arg->priv;

  if(priv)
#if defined (SPECK_ALIGNED_CTX)
    _mm_free (priv);
#else
    free (priv);
#endif
  return 0;
}

/* ****************************************************** */

static void set_speck_iv(transop_speck_t *priv, n2n_speck_ivec_t ivec) {
  // keep in mind the following condition: N2N_SPECK_IVEC_SIZE % sizeof(rand_value) == 0 !
  uint32_t rand_value;
  for (uint8_t i = 0; i < N2N_SPECK_IVEC_SIZE; i += sizeof(rand_value)) {
    rand_value = rand(); // CONCERN: rand() is not considered cryptographicly secure, REPLACE later
    memcpy(ivec + i, &rand_value, sizeof(rand_value));
  }
}

/* ****************************************************** */

/** The Speck packet format consists of:
 *
 *  - a 8-bit speck encoding version in clear text
 *  - a 128-bit random IV
 *  - encrypted payload.
 *
 *  [V|IIII|DDDDDDDDDDDDDDDDDDDDD]
 *         |<---- encrypted ---->|
 */
static int transop_encode_speck(n2n_trans_op_t * arg,
			       uint8_t * outbuf,
			       size_t out_len,
			       const uint8_t * inbuf,
			       size_t in_len,
			       const uint8_t * peer_mac) {
  int len=-1;
  transop_speck_t * priv = (transop_speck_t *)arg->priv;

  if(in_len <= N2N_PKT_BUF_SIZE) {
    if((in_len + TRANSOP_SPECK_PREAMBLE_SIZE) <= out_len) {
      size_t idx=0;
      n2n_speck_ivec_t enc_ivec = {0};

      traceEvent(TRACE_DEBUG, "encode_speck %lu bytes", in_len);

      /* Encode the Speck format version. */
      encode_uint8(outbuf, &idx, N2N_SPECK_TRANSFORM_VERSION);

      /* Generate and encode the IV. */
      set_speck_iv(priv, enc_ivec);
      encode_buf(outbuf, &idx, &enc_ivec, N2N_SPECK_IVEC_SIZE);

      /* Encrypt the payload and write the ciphertext after the iv. */
      /* len is set to the length of the cipher plain text to be encrpyted
	 which is (in this case) identical to original packet lentgh */
      len = in_len;

      speck_ctr (outbuf + TRANSOP_SPECK_PREAMBLE_SIZE, inbuf, in_len, enc_ivec,
#if defined (SPECK_CTX_BYVAL)
	         (priv->ctx));
#else
	         &(priv->ctx));
#endif
      traceEvent(TRACE_DEBUG, "encode_speck: encrypted %u bytes.\n", in_len);

      len += TRANSOP_SPECK_PREAMBLE_SIZE; /* size of data carried in UDP. */
    } else
      traceEvent(TRACE_ERROR, "encode_speck outbuf too small.");
  } else
    traceEvent(TRACE_ERROR, "encode_speck inbuf too big to encrypt.");

  return len;
}

/* ****************************************************** */

/* See transop_encode_speck for packet format */
static int transop_decode_speck(n2n_trans_op_t * arg,
			       uint8_t * outbuf,
			       size_t out_len,
			       const uint8_t * inbuf,
			       size_t in_len,
			       const uint8_t * peer_mac) {
  int len=0;
  transop_speck_t * priv = (transop_speck_t *)arg->priv;

  if(((in_len - TRANSOP_SPECK_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* Cipher text fits in buffer */
     && (in_len >= TRANSOP_SPECK_PREAMBLE_SIZE) /* Has at least version, iv */
  )
  {
    size_t rem=in_len;
    size_t idx=0;
    uint8_t speck_enc_ver=0;
    n2n_speck_ivec_t dec_ivec = {0};

    /* Get the encoding version to make sure it is supported */
    decode_uint8(&speck_enc_ver, inbuf, &rem, &idx );

    if(N2N_SPECK_TRANSFORM_VERSION == speck_enc_ver) {
      traceEvent(TRACE_DEBUG, "decode_speck %lu bytes", in_len);
      len = (in_len - TRANSOP_SPECK_PREAMBLE_SIZE);

      /* Get the IV */
      decode_buf((uint8_t *)&dec_ivec, N2N_SPECK_IVEC_SIZE, inbuf, &rem, &idx);

      speck_ctr (outbuf, inbuf + TRANSOP_SPECK_PREAMBLE_SIZE, len, dec_ivec,
#if defined (SPECK_CTX_BYVAL)
		 (priv->ctx));
#else
		 &(priv->ctx));
#endif
      traceEvent(TRACE_DEBUG, "decode_speck: decrypted %u bytes.\n", len);

    } else
      traceEvent(TRACE_ERROR, "decode_speck unsupported Speck version %u.", speck_enc_ver);
  } else
  traceEvent(TRACE_ERROR, "decode_speck inbuf wrong size (%ul) to decrypt.", in_len);

  return len;
}

/* ****************************************************** */

static int setup_speck_key(transop_speck_t *priv, const uint8_t *key, ssize_t key_size) {

  uint8_t key_mat_buf[32] = { 0x00 };

  /* Clear out any old possibly longer key matter. */
  memset(&(priv->ctx), 0, sizeof(speck_context_t) );

  /* TODO: The input key always gets hashed to make a more unpredictable and more complete use of the key space */
  // REVISIT: Hash the key to keymat (formerly used: SHA)
  //   SHA256(key, key_size, key_mat_buf)
  //   memcpy (priv->key, key_mat_buf, SHA256_DIGEST_LENGTH);
  // ADD: Pearson Hashing
  // FOR NOW: USE KEY ITSELF
  memcpy (key_mat_buf, key, ((key_size>32)?32:key_size) );
  speck_expand_key (key_mat_buf, &(priv->ctx));

  traceEvent(TRACE_DEBUG, "Speck key setup completed\n");

  return(0);
}

/* ****************************************************** */

static void transop_tick_speck(n2n_trans_op_t * arg, time_t now) { ; }

/* ****************************************************** */
/* Speck initialization function */
int n2n_transop_speck_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {
  transop_speck_t *priv;
  const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
  size_t encrypt_key_len = strlen(conf->encrypt_key);

  memset(ttt, 0, sizeof(*ttt));
  ttt->transform_id = N2N_TRANSFORM_ID_SPECK;

  ttt->tick = transop_tick_speck;
  ttt->deinit = transop_deinit_speck;
  ttt->fwd = transop_encode_speck;
  ttt->rev = transop_decode_speck;
#if defined (SPECK_ALIGNED_CTX)
  priv = (transop_speck_t*) _mm_malloc (sizeof(transop_speck_t), SPECK_ALIGNED_CTX);
#else
  priv = (transop_speck_t*) calloc (1, sizeof(transop_speck_t));
#endif
  if(!priv) {
    traceEvent(TRACE_ERROR, "cannot allocate transop_speck_t memory");
    return(-1);
  }
  ttt->priv = priv;

  /* Setup the cipher and key */
  return(setup_speck_key(priv, encrypt_key, encrypt_key_len));
}

