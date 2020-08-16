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


typedef struct transop_tf {
  TWOFISH*           enc_tf; /* tx state */
  TWOFISH*           dec_tf; /* rx state */
} transop_tf_t;

static int transop_deinit_twofish( n2n_trans_op_t * arg ) {
  transop_tf_t *priv = (transop_tf_t *)arg->priv;

  if(priv) {
    TwoFishDestroy(priv->enc_tf); /* deallocate TWOFISH */
    TwoFishDestroy(priv->dec_tf); /* deallocate TWOFISH */
    free(priv);
  }

  return 0;
}

#define TRANSOP_TF_NONCE_SIZE   4

/** The twofish packet format consists of:
 *
 *  - ciphertext encrypted from a 32-bit nonce followed by the payload.
 *
 *  [nnnnDDDDDDDDDDDDDDDDDDDDD]
 *  |<------ encrypted ------>|
 */
static int transop_encode_twofish( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len,
				   const uint8_t * peer_mac)
{
  int len=-1;
  transop_tf_t * priv = (transop_tf_t *)arg->priv;
  uint8_t assembly[N2N_PKT_BUF_SIZE];
  uint32_t * pnonce;

  if ( (in_len + TRANSOP_TF_NONCE_SIZE) <= N2N_PKT_BUF_SIZE )
    {
      if ( (in_len + TRANSOP_TF_NONCE_SIZE) <= out_len )
        {
	  traceEvent(TRACE_DEBUG, "encode_twofish %lu", in_len);

	  /* The assembly buffer is a source for encrypting data. The nonce is
	   * written in first followed by the packet payload. The whole
	   * contents of assembly are encrypted. */
	  pnonce = (uint32_t *)assembly;
	  *pnonce = n2n_rand();
	  memcpy( assembly + TRANSOP_TF_NONCE_SIZE, inbuf, in_len );

	  /* Encrypt the assembly contents and write the ciphertext after the SA. */
	  len = TwoFishEncryptRaw( assembly, /* source */
				   outbuf,
				   in_len + TRANSOP_TF_NONCE_SIZE, /* enc size */
				   priv->enc_tf);
	  if ( len <= 0 )
            {
	      traceEvent( TRACE_ERROR, "encode_twofish encryption failed." );
            }

        }
      else
        {
	  traceEvent( TRACE_ERROR, "encode_twofish outbuf too small." );
        }
    }
  else
    {
      traceEvent( TRACE_ERROR, "encode_twofish inbuf too big to encrypt." );
    }

  return len;
}


static int transop_decode_twofish( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len,
				   const uint8_t * peer_mac)
{
  int len=0;
  transop_tf_t * priv = (transop_tf_t *)arg->priv;
  uint8_t assembly[N2N_PKT_BUF_SIZE];

  if ( ( in_len <= N2N_PKT_BUF_SIZE ) /* Cipher text fits in assembly */
       && (in_len >= TRANSOP_TF_NONCE_SIZE ) /* Has at least nonce */
       ) {

	  traceEvent(TRACE_DEBUG, "decode_twofish %lu", in_len);

	  len = TwoFishDecryptRaw( (void *)inbuf,
				     assembly, /* destination */
				     in_len,
				     priv->dec_tf);

	  if(len > 0) {
	    /* Step over 4-byte random nonce value */
	    len -= TRANSOP_TF_NONCE_SIZE; /* size of ethernet packet */

	    memcpy( outbuf, 
		    assembly + TRANSOP_TF_NONCE_SIZE, 
		    len );
	  } else
	    traceEvent(TRACE_ERROR, "decode_twofish decryption failed");
  } else
    traceEvent( TRACE_ERROR, "decode_twofish inbuf wrong size (%ul) to decrypt.", in_len );

  return len;
}

static void transop_tick_twofish( n2n_trans_op_t * arg, time_t now ) {}

/* Twofish initialization function */
int n2n_transop_twofish_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {
  transop_tf_t *priv;
  const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
  size_t encrypt_key_len = strlen(conf->encrypt_key);
  uint8_t key_hash[32];

  memset(ttt, 0, sizeof(*ttt));
  ttt->transform_id = N2N_TRANSFORM_ID_TWOFISH;

  ttt->tick = transop_tick_twofish;
  ttt->deinit = transop_deinit_twofish;
  ttt->fwd = transop_encode_twofish;
  ttt->rev = transop_decode_twofish;

  priv = (transop_tf_t*) calloc(1, sizeof(transop_tf_t));
  if(!priv) {
    traceEvent(TRACE_ERROR, "cannot allocate transop_tf_t memory");
    return(-1);
  }
  ttt->priv = priv;

  /* This is a preshared key setup. Both Tx and Rx are using the same security association. */
  pearson_hash_256 (key_hash, encrypt_key, encrypt_key_len);
  priv->enc_tf = TwoFishInit(key_hash);
  priv->dec_tf = TwoFishInit(key_hash);

  if((!priv->enc_tf) || (!priv->dec_tf)) {
    if(priv->enc_tf) TwoFishDestroy(priv->enc_tf);
    if(priv->dec_tf) TwoFishDestroy(priv->dec_tf);
    free(priv);
    traceEvent(TRACE_ERROR, "TwoFishInit failed");
    return(-2);
  }

  return(0);
}
