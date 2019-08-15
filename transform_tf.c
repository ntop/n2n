/**
 * (C) 2007-18 - ntop.org and contributors
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
#include "twofish.h"
#include "random_numbers.h"
#ifndef _MSC_VER
/* Not included in Visual Studio 2008 */
#include <strings.h> /* index() */
#endif

#define N2N_TWOFISH_NUM_SA              32 /* space for SAa */

#define N2N_TWOFISH_TRANSFORM_VERSION   1  /* version of the transform encoding */

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

#define TRANSOP_TF_VER_SIZE     1       /* Support minor variants in encoding in one module. */
#define TRANSOP_TF_NONCE_SIZE   4
#define TRANSOP_TF_SA_SIZE      4

/** The twofish packet format consists of:
 *
 *  - a 8-bit twofish encoding version in clear text
 *  - a 32-bit SA number in clear text
 *  - ciphertext encrypted from a 32-bit nonce followed by the payload.
 *
 *  [V|SSSS|nnnnDDDDDDDDDDDDDDDDDDDDD]
 *         |<------ encrypted ------>|
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
      if ( (in_len + TRANSOP_TF_NONCE_SIZE + TRANSOP_TF_SA_SIZE + TRANSOP_TF_VER_SIZE) <= out_len )
        {
	  size_t idx=0;
	  uint32_t sa_id=0; // Not used

	  traceEvent(TRACE_DEBUG, "encode_twofish %lu", in_len);
            
	  /* Encode the twofish format version. */
	  encode_uint8( outbuf, &idx, N2N_TWOFISH_TRANSFORM_VERSION );

	  /* Encode the security association (SA) number */
	  encode_uint32( outbuf, &idx, sa_id );

	  /* The assembly buffer is a source for encrypting data. The nonce is
	   * written in first followed by the packet payload. The whole
	   * contents of assembly are encrypted. */
	  pnonce = (uint32_t *)assembly;
	  *pnonce = n2n_rand();
	  memcpy( assembly + TRANSOP_TF_NONCE_SIZE, inbuf, in_len );

	  /* Encrypt the assembly contents and write the ciphertext after the SA. */
	  len = TwoFishEncryptRaw( assembly, /* source */
				   outbuf + TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE, 
				   in_len + TRANSOP_TF_NONCE_SIZE, /* enc size */
				   priv->enc_tf);
	  if ( len > 0 )
            {
	      len += TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE; /* size of data carried in UDP. */
            }
	  else
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

/** The twofish packet format consists of:
 *
 *  - a 8-bit twofish encoding version in clear text
 *  - a 32-bit SA number in clear text
 *  - ciphertext encrypted from a 32-bit nonce followed by the payload.
 *
 *  [V|SSSS|nnnnDDDDDDDDDDDDDDDDDDDDD]
 *         |<------ encrypted ------>|
 */
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

  if ( ( (in_len - (TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE)) <= N2N_PKT_BUF_SIZE ) /* Cipher text fits in assembly */ 
       && (in_len >= (TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE + TRANSOP_TF_NONCE_SIZE) ) /* Has at least version, SA and nonce */
       ) {
      size_t rem=in_len;
      size_t idx=0;
      uint8_t tf_enc_ver=0;
      uint32_t sa_rx=0; // Not used

      /* Get the encoding version to make sure it is supported */
      decode_uint8( &tf_enc_ver, inbuf, &rem, &idx );

      if ( N2N_TWOFISH_TRANSFORM_VERSION == tf_enc_ver ) {
	  /* Get the SA number and make sure we are decrypting with the right one. */
	  decode_uint32( &sa_rx, inbuf, &rem, &idx );

	  traceEvent(TRACE_DEBUG, "decode_twofish %lu", in_len);

	  len = TwoFishDecryptRaw( (void *)(inbuf + TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE),
				     assembly, /* destination */
				     (in_len - (TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE)), 
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
	traceEvent( TRACE_ERROR, "decode_twofish unsupported twofish version %u.", tf_enc_ver );   
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
  priv->enc_tf = TwoFishInit(encrypt_key, encrypt_key_len);
  priv->dec_tf = TwoFishInit(encrypt_key, encrypt_key_len);

  if((!priv->enc_tf) || (!priv->dec_tf)) {
    if(priv->enc_tf) TwoFishDestroy(priv->enc_tf);
    if(priv->dec_tf) TwoFishDestroy(priv->dec_tf);
    free(priv);
    traceEvent(TRACE_ERROR, "TwoFishInit failed");
    return(-2);
  }

  return(0);
}
