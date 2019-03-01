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
#ifndef _MSC_VER
/* Not included in Visual Studio 2008 */
#include <strings.h> /* index() */
#endif

#define N2N_TWOFISH_NUM_SA              32 /* space for SAa */

#define N2N_TWOFISH_TRANSFORM_VERSION   1  /* version of the transform encoding */

struct sa_twofish
{
  n2n_cipherspec_t    spec;   /* cipher spec parameters */
  n2n_sa_t            sa_id;  /* security association index */
  TWOFISH *           enc_tf; /* tx state */
  TWOFISH *           dec_tf; /* rx state */
};

typedef struct sa_twofish sa_twofish_t;


/** Twofish transform state data.
 *
 *  With a key-schedule in place this will be populated with a number of
 *  SAs. Each SA has a lifetime and some opque data. The opaque data for twofish
 *  consists of the SA number and key material.
 *
 */
struct transop_tf
{
  ssize_t             tx_sa;
  size_t              num_sa;
  sa_twofish_t        sa[N2N_TWOFISH_NUM_SA];
};

typedef struct transop_tf transop_tf_t;

static int transop_deinit_twofish( n2n_trans_op_t * arg )
{
  transop_tf_t * priv = (transop_tf_t *)arg->priv;
  size_t i;

  if ( priv )
    {
      /* Memory was previously allocated */
      for (i=0; i<N2N_TWOFISH_NUM_SA; ++i )
        {
	  sa_twofish_t * sa = &(priv->sa[i]);

	  TwoFishDestroy(sa->enc_tf); /* deallocate TWOFISH */
	  sa->enc_tf=NULL;

	  TwoFishDestroy(sa->dec_tf); /* deallocate TWOFISH */
	  sa->dec_tf=NULL;

	  sa->sa_id=0;
        }
    
      priv->num_sa=0;
      priv->tx_sa=-1;

      free(priv);
    }

  arg->priv=NULL; /* return to fully uninitialised state */

  return 0;
}

static size_t tf_choose_tx_sa( transop_tf_t * priv )
{
  return priv->tx_sa; /* set in tick */
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
	  sa_twofish_t * sa;
	  size_t tx_sa_num = 0;

	  /* The transmit sa is periodically updated */
	  tx_sa_num = tf_choose_tx_sa( priv );

	  sa = &(priv->sa[tx_sa_num]); /* Proper Tx SA index */
        
	  traceEvent( TRACE_DEBUG, "encode_twofish %lu with SA %lu.", in_len, sa->sa_id );
            
	  /* Encode the twofish format version. */
	  encode_uint8( outbuf, &idx, N2N_TWOFISH_TRANSFORM_VERSION );

	  /* Encode the security association (SA) number */
	  encode_uint32( outbuf, &idx, sa->sa_id );

	  /* The assembly buffer is a source for encrypting data. The nonce is
	   * written in first followed by the packet payload. The whole
	   * contents of assembly are encrypted. */
	  pnonce = (uint32_t *)assembly;
	  *pnonce = rand();
	  memcpy( assembly + TRANSOP_TF_NONCE_SIZE, inbuf, in_len );

	  /* Encrypt the assembly contents and write the ciphertext after the SA. */
	  len = TwoFishEncryptRaw( assembly, /* source */
				   outbuf + TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE, 
				   in_len + TRANSOP_TF_NONCE_SIZE, /* enc size */
				   sa->enc_tf);
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


/* Search through the array of SAs to find the one with the required ID.
 *
 * @return array index where found or -1 if not found
 */
static ssize_t twofish_find_sa( const transop_tf_t * priv, const n2n_sa_t req_id )
{
  size_t i;
    
  for (i=0; i < priv->num_sa; ++i)
    {
      const sa_twofish_t * sa=NULL;

      sa = &(priv->sa[i]);
      if (req_id == sa->sa_id)
        {
	  return i;
        }
    }

  return -1;
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
       )
    {
      n2n_sa_t sa_rx;
      ssize_t sa_idx=-1;
      size_t rem=in_len;
      size_t idx=0;
      uint8_t tf_enc_ver=0;

      /* Get the encoding version to make sure it is supported */
      decode_uint8( &tf_enc_ver, inbuf, &rem, &idx );

      if ( N2N_TWOFISH_TRANSFORM_VERSION == tf_enc_ver )
        {
	  /* Get the SA number and make sure we are decrypting with the right one. */
	  decode_uint32( &sa_rx, inbuf, &rem, &idx );

	  sa_idx = twofish_find_sa(priv, sa_rx);
	  if ( sa_idx >= 0 )
            {
	      sa_twofish_t * sa = &(priv->sa[sa_idx]);

	      traceEvent( TRACE_DEBUG, "decode_twofish %lu with SA %lu.", in_len, sa_rx, sa->sa_id );

	      len = TwoFishDecryptRaw( (void *)(inbuf + TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE),
				       assembly, /* destination */
				       (in_len - (TRANSOP_TF_VER_SIZE + TRANSOP_TF_SA_SIZE)), 
				       sa->dec_tf);

	      if ( len > 0 )
                {
		  /* Step over 4-byte random nonce value */
		  len -= TRANSOP_TF_NONCE_SIZE; /* size of ethernet packet */

		  memcpy( outbuf, 
			  assembly + TRANSOP_TF_NONCE_SIZE, 
			  len );
                }
	      else
                {
		  traceEvent( TRACE_ERROR, "decode_twofish decryption failed." );
                }

            }
	  else
            {
	      /* Wrong security association; drop the packet as it is undecodable. */
	      traceEvent( TRACE_ERROR, "decode_twofish SA number %lu not found.", sa_rx );

	      /* REVISIT: should be able to load a new SA at this point to complete the decoding. */
            }
        }
      else
        {
	  /* Wrong security association; drop the packet as it is undecodable. */
	  traceEvent( TRACE_ERROR, "decode_twofish unsupported twofish version %u.", tf_enc_ver );

	  /* REVISIT: should be able to load a new SA at this point to complete the decoding. */
        }        
    }
  else
    {
      traceEvent( TRACE_ERROR, "decode_twofish inbuf wrong size (%ul) to decrypt.", in_len );
    }

  return len;
}

static int transop_addspec_twofish( n2n_trans_op_t * arg, const n2n_cipherspec_t * cspec )
{
  int retval = 1;
  ssize_t pstat=-1;
  transop_tf_t * priv = (transop_tf_t *)arg->priv;
  uint8_t keybuf[N2N_MAX_KEYSIZE];

  if ( priv->num_sa < N2N_TWOFISH_NUM_SA )
    {
      const char * op = (const char *)cspec->opaque;
#ifdef __ANDROID_NDK__
      const char *sep = strchr(op, '_');
#else
      const char * sep = index( op, '_' );
#endif // __ANDROID_NDK__

      if ( sep )
        {
	  char tmp[256];
	  size_t s;
            
	  s = sep - op;
	  memcpy( tmp, cspec->opaque, s );
	  tmp[s]=0;
            
	  s = strlen(sep+1); /* sep is the _ which might be immediately followed by NULL */

	  priv->sa[priv->num_sa].spec = *cspec;
	  priv->sa[priv->num_sa].sa_id = strtoul(tmp, NULL, 10);

	  pstat = n2n_parse_hex( keybuf, N2N_MAX_KEYSIZE, sep+1, s );
	  if ( pstat > 0 )
            {
	      priv->sa[priv->num_sa].enc_tf = TwoFishInit( keybuf, pstat);
	      priv->sa[priv->num_sa].dec_tf = TwoFishInit( keybuf, pstat);
                
	      traceEvent( TRACE_DEBUG, "transop_addspec_twofish sa_id=%u data=%s.\n",
			  priv->sa[priv->num_sa].sa_id, sep+1);
                
	      ++(priv->num_sa);
	      retval = 0;
            }
        }
      else
        {
	  traceEvent( TRACE_ERROR, "transop_addspec_twofish : bad key data - missing '_'.\n");
        }
    }
  else
    {
      traceEvent( TRACE_ERROR, "transop_addspec_twofish : full.\n");
    }
    
  return retval;
}


static n2n_tostat_t transop_tick_twofish( n2n_trans_op_t * arg, time_t now )
{
  transop_tf_t * priv = (transop_tf_t *)arg->priv;
  size_t i;
  int found=0;
  n2n_tostat_t r;

  memset( &r, 0, sizeof(r) );

  traceEvent( TRACE_DEBUG, "transop_tf tick num_sa=%u", priv->num_sa );

  for ( i=0; i < priv->num_sa; ++i )
    {
      if ( 0 == validCipherSpec( &(priv->sa[i].spec), now ) )
        {
	  time_t remaining = priv->sa[i].spec.valid_until - now;

	  traceEvent( TRACE_INFO, "transop_tf choosing tx_sa=%u (valid for %lu sec)", priv->sa[i].sa_id, remaining );
	  priv->tx_sa=i;
	  found=1;
	  break;
        }
      else
        {
	  traceEvent( TRACE_DEBUG, "transop_tf tick rejecting sa=%u  %lu -> %lu", 
		      priv->sa[i].sa_id, priv->sa[i].spec.valid_from, priv->sa[i].spec.valid_until );
        }
    }

  if ( 0==found)
    {
      traceEvent( TRACE_INFO, "transop_tf no keys are currently valid. Keeping tx_sa=%u", priv->tx_sa );
    }
  else
    {
      r.can_tx = 1;
      r.tx_spec.t = N2N_TRANSFORM_ID_TWOFISH;
      r.tx_spec = priv->sa[priv->tx_sa].spec;
    }

  return r;
}

int transop_twofish_setup_psk( n2n_trans_op_t * ttt, 
                           n2n_sa_t sa_num,
                           uint8_t * encrypt_pwd, 
                           uint32_t encrypt_pwd_len )
{
  int retval = 1;
  transop_tf_t * priv = (transop_tf_t *)ttt->priv;

  if(priv) {
    sa_twofish_t *sa;

    priv->num_sa=1;         /* There is one SA in the array. */
    priv->tx_sa=0;
    sa = &(priv->sa[priv->tx_sa]);
    sa->sa_id=sa_num;
    sa->spec.valid_until = 0x7fffffff;

    /* This is a preshared key setup. Both Tx and Rx are using the same security association. */

    sa->enc_tf = TwoFishInit(encrypt_pwd, encrypt_pwd_len);
    sa->dec_tf = TwoFishInit(encrypt_pwd, encrypt_pwd_len);

    if ( (sa->enc_tf) && (sa->dec_tf) )
      retval = 0;
    else
      traceEvent( TRACE_ERROR, "transop_twofish_setup_psk" );
  } else
    traceEvent( TRACE_ERROR, "twofish priv is not allocated" );

  return retval;
}

int transop_twofish_init( n2n_trans_op_t * ttt )
{
  int retval = 1;
  transop_tf_t * priv = NULL;

  if ( ttt->priv )
    {
      transop_deinit_twofish( ttt );
    }

  memset( ttt, 0, sizeof( n2n_trans_op_t ) );

  priv = (transop_tf_t *) malloc( sizeof(transop_tf_t) );

  if ( NULL != priv ) {
      size_t i;
      sa_twofish_t * sa=NULL;

      /* install the private structure. */
      ttt->priv = priv;
      priv->num_sa=0;
      priv->tx_sa=0; /* We will use this sa index for encoding. */

      ttt->transform_id = N2N_TRANSFORM_ID_TWOFISH;
      ttt->addspec = transop_addspec_twofish;
      ttt->tick = transop_tick_twofish; /* chooses a new tx_sa */
      ttt->deinit = transop_deinit_twofish;
      ttt->fwd = transop_encode_twofish;
      ttt->rev = transop_decode_twofish;

      for(i=0; i<N2N_TWOFISH_NUM_SA; ++i)
        {
	  sa = &(priv->sa[i]);
	  sa->sa_id=0;
	  memset( &(sa->spec), 0, sizeof(n2n_cipherspec_t) );
	  sa->enc_tf=NULL;
	  sa->dec_tf=NULL;
        }

      retval = 0;
    } else {
      memset( ttt, 0, sizeof(n2n_trans_op_t) );
      traceEvent( TRACE_ERROR, "Failed to allocate priv for twofish" );
    }

  return retval;
}
