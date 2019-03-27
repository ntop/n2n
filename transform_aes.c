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

#if defined(N2N_HAVE_AES)

#include "openssl/aes.h"
#include "openssl/sha.h"
#ifndef _MSC_VER
/* Not included in Visual Studio 2008 */
#include <strings.h> /* index() */
#endif

#define N2N_AES_NUM_SA                  32 /* space for SAa */

#define N2N_AES_TRANSFORM_VERSION_MAX   2  /* maximum version of the transform encoding */
#define N2N_AES_TRANSFORM_VERSION_MIN   1  /* minimum version of the transform encoding */
#define N2N_AES_IVEC_SIZE               16 /* Enough space for biggest AES ivec */
#define N2N_AES_MSGAUTH_SIZE		16 /* size of the message authentication code length, from 0 ... 16 = AES_BLOCK_SIZE */

#define N2N_MAX_PACKET_DELAY		16000000 /* the maximum allowable time stamp difference time in microseconds = 16 sec */
#define N2N_MAX_PACKET_DEVIATION_TIME	160000 /* the maximum allowable time stamp difference [usec] a packet may be earlier than another = 160 ms*/

typedef unsigned char n2n_aes_ivec_t[N2N_AES_IVEC_SIZE];

struct sa_aes
{
    n2n_cipherspec_t    spec;           /* cipher spec parameters */
    n2n_sa_t            sa_id;          /* security association index */
    AES_KEY             enc_key_K;      /* v1: tx key */
    AES_KEY             dec_key_K;      /* v1: tx key */
    AES_KEY		enc_key_K1;	/* v2: primary key for encryption */
    AES_KEY		dec_key_K1;	/* v2: primary key for decryption */
    AES_KEY		enc_key_K2;	/* v2: secondary key for IV encryption and msg auth signing */
    AES_KEY		dec_key_K2;	/* v2: secondary key for IV decryption and msg auth signature check */
    uint64_t		prev_time_stamp;/* time stamp [usec] of previous packet sent from the associated node */
};

typedef struct sa_aes sa_aes_t;


/** Aes transform state data.
 *
 *  With a key-schedule in place this will be populated with a number of
 *  SAs. Each SA has a lifetime and some opque data. The opaque data for aes
 *  consists of the SA number and key material.
 *
 */
struct transop_aes
{
    ssize_t             tx_sa;
    size_t              num_sa;
    sa_aes_t            sa[N2N_AES_NUM_SA];
    int			version; /* indicates the encryption scheme version */

    /* PSK mode only */
    int                 psk_mode;
    u_int8_t            mac_sa[N2N_AES_NUM_SA][N2N_MAC_SIZE]; /* this is used as a key in the sa array */
    uint8_t             *encrypt_pwd;
    uint32_t            encrypt_pwd_len;
    size_t              sa_to_replace;
};

typedef struct transop_aes transop_aes_t;

static ssize_t aes_find_sa( const transop_aes_t * priv, const n2n_sa_t req_id );
static int setup_aes_key(transop_aes_t *priv, uint8_t *keybuf, ssize_t pstat, size_t sa_num);


/* Helper function to xor destination and source memory to destination.
   Taken from gnutls which is under GPL 3.0.
   Written by Simon Josefsson.  The interface was inspired by memxor
   in Niels Möller's Nettle. */
void *
memxor (void *restrict dest, const void *restrict src, size_t n)
{
  char const *s = src;
  char *d = dest;

  for (; n > 0; n--)
    *d++ ^= *s++;

  return dest;
}

static int transop_deinit_aes( n2n_trans_op_t * arg )
{
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    size_t i;

    if ( priv )
    {
        /* Memory was previously allocated */
        for (i=0; i<N2N_AES_NUM_SA; ++i )
        {
            sa_aes_t * sa = &(priv->sa[i]);

            sa->sa_id=0;
        }
    
        priv->num_sa=0;
        priv->tx_sa=-1;

        free(priv);
    }

    arg->priv=NULL; /* return to fully uninitialised state */

    return 0;
}

/* Find the peer_mac sa */
static size_t aes_psk_get_peer_sa(transop_aes_t * priv, const u_int8_t * peer_mac) {
    size_t i;
    int found = 0;

    /* Find the MAC sa */
    for(i=0; i<priv->num_sa; i++) {
        if(!memcmp(priv->mac_sa[i], peer_mac, N2N_MAC_SIZE)) {
            found = 1;
            break;
        }
    }

    if(found)
        return(i);

    size_t new_sa = priv->sa_to_replace;
    macstr_t mac_buf;
    macaddr_str(mac_buf, peer_mac);
    traceEvent(TRACE_DEBUG, "Assigning SA %u to %s", new_sa, mac_buf);

    setup_aes_key(priv, priv->encrypt_pwd, priv->encrypt_pwd_len, new_sa);
    priv->num_sa = max(priv->num_sa, new_sa + 1);
    memcpy(priv->mac_sa[new_sa], peer_mac, N2N_MAC_SIZE);
    priv->sa[new_sa].sa_id = new_sa;

    /* Use sa_to_replace round-robin */
    priv->sa_to_replace = (priv->sa_to_replace + 1) % N2N_AES_NUM_SA;

    return new_sa;
}

static size_t aes_choose_tx_sa( transop_aes_t * priv, const u_int8_t * peer_mac ) {
    if(!priv->psk_mode)
        return priv->tx_sa; /* set in tick */
    else
        return aes_psk_get_peer_sa(priv, peer_mac);
}

static ssize_t aes_choose_rx_sa( transop_aes_t * priv, const u_int8_t * peer_mac, ssize_t sa_rx) {
    if(!priv->psk_mode)
        return aes_find_sa(priv, sa_rx);
    else
        /* NOTE the sa_rx of the packet is ignored in this case */
        return aes_psk_get_peer_sa(priv, peer_mac);
}

#define TRANSOP_AES_VER_SIZE     1       /* Support minor variants in encoding in one module. */
#define TRANSOP_AES_NONCE_SIZE   4
#define TRANSOP_AES_DATA_LEN     2
#define TRANSOP_AES_SA_SIZE      4

#define AES256_KEY_BYTES (256/8)
#define AES192_KEY_BYTES (192/8)
#define AES128_KEY_BYTES (128/8)

/* Return the best acceptable AES key size (in bytes) given an input keysize. 
 *
 * The value returned will be one of AES128_KEY_BYTES, AES192_KEY_BYTES or
 * AES256_KEY_BYTES.
 */
static size_t aes_best_keysize(size_t numBytes)
{
    if (numBytes >= AES256_KEY_BYTES)
    {
        return AES256_KEY_BYTES;
    }
    else if (numBytes >= AES192_KEY_BYTES)
    {
        return AES192_KEY_BYTES;
    }
    else
    {
        return AES128_KEY_BYTES;
    }
}


/** The aes packet format consists of:
 *
 *  - a 8-bit aes encoding version in clear text
 *  - a 32-bit SA number in clear text
 *  - (V2 only) a 128 bit inner message authentication code (last encrypted data block encrypted again using K2),
 *  - (V2 only) the separately encrypted 128 bit IV (using K2),
 *  - (V1 only) a 32-bit random nonce (encrypted together with ...
 *  - (V2 only) the 16-bit packet length of the following data (encrypted together with...
 *  - ...the following payload data (using V1 key K or V2 key K1).
 *  with K = key (V1) and
 *       K1 = key1 and K2 = key2 (V2)
 *
 *  V1:
 *  [V|SSSS|nnnnDDDDDDDDDDDDDDDDDDDDD]
 *         |<-- encrypted with K  -->|
 *
 *  V2:
 *  [V|SSSS|MMMMMMMMMMMMMMMM|IIIIIIIIIIIIIIII|LLDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD]
 *         |<- encrypted -->|<- encrypted -->|<----- encrypted with K1 ------>|
 *         |<- with K2   -->|<- with K2   -->|                                |
 */
static int transop_encode_aes( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len,
                                   const uint8_t * peer_mac)
{
    int len2=-1;
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE];
    uint32_t * pnonce;
    uint16_t * data_len;
    uint8_t full_msg_auth[AES_BLOCK_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];

    if ( (in_len + TRANSOP_AES_DATA_LEN) > N2N_PKT_BUF_SIZE )
    {
        traceEvent( TRACE_ERROR, "encode_aes inbuf too big to encrypt." );
	goto error;
    }
    if ( (in_len + TRANSOP_AES_DATA_LEN + N2N_AES_IVEC_SIZE + N2N_AES_MSGAUTH_SIZE + TRANSOP_AES_SA_SIZE + TRANSOP_AES_VER_SIZE) > out_len )
    {
        traceEvent( TRACE_ERROR, "encode_aes outbuf too small." );
	goto error;
    }

    int len=-1;
    size_t idx=0;
    sa_aes_t * sa;
    size_t tx_sa_num = 0;

    /* The transmit sa is periodically updated */
    tx_sa_num = aes_choose_tx_sa( priv, peer_mac );
    sa = &(priv->sa[tx_sa_num]); /* Proper Tx SA index */

    traceEvent( TRACE_DEBUG, "encode_aes %lu with SA %lu.", in_len, sa->sa_id );

    /* Encode the aes format version. */
    encode_uint8( outbuf, &idx, priv->version );

    /* Encode the security association (SA) number */
    encode_uint32( outbuf, &idx, sa->sa_id );

    /* v2: The following fields (message authentication, IV) are calculated respectively filled 
       after data encrpytion */

    /* prepare assembly buffer with nonce (v1) or data length (v2) respectively
       and calculate the length of data to be encrypted */
    uint8_t ethernet_data_offset;
    uint8_t buffer_suffix;
    uint8_t skip_to_data;
    switch (priv->version)
    {
	case 1 :
	{
	    ethernet_data_offset = TRANSOP_AES_NONCE_SIZE;
            pnonce = (uint32_t *)assembly;
            *pnonce = rand();
	    buffer_suffix = 1; /* one byte follows buffer's end for padding length, not to be encrypted */
            skip_to_data = TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE;
	    break;
	}
	case 2 :
	{
	    ethernet_data_offset = TRANSOP_AES_DATA_LEN;
	    /* version 2 also requires the data length to be part of encrypted data */
	    data_len = (uint16_t *)assembly;
	     *data_len = htons(in_len);
	    buffer_suffix = 0; /* nothing to be added behind buffer's end */
	    skip_to_data = TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE;
	    break;
	}
    }
    /* also count the prepending data fields for encryption */
    len = in_len + ethernet_data_offset;
    /* Round up to next whole AES block size */
    len2 = ( ( ( len - 1 + buffer_suffix) / AES_BLOCK_SIZE) + 1 ) * AES_BLOCK_SIZE; 

    /* The assembly buffer is a source for encrypting data.
     * The whole contents of assembly are encrypted. */
    memcpy( assembly + ethernet_data_offset , inbuf, in_len );

    /* prepare the encryption by performing the version-dependant padding
       at buffer's end as well as the IV, also choose key */
    AES_KEY key;
    switch (priv->version)
    {
	case 1 :
 	{
	    assembly[ len2-1 ]=(len2-len);
            traceEvent( TRACE_DEBUG, "padding = %u", assembly[ len2-1 ] );
	    /* set IV to 0 for v1 */
	    memset (iv, 0, N2N_AES_IVEC_SIZE);
            /* data will be encrypted using v1 key K */
	    key = sa->enc_key_K;
	    break;
	}
	case 2 :
	{
	    /* generate random padding for the last plain text block and also
               generate a random initialization vector for CBC directly to its field in the buffer
               only proceed if random values are cryptographically safe (return value == 1) */
	    if ((RAND_bytes(assembly + len + 1, len2 - len) != 1) ||
	        (RAND_bytes(outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, N2N_AES_IVEC_SIZE) != 1))
	    {
	        traceEvent ( TRACE_ERROR, "encode_aes no random data available for padding and initialization vector." );
	        goto error;
	    }
	    /* encode system time to IV for replay attack protection */
	    /* get current system time (for international use: not local time) to encode it in IV */
	    struct timeval tod;
	    uint64_t micro_seconds;
	    gettimeofday (&tod, NULL);
	    /* We will calculate and put the microseconds since 1970 leftbound into the IV.
	       As microseconds fraction never exceeds 1,000,000 , a max of 20 bits is
	       used to encode the value tv_usec. 32 bits are used for tv_sec.
	       Thus, micro_seconds' 12 most significant bits are not used.
	       As we do not want 12 definetely zeroed bits IV, some bit masking is required
	       to only copy the 52 (least) significant bits leaving the other 12 random as before
	       - converting in host byte order to make sure bitwise masking is applied correctly;
	       shifting might be independet from byte order, though. */
	    micro_seconds = be64toh(*(uint64_t*)(outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE));
	    micro_seconds = htobe64( ( (tod.tv_sec * 1000000 + tod.tv_usec) << 12)
	                             | (0x0000000000000FFF & micro_seconds));
	    memcpy (outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, &micro_seconds, sizeof (micro_seconds));
	    /* nybblewise (4 bit portions), the whole 128 bit IV should look as follows:
	       MMMMMMMMMMMMMrrrrrrrrrrrrrrrrrrr
	       M = 52 bit value of microseconds since 1970
	       r = random data */
	    /* to prevent an all too predictable content of this modified IV,
	       before use it gets encrypted using K1 directly in the buffer */
	    AES_encrypt (outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, /* src: IV position in outbuffer */
	                 outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE , /* dst: same place as src */
	                 &(sa->enc_key_K1)); /* using key K1 */

	    /* copy IV to the field later provided to AES_cbc_encrypt (where it gets corrupted during cbc mode encryption) */
	    memcpy(iv, outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, N2N_AES_IVEC_SIZE );
            /* data will be encrypted using v2 key K1 */
            key = sa->enc_key_K1;
	    break;
	}
    }

    /* encrypt the payload (including prepending data)  */
    AES_cbc_encrypt(assembly, /* source */
                    outbuf + skip_to_data, /* dest */
                    len2, /* enc size */
                    &key, /* using key K (v1) or K1 (v2) */
                    iv, /* IV */
                    1); /* = encryption */

    /* v2: now that IV was used, it gets encrypted for transmission. */
    if (priv->version == 2)
    {
        /* this is necessary because first block of plain text is quite predicable (length, preamble, NIC MACs) 
           encrypt the initialization vector directly on its field in the buffer using secondary key K2 */
        AES_encrypt (outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, /* src: IV field in the buffer */
                     outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, /* dst: same field */
                     &(sa->enc_key_K2)); /* using the secondary key K2 */
        /* prepare the message authentication buffer */
        memset (full_msg_auth, 0, AES_BLOCK_SIZE);
        /* copy the AES version and security association to that buffer (left bound) */
        memcpy (full_msg_auth, outbuf, TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE);
        /* xor the last cipher block with that prefilled buffer */
        memxor (full_msg_auth, /* operand and destination */
                outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE + len2 - AES_BLOCK_SIZE, /* 2nd operand, last cipher block */
                AES_BLOCK_SIZE);
        /* encrypt the so far generated message authentication code using K2 to generate ECBC-MAC, which now also includes the preceeding fields VER_SIZE and SA_SIZE */
        AES_encrypt (full_msg_auth, /* src */
                     full_msg_auth, /* dst */
                     &(sa->enc_key_K2)); /* using the secondary key K2 */
        /* copy only the defined number of bytes for transmission to output buffer */
        memcpy (outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE, full_msg_auth, N2N_AES_MSGAUTH_SIZE);
    }

    /* prepare return value */
    len2 += skip_to_data; /* size of data carried in UDP. */

error:
    return len2;
}


/* Search through the array of SAs to find the one with the required ID.
 *
 * @return array index where found or -1 if not found
 */
static ssize_t aes_find_sa( const transop_aes_t * priv, const n2n_sa_t req_id )
{
    size_t i;
    
    for (i=0; i < priv->num_sa; ++i)
    {
        const sa_aes_t * sa=NULL;

        sa = &(priv->sa[i]);
        if (req_id == sa->sa_id)
        {
            return i;
        }
    }

    return -1;
}

/** The aes packet format consists of:
 *
 *  - a 8-bit aes encoding version in clear text
 *  - a 32-bit SA number in clear text
 *  - (V2 only) a 128 bit inner message authentication code (last encrypted data block encrypted again using K2),
 *  - (V2 only) the separately encrypted 128 bit IV (using K2),
 *  - (V1 only) a 32-bit random nonce (encrypted together with ...
 *  - (V2 only) the 16-bit packet length of the following data (encrypted together with...
 *  - ...the following payload data (using V1 key K or V2 key K1).
 *  with K = key (V1) and
 *       K1 = key1 and K2 = key2 (V2)
 *
 *  V1:
 *  [V|SSSS|nnnnDDDDDDDDDDDDDDDDDDDDD]
 *         |<-- encrypted with K  -->|
 *
 *  V2:
 *  [V|SSSS|MMMMMMMMMMMMMMMM|IIIIIIIIIIIIIIII|LLDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD]
 *         |<- encrypted -->|<- encrypted -->|<----- encrypted with K1 ------>|
 *         |<- with K2   -->|<- with K2   -->|                                |
 */
static int transop_decode_aes( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len,
                                   const uint8_t * peer_mac)
{
    int len=0;
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE];
    uint8_t assembly2[N2N_PKT_BUF_SIZE];
    n2n_aes_ivec_t temp_iv;
    n2n_aes_ivec_t actual_iv;
    uint8_t full_msg_auth[AES_BLOCK_SIZE];

    n2n_sa_t sa_rx;
    ssize_t sa_idx=-1;
    size_t rem=in_len;
    size_t idx=0;

    /* Get the encoding version ... */
    uint8_t aes_enc_ver=0;
    decode_uint8( &aes_enc_ver, inbuf, &rem, &idx );
    /* ... to make sure it is supported 
       and calculate prepending packet overhead */
    uint32_t skip_to_encrypted_data;
    switch (aes_enc_ver)
    {
	case 1 :
	{
	    skip_to_encrypted_data = TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE;
	    break;
	}
        case 2 :
	{
	    skip_to_encrypted_data = TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE;
            break;
	}
        default:
	{
            traceEvent( TRACE_ERROR, "decode_aes unsupported aes version %u.", aes_enc_ver );
            /* REVISIT: should be able to load a new SA at this point to complete the decoding. */
	    goto error;
	    break;
	}
    }

    /* reasonable length check */
    if ( ( (in_len - skip_to_encrypted_data) > N2N_PKT_BUF_SIZE ) /* Cipher text fits in assembly ... */ 
        || (in_len < (skip_to_encrypted_data + AES_BLOCK_SIZE) ) /* .. and has at least all neccessary fields and at least one cipher block */
       )
    {
        traceEvent( TRACE_ERROR, "decode_aes inbuf wrong size (%ul) to decrypt.", in_len );
	goto error;
    }

    /* Get the SA number and make sure we are decrypting with the right one. */
    decode_uint32( &sa_rx, inbuf, &rem, &idx );
    sa_idx = aes_choose_rx_sa(priv, peer_mac, sa_rx);
    if ( sa_idx < 0 )
    {
        traceEvent( TRACE_ERROR, "decode_aes SA number %lu not found.", sa_rx );
        /* REVISIT: should be able to load a new SA at this point to complete the decoding. */
	goto error;
    }
    sa_aes_t * sa = &(priv->sa[sa_idx]);
    traceEvent( TRACE_DEBUG, "decode_aes %lu with SA %lu.", in_len, sa_rx, sa->sa_id );

    /* calculate encrypted data length */
    len = in_len - skip_to_encrypted_data;
    if ( 0 != (len % AES_BLOCK_SIZE ) )
    {
        traceEvent( TRACE_WARNING, "Encrypted length %d is not a multiple of AES_BLOCK_SIZE (%d)", len, AES_BLOCK_SIZE );
	len = 0;
        goto error;
    }

    /* prepare IV for CBC decryption and also set decryption key */
    AES_KEY key;
    switch (aes_enc_ver)
    {
	case 1 :
	{
       	    memset (actual_iv, 0, N2N_AES_IVEC_SIZE);
	    key = sa->dec_key_K;
            break;
	}
        case 2 :
	{
	    /* decrypt the initialization vector using secondary key K2 */
	    AES_decrypt (inbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, /* src: IV field in the buffer */
	                 actual_iv, /* dst:  IV field in SA-structure getting used in the next step, i.e. cbc decryption of data */
                         &(sa->dec_key_K2)); /* using secondary key K2 */
	    key = sa->dec_key_K1;
	    break;
	}
    }

    /* prevent replay attacks, encryption scheme version 2 only */
    uint64_t iv_micro_seconds;
    if (aes_enc_ver == 2)
    {
        /* get current system time (for international use - not local time) for later
        comparison to the one encoded in IV */
        struct timeval tod;
        uint64_t micro_seconds;
        gettimeofday (&tod, NULL);
        micro_seconds = tod.tv_sec * 1000000 + tod.tv_usec;
        AES_decrypt (actual_iv, /* src: IV */
                     temp_iv, /* dst: borrowed a temporary IV field getting used later in cbc decryption of data */
                     &(sa->dec_key_K1)); /* using key K1 */
        /* extract encoded system time out of IV */
        iv_micro_seconds = be64toh(*(uint64_t*)temp_iv) >> 12 ;
        /* it needs to be in the allowed time frame */
        if (abs (micro_seconds - iv_micro_seconds) > N2N_MAX_PACKET_DELAY)
        {
            traceEvent( TRACE_WARNING, "Packet did not arrive in expected time frame: %u microseconds off.", abs (micro_seconds - iv_micro_seconds) );
            goto error;
        }
        /* time stamp has to be bigger than the one of packet received before */
        /* the only exception to let pass: the first packet ever */
        if (sa->prev_time_stamp == 0)
        {
            sa->prev_time_stamp = iv_micro_seconds;
        }
        /* allow for some grace time because packets sometimes seem to overtake each other
           either on the line or somewhere inside the network stack */
        if (iv_micro_seconds < (sa->prev_time_stamp - N2N_MAX_PACKET_DEVIATION_TIME))
        {
            traceEvent( TRACE_WARNING, "Packet's time stamp by %u microseconds lower than in previous packet.", abs (sa->prev_time_stamp - iv_micro_seconds) );
	    goto error;
	}
        /* restore a copy of initialization vector in the temp field for later use in
           message authentication verification as aes_cbc's parameter gets scrambled during cbc process */
        memcpy (temp_iv, actual_iv, N2N_AES_IVEC_SIZE);
    }

    /* decrypt payload in cbc mode using primary key K1 */
    AES_cbc_encrypt (inbuf + skip_to_encrypted_data, /* src: payload from buffer */
                     assembly, /* dst: assembly */
                     len,
                     &key, /* using key K (v1) or K1 (v2) */
                     actual_iv,/* using the beforehand prepared IV */
                     0); /* = decryption */

    /* reconstruct original packet length */
    switch (aes_enc_ver)
    {
	case 1 :
	{
	   uint8_t padding;
            /* last byte is how much was padding: max value should be
             * AES_BLOCKSIZE-1 */
            padding = assembly[ len-1 ] & 0xff;
            /* strictly speaking for this to be an ethernet packet
             * it is going to need to be even bigger; but this is
             * enough to prevent segfaults. */
            if ( len < (padding + TRANSOP_AES_NONCE_SIZE))
	    {
		traceEvent( TRACE_WARNING, "UDP payload decryption failed." );
		goto error;
            }
	    traceEvent( TRACE_DEBUG, "padding = %u", padding );
            len -= padding;
            len -= TRANSOP_AES_NONCE_SIZE; /* size of ethernet packet */
	    break;
	}
	case 2 :
	{
	    uint16_t data_len;
	    data_len = ntohs(*(uint16_t*)assembly);
            /* the transmitted data length (data_len + its own field size) should match the encrypted data length (len) +/- blocksize */
            if ( (len < (data_len + TRANSOP_AES_DATA_LEN)) || ( (len - AES_BLOCK_SIZE) >= (data_len + TRANSOP_AES_DATA_LEN) ) )
	    {
                traceEvent( TRACE_WARNING, "The length of received encrypted data does not even roughly match the alleged UDP payload size." );
		goto error;
	    }
            len = data_len;
            break;
	}
    }

    /* verify message authentication code (encryption scheme version 2 only) ... */
    if (aes_enc_ver == 2)
    {
        /* ... by
           1. cbc'ing the decrypted data again completly using K1,
           2. xor'ing this block with VERSION and SA fields
           3. encrypting the last cipher block using secondary key K2, and
           4. finally, comparing with the trasmitted message authentication code */

        /* encrypt payload in cbc mode again using key K1 */
        AES_cbc_encrypt (assembly, /* src: the already decrypted data in assembly buffer */
                         assembly2, /* dst: assembly2 */
                         len + TRANSOP_AES_DATA_LEN,
                         &(sa->enc_key_K1), /* using key K1 */
                         temp_iv,/* using the saved IV from above */
                         1); /* = encryption */
        /* xor that just encrypted last cipher block with AES version and security association (left bound) */
        memxor (assembly2 + len - AES_BLOCK_SIZE,  /* dst and operand */
                inbuf, /* 2nd operand: the decrypted aes version and security associtation number */
                TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE);
        /* encrypt that modified last cipher block again using K2 to generate ECBC-MAC for message authentication code */
        AES_encrypt (assembly2 + len - AES_BLOCK_SIZE, /* src: last cipher block */
                     assembly2 + len - AES_BLOCK_SIZE, /* dst: just overwrite in the same place as assembly2 is not needed anymore*/
                     &(sa->enc_key_K2)); /* using the secondary key K2 */
        /* compare the just generated ECBC-MAC to the one transmitted in the packet */
        if (!memcmp (assembly2 + len - AES_BLOCK_SIZE, inbuf+ TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE, N2N_AES_MSGAUTH_SIZE))
        {
                traceEvent( TRACE_WARNING, "Message authentication failed." );
                goto error;
        }
        /* For replay prevention: Update time stamp after verified decryption */
        sa->prev_time_stamp = iv_micro_seconds;
    }

    /* Step over nonce length (v1) or data length value (v2) repectively */
    uint8_t ethernet_data_offset;
    switch (aes_enc_ver)
    {
	case 1 :
	{
	    ethernet_data_offset = TRANSOP_AES_NONCE_SIZE;
	    break;
	}
	case 2 :
	{
	    ethernet_data_offset = TRANSOP_AES_DATA_LEN;
	    break;
	}
    }

    /* copy ethernet packet data to outuf */
    memcpy( outbuf,
            assembly + ethernet_data_offset,
            len );

error:
    return len;
}

/* NOTE: the caller should adjust priv->num_sa accordingly */
static int setup_aes_key(transop_aes_t *priv, uint8_t *keybuf, ssize_t pstat, size_t sa_num) {
    /* pstat is number of bytes read into keybuf. */
    sa_aes_t * sa = &(priv->sa[sa_num]);
    size_t aes_keysize_bytes;
    size_t aes_keysize_bits;
    uint8_t * modified_keybuf;

    /* Clear out any old possibly longer key material */
    memset( &(sa->enc_key_K), 0, sizeof(AES_KEY) );
    memset( &(sa->dec_key_K), 0, sizeof(AES_KEY) );
    memset( &(sa->enc_key_K1), 0, sizeof(AES_KEY) );
    memset( &(sa->enc_key_K1), 0, sizeof(AES_KEY) );
    memset( &(sa->enc_key_K2), 0, sizeof(AES_KEY) );
    memset( &(sa->enc_key_K2), 0, sizeof(AES_KEY) );
    /* ... and also some possible rest of a former time stamp used by v2 */
    memset( &(sa->prev_time_stamp), 0, sizeof (sa->prev_time_stamp));
    /* we need to setup all version's keys because as long as we try to be backward 
       compatible, we never know what versioned packet will arrive and need to be decoded */

    /* setup version 1 key K */
    aes_keysize_bytes = aes_best_keysize(pstat);
    aes_keysize_bits = 8 * aes_keysize_bytes;
   /* The aes_keysize_bytes may differ from pstat, possibly pad */
    modified_keybuf = calloc(1, aes_keysize_bytes);
    if(!modified_keybuf)
        return(1);
    memcpy(modified_keybuf, keybuf, (pstat <= aes_keysize_bytes)?pstat:aes_keysize_bytes);
    /* Use N2N_MAX_KEYSIZE because the AES key needs to be of fixed
     * size. If fewer bits specified then the rest will be
     * zeroes. AES acceptable key sizes are 128, 192 and 256
     * bits. */
    AES_set_encrypt_key(modified_keybuf, aes_keysize_bits, &(sa->enc_key_K));
    AES_set_decrypt_key(modified_keybuf, aes_keysize_bits, &(sa->dec_key_K));
    traceEvent( TRACE_DEBUG, "transop_addspec_aes sa_id=%u, %u bits data=%s.\n",
                priv->sa[sa_num].sa_id, aes_keysize_bits, keybuf);
    free(modified_keybuf);

    /* setup version 2 keys K1 and K2 */
    /* cli keys are given in ascii or some other letter coding which show
       far less entropy as they do no use the full byte range. Thus, we
       assume 4 password letters/special characters  to have the same entropy
       than one random byte, that's why pstat gets divided by 4 for 
       key size determination. */
    aes_keysize_bytes = aes_best_keysize(pstat / 4);
    /* AES acceptable key sizes are 128, 192 and 256 bits. */
    aes_keysize_bits = 8 * aes_keysize_bytes;

    /* The aes_keysize_bytes may differ from pstat, therefore hash and make sure that
       HASH_SIZE > KEY_SIZE, that is essential to security because two keys are derived */
    modified_keybuf = calloc(1, SHA512_DIGEST_LENGTH);
    if(!modified_keybuf)
        return(1);
    SHA512(keybuf, pstat, modified_keybuf);
    /* set (primary) en/decryption key , use #aes_keysize_bits first bits of hash */
    AES_set_encrypt_key(modified_keybuf, aes_keysize_bits, &(sa->enc_key_K1));
    AES_set_decrypt_key(modified_keybuf, aes_keysize_bits, &(sa->dec_key_K1));
    /* use the last part of the hash as secondary key */
    AES_set_encrypt_key(modified_keybuf+SHA512_DIGEST_LENGTH/2, aes_keysize_bits, &(sa->enc_key_K2));
    AES_set_decrypt_key(modified_keybuf+SHA512_DIGEST_LENGTH/2, aes_keysize_bits, &(sa->dec_key_K2));
    free(modified_keybuf);

    ++(priv->num_sa);

    return(0);
}

/*
 * priv: pointer to transform state
 * keybuf: buffer holding the key
 * pstat: length of keybuf
 */
static void add_aes_key(transop_aes_t *priv, uint8_t *keybuf, ssize_t pstat) {
    setup_aes_key(priv, keybuf, pstat, priv->num_sa);
    ++(priv->num_sa);
}

static int transop_addspec_aes( n2n_trans_op_t * arg, const n2n_cipherspec_t * cspec )
{
    int retval = 1;
    ssize_t pstat=-1;
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    uint8_t keybuf[N2N_MAX_KEYSIZE];

    if ( priv->num_sa < N2N_AES_NUM_SA )
    {
        const char * op = (const char *)cspec->opaque;
        const char * sep = index( op, '_' );

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

            memset( keybuf, 0, N2N_MAX_KEYSIZE );
            pstat = n2n_parse_hex( keybuf, N2N_MAX_KEYSIZE, sep+1, s );
            if ( pstat > 0 )
            {
                add_aes_key(priv, keybuf, pstat);
                retval = 0;
            }
        }
        else
        {
            traceEvent( TRACE_ERROR, "transop_addspec_aes : bad key data - missing '_'.\n");
        }
    }
    else
    {
        traceEvent( TRACE_ERROR, "transop_addspec_aes : full.\n");
    }
    
    return retval;
}


static n2n_tostat_t transop_tick_aes( n2n_trans_op_t * arg, time_t now )
{
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    size_t i;
    int found=0;
    n2n_tostat_t r;

    memset( &r, 0, sizeof(r) );

    traceEvent( TRACE_DEBUG, "transop_aes tick num_sa=%u now=%lu", priv->num_sa, now );

    for ( i=0; i < priv->num_sa; ++i )
    {
        if ( 0 == validCipherSpec( &(priv->sa[i].spec), now ) )
        {
            time_t remaining = priv->sa[i].spec.valid_until - now;

            traceEvent( TRACE_INFO, "transop_aes choosing tx_sa=%u (valid for %lu sec)", priv->sa[i].sa_id, remaining );
            priv->tx_sa=i;
            found=1;
            break;
        }
        else
        {
            traceEvent( TRACE_DEBUG, "transop_aes tick rejecting sa=%u  %lu -> %lu", 
                        priv->sa[i].sa_id, priv->sa[i].spec.valid_from, priv->sa[i].spec.valid_until );
        }
    }

    if ( 0==found)
    {
        traceEvent( TRACE_INFO, "transop_aes no keys are currently valid. Keeping tx_sa=%u", priv->tx_sa );
    }
    else
    {
        r.can_tx = 1;
        r.tx_spec.t = N2N_TRANSFORM_ID_AESCBC;
        r.tx_spec = priv->sa[priv->tx_sa].spec;
    }

    return r;
}

static n2n_tostat_t transop_tick_aes_psk(n2n_trans_op_t * arg, time_t now) {
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    n2n_tostat_t r;

    memset(&r, 0, sizeof(r));

    // Always tx
    r.can_tx = 1;
    r.tx_spec.t = N2N_TRANSFORM_ID_AESCBC;
    r.tx_spec = priv->sa[priv->tx_sa].spec;

    return r;
}

int transop_aes_init( n2n_trans_op_t * ttt )
{
    int retval = 1;
    transop_aes_t * priv = NULL;

    if ( ttt->priv )
    {
        transop_deinit_aes( ttt );
    }

    memset( ttt, 0, sizeof( n2n_trans_op_t ) );

    priv = (transop_aes_t *) calloc(1, sizeof(transop_aes_t));

    if ( NULL != priv )
    {
        size_t i;
        sa_aes_t * sa=NULL;

        /* install the private structure. */
        ttt->priv = priv;
        priv->num_sa=0;
        priv->tx_sa=0; /* We will use this sa index for encoding. */
        priv->psk_mode = 0;
	priv->version = N2N_AES_TRANSFORM_VERSION_MIN;

        ttt->transform_id = N2N_TRANSFORM_ID_AESCBC;
        ttt->addspec = transop_addspec_aes;
        ttt->tick = transop_tick_aes; /* chooses a new tx_sa */
        ttt->deinit = transop_deinit_aes;
        ttt->fwd = transop_encode_aes;
        ttt->rev = transop_decode_aes;

        for(i=0; i<N2N_AES_NUM_SA; ++i)
        {
            sa = &(priv->sa[i]);
            sa->sa_id=0;
            memset( &(sa->spec), 0, sizeof(n2n_cipherspec_t) );
            memset( &(sa->enc_key_K), 0, sizeof(AES_KEY) );
            memset( &(sa->dec_key_K), 0, sizeof(AES_KEY) );
            memset( &(sa->enc_key_K1), 0, sizeof(AES_KEY) );
            memset( &(sa->dec_key_K1), 0, sizeof(AES_KEY) );
            memset( &(sa->enc_key_K2), 0, sizeof(AES_KEY) );
            memset( &(sa->dec_key_K2), 0, sizeof(AES_KEY) );
            memset( &(sa->prev_time_stamp), 0, sizeof (sa->prev_time_stamp));
        }

        retval = 0;
    }
    else
    {
        memset( ttt, 0, sizeof(n2n_trans_op_t) );
        traceEvent( TRACE_ERROR, "Failed to allocate priv for aes" );
    }

    return retval;
}

/* Setup AES in pre-shared key mode */
int transop_aes_setup_psk(n2n_trans_op_t *ttt,
                           n2n_sa_t sa_num,
                           uint8_t *encrypt_pwd,
                           uint32_t encrypt_pwd_len,
                           uint8_t aes_version) {
    static const u_int8_t broadcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    int retval = 1;
    transop_aes_t *priv = (transop_aes_t *)ttt->priv;

    if(ttt->priv) {
        /* Replace the tick function with the PSK version of it */
        ttt->tick = transop_tick_aes_psk;
        priv->psk_mode = 1;
        memset(priv->mac_sa, 0, sizeof(priv->mac_sa));
        priv->encrypt_pwd = encrypt_pwd;
        priv->encrypt_pwd_len = encrypt_pwd_len;

        priv->num_sa=0;
        priv->tx_sa=0;

	/* encryption scheme version */
	priv->version = aes_version;

        /* Add the key to be used for broadcast */
        add_aes_key(priv, priv->encrypt_pwd, priv->encrypt_pwd_len);

        memcpy(priv->mac_sa[0], broadcast_mac, N2N_MAC_SIZE);
        priv->sa_to_replace = priv->num_sa;

        retval = 0;
    } else
        traceEvent(TRACE_ERROR, "AES priv is not allocated");

    return retval;
}

#else /* #if defined(N2N_HAVE_AES) */

struct transop_aes
{
    ssize_t             tx_sa;
};

typedef struct transop_aes transop_aes_t;


static int transop_deinit_aes( n2n_trans_op_t * arg )
{
    transop_aes_t * priv = (transop_aes_t *)arg->priv;

    if ( priv )
    {
        free(priv);
    }

    arg->priv=NULL; /* return to fully uninitialised state */

    return 0;
}

static int transop_encode_aes( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len )
{
    return -1;
}

static int transop_decode_aes( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len )
{
    return -1;
}

static int transop_addspec_aes( n2n_trans_op_t * arg, const n2n_cipherspec_t * cspec )
{
    traceEvent( TRACE_DEBUG, "transop_addspec_aes AES not built into edge.\n");

    return -1;
}

static n2n_tostat_t transop_tick_aes( n2n_trans_op_t * arg, time_t now )
{
    n2n_tostat_t r;

    memset( &r, 0, sizeof(r) );

    return r;
}

int transop_aes_init( n2n_trans_op_t * ttt )
{
    int retval = 1;
    transop_aes_t * priv = NULL;

    if ( ttt->priv )
    {
        transop_deinit_aes( ttt );
    }

    memset( ttt, 0, sizeof( n2n_trans_op_t ) );

    priv = (transop_aes_t *) malloc( sizeof(transop_aes_t) );

    if ( NULL != priv )
    {
        /* install the private structure. */
        ttt->priv = priv;
        priv->tx_sa=0; /* We will use this sa index for encoding. */

        ttt->transform_id = N2N_TRANSFORM_ID_AESCBC;
        ttt->addspec = transop_addspec_aes;
        ttt->tick = transop_tick_aes; /* chooses a new tx_sa */
        ttt->deinit = transop_deinit_aes;
        ttt->fwd = transop_encode_aes;
        ttt->rev = transop_decode_aes;

        retval = 0;
    }
    else
    {
        memset( ttt, 0, sizeof(n2n_trans_op_t) );
        traceEvent( TRACE_ERROR, "Failed to allocate priv for aes" );
    }

    return retval;
}


int transop_aes_setup_psk(n2n_trans_op_t *ttt,
                           n2n_sa_t sa_num,
                           uint8_t *encrypt_pwd,
                           uint32_t encrypt_pwd_len) {
    return 0;
}

#endif /* #if defined(N2N_HAVE_AES) */

