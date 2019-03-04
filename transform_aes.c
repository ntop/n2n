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

#define N2N_AES_TRANSFORM_VERSION       2  /* version of the transform encoding */
#define N2N_AES_IVEC_SIZE               16 /* Enough space for biggest AES ivec */
#define N2N_AES_MSGAUTH_SIZE		16 /* size of the message authentication code length, from 0 ... 16 = AES_BLOCK_SIZE */

typedef unsigned char n2n_aes_ivec_t[N2N_AES_IVEC_SIZE];

struct sa_aes
{
    n2n_cipherspec_t    spec;           /* cipher spec parameters */
    n2n_sa_t            sa_id;          /* security association index */
    AES_KEY             enc_key;        /* tx key */
    n2n_aes_ivec_t      enc_ivec;       /* tx CBC state */
    AES_KEY             dec_key;        /* tx key */
    n2n_aes_ivec_t      dec_ivec;       /* tx CBC state */
    AES_KEY		enc_key_2;	/* secondary key for IV encryption and msg auth signing */
    AES_KEY		dec_key_2;	/* secondary key for IV encryption and msg auth signing */
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
	/* this is a shortcut to always use full key size for security reasons */
	/* however, performance needs might require platform-dependant changes, e.g. for routers */
        return AES256_KEY_BYTES;
}

/** The aes packet format consists of:
 *
 *  - a 8-bit aes encoding version in clear text
 *  - a 32-bit SA number in clear text
 *  - a 128 bit inner message authentication code (last encrypted data block encrypted again using K2),
 *  - the separately encrypted 128 bit IV (using K2),
 *  - the 16-bit packet length of the following data (encrypted together with...
 *  - ...the following payload data (using K1).
 *  with K1 = key1 and K2 = key2.
 *
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
    uint16_t * data_len;
    uint8_t full_msg_auth[AES_BLOCK_SIZE];

    if ( (in_len + TRANSOP_AES_DATA_LEN) <= N2N_PKT_BUF_SIZE )
    {
        if ( (in_len + TRANSOP_AES_DATA_LEN + N2N_AES_IVEC_SIZE + N2N_AES_MSGAUTH_SIZE + TRANSOP_AES_SA_SIZE + TRANSOP_AES_VER_SIZE) <= out_len )
        {
            int len=-1;
            size_t idx=0;
            sa_aes_t * sa;
            size_t tx_sa_num = 0;

            /* The transmit sa is periodically updated */
            tx_sa_num = aes_choose_tx_sa( priv, peer_mac );

            sa = &(priv->sa[tx_sa_num]); /* Proper Tx SA index */
        
            traceEvent( TRACE_DEBUG, "encode_aes %lu with SA %lu.", in_len, sa->sa_id );
            
            /* Encode the aes format version. */
            encode_uint8( outbuf, &idx, N2N_AES_TRANSFORM_VERSION );

            /* Encode the security association (SA) number */
            encode_uint32( outbuf, &idx, sa->sa_id );

           /* The following fields (message authentication, IV) are calculated respectively filled after data encrpytion */

            /* Encrypt the assembly contents and write the ciphertext after the IV. */
            len = in_len + TRANSOP_AES_DATA_LEN;

            /* The assembly buffer is a source for encrypting data. The data length is
             * written in first followed by the packet payload. The whole
             * contents of assembly are encrypted. */
            data_len = (uint16_t *)assembly;
            *data_len = htons(in_len);

	    memcpy( assembly + TRANSOP_AES_DATA_LEN , inbuf, in_len );
            len2 = ( ( ( len - 1) / AES_BLOCK_SIZE) + 1 ) * AES_BLOCK_SIZE; /* Round up to next whole AES block size */

            /* generate a random initialization vector for CBC directly to its field in the buffer */
            /* only proceed if random values are cryptographically safe (return value == 1) */
            if (RAND_bytes(outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, N2N_AES_IVEC_SIZE) == 1)   /* get a cryptographically safely randomized initialization vector */
            {
                /* sa->enc_ivec gets changed during cbc encryption procedure; to keep the original value safe (it is needed later), copy it from its field in the buffer */
                memcpy((sa->enc_ivec), outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, N2N_AES_IVEC_SIZE );

                /* encrypt the payload (including packet length)  */
                AES_cbc_encrypt( assembly, /* source */
                                 outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE, /* dest */
                                 len2, /* enc size */
                                 &(sa->enc_key), /* using key K1 */
                                 &(sa->enc_ivec), /* the copy of IV */
				 1); /* = encryption */

                /* now that iv was used, it gets encrypted for transmission. */
                /* this is necessary because first block of plain text is quite predicable (length, preamble, NIC MACs) */
                /* encrypt the initialization vector directly on its field in the buffer using secondary key K2 */
                AES_encrypt (outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, /* src: IV field in the buffer */
                             outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, /* dst: same field */
                             &(sa->enc_key_2)); /* using the secondary key K2 */

                /* encrypt the last cipher block again using K2 to generate ECBC-MAC for message authentication code */
                AES_encrypt (outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE + len2 - AES_BLOCK_SIZE, /* src: last cipher block */
                             full_msg_auth, /* dst: a buffer for the full length message authentication code */
                             &(sa->enc_key_2)); /* using the secondary key K2 */

                /* copy only the defined number of bytes for transmission */
                memcpy (outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE, full_msg_auth, N2N_AES_MSGAUTH_SIZE);

                len2 += TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE; /* size of data carried in UDP. */
            }
            else
            {
                traceEvent ( TRACE_ERROR, "encode_aes no random data available for initialization vector." );
            }
        }
        else
        {
            traceEvent( TRACE_ERROR, "encode_aes outbuf too small." );
        }
    }
    else
    {
        traceEvent( TRACE_ERROR, "encode_aes inbuf too big to encrypt." );
    }

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
 *  - a 128 bit inner message authentication code (last encrypted data block encrypted again using K2),
 *  - the separately encrypted 128 bit IV (using K2),
 *  - the 16-bit packet length of the following data (encrypted together with...
 *  - ...the following payload data (using K1).
 *  with K1 = key1 and K2 = key2.
 *
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
    n2n_aes_ivec_t iv;

    if ( ( (in_len - (TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE)) <= N2N_PKT_BUF_SIZE ) /* Cipher text fits in assembly */ 
         && (in_len >= (TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE + AES_BLOCK_SIZE) ) /* Has at least all neccessary fields and at least one cipher block */
        )
    {
        n2n_sa_t sa_rx;
        ssize_t sa_idx=-1;
        size_t rem=in_len;
        size_t idx=0;
        uint8_t aes_enc_ver=0;

        /* Get the encoding version to make sure it is supported */
        decode_uint8( &aes_enc_ver, inbuf, &rem, &idx );

        if ( N2N_AES_TRANSFORM_VERSION == aes_enc_ver )
        {
            /* Get the SA number and make sure we are decrypting with the right one. */
            decode_uint32( &sa_rx, inbuf, &rem, &idx );

            sa_idx = aes_choose_rx_sa(priv, peer_mac, sa_rx);

            if ( sa_idx >= 0 )
            {
                sa_aes_t * sa = &(priv->sa[sa_idx]);

                traceEvent( TRACE_DEBUG, "decode_aes %lu with SA %lu.", in_len, sa_rx, sa->sa_id );

                len = (in_len - (TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE));
                
                if ( 0 == (len % AES_BLOCK_SIZE ) )
                {
                    uint16_t data_len;

                    /* decrypt the initialization vector using secondary key K2 */
                    AES_decrypt (inbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE, /* src: IV field in the buffer */
                                 &(sa->dec_ivec), /* dst:  IV field in SA-structure getting used in the next step, i.e. cbc decryption of data */
                                 &(sa->dec_key_2)); /* using secondary key K2 */

                    /* save the decrypted initialization vector for later use in message authentication verification as sa->dec_ivec gets scrambled during cbc process */
                    memcpy (&iv, &(sa->dec_ivec), N2N_AES_IVEC_SIZE);

                    /* decrypt payload in cbc mode using secondary key K2 */
                    AES_cbc_encrypt (inbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + N2N_AES_MSGAUTH_SIZE + N2N_AES_IVEC_SIZE, /* src: payload from buffer */
                                     assembly, /* dst: assembly */
                                     len, 
                                     &(sa->dec_key), /* using key K1 */
                                     &(sa->dec_ivec),/* using the already decrypted IV */
                                     0); /* = decryption */

                    data_len = ntohs(*(uint16_t*)assembly);

                    /* the transmitted data length (data_len + its own field size) should match the encrypted data length (len) +/- blocksize */
                    if ( (len >= (data_len + TRANSOP_AES_DATA_LEN)) && ( (len - AES_BLOCK_SIZE) < (data_len + TRANSOP_AES_DATA_LEN) ) )
                    {
                        /* strictly speaking for this to be an ethernet packet
                         * it is going to need to be even bigger; but this is
                         * enough to prevent segfaults. */

                         /* verify message authentication code by
                            1. cbc'ing the decrypted data again completly using K1,
                            2. encrypting the last cipher block using secondary key K2, and
                            3. finally, comparing with the trasmitted message authentication code */

			 /* encrypt payload in cbc mode again using key K1 */
                         AES_cbc_encrypt (assembly, /* src: the already decrypted data in assembly buffer */
                                          assembly2, /* dst: assembly2 */
                                          len,
                                          &(sa->enc_key), /* using key K1 */
                                          &iv,/* using the saved, already derypted IV from above */
                                          1); /* = encryption */

                         /* encrypt the last cipher block again using K2 to generate ECBC-MAC for message authentication code */
                         AES_encrypt (assembly2 + len - AES_BLOCK_SIZE, /* src: last cipher block */
                                      assembly2 + len - AES_BLOCK_SIZE, /* dst: just overwrite in the same place as assembly2 is not needed anymore*/
                                      &(sa->enc_key_2)); /* using the secondary key K2 */

                        /* compare the just generated ECBC-MAC to the one transmitted in the packet */
                        if (!memcmp (assembly2 + len - AES_BLOCK_SIZE, inbuf+ TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE, N2N_AES_MSGAUTH_SIZE))
                        {
                            len = data_len;

                            /* Step over data length value */
                            memcpy( outbuf, 
                                    assembly + TRANSOP_AES_DATA_LEN, 
                                    len );
                        }
                        else
                        {
                            traceEvent( TRACE_WARNING, "Message authentication failed." );
                        }
                    }
                    else
                    {
                        traceEvent( TRACE_WARNING, "The length of received encrypted data does not even roughly match the alleged UDP payload size." );
                    }
                }
                else
                {
                    traceEvent( TRACE_WARNING, "Encrypted length %d is not a multiple of AES_BLOCK_SIZE (%d)", len, AES_BLOCK_SIZE );
                    len = 0;
                }
            }
            else
            {
                /* Wrong security association; drop the packet as it is undecodable. */
                traceEvent( TRACE_ERROR, "decode_aes SA number %lu not found.", sa_rx );

                /* REVISIT: should be able to load a new SA at this point to complete the decoding. */
            }
        }
        else
        {
            /* Wrong security association; drop the packet as it is undecodable. */
            traceEvent( TRACE_ERROR, "decode_aes unsupported aes version %u.", aes_enc_ver );

            /* REVISIT: should be able to load a new SA at this point to complete the decoding. */
        }        
    }
    else
    {
        traceEvent( TRACE_ERROR, "decode_aes inbuf wrong size (%ul) to decrypt.", in_len );
    }

    return len;
}

/* NOTE: the caller should adjust priv->num_sa accordingly */
static int setup_aes_key(transop_aes_t *priv, uint8_t *keybuf, ssize_t pstat, size_t sa_num) {
    /* pstat is number of bytes read into keybuf. */
    sa_aes_t * sa = &(priv->sa[sa_num]);
    size_t aes_keysize_bytes;
    size_t aes_keysize_bits;
    uint8_t * hashed_keybuf;

    /* Clear out any old possibly longer key matter. */
    memset( &(sa->enc_key), 0, sizeof(AES_KEY) );
    memset( &(sa->dec_key), 0, sizeof(AES_KEY) );

    aes_keysize_bytes = aes_best_keysize(pstat);
    aes_keysize_bits = 8 * aes_keysize_bytes;

    /* The aes_keysize_bytes may differ from pstat, therefore hash */
    /* HASH_SIZE > KEY_SIZE, essential to security  */
    hashed_keybuf = calloc(1, SHA512_DIGEST_LENGTH);
    if(!hashed_keybuf)
        return(1);
    SHA512(keybuf, pstat, hashed_keybuf);

    /* Use N2N_MAX_KEYSIZE because the AES key needs to be of fixed
     * size. If fewer bits specified then the rest will be
     * zeroes. AES acceptable key sizes are 128, 192 and 256
     * bits. */
    AES_set_encrypt_key(hashed_keybuf, aes_keysize_bits, &(sa->enc_key));
    AES_set_decrypt_key(hashed_keybuf, aes_keysize_bits, &(sa->dec_key));
    /* ivecs remain untouched here and get set directly before encryption or decryption respectively */
    /* use the last part of the hash as secondary key */
    AES_set_encrypt_key(hashed_keybuf+SHA512_DIGEST_LENGTH-aes_keysize_bytes, aes_keysize_bits, &(sa->enc_key_2));
    AES_set_decrypt_key(hashed_keybuf+SHA512_DIGEST_LENGTH-aes_keysize_bytes, aes_keysize_bits, &(sa->dec_key_2));
    
    traceEvent( TRACE_DEBUG, "transop_addspec_aes sa_id=%u, %u bits data=%s.\n",
                priv->sa[sa_num].sa_id, aes_keysize_bits, keybuf);
    free(hashed_keybuf);

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
            memset( &(sa->enc_key), 0, sizeof(AES_KEY) );
            memset( &(sa->enc_ivec), 0, N2N_AES_IVEC_SIZE );
            memset( &(sa->dec_key), 0, sizeof(AES_KEY) );
            memset( &(sa->dec_ivec), 0, N2N_AES_IVEC_SIZE );
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
                           uint32_t encrypt_pwd_len) {
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

