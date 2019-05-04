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

#define N2N_AES_TRANSFORM_VERSION       1  /* version of the transform encoding */
#define N2N_AES_IVEC_SIZE               32 /* Enough space for biggest AES ivec */

#define AES256_KEY_BYTES (256/8)
#define AES192_KEY_BYTES (192/8)
#define AES128_KEY_BYTES (128/8)

typedef unsigned char n2n_aes_ivec_t[N2N_AES_IVEC_SIZE];

struct sa_aes
{
    n2n_cipherspec_t    spec;           /* cipher spec parameters */
    n2n_sa_t            sa_id;          /* security association index */
    AES_KEY             enc_key;        /* tx key */
    AES_KEY             dec_key;        /* tx key */
    AES_KEY             iv_enc_key;     /* key used to encrypt the IV */
    uint8_t             iv_ext_val[AES128_KEY_BYTES]; /* key used to extend the random IV seed to full block size */
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
    u_int8_t            psk_mode;
};

typedef struct transop_aes transop_aes_t;

static ssize_t aes_find_sa( const transop_aes_t * priv, const n2n_sa_t req_id );
static int setup_aes_key(transop_aes_t *priv, const uint8_t *key, ssize_t key_size, size_t sa_num);

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

static size_t aes_choose_tx_sa( transop_aes_t * priv, const u_int8_t * peer_mac ) {
    return priv->tx_sa; /* set in tick */
}

static ssize_t aes_choose_rx_sa( transop_aes_t * priv, const u_int8_t * peer_mac, ssize_t sa_rx) {
    if(!priv->psk_mode)
        return aes_find_sa(priv, sa_rx);
    else
        /* NOTE the sa_rx of the packet is ignored in this case */
        return 0;
}

/* AES plaintext preamble */
#define TRANSOP_AES_VER_SIZE     1       /* Support minor variants in encoding in one module. */
#define TRANSOP_AES_SA_SIZE      4
#define TRANSOP_AES_IV_SEED_SIZE 8
#define TRANSOP_AES_PREAMBLE_SIZE (TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + TRANSOP_AES_IV_SEED_SIZE)

/* AES ciphertext preamble */
#define TRANSOP_AES_NONCE_SIZE   4

/* Return the best acceptable AES key size (in bytes) given an input keysize. 
 *
 * The value returned will be one of AES128_KEY_BYTES, AES192_KEY_BYTES or
 * AES256_KEY_BYTES.
 */
static size_t aes_best_keysize(size_t numBytes)
{
    if (numBytes >= AES256_KEY_BYTES )
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

static void set_aes_cbc_iv(sa_aes_t *sa, n2n_aes_ivec_t ivec, uint64_t iv_seed) {
    uint8_t iv_full[AES_BLOCK_SIZE];

    /* Extend the seed to full block size via the fixed ext value */
    memcpy(iv_full, sa->iv_ext_val, sizeof(iv_seed)); // note: only 64bits used of 128 available
    memcpy(iv_full + sizeof(iv_seed), &iv_seed, sizeof(iv_seed));

    /* Encrypt the IV with secret key to make it unpredictable.
     * As discussed in https://github.com/ntop/n2n/issues/72, it's important to
     * have an unpredictable IV since the initial part of the packet plaintext
     * can be easily reconstructed from plaintext headers and used by an attacker
     * to perform differential analysis.
     */
    AES_ecb_encrypt(iv_full, ivec, &sa->iv_enc_key, AES_ENCRYPT);
}

/** The aes packet format consists of:
 *
 *  - a 8-bit aes encoding version in clear text
 *  - a 32-bit SA number in clear text
 *  - a 64-bit random IV seed
 *  - ciphertext encrypted from a 32-bit nonce followed by the payload.
 *
 *  [V|SSSS|II|nnnnDDDDDDDDDDDDDDDDDDDDD]
 *            |<------ encrypted ------>|
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
    uint8_t assembly[N2N_PKT_BUF_SIZE] = {0};
    uint32_t * pnonce;

    if ( (in_len + TRANSOP_AES_NONCE_SIZE) <= N2N_PKT_BUF_SIZE )
    {
        if ( (in_len + TRANSOP_AES_NONCE_SIZE + TRANSOP_AES_PREAMBLE_SIZE) <= out_len )
        {
            int len=-1;
            size_t idx=0;
            sa_aes_t * sa;
            size_t tx_sa_num = 0;
            uint64_t iv_seed = 0;
            uint8_t padding = 0;
            n2n_aes_ivec_t enc_ivec = {0};

            /* The transmit sa is periodically updated */
            tx_sa_num = aes_choose_tx_sa( priv, peer_mac );

            sa = &(priv->sa[tx_sa_num]); /* Proper Tx SA index */
        
            traceEvent( TRACE_DEBUG, "encode_aes %lu with SA %lu.", in_len, sa->sa_id );
            
            /* Encode the aes format version. */
            encode_uint8( outbuf, &idx, N2N_AES_TRANSFORM_VERSION );

            /* Encode the security association (SA) number */
            encode_uint32( outbuf, &idx, sa->sa_id );

            /* Generate and encode the IV seed.
             * Using two calls to rand() because RAND_MAX is usually < 64bit
             * (e.g. linux) and sometimes < 32bit (e.g. Windows).
             */
            ((uint32_t*)&iv_seed)[0] = rand();
            ((uint32_t*)&iv_seed)[1] = rand();
            encode_buf(outbuf, &idx, &iv_seed, sizeof(iv_seed));

            /* Encrypt the assembly contents and write the ciphertext after the SA. */
            len = in_len + TRANSOP_AES_NONCE_SIZE;

            /* The assembly buffer is a source for encrypting data. The nonce is
             * written in first followed by the packet payload. The whole
             * contents of assembly are encrypted. */
            pnonce = (uint32_t *)assembly;
            *pnonce = rand();
            memcpy( assembly + TRANSOP_AES_NONCE_SIZE, inbuf, in_len );

            /* Need at least one encrypted byte at the end for the padding. */
            len2 = ( (len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE; /* Round up to next whole AES adding at least one byte. */
            padding = (len2-len);
            assembly[len2 - 1] = padding;
            traceEvent( TRACE_DEBUG, "padding = %u, seed = %016lx", padding, iv_seed );

            set_aes_cbc_iv(sa, enc_ivec, iv_seed);

            AES_cbc_encrypt( assembly, /* source */
                             outbuf + TRANSOP_AES_PREAMBLE_SIZE, /* dest */
                             len2, /* enc size */
                             &(sa->enc_key), enc_ivec, AES_ENCRYPT );

            len2 += TRANSOP_AES_PREAMBLE_SIZE; /* size of data carried in UDP. */
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


/* See transop_encode_aes for packet format */
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

    if ( ( (in_len - TRANSOP_AES_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE ) /* Cipher text fits in assembly */
         && (in_len >= (TRANSOP_AES_PREAMBLE_SIZE + TRANSOP_AES_NONCE_SIZE) ) /* Has at least version, SA, iv seed and nonce */
        )
    {
        n2n_sa_t sa_rx;
        ssize_t sa_idx=-1;
        size_t rem=in_len;
        size_t idx=0;
        uint8_t aes_enc_ver=0;
        uint64_t iv_seed=0;

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

                /* Get the IV seed */
                decode_buf((uint8_t *)&iv_seed, sizeof(iv_seed), inbuf, &rem, &idx);

                traceEvent( TRACE_DEBUG, "decode_aes %lu with SA %lu and seed %016lx", in_len, sa->sa_id, iv_seed );

                len = (in_len - TRANSOP_AES_PREAMBLE_SIZE);
                
                if ( 0 == (len % AES_BLOCK_SIZE ) )
                {
                    uint8_t padding;
                    n2n_aes_ivec_t dec_ivec = {0};

                    set_aes_cbc_iv(sa, dec_ivec, iv_seed);

                    AES_cbc_encrypt( (inbuf + TRANSOP_AES_PREAMBLE_SIZE),
                                     assembly, /* destination */
                                     len, 
                                     &(sa->dec_key),
                                     dec_ivec, AES_DECRYPT );

                    /* last byte is how much was padding: max value should be
                     * AES_BLOCKSIZE-1 */
                    padding = assembly[ len-1 ] & 0xff; 

                    if ( len >= (padding + TRANSOP_AES_NONCE_SIZE))
                    {
                        /* strictly speaking for this to be an ethernet packet
                         * it is going to need to be even bigger; but this is
                         * enough to prevent segfaults. */
                        traceEvent( TRACE_DEBUG, "padding = %u", padding );
                        len -= padding;

                        len -= TRANSOP_AES_NONCE_SIZE; /* size of ethernet packet */

                        /* Step over 4-byte random nonce value */
                        memcpy( outbuf, 
                                assembly + TRANSOP_AES_NONCE_SIZE, 
                                len );
                    }
                    else
                    {
                        traceEvent( TRACE_WARNING, "UDP payload decryption failed." );
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

struct sha512_keybuf {
    uint8_t enc_dec_key[AES256_KEY_BYTES];          /* The key to use for AES CBC encryption/decryption */
    uint8_t iv_enc_key[AES128_KEY_BYTES];           /* The key to use to encrypt the IV with AES ECB */
    uint8_t iv_ext_val[AES128_KEY_BYTES];           /* A value to extend the IV seed */
}; /* size: SHA512_DIGEST_LENGTH */

/* NOTE: the caller should adjust priv->num_sa accordingly */
static int setup_aes_key(transop_aes_t *priv, const uint8_t *key, ssize_t key_size, size_t sa_num) {
    sa_aes_t * sa = &(priv->sa[sa_num]);
    size_t aes_keysize_bytes;
    size_t aes_keysize_bits;
    struct sha512_keybuf keybuf;

    /* Clear out any old possibly longer key matter. */
    memset( &(sa->enc_key), 0, sizeof(sa->enc_key) );
    memset( &(sa->dec_key), 0, sizeof(sa->dec_key) );
    memset( &(sa->iv_enc_key), 0, sizeof(sa->iv_enc_key) );
    memset( &(sa->iv_ext_val), 0, sizeof(sa->iv_ext_val) );

    /* We still use aes_best_keysize (even not necessary since we hash the key
     * into the 256bits enc_dec_key) to let the users choose the degree of encryption.
     * Long keys will pick AES192 or AES256 with more robust but expensive encryption.
     */
    aes_keysize_bytes = aes_best_keysize(key_size);
    aes_keysize_bits = 8 * aes_keysize_bytes;

    /* Hash the main key to generate subkeys */
    SHA512(key, key_size, (u_char*)&keybuf);

    /* setup of enc_key/dec_key, used for the CBC encryption */
    AES_set_encrypt_key(keybuf.enc_dec_key, aes_keysize_bits, &(sa->enc_key));
    AES_set_decrypt_key(keybuf.enc_dec_key, aes_keysize_bits, &(sa->dec_key));

    /* setup of iv_enc_key and iv_ext_val, used for generating the CBC IV */
    AES_set_encrypt_key(keybuf.iv_enc_key, sizeof(keybuf.iv_enc_key) * 8, &(sa->iv_enc_key));
    memcpy(sa->iv_ext_val, keybuf.iv_ext_val, sizeof(keybuf.iv_ext_val));

    traceEvent( TRACE_DEBUG, "transop_addspec_aes sa_id=%u, %u bits key=%s.\n",
                priv->sa[sa_num].sa_id, aes_keysize_bits, key);

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
            memset( &(sa->enc_key), 0, sizeof(sa->enc_key) );
            memset( &(sa->dec_key), 0, sizeof(sa->dec_key) );
            memset( &(sa->iv_enc_key), 0, sizeof(sa->iv_enc_key) );
            memset( &(sa->iv_ext_val), 0, sizeof(sa->iv_ext_val) );
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
    int retval = 1;
    transop_aes_t *priv = (transop_aes_t *)ttt->priv;

    if(ttt->priv) {
        /* Replace the tick function with the PSK version of it */
        ttt->tick = transop_tick_aes_psk;
        priv->psk_mode = 1;
        priv->num_sa=0;
        priv->tx_sa=0;

        /* Setup the key to use for encryption/decryption */
        add_aes_key(priv, encrypt_pwd, encrypt_pwd_len);

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

