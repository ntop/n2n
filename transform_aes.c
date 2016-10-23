/* (c) 2009 Richard Andrews <andrews@ntop.org> */
/* Contributions from:
 *     - Jozef Kralik
 */

#include "n2n.h"
#include "n2n_transforms.h"

#if defined(N2N_HAVE_AES)


#include "openssl/aes.h"
#ifndef _MSC_VER
/* Not included in Visual Studio 2008 */
#include <strings.h> /* index() */
#endif

#define N2N_AES_NUM_SA                  32 /* space for SAa */

#define N2N_AES_TRANSFORM_VERSION       1  /* version of the transform encoding */
#define N2N_AES_IVEC_SIZE               32 /* Enough space for biggest AES ivec */

typedef unsigned char n2n_aes_ivec_t[N2N_AES_IVEC_SIZE];

struct sa_aes
{
    n2n_cipherspec_t    spec;           /* cipher spec parameters */
    n2n_sa_t            sa_id;          /* security association index */
    AES_KEY             enc_key;        /* tx key */
    n2n_aes_ivec_t      enc_ivec;       /* tx CBC state */
    AES_KEY             dec_key;        /* tx key */
    n2n_aes_ivec_t      dec_ivec;       /* tx CBC state */
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
};

typedef struct transop_aes transop_aes_t;

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

static size_t aes_choose_tx_sa( transop_aes_t * priv )
{
    return priv->tx_sa; /* set in tick */
}

#define TRANSOP_AES_VER_SIZE     1       /* Support minor variants in encoding in one module. */
#define TRANSOP_AES_NONCE_SIZE   4
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

/** The aes packet format consists of:
 *
 *  - a 8-bit aes encoding version in clear text
 *  - a 32-bit SA number in clear text
 *  - ciphertext encrypted from a 32-bit nonce followed by the payload.
 *
 *  [V|SSSS|nnnnDDDDDDDDDDDDDDDDDDDDD]
 *         |<------ encrypted ------>|
 */
static int transop_encode_aes( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len )
{
    int len2=-1;
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE];
    uint32_t * pnonce;

    if ( (in_len + TRANSOP_AES_NONCE_SIZE) <= N2N_PKT_BUF_SIZE )
    {
        if ( (in_len + TRANSOP_AES_NONCE_SIZE + TRANSOP_AES_SA_SIZE + TRANSOP_AES_VER_SIZE) <= out_len )
        {
            int len=-1;
            size_t idx=0;
            sa_aes_t * sa;
            size_t tx_sa_num = 0;

            /* The transmit sa is periodically updated */
            tx_sa_num = aes_choose_tx_sa( priv );

            sa = &(priv->sa[tx_sa_num]); /* Proper Tx SA index */
        
            traceEvent( TRACE_DEBUG, "encode_aes %lu with SA %lu.", in_len, sa->sa_id );
            
            /* Encode the aes format version. */
            encode_uint8( outbuf, &idx, N2N_AES_TRANSFORM_VERSION );

            /* Encode the security association (SA) number */
            encode_uint32( outbuf, &idx, sa->sa_id );

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
            assembly[ len2-1 ]=(len2-len);
            traceEvent( TRACE_DEBUG, "padding = %u", assembly[ len2-1 ] );

            memset( &(sa->enc_ivec), 0, sizeof(N2N_AES_IVEC_SIZE) );
            AES_cbc_encrypt( assembly, /* source */
                             outbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE, /* dest */
                             len2, /* enc size */
                             &(sa->enc_key), sa->enc_ivec, 1 /* encrypt */ );

            len2 += TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE; /* size of data carried in UDP. */
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
 *  - ciphertext encrypted from a 32-bit nonce followed by the payload.
 *
 *  [V|SSSS|nnnnDDDDDDDDDDDDDDDDDDDDD]
 *         |<------ encrypted ------>|
 */
static int transop_decode_aes( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len )
{
    int len=0;
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE];

    if ( ( (in_len - (TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE)) <= N2N_PKT_BUF_SIZE ) /* Cipher text fits in assembly */ 
         && (in_len >= (TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE + TRANSOP_AES_NONCE_SIZE) ) /* Has at least version, SA and nonce */
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

            sa_idx = aes_find_sa(priv, sa_rx);
            if ( sa_idx >= 0 )
            {
                sa_aes_t * sa = &(priv->sa[sa_idx]);

                traceEvent( TRACE_DEBUG, "decode_aes %lu with SA %lu.", in_len, sa_rx, sa->sa_id );

                len = (in_len - (TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE));
                
                if ( 0 == (len % AES_BLOCK_SIZE ) )
                {
                    uint8_t padding;

                    memset( &(sa->dec_ivec), 0, sizeof(N2N_AES_IVEC_SIZE) );
                    AES_cbc_encrypt( (inbuf + TRANSOP_AES_VER_SIZE + TRANSOP_AES_SA_SIZE),
                                     assembly, /* destination */
                                     len, 
                                     &(sa->dec_key),
                                     sa->dec_ivec, 0 /* decrypt */ );

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
                /* pstat is number of bytes read into keybuf. */
                sa_aes_t * sa = &(priv->sa[priv->num_sa]);
                size_t aes_keysize_bytes;
                size_t aes_keysize_bits;

                /* Clear out any old possibly longer key matter. */
                memset( &(sa->enc_key), 0, sizeof(AES_KEY) );
                memset( &(sa->dec_key), 0, sizeof(AES_KEY) );

                memset( &(sa->enc_ivec), 0, sizeof(N2N_AES_IVEC_SIZE) );
                memset( &(sa->dec_ivec), 0, sizeof(N2N_AES_IVEC_SIZE) );

                aes_keysize_bytes = aes_best_keysize(pstat);
                aes_keysize_bits = 8 * aes_keysize_bytes;

                /* Use N2N_MAX_KEYSIZE because the AES key needs to be of fixed
                 * size. If fewer bits specified then the rest will be
                 * zeroes. AES acceptable key sizes are 128, 192 and 256
                 * bits. */
                AES_set_encrypt_key( keybuf, aes_keysize_bits, &(sa->enc_key));
                AES_set_decrypt_key( keybuf, aes_keysize_bits, &(sa->dec_key));
                /* Leave ivecs set to all zeroes */
                
                traceEvent( TRACE_DEBUG, "transop_addspec_aes sa_id=%u, %u bits data=%s.\n",
                            priv->sa[priv->num_sa].sa_id, aes_keysize_bits, sep+1);
                
                ++(priv->num_sa);
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
        size_t i;
        sa_aes_t * sa=NULL;

        /* install the private structure. */
        ttt->priv = priv;
        priv->num_sa=0;
        priv->tx_sa=0; /* We will use this sa index for encoding. */

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
            memset( &(sa->enc_ivec), 0, sizeof(N2N_AES_IVEC_SIZE) );
            memset( &(sa->dec_key), 0, sizeof(AES_KEY) );
            memset( &(sa->dec_ivec), 0, sizeof(N2N_AES_IVEC_SIZE) );
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

#endif /* #if defined(N2N_HAVE_AES) */

