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

#ifdef N2N_HAVE_AES

#include <openssl/aes.h>
#include <openssl/sha.h>

#define N2N_AES_TRANSFORM_VERSION       1  /* version of the transform encoding */
#define N2N_AES_IVEC_SIZE               (AES_BLOCK_SIZE)

#define AES256_KEY_BYTES (256/8)
#define AES192_KEY_BYTES (192/8)
#define AES128_KEY_BYTES (128/8)

/* AES plaintext preamble */
#define TRANSOP_AES_VER_SIZE     1       /* Support minor variants in encoding in one module. */
#define TRANSOP_AES_IV_SEED_SIZE 8	/* size of transmitted random part of IV in bytes; leave it set to 8 for now */
#define TRANSOP_AES_IV_PADDING_SIZE (N2N_AES_IVEC_SIZE - TRANSOP_AES_IV_SEED_SIZE)
#define TRANSOP_AES_IV_KEY_BYTES (AES128_KEY_BYTES) /* use AES128 for IV encryption */
#define TRANSOP_AES_PREAMBLE_SIZE (TRANSOP_AES_VER_SIZE + TRANSOP_AES_IV_SEED_SIZE)

/* AES ciphertext preamble */
#define TRANSOP_AES_ENC_DATA_FLAGS_SIZE   		1	/* this 8-bit flag indicates any special treatment of the following data
								   applied before encryption at the beginning of the data block */
#define TRANSOP_AES_ENC_DATA_FLAGS_NONE			0	/* no special data treatment */
#define TRANSOP_AES_ENC_DATA_FLAGS_COMPRESSION_MINILZO	1	/* minilzo compression */

#define COMPRESSION_ENABLED	/* defines if compression is enabled for outgoing packets; comment out for no compression */
				/* compressed packets can always be decoded */

/* Work-memory needed for compression. Allocate memory in units
 * of 'lzo_align_t' (instead of 'char') to make sure it is properly aligned.
 */
#ifdef COMPRESSION_ENABLED
#define HEAP_ALLOC(var,size) lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]
static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);
#endif

typedef unsigned char n2n_aes_ivec_t[N2N_AES_IVEC_SIZE];

typedef struct transop_aes {
    AES_KEY             enc_key;        /* tx key */
    AES_KEY             dec_key;        /* tx key */
    AES_KEY             iv_enc_key;     /* key used to encrypt the IV */
    uint8_t             iv_pad_val[TRANSOP_AES_IV_PADDING_SIZE]; /* key used to pad the random IV seed to full block size */
} transop_aes_t;

static int transop_deinit_aes(n2n_trans_op_t *arg) {
    transop_aes_t *priv = (transop_aes_t *)arg->priv;

    if(priv)
        free(priv);

    return 0;
}

static void set_aes_cbc_iv(transop_aes_t *priv, n2n_aes_ivec_t ivec, uint64_t iv_seed) {
    uint8_t iv_full[N2N_AES_IVEC_SIZE];

    /* Extend the seed to full block size with padding value */
    memcpy(iv_full, priv->iv_pad_val, TRANSOP_AES_IV_PADDING_SIZE);
    memcpy(iv_full + TRANSOP_AES_IV_PADDING_SIZE, &iv_seed, TRANSOP_AES_IV_SEED_SIZE);

    /* Encrypt the IV with secret key to make it unpredictable.
     * As discussed in https://github.com/ntop/n2n/issues/72, it's important to
     * have an unpredictable IV since the initial part of the packet plaintext
     * can be easily reconstructed from plaintext headers and used by an attacker
     * to perform differential analysis.
     */
    AES_ecb_encrypt(iv_full, ivec, &priv->iv_enc_key, AES_ENCRYPT);
}

/** The aes packet format consists of:
 *
 *  - a 8-bit aes encoding version in clear text
 *  - a 64-bit random IV seed
 *  - a 8-bit data flags field; encrypted together with the following...
 *  - UDP payload data
 *
 *  [V|II|cDDDDDDDDDDDDDDDDDDDD]
 *       |<---- encrypted ---->|
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

    if ( (in_len + TRANSOP_AES_ENC_DATA_FLAGS_SIZE) <= N2N_PKT_BUF_SIZE) {
        if ( (in_len + TRANSOP_AES_PREAMBLE_SIZE + TRANSOP_AES_ENC_DATA_FLAGS_SIZE) <= out_len) {
            int len=-1;
            size_t idx=0;
            uint64_t iv_seed = 0;
            uint8_t padding = 0;
            n2n_aes_ivec_t enc_ivec = {0};

            traceEvent(TRACE_DEBUG, "encode_aes %lu", in_len);

            /* Encode the aes format version. */
            encode_uint8( outbuf, &idx, N2N_AES_TRANSFORM_VERSION);

            /* Generate and encode the IV seed.
             * Using two calls to rand() because RAND_MAX is usually < 64bit
             * (e.g. linux) and sometimes < 32bit (e.g. Windows).
             */
            iv_seed = ((((uint64_t)rand() & 0xFFFFFFFF)) << 32) | rand();
            encode_buf(outbuf, &idx, &iv_seed, TRANSOP_AES_IV_SEED_SIZE);

	    len = in_len;
#ifdef COMPRESSION_ENABLED
	    /* test for compressability and set data flags accordingly */
	    uint8_t * compression_buffer;
	    lzo_uint compression_len;
 	    uint8_t *data_flags;
	    data_flags = (uint8_t *)assembly;
	    *data_flags = 0x00;
            compression_buffer = malloc (in_len + in_len / 16 + 64 + 3);
            if (lzo1x_1_compress(inbuf, in_len, compression_buffer, &compression_len, wrkmem) == LZO_E_OK) {
                /* compressible? then set compression type (TRANSOP_AES_ENC_DATA_FLAGS_COMPRESSION_MINILZO)! */
		if (compression_len < in_len) {
		    *data_flags = TRANSOP_AES_ENC_DATA_FLAGS_COMPRESSION_MINILZO;
		    /* correct the previously calculated length */
		    len -= (in_len - compression_len);
		    traceEvent (TRACE_DEBUG, "payload compression: compressed %u bytes to %u bytes\n",
                                             in_len, compression_len);
		}
            }
            /* The assembly buffer will be the source for encrypting data. */
            if (*data_flags == TRANSOP_AES_ENC_DATA_FLAGS_COMPRESSION_MINILZO) {
                memcpy( assembly + TRANSOP_AES_ENC_DATA_FLAGS_SIZE, compression_buffer, compression_len );
                free (compression_buffer);
	    } else
#endif
                memcpy( assembly + TRANSOP_AES_ENC_DATA_FLAGS_SIZE, inbuf, in_len );

	    /* len is set to the length of the cipher plain text to be encrpyted
               which is (in this case) identical to (maybe compressed) packet lentgh plus
	       the length of compression indication field */
            len += TRANSOP_AES_ENC_DATA_FLAGS_SIZE;

            /* Need at least one encrypted byte at the end for the padding. */
            len2 = ( (len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE; /* Round up to next whole AES adding at least one byte. */
            padding = (len2-len);
            assembly[len2 - 1] = padding;
            traceEvent(TRACE_DEBUG, "padding = %u, seed = %016llx", padding, iv_seed);

            set_aes_cbc_iv(priv, enc_ivec, iv_seed);

            /* Encrypt the assembly contents and write the ciphertext after the iv seed. */
            AES_cbc_encrypt( assembly, /* source */
                             outbuf + TRANSOP_AES_PREAMBLE_SIZE, /* dest */
                             len2, /* enc size */
                             &(priv->enc_key), enc_ivec, AES_ENCRYPT);

            len2 += TRANSOP_AES_PREAMBLE_SIZE; /* size of data carried in UDP. */
        } else
            traceEvent(TRACE_ERROR, "encode_aes outbuf too small.");
    } else
        traceEvent(TRACE_ERROR, "encode_aes inbuf too big to encrypt.");

    return len2;
}

/* See transop_encode_aes for packet format */
static int transop_decode_aes( n2n_trans_op_t * arg,
                                   uint8_t * outbuf,
                                   size_t out_len,
                                   const uint8_t * inbuf,
                                   size_t in_len,
                                   const uint8_t * peer_mac) {
    int len=0;
    transop_aes_t * priv = (transop_aes_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE];

    if ( ( (in_len - TRANSOP_AES_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* Cipher text fits in assembly */
         && (in_len >= TRANSOP_AES_PREAMBLE_SIZE + TRANSOP_AES_ENC_DATA_FLAGS_SIZE) /* Has at least version, iv seed, data flags */
       )
    {
        size_t rem=in_len;
        size_t idx=0;
        uint8_t aes_enc_ver=0;
        uint64_t iv_seed=0;

        /* Get the encoding version to make sure it is supported */
        decode_uint8( &aes_enc_ver, inbuf, &rem, &idx );

        if ( N2N_AES_TRANSFORM_VERSION == aes_enc_ver) {
            /* Get the IV seed */
            decode_buf((uint8_t *)&iv_seed, TRANSOP_AES_IV_SEED_SIZE, inbuf, &rem, &idx);

            traceEvent(TRACE_DEBUG, "decode_aes %lu with seed %016llx", in_len, iv_seed);

            len = (in_len - TRANSOP_AES_PREAMBLE_SIZE);

            if ( 0 == (len % AES_BLOCK_SIZE)) {
                uint8_t padding;
                n2n_aes_ivec_t dec_ivec = {0};

                set_aes_cbc_iv(priv, dec_ivec, iv_seed);

                AES_cbc_encrypt( (inbuf + TRANSOP_AES_PREAMBLE_SIZE),
                                 assembly, /* destination */
                                 len,
                                 &(priv->dec_key),
                                 dec_ivec, AES_DECRYPT);

                /* last byte is how much was padding: max value should be
                 * AES_BLOCKSIZE-1 */
                padding = assembly[ len-1 ] & 0xff;

                if ( len >= (padding + TRANSOP_AES_ENC_DATA_FLAGS_SIZE) )
                {
                    /* strictly speaking for this to be an ethernet packet
                     * it is going to need to be even bigger; but this is
                     * enough to prevent segfaults. */
                    traceEvent(TRACE_DEBUG, "padding = %u", padding);
                    len -= padding;
		    len -= TRANSOP_AES_ENC_DATA_FLAGS_SIZE;

		    /* decompress if necessary */
		    uint8_t data_flags = assembly[0];
		    uint8_t * deflation_buffer;
		    lzo_uint deflated_len;
		    if (data_flags == TRANSOP_AES_ENC_DATA_FLAGS_COMPRESSION_MINILZO) {
			deflation_buffer = malloc (N2N_PKT_BUF_SIZE);
                        /* decompress */
			lzo1x_decompress (assembly + TRANSOP_AES_ENC_DATA_FLAGS_SIZE, len, deflation_buffer, &deflated_len, NULL);
			traceEvent (TRACE_DEBUG, "payload compression: deflated %u bytes to %u bytes",
                                                 len, (int)deflated_len);
                        memcpy( outbuf,
                                deflation_buffer,
                                deflated_len );
			free (deflation_buffer);
			len = deflated_len;
		    } else if (data_flags == TRANSOP_AES_ENC_DATA_FLAGS_NONE) {
                        /* Step over 1-byte data flags */
                        memcpy( outbuf,
                                assembly + TRANSOP_AES_ENC_DATA_FLAGS_SIZE,
                                len );
		    } else {
			traceEvent (TRACE_DEBUG, "payload treatment: unknown data flags %u", data_flags);
		    }
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

static int setup_aes_key(transop_aes_t *priv, const uint8_t *key, ssize_t key_size) {
    size_t aes_key_size_bytes;
    size_t aes_key_size_bits;

    uint8_t key_mat_buf[SHA512_DIGEST_LENGTH + SHA256_DIGEST_LENGTH];
    size_t key_mat_buf_length;

    /* Clear out any old possibly longer key matter. */
    memset( &(priv->enc_key), 0, sizeof(priv->enc_key) );
    memset( &(priv->dec_key), 0, sizeof(priv->dec_key) );
    memset( &(priv->iv_enc_key), 0, sizeof(priv->iv_enc_key) );
    memset( &(priv->iv_pad_val), 0, sizeof(priv->iv_pad_val) );

    /* Let the user choose the degree of encryption:
     * Long input keys will pick AES192 or AES256 with more robust but expensive encryption.
     *
     * The input key always gets hashed to make a more unpredictable use of the key space and
     * also to derive some additional material (key for IV encrpytion, IV padding).
     *
     * The following scheme for key setup was discussed on github:
     * https://github.com/ntop/n2n/issues/101
     */

    /* create a working buffer of maximal occuring hashes size and generate
     * the hashes for the aes key material, key_mat_buf_lengh indicates the
     * actual "filling level" of the buffer
     */

    if (key_size >= 65)
    {
        aes_key_size_bytes = AES256_KEY_BYTES;
        SHA512(key, key_size, key_mat_buf);
        key_mat_buf_length = SHA512_DIGEST_LENGTH;
    }
    else if (key_size >= 44)
    {
        aes_key_size_bytes = AES192_KEY_BYTES;
        SHA384(key, key_size, key_mat_buf);
	/* append a hash of the first hash to create enough material for IV padding */
        SHA256(key_mat_buf, SHA384_DIGEST_LENGTH, key_mat_buf + SHA384_DIGEST_LENGTH);
	key_mat_buf_length = SHA384_DIGEST_LENGTH + SHA256_DIGEST_LENGTH;
    }
    else
    {
        aes_key_size_bytes = AES128_KEY_BYTES;
        SHA256(key, key_size, key_mat_buf);
	/* append a hash of the first hash to create enough material for IV padding */
        SHA256(key_mat_buf, SHA256_DIGEST_LENGTH, key_mat_buf + SHA256_DIGEST_LENGTH);
        key_mat_buf_length = 2 * SHA256_DIGEST_LENGTH;
    }

    /* is there enough material available? */
    if (key_mat_buf_length < (aes_key_size_bytes + TRANSOP_AES_IV_KEY_BYTES + TRANSOP_AES_IV_PADDING_SIZE))
    {
        /* this should never happen */
	traceEvent( TRACE_ERROR, "AES missing %u bits hashed key material\n",
                    (aes_key_size_bytes + TRANSOP_AES_IV_KEY_BYTES + TRANSOP_AES_IV_PADDING_SIZE - key_mat_buf_length) * 8);
	return(1);
    }

    /* setup of enc_key/dec_key, used for the CBC encryption */
    aes_key_size_bits = 8 * aes_key_size_bytes;
    AES_set_encrypt_key(key_mat_buf, aes_key_size_bits, &(priv->enc_key));
    AES_set_decrypt_key(key_mat_buf, aes_key_size_bits, &(priv->dec_key));

    /* setup of iv_enc_key (AES128 key) and iv_pad_val, used for generating the CBC IV */
    AES_set_encrypt_key(key_mat_buf + aes_key_size_bytes, TRANSOP_AES_IV_KEY_BYTES * 8, &(priv->iv_enc_key));
    memcpy(priv->iv_pad_val, key_mat_buf + aes_key_size_bytes + TRANSOP_AES_IV_KEY_BYTES, TRANSOP_AES_IV_PADDING_SIZE);

    traceEvent(TRACE_DEBUG, "AES %u bits setup completed\n",
                aes_key_size_bits);

    return(0);
}

static void transop_tick_aes(n2n_trans_op_t * arg, time_t now) {}

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

  /* Setup the key */
  return(setup_aes_key(priv, encrypt_key, encrypt_key_len));
}

#endif /* N2N_HAVE_AES */
