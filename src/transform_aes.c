/**
 * (C) 2007-22 - ntop.org and contributors
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


// size of random value prepended to plaintext defaults to AES BLOCK_SIZE;
// gradually abandoning security, lower values could be chosen;
// however, minimum transmission size with cipher text stealing scheme is one
// block; as network packets should be longer anyway, only low level programmer
// might encounter an issue with lower values here
#define AES_PREAMBLE_SIZE       (AES_BLOCK_SIZE)


// cts/cbc mode is being used with random value prepended to plaintext
// instead of iv so, actual iv is aes_null_iv
const uint8_t aes_null_iv[AES_IV_SIZE] = { 0 };

typedef struct transop_aes {
    aes_context_t       *ctx;
} transop_aes_t;


static int transop_deinit_aes (n2n_trans_op_t *arg) {

    transop_aes_t *priv = (transop_aes_t *)arg->priv;

    if(priv) {
        if(priv->ctx)
            aes_deinit(priv->ctx);
        free(priv);
    }

    return 0;
}


// the aes packet format consists of
//
//  - a random AES_PREAMBLE_SIZE-sized value prepended to plaintext
//    encrypted together with the...
//  - ... payload data
//
//  [VV|DDDDDDDDDDDDDDDDDDDDD]
//  | <---- encrypted ---->  |
//
static int transop_encode_aes (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    transop_aes_t *priv = (transop_aes_t *)arg->priv;

    // the assembly buffer is a source for encrypting data
    // the whole contents of assembly are encrypted
    uint8_t assembly[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    int padded_len;
    uint8_t padding;
    uint8_t buf[AES_BLOCK_SIZE];

    if(in_len <= N2N_PKT_BUF_SIZE) {
        if((in_len + AES_PREAMBLE_SIZE + AES_BLOCK_SIZE) <= out_len) {
            traceEvent(TRACE_DEBUG, "transop_encode_aes %lu bytes plaintext", in_len);

            // full block sized random value (128 bit)
            encode_uint64(assembly, &idx, n2n_rand());
            encode_uint64(assembly, &idx, n2n_rand());

            // adjust for maybe differently chosen AES_PREAMBLE_SIZE
            idx = AES_PREAMBLE_SIZE;

            // the plaintext data
            encode_buf(assembly, &idx, inbuf, in_len);

            // round up to next whole AES block size
            padded_len = (((idx - 1) / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
            padding = (padded_len-idx);

            // pad the following bytes with zero, fixed length (AES_BLOCK_SIZE) seems to compile
            // to slightly faster code than run-time dependant 'padding'
            memset(assembly + idx, 0, AES_BLOCK_SIZE);

            aes_cbc_encrypt(outbuf, assembly, padded_len, aes_null_iv, priv->ctx);

            if(padding) {
                // exchange last two cipher blocks
                memcpy(buf, outbuf+padded_len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
                memcpy(outbuf + padded_len - AES_BLOCK_SIZE, outbuf + padded_len - 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
                memcpy(outbuf + padded_len - 2 * AES_BLOCK_SIZE, buf, AES_BLOCK_SIZE);
            }
        } else
            traceEvent(TRACE_ERROR, "transop_encode_aes outbuf too small");
    } else
    traceEvent(TRACE_ERROR, "transop_encode_aes inbuf too big to encrypt");

    return idx;
}


// see transop_encode_aes for packet format
static int transop_decode_aes (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    transop_aes_t *priv = (transop_aes_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE];

    uint8_t rest;
    size_t penultimate_block;
    uint8_t buf[AES_BLOCK_SIZE];
    int len = -1;

     if(((in_len - AES_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* cipher text fits in assembly */
      && (in_len >= AES_PREAMBLE_SIZE)                     /* has at least random number */
      && (in_len >= AES_BLOCK_SIZE)) {                     /* minimum size requirement for cipher text stealing */
        traceEvent(TRACE_DEBUG, "transop_decode_aes %lu bytes ciphertext", in_len);

        rest = in_len % AES_BLOCK_SIZE;
        if(rest) { /* cipher text stealing */
            penultimate_block = ((in_len / AES_BLOCK_SIZE) - 1) * AES_BLOCK_SIZE;

            // everything normal up to penultimate block
            memcpy(assembly, inbuf, penultimate_block);

            // prepare new penultimate block in buf
            aes_ecb_decrypt(buf, inbuf + penultimate_block, priv->ctx);
            memcpy(buf, inbuf + in_len - rest, rest);

            // former penultimate block becomes new ultimate block
            memcpy(assembly + penultimate_block + AES_BLOCK_SIZE, inbuf + penultimate_block, AES_BLOCK_SIZE);

            // write new penultimate block from buf
            memcpy(assembly + penultimate_block, buf, AES_BLOCK_SIZE);

            // regular cbc decryption of the re-arranged ciphertext
            aes_cbc_decrypt(assembly, assembly, in_len + AES_BLOCK_SIZE - rest, aes_null_iv, priv->ctx);

            // check for expected zero padding and give a warning otherwise
            if(memcmp(assembly + in_len, aes_null_iv, AES_BLOCK_SIZE - rest)) {
                traceEvent(TRACE_WARNING, "transop_decode_aes payload decryption failed with unexpected cipher text stealing padding");
                return -1;
            }
        } else {
            // regular cbc decryption on multiple block-sized payload
            aes_cbc_decrypt(assembly, inbuf, in_len, aes_null_iv, priv->ctx);
        }
        len = in_len - AES_PREAMBLE_SIZE;
        memcpy(outbuf, assembly + AES_PREAMBLE_SIZE, len);
    } else
        traceEvent(TRACE_ERROR, "transop_decode_aes inbuf wrong size (%ul) to decrypt", in_len);

    return len;
}


static int setup_aes_key (transop_aes_t *priv, const uint8_t *password, ssize_t password_len) {

    unsigned char   key_mat[32];     /* maximum aes key length, equals hash length */
    unsigned char   *key;
    size_t          key_size;

    // let the user choose the degree of encryption:
    // long input passwords will pick AES192 or AES256 with more robust but expensive encryption

    // the input password always gets hashed to make a more unpredictable use of the key space
    // just think of usually reset MSB of ASCII coded password bytes
    pearson_hash_256(key_mat, password, password_len);

    // the length-dependant scheme for key setup was discussed on github:
    // https://github.com/ntop/n2n/issues/101 -- as no iv encryption required
    //  anymore, the key-size trigger values were roughly halved
    if(password_len >= 33) {
        key_size = AES256_KEY_BYTES;       /* 256 bit */
    } else if(password_len >= 23) {
        key_size = AES192_KEY_BYTES;       /* 192 bit */
    } else {
        key_size = AES128_KEY_BYTES;       /* 128 bit */
    }

    // and use the last key-sized part of the hash as aes key
    key = key_mat + sizeof(key_mat) - key_size;

    // setup the key and have corresponding context created
    if(aes_init (key, key_size, &(priv->ctx))) {
        traceEvent(TRACE_ERROR, "setup_aes_key %u-bit key setup unsuccessful", key_size * 8);
        return -1;
    }
    traceEvent(TRACE_DEBUG, "setup_aes_key %u-bit key setup completed", key_size * 8);

    return 0;
}


static void transop_tick_aes (n2n_trans_op_t *arg, time_t now) {

    // no tick action
}


// AES initialization function
int n2n_transop_aes_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    transop_aes_t *priv;
    const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
    size_t encrypt_key_len = strlen(conf->encrypt_key);

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_AES;

    ttt->tick         = transop_tick_aes;
    ttt->deinit       = transop_deinit_aes;
    ttt->fwd          = transop_encode_aes;
    ttt->rev          = transop_decode_aes;

    priv = (transop_aes_t*)calloc(1, sizeof(transop_aes_t));
    if(!priv) {
        traceEvent(TRACE_ERROR, "n2n_transop_aes_init cannot allocate transop_aes_t memory");
        return -1;
    }
    ttt->priv = priv;

    // setup the cipher and key
    return setup_aes_key(priv, encrypt_key, encrypt_key_len);
}
