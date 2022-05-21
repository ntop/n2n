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


// Speck plaintext preamble
#define TRANSOP_SPECK_PREAMBLE_SIZE   (N2N_SPECK_IVEC_SIZE)


typedef struct transop_speck {
    speck_context_t      *ctx;        /* the round keys for payload encryption & decryption */
} transop_speck_t;


static int transop_deinit_speck (n2n_trans_op_t *arg) {

    transop_speck_t *priv = (transop_speck_t *)arg->priv;

    if(priv) {
        if(priv->ctx)
            speck_deinit(priv->ctx);
        free(priv);
    }

    return 0;
}


// the Speck packet format consists of
//
//  - a 128-bit random iv
//  - encrypted payload
//
//  [IIII|DDDDDDDDDDDDDDDDDDDDD]
//       |<---- encrypted ---->|
//
static int transop_encode_speck (n2n_trans_op_t *arg,
                                 uint8_t *outbuf,
                                 size_t out_len,
                                 const uint8_t *inbuf,
                                 size_t in_len,
                                 const uint8_t *peer_mac) {

    int len = -1;
    transop_speck_t *priv = (transop_speck_t *)arg->priv;

    if(in_len <= N2N_PKT_BUF_SIZE) {
        if((in_len + TRANSOP_SPECK_PREAMBLE_SIZE) <= out_len) {
            size_t idx = 0;

            traceEvent(TRACE_DEBUG, "encode_speck %lu bytes", in_len);

            // generate and encode the iv
            encode_uint64(outbuf, &idx, n2n_rand());
            encode_uint64(outbuf, &idx, n2n_rand());

            // encrypt the payload and write the ciphertext after the iv
            // len is set to the length of the cipher plain text to be encrpyted
            // which is (in this case) identical to original packet lentgh
            len = in_len;
            speck_ctr (outbuf + TRANSOP_SPECK_PREAMBLE_SIZE, /* output starts right after the iv */
                       inbuf,       /* input */
                       in_len,      /* len */
                       outbuf,      /* iv, already encoded in outbuf, speck does not change it */
                       priv->ctx);  /* ctx already setup with round keys */

            traceEvent(TRACE_DEBUG, "encode_speck: encrypted %u bytes.\n", in_len);

            // size of data carried in UDP
            len += TRANSOP_SPECK_PREAMBLE_SIZE;
        } else
            traceEvent(TRACE_ERROR, "encode_speck outbuf too small.");
    } else
        traceEvent(TRACE_ERROR, "encode_speck inbuf too big to encrypt.");

    return len;
}


// see transop_encode_speck for packet format
static int transop_decode_speck (n2n_trans_op_t *arg,
                                 uint8_t *outbuf,
                                 size_t out_len,
                                 const uint8_t *inbuf,
                                 size_t in_len,
                                 const uint8_t *peer_mac) {

    int len = 0;
    transop_speck_t *priv = (transop_speck_t *)arg->priv;

    if(((in_len - TRANSOP_SPECK_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* cipher text fits in buffer */
     && (in_len >= TRANSOP_SPECK_PREAMBLE_SIZE)) {                  /* has at least iv */

        traceEvent(TRACE_DEBUG, "decode_speck %lu bytes", in_len);

        len = (in_len - TRANSOP_SPECK_PREAMBLE_SIZE);
        speck_ctr (outbuf,     /* output */
                   inbuf + TRANSOP_SPECK_PREAMBLE_SIZE, /* encrypted data starts right after preamble (iv) */
                   len,        /* len */
                   inbuf,      /* iv can be found at input's beginning */
                   priv->ctx); /* ctx already setup with round keys */

        traceEvent(TRACE_DEBUG, "decode_speck decrypted %u bytes.\n", len);
    } else
        traceEvent(TRACE_ERROR, "decode_speck inbuf wrong size (%ul) to decrypt.", in_len);

    return len;
}


static int setup_speck_key (transop_speck_t *priv, const uint8_t *key, ssize_t key_size) {

    uint8_t key_mat_buf[32];

    // the input key always gets hashed to make a more unpredictable and more complete use of the key space
    pearson_hash_256(key_mat_buf, key, key_size);

    // expand the key material to the context (= round keys), 256 bit keysize
    speck_init(&(priv->ctx), key_mat_buf, 256);

    traceEvent(TRACE_DEBUG, "setup_speck_key completed\n");

    return 0;
}


static void transop_tick_speck (n2n_trans_op_t *arg, time_t now) {

    // no tick action
}


// Speck initialization function
int n2n_transop_speck_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    transop_speck_t *priv;
    const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
    size_t encrypt_key_len = strlen(conf->encrypt_key);

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_SPECK;

    ttt->tick         = transop_tick_speck;
    ttt->deinit       = transop_deinit_speck;
    ttt->fwd          = transop_encode_speck;
    ttt->rev          = transop_decode_speck;

    priv = (transop_speck_t*)calloc(1, sizeof(transop_speck_t));
    if(!priv) {
        traceEvent(TRACE_ERROR, "n2n_transop_speck_init cannot allocate transop_speck_t memory");
        return -1;
    }
    ttt->priv = priv;

    // setup the cipher and key
    return setup_speck_key(priv, encrypt_key, encrypt_key_len);
}
