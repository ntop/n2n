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


// ChaCha20 plaintext preamble
#define CC20_PREAMBLE_SIZE    (CC20_IV_SIZE)


typedef struct transop_cc20 {
    cc20_context_t       *ctx;
} transop_cc20_t;


static int transop_deinit_cc20 (n2n_trans_op_t *arg) {

    transop_cc20_t *priv = (transop_cc20_t *)arg->priv;

    if(priv) {
        if(priv->ctx)
            cc20_deinit(priv->ctx);
        free(priv);
    }

    return 0;
}


// the ChaCha20 packet format consists of
//
//  - a 128-bit random iv
//  - encrypted payload
//
//  [IIII|DDDDDDDDDDDDDDDDDDDDD]
//       |<---- encrypted ---->|
//
static int transop_encode_cc20 (n2n_trans_op_t *arg,
                                uint8_t *outbuf,
                                size_t out_len,
                                const uint8_t *inbuf,
                                size_t in_len,
                                const uint8_t *peer_mac) {

    int len = -1;
    transop_cc20_t *priv = (transop_cc20_t *)arg->priv;

    if(in_len <= N2N_PKT_BUF_SIZE) {
        if((in_len + CC20_PREAMBLE_SIZE) <= out_len) {
            size_t idx = 0;

            traceEvent(TRACE_DEBUG, "encode_cc20 %lu bytes", in_len);

            // full iv sized random value (128 bit)
            encode_uint64(outbuf, &idx, n2n_rand());
            encode_uint64(outbuf, &idx, n2n_rand());

            len = in_len;
            cc20_crypt(outbuf + CC20_PREAMBLE_SIZE,
                       inbuf,
                       in_len,
                       outbuf, /* iv */
                       priv->ctx);

            // size of datacarried in UDP
            len += CC20_PREAMBLE_SIZE;
        } else
            traceEvent(TRACE_ERROR, "encode_cc20 outbuf too small.");
    } else
        traceEvent(TRACE_ERROR, "encode_cc20 inbuf too big to encrypt.");

    return len;
}


// see transop_encode_cc20 for packet format
static int transop_decode_cc20 (n2n_trans_op_t *arg,
                                uint8_t *outbuf,
                                size_t out_len,
                                const uint8_t *inbuf,
                                size_t in_len,
                                const uint8_t *peer_mac) {

    int len = 0;
    transop_cc20_t *priv = (transop_cc20_t *)arg->priv;

    if(((in_len - CC20_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* cipher text fits in assembly */
       && (in_len >= CC20_PREAMBLE_SIZE)) {                /* has at least iv */

        traceEvent(TRACE_DEBUG, "decode_cc20 %lu bytes", in_len);

        len = (in_len - CC20_PREAMBLE_SIZE);

        cc20_crypt(outbuf,
                   inbuf + CC20_PREAMBLE_SIZE,
                   in_len,
                   inbuf, /* iv */
                   priv->ctx);
    } else
        traceEvent(TRACE_ERROR, "decode_cc20 inbuf wrong size (%ul) to decrypt.", in_len);

    return len;
}


static int setup_cc20_key (transop_cc20_t *priv, const uint8_t *password, ssize_t password_len) {

    uint8_t key_mat[CC20_KEY_BYTES];

    // the input key always gets hashed to make a more unpredictable and more complete use of the key space
    pearson_hash_256(key_mat, password, password_len);

    if(cc20_init(key_mat, &(priv->ctx))) {
        traceEvent(TRACE_ERROR, "setup_cc20_key setup unsuccessful");
        return -1;
    }

    traceEvent(TRACE_DEBUG, "setup_cc20_key completed");

    return 0;
}


static void transop_tick_cc20 (n2n_trans_op_t *arg, time_t now) {

    // no tick action
}


// ChaCha20 initialization function
int n2n_transop_cc20_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    transop_cc20_t *priv;
    const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
    size_t encrypt_key_len = strlen(conf->encrypt_key);

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_CHACHA20;

    ttt->tick         = transop_tick_cc20;
    ttt->deinit       = transop_deinit_cc20;
    ttt->fwd          = transop_encode_cc20;
    ttt->rev          = transop_decode_cc20;

    priv = (transop_cc20_t*)calloc(1, sizeof(transop_cc20_t));
    if(!priv) {
        traceEvent(TRACE_ERROR, "cannot allocate transop_cc20_t memory");
        return -1;
    }
    ttt->priv = priv;

    // setup the cipher and key
    return setup_cc20_key(priv, encrypt_key, encrypt_key_len);
}
