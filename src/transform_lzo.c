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


/* heap allocation for compression as per lzo example doc  */
#define HEAP_ALLOC(var,size)   lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]


typedef struct transop_lzo {
    HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);
} transop_lzo_t;


static int transop_deinit_lzo (n2n_trans_op_t *arg) {

    transop_lzo_t *priv = (transop_lzo_t *)arg->priv;

    if(priv)
        free(priv);

    return 0;
}


// returns compressed packet length
// returns 0 if error occured, the caller would have to use
// original, i.e. uncompressed data then
static int transop_encode_lzo (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    transop_lzo_t *priv = (transop_lzo_t *)arg->priv;
    lzo_uint compression_len = 0;

    if(in_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "encode_lzo inbuf wrong size (%ul) to compress", in_len);
        return 0;
    }

    if(out_len < in_len + in_len / 16 + 64 + 3) {
        traceEvent(TRACE_ERROR, "encode_lzo outbuf too small (%ul) to compress inbuf (%ul)",
                                out_len, in_len);
        return 0;
    }

    if(lzo1x_1_compress(inbuf, in_len, outbuf, &compression_len, priv->wrkmem) != LZO_E_OK) {
        traceEvent(TRACE_ERROR, "encode_lzo compression error");
        compression_len = 0;
    }

    return compression_len;
}


static int transop_decode_lzo (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    lzo_uint deflated_len = N2N_PKT_BUF_SIZE;

    if(in_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "decode_lzo inbuf wrong size (%ul) to decompress", in_len);
        return 0;
    }

    lzo1x_decompress(inbuf, in_len, outbuf, &deflated_len, NULL);

    if(deflated_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "decode_lzo outbuf wrong size (%ul) decompressed", deflated_len);
        return 0;
    }

    return deflated_len;
}


static void transop_tick_lzo (n2n_trans_op_t *arg, time_t now) {

    // no tick action
}


// lzo initialization function
int n2n_transop_lzo_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    transop_lzo_t *priv;

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_COMPRESSION_ID_LZO;

    ttt->tick         = transop_tick_lzo;
    ttt->deinit       = transop_deinit_lzo;
    ttt->fwd          = transop_encode_lzo;
    ttt->rev          = transop_decode_lzo;

    priv = (transop_lzo_t*)calloc(1, sizeof(transop_lzo_t));
    if(!priv) {
        traceEvent(TRACE_ERROR, "lzo_init cannot allocate transop_lzo memory");
        return -1;
    }
    ttt->priv = priv;

    if(lzo_init() != LZO_E_OK) {
        traceEvent(TRACE_ERROR, "lzo_init cannot init lzo compression");
        return -1;
    }

    return 0;
}
