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


#ifdef HAVE_ZSTD


typedef struct transop_zstd {
    // no local data
} transop_zstd_t;


static int transop_deinit_zstd (n2n_trans_op_t *arg) {

    transop_zstd_t *priv = (transop_zstd_t *)arg->priv;

    if(priv)
        free(priv);

    return 0;
}


// returns compressed packet length
// returns 0 if error occured, the caller would have to use
// original, i.e. uncompressed data then
static int transop_encode_zstd (n2n_trans_op_t *arg,
                                uint8_t *outbuf,
                                size_t out_len,
                                const uint8_t *inbuf,
                                size_t in_len,
                                const uint8_t *peer_mac) {

    /* transop_zstd_t *priv = (transop_zstd_t *)arg->priv; */
    int32_t compression_len = 0;

    if(in_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "encode_zstd inbuf wrong size (%ul) to compress", in_len);
        return 0;
    }

    if(out_len < in_len + 128) { // 128 leaves enough room,
                                 // for exact size call
                                 // ZSTD_compressBound(in_len)
                                 // which is slower
        traceEvent(TRACE_ERROR, "encode_zstd outbuf too small (%ul) to compress inbuf (%ul)",
                                out_len, in_len);
        return 0;
    }

    compression_len = ZSTD_compress(outbuf, out_len, inbuf, in_len, ZSTD_COMPRESSION_LEVEL);
    if(ZSTD_isError(compression_len)) {
        traceEvent(TRACE_ERROR, "payload compression failed with zstd error '%s'",
                                ZSTD_getErrorName(compression_len));
        // we do no return the error code to the caller, just return 0 len
        // so, any further specific error handling would have to happen right here
        compression_len = 0;
    }

    return compression_len;
}


static int transop_decode_zstd (n2n_trans_op_t *arg,
                                uint8_t *outbuf,
                                size_t out_len,
                                const uint8_t *inbuf,
                                size_t in_len,
                                const uint8_t *peer_mac) {

    int32_t deflated_len = 0;

    if(in_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "decode_zstd inbuf wrong size (%ul) to decompress", in_len);
        return 0;
    }

    deflated_len = ZSTD_decompress(outbuf, out_len, inbuf, in_len);

    if(ZSTD_isError(deflated_len)) {
        traceEvent(TRACE_WARNING, "payload decompression failed with zstd error '%s'",
                                   ZSTD_getErrorName(deflated_len));
        return 0; // cannot help it
    }

    // we should have noticed by memory break or ZSTD complaining about a too small of an out_len
    if(deflated_len > N2N_PKT_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "decode_zstd outbuf wrong size (%ul) decompressed", deflated_len);
        return 0;
    }

    return deflated_len;
}


static void transop_tick_zstd (n2n_trans_op_t *arg, time_t now) {

    // no tick action
}


// zstd initialization function
int n2n_transop_zstd_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    transop_zstd_t *priv;

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_COMPRESSION_ID_ZSTD;

    ttt->tick         = transop_tick_zstd;
    ttt->deinit       = transop_deinit_zstd;
    ttt->fwd          = transop_encode_zstd;
    ttt->rev          = transop_decode_zstd;

    priv = (transop_zstd_t*)calloc(1, sizeof(transop_zstd_t));
    if(!priv) {
        traceEvent(TRACE_ERROR, "zstd_init cannot allocate transop_zstd memory");
        return -1;
    }
    ttt->priv = priv;

    // zstd does not require initialization
    // if it requires one day, this is the place to do it and eventually throw an error
    // (see 'transform_lzo.c')

    return 0;
}


#endif // HAVE_ZSTD
