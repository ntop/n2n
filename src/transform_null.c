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


static int transop_deinit_null (n2n_trans_op_t *arg ) {

    // nothing to deallocate, nothing to release

    return 0;
}


static int transop_encode_null (n2n_trans_op_t *arg,
                                uint8_t *outbuf,
                                size_t out_len,
                                const uint8_t *inbuf,
                                size_t in_len,
                                const uint8_t *peer_mac) {

    int retval = -1;

    traceEvent(TRACE_DEBUG, "encode_null %lu", in_len);
    if(out_len >= in_len) {
        memcpy(outbuf, inbuf, in_len);
        retval = in_len;
    } else {
        traceEvent(TRACE_DEBUG, "encode_null %lu too big for packet buffer", in_len);
    }

    return retval;
}


static int transop_decode_null (n2n_trans_op_t *arg,
                                uint8_t *outbuf,
                                size_t out_len,
                                const uint8_t *inbuf,
                                size_t in_len,
                                const uint8_t *peer_mac) {

    int retval = -1;

    traceEvent(TRACE_DEBUG, "decode_null %lu", in_len);
    if(out_len >= in_len) {
        memcpy(outbuf, inbuf, in_len);
        retval = in_len;
    } else {
        traceEvent(TRACE_DEBUG, "decode_null %lu too big for packet buffer", in_len);
    }

    return retval;
}


static void transop_tick_null (n2n_trans_op_t *arg, time_t now) {

    // no tick action
}


int n2n_transop_null_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    memset(ttt, 0, sizeof(n2n_trans_op_t));

    ttt->transform_id  = N2N_TRANSFORM_ID_NULL;
    ttt->no_encryption = 1;
    ttt->deinit        = transop_deinit_null;
    ttt->tick          = transop_tick_null;
    ttt->fwd           = transop_encode_null;
    ttt->rev           = transop_decode_null;

    return 0;
}
