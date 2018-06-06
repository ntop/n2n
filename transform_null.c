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

static int transop_deinit_null( n2n_trans_op_t * arg )
{
    /* nothing to deallocate, nothing to release. */
    return 0;
}

static int transop_encode_null( n2n_trans_op_t * arg,
                                uint8_t * outbuf,
                                size_t out_len,
                                const uint8_t * inbuf,
                                size_t in_len )
{
    int retval = -1;

    traceEvent( TRACE_DEBUG, "encode_null %lu", in_len );
    if ( out_len >= in_len )
    {
        memcpy( outbuf, inbuf, in_len );
        retval = in_len;
    }
    else
    {
        traceEvent( TRACE_DEBUG, "encode_null %lu too big for packet buffer", in_len );        
    }

    return retval;
}

static int transop_decode_null( n2n_trans_op_t * arg,
                                uint8_t * outbuf,
                                size_t out_len,
                                const uint8_t * inbuf,
                                size_t in_len )
{
    int retval = -1;

    traceEvent( TRACE_DEBUG, "decode_null %lu", in_len );
    if ( out_len >= in_len )
    {
        memcpy( outbuf, inbuf, in_len );
        retval = in_len;
    }
    else
    {
        traceEvent( TRACE_DEBUG, "decode_null %lu too big for packet buffer", in_len );        
    }

    return retval;
}

static int transop_addspec_null( n2n_trans_op_t * arg, const n2n_cipherspec_t * cspec )
{
    return 0;
}

static n2n_tostat_t transop_tick_null( n2n_trans_op_t * arg, time_t now )
{
    n2n_tostat_t r;

    r.can_tx=1;
    r.tx_spec.t = N2N_TRANSFORM_ID_NULL;
    r.tx_spec.valid_from = 0;
    r.tx_spec.valid_until = (time_t)(-1);
    r.tx_spec.opaque_size=0;

    return r;
}

void transop_null_init( n2n_trans_op_t * ttt )
{
    memset(ttt, 0, sizeof(n2n_trans_op_t) );

    ttt->transform_id = N2N_TRANSFORM_ID_NULL;
    ttt->deinit  = transop_deinit_null;
    ttt->addspec = transop_addspec_null;
    ttt->tick    = transop_tick_null;
    ttt->fwd     = transop_encode_null;
    ttt->rev     = transop_decode_null;
}
