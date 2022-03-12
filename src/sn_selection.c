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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include "n2n.h"


static SN_SELECTION_CRITERION_DATA_TYPE sn_selection_criterion_common_read (n2n_edge_t *eee);
static int sn_selection_criterion_sort (peer_info_t *a, peer_info_t *b);


/* Initialize selection_criterion field in peer_info structure*/
int sn_selection_criterion_init (peer_info_t *peer) {

    if(peer != NULL) {
        sn_selection_criterion_default(&(peer->selection_criterion));
    }

    return 0; /* OK */
}


/* Set selection_criterion field to default value according to selected strategy. */
int sn_selection_criterion_default (SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion) {

    *selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)(UINT64_MAX >> 1) - 1;

    return 0; /* OK */
}


/* Set selection_criterion field to 'bad' value (worse than default) according to selected strategy. */
int sn_selection_criterion_bad (SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion) {

    *selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)(UINT64_MAX >> 1);

    return 0; /* OK */
}

/* Set selection_criterion field to 'good' value (better than default) according to selected strategy. */
int sn_selection_criterion_good (SN_SELECTION_CRITERION_DATA_TYPE *selection_criterion) {

    *selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)(UINT64_MAX >> 1) - 2;

    return 0; /* OK */
}


/* Take data from PEER_INFO payload and transform them into a selection_criterion.
 * This function is highly dependant of the chosen selection criterion.
 */
int sn_selection_criterion_calculate (n2n_edge_t *eee, peer_info_t *peer, SN_SELECTION_CRITERION_DATA_TYPE *data) {

    SN_SELECTION_CRITERION_DATA_TYPE common_data;
    int sum = 0;

    common_data = sn_selection_criterion_common_read(eee);

    switch(eee->conf.sn_selection_strategy) {

        case SN_SELECTION_STRATEGY_LOAD: {
            peer->selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)(be32toh(*data) + common_data);

            /* Mitigation of the real supernode load in order to see less oscillations.
             * Edges jump from a supernode to another back and forth due to purging.
             * Because this behavior has a cost of switching, the real load is mitigated with a stickyness factor.
             * This factor is dynamically calculated basing on network size and prevent that unnecessary switching */
            if(peer == eee->curr_sn) {
                sum = HASH_COUNT(eee->known_peers) + HASH_COUNT(eee->pending_peers);
                peer->selection_criterion = peer->selection_criterion * sum / (sum + 1);
            }
            break;
        }

        case SN_SELECTION_STRATEGY_RTT: {
            peer->selection_criterion = (SN_SELECTION_CRITERION_DATA_TYPE)((uint32_t)time_stamp() >> 22) - common_data;
            break;
        }

        case SN_SELECTION_STRATEGY_MAC: {
            peer->selection_criterion = 0;
            memcpy(&peer->selection_criterion, /* leftbound, don't mess with pointer arithmetics */
                   peer->mac_addr,
                   N2N_MAC_SIZE);
            peer->selection_criterion = be64toh(peer->selection_criterion);
            peer->selection_criterion >>= (sizeof(peer->selection_criterion) - N2N_MAC_SIZE) * 8; /* rightbound */
            break;
        }

        default: {
            // this should never happen
            traceEvent(TRACE_ERROR, "selection_criterion unknown selection strategy configuration");
            break;
        }
    }

    return 0; /* OK */
}


/* Set sn_selection_criterion_common_data field to default value. */
int sn_selection_criterion_common_data_default (n2n_edge_t *eee) {

    switch(eee->conf.sn_selection_strategy) {

        case SN_SELECTION_STRATEGY_LOAD: {
            SN_SELECTION_CRITERION_DATA_TYPE tmp = 0;

            tmp = HASH_COUNT(eee->pending_peers);
            if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                tmp *= 2;
            }
            eee->sn_selection_criterion_common_data = tmp / HASH_COUNT(eee->conf.supernodes);
            break;
        }

        case SN_SELECTION_STRATEGY_RTT: {
            eee->sn_selection_criterion_common_data = (SN_SELECTION_CRITERION_DATA_TYPE)((uint32_t)time_stamp() >> 22);
            break;
        }

        case SN_SELECTION_STRATEGY_MAC: {
            eee->sn_selection_criterion_common_data = 0;
            break;
        }

        default: {
            // this should never happen
            traceEvent(TRACE_ERROR, "selection_criterion unknown selection strategy configuration");
            break;
        }
    }

    return 0; /* OK */
}


/* Return the value of sn_selection_criterion_common_data field. */
static SN_SELECTION_CRITERION_DATA_TYPE sn_selection_criterion_common_read (n2n_edge_t *eee) {

    return eee->sn_selection_criterion_common_data;
}


/* Function that compare two selection_criterion fields and sorts them in ascending order. */
static int sn_selection_criterion_sort (peer_info_t *a, peer_info_t *b) {

    int ret = 0;

    // comparison function for sorting supernodes in ascending order of their selection_criterion.
    if(a->selection_criterion > b->selection_criterion)
        ret = 1;
    else if(a->selection_criterion < b->selection_criterion)
        ret = -1;

    return ret;
}


/* Function that sorts peer_list using sn_selection_criterion_sort. */
int sn_selection_sort (peer_info_t **peer_list) {

    HASH_SORT(*peer_list, sn_selection_criterion_sort);

    return 0; /* OK */
}


/* Function that gathers requested data on a supernode.
 * it remains unaffected by selection strategy because it refers to edge behaviour only
 */
SN_SELECTION_CRITERION_DATA_TYPE sn_selection_criterion_gather_data (n2n_sn_t *sss) {

    SN_SELECTION_CRITERION_DATA_TYPE data = 0, tmp = 0;
    struct sn_community *comm, *tmp_comm;

    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        // number of nodes in the community + the community itself
        tmp = HASH_COUNT(comm->edges) + 1;
        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            // double-count encrypted communities (and their nodes): they exert more load on supernode
            tmp *= 2;
        }
        data += tmp;
    }

    return htobe64(data);
}


/* Convert selection_criterion field in a string for management port output. */
extern char * sn_selection_criterion_str (n2n_edge_t *eee, selection_criterion_str_t out, peer_info_t *peer) {

    int chars = 0;


    if(NULL == out) {
        return NULL;
    }
    memset(out, 0, SN_SELECTION_CRITERION_BUF_SIZE);

    // keep off the super-big values (used for "bad" or "good" or "undetermined" supernodes,
    // easier to sort to the end of the list).
    // Alternatively, typecast to (int16_t) and check for greater or equal zero
    if(peer->selection_criterion < (UINT64_MAX >> 2)) {

        switch(eee->conf.sn_selection_strategy) {

            case SN_SELECTION_STRATEGY_LOAD: {
                chars = snprintf(out, SN_SELECTION_CRITERION_BUF_SIZE, "load = %8ld", peer->selection_criterion);
                break;
            }

            case SN_SELECTION_STRATEGY_RTT: {
                chars = snprintf(out, SN_SELECTION_CRITERION_BUF_SIZE, "rtt = %6ld ms", peer->selection_criterion);
                break;
            }

            case SN_SELECTION_STRATEGY_MAC: {
                chars = snprintf(out, SN_SELECTION_CRITERION_BUF_SIZE, "%s", ((int64_t)peer->selection_criterion > 0 ?
                                                                              ((peer == eee->curr_sn) ? "active" : "standby") : ""));
                break;
            }

            default: {
                // this should never happen
                traceEvent(TRACE_ERROR, "selection_criterion unknown selection strategy configuration");
                break;
            }
        }

        // this test is to make "-Wformat-truncation" less sad
        if(chars > SN_SELECTION_CRITERION_BUF_SIZE) {
            traceEvent(TRACE_ERROR, "selection_criterion buffer overflow");
        }
    }

    return out;
}
