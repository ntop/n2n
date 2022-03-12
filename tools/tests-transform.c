/*
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */

#include <inttypes.h>

#include "n2n.h"
#include "hexdump.h"

#define DURATION                2.5   // test duration per algorithm
#define PACKETS_BEFORE_GETTIME  2047  // do not check time after every packet but after (2 ^ n - 1)


uint8_t PKT_CONTENT[]={
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};

/* Prototypes */
static ssize_t do_encode_packet ( uint8_t * pktbuf, size_t bufsize, const n2n_community_t c );
static void run_transop_benchmark (const char *op_name, n2n_trans_op_t *op_fn, n2n_edge_conf_t *conf, uint8_t *pktbuf);


int main (int argc, char * argv[]) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    n2n_trans_op_t transop_null, transop_tf;
    n2n_trans_op_t transop_aes;
    n2n_trans_op_t transop_cc20;
    n2n_trans_op_t transop_speck;
    n2n_trans_op_t transop_lzo;
#ifdef HAVE_ZSTD
    n2n_trans_op_t transop_zstd;
#endif
    n2n_edge_conf_t conf;

    /* Init configuration */
    edge_init_conf_defaults(&conf);
    strncpy((char *)conf.community_name, "abc123def456", sizeof(conf.community_name));
    conf.encrypt_key = "SoMEVer!S$cUREPassWORD";

    char *test_name = "environment";
    printf("%s: community_name = \"%s\"\n", test_name, conf.community_name);
    printf("%s: encrypt_key = \"%s\"\n", test_name, conf.encrypt_key);
    printf("%s: input size = 0x%" PRIx64 "\n", test_name, sizeof(PKT_CONTENT));
    fhexdump(0, PKT_CONTENT, sizeof(PKT_CONTENT), stdout);
    printf("\n");

    /* Init transopts */
    n2n_transop_null_init(&conf, &transop_null);
    n2n_transop_tf_init(&conf, &transop_tf);
    n2n_transop_aes_init(&conf, &transop_aes);
    n2n_transop_cc20_init(&conf, &transop_cc20);
    n2n_transop_speck_init(&conf, &transop_speck);
    n2n_transop_lzo_init(&conf, &transop_lzo);
#ifdef HAVE_ZSTD
    n2n_transop_zstd_init(&conf, &transop_zstd);
#endif

    /* Run the tests */
    /* FIXME: interop tests are pretty useless without the expected encrypted buffer data */
    run_transop_benchmark("null", &transop_null, &conf, pktbuf);
    run_transop_benchmark("tf", &transop_tf, &conf, pktbuf);
    run_transop_benchmark("aes", &transop_aes, &conf, pktbuf);
    run_transop_benchmark("cc20", &transop_cc20, &conf, pktbuf);
    run_transop_benchmark("speck", &transop_speck, &conf, pktbuf);
    run_transop_benchmark("lzo", &transop_lzo, &conf, pktbuf);
#ifdef HAVE_ZSTD
    run_transop_benchmark("zstd", &transop_zstd, &conf, pktbuf);
#else
    // FIXME - output dummy data to the stdout for easy comparison
    printf("zstd: output size = 0x47\n");
    printf("000: 03 02 00 03 61 62 63 31  32 33 64 65 66 34 35 36   |    abc123def456|\n");
    printf("010: 00 00 00 00 00 00 00 00  00 01 02 03 04 05 00 01   |                |\n");
    printf("020: 02 03 04 05 00 00 28 b5  2f fd 60 00 01 bd 00 00   |      ( / `     |\n");
    printf("030: 80 00 01 02 03 04 05 06  07 08 09 0a 0b 0c 0d 0e   |                |\n");
    printf("040: 0f 01 00 da 47 9d 4b                               |    G K|\n");

    fprintf(stderr, "%s: not compiled - dummy data output\n", "zstd");
    printf("\n");
#endif

    /* Cleanup */
    transop_null.deinit(&transop_null);
    transop_tf.deinit(&transop_tf);
    transop_aes.deinit(&transop_aes);
    transop_cc20.deinit(&transop_cc20);
    transop_speck.deinit(&transop_speck);
    transop_lzo.deinit(&transop_lzo);
#ifdef HAVE_ZSTD
    transop_zstd.deinit(&transop_zstd);
#endif

    return 0;
}

// --- transop benchmark ------------------------------------------------------------------

static void run_transop_benchmark (const char *op_name, n2n_trans_op_t *op_fn, n2n_edge_conf_t *conf, uint8_t *pktbuf) {
    n2n_common_t cmn;
    n2n_PACKET_t pkt;
    n2n_mac_t mac_buf;
    uint8_t decodebuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    size_t rem;
    size_t nw;

    // encryption
    memset(mac_buf, 0, sizeof(mac_buf));

    nw = do_encode_packet( pktbuf, N2N_PKT_BUF_SIZE, conf->community_name);
    nw += op_fn->fwd(op_fn,
                     pktbuf+nw, N2N_PKT_BUF_SIZE-nw,
                     PKT_CONTENT, sizeof(PKT_CONTENT), mac_buf);

    printf("%s: output size = 0x%" PRIx64 "\n", op_name, nw);
    fhexdump(0, pktbuf, nw, stdout);

    // decrpytion
    idx=0;
    rem=nw;
    decode_common( &cmn, pktbuf, &rem, &idx);
    decode_PACKET( &pkt, &cmn, pktbuf, &rem, &idx );
    op_fn->rev(op_fn, decodebuf, sizeof(decodebuf), pktbuf+idx, rem, 0);

    if(memcmp(decodebuf, PKT_CONTENT, sizeof(PKT_CONTENT)) != 0) {
        fprintf(stderr, "%s: round-trip buffer mismatch\n", op_name);
        exit(1);
    }

    fprintf(stderr, "%s: tested\n", op_name);
    printf("\n");
}


static ssize_t do_encode_packet ( uint8_t * pktbuf, size_t bufsize, const n2n_community_t c )
{
    // FIXME: this is a parameter of the test environment
    n2n_mac_t destMac={0,1,2,3,4,5};

    n2n_common_t cmn;
    n2n_PACKET_t pkt;
    size_t idx;


    memset( &cmn, 0, sizeof(cmn) );
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_packet;
    cmn.flags=0; /* no options, not from supernode, no socket */
    memcpy( cmn.community, c, N2N_COMMUNITY_SIZE );

    memset( &pkt, 0, sizeof(pkt) );
    memcpy( pkt.srcMac, destMac, N2N_MAC_SIZE);
    memcpy( pkt.dstMac, destMac, N2N_MAC_SIZE);

    pkt.sock.family=0; /* do not encode sock */

    idx=0;
    encode_PACKET( pktbuf, &idx, &cmn, &pkt );
    traceEvent( TRACE_DEBUG, "encoded PACKET header of size=%u", (unsigned int)idx );

    return idx;
}
