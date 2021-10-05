/*
 * (C) 2007-21 - ntop.org and contributors
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

#include <sys/time.h>

#include "n2n.h"

#define DURATION                2.5   // test duration per algorithm
#define PACKETS_BEFORE_GETTIME  2047  // do not check time after every packet but after (2 ^ n - 1)

/* heap allocation for compression as per lzo example doc */
#define HEAP_ALLOC(var,size) lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]
static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);


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
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };

/* Prototypes */
static ssize_t do_encode_packet( uint8_t * pktbuf, size_t bufsize, const n2n_community_t c );
static void run_transop_benchmark(const char *op_name, n2n_trans_op_t *op_fn, n2n_edge_conf_t *conf, uint8_t *pktbuf);
static void init_compression_for_benchmark(void);
static void deinit_compression_for_benchmark(void);
static void run_compression_benchmark(void);
static void run_hashing_benchmark(void);
static void run_ecc_benchmark(void);


int main(int argc, char * argv[]) {
  uint8_t pktbuf[N2N_PKT_BUF_SIZE];
  n2n_trans_op_t transop_null, transop_tf;
  n2n_trans_op_t transop_aes;
  n2n_trans_op_t transop_cc20;

  n2n_trans_op_t transop_speck;
  n2n_edge_conf_t conf;

  print_n2n_version();

  /* Init configuration */
  edge_init_conf_defaults(&conf);
  strncpy((char*)conf.community_name, "abc123def456", sizeof(conf.community_name));
  conf.encrypt_key = "SoMEVer!S$cUREPassWORD";

  pearson_hash_init();

  /* Init transopts */
  n2n_transop_null_init(&conf, &transop_null);
  n2n_transop_tf_init(&conf, &transop_tf);
  n2n_transop_aes_init(&conf, &transop_aes);
  n2n_transop_cc20_init(&conf, &transop_cc20);
  n2n_transop_speck_init(&conf, &transop_speck);

  /* Run the tests */
  run_transop_benchmark("null", &transop_null, &conf, pktbuf);
  run_transop_benchmark("tf", &transop_tf, &conf, pktbuf);
  run_transop_benchmark("aes", &transop_aes, &conf, pktbuf);
  run_transop_benchmark("cc20", &transop_cc20, &conf, pktbuf);
  run_transop_benchmark("speck", &transop_speck, &conf, pktbuf);

  run_ecc_benchmark();

  /* Also for compression (init moved here for ciphers get run before in case of lzo init error) */
  init_compression_for_benchmark();
  run_compression_benchmark();

  run_hashing_benchmark();


  /* Cleanup */
  transop_null.deinit(&transop_null);
  transop_tf.deinit(&transop_tf);
  transop_aes.deinit(&transop_aes);
  transop_cc20.deinit(&transop_cc20);
  transop_speck.deinit(&transop_speck);

  deinit_compression_for_benchmark();

  return 0;
}

// --- compression benchmark --------------------------------------------------------------

static void init_compression_for_benchmark(void) {

  if(lzo_init() != LZO_E_OK) {
    traceEvent(TRACE_ERROR, "LZO compression init error");
    exit(1);
  }

#ifdef N2N_HAVE_ZSTD
  // zstd does not require initialization. if it were required, this would be a good place
#endif
}


static void deinit_compression_for_benchmark(void) {

  // lzo1x does not require de-initialization. if it were required, this would be a good place

#ifdef N2N_HAVE_ZSTD
  // zstd does not require de-initialization. if it were required, this would be a good place
#endif
}


static void run_compression_benchmark() {
  const float target_sec = DURATION;
  struct timeval t1;
  struct timeval t2;
  ssize_t target_usec = target_sec * 1e6;
  ssize_t tdiff; // microseconds
  size_t num_packets;
  float mpps;
  uint8_t compression_buffer[N2N_PKT_BUF_SIZE]; // size allows enough of a reserve required for compression
  lzo_uint compression_len = N2N_PKT_BUF_SIZE;
  uint8_t deflation_buffer[N2N_PKT_BUF_SIZE];
  int64_t deflated_len;

  // compression
  printf("{%s}\t%s\t%.1f sec\t(%u bytes)",
	 "lzo1x", "compr", target_sec, (unsigned int)sizeof(PKT_CONTENT));
  fflush(stdout);
  tdiff = 0;
  num_packets = 0;
  gettimeofday( &t1, NULL );

  while(tdiff < target_usec) {
    compression_len = N2N_PKT_BUF_SIZE;
    if(lzo1x_1_compress(PKT_CONTENT, sizeof(PKT_CONTENT), compression_buffer, &compression_len, wrkmem) != LZO_E_OK) {
      printf("\n\t compression error\n");
      exit(1);
    }
    num_packets++;
    if (!(num_packets & PACKETS_BEFORE_GETTIME)) {
      gettimeofday( &t2, NULL );
      tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
    }
  }
  mpps = num_packets / (tdiff / 1e6) / 1e6;
  printf(" ---> (%u bytes)\t%12u packets\t%8.1f Kpps\t%8.1f MB/s\n",
	 (unsigned int)compression_len, (unsigned int)num_packets, mpps * 1e3, mpps * sizeof(PKT_CONTENT));

  // decompression
  printf("\t%s\t%.1f sec\t(%u bytes)",
	 "decompr", target_sec, (unsigned int)sizeof(PKT_CONTENT));
  fflush(stdout);
  tdiff = 0;
  num_packets = 0;
  gettimeofday( &t1, NULL );

  while(tdiff < target_usec) {
    deflated_len = N2N_PKT_BUF_SIZE;
    lzo1x_decompress (compression_buffer, compression_len, deflation_buffer, (lzo_uint*)&deflated_len, NULL);
    num_packets++;
    if (!(num_packets & PACKETS_BEFORE_GETTIME)) {
      gettimeofday( &t2, NULL );
      tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
    }
  }
  mpps = num_packets / (tdiff / 1e6) / 1e6;
  printf(" <--- (%u bytes)\t%12u packets\t%8.1f Kpps\t%8.1f MB/s\n",
	 (unsigned int)compression_len, (unsigned int)num_packets, mpps * 1e3, mpps * sizeof(PKT_CONTENT));
  if(memcmp(deflation_buffer, PKT_CONTENT, sizeof(PKT_CONTENT)) != 0)
    printf("\n\tdecompression error\n");
  printf ("\n");

#ifdef N2N_HAVE_ZSTD
  // compression
  printf("{%s}\t%s\t%.1f sec\t(%u bytes)",
	 "zstd", "compr", target_sec, (unsigned int)sizeof(PKT_CONTENT));
  fflush(stdout);
  tdiff = 0;
  num_packets = 0;
  gettimeofday( &t1, NULL );
  while(tdiff < target_usec) {
    compression_len = N2N_PKT_BUF_SIZE;
    compression_len = ZSTD_compress(compression_buffer, compression_len, PKT_CONTENT, sizeof(PKT_CONTENT), ZSTD_COMPRESSION_LEVEL) ;
    if(ZSTD_isError(compression_len)) {
      printf("\n\t compression error\n");
      exit(1);
    }
    num_packets++;
    if (!(num_packets & PACKETS_BEFORE_GETTIME)) {
      gettimeofday( &t2, NULL );
      tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
    }
  }
  mpps = num_packets / (tdiff / 1e6) / 1e6;
  printf(" ---> (%u bytes)\t%12u packets\t%8.1f Kpps\t%8.1f MB/s\n",
	 (unsigned int)compression_len, (unsigned int)num_packets, mpps * 1e3, mpps * sizeof(PKT_CONTENT));

  // decompression
  printf("\t%s\t%.1f sec\t(%u bytes)",
	 "decompr", target_sec, (unsigned int)sizeof(PKT_CONTENT));
  fflush(stdout);
  tdiff = 0;
  num_packets = 0;
  gettimeofday( &t1, NULL );
  while(tdiff < target_usec) {
    deflated_len = N2N_PKT_BUF_SIZE;
    deflated_len = (int32_t)ZSTD_decompress (deflation_buffer, deflated_len, compression_buffer, compression_len);
    if(ZSTD_isError(deflated_len)) {
      printf("\n\tdecompression error '%s'\n",
             ZSTD_getErrorName(deflated_len));
        exit(1);
    }
    num_packets++;
    if (!(num_packets & PACKETS_BEFORE_GETTIME)) {
      gettimeofday( &t2, NULL );
      tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
    }
  }
  mpps = num_packets / (tdiff / 1e6) / 1e6;
  printf(" <--- (%u bytes)\t%12u packets\t%8.1f Kpps\t%8.1f MB/s\n",
	 (unsigned int)compression_len, (unsigned int)num_packets, mpps * 1e3, mpps * sizeof(PKT_CONTENT));
  if(memcmp(deflation_buffer, PKT_CONTENT, sizeof(PKT_CONTENT)) != 0)
    printf("\n\tdecompression error\n");
  printf ("\n");
#endif
}

// --- hashing benchmark ------------------------------------------------------------------

static void run_hashing_benchmark(void) {
  const float target_sec = DURATION;
  struct timeval t1;
  struct timeval t2;
  ssize_t nw;
  ssize_t target_usec = target_sec * 1e6;
  ssize_t tdiff = 0; // microseconds
  size_t num_packets = 0;

  uint64_t hash;

  printf("(%s)\t%s\t%.1f sec\t(%u bytes)",
	 "prs64", "hash", target_sec, (unsigned int)sizeof(PKT_CONTENT));
  fflush(stdout);

  gettimeofday( &t1, NULL );
  nw = 8;

  while(tdiff < target_usec) {
    hash = pearson_hash_64(PKT_CONTENT, sizeof(PKT_CONTENT));
    hash++; // clever compiler finds out that we do no use the variable
    num_packets++;
    if (!(num_packets & PACKETS_BEFORE_GETTIME)) {
      gettimeofday( &t2, NULL );
      tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
    }
  }

  float mpps = num_packets / (tdiff / 1e6) / 1e6;

  printf(" ---> (%u bytes)\t%12u packets\t%8.1f Kpps\t%8.1f MB/s\n",
	 (unsigned int)nw, (unsigned int)num_packets, mpps * 1e3, mpps * sizeof(PKT_CONTENT));
  printf("\n");
}

// --- ecc benchmark ----------------------------------------------------------------------

static void run_ecc_benchmark(void) {
  const float target_sec = DURATION;
  struct timeval t1;
  struct timeval t2;
  ssize_t nw;
  ssize_t target_usec = target_sec * 1e6;
  ssize_t tdiff = 0; // microseconds
  size_t num_packets = 0;

  unsigned char b[32];
  unsigned char k[32];

  memset(b, 0x00, 31);
  b[31] = 9;

  memset(k, 0x55, 32);

  printf("[%s]\t%s\t%.1f sec\t(%u bytes) ",
	 "curve", "25519", target_sec, 32);
  fflush(stdout);

  gettimeofday( &t1, NULL );
  nw = 32;

  while(tdiff < target_usec) {
    curve25519(b, k, b);
    num_packets++;
    gettimeofday( &t2, NULL );
    tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
  }

  float mpps = num_packets / (tdiff / 1e6) / 1e6;

  printf(" ---> (%u bytes)\t%12u ops\t%8.1f Kops/s\n",
	 (unsigned int)nw, (unsigned int)num_packets, mpps * 1e3);
  printf("\n");
}

// --- cipher benchmark -------------------------------------------------------------------

static void run_transop_benchmark(const char *op_name, n2n_trans_op_t *op_fn, n2n_edge_conf_t *conf, uint8_t *pktbuf) {
  n2n_common_t cmn;
  n2n_PACKET_t pkt;
  n2n_mac_t mac_buf;
  uint8_t decodebuf[N2N_PKT_BUF_SIZE];
  const float target_sec = DURATION;
  struct timeval t1;
  struct timeval t2;
  size_t idx;
  size_t rem;
  size_t nw;
  ssize_t target_usec = target_sec * 1e6;
  ssize_t tdiff; // microseconds
  size_t num_packets;
  float mpps;

  // encryption
  printf("[%s]\t%s\t%.1f sec\t(%u bytes)",
	 op_name, "encrypt" , target_sec, (unsigned int)sizeof(PKT_CONTENT));
  fflush(stdout);
  memset(mac_buf, 0, sizeof(mac_buf));
  num_packets = 0;
  tdiff = 0;
  gettimeofday( &t1, NULL );
  while(tdiff < target_usec) {
    nw = do_encode_packet( pktbuf, N2N_PKT_BUF_SIZE, conf->community_name);
    nw += op_fn->fwd(op_fn,
		     pktbuf+nw, N2N_PKT_BUF_SIZE-nw,
		     PKT_CONTENT, sizeof(PKT_CONTENT), mac_buf);
    num_packets++;
    if (!(num_packets & PACKETS_BEFORE_GETTIME)) {
      gettimeofday( &t2, NULL );
      tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
    }
  }
  mpps = num_packets / (tdiff / 1e6) / 1e6;
  printf(" ---> (%u bytes)\t%12u packets\t%8.1f Kpps\t%8.1f MB/s\n",
	 (unsigned int)nw, (unsigned int)num_packets, mpps * 1e3, mpps * sizeof(PKT_CONTENT));

  // decrpytion
  printf("\t%s\t%.1f sec\t(%u bytes)",
	 "decrypt" , target_sec, (unsigned int)sizeof(PKT_CONTENT));
  fflush(stdout);
  num_packets = 0;
  tdiff = 0;
  gettimeofday( &t1, NULL );
  while(tdiff < target_usec) {
    idx=0;
    rem=nw;
    decode_common( &cmn, pktbuf, &rem, &idx);
    decode_PACKET( &pkt, &cmn, pktbuf, &rem, &idx );
    op_fn->rev(op_fn, decodebuf, N2N_PKT_BUF_SIZE, pktbuf+idx, rem, 0);
    num_packets++;
    if (!(num_packets & PACKETS_BEFORE_GETTIME)) {
      gettimeofday( &t2, NULL );
      tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
    }
  }
  mpps = num_packets / (tdiff / 1e6) / 1e6;
  printf(" <--- (%u bytes)\t%12u packets\t%8.1f Kpps\t%8.1f MB/s\n",
	 (unsigned int)nw, (unsigned int)num_packets, mpps * 1e3, mpps * sizeof(PKT_CONTENT));
  if(memcmp(decodebuf, PKT_CONTENT, sizeof(PKT_CONTENT)) != 0)
    printf("\tpayload decryption failed!\n");
  printf("\n");
}


static ssize_t do_encode_packet( uint8_t * pktbuf, size_t bufsize, const n2n_community_t c )
{
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
