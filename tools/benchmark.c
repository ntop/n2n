/*
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */

#include "n2n_wire.h"
#include "n2n_transforms.h"
#include "n2n.h"
#ifdef __GNUC__
#include <sys/time.h>
#endif
#include <time.h>
#include <string.h>
#include <stdio.h>


#if defined(WIN32) && !defined(__GNUC__)
#include <windows.h>

static int gettimeofday(struct timeval *tp, void *tzp)
{
	time_t clock;
	struct tm tm;
	SYSTEMTIME wtm;
	GetLocalTime(&wtm);
	tm.tm_year = wtm.wYear - 1900;
	tm.tm_mon = wtm.wMonth - 1;
	tm.tm_mday = wtm.wDay;
	tm.tm_hour = wtm.wHour;
	tm.tm_min = wtm.wMinute;
	tm.tm_sec = wtm.wSecond;
	tm.tm_isdst = -1;
	clock = mktime(&tm);
	tp->tv_sec = clock;
	tp->tv_usec = wtm.wMilliseconds * 1000;
	return (0);
}
#endif

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
static int perform_decryption = 0;

static void usage() {
  fprintf(stderr, "Usage: benchmark [-d]\n"
    " -d\t\tEnable decryption. Default: only encryption is performed\n");
  exit(1);
}

static void parseArgs(int argc, char * argv[]) {
  if((argc != 1) && (argc != 2))
    usage();

  if(argc == 2) {
    if(strcmp(argv[1], "-d") != 0)
      usage();

    perform_decryption = 1;
  }
}

int main(int argc, char * argv[]) {
  uint8_t pktbuf[N2N_PKT_BUF_SIZE];
  n2n_trans_op_t transop_null, transop_twofish;
#ifdef N2N_HAVE_AES
  n2n_trans_op_t transop_aes_cbc;
#endif
#ifdef HAVE_OPENSSL_1_1
  n2n_trans_op_t transop_cc20;
#endif

  n2n_trans_op_t transop_speck;
  n2n_edge_conf_t conf;

  parseArgs(argc, argv);

  /* Init configuration */
  edge_init_conf_defaults(&conf);
  strncpy((char*)conf.community_name, "abc123def456", sizeof(conf.community_name));
  conf.encrypt_key = "SoMEVer!S$cUREPassWORD";

  /* Init transopts */
  n2n_transop_null_init(&conf, &transop_null);
  n2n_transop_twofish_init(&conf, &transop_twofish);
#ifdef N2N_HAVE_AES
  n2n_transop_aes_cbc_init(&conf, &transop_aes_cbc);
#endif
#ifdef HAVE_OPENSSL_1_1
  n2n_transop_cc20_init(&conf, &transop_cc20);
#endif
  n2n_transop_speck_init(&conf, &transop_speck);
  
  /* Run the tests */
  run_transop_benchmark("transop_null", &transop_null, &conf, pktbuf);
  run_transop_benchmark("transop_twofish", &transop_twofish, &conf, pktbuf);
#ifdef N2N_HAVE_AES
  run_transop_benchmark("transop_aes", &transop_aes_cbc, &conf, pktbuf);
#endif
#ifdef HAVE_OPENSSL_1_1
  run_transop_benchmark("transop_cc20", &transop_cc20, &conf, pktbuf);
#endif
  run_transop_benchmark("transop_speck", &transop_speck, &conf, pktbuf);

  /* Cleanup */
  transop_null.deinit(&transop_null);
  transop_twofish.deinit(&transop_twofish);
#ifdef N2N_HAVE_AES
  transop_aes_cbc.deinit(&transop_aes_cbc);
#endif
#ifdef HAVE_OPENSSL_1_1
  transop_cc20.deinit(&transop_cc20);
#endif
  transop_speck.deinit(&transop_speck);

  return 0;
}

static void run_transop_benchmark(const char *op_name, n2n_trans_op_t *op_fn, n2n_edge_conf_t *conf, uint8_t *pktbuf) {
  n2n_common_t cmn;
  n2n_PACKET_t pkt;
  n2n_mac_t mac_buf;
  const int target_sec = 3;
  struct timeval t1;
  struct timeval t2;
  size_t idx;
  size_t rem;
  ssize_t nw;
  ssize_t target_usec = target_sec * 1e6;
  ssize_t tdiff = 0; // microseconds
  size_t num_packets = 0;

  printf("Run %s[%s] for %us (%u bytes):   ", perform_decryption ? "enc/dec" : "enc",
            op_name, target_sec, (unsigned int)sizeof(PKT_CONTENT));
  fflush(stdout);

  memset(mac_buf, 0, sizeof(mac_buf));
  gettimeofday( &t1, NULL );

  while(tdiff < target_usec) {
    nw = do_encode_packet( pktbuf, N2N_PKT_BUF_SIZE, conf->community_name);

    nw += op_fn->fwd(op_fn,
	  pktbuf+nw, N2N_PKT_BUF_SIZE-nw,
	  PKT_CONTENT, sizeof(PKT_CONTENT), mac_buf);

    idx=0;
    rem=nw;

    decode_common( &cmn, pktbuf, &rem, &idx);
    decode_PACKET( &pkt, &cmn, pktbuf, &rem, &idx );

    if(perform_decryption) {
      uint8_t decodebuf[N2N_PKT_BUF_SIZE];

      op_fn->rev(op_fn, decodebuf, N2N_PKT_BUF_SIZE, pktbuf+idx, rem, 0);

      if(memcmp(decodebuf, PKT_CONTENT, sizeof(PKT_CONTENT)) != 0)
        fprintf(stderr, "Payload decryption failed!\n");
    }

    gettimeofday( &t2, NULL );
    tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
    num_packets++;
  }

  float mpps = num_packets / (tdiff / 1e6) / 1e6;

  printf("\t%12u packets\t%8.1f Kpps\t%8.1f MB/s\n",
	   (unsigned int)num_packets, mpps * 1e3, mpps * sizeof(PKT_CONTENT));
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

