/**
 * (C) 2019-22 - ntop.org and contributors
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

#include "config.h"

#ifdef HAVE_LIBPCAP

#include <errno.h>             // for errno
#include <pcap.h>
#include <signal.h>            // for signal, SIGINT, SIGTERM
#include "n2n.h"
#include "n2n_wire.h"

#define SNAPLEN 1500
#define TIMEOUT 200

/* *************************************************** */

static int aes_mode = 0;
static int running = 1;
static char *ifname = NULL;
static n2n_edge_conf_t conf;
static n2n_trans_op_t transop;
static pcap_t *handle;
static pcap_dumper_t *dumper;

/* *************************************************** */

static void help() {
  fprintf(stderr, "n2n-decode -i ifname -k key -c community [-B bpf] [-w fname] [-v]"
#ifdef N2N_HAVE_AES
    " [-A]"
#endif
    "\n");
  fprintf(stderr, "-i <ifname>              | Specify the capture interface name.\n");
  fprintf(stderr, "-c <community>           | Specify the community.\n");
  fprintf(stderr, "-k <key>                 | Specify the encryption key.\n");
#ifdef N2N_HAVE_AES
  fprintf(stderr, "-A                       | Use AES decryption (default=use twofish).\n");
#endif
  fprintf(stderr, "-B <bpf>                 | Use set a BPF filter for the capture.\n");
  fprintf(stderr, "-w <fname>               | Write decoded PCAP to file.\n");
  fprintf(stderr, "-v                       | Increase verbosity level.\n");

  exit(0);
}

/* *************************************************** */

#ifdef _WIN32
BOOL WINAPI term_handler(DWORD sig)
#else
static void term_handler(int sig)
#endif
{
  static int called = 0;

  if(called) {
    traceEvent(TRACE_NORMAL, "Ok I am leaving now");
    _exit(0);
  } else {
    traceEvent(TRACE_NORMAL, "Shutting down...");
    called = 1;
  }

  running = 0;
#ifdef _WIN32
  return(TRUE);
#endif
}

/* *************************************************** */

static void write_packet(const u_char *packet, struct pcap_pkthdr *hdr) {
  pcap_dump((unsigned char*)dumper, hdr, packet);
  pcap_dump_flush(dumper);
}

/* *************************************************** */

static int decode_encrypted_packet(const u_char *packet, struct pcap_pkthdr *header,
          n2n_PACKET_t *pkt, int encrypted_offset) {
  uint8_t decoded_packet[encrypted_offset + N2N_PKT_BUF_SIZE];
  int decoded_eth_size;
  int transop_shift;

  switch(pkt->transform) {
  case N2N_TRANSFORM_ID_NULL:
    /* Not encrypted, dump it */
    write_packet(packet, header);
    break;
  case N2N_TRANSFORM_ID_TWOFISH:
    if(aes_mode) {
      traceEvent(TRACE_INFO, "Skipping twofish encrypted packet");
      return(-1);
    }
    break;
  case N2N_TRANSFORM_ID_AES:
    if(!aes_mode) {
      traceEvent(TRACE_INFO, "Skipping AES encrypted packet");
      return(-1);
    }
    break;
  default:
    traceEvent(TRACE_INFO, "Skipping unknown transform packet: %d", pkt->transform);
    return(-2);
  }

  decoded_eth_size = transop.rev(&transop, decoded_packet+encrypted_offset, N2N_PKT_BUF_SIZE, packet + encrypted_offset,
    header->caplen - encrypted_offset, pkt->srcMac);

  transop_shift = (header->caplen - encrypted_offset) - decoded_eth_size;

  if(transop_shift >= 0) {
    int transform_id_offset = encrypted_offset - 2;

    /* Copy the initial part of the packet */
    memcpy(decoded_packet, packet, encrypted_offset);

    /* Change the packet transform to NULL as there is now plaintext data */
    *((u_int16_t*)(decoded_packet + transform_id_offset)) = htons(N2N_TRANSFORM_ID_NULL);

    // TODO fix IP and UDP chechsums
    write_packet(decoded_packet, header);
    return(0);
  }

  traceEvent(TRACE_INFO, "Something was wrong in the decoding");
  return(-3);
}

/* *************************************************** */

#define ETH_SIZE 14
#define UDP_SIZE 8
#define MIN_IP_SIZE 20
#define MIN_LEN (ETH_SIZE + UDP_SIZE + MIN_IP_SIZE + sizeof(n2n_common_t))

static int run_packet_loop() {
  struct pcap_pkthdr header;
  const u_char *packet;

  traceEvent(TRACE_NORMAL, "Capturing packets on %s...", ifname);

  while(running) {
    n2n_common_t common;
    n2n_PACKET_t pkt;
    uint ipsize, common_offset;
    size_t idx, rem;

    memset(&common, 0, sizeof(common));
    memset(&pkt, 0, sizeof(pkt));

    packet = pcap_next(handle, &header);

    if(!packet)
      continue;

    if(header.caplen < MIN_LEN) {
      traceEvent(TRACE_INFO, "Skipping packet too small: size=%d", header.caplen);
      continue;
    }

    if(ntohs(*(uint16_t*)(packet + 12)) != 0x0800) {
      traceEvent(TRACE_INFO, "Skipping non IPv4 packet");
      continue;
    }

    if(packet[ETH_SIZE + 9] != IPPROTO_UDP) {
      traceEvent(TRACE_INFO, "Skipping non UDP packet");
      continue;
    }

    ipsize = (packet[ETH_SIZE] & 0x0F) * 4;
    common_offset = ETH_SIZE + ipsize + UDP_SIZE;

    idx = common_offset;
    rem = header.caplen - idx;

    if(decode_common(&common, packet, &rem, &idx) == -1) {
      traceEvent(TRACE_INFO, "Skipping packet, decode common failed");
      continue;
    }

    if(strncmp((char*)conf.community_name, (char*)common.community, N2N_COMMUNITY_SIZE) != 0) {
      traceEvent(TRACE_INFO, "Skipping packet with non-matching community");
      continue;
    }

    switch(common.pc) {
    case n2n_ping:
    case n2n_register:
    case n2n_deregister:
    case n2n_register_ack:
    case n2n_register_super:
    case n2n_register_super_ack:
    case n2n_register_super_nak:
    case n2n_federation:
    case n2n_peer_info:
    case n2n_query_peer:
      write_packet(packet, &header);
      break;
    case n2n_packet:
      decode_PACKET(&pkt, &common, packet, &rem, &idx);
      decode_encrypted_packet(packet, &header, &pkt, idx);
      break;
    default:
      traceEvent(TRACE_INFO, "Skipping packet with unknown type: %d", common.pc);
      continue;
    }
  }

  return(0);
}

/* *************************************************** */

int main(int argc, char* argv[]) {
  u_char c;
  struct bpf_program fcode;
  char *bpf_filter = NULL, *out_fname = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  int rv = 0;
  FILE *outf = stdout;

  /* Trace to stderr to leave stdout for the PCAP dump if "-w -" is used */
  setTraceFile(stderr);

  /* Init configuration */
  edge_init_conf_defaults(&conf);

  while((c = getopt(argc, argv,
    "k:i:B:w:c:v"
#ifdef N2N_HAVE_AES
    "A"
#endif
  )) != '?') {
    if(c == 255) break;

    switch(c) {
    case 'c':
      strncpy((char*)conf.community_name, optarg, sizeof(conf.community_name)-1);
      break;
    case 'i':
      ifname = strdup(optarg);
      break;
    case 'k':
      conf.encrypt_key = strdup(optarg);
      break;
    case 'B':
      bpf_filter = strdup(optarg);
      break;
#ifdef N2N_HAVE_AES
    case 'A':
      aes_mode = 1;
      break;
#endif
    case 'w':
      if(strcmp(optarg, "-") != 0)
        out_fname = strdup(optarg);
      break;
    case 'v': /* verbose */
      setTraceLevel(getTraceLevel() + 1);
      break;
    default:
      help();
    }
  }

  if((ifname == NULL) || (conf.encrypt_key == NULL) || (conf.community_name[0] == '\0'))
    help();

#ifdef N2N_HAVE_AES
  if(aes_mode)
    n2n_transop_aes_init(&conf, &transop);
  else
#endif
    n2n_transop_tf_init(&conf, &transop);

  if((handle = pcap_create(ifname, errbuf)) == NULL) {
    traceEvent(TRACE_ERROR, "Cannot open device %s: %s", ifname, errbuf);
    return(1);
  }

  if((pcap_set_timeout(handle, TIMEOUT) != 0) ||
     (pcap_set_snaplen(handle, SNAPLEN) != 0)) {
    traceEvent(TRACE_ERROR, "Error while setting timeout/snaplen");
    return(1);
  }

#ifdef HAVE_PCAP_IMMEDIATE_MODE
  /* The timeout is not honored unless immediate mode is set.
   * See https://github.com/mfontanini/libtins/issues/180 */
  if(pcap_set_immediate_mode(handle, 1) != 0) {
    traceEvent(TRACE_ERROR, "Could not set PCAP immediate mode");
    return(1);
  }
#endif

  if(pcap_activate(handle) != 0) {
    traceEvent(TRACE_ERROR, "pcap_activate failed: %s", pcap_geterr(handle));
  }

  if(pcap_datalink(handle) != DLT_EN10MB) {
    traceEvent(TRACE_ERROR, "Device %s doesn't provide Ethernet headers - not supported", ifname);
    return(2);
  }

  if(bpf_filter) {
    bpf_u_int32 net, mask;

    if(pcap_lookupnet(ifname, &net, &mask, errbuf) == -1) {
      traceEvent(TRACE_WARNING, "Couldn't get netmask for device %s: %s", ifname, errbuf);
      net = 0;
      mask = 0;
    }

    if((pcap_compile(handle, &fcode, bpf_filter, 1, net) < 0)
     || (pcap_setfilter(handle, &fcode) < 0)) {
       traceEvent(TRACE_ERROR, "Could not set BPF filter: %s", pcap_geterr(handle));
       return(3);
    }
  }

  if(out_fname) {
    outf = fopen(out_fname, "wb");

    if(outf == NULL) {
      traceEvent(TRACE_ERROR, "Could not open %s for write[%d]: %s", errno, strerror(errno));
      return(4);
    }
  }

  dumper = pcap_dump_fopen(handle, outf);

  if(dumper == NULL) {
    traceEvent(TRACE_ERROR, "Could dump file: %s", pcap_geterr(handle));
    return(5);
  }

#ifdef _WIN32
  SetConsoleCtrlHandler(term_handler, TRUE);
#else
  signal(SIGTERM, term_handler);
  signal(SIGINT,  term_handler);
#endif

  rv = run_packet_loop();

  /* Cleanup */
  pcap_close(handle);

  if(conf.encrypt_key) free(conf.encrypt_key);
  if(bpf_filter) free(bpf_filter);
  if(ifname) free(ifname);

  if(out_fname) {
    fclose(outf);
    free(out_fname);
  }

  return(rv);
}

#else

#include <stdio.h>

int main() {
    printf("n2n was compiled without libpcap support");
    return -1;
}

#endif /* HAVE_LIBPCAP */
