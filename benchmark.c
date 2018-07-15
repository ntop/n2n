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


#ifdef WIN32
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

int main(int argc, char * argv[]) {
  uint8_t pktbuf[N2N_PKT_BUF_SIZE];
  n2n_trans_op_t transop_null;

  n2n_common_t cmn;
  n2n_PACKET_t pkt;
  n2n_community_t c;

  struct timeval t1;
  struct timeval t2;

  size_t i;
  size_t n;
  size_t idx;
  size_t rem;
  ssize_t nw;
  ssize_t tdiff;

  transop_null_init( &transop_null );
  memset(c,0,sizeof(N2N_COMMUNITY_SIZE));

  n=10000;
  memcpy( c, "abc123def456", 12 );

  gettimeofday( &t1, NULL );
  for(i=0; i<n; ++i)
    {
      nw = do_encode_packet( pktbuf, N2N_PKT_BUF_SIZE, c);

      nw += transop_null.fwd( &transop_null,
			      pktbuf+nw, N2N_PKT_BUF_SIZE-nw,
			      PKT_CONTENT, sizeof(PKT_CONTENT) );

      idx=0;
      rem=nw;

      decode_common( &cmn, pktbuf, &rem, &idx);
      decode_PACKET( &pkt, &cmn, pktbuf, &rem, &idx );

      if ( 0 == (i%1000) )
        {
	  fprintf(stderr,".");
        }
    }
  gettimeofday( &t2, NULL );

  tdiff = ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);

  fprintf( stderr, "\nrun %u times. (%u -> %u nsec each) %u.%06u -> %u.%06u.\n",
	   (unsigned int)i, (unsigned int)tdiff,
	   (unsigned int)((tdiff *1000)/i),
	   (uint32_t)t1.tv_sec, (uint32_t)t1.tv_usec,
	   (uint32_t)t2.tv_sec, (uint32_t)t2.tv_usec );

  return 0;
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
