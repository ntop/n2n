/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *               Richard Andrews <andrews@ntop.org>
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
 * Code contributions courtesy of:
 * Massimo Torquati <torquati@ntop.org>
 * Matt Gilg
 *
 */

#include "n2n.h"

#include "minilzo.h"

#include <assert.h>

#if defined(DEBUG)
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT          120
#else /* #if defined(DEBUG) */
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT           (60*20)
#endif /* #if defined(DEBUG) */


const uint8_t broadcast_addr[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const uint8_t multicast_addr[6] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */
const uint8_t ipv6_multicast_addr[6] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 }; /* First 2 bytes are meaningful */

/* ************************************** */

SOCKET open_socket(int local_port, int bind_any) {
  SOCKET sock_fd;
  struct sockaddr_in local_address;
  int sockopt = 1;

  if((sock_fd = socket(PF_INET, SOCK_DGRAM, 0))  < 0) {
    traceEvent(TRACE_ERROR, "Unable to create socket [%s][%d]\n",
	       strerror(errno), sock_fd);
    return(-1);
  }

#ifndef WIN32
  /* fcntl(sock_fd, F_SETFL, O_NONBLOCK); */
#endif

  setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

  memset(&local_address, 0, sizeof(local_address));
  local_address.sin_family = AF_INET;
  local_address.sin_port = htons(local_port);
  local_address.sin_addr.s_addr = htonl(bind_any?INADDR_ANY:INADDR_LOOPBACK);
  if(bind(sock_fd, (struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
    traceEvent(TRACE_ERROR, "Bind error [%s]\n", strerror(errno));
    return(-1);
  }

  return(sock_fd);
}





int traceLevel = 2 /* NORMAL */;
int useSyslog = 0, syslog_opened = 0;

#define N2N_TRACE_DATESIZE 32
void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= traceLevel) {
    char buf[2048];
    char out_buf[640];
    char theDate[N2N_TRACE_DATESIZE];
    char *extra_msg = "";
    time_t theTime = time(NULL);
#ifdef WIN32
	int i;
#endif

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, N2N_TRACE_DATESIZE, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    va_start (va_ap, format);
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);
    va_end(va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

#ifndef WIN32
    if(useSyslog) {
      if(!syslog_opened) {
        openlog("n2n", LOG_PID, LOG_DAEMON);
        syslog_opened = 1;
      }

      snprintf(out_buf, sizeof(out_buf), "%s%s", extra_msg, buf);
      syslog(LOG_INFO, "%s", out_buf);
    } else {
      snprintf(out_buf, sizeof(out_buf), "%s [%11s:%4d] %s%s", theDate, file, line, extra_msg, buf);
      printf("%s\n", out_buf);
      fflush(stdout);
    }
#else
    /* this is the WIN32 code */
	for(i=strlen(file)-1; i>0; i--) if(file[i] == '\\') { i++; break; };
    snprintf(out_buf, sizeof(out_buf), "%s [%11s:%4d] %s%s", theDate, &file[i], line, extra_msg, buf);
    printf("%s\n", out_buf);
    fflush(stdout);
#endif
  }

}

/* *********************************************** */

/* addr should be in network order. Things are so much simpler that way. */
char* intoa(uint32_t /* host order */ addr, char* buf, uint16_t buf_len) {
  char *cp, *retStr;
  uint8_t byteval;
  int n;

  cp = &buf[buf_len];
  *--cp = '\0';

  n = 4;
  do {
    byteval = addr & 0xff;
    *--cp = byteval % 10 + '0';
    byteval /= 10;
    if (byteval > 0) {
      *--cp = byteval % 10 + '0';
      byteval /= 10;
      if (byteval > 0)
        *--cp = byteval + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* *********************************************** */

char * macaddr_str( macstr_t buf,
                    const n2n_mac_t mac )
{
    snprintf(buf, N2N_MACSTR_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
             mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);
    return(buf);
}

/* *********************************************** */

uint8_t is_multi_broadcast(const uint8_t * dest_mac) {

       int is_broadcast = ( memcmp(broadcast_addr, dest_mac, 6) == 0 );
       int is_multicast = ( memcmp(multicast_addr, dest_mac, 3) == 0 );
       int is_ipv6_multicast = ( memcmp(ipv6_multicast_addr, dest_mac, 2) == 0 );

       return is_broadcast || is_multicast || is_ipv6_multicast;

}

/* http://www.faqs.org/rfcs/rfc908.html */


/* *********************************************** */

char* msg_type2str(uint16_t msg_type) {
  switch(msg_type) {
  case MSG_TYPE_REGISTER: return("MSG_TYPE_REGISTER");
  case MSG_TYPE_DEREGISTER: return("MSG_TYPE_DEREGISTER");
  case MSG_TYPE_PACKET: return("MSG_TYPE_PACKET");
  case MSG_TYPE_REGISTER_ACK: return("MSG_TYPE_REGISTER_ACK");
  case MSG_TYPE_REGISTER_SUPER: return("MSG_TYPE_REGISTER_SUPER");
  case MSG_TYPE_REGISTER_SUPER_ACK: return("MSG_TYPE_REGISTER_SUPER_ACK");
  case MSG_TYPE_REGISTER_SUPER_NAK: return("MSG_TYPE_REGISTER_SUPER_NAK");
  case MSG_TYPE_FEDERATION: return("MSG_TYPE_FEDERATION");
  default: return("???");
  }

  return("???");
}

/* *********************************************** */

void hexdump(const uint8_t * buf, size_t len)
{
    size_t i;

    if ( 0 == len ) { return; }

    for(i=0; i<len; i++)
    {
        if((i > 0) && ((i % 16) == 0)) { printf("\n"); }
        printf("%02X ", buf[i] & 0xFF);
    }

    printf("\n");
}

/* *********************************************** */

void print_n2n_version() {
  printf("Welcome to n2n v.%s for %s\n"
         "Built on %s\n"
	 "Copyright 2007-09 - http://www.ntop.org\n\n",
         n2n_sw_version, n2n_sw_osName, n2n_sw_buildDate);
}




/** Find the peer entry in list with mac_addr equal to mac.
 *
 *  Does not modify the list.
 *
 *  @return NULL if not found; otherwise pointer to peer entry.
 */
struct peer_info * find_peer_by_mac( struct peer_info * list, const n2n_mac_t mac )
{
  while(list != NULL)
    {
      if( 0 == memcmp(mac, list->mac_addr, 6) )
        {
	  return list;
        }
      list = list->next;
    }

  return NULL;
}


/** Return the number of elements in the list.
 *
 */
size_t peer_list_size( const struct peer_info * list )
{
  size_t retval=0;

  while ( list )
    {
      ++retval;
      list = list->next;
    }

  return retval;
}

/** Add new to the head of list. If list is NULL; create it.
 *
 *  The item new is added to the head of the list. New is modified during
 *  insertion. list takes ownership of new.
 */
void peer_list_add( struct peer_info * * list,
                    struct peer_info * new )
{
  new->next = *list;
  new->last_seen = time(NULL);
  *list = new;
}


size_t purge_expired_registrations( struct peer_info ** peer_list ) {
  static time_t last_purge = 0;
  time_t now = time(NULL);
  size_t num_reg = 0;

  if((now - last_purge) < PURGE_REGISTRATION_FREQUENCY) return 0;

  traceEvent(TRACE_INFO, "Purging old registrations");

  num_reg = purge_peer_list( peer_list, now-REGISTRATION_TIMEOUT );

  last_purge = now;
  traceEvent(TRACE_INFO, "Remove %ld registrations", num_reg);

  return num_reg;
}

/** Purge old items from the peer_list and return the number of items that were removed. */
size_t purge_peer_list( struct peer_info ** peer_list,
                        time_t purge_before )
{
  struct peer_info *scan;
  struct peer_info *prev;
  size_t retval=0;

  scan = *peer_list;
  prev = NULL;
  while(scan != NULL)
    {
      if(scan->last_seen < purge_before)
        {
	  struct peer_info *next = scan->next;

	  if(prev == NULL)
            {
	      *peer_list = next;
            }
	  else
            {
	      prev->next = next;
            }

	  ++retval;
	  free(scan);
	  scan = next;
        }
      else
        {
	  prev = scan;
	  scan = scan->next;
        }
    }

  return retval;
}

/** Purge all items from the peer_list and return the number of items that were removed. */
size_t clear_peer_list( struct peer_info ** peer_list )
{
    struct peer_info *scan;
    struct peer_info *prev;
    size_t retval=0;

    scan = *peer_list;
    prev = NULL;
    while(scan != NULL)
    {
        struct peer_info *next = scan->next;

        if(prev == NULL)
        {
            *peer_list = next;
        }
        else
        {
            prev->next = next;
        }

        ++retval;
        free(scan);
        scan = next;
    }

    return retval;
}

static uint8_t hex2byte( const char * s )
{
  char tmp[3];
  tmp[0]=s[0];
  tmp[1]=s[1];
  tmp[2]=0; /* NULL term */

  return((uint8_t)strtol( s, NULL, 16 ));
}

extern int str2mac( uint8_t * outmac /* 6 bytes */, const char * s )
{
  size_t i;

  /* break it down as one case for the first "HH", the 5 x through loop for
   * each ":HH" where HH is a two hex nibbles in ASCII. */

  *outmac=hex2byte(s);
  ++outmac;
  s+=2; /* don't skip colon yet - helps generalise loop. */

  for (i=1; i<6; ++i )
    {
      s+=1;
      *outmac=hex2byte(s);
      ++outmac;
      s+=2;
    }

  return 0; /* ok */
}

extern char * sock_to_cstr( n2n_sock_str_t out,
                            const n2n_sock_t * sock )
{
    int r;

    if ( NULL == out ) { return NULL; }
    memset(out, 0, N2N_SOCKBUF_SIZE);

    if ( AF_INET6 == sock->family )
    {
        /* INET6 not written yet */
        r = snprintf( out, N2N_SOCKBUF_SIZE, "XXXX:%hu", sock->port );
        return out;
    }
    else
    {
        const uint8_t * a = sock->addr.v4;
        r = snprintf( out, N2N_SOCKBUF_SIZE, "%hu.%hu.%hu.%hu:%hu", 
                      (a[0] & 0xff), (a[1] & 0xff), (a[2] & 0xff), (a[3] & 0xff), sock->port );
        return out;
    }
}

/* @return zero if the two sockets are equivalent. */
int sock_equal( const n2n_sock_t * a,
                const n2n_sock_t * b )
{
    if ( a->port != b->port ) { return 1; }
    if ( a->family != b->family ) { return 1; }
    switch (a->family) /* they are the same */
    {
    case AF_INET:
        if ( 0 != memcmp( a->addr.v4, b->addr.v4, IPV4_SIZE ) ) { return 1;};
        break;
    default:
        if ( 0 != memcmp( a->addr.v6, b->addr.v6, IPV6_SIZE ) ) { return 1;};
        break;
    }

    return 0;
}

