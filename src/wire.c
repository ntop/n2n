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

/** Routines for encoding and decoding n2n packets on the wire.
 *
 *  encode_X(base,idx,v) prototypes are inspired by the erlang internal
 *  encoding model. Passing the start of a buffer in base and a pointer to an
 *  integer (initially set to zero). Each encode routine increases idx by the
 *  amount written and returns the amount written. In this way complex sequences
 *  of encodings can be represented cleanly. See encode_register() for an
 *  example.
 */


#include <stdint.h>      // for uint8_t, uint16_t, uint32_t, uint64_t
#include <string.h>      // for size_t, memset, memcpy
#include "portable_endian.h"  // for be64toh, htobe64
#include "n2n.h"         // for n2n_sock_t, n2n_common_t, n2n_auth_t, n2n_RE...
#include "n2n_wire.h"    // for decode_PACKET, decode_PEER_INFO, decode_QUER...

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <netinet/in.h>  // for sockaddr_in, sockaddr_in6, in6_addr, in_addr
#include <sys/socket.h>  // for AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM
#include <sys/un.h>      // for sa_family_t
#endif


int encode_uint8 (uint8_t * base,
                  size_t * idx,
                  const uint8_t v) {

    *(base + (*idx)) = (v & 0xff);
    ++(*idx);

    return 1;
}

int decode_uint8 (uint8_t * out,
                  const uint8_t * base,
                  size_t * rem,
                  size_t * idx) {

    if(*rem < 1) {
        return 0;
    }

    *out = ( base[*idx] & 0xff );
    ++(*idx);
    --(*rem);

    return 1;
}

int encode_uint16 (uint8_t * base,
                   size_t * idx,
                   const uint16_t v) {

    *(base + (*idx))     = ( v >> 8) & 0xff;
    *(base + (1 + *idx)) = ( v & 0xff );
    *idx += 2;

    return 2;
}

int decode_uint16 (uint16_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    if(*rem < 2) {
        return 0;
    }

    *out  = ( base[*idx] & 0xff ) << 8;
    *out |= ( base[1 + *idx] & 0xff );
    *idx += 2;
    *rem -= 2;

    return 2;
}

int encode_uint32 (uint8_t * base,
                   size_t * idx,
                   const uint32_t v) {

    *(base + (0 + *idx)) = ( v >> 24) & 0xff;
    *(base + (1 + *idx)) = ( v >> 16) & 0xff;
    *(base + (2 + *idx)) = ( v >> 8) & 0xff;
    *(base + (3 + *idx)) = ( v & 0xff );
    *idx += 4;

    return 4;
}

int decode_uint32 (uint32_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    if(*rem < 4) {
        return 0;
    }

    *out  = ( base[0 + *idx] & 0xff ) << 24;
    *out |= ( base[1 + *idx] & 0xff ) << 16;
    *out |= ( base[2 + *idx] & 0xff ) << 8;
    *out |= ( base[3 + *idx] & 0xff );
    *idx += 4;
    *rem -= 4;

    return 4;
}

int encode_uint64 (uint8_t * base,
                   size_t * idx,
                   const uint64_t v) {

    *(uint64_t*)(base + *idx) = htobe64(v);
    *idx += 8;

    return 8;
}

int decode_uint64 (uint64_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    if(*rem < 8) {
        return 0;
    }

    *out  = be64toh(*(uint64_t*)base + *idx);
    *idx += 8;
    *rem -= 8;

    return 8;
}

int encode_buf (uint8_t * base,
                size_t * idx,
                const void * p,
                size_t s) {

    memcpy((base + (*idx)), p, s);
    *idx += s;

    return s;
}

/* Copy from base to out of size bufsize */
int decode_buf (uint8_t * out,
                size_t bufsize,
                const uint8_t * base,
                size_t * rem,
                size_t * idx) {

    if(*rem < bufsize) {
        return 0;
    }

    memcpy(out, (base + *idx), bufsize);
    *idx += bufsize;
    *rem -= bufsize;

    return bufsize;
}


int encode_mac (uint8_t * base,  /* n2n_mac_t is typedefed array type which is always passed by reference */
                size_t * idx,
                const n2n_mac_t m) {

    return encode_buf(base, idx, m, N2N_MAC_SIZE);
}

int decode_mac (n2n_mac_t out,
                const uint8_t * base,
                size_t * rem,
                size_t * idx) {

    return decode_buf(out, N2N_MAC_SIZE, base, rem, idx);
}

int encode_cookie (uint8_t * base,
                   size_t * idx,
                   const n2n_cookie_t c) {

    return encode_uint32(base, idx, c);
}

int decode_cookie (n2n_cookie_t * out,  /* cookies are typedef'd as uint32_t which needs to correspond to this code */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    return decode_uint32(out, base, rem, idx);
}


int encode_common (uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common) {

    uint16_t flags = 0;

    encode_uint8(base, idx, N2N_PKT_VERSION);
    encode_uint8(base, idx, common->ttl);

    flags  = common->pc & N2N_FLAGS_TYPE_MASK;
    flags |= common->flags & N2N_FLAGS_BITS_MASK;

    encode_uint16(base, idx, flags);
    encode_buf(base, idx, common->community, N2N_COMMUNITY_SIZE);

    return -1;
}

int decode_common (n2n_common_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    size_t idx0 = *idx;
    uint8_t dummy = 0;

    decode_uint8(&dummy, base, rem, idx);

    if(N2N_PKT_VERSION != dummy) {
        return -1;
    }

    decode_uint8(&(out->ttl), base, rem, idx);
    decode_uint16(&(out->flags), base, rem, idx);
    out->pc = (out->flags & N2N_FLAGS_TYPE_MASK);
    out->flags &= N2N_FLAGS_BITS_MASK;

    decode_buf(out->community, N2N_COMMUNITY_SIZE, base, rem, idx);

    return (*idx - idx0);
}


int encode_sock (uint8_t * base,
                 size_t * idx,
                 const n2n_sock_t * sock) {

    int retval = 0;
    uint16_t f;

    switch(sock->family) {
        case AF_INET: {
            f = 0;
            if(sock->type == SOCK_STREAM) {
                f |= 0x4000;
            }
            retval += encode_uint16(base, idx, f);
            retval += encode_uint16(base, idx, sock->port);
            retval += encode_buf(base, idx, sock->addr.v4, IPV4_SIZE);
            break;
        }

        case AF_INET6: {
            f = 0x8000;
            if(sock->type == SOCK_STREAM) {
                f |= 0x4000;
            }
            retval += encode_uint16(base, idx, f);
            retval += encode_uint16(base, idx, sock->port);
            retval += encode_buf(base, idx, sock->addr.v6, IPV6_SIZE);
            break;
        }

        default:
            retval = -1;
    }

    return retval;
}


int decode_sock (n2n_sock_t * sock,
                 const uint8_t * base,
                 size_t * rem,
                 size_t * idx) {

    size_t * idx0 = idx;
    uint16_t f = 0;

    decode_uint16(&f, base, rem, idx);
    decode_uint16(&(sock->port), base, rem, idx);

    if(f & 0x8000) {
        // IPv6
        sock->family = AF_INET6;
        decode_buf(sock->addr.v6, IPV6_SIZE, base, rem, idx);
    } else {
        // IPv4
        sock->family = AF_INET;
        memset(sock->addr.v6, 0, IPV6_SIZE); /* so memcmp() works for equality. */
        decode_buf(sock->addr.v4, IPV4_SIZE, base, rem, idx);
    }

    if(f & 0x4000) {
        // TCP
        sock->type = SOCK_STREAM;
    } else {
        // UDP
        sock->type = SOCK_DGRAM;
    }

    return (idx - idx0);
}


// bugfix for https://github.com/ntop/n2n/issues/1029
// REVISIT: best to be removed with 4.0
int encode_sock_payload (uint8_t * base,
                         size_t * idx,
                         const n2n_sock_t * sock) {

    int retval = 0;

    retval += encode_uint8(base, idx, sock->family);
    retval += encode_uint8(base, idx, 0); // blank
    retval += encode_uint8(base, idx, sock->port & 0x00FF);
    retval += encode_uint8(base, idx, sock->port >> 8);
    // copy full address field length
    retval += encode_buf(base, idx, sock->addr.v6, IPV6_SIZE);

    return retval;
}


// bugfix for https://github.com/ntop/n2n/issues/1029
// REVISIT: best to be removed with 4.0
int decode_sock_payload (n2n_sock_t * sock,
                         const uint8_t * base,
                         size_t * rem,
                         size_t * idx) {

    int retval = 0;
    uint8_t port_low = 0;
    uint8_t port_high = 0;

    retval += decode_uint8(&(sock->family), base, rem, idx);
    ++(*idx); // skip blank
    --(*rem);
    ++retval;
    retval += decode_uint8(&port_low, base, rem, idx);
    retval += decode_uint8(&port_high, base, rem, idx);
    sock->port = ((uint16_t)port_high << 8) + port_low;
    // copy full address field length
    retval += decode_buf(sock->addr.v6, IPV6_SIZE, base, rem, idx);

    return retval;
}


int encode_REGISTER (uint8_t *base,
                     size_t *idx,
                     const n2n_common_t *common,
                     const n2n_REGISTER_t *reg) {

    int retval = 0;

    retval += encode_common(base, idx, common);
    retval += encode_cookie(base, idx, reg->cookie);
    retval += encode_mac(base, idx, reg->srcMac);
    retval += encode_mac(base, idx, reg->dstMac);
    if(common->flags & N2N_FLAGS_SOCKET) {
        retval += encode_sock(base, idx, &(reg->sock));
    }
    retval += encode_uint32(base, idx, reg->dev_addr.net_addr);
    retval += encode_uint8(base, idx, reg->dev_addr.net_bitlen);
    retval += encode_buf(base, idx, reg->dev_desc, N2N_DESC_SIZE);

    return retval;
}


int decode_REGISTER (n2n_REGISTER_t *reg,
                     const n2n_common_t *cmn, /* info on how to interpret it */
                     const uint8_t *base,
                     size_t *rem,
                     size_t *idx) {

    size_t retval = 0;
    memset(reg, 0, sizeof(n2n_REGISTER_t));

    retval += decode_cookie(&reg->cookie, base, rem, idx);
    retval += decode_mac(reg->srcMac, base, rem, idx);
    retval += decode_mac(reg->dstMac, base, rem, idx);
    if(cmn->flags & N2N_FLAGS_SOCKET) {
        retval += decode_sock(&(reg->sock), base, rem, idx);
    }
    retval += decode_uint32(&(reg->dev_addr.net_addr), base, rem, idx);
    retval += decode_uint8(&(reg->dev_addr.net_bitlen), base, rem, idx);
    retval += decode_buf(reg->dev_desc, N2N_DESC_SIZE, base, rem, idx);

    return retval;
}


int encode_REGISTER_SUPER (uint8_t *base,
                           size_t *idx,
                           const n2n_common_t *common,
                           const n2n_REGISTER_SUPER_t *reg) {

    int retval = 0;

    retval += encode_common(base, idx, common);
    retval += encode_cookie(base, idx, reg->cookie);
    retval += encode_mac(base, idx, reg->edgeMac);
    if(common->flags & N2N_FLAGS_SOCKET) {
        retval += encode_sock(base, idx, &(reg->sock));
    }
    retval += encode_uint32(base, idx, reg->dev_addr.net_addr);
    retval += encode_uint8(base, idx, reg->dev_addr.net_bitlen);
    retval += encode_buf(base, idx, reg->dev_desc, N2N_DESC_SIZE);
    retval += encode_uint16(base, idx, reg->auth.scheme);
    retval += encode_uint16(base, idx, reg->auth.token_size);
    retval += encode_buf(base, idx, reg->auth.token, reg->auth.token_size);
    retval += encode_uint32(base, idx, reg->key_time);

    return retval;
}


int decode_REGISTER_SUPER (n2n_REGISTER_SUPER_t *reg,
                           const n2n_common_t *cmn, /* info on how to interpret it */
                           const uint8_t *base,
                           size_t *rem,
                           size_t *idx) {

    size_t retval = 0;
    memset(reg, 0, sizeof(n2n_REGISTER_SUPER_t));

    retval += decode_cookie(&reg->cookie, base, rem, idx);
    retval += decode_mac(reg->edgeMac, base, rem, idx);
    if(cmn->flags & N2N_FLAGS_SOCKET) {
        retval += decode_sock(&(reg->sock), base, rem, idx);
    }
    retval += decode_uint32(&(reg->dev_addr.net_addr), base, rem, idx);
    retval += decode_uint8(&(reg->dev_addr.net_bitlen), base, rem, idx);
    retval += decode_buf(reg->dev_desc, N2N_DESC_SIZE, base, rem, idx);
    retval += decode_uint16(&(reg->auth.scheme), base, rem, idx);
    retval += decode_uint16(&(reg->auth.token_size), base, rem, idx);
    retval += decode_buf(reg->auth.token, reg->auth.token_size, base, rem, idx);
    retval += decode_uint32(&(reg->key_time), base, rem, idx);

    return retval;
}


int encode_UNREGISTER_SUPER (uint8_t *base,
                             size_t *idx,
                             const n2n_common_t *common,
                             const n2n_UNREGISTER_SUPER_t *unreg) {

    int retval = 0;

    retval += encode_common(base, idx, common);
    retval += encode_uint16(base, idx, unreg->auth.scheme);
    retval += encode_uint16(base, idx, unreg->auth.token_size);
    retval += encode_buf(base, idx, unreg->auth.token, unreg->auth.token_size);
    retval += encode_mac(base, idx, unreg->srcMac);

    return retval;
}


int decode_UNREGISTER_SUPER (n2n_UNREGISTER_SUPER_t *unreg,
                             const n2n_common_t *cmn, /* info on how to interpret it */
                             const uint8_t *base,
                             size_t *rem,
                             size_t *idx) {

    size_t retval = 0;
    memset(unreg, 0, sizeof(n2n_UNREGISTER_SUPER_t));

    retval += decode_uint16(&(unreg->auth.scheme), base, rem, idx);
    retval += decode_uint16(&(unreg->auth.token_size), base, rem, idx);
    retval += decode_buf(unreg->auth.token, unreg->auth.token_size, base, rem, idx);
    retval += decode_mac(unreg->srcMac, base, rem, idx);

    return retval;
}


int encode_REGISTER_ACK (uint8_t *base,
                         size_t *idx,
                         const n2n_common_t *common,
                         const n2n_REGISTER_ACK_t *reg) {

    int retval = 0;

    retval += encode_common(base, idx, common);
    retval += encode_cookie(base, idx, reg->cookie);
    retval += encode_mac(base, idx, reg->dstMac);
    retval += encode_mac(base, idx, reg->srcMac);

    /* The socket in REGISTER_ACK is the socket from which the REGISTER
     * arrived. This is sent back to the sender so it knows what its public
     * socket is. */
    if(common->flags & N2N_FLAGS_SOCKET) {
        retval += encode_sock(base, idx, &(reg->sock));
    }

    return retval;
}


int decode_REGISTER_ACK (n2n_REGISTER_ACK_t *reg,
                         const n2n_common_t *cmn, /* info on how to interpret it */
                         const uint8_t *base,
                         size_t *rem,
                         size_t *idx) {

    size_t retval = 0;
    memset(reg, 0, sizeof(n2n_REGISTER_ACK_t));

    retval += decode_cookie(&reg->cookie, base, rem, idx);
    retval += decode_mac(reg->dstMac, base, rem, idx);
    retval += decode_mac(reg->srcMac, base, rem, idx);

    /* The socket in REGISTER_ACK is the socket from which the REGISTER
     * arrived. This is sent back to the sender so it knows what its public
     * socket is. */
    if(cmn->flags & N2N_FLAGS_SOCKET) {
        retval += decode_sock(&(reg->sock), base, rem, idx);
    }

    return retval;
}


int encode_REGISTER_SUPER_ACK (uint8_t *base,
                               size_t *idx,
                               const n2n_common_t *common,
                               const n2n_REGISTER_SUPER_ACK_t *reg,
                               uint8_t *tmpbuf) {

    int retval = 0;

    retval += encode_common(base, idx, common);
    retval += encode_cookie(base, idx, reg->cookie);
    retval += encode_mac(base, idx, reg->srcMac);
    retval += encode_uint32(base, idx, reg->dev_addr.net_addr);
    retval += encode_uint8(base, idx, reg->dev_addr.net_bitlen);
    retval += encode_uint16(base, idx, reg->lifetime);

    retval += encode_sock(base, idx, &(reg->sock));

    retval += encode_uint16(base, idx, reg->auth.scheme);
    retval += encode_uint16(base, idx, reg->auth.token_size);
    retval += encode_buf(base, idx, reg->auth.token, reg->auth.token_size);

    retval += encode_uint8(base, idx, reg->num_sn);
    retval += encode_buf(base, idx, tmpbuf, (reg->num_sn*REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE));

    retval += encode_uint32(base, idx, reg->key_time);

    return retval;
}


int decode_REGISTER_SUPER_ACK (n2n_REGISTER_SUPER_ACK_t *reg,
                               const n2n_common_t *cmn, /* info on how to interpret it */
                               const uint8_t *base,
                               size_t *rem,
                               size_t *idx,
                               uint8_t *tmpbuf) {

    size_t retval = 0;
    memset(reg, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));

    retval += decode_cookie(&reg->cookie, base, rem, idx);
    retval += decode_mac(reg->srcMac, base, rem, idx);
    retval += decode_uint32(&(reg->dev_addr.net_addr), base, rem, idx);
    retval += decode_uint8(&(reg->dev_addr.net_bitlen), base, rem, idx);
    retval += decode_uint16(&(reg->lifetime), base, rem, idx);

    /* Socket is mandatory in this message type */
    retval += decode_sock(&(reg->sock), base, rem, idx);

    retval += decode_uint16(&(reg->auth.scheme), base, rem, idx);
    retval += decode_uint16(&(reg->auth.token_size), base, rem, idx);
    retval += decode_buf(reg->auth.token, reg->auth.token_size, base, rem, idx);

    /* Following the edge socket are an array of backup supernodes. */
    retval += decode_uint8(&(reg->num_sn), base, rem, idx);
    retval += decode_buf(tmpbuf, (reg->num_sn * REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE), base, rem, idx);

    retval += decode_uint32(&(reg->key_time), base, rem, idx);

    return retval;
}


int encode_REGISTER_SUPER_NAK (uint8_t *base,
                               size_t *idx,
                               const n2n_common_t *common,
                               const n2n_REGISTER_SUPER_NAK_t *nak) {

    int retval = 0;

    retval += encode_common(base, idx, common);
    retval += encode_cookie(base, idx, nak->cookie);
    retval += encode_mac(base, idx, nak->srcMac);

    retval += encode_uint16(base, idx, nak->auth.scheme);
    retval += encode_uint16(base, idx, nak->auth.token_size);
    retval += encode_buf(base, idx, nak->auth.token, nak->auth.token_size);

    return retval;
}


int decode_REGISTER_SUPER_NAK (n2n_REGISTER_SUPER_NAK_t *nak,
                               const n2n_common_t *cmn, /* info on how to interpret it */
                               const uint8_t *base,
                               size_t *rem,
                               size_t *idx) {

    size_t retval = 0;
    memset(nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

    retval += decode_cookie(&nak->cookie, base, rem, idx);
    retval += decode_mac(nak->srcMac, base, rem, idx);

    retval += decode_uint16(&(nak->auth.scheme), base, rem, idx);
    retval += decode_uint16(&(nak->auth.token_size), base, rem, idx);
    retval += decode_buf(nak->auth.token, nak->auth.token_size, base, rem, idx);

    return retval;
}


int fill_sockaddr (struct sockaddr * addr,
                   size_t addrlen,
                   const n2n_sock_t * sock) {

    int retval = -1;

    if(AF_INET == sock->family) {
        if(addrlen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in * si = (struct sockaddr_in *)addr;
            si->sin_family = sock->family;
            si->sin_port = htons(sock->port);
            memcpy(&(si->sin_addr.s_addr), sock->addr.v4, IPV4_SIZE);
            retval = 0;
        }
    }
    if(AF_INET6 == sock->family) {
        if(addrlen >= sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 * si = (struct sockaddr_in6 *)addr;
            si->sin6_family = sock->family;
            si->sin6_port = htons(sock->port);
            memcpy(&(si->sin6_addr.s6_addr), sock->addr.v6, IPV6_SIZE);
            retval = 0;
        }
    }

    return retval;
}


// fills struct sockaddr's data into n2n_sock
int fill_n2nsock (n2n_sock_t* sock, const struct sockaddr* sa) {

    sock->family = sa->sa_family;

    switch(sock->family) {
        case AF_INET: {
            sock->port = ntohs(((struct sockaddr_in*)sa)->sin_port);
            memcpy(sock->addr.v4, &((struct sockaddr_in*)sa)->sin_addr.s_addr, sizeof(struct in_addr));
            break;
        }
        case AF_INET6: {
            sock->port = ntohs(((struct sockaddr_in6*)sa)->sin6_port);
            memcpy(sock->addr.v6, &((struct sockaddr_in6*)sa)->sin6_addr.s6_addr, sizeof(struct in6_addr));
            break;
        }
        default:
            sock->family = AF_INVALID;
            return -1;
            break; /* well, ... */
    }

    return 0;
}


int encode_PACKET (uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common,
                   const n2n_PACKET_t * pkt) {

    int retval = 0;

    retval += encode_common(base, idx, common);
    retval += encode_mac(base, idx, pkt->srcMac);
    retval += encode_mac(base, idx, pkt->dstMac);
    if(common->flags & N2N_FLAGS_SOCKET) {
        retval += encode_sock(base, idx, &(pkt->sock));
    }
    retval += encode_uint8(base, idx, pkt->compression);
    retval += encode_uint8(base, idx, pkt->transform);

    return retval;
}


int decode_PACKET (n2n_PACKET_t * pkt,
                   const n2n_common_t * cmn, /* info on how to interpret it */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    size_t retval = 0;
    memset(pkt, 0, sizeof(n2n_PACKET_t));

    retval += decode_mac(pkt->srcMac, base, rem, idx);
    retval += decode_mac(pkt->dstMac, base, rem, idx);

    if(cmn->flags & N2N_FLAGS_SOCKET) {
        retval += decode_sock(&(pkt->sock), base, rem, idx);
    }

    retval += decode_uint8(&(pkt->compression), base, rem, idx);
    retval += decode_uint8(&(pkt->transform), base, rem, idx);

    return retval;
}


int encode_PEER_INFO (uint8_t *base,
                      size_t *idx,
                      const n2n_common_t *cmn,
                      const n2n_PEER_INFO_t *pkt) {

    int retval = 0;

    retval += encode_common(base, idx, cmn);
    retval += encode_uint16(base, idx, pkt->aflags);
    retval += encode_mac(base, idx, pkt->srcMac);
    retval += encode_mac(base, idx, pkt->mac);
    retval += encode_sock(base, idx, &pkt->sock);
    if(cmn->flags & N2N_FLAGS_SOCKET) {
        retval += encode_sock(base, idx, &pkt->preferred_sock);
    }
    retval += encode_uint32(base, idx, (uint32_t)pkt->load);
    retval += encode_uint32(base, idx, (uint32_t)pkt->uptime);
    retval += encode_buf(base, idx, pkt->version, sizeof(n2n_version_t));

    return retval;
}


int decode_PEER_INFO (n2n_PEER_INFO_t *pkt,
                      const n2n_common_t *cmn, /* info on how to interpret it */
                      const uint8_t *base,
                      size_t *rem,
                      size_t *idx) {

    size_t retval = 0;
    memset(pkt, 0, sizeof(n2n_PEER_INFO_t));

    retval += decode_uint16(&(pkt->aflags), base, rem, idx);
    retval += decode_mac(pkt->srcMac, base, rem, idx);
    retval += decode_mac(pkt->mac, base, rem, idx);
    retval += decode_sock(&pkt->sock, base, rem, idx);
    if(cmn->flags & N2N_FLAGS_SOCKET) {
        retval += decode_sock(&pkt->preferred_sock, base, rem, idx);
    }
    retval += decode_uint32(&pkt->load, base, rem, idx);
    retval += decode_uint32((uint32_t*)&pkt->uptime, base, rem, idx);
    retval += decode_buf((uint8_t*)pkt->version, sizeof(n2n_version_t), base, rem, idx);

    return retval;
}


int encode_QUERY_PEER (uint8_t * base,
                       size_t * idx,
                       const n2n_common_t * common,
                       const n2n_QUERY_PEER_t * pkt) {

    int retval = 0;

    retval += encode_common(base, idx, common);
    retval += encode_mac(base, idx, pkt->srcMac);
    retval += encode_mac(base, idx, pkt->targetMac);
    retval += encode_uint16(base, idx, pkt->aflags);

    return retval;
}

int decode_QUERY_PEER (n2n_QUERY_PEER_t * pkt,
                       const n2n_common_t * cmn, /* info on how to interpret it */
                       const uint8_t * base,
                       size_t * rem,
                       size_t * idx) {

    size_t retval = 0;
    memset(pkt, 0, sizeof(n2n_QUERY_PEER_t));

    retval += decode_mac(pkt->srcMac, base, rem, idx);
    retval += decode_mac(pkt->targetMac, base, rem, idx);
    retval += decode_uint16(&(pkt->aflags), base, rem, idx);

    return retval;
}
