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


// taken from
// https://raw.githubusercontent.com/pyca/bcrypt/master/src/_csrc/portable_endian.h
// as of June 11, 2020

// "License": Public Domain
// I, Mathias Panzenböck, place this file hereby into the public domain. Use it at your own risk for whatever you like.
// In case there are jurisdictions that don't support putting things in the public domain you can also consider it to
// be "dual licensed" under the BSD, MIT and Apache licenses, if you want to. This code is trivial anyway. Consider it
// an example on how to get the endian conversion functions on different platforms.

#ifndef PORTABLE_ENDIAN_H__
#define PORTABLE_ENDIAN_H__

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#   define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__)
/* Define necessary macros for the header to expose all fields. */
#   if !defined(_BSD_SOURCE)
#       define _BSD_SOURCE
#   endif
#   if !defined(__USE_BSD)
#       define __USE_BSD
#   endif
#   if !defined(_DEFAULT_SOURCE)
#       define _DEFAULT_SOURCE
#   endif
#   include <endian.h>
#   include <features.h>
/* See http://linux.die.net/man/3/endian */
#   if defined(htobe16) && defined(htole16) && defined(be16toh) && defined(le16toh) && defined(htobe32) && defined(htole32) && defined(be32toh) && defined(htole32) && defined(htobe64) && defined(htole64) && defined(htobe64) && defined(be64toh) && defined(htole64) && defined(le64toh)
/* Do nothing. The macros we need already exist. */
#   elif !defined(__GLIBC__) || !defined(__GLIBC_MINOR__) || ((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 9)))
#       include <arpa/inet.h>
#       if defined(__BYTE_ORDER) && (__BYTE_ORDER == __LITTLE_ENDIAN)
#           define htobe16(x) htons(x)
#           define htole16(x) (x)
#           define be16toh(x) ntohs(x)
#           define le16toh(x) (x)

#           define htobe32(x) htonl(x)
#           define htole32(x) (x)
#           define be32toh(x) ntohl(x)
#           define le32toh(x) (x)

#           define htobe64(x) (((uint64_t)htonl(((uint32_t)(((uint64_t)(x)) >> 32)))) | (((uint64_t)htonl(((uint32_t)(x)))) << 32))
#           define htole64(x) (x)
#           define be64toh(x) (((uint64_t)ntohl(((uint32_t)(((uint64_t)(x)) >> 32)))) | (((uint64_t)ntohl(((uint32_t)(x)))) << 32))
#           define le64toh(x) (x)
#       elif defined(__BYTE_ORDER) && (__BYTE_ORDER == __BIG_ENDIAN)
#           define htobe16(x) (x)
#           define htole16(x) (((((uint16_t)(x)) >> 8))|((((uint16_t)(x)) << 8)))
#           define be16toh(x) (x)
#           define le16toh(x) (((((uint16_t)(x)) >> 8))|((((uint16_t)(x)) << 8)))

#           define htobe32(x) (x)
#           define htole32(x) (((uint32_t)htole16(((uint16_t)(((uint32_t)(x)) >> 16)))) | (((uint32_t)htole16(((uint16_t)(x)))) << 16))
#           define be32toh(x) (x)
#           define le32toh(x) (((uint32_t)le16toh(((uint16_t)(((uint32_t)(x)) >> 16)))) | (((uint32_t)le16toh(((uint16_t)(x)))) << 16))

#           define htobe64(x) (x)
#           define htole64(x) (((uint64_t)htole32(((uint32_t)(((uint64_t)(x)) >> 32)))) | (((uint64_t)htole32(((uint32_t)(x)))) << 32))
#           define be64toh(x) (x)
#           define le64toh(x) (((uint64_t)le32toh(((uint32_t)(((uint64_t)(x)) >> 32)))) | (((uint64_t)le32toh(((uint32_t)(x)))) << 32))
#       else
#           error Byte Order not supported or not defined.
#       endif
#   endif

#elif defined(__APPLE__)

#   include <libkern/OSByteOrder.h>

#   define htobe16(x) OSSwapHostToBigInt16(x)
#   define htole16(x) OSSwapHostToLittleInt16(x)
#   define be16toh(x) OSSwapBigToHostInt16(x)
#   define le16toh(x) OSSwapLittleToHostInt16(x)

#   define htobe32(x) OSSwapHostToBigInt32(x)
#   define htole32(x) OSSwapHostToLittleInt32(x)
#   define be32toh(x) OSSwapBigToHostInt32(x)
#   define le32toh(x) OSSwapLittleToHostInt32(x)

#   define htobe64(x) OSSwapHostToBigInt64(x)
#   define htole64(x) OSSwapHostToLittleInt64(x)
#   define be64toh(x) OSSwapBigToHostInt64(x)
#   define le64toh(x) OSSwapLittleToHostInt64(x)

#   define __BYTE_ORDER    BYTE_ORDER
#   define __BIG_ENDIAN    BIG_ENDIAN
#   define __LITTLE_ENDIAN LITTLE_ENDIAN
#   define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(__OpenBSD__)

#   include <sys/endian.h>

#elif defined(__HAIKU__)

#   include <endian.h>

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

#   include <sys/endian.h>

#   if !defined(be16toh)
    #   define be16toh(x) betoh16(x)
    #   define le16toh(x) letoh16(x)
#   endif

#   if !defined(be32toh)
    #   define be32toh(x) betoh32(x)
    #   define le32toh(x) letoh32(x)
#   endif

#   if !defined(be64toh)
    #   define be64toh(x) betoh64(x)
    #   define le64toh(x) letoh64(x)
#   endif

#elif defined(__WINDOWS__)

#   if BYTE_ORDER == LITTLE_ENDIAN

#       define htobe16(x) _byteswap_ushort(x)
#       define htole16(x) (x)
#       define be16toh(x) _byteswap_ushort(x)
#       define le16toh(x) (x)

#       define htobe32(x) _byteswap_ulong(x)
#       define htole32(x) (x)
#       define be32toh(x) _byteswap_ulong(x)
#       define le32toh(x) (x)

#       define htobe64(x) (((uint64_t)htobe32(((uint32_t)(((uint64_t)(x)) >> 32))) & 0x00000000FFFFFFFFULL) | (((uint64_t)htobe32(((uint32_t)(x)))) << 32))
#       define be64toh(x) (((uint64_t)be32toh(((uint32_t)(((uint64_t)(x)) >> 32))) & 0x00000000FFFFFFFFULL) | (((uint64_t)be32toh(((uint32_t)(x)))) << 32))
#       define htole64(x) (x)
#       define le64toh(x) (x)

#   elif BYTE_ORDER == BIG_ENDIAN

        /* that would be xbox 360 */
#       define htobe16(x) (x)
#       define htole16(x) __builtin_bswap16(x)
#       define be16toh(x) (x)
#       define le16toh(x) __builtin_bswap16(x)

#       define htobe32(x) (x)
#       define htole32(x) __builtin_bswap32(x)
#       define be32toh(x) (x)
#       define le32toh(x) __builtin_bswap32(x)

#       define htobe64(x) (x)
#       define htole64(x) __builtin_bswap64(x)
#       define be64toh(x) (x)
#       define le64toh(x) __builtin_bswap64(x)

#   else

#       error byte order not supported

#   endif

#   define __BYTE_ORDER    BYTE_ORDER
#   define __BIG_ENDIAN    BIG_ENDIAN
#   define __LITTLE_ENDIAN LITTLE_ENDIAN
#   define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(__sun)

#   include <sys/byteorder.h>

#   define htobe16(x) BE_16(x)
#   define htole16(x) LE_16(x)
#   define be16toh(x) BE_16(x)
#   define le16toh(x) LE_16(x)

#   define htobe32(x) BE_32(x)
#   define htole32(x) LE_32(x)
#   define be32toh(x) BE_32(x)
#   define le32toh(x) LE_32(x)

#   define htobe64(x) BE_64(x)
#   define htole64(x) LE_64(x)
#   define be64toh(x) BE_64(x)
#   define le64toh(x) LE_64(x)

#elif defined _AIX      /* AIX is always big endian */
#       define be64toh(x) (x)
#       define be32toh(x) (x)
#       define be16toh(x) (x)
#       define le32toh(x)                              \
         ((((x) & 0xff) << 24) |                 \
           (((x) & 0xff00) << 8) |                \
           (((x) & 0xff0000) >> 8) |              \
           (((x) & 0xff000000) >> 24))
#       define   le64toh(x)                               \
         ((((x) & 0x00000000000000ffL) << 56) |   \
          (((x) & 0x000000000000ff00L) << 40) |   \
          (((x) & 0x0000000000ff0000L) << 24) |   \
          (((x) & 0x00000000ff000000L) << 8)  |   \
          (((x) & 0x000000ff00000000L) >> 8)  |   \
          (((x) & 0x0000ff0000000000L) >> 24) |   \
          (((x) & 0x00ff000000000000L) >> 40) |   \
          (((x) & 0xff00000000000000L) >> 56))
#       ifndef htobe64
#               define htobe64(x) be64toh(x)
#       endif
#       ifndef htobe32
#               define htobe32(x) be32toh(x)
#       endif
#       ifndef htobe16
#               define htobe16(x) be16toh(x)
#       endif


#else

#   error platform not supported

#endif

#endif
