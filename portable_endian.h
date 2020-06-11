// taken from
// https://gist.githubusercontent.com/PkmX/63dd23f28ba885be53a5/raw/c89538c921f08f8dbb5bc5957c871060c720605a/portable_endian.h
// as of June 11, 2020

// "License": Public Domain
// I, Mathias Panzenb�ck, place this file hereby into the public domain. Use it at your own risk for whatever you like.
// In case there are jurisdictions that don't support putting things in the public domain you can also consider it to
// be "dual licensed" under the BSD, MIT and Apache licenses, if you want to. This code is trivial anyway. Consider it
// an example on how to get the endian conversion functions on different platforms.

#ifndef PORTABLE_ENDIAN_H__
#define PORTABLE_ENDIAN_H__

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#	define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__)

#	include <endian.h>

#elif defined(__APPLE__)

#	include <libkern/OSByteOrder.h>

#	define htobe16(x) OSSwapHostToBigInt16(x)
#	define htole16(x) OSSwapHostToLittleInt16(x)
#	define be16toh(x) OSSwapBigToHostInt16(x)
#	define le16toh(x) OSSwapLittleToHostInt16(x)

#	define htobe32(x) OSSwapHostToBigInt32(x)
#	define htole32(x) OSSwapHostToLittleInt32(x)
#	define be32toh(x) OSSwapBigToHostInt32(x)
#	define le32toh(x) OSSwapLittleToHostInt32(x)

#	define htobe64(x) OSSwapHostToBigInt64(x)
#	define htole64(x) OSSwapHostToLittleInt64(x)
#	define be64toh(x) OSSwapBigToHostInt64(x)
#	define le64toh(x) OSSwapLittleToHostInt64(x)

#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(__OpenBSD__)

#	include <sys/endian.h>

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

#	include <sys/endian.h>

#	define be16toh(x) betoh16(x)
#	define le16toh(x) letoh16(x)

#	define be32toh(x) betoh32(x)
#	define le32toh(x) letoh32(x)

#	define be64toh(x) betoh64(x)
#	define le64toh(x) letoh64(x)

#elif defined(__WINDOWS__)

#	include <windows.h>

#	if BYTE_ORDER == LITTLE_ENDIAN

#               if defined(_MSC_VER)
#                       include <stdlib.h>
#			define htobe16(x) _byteswap_ushort(x)
#			define htole16(x) (x)
#			define be16toh(x) _byteswap_ushort(x)
#			define le16toh(x) (x)

#			define htobe32(x) _byteswap_ulong(x)
#			define htole32(x) (x)
#			define be32toh(x) _byteswap_ulong(x)
#			define le32toh(x) (x)

#			define htobe64(x) _byteswap_uint64(x)
#			define htole64(x) (x)
#			define be64toh(x) _byteswap_uint64(x)
#			define le64toh(x) (x)

#               elif defined(__GNUC__) || defined(__clang__)

#			define htobe16(x) __builtin_bswap16(x)
#			define htole16(x) (x)
#			define be16toh(x) __builtin_bswap16(x)
#			define le16toh(x) (x)

#			define htobe32(x) __builtin_bswap32(x)
#			define htole32(x) (x)
#			define be32toh(x) __builtin_bswap32(x)
#			define le32toh(x) (x)

#			define htobe64(x) __builtin_bswap64(x)
#			define htole64(x) (x)
#			define be64toh(x) __builtin_bswap64(x)
#			define le64toh(x) (x)
#               else
#                       error platform not supported
#               endif

#	else

#		error byte order not supported

#	endif

#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#else

#	error platform not supported

#endif

#endif
