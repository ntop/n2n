/*
 * Basic definitions needed for any windows compile
 *
 */

#ifndef _WIN32_DEFS_H_
#define _WIN32_DEFS_H_

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define WIN32_LEAN_AND_MEAN

#ifndef _WIN64
/* needs to be defined before winsock gets included */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x501

const char *subst_inet_ntop (int, const void *, char *, int);
#define inet_ntop subst_inet_ntop
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#endif
