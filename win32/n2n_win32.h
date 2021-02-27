/*

	(C) 2007-09 - Luca Deri <deri@ntop.org>

*/

#ifndef _N2N_WIN32_H_
#define _N2N_WIN32_H_

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define WIN32_LEAN_AND_MEAN

#if defined(__MINGW32__)
/* should be defined here and before winsock gets included */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x501 //Otherwise the linker doesnt find getaddrinfo
#endif /* #ifndef _WIN32_WINNT */
#include <inttypes.h>
#endif /* #if defined(__MINGW32__) */

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>


#include "wintap.h"

#undef EAFNOSUPPORT
#define EAFNOSUPPORT   WSAEAFNOSUPPORT 
#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a < b ? a : b)

#define snprintf _snprintf
#define strdup _strdup

#define socklen_t int


/* ************************************* */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#else
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        short   ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        short   ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


/* ************************************* */


typedef struct tuntap_dev {
	HANDLE          device_handle;
	char            *device_name;
	char            *ifName;
	OVERLAPPED      overlap_read, overlap_write;
	n2n_mac_t       mac_addr;
	uint32_t        ip_addr;
	uint32_t        device_mask;
	unsigned int    mtu;
	unsigned int    metric;
} tuntap_dev;


/* ************************************* */


#define index(a, b) strchr(a, b)
#define sleep(x) Sleep(x * 1000)


/* ************************************* */


#define HAVE_PTHREAD
#define pthread_t       HANDLE
#define pthread_mutex_t HANDLE

#define pthread_create(p_thread_handle, attr, thread_func, p_param)                         \
    (*p_thread_handle = CreateThread(0 /* default security flags */, 0 /*default stack*/,   \
                 thread_func, p_param, 0 /* default creation flags */,                      \
                 NULL) == 0)

#define pthread_cancel(p_thread_handle) \
    TerminateThread(p_thread_handle, 0)

#define pthread_mutex_init(p_mutex_handle, attr)                      \
     *p_mutex_handle = CreateMutex(NULL /*default security flags */,  \
     FALSE /* initially not owned */, NULL /* unnamed */)

#define pthread_mutex_lock(mutex)         \
    WaitForSingleObject(*mutex, INFINITE)

#define pthread_mutex_trylock(mutex)  \
    WaitForSingleObject(*mutex, NULL)

#define pthread_mutex_unlock(mutex) \
    ReleaseMutex(*mutex)


/* ************************************* */


#endif
