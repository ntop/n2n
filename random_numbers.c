
/* The following code offers an alterate pseudo random number generator
   namely XORSHIFT128+ to use instead of C's rand(). Its performance is 
   on par with C's rand().
 */

#include <stdint.h>
#ifdef __GNUC__
#include <sys/time.h>
#endif
#include <time.h>
#include "random_numbers.h"

struct rn_generator_state_t {
    uint64_t a, b;
 };

/* The state must be seeded so that it is not all zero, choose some
   arbitrary defaults (in this case: taken from splitmix64)
 */
static struct rn_generator_state_t rn_current_state
			       = { .a    = 0x9E3779B97F4A7C15,
			           .b    = 0xBF58476D1CE4E5B9
};

/* taken from benchmark.c */
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

static int32_t set_seed (uint64_t seed) {
    /* shift a --> b , so
       call this function 2 times to enter full 128 bit seed */
    rn_current_state.b = rn_current_state.a;
    /* for xorshift128p, an all zero state must be avoided
       so, we generally do not allow 0's */
    if (seed != 0) {
	rn_current_state.a = seed;
    }
    else {
	/* otherwise, entropy seed */
	/* use whatever it was before, no wiping */
	rn_current_state.a ^= 0xBF58476D1CE4E5B9;
	/* time(NULL) = currenctUTC in seconds;
	   clock() = clock_ticks since program start */
	rn_current_state.a ^= (uint64_t)time(NULL) * (uint64_t)clock();
	/* rv_usec = second fraction of current time */
	struct timeval tv;
	gettimeofday(&tv, NULL);
	rn_current_state.a ^= (uint64_t)tv.tv_usec << 16;
    }
    /* stabilize in case of weak seed with only a few bits set */
    for (int i = 0; i < 32; i++)
	random_number_64();
    return (0);
}

/* The following code of xorshift128p was taken from
   https://en.wikipedia.org/wiki/Xorshift as of July, 2019
   and thus is considered public domain.
 */
static uint64_t xorshift128p_64 () {
    uint64_t t =  rn_current_state.a;
    uint64_t const s = rn_current_state.b;
    rn_current_state.a = s;
    t ^= t << 23;
    t ^= t >> 17;
    t ^= s ^ (s >> 26);
    rn_current_state.b = t;
    return t + s;
}

static uint32_t xorshift128p_32 () {
    uint64_t t = rn_current_state.a;
    uint64_t const s = rn_current_state.b;
    rn_current_state.a = s;
    t ^= t << 23;
    t ^= t >> 17;
    t ^= s ^ (s >> 26);
    rn_current_state.b = t;
    /* downcast to uint32_t */
    return (uint32_t)(t + s);
}

/* ---  the following code is public/exported  ---
	internal functions are wrapped for the
	sake of future further ramification of
	internal functions */

int32_t random_number_seed (uint64_t seed) {
    return (set_seed (seed));
}

uint64_t random_number_64 () {
    return (xorshift128p_64 ());
}

uint32_t random_number_32 () {
    return (xorshift128p_32 ());
}
