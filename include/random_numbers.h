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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#ifndef RND_H
#define RND_H


#include <stdint.h>   // for uint64_t, uint32_t


// syscall and inquiring random number from hardware generators might fail, so we will retry
#define RND_RETRIES      1000

#if defined (__linux__)
#include <syscall.h>  // for SYS_getrandom
#ifdef SYS_getrandom
#define GRND_NONBLOCK       1
#endif
#endif

#if defined (__RDRND__) || defined (__RDSEED__)
#include <immintrin.h>  /* _rdrand64_step, rdseed4_step */
#endif

#ifdef _WIN32
#include <wincrypt.h>   // HCTYPTPROV, Crypt*-functions
#endif


typedef struct rn_generator_state_t {
    uint64_t a, b;
} rn_generator_state_t;

typedef struct splitmix64_state_t {
    uint64_t s;
} splitmix64_state_t;


int n2n_srand (uint64_t seed);

uint64_t n2n_rand (void);

uint64_t n2n_seed (void);

uint32_t n2n_rand_sqr (uint32_t max_n);


#endif // RND_H
