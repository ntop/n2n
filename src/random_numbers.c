/**
 * (C) 2007-20 - ntop.org and contributors
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

#include "n2n.h"

/* The following code offers an alterate pseudo random number generator
   namely XORSHIFT128+ to use instead of C's rand(). Its performance is
   on par with C's rand().
*/


/* The state must be seeded in a way that it is not all zero, choose some
   arbitrary defaults (in this case: taken from splitmix64) */
static struct rn_generator_state_t rn_current_state = {
  .a    = 0x9E3779B97F4A7C15,
  .b    = 0xBF58476D1CE4E5B9 };


/* used for mixing the initializing seed */
static uint64_t splitmix64 (struct splitmix64_state_t *state) {

  uint64_t result = state->s;

  state->s = result + 0x9E3779B97F4A7C15;

  result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9;
  result = (result ^ (result >> 27)) * 0x94D049BB133111EB;

  return result ^ (result >> 31);
}


int n2n_srand (uint64_t seed) {
  uint8_t i;
  struct splitmix64_state_t smstate = {seed};

  rn_current_state.a = 0;
  rn_current_state.b = 0;

  rn_current_state.a = splitmix64 (&smstate);
  rn_current_state.b = splitmix64 (&smstate);

  /* the following lines could be deleted as soon as it is formally prooved that
     there is no seed leading to (a == b == 0). Until then, just to be safe: */
  if ( (rn_current_state.a == 0) && (rn_current_state.b == 0) ) {
    rn_current_state.a = 0x9E3779B97F4A7C15;
    rn_current_state.b = 0xBF58476D1CE4E5B9;
  }

  /* stabilize in unlikely case of weak state with only a few bits set */
  for(i = 0; i < 32; i++)
    n2n_rand();

  return 0;
}


/* The following code of xorshift128p was taken from
   https://en.wikipedia.org/wiki/Xorshift as of July, 2019
   and thus is considered public domain. */
uint64_t n2n_rand () {

  uint64_t t       = rn_current_state.a;
  uint64_t const s = rn_current_state.b;

  rn_current_state.a = s;
  t ^= t << 23;
  t ^= t >> 17;
  t ^= s ^ (s >> 26);
  rn_current_state.b = t;

  return t + s;
}


/* The following code tries to gather some entropy from several sources
   for use as seed. Note, that this code does not set the random generator
   state yet, a call to   n2n_srand ( n2n_seed() )   would do. */
uint64_t n2n_seed (void) {

  uint64_t seed = 0;
  uint64_t ret  = 0;

#ifdef SYS_getrandom
  syscall (SYS_getrandom, &seed, sizeof(seed), GRND_NONBLOCK);
  ret += seed;
#endif

  // __RDRND__ is set only if architecturual feature is set, e.g. compile with -march=native
#ifdef __RDRND__
  _rdrand64_step ((unsigned long long*)&seed);
  ret += seed;
#endif

  // __RDSEED__ ist set only if architecturual feature is set, e.g. compile with -march=native
#ifdef __RDSEED__
  _rdseed64_step((unsigned long long*)&seed);
  ret += seed;
#endif

  /* The WIN32 code is still untested and thus commented
     #ifdef WIN32
     HCRYPTPROV crypto_provider;
     CryptAcquireContext (&crypto_provider, NULL, (LPCWSTR)L"Microsoft Base Cryptographic Provider v1.0",
     PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
     CryptGenRandom (crypto_provider, 8, &seed);
     CryptReleaseContext (crypto_provider, 0);
     ret += seed;
     #endif */

  seed = time(NULL); /* UTC in seconds */
  ret += seed;

  seed = clock() * 8996146197;  /* clock() = ticks since program start */
  ret += seed;

  return ret;
}
