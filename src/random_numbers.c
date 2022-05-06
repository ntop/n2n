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


#include "random_numbers.h"


// the following code offers an alterate pseudo random number generator
// namely XORSHIFT128+ to use instead of C's rand()
// its performance is on par with C's rand()


// the state must be seeded in a way that it is not all zero, choose some
// arbitrary defaults (in this case: taken from splitmix64)
static rn_generator_state_t rn_current_state = {
    .a = 0x9E3779B97F4A7C15,
    .b = 0xBF58476D1CE4E5B9
};


// used for mixing the initializing seed
static uint64_t splitmix64 (splitmix64_state_t *state) {

    uint64_t result = state->s;

    state->s = result + 0x9E3779B97F4A7C15;

    result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9;
    result = (result ^ (result >> 27)) * 0x94D049BB133111EB;

    return result ^ (result >> 31);
}


int n2n_srand (uint64_t seed) {

    uint8_t i;
    splitmix64_state_t smstate = { seed };

    rn_current_state.a = 0;
    rn_current_state.b = 0;

    rn_current_state.a = splitmix64 (&smstate);
    rn_current_state.b = splitmix64 (&smstate);

    // the following lines could be deleted as soon as it is formally prooved that
    // there is no seed leading to (a == b == 0). until then, just to be safe:
    if((rn_current_state.a == 0) && (rn_current_state.b == 0)) {
        rn_current_state.a = 0x9E3779B97F4A7C15;
        rn_current_state.b = 0xBF58476D1CE4E5B9;
    }

    // stabilize in unlikely case of weak state with only a few bits set
    for(i = 0; i < 32; i++)
        n2n_rand();

    return 0;
}


// the following code of xorshift128p was taken from
// https://en.wikipedia.org/wiki/Xorshift as of July, 2019
// and thus is considered public domain
uint64_t n2n_rand (void) {

    uint64_t t       = rn_current_state.a;
    uint64_t const s = rn_current_state.b;

    rn_current_state.a = s;
    t ^= t << 23;
    t ^= t >> 17;
    t ^= s ^ (s >> 26);
    rn_current_state.b = t;

    return t + s;
}


// the following code tries to gather some entropy from several sources
// for use as seed. Note, that this code does not set the random generator
// state yet, a call to   n2n_srand (n2n_seed())   would do
uint64_t n2n_seed (void) {

    uint64_t seed = 0;   /* this could even go uninitialized */
    uint64_t ret = 0;    /* this could even go uninitialized */

#ifdef SYS_getrandom
    size_t i = 0;
    int rc = -1;
    
    for(i = 0; (i < RND_RETRIES) && (rc != sizeof(seed)); i++) {
        rc = syscall (SYS_getrandom, &seed, sizeof(seed), GRND_NONBLOCK);
        // if successful, rc should contain the requested number of random bytes
        if(rc != sizeof(seed)) {
            if (errno != EAGAIN) {
                traceEvent(TRACE_ERROR, "n2n_seed faced error errno=%u from getrandom syscall.", errno);
                break;
            }
        }
    }

    // if we still see an EAGAIN error here, we must have run out of retries
    if(errno == EAGAIN) {
        traceEvent(TRACE_ERROR, "n2n_seed saw getrandom syscall indicate not being able to provide enough entropy yet.");
    }
#endif

    // as we want randomness, it does no harm to add up even uninitialized values or
    // erroneously arbitrary values returned from the syscall for the first time
    ret += seed;

    // __RDRND__ is set only if architecturual feature is set, e.g. compiled with -march=native
#ifdef __RDRND__
    for(i = 0; i < RND_RETRIES; i++) {
        if(_rdrand64_step((unsigned long long*)&seed)) {
            // success!
            // from now on, we keep this inside the loop because in case of failure
            // and with unchanged values, we do not want to double the previous value
            ret += seed;
            break;
        }
        // continue loop to try again otherwise
    }
    if(i == RND_RETRIES) {
        traceEvent(TRACE_ERROR, "n2n_seed was not able to get a hardware generated random number from RDRND.");
    }
#endif

    // __RDSEED__ ist set only if architecturual feature is set, e.g. compile with -march=native
#ifdef __RDSEED__
#if __GNUC__ > 4
    for(i = 0; i < RND_RETRIES; i++) {
        if(_rdseed64_step((unsigned long long*)&seed)) {
            // success!
            ret += seed;
            break;
        }
        // continue loop to try again otherwise
    }
    if(i == RND_RETRIES) {
        traceEvent(TRACE_ERROR, "n2n_seed was not able to get a hardware generated random number from RDSEED.");
    }
#endif
#endif

#ifdef WIN32
    HCRYPTPROV crypto_provider;
    CryptAcquireContext (&crypto_provider, NULL, NULL,
                         PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptGenRandom (crypto_provider, 8, &seed);
    CryptReleaseContext (crypto_provider, 0);
    ret += seed;
#endif

    seed  = time(NULL);             /* UTC in seconds */
    ret  += seed;

    seed  = clock();               /* ticks since program start */
    seed *= 18444244737;
    ret  += seed;

    return ret;
}

// an integer squrare root approximation
// from https://stackoverflow.com/a/1100591
static int ftbl[33] = {
    0, 1, 1, 2, 2, 4, 5, 8, 11, 16, 22, 32, 45, 64, 90,
    128, 181 ,256 ,362, 512, 724, 1024, 1448, 2048, 2896,
    4096, 5792, 8192, 11585, 16384, 23170, 32768, 46340 };


static int ftbl2[32] = {
    32768, 33276, 33776, 34269, 34755, 35235, 35708, 36174,
    36635, 37090, 37540, 37984, 38423, 38858, 39287, 39712,
    40132, 40548, 40960, 41367, 41771, 42170, 42566, 42959,
    43347, 43733, 44115, 44493, 44869, 45241, 45611, 45977 };


static int i_sqrt (int val) {

    int cnt = 0;
    int t = val;

    while(t) {
        cnt++;
        t>>=1;
    }

    if(6 >= cnt)
        t = (val << (6-cnt));
    else
        t = (val >> (cnt-6));

    return (ftbl[cnt] * ftbl2[t & 31]) >> 15;
}


static int32_t int_sqrt (int val) {

    int ret;

    ret  = i_sqrt (val);
    ret += i_sqrt (val - ret * ret) / 16;

    return ret;
}


// returns a random number from [0, max_n] with higher probability towards the borders
uint32_t n2n_rand_sqr (uint32_t max_n) {

    uint32_t raw_max = 0;
    uint32_t raw_rnd = 0;
    int32_t  ret     = 0;

    raw_max = (max_n+2) * (max_n+2);
    raw_rnd = n2n_rand() % (raw_max);

    ret = int_sqrt(raw_rnd) / 2;
    ret = (raw_rnd & 1) ? ret : -ret;
    ret = max_n / 2 + ret;

    if(ret < 0)
        ret = 0;
    if (ret > max_n)
        ret = max_n;

    return ret;
}
