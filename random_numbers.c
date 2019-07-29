
/* The following code offers an alterate pseudo random number generator
   namely XORSHIFT128+ to use instead of C's pretty simple rand(). Its
   performance is on par with C's rand().
 */

#include <stdint.h>
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
	/* otherwise, default seed */
	rn_current_state.a = 0x9E3779B97F4A7C15;
    }
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

// !!!
#include <stdio.h>
#include "n2n.h"
int main() {
  random_number_seed(1);
  random_number_seed(1);
  printf ("key: %llx %llx %llx\n", random_number_64(), random_number_64(), random_number_32());


  return (0);
}
