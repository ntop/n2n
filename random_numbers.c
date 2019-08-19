/* The following code offers an alterate pseudo random number generator
   namely XORSHIFT128+ to use instead of C's rand(). Its performance is 
   on par with C's rand().
 */

#include <stdint.h>
#include "n2n.h"
#include "random_numbers.h"

struct rn_generator_state_t {
    uint64_t a, b;
 };

struct splitmix64_state {
	uint64_t s;
};

/* The state must be seeded in a way that it is not all zero, choose some
   arbitrary defaults (in this case: taken from splitmix64)
 */
static struct rn_generator_state_t rn_current_state
			       = { .a    = 0x9E3779B97F4A7C15,
			           .b    = 0xBF58476D1CE4E5B9
};

static uint64_t splitmix64(struct splitmix64_state *state) {
	uint64_t result = state->s;

	state->s = result + 0x9E3779B97f4A7C15;
	result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9;
	result = (result ^ (result >> 27)) * 0x94D049BB133111EB;
	return result ^ (result >> 31);
}

int32_t n2n_srand (uint64_t seed) {
    struct splitmix64_state smstate = {seed};
    rn_current_state.a = 0;
    rn_current_state.b = 0;

    rn_current_state.a = splitmix64(&smstate);
    rn_current_state.b = splitmix64(&smstate);

    /* stabilize in unlikely case of weak state with only a few bits set */
    for (uint8_t i = 0; i < 32; i++)
	n2n_rand();

    return (0);
}

/* The following code of xorshift128p was taken from
   https://en.wikipedia.org/wiki/Xorshift as of July, 2019
   and thus is considered public domain.
 */
uint64_t n2n_rand () {
    uint64_t t =  rn_current_state.a;
    uint64_t const s = rn_current_state.b;
    rn_current_state.a = s;
    t ^= t << 23;
    t ^= t >> 17;
    t ^= s ^ (s >> 26);
    rn_current_state.b = t;
    return t + s;
}
