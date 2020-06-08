#include <stdint.h>
#include <time.h>


#if defined (__linux__)
  #include <sys/syscall.h>
  #include <unistd.h>
  #define GRND_NONBLOCK       1
#endif

#if defined (__RDRND__) || defined (__RDSEED__)
  #include <immintrin.h>
#endif

/* The WIN32 code is still untested and thus commented
#if defined (WIN32)
  #include <Wincrypt.h>
#endif */


struct rn_generator_state_t {
    uint64_t a, b;
};

struct splitmix64_state_t {
    uint64_t s;
};


int n2n_srand (uint64_t seed);

uint64_t n2n_rand ();

uint64_t n2n_seed ();
