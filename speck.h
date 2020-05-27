
#define u64 uint64_t

int speck_ctr (unsigned char *out, const unsigned char *in,
	       unsigned long long inlen,
               const unsigned char *n,
               u64 rk[]);

int speck_expand_key (const unsigned char *k, u64 rk[]);
