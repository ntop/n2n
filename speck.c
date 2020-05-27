// cipher SPECK -- 128 bit block size -- 256 bit key size
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/ref/stream.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// #define u64 unsigned long long
#define u64 uint64_t

#define ROR64(x,r) (((x)>>(r))|((x)<<(64-(r))))
#define ROL64(x,r) (((x)<<(r))|((x)>>(64-(r))))
#define R(x,y,k) (x=ROR64(x,8), x+=y, x^=k, y=ROL64(y,3), y^=x)
#define RI(x,y,k) (y^=x, y=ROR64(y,3), x^=k, x-=y, x=ROL64(x,8))


static int speck_encrypt(u64 *u, u64 *v, u64 key[]) {

	u64 i, x = *u, y = *v;

	for (i = 0; i < 34; i++)
		R (x, y, key[i]);

	*u = x; *v = y;

	return 0;
}


// not neccessary for CTR mode
/* static int speck_decrypt(u64 *u, u64 *v, u64 key[]) {

	int i;
	u64 x=*u,y=*v;
	for (i = 33; i >= 0 ;i--)
		RI (x, y, key[i]);

	*u = x; *v = y;

	return 0;
} */


int speck_ctr (unsigned char *out, const unsigned char *in,
	       unsigned long long inlen,
	       const unsigned char *n,
	       u64 rk[]) {

	u64 i, nonce[2], x, y, t;
	unsigned char *block = malloc (16);

	if (!inlen) {
		free (block);
		return 0;
	}
// !!! htole64 !!!
	nonce[0] = htole64 ( ((u64*)n)[0] );
	nonce[1] = htole64 ( ((u64*)n)[1] );

	t=0;
	while(inlen >= 16) {
		x = nonce[1]; y = nonce[0]; nonce[0]++;
		speck_encrypt (&x, &y, rk);
// !!! htole64 !!!
		((u64 *)out)[1+t] = htole64 (x ^ ((u64 *)in)[1+t]);
		((u64 *)out)[0+t] = htole64 (y ^ ((u64 *)in)[0+t]);
		t += 2;
		inlen -= 16;
	}
	if (inlen > 0) {
		x = nonce[1]; y = nonce[0];
		speck_encrypt (&x, &y, rk);
// !!! htole64 !!!
		((u64 *)block)[1] = htole64 (x); ((u64 *)block)[0] = htole64 (y);
		for (i=0; i < inlen; i++)
			out[i + 8*t] = block[i] ^ in[i + 8*t];
	}

	free (block);

	return 0;
}


int speck_expand_key (const unsigned char *k, u64 rk[]) {

	u64 K[4];
	u64 i;

	for (i=0; i < 4; i++)
// !!! htole64 !!!
		K[i] = htole64 ( ((u64 *)k)[i] );


	u64 D = K[3], C = K[2], B = K[1], A = K[0];

	for (i = 0; i < 33; i += 3) {
		rk[i  ] = A; R (B, A, i    );
		rk[i+1] = A; R (C, A, i + 1);
		rk[i+2] = A; R (D, A, i + 2);
	}
	rk[33] = A;

	return 1;
}


int speck_test () {

	uint8_t key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };


	uint8_t iv[16]  = { 0x70, 0x6f, 0x6f, 0x6e, 0x65, 0x72, 0x2e, 0x20,
			    0x49, 0x6e, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65 };

	uint8_t pt[16]  = { 0x00 };

	// expected outcome (according to pp. 35 & 36 of Implementation Guide)
	uint8_t ct[16]  = { 0x43, 0x8f, 0x18, 0x9c, 0x8d, 0xb4, 0xee, 0x4e,
			    0x3e, 0xf5, 0xc0, 0x05, 0x04, 0x01, 0x09, 0x41 };

	u64 round_keys[34];
	speck_expand_key (key, round_keys);

	speck_ctr (pt, pt, 16, iv, round_keys);

fprintf (stderr, "rk00: %016lx\n",             round_keys[0]);
fprintf (stderr, "rk33: %016lx\n",             round_keys[33]);
fprintf (stderr, "out : %016lx\n", *(uint64_t*)pt);
fprintf (stderr, "mem : " ); for (int i=0; i < 16; i++) fprintf (stderr, "%02x ", pt[i]); fprintf (stderr, "\n");

	int ret = 1;
	for (int i=0; i < 16; i++)
		if (pt[i] != ct[i]) ret = 0;

	return (ret);
}

/*
int main (int argc, char* argv[]) {

	fprintf (stdout, "SPECK SELF TEST RESULT: %u\n", speck_test (0,NULL));
}
*/

