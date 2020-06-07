// cipher SPECK -- 128 bit block size -- 256 bit key size
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "speck.h"

#if defined (__AVX2__)	// AVX support ----------------------------------------------------


#include <immintrin.h>

#define u32 uint32_t
#define u64 uint64_t
#define u256 __m256i

#define LCS(x,r) (((x)<<r)|((x)>>(64-r)))
#define RCS(x,r) (((x)>>r)|((x)<<(64-r)))

#define XOR _mm256_xor_si256
#define AND _mm256_and_si256
#define ADD _mm256_add_epi64
#define SL  _mm256_slli_epi64
#define SR  _mm256_srli_epi64

#define _q SET(0x3,0x1,0x2,0x0)
#define _four SET(0x4,0x4,0x4,0x4)

#define SET _mm256_set_epi64x
#define SET1(X,c) (X=SET(c,c,c,c))
#define SET4(X,c) (X=SET(c,c,c,c), X=ADD(X,_q))

#define LOW  _mm256_unpacklo_epi64
#define HIGH _mm256_unpackhi_epi64
#define LD(ip) _mm256_loadu_si256((__m256i *)(ip))
#define ST(ip,X) _mm256_storeu_si256((__m256i *)(ip),X)
#define STORE(out,X,Y) (ST(out,LOW(Y,X)), ST(out+32,HIGH(Y,X)))
#define STORE_ALT(out,X,Y) (ST(out,LOW(X,Y)), ST(out+32,HIGH(X,Y)))
#define XOR_STORE(in,out,X,Y) (ST(out,XOR(LD(in),LOW(Y,X))), ST(out+32,XOR(LD(in+32),HIGH(Y,X))))
#define XOR_STORE_ALT(in,out,X,Y) (ST(out,XOR(LD(in),LOW(X,Y))), ST(out+32,XOR(LD(in+32),HIGH(X,Y))))

#define SHFL _mm256_shuffle_epi8
#define R8 SET(0x080f0e0d0c0b0a09LL,0x0007060504030201LL,0x080f0e0d0c0b0a09LL,0x0007060504030201LL)
#define L8 SET(0x0e0d0c0b0a09080fLL,0x0605040302010007LL,0x0e0d0c0b0a09080fLL,0x0605040302010007LL)
#define ROL8(X)  (SHFL(X,L8))
#define ROR8(X)  (SHFL(X,R8))
#define ROL(X,r) (XOR(SL(X,r),SR(X,(64-r))))
#define ROR(X,r) (XOR(SR(X,r),SL(X,(64-r))))

#define numrounds   34
#define numkeywords 4

#define R(X,Y,k) (X=XOR(ADD(ROR8(X),Y),k), Y=XOR(ROL(Y,3),X))

#define Rx4(X,Y,k)  (R(X[0],Y[0],k))
#define Rx8(X,Y,k)  (R(X[0],Y[0],k), R(X[1],Y[1],k))
#define Rx12(X,Y,k) (R(X[0],Y[0],k), R(X[1],Y[1],k), R(X[2],Y[2],k))

#define Rx16(X,Y,k) (X[0]=ROR8(X[0]), X[0]=ADD(X[0],Y[0]), X[1]=ROR8(X[1]), X[1]=ADD(X[1],Y[1]), \
		     X[2]=ROR8(X[2]), X[2]=ADD(X[2],Y[2]), X[3]=ROR8(X[3]), X[3]=ADD(X[3],Y[3]), \
		     X[0]=XOR(X[0],k), X[1]=XOR(X[1],k), X[2]=XOR(X[2],k), X[3]=XOR(X[3],k), \
		     Z[0]=Y[0], Z[1]=Y[1], Z[2]=Y[2], Z[3]=Y[3],	\
		     Z[0]=SL(Z[0],3),  Y[0]=SR(Y[0],61), Z[1]=SL(Z[1],3), Y[1]=SR(Y[1],61), \
		     Z[2]=SL(Z[2],3),  Y[2]=SR(Y[2],61), Z[3]=SL(Z[3],3), Y[3]=SR(Y[3],61), \
		     Y[0]=XOR(Y[0],Z[0]), Y[1]=XOR(Y[1],Z[1]), Y[2]=XOR(Y[2],Z[2]), Y[3]=XOR(Y[3],Z[3]), \
		     Y[0]=XOR(X[0],Y[0]), Y[1]=XOR(X[1],Y[1]), Y[2]=XOR(X[2],Y[2]), Y[3]=XOR(X[3],Y[3]))

#define Rx2(x,y,k) (x[0]=RCS(x[0],8), x[1]=RCS(x[1],8), x[0]+=y[0], x[1]+=y[1],	\
                    x[0]^=k, x[1]^=k, y[0]=LCS(y[0],3), y[1]=LCS(y[1],3), y[0]^=x[0], y[1]^=x[1])

#define Rx1(x,y,k) (x[0]=RCS(x[0],8), x[0]+=y[0], x[0]^=k, y[0]=LCS(y[0],3), y[0]^=x[0])

#define Rx1b(x,y,k) (x=RCS(x,8), x+=y, x^=k, y=LCS(y,3), y^=x)

#define Encrypt(X,Y,k,n) (Rx##n(X,Y,k[0]),  Rx##n(X,Y,k[1]),  Rx##n(X,Y,k[2]),  Rx##n(X,Y,k[3]),  Rx##n(X,Y,k[4]),  Rx##n(X,Y,k[5]),  Rx##n(X,Y,k[6]),  Rx##n(X,Y,k[7]), \
			  Rx##n(X,Y,k[8]),  Rx##n(X,Y,k[9]),  Rx##n(X,Y,k[10]), Rx##n(X,Y,k[11]), Rx##n(X,Y,k[12]), Rx##n(X,Y,k[13]), Rx##n(X,Y,k[14]), Rx##n(X,Y,k[15]), \
			  Rx##n(X,Y,k[16]), Rx##n(X,Y,k[17]), Rx##n(X,Y,k[18]), Rx##n(X,Y,k[19]), Rx##n(X,Y,k[20]), Rx##n(X,Y,k[21]), Rx##n(X,Y,k[22]), Rx##n(X,Y,k[23]), \
			  Rx##n(X,Y,k[24]), Rx##n(X,Y,k[25]), Rx##n(X,Y,k[26]), Rx##n(X,Y,k[27]), Rx##n(X,Y,k[28]), Rx##n(X,Y,k[29]), Rx##n(X,Y,k[30]), Rx##n(X,Y,k[31]), \
			  Rx##n(X,Y,k[32]), Rx##n(X,Y,k[33]))

#define RK(X,Y,k,key,i)   (SET1(k[i],Y), key[i]=Y, X=RCS(X,8), X+=Y, X^=i, Y=LCS(Y,3), Y^=X)

#define EK(A,B,C,D,k,key) (RK(B,A,k,key,0),  RK(C,A,k,key,1),  RK(D,A,k,key,2),  RK(B,A,k,key,3),  RK(C,A,k,key,4),  RK(D,A,k,key,5),  RK(B,A,k,key,6), \
			   RK(C,A,k,key,7),  RK(D,A,k,key,8),  RK(B,A,k,key,9),  RK(C,A,k,key,10), RK(D,A,k,key,11), RK(B,A,k,key,12), RK(C,A,k,key,13), \
			   RK(D,A,k,key,14), RK(B,A,k,key,15), RK(C,A,k,key,16), RK(D,A,k,key,17), RK(B,A,k,key,18), RK(C,A,k,key,19), RK(D,A,k,key,20), \
			   RK(B,A,k,key,21), RK(C,A,k,key,22), RK(D,A,k,key,23), RK(B,A,k,key,24), RK(C,A,k,key,25), RK(D,A,k,key,26), RK(B,A,k,key,27), \
			   RK(C,A,k,key,28), RK(D,A,k,key,29), RK(B,A,k,key,30), RK(C,A,k,key,31), RK(D,A,k,key,32), RK(B,A,k,key,33))

typedef struct {
  u256 rk[34];
  u64 key[34];
} speck_context_t;


static int speck_encrypt_xor(unsigned char *out, const unsigned char *in, u64 nonce[], speck_context_t *ctx, int numbytes) {

  u64  x[2], y[2];
  u256 X[4], Y[4], Z[4];

  if (numbytes == 16) {
    x[0] = nonce[1]; y[0] = nonce[0]; nonce[0]++;
    Encrypt (x, y, ctx->key, 1);
    ((u64 *)out)[1] = x[0]; ((u64 *)out)[0] = y[0];
    return 0;
  }

  if (numbytes == 32) {
    x[0] = nonce[1]; y[0] = nonce[0]; nonce[0]++;
    x[1] = nonce[1]; y[1] = nonce[0]; nonce[0]++;
    Encrypt (x , y, ctx->key, 2);
    ((u64 *)out)[1] = x[0] ^ ((u64 *)in)[1]; ((u64 *)out)[0] = y[0] ^ ((u64 *)in)[0];
    ((u64 *)out)[3] = x[1] ^ ((u64 *)in)[3]; ((u64 *)out)[2] = y[1] ^ ((u64 *)in)[2];
    return 0;
  }

  SET1 (X[0], nonce[1]); SET4 (Y[0], nonce[0]);

  if (numbytes == 64)
    Encrypt (X, Y, ctx->rk, 4);
  else {
    X[1] = X[0];
    Y[1] = ADD (Y[0], _four);
    if (numbytes == 128)
      Encrypt (X, Y, ctx->rk, 8);
    else {
      X[2] = X[0];
      Y[2] = ADD (Y[1], _four);
      if (numbytes == 192)
	Encrypt (X, Y, ctx->rk, 12);
      else {
	X[3] = X[0];
	Y[3] = ADD (Y[2], _four);
	Encrypt (X, Y, ctx->rk, 16);
      }
    }
  }

  nonce[0] += (numbytes>>4);

  XOR_STORE (in, out, X[0], Y[0]);
  if (numbytes >= 128)
    XOR_STORE (in +  64, out +  64, X[1], Y[1]);
  if (numbytes >= 192)
    XOR_STORE (in + 128, out + 128, X[2], Y[2]);
  if (numbytes >= 256)
    XOR_STORE (in + 192, out + 192, X[3], Y[3]);

  return 0;
}


int speck_ctr( unsigned char *out, const unsigned char *in, unsigned long long inlen,
	       const unsigned char *n, speck_context_t *ctx) {

  int i;
  u64 nonce[2];
  unsigned char block[16];
  u64 * const block64 = (u64 *)block;

  if (!inlen)
    return 0;

  nonce[0] = ((u64 *)n)[0];
  nonce[1] = ((u64 *)n)[1];

  while (inlen >= 256) {
    speck_encrypt_xor (out, in, nonce, ctx, 256);
    in += 256; inlen -= 256; out += 256;
  }

  if (inlen >= 192) {
    speck_encrypt_xor (out, in, nonce, ctx, 192);
    in += 192; inlen -= 192; out += 192;
  }

  if (inlen >= 128) {
    speck_encrypt_xor (out, in, nonce, ctx, 128);
    in += 128; inlen -= 128; out += 128;
  }

  if (inlen >= 64) {
    speck_encrypt_xor (out, in, nonce, ctx, 64);
    in += 64; inlen -= 64; out += 64;
  }

  if (inlen >= 32) {
    speck_encrypt_xor (out, in, nonce, ctx, 32);
    in += 32; inlen -= 32; out += 32;
  }

  if (inlen >= 16) {
    speck_encrypt_xor (block, in, nonce, ctx, 16);
    ((u64 *)out)[0] = block64[0] ^ ((u64 *)in)[0];
    ((u64 *)out)[1] = block64[1] ^ ((u64 *)in)[1];
    in += 16; inlen -= 16; out += 16;
  }

  if (inlen > 0) {
    speck_encrypt_xor (block, in, nonce, ctx, 16);
    for (i = 0; i < inlen; i++)
      out[i] = block[i] ^ in[i];
  }

  return 0;
}


int speck_expand_key (const unsigned char *k, speck_context_t *ctx) {

  u64 K[4];
  size_t i;
  for (i = 0; i < numkeywords; i++)
    K[i] = ((u64 *)k)[i];

  EK (K[0], K[1], K[2], K[3], ctx->rk, ctx->key);

  return 0;
}


#elif defined (__SSE4_2__) // SSE support -------------------------------------------------


#include <immintrin.h>

#define SPECK_CTX_BYVAL		1

#define u32 unsigned
#define u64 unsigned long long
#define u128 __m128i

#define LCS(x,r) (((x)<<r)|((x)>>(64-r)))
#define RCS(x,r) (((x)>>r)|((x)<<(64-r)))

#define XOR _mm_xor_si128
#define AND _mm_and_si128
#define ADD _mm_add_epi64
#define SL  _mm_slli_epi64
#define SR  _mm_srli_epi64

#define _q SET(0x1,0x0)
#define _two SET(0x2,0x2)

#define SET _mm_set_epi64x
#define SET1(X,c) (X=SET(c,c))
#define SET2(X,c) (X=SET(c,c), X=ADD(X,_q))

#define LOW _mm_unpacklo_epi64
#define HIGH _mm_unpackhi_epi64
#define LD(ip) _mm_loadu_si128((__m128i *)(ip))
#define ST(ip,X) _mm_storeu_si128((__m128i *)(ip),X)
#define STORE(out,X,Y) (ST(out,LOW(Y,X)), ST(out+16,HIGH(Y,X)))
#define STORE_ALT(out,X,Y) (ST(out,LOW(X,Y)), ST(out+16,HIGH(X,Y)))
#define XOR_STORE(in,out,X,Y) (ST(out,XOR(LD(in),LOW(Y,X))), ST(out+16,XOR(LD(in+16),HIGH(Y,X))))
#define XOR_STORE_ALT(in,out,X,Y) (ST(out,XOR(LD(in),LOW(X,Y))), ST(out+16,XOR(LD(in+16),HIGH(X,Y))))

#define SHFL _mm_shuffle_epi8
#define R8   _mm_set_epi64x(0x080f0e0d0c0b0a09LL,0x0007060504030201LL)
#define L8   _mm_set_epi64x(0x0e0d0c0b0a09080fLL,0x0605040302010007LL)
#define ROL8(X)  (SHFL(X,L8))
#define ROR8(X)  (SHFL(X,R8))
#define ROL(X,r) (XOR(SL(X,r),SR(X,(64-r))))
#define ROR(X,r) (XOR(SR(X,r),SL(X,(64-r))))

#define numrounds   34
#define numkeywords 4

#define R(X,Y,k) (X=XOR(ADD(ROR8(X),Y),k), Y=XOR(ROL(Y,3),X))

#define Rx2(X,Y,k) (R(X[0],Y[0],k))
#define Rx4(X,Y,k) (R(X[0],Y[0],k), R(X[1],Y[1],k))
#define Rx6(X,Y,k) (R(X[0],Y[0],k), R(X[1],Y[1],k), R(X[2],Y[2],k))

#define Rx8(X,Y,k) (X[0]=ROR8(X[0]), X[0]=ADD(X[0],Y[0]), X[1]=ROR8(X[1]), X[1]=ADD(X[1],Y[1]), \
                    X[2]=ROR8(X[2]), X[2]=ADD(X[2],Y[2]), X[3]=ROR8(X[3]), X[3]=ADD(X[3],Y[3]), \
                    X[0]=XOR(X[0],k), X[1]=XOR(X[1],k), X[2]=XOR(X[2],k), X[3]=XOR(X[3],k), \
                    Z[0]=Y[0], Z[1]=Y[1], Z[2]=Y[2], Z[3]=Y[3],         \
                    Z[0]=SL(Z[0],3),  Y[0]=SR(Y[0],61), Z[1]=SL(Z[1],3), Y[1]=SR(Y[1],61), \
                    Z[2]=SL(Z[2],3),  Y[2]=SR(Y[2],61), Z[3]=SL(Z[3],3), Y[3]=SR(Y[3],61), \
                    Y[0]=XOR(Y[0],Z[0]), Y[1]=XOR(Y[1],Z[1]), Y[2]=XOR(Y[2],Z[2]), Y[3]=XOR(Y[3],Z[3]), \
                    Y[0]=XOR(X[0],Y[0]), Y[1]=XOR(X[1],Y[1]), Y[2]=XOR(X[2],Y[2]), Y[3]=XOR(X[3],Y[3]))

#define Rx1(x,y,k) (x[0]=RCS(x[0],8), x[0]+=y[0], x[0]^=k, y[0]=LCS(y[0],3), y[0]^=x[0])

#define Rx1b(x,y,k) (x=RCS(x,8), x+=y, x^=k, y=LCS(y,3), y^=x)

#define Encrypt(X,Y,k,n) (Rx##n(X,Y,k[0]),  Rx##n(X,Y,k[1]),  Rx##n(X,Y,k[2]),  Rx##n(X,Y,k[3]),  Rx##n(X,Y,k[4]),  Rx##n(X,Y,k[5]),  Rx##n(X,Y,k[6]),  Rx##n(X,Y,k[7]), \
                          Rx##n(X,Y,k[8]),  Rx##n(X,Y,k[9]),  Rx##n(X,Y,k[10]), Rx##n(X,Y,k[11]), Rx##n(X,Y,k[12]), Rx##n(X,Y,k[13]), Rx##n(X,Y,k[14]), Rx##n(X,Y,k[15]), \
                          Rx##n(X,Y,k[16]), Rx##n(X,Y,k[17]), Rx##n(X,Y,k[18]), Rx##n(X,Y,k[19]), Rx##n(X,Y,k[20]), Rx##n(X,Y,k[21]), Rx##n(X,Y,k[22]), Rx##n(X,Y,k[23]), \
                          Rx##n(X,Y,k[24]), Rx##n(X,Y,k[25]), Rx##n(X,Y,k[26]), Rx##n(X,Y,k[27]), Rx##n(X,Y,k[28]), Rx##n(X,Y,k[29]), Rx##n(X,Y,k[30]), Rx##n(X,Y,k[31]), \
                          Rx##n(X,Y,k[32]), Rx##n(X,Y,k[33]))

#define RK(X,Y,k,key,i)   (SET1(k[i],Y), key[i]=Y, X=RCS(X,8), X+=Y, X^=i, Y=LCS(Y,3), Y^=X)

#define EK(A,B,C,D,k,key) (RK(B,A,k,key,0),  RK(C,A,k,key,1),  RK(D,A,k,key,2),  RK(B,A,k,key,3),  RK(C,A,k,key,4),  RK(D,A,k,key,5),  RK(B,A,k,key,6), \
                           RK(C,A,k,key,7),  RK(D,A,k,key,8),  RK(B,A,k,key,9),  RK(C,A,k,key,10), RK(D,A,k,key,11), RK(B,A,k,key,12), RK(C,A,k,key,13), \
                           RK(D,A,k,key,14), RK(B,A,k,key,15), RK(C,A,k,key,16), RK(D,A,k,key,17), RK(B,A,k,key,18), RK(C,A,k,key,19), RK(D,A,k,key,20), \
                           RK(B,A,k,key,21), RK(C,A,k,key,22), RK(D,A,k,key,23), RK(B,A,k,key,24), RK(C,A,k,key,25), RK(D,A,k,key,26), RK(B,A,k,key,27), \
                           RK(C,A,k,key,28), RK(D,A,k,key,29), RK(B,A,k,key,30), RK(C,A,k,key,31), RK(D,A,k,key,32), RK(B,A,k,key,33))

typedef struct {
  u128 rk[34];
  u64 key[34];
} speck_context_t;


static int speck_encrypt_xor (unsigned char *out, const unsigned char *in, u64 nonce[], const speck_context_t ctx, int numbytes) {

  u64  x[2], y[2];
  u128 X[4], Y[4], Z[4];

  if (numbytes == 16) {
    x[0] = nonce[1]; y[0] = nonce[0]; nonce[0]++;
    Encrypt (x, y, ctx.key, 1);
    ((u64 *)out)[1] = x[0]; ((u64 *)out)[0] = y[0];
    return 0;
  }

  SET1 (X[0], nonce[1]); SET2 (Y[0], nonce[0]);

  if (numbytes == 32)
    Encrypt (X, Y, ctx.rk, 2);
  else {
    X[1] = X[0]; Y[1] = ADD (Y[0], _two);
    if (numbytes == 64)
      Encrypt (X, Y, ctx.rk, 4);
    else {
      X[2] = X[0]; Y[2] = ADD (Y[1], _two);
      if (numbytes == 96)
	Encrypt (X, Y, ctx.rk, 6);
      else {
	X[3] = X[0]; Y[3] = ADD (Y[2], _two);
	Encrypt (X, Y, ctx.rk, 8);
      }
    }
  }

  nonce[0] += (numbytes>>4);

  XOR_STORE (in, out, X[0], Y[0]);
  if (numbytes >= 64)
    XOR_STORE (in + 32, out + 32, X[1], Y[1]);
  if (numbytes >= 96)
    XOR_STORE (in + 64, out + 64, X[2], Y[2]);
  if (numbytes >= 128)
    XOR_STORE (in + 96, out + 96, X[3], Y[3]);

  return 0;
}


int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
	       const unsigned char *n, const speck_context_t ctx) {

  int i;
  u64 nonce[2];
  unsigned char block[16];
  u64 * const block64 = (u64 *)block;

  if (!inlen)
    return 0;

  nonce[0] = ((u64 *)n)[0];
  nonce[1] = ((u64 *)n)[1];

  while (inlen >= 128) {
    speck_encrypt_xor (out, in, nonce, ctx, 128);
    in += 128; inlen -= 128; out += 128;
  }

  if (inlen >= 96) {
    speck_encrypt_xor (out, in, nonce, ctx, 96);
    in += 96; inlen -= 96; out += 96;
  }

  if (inlen >= 64) {
    speck_encrypt_xor (out, in, nonce, ctx, 64);
    in += 64; inlen -= 64; out += 64;
  }

  if (inlen >= 32) {
    speck_encrypt_xor (out, in, nonce, ctx, 32);
    in += 32; inlen -= 32; out += 32;
  }

  if (inlen >= 16) {
    speck_encrypt_xor (block, in, nonce, ctx, 16);
    ((u64 *)out)[0] = block64[0] ^ ((u64 *)in)[0];
    ((u64 *)out)[1] = block64[1] ^ ((u64 *)in)[1];
    in += 16; inlen -= 16; out += 16;
  }

  if (inlen > 0) {
    speck_encrypt_xor (block, in, nonce, ctx, 16);
    for (i = 0; i < inlen; i++)
      out[i] = block[i] ^ in[i];
  }

  return 0;
}


int speck_expand_key (const unsigned char *k, speck_context_t *ctx) {

  u64 K[4];
  size_t i;
  for (i = 0; i < numkeywords; i++)
    K[i] = ((u64 *)k)[i];

  EK (K[0], K[1], K[2], K[3], ctx->rk, ctx->key);

  return 0;
}


#elif defined (__ARM_NEON)	// NEON support -------------------------------------------


#include <arm_neon.h>

#define u32 uint32_t
#define u64 uint64_t
#define u128 uint64x2_t

#define LCS(x,r) (((x)<<r)|((x)>>(64-r)))
#define RCS(x,r) (((x)>>r)|((x)<<(64-r)))

#define XOR veorq_u64
#define AND vandq_u64
#define ADD vaddq_u64
#define SL vshlq_n_u64
#define SR vshrq_n_u64

#define SET(a,b) vcombine_u64((uint64x1_t)(a),(uint64x1_t)(b))
#define SET1(X,c) (X=SET(c,c))
#define SET2(X,c) (SET1(X,c), X=ADD(X,SET(0x1ll,0x0ll)),c+=2)

#define LOW(Z) vgetq_lane_u64(Z,0)
#define HIGH(Z) vgetq_lane_u64(Z,1)
#define STORE(ip,X,Y) (((u64 *)(ip))[0]=HIGH(Y), ((u64 *)(ip))[1]=HIGH(X), ((u64 *)(ip))[2]=LOW(Y), ((u64 *)(ip))[3]=LOW(X))
#define XOR_STORE(in,out,X,Y) (Y=XOR(Y,SET(((u64 *)(in))[2],((u64 *)(in))[0])), X=XOR(X,SET(((u64 *)(in))[3],((u64 *)(in))[1])), STORE(out,X,Y))

#define ROR(X,r) vsriq_n_u64(SL(X,(64-r)),X,r)
#define ROL(X,r) ROR(X,(64-r))

#define tableR vcreate_u8(0x0007060504030201LL)
#define tableL vcreate_u8(0x0605040302010007LL)
#define ROR8(X) SET(vtbl1_u8((uint8x8_t)vget_low_u64(X),tableR), vtbl1_u8((uint8x8_t)vget_high_u64(X),tableR))
#define ROL8(X) SET(vtbl1_u8((uint8x8_t)vget_low_u64(X),tableL), vtbl1_u8((uint8x8_t)vget_high_u64(X),tableL))

#define numrounds 34
#define numkeywords 4

#define R(X,Y,k) (X=XOR(ADD(ROR8(X),Y),k), Y=XOR(ROL(Y,3),X))

#define Rx2(X,Y,k) (R(X[0],Y[0],k))

#define Rx4(X,Y,k) (R(X[0],Y[0],k), R(X[1],Y[1],k))
#define Rx6(X,Y,k) (R(X[0],Y[0],k), R(X[1],Y[1],k), R(X[2],Y[2],k))
#define Rx8(X,Y,k) (X[0]=ROR8(X[0]), X[0]=ADD(X[0],Y[0]), X[0]=XOR(X[0],k), X[1]=ROR8(X[1]), X[1]=ADD(X[1],Y[1]), X[1]=XOR(X[1],k), \
		    X[2]=ROR8(X[2]), X[2]=ADD(X[2],Y[2]), X[2]=XOR(X[2],k), X[3]=ROR8(X[3]), X[3]=ADD(X[3],Y[3]), X[3]=XOR(X[3],k), \
                    Z[0]=SL(Y[0],3), Z[1]=SL(Y[1],3), Z[2]=SL(Y[2],3), Z[3]=SL(Y[3],3),	\
                    Y[0]=SR(Y[0],61), Y[1]=SR(Y[1],61), Y[2]=SR(Y[2],61), Y[3]=SR(Y[3],61), \
                    Y[0]=XOR(Y[0],Z[0]), Y[1]=XOR(Y[1],Z[1]), Y[2]=XOR(Y[2],Z[2]), Y[3]=XOR(Y[3],Z[3]),	\
                    Y[0]=XOR(X[0],Y[0]), Y[1]=XOR(X[1],Y[1]), Y[2]=XOR(X[2],Y[2]), Y[3]=XOR(X[3],Y[3]))

#define Rx1(x,y,k) (x[0]=RCS(x[0],8), x[0]+=y[0], x[0]^=k, y[0]=LCS(y[0],3), y[0]^=x[0])

#define Rx1b(x,y,k) (x=RCS(x,8), x+=y, x^=k, y=LCS(y,3), y^=x)

#define Encrypt(X,Y,k,n) (Rx##n(X,Y,k[0]),  Rx##n(X,Y,k[1]),  Rx##n(X,Y,k[2]),  Rx##n(X,Y,k[3]),  Rx##n(X,Y,k[4]),  Rx##n(X,Y,k[5]),  Rx##n(X,Y,k[6]),  Rx##n(X,Y,k[7]), \
			  Rx##n(X,Y,k[8]),  Rx##n(X,Y,k[9]),  Rx##n(X,Y,k[10]), Rx##n(X,Y,k[11]), Rx##n(X,Y,k[12]), Rx##n(X,Y,k[13]), Rx##n(X,Y,k[14]), Rx##n(X,Y,k[15]), \
			  Rx##n(X,Y,k[16]), Rx##n(X,Y,k[17]), Rx##n(X,Y,k[18]), Rx##n(X,Y,k[19]), Rx##n(X,Y,k[20]), Rx##n(X,Y,k[21]), Rx##n(X,Y,k[22]), Rx##n(X,Y,k[23]), \
			  Rx##n(X,Y,k[24]), Rx##n(X,Y,k[25]), Rx##n(X,Y,k[26]), Rx##n(X,Y,k[27]), Rx##n(X,Y,k[28]), Rx##n(X,Y,k[29]), Rx##n(X,Y,k[30]), Rx##n(X,Y,k[31]), \
			  Rx##n(X,Y,k[32]), Rx##n(X,Y,k[33]))

#define RK(X,Y,k,key,i) (SET1(k[i],Y), key[i]=Y, X=RCS(X,8), X+=Y, X^=i, Y=LCS(Y,3), Y^=X)

#define EK(A,B,C,D,k,key) (RK(B,A,k,key,0),  RK(C,A,k,key,1),  RK(D,A,k,key,2),  RK(B,A,k,key,3),  RK(C,A,k,key,4),  RK(D,A,k,key,5),  RK(B,A,k,key,6),	\
			   RK(C,A,k,key,7),  RK(D,A,k,key,8),  RK(B,A,k,key,9),  RK(C,A,k,key,10), RK(D,A,k,key,11), RK(B,A,k,key,12), RK(C,A,k,key,13), \
			   RK(D,A,k,key,14), RK(B,A,k,key,15), RK(C,A,k,key,16), RK(D,A,k,key,17), RK(B,A,k,key,18), RK(C,A,k,key,19), RK(D,A,k,key,20), \
			   RK(B,A,k,key,21), RK(C,A,k,key,22), RK(D,A,k,key,23), RK(B,A,k,key,24), RK(C,A,k,key,25), RK(D,A,k,key,26), RK(B,A,k,key,27), \
			   RK(C,A,k,key,28), RK(D,A,k,key,29), RK(B,A,k,key,30), RK(C,A,k,key,31), RK(D,A,k,key,32), RK(B,A,k,key,33))

typedef struct {
  u128 rk[34];
  u64 key[34];
} speck_context_t;


static int speck_encrypt_xor (unsigned char *out, const unsigned char *in, u64 nonce[], speck_context_t *ctx, int numbytes) {

  u64  x[2], y[2];
  u128 X[4], Y[4], Z[4];

  if (numbytes == 16) {
    x[0] = nonce[1]; y[0]=nonce[0]; nonce[0]++;
    Encrypt (x, y, ctx->key, 1);
    ((u64 *)out)[1] = x[0]; ((u64 *)out)[0] = y[0];
    return 0;
  }

  SET1 (X[0], nonce[1]); SET2 (Y[0], nonce[0]);

  if (numbytes == 32)
    Encrypt (X, Y, ctx->rk, 2);
  else {
    X[1] = X[0]; SET2 (Y[1], nonce[0]);
    if (numbytes == 64)
      Encrypt (X, Y, ctx->rk, 4);
    else {
      X[2] = X[0]; SET2 (Y[2], nonce[0]);
      if (numbytes == 96)
	Encrypt (X, Y, ctx->rk, 6);
      else {
	X[3] = X[0]; SET2 (Y[3], nonce[0]);
	Encrypt (X, Y, ctx->rk, 8);
      }
    }
  }

  XOR_STORE (in, out, X[0], Y[0]);
  if (numbytes >= 64)
    XOR_STORE (in +  32, out +  32, X[1], Y[1]);
  if (numbytes >= 96)
    XOR_STORE (in +  64, out +  64, X[2], Y[2]);
  if (numbytes >= 128)
    XOR_STORE (in +  96, out +  96, X[3], Y[3]);

  return 0;
}


int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
	       const unsigned char *n, speck_context_t *ctx) {

  int i;
  u64 nonce[2];
  unsigned char block[16];
  u64 *const block64 = (u64 *)block;

  if (!inlen)
    return 0;

  nonce[0] = ((u64 *)n)[0];
  nonce[1] = ((u64 *)n)[1];

  while (inlen >= 128) {
    speck_encrypt_xor (out, in, nonce, ctx, 128);
    in += 128; inlen -= 128; out += 128;
  }

  if (inlen >= 96) {
    speck_encrypt_xor (out, in, nonce, ctx, 96);
    in += 96; inlen -= 96; out += 96;
  }

  if (inlen >= 64) {
    speck_encrypt_xor (out, in, nonce, ctx, 64);
    in += 64; inlen -= 64; out += 64;
  }

  if (inlen >= 32) {
    speck_encrypt_xor (out, in, nonce, ctx, 32);
    in += 32; inlen -= 32; out += 32;
  }

  if (inlen >= 16) {
    speck_encrypt_xor (block, in, nonce, ctx, 16);
    ((u64 *)out)[0] = block64[0] ^ ((u64 *)in)[0];
    ((u64 *)out)[1] = block64[1] ^ ((u64 *)in)[1];
    in += 16; inlen -= 16; out += 16;
  }

  if (inlen > 0) {
    speck_encrypt_xor (block, in, nonce, ctx, 16);
    for (i = 0; i < inlen; i++)
      out[i] = block[i] ^ in[i];
  }

  return 0;
}


int speck_expand_key (const unsigned char *k, speck_context_t *ctx) {

  u64 K[4];
  size_t i;
  for (i = 0; i < numkeywords; i++)
    K[i] = ((u64 *)k)[i];

  EK (K[0], K[1], K[2], K[3], ctx->rk, ctx->key);

  return 0;
}


#else 		// plain C ----------------------------------------------------------------


#define u64 uint64_t

#define ROR64(x,r) (((x)>>(r))|((x)<<(64-(r))))
#define ROL64(x,r) (((x)<<(r))|((x)>>(64-(r))))
#define R(x,y,k) (x=ROR64(x,8), x+=y, x^=k, y=ROL64(y,3), y^=x)


static int speck_encrypt (u64 *u, u64 *v, speck_context_t *ctx) {

  u64 i, x = *u, y = *v;

  for (i = 0; i < 34; i++)
    R (x, y, ctx->key[i]);

  *u = x; *v = y;

  return 0;
}


int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
	       const unsigned char *n, speck_context_t *ctx) {

  u64 i, nonce[2], x, y, t;
  unsigned char *block = malloc (16);

  if (!inlen) {
    free (block);
    return 0;
  }
  nonce[0] = htole64 ( ((u64*)n)[0] );
  nonce[1] = htole64 ( ((u64*)n)[1] );

  t=0;
  while (inlen >= 16) {
    x = nonce[1]; y = nonce[0]; nonce[0]++;
    speck_encrypt (&x, &y, ctx);
    ((u64 *)out)[1+t] = htole64 (x ^ ((u64 *)in)[1+t]);
    ((u64 *)out)[0+t] = htole64 (y ^ ((u64 *)in)[0+t]);
    t += 2;
    inlen -= 16;
  }
  if (inlen > 0) {
    x = nonce[1]; y = nonce[0];
    speck_encrypt (&x, &y, ctx);
    ((u64 *)block)[1] = htole64 (x); ((u64 *)block)[0] = htole64 (y);
    for (i = 0; i < inlen; i++)
      out[i + 8*t] = block[i] ^ in[i + 8*t];
  }

  free (block);
  return 0;
}


int speck_expand_key (const unsigned char *k, speck_context_t *ctx) {

  u64 K[4];
  u64 i;

  for (i = 0; i < 4; i++)
    K[i] = htole64 ( ((u64 *)k)[i] );

  for (i = 0; i < 33; i += 3) {
    ctx->key[i  ] = K[0];
    R (K[1], K[0], i    );
    ctx->key[i+1] = K[0];
    R (K[2], K[0], i + 1);
    ctx->key[i+2] = K[0];
    R (K[3], K[0], i + 2);
  }
  ctx->key[33] = K[0];
  return 1;
}


#endif		// AVX, SSE, NEON, plain C ------------------------------------------------


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

  speck_context_t ctx;

  speck_expand_key (key, &ctx);
#if defined (SPECK_CTX_BYVAL)
  speck_ctr (pt, pt, 16, iv, ctx);
#else
  speck_ctr (pt, pt, 16, iv, &ctx);
#endif
  u64 i;
  // fprintf (stderr, "rk00: %016llx\n",  ctx.key[0]);
  // fprintf (stderr, "rk33: %016llx\n",  ctx.key[33]);
  // fprintf (stderr, "out : %016lx\n", *(uint64_t*)pt);
  // fprintf (stderr, "mem : " ); for (i=0; i < 16; i++) fprintf (stderr, "%02x ", pt[i]); fprintf (stderr, "\n");

  int ret = 1;
  for (i=0; i < 16; i++)
    if (pt[i] != ct[i]) ret = 0;

  return (ret);
}

/*
  int main (int argc, char* argv[]) {

  fprintf (stdout, "SPECK SELF TEST RESULT: %u\n", speck_test (0,NULL));
  }
*/
