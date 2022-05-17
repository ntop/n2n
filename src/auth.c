/*
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */


#include "auth.h"


// mapping six binary bits to printable ascii character
static uint8_t b2a[64]  = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,   /* 0 ... 9, A ... F */
                            0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,   /* G ... V          */
                            0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,   /* W ... Z, a ... l */
                            0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x2b, 0x2d }; /* m ... z, + , -   */

// mapping ascii 0x30 ...0x7f back to 6 bit binary, invalids are mapped to 0xff
static uint8_t a2b[256] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0x3f, 0xff, 0xff,   /* 0x20 ... 0x2f */
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0x3e, 0xff, 0x3f, 0xff,   /* 0x30 ... 0x3f */
                            0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,   /* 0x40 ... 0x4f */
                            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0xff, 0xff, 0xff, 0xff, 0xff,   /* 0x50 ... 0x5f */
                            0xff, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,   /* 0x60 ... 0x6f */
                            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff }; /* 0x70 ... 0x7f */


int bin_to_ascii (char *out, uint8_t *in, size_t in_len) {

    // in buffer contains binary data of length in_len

    // out buffer is already allocated and of size   ceiling(in_len * 8 / 6) + 1
    // out buffer will be filled with a string including trailing 0x00

    size_t bit_count = 0;
    size_t out_count = 0;
    uint8_t buf1, buf2;

    for(bit_count = 0; bit_count < 8 * in_len; bit_count += 6) {
        buf1 = in[bit_count / 8];
        buf1 <<= bit_count % 8;

        buf2 = ((bit_count + 8) < (8 * in_len)) ? in[bit_count / 8 + 1] : 0;
        buf2 >>= 8 - (bit_count % 8);

        buf1 |= buf2;
        buf1 >>= 2;

        out[out_count++] = b2a[buf1];
    }
    out[out_count] = 0;

    return 0;
}


int ascii_to_bin (uint8_t *out, char *in) {

    // in buffer contains 0x00-terminated string to be decoded

    // out buffer will contain decoded binary data
    // out buffer is already allocated and of size   floor(strlen(in) * 6 / 8)

    size_t in_count, out_count, bit_count;
    uint16_t buf = 0;

    bit_count = 0;
    out_count = 0;
    for(in_count = 0; in_count < strlen(in); in_count++) {
        buf <<= 6;

        int ch = in[in_count];
        if((ch > 0x20) && (ch < 0x80)) {
            if(a2b[ch] != 0xFF) {
                buf |= a2b[ch - 0x20];
            } else {
                traceEvent(TRACE_NORMAL, "ascii_to_bin encountered the unknown character '%c'", in[in_count]);
            }
        } else {
            traceEvent(TRACE_WARNING, "ascii_to_bin encountered a completely out-of-range character");
        }
        bit_count += 6;

        if(bit_count / 8) {
            bit_count -= 8;
            out[out_count++] = ((uint8_t)(buf >> bit_count));
        }

    }

    return 0;
}


int generate_private_key (n2n_private_public_key_t key, char *in) {

    // hash the 0-terminated string input twice to generate private key

    pearson_hash_256(key, (uint8_t *)in, strlen(in));
    pearson_hash_256(key, key, sizeof(n2n_private_public_key_t));

    return 0;
}


int generate_public_key (n2n_private_public_key_t pub, n2n_private_public_key_t prv) {

    // generator point '9' on curve
    static uint8_t gen[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 };

    curve25519(pub, prv, gen);

    return 0;
}


int generate_shared_secret (n2n_private_public_key_t shared, n2n_private_public_key_t prv, n2n_private_public_key_t pub) {

    curve25519(shared, prv, pub);
    pearson_hash_256(shared, shared, sizeof(n2n_private_public_key_t));

    return 0;
}


int bind_private_key_to_username (n2n_private_public_key_t prv, char *username) {

    uint8_t tmp[32];

    pearson_hash_256(tmp, (uint8_t *)username, strlen(username));
    memxor(prv, tmp, sizeof(n2n_private_public_key_t));

    return 0;
}


// calculate SPECK ( plain = HASH³(time), key = HASH³(comm) ^ HASH³(fed) )
int calculate_dynamic_key (uint8_t out_key[N2N_AUTH_CHALLENGE_SIZE],
                           uint32_t key_time, n2n_community_t comm, n2n_community_t fed) {

    uint8_t           key[N2N_AUTH_CHALLENGE_SIZE];
    uint8_t           tmp[N2N_AUTH_CHALLENGE_SIZE];
    speck_context_t   *ctx;

    // we know that N2N_AUTH_CHALLENGE_SIZE == 16, i.e. 128 bit that can take the hash value
    pearson_hash_128(key, comm, sizeof(n2n_community_t));
    pearson_hash_128(key, key, N2N_AUTH_CHALLENGE_SIZE);
    pearson_hash_128(key, key, N2N_AUTH_CHALLENGE_SIZE);

    pearson_hash_128(tmp, fed, sizeof(n2n_community_t));
    pearson_hash_128(tmp, tmp, N2N_AUTH_CHALLENGE_SIZE);
    pearson_hash_128(tmp, tmp, N2N_AUTH_CHALLENGE_SIZE);

    memxor(key, tmp, N2N_AUTH_CHALLENGE_SIZE);

    ctx = (speck_context_t*)calloc(1, sizeof(speck_context_t));
    speck_init((speck_context_t**)&ctx, key, 128);

    pearson_hash_128(tmp, (uint8_t*)&key_time, sizeof(key_time));
    pearson_hash_128(tmp, tmp, N2N_AUTH_CHALLENGE_SIZE);
    pearson_hash_128(out_key, tmp, N2N_AUTH_CHALLENGE_SIZE);

    speck_128_encrypt(out_key, ctx);

    free(ctx);

    return 0;
}
