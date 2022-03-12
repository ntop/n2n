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


// taken (and modified) from github/fudanchii/twofish as of August 2020
// which itself is a modified copy of Andrew T. Csillag's implementation
// published on github/drewcsillag/twofish


/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Andrew T. Csillag
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include "tf.h"


const uint8_t RS[4][8] = { { 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, },
                           { 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5, },
                           { 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19, },
                           { 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03  } };

const uint8_t Q0[] = { 0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
                       0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
                       0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
                       0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
                       0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
                       0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
                       0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
                       0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
                       0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
                       0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
                       0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
                       0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
                       0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
                       0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
                       0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
                       0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0 };

const uint8_t Q1[] = { 0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
                       0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
                       0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
                       0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
                       0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
                       0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
                       0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
                       0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
                       0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
                       0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
                       0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
                       0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
                       0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
                       0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
                       0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
                       0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91 };

const uint8_t mult5B[] = { 0x00, 0x5B, 0xB6, 0xED, 0x05, 0x5E, 0xB3, 0xE8, 0x0A, 0x51, 0xBC, 0xE7, 0x0F, 0x54, 0xB9, 0xE2,
                           0x14, 0x4F, 0xA2, 0xF9, 0x11, 0x4A, 0xA7, 0xFC, 0x1E, 0x45, 0xA8, 0xF3, 0x1B, 0x40, 0xAD, 0xF6,
                           0x28, 0x73, 0x9E, 0xC5, 0x2D, 0x76, 0x9B, 0xC0, 0x22, 0x79, 0x94, 0xCF, 0x27, 0x7C, 0x91, 0xCA,
                           0x3C, 0x67, 0x8A, 0xD1, 0x39, 0x62, 0x8F, 0xD4, 0x36, 0x6D, 0x80, 0xDB, 0x33, 0x68, 0x85, 0xDE,
                           0x50, 0x0B, 0xE6, 0xBD, 0x55, 0x0E, 0xE3, 0xB8, 0x5A, 0x01, 0xEC, 0xB7, 0x5F, 0x04, 0xE9, 0xB2,
                           0x44, 0x1F, 0xF2, 0xA9, 0x41, 0x1A, 0xF7, 0xAC, 0x4E, 0x15, 0xF8, 0xA3, 0x4B, 0x10, 0xFD, 0xA6,
                           0x78, 0x23, 0xCE, 0x95, 0x7D, 0x26, 0xCB, 0x90, 0x72, 0x29, 0xC4, 0x9F, 0x77, 0x2C, 0xC1, 0x9A,
                           0x6C, 0x37, 0xDA, 0x81, 0x69, 0x32, 0xDF, 0x84, 0x66, 0x3D, 0xD0, 0x8B, 0x63, 0x38, 0xD5, 0x8E,
                           0xA0, 0xFB, 0x16, 0x4D, 0xA5, 0xFE, 0x13, 0x48, 0xAA, 0xF1, 0x1C, 0x47, 0xAF, 0xF4, 0x19, 0x42,
                           0xB4, 0xEF, 0x02, 0x59, 0xB1, 0xEA, 0x07, 0x5C, 0xBE, 0xE5, 0x08, 0x53, 0xBB, 0xE0, 0x0D, 0x56,
                           0x88, 0xD3, 0x3E, 0x65, 0x8D, 0xD6, 0x3B, 0x60, 0x82, 0xD9, 0x34, 0x6F, 0x87, 0xDC, 0x31, 0x6A,
                           0x9C, 0xC7, 0x2A, 0x71, 0x99, 0xC2, 0x2F, 0x74, 0x96, 0xCD, 0x20, 0x7B, 0x93, 0xC8, 0x25, 0x7E,
                           0xF0, 0xAB, 0x46, 0x1D, 0xF5, 0xAE, 0x43, 0x18, 0xFA, 0xA1, 0x4C, 0x17, 0xFF, 0xA4, 0x49, 0x12,
                           0xE4, 0xBF, 0x52, 0x09, 0xE1, 0xBA, 0x57, 0x0C, 0xEE, 0xB5, 0x58, 0x03, 0xEB, 0xB0, 0x5D, 0x06,
                           0xD8, 0x83, 0x6E, 0x35, 0xDD, 0x86, 0x6B, 0x30, 0xD2, 0x89, 0x64, 0x3F, 0xD7, 0x8C, 0x61, 0x3A,
                           0xCC, 0x97, 0x7A, 0x21, 0xC9, 0x92, 0x7F, 0x24, 0xC6, 0x9D, 0x70, 0x2B, 0xC3, 0x98, 0x75, 0x2E };

const uint8_t multEF[] = { 0x00, 0xEF, 0xB7, 0x58, 0x07, 0xE8, 0xB0, 0x5F, 0x0E, 0xE1, 0xB9, 0x56, 0x09, 0xE6, 0xBE, 0x51,
                           0x1C, 0xF3, 0xAB, 0x44, 0x1B, 0xF4, 0xAC, 0x43, 0x12, 0xFD, 0xA5, 0x4A, 0x15, 0xFA, 0xA2, 0x4D,
                           0x38, 0xD7, 0x8F, 0x60, 0x3F, 0xD0, 0x88, 0x67, 0x36, 0xD9, 0x81, 0x6E, 0x31, 0xDE, 0x86, 0x69,
                           0x24, 0xCB, 0x93, 0x7C, 0x23, 0xCC, 0x94, 0x7B, 0x2A, 0xC5, 0x9D, 0x72, 0x2D, 0xC2, 0x9A, 0x75,
                           0x70, 0x9F, 0xC7, 0x28, 0x77, 0x98, 0xC0, 0x2F, 0x7E, 0x91, 0xC9, 0x26, 0x79, 0x96, 0xCE, 0x21,
                           0x6C, 0x83, 0xDB, 0x34, 0x6B, 0x84, 0xDC, 0x33, 0x62, 0x8D, 0xD5, 0x3A, 0x65, 0x8A, 0xD2, 0x3D,
                           0x48, 0xA7, 0xFF, 0x10, 0x4F, 0xA0, 0xF8, 0x17, 0x46, 0xA9, 0xF1, 0x1E, 0x41, 0xAE, 0xF6, 0x19,
                           0x54, 0xBB, 0xE3, 0x0C, 0x53, 0xBC, 0xE4, 0x0B, 0x5A, 0xB5, 0xED, 0x02, 0x5D, 0xB2, 0xEA, 0x05,
                           0xE0, 0x0F, 0x57, 0xB8, 0xE7, 0x08, 0x50, 0xBF, 0xEE, 0x01, 0x59, 0xB6, 0xE9, 0x06, 0x5E, 0xB1,
                           0xFC, 0x13, 0x4B, 0xA4, 0xFB, 0x14, 0x4C, 0xA3, 0xF2, 0x1D, 0x45, 0xAA, 0xF5, 0x1A, 0x42, 0xAD,
                           0xD8, 0x37, 0x6F, 0x80, 0xDF, 0x30, 0x68, 0x87, 0xD6, 0x39, 0x61, 0x8E, 0xD1, 0x3E, 0x66, 0x89,
                           0xC4, 0x2B, 0x73, 0x9C, 0xC3, 0x2C, 0x74, 0x9B, 0xCA, 0x25, 0x7D, 0x92, 0xCD, 0x22, 0x7A, 0x95,
                           0x90, 0x7F, 0x27, 0xC8, 0x97, 0x78, 0x20, 0xCF, 0x9E, 0x71, 0x29, 0xC6, 0x99, 0x76, 0x2E, 0xC1,
                           0x8C, 0x63, 0x3B, 0xD4, 0x8B, 0x64, 0x3C, 0xD3, 0x82, 0x6D, 0x35, 0xDA, 0x85, 0x6A, 0x32, 0xDD,
                           0xA8, 0x47, 0x1F, 0xF0, 0xAF, 0x40, 0x18, 0xF7, 0xA6, 0x49, 0x11, 0xFE, 0xA1, 0x4E, 0x16, 0xF9,
                           0xB4, 0x5B, 0x03, 0xEC, 0xB3, 0x5C, 0x04, 0xEB, 0xBA, 0x55, 0x0D, 0xE2, 0xBD, 0x52, 0x0A, 0xE5 };


#define RS_MOD 0x14D
#define RHO 0x01010101L

#define ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#define _b(x, N) (((x) >> (N*8)) & 0xFF)

#define b0(x) ((uint8_t)(x))
#define b1(x) ((uint8_t)((x) >> 8))
#define b2(x) ((uint8_t)((x) >> 16))
#define b3(x) ((uint8_t)((x) >> 24))

#define U8ARRAY_TO_U32(r) ((r[0] << 24) ^ (r[1] << 16) ^ (r[2] << 8) ^ r[3])
#define U8S_TO_U32(r0, r1, r2, r3) ((r0 << 24) ^ (r1 << 16) ^ (r2 << 8) ^ r3)


// multiply two polynomials represented as u32's, actually called with bytes
uint32_t polyMult(uint32_t a, uint32_t b) {

    uint32_t t=0;

    while(a) {
        if(a & 1)
            t^=b;
        b <<= 1;
        a >>= 1;
    }

    return t;
}


// take the polynomial t and return the t % modulus in GF(256)
uint32_t gfMod(uint32_t t, uint32_t modulus) {

    int i;
    uint32_t tt;

    modulus <<= 7;
    for(i = 0; i < 8; i++) {
        tt = t ^ modulus;
        if(tt < t)
             t = tt;
        modulus >>= 1;
    }

    return t;
}


// multiply a and b and return the modulus
#define gfMult(a, b, modulus) gfMod(polyMult(a, b), modulus)


// return a u32 containing the result of multiplying the RS Code matrix by the sd matrix
uint32_t RSMatrixMultiply(uint8_t sd[8]) {

    int j, k;
    uint8_t t;
    uint8_t result[4];

    for(j = 0; j < 4; j++) {
        t = 0;
        for(k = 0; k < 8; k++) {
            t ^= gfMult(RS[j][k], sd[k], RS_MOD);
        }
        result[3-j] = t;
    }

    return U8ARRAY_TO_U32(result);
}


// the Zero-keyed h function (used by the key setup routine)
uint32_t h(uint32_t X, uint32_t L[4], int k) {

    uint8_t y0, y1, y2, y3;
    uint8_t z0, z1, z2, z3;

    y0 = b0(X);
    y1 = b1(X);
    y2 = b2(X);
    y3 = b3(X);

    switch(k) {
        case 4:
            y0 = Q1[y0] ^ b0(L[3]);
            y1 = Q0[y1] ^ b1(L[3]);
            y2 = Q0[y2] ^ b2(L[3]);
            y3 = Q1[y3] ^ b3(L[3]);
        case 3:
            y0 = Q1[y0] ^ b0(L[2]);
            y1 = Q1[y1] ^ b1(L[2]);
            y2 = Q0[y2] ^ b2(L[2]);
            y3 = Q0[y3] ^ b3(L[2]);
        case 2:
            y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
            y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
            y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
            y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
    }

    // inline the MDS matrix multiply
    z0 = multEF[y0] ^ y1 ^         multEF[y2] ^ mult5B[y3];
    z1 = multEF[y0] ^ mult5B[y1] ^ y2 ^         multEF[y3];
    z2 = mult5B[y0] ^ multEF[y1] ^ multEF[y2] ^ y3;
    z3 = y0 ^         multEF[y1] ^ mult5B[y2] ^ mult5B[y3];

    return U8S_TO_U32(z0, z1, z2, z3);
}


// given the Sbox keys, create the fully keyed QF
void fullKey(uint32_t L[4], int k, uint32_t QF[4][256]) {

    uint8_t y0, y1, y2, y3;
    int i;

    // for all input values to the Q permutations
    for(i = 0; i < 256; i++) {
        // run the Q permutations
        y0 = i; y1 = i; y2 = i; y3 = i;
        switch(k) {
            case 4:
                y0 = Q1[y0] ^ b0(L[3]);
                y1 = Q0[y1] ^ b1(L[3]);
                y2 = Q0[y2] ^ b2(L[3]);
                y3 = Q1[y3] ^ b3(L[3]);
            case 3:
                y0 = Q1[y0] ^ b0(L[2]);
                y1 = Q1[y1] ^ b1(L[2]);
                y2 = Q0[y2] ^ b2(L[2]);
                y3 = Q0[y3] ^ b3(L[2]);
            case 2:
                y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
                y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
                y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
                y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
        }

        // now do the partial MDS matrix multiplies
        QF[0][i] = ((multEF[y0] << 24)
                 | (multEF[y0] << 16)
                 | (mult5B[y0] << 8)
                 | y0);
        QF[1][i] = ((y1 << 24)
                 | (mult5B[y1] << 16)
                 | (multEF[y1] << 8)
                 | multEF[y1]);
        QF[2][i] = ((multEF[y2] << 24)
                 | (y2 << 16)
                 | (multEF[y2] << 8)
                 | mult5B[y2]);
        QF[3][i] = ((mult5B[y3] << 24)
                 | (multEF[y3] << 16)
                 | (y3 << 8)
                 | mult5B[y3]);
    }
}

// ----------------------------------------------------------------------------------------------------------------


// fully keyed h (aka g) function
#define fkh(X) (ctx->QF[0][b0(X)]^ctx->QF[1][b1(X)]^ctx->QF[2][b2(X)]^ctx->QF[3][b3(X)])


// ----------------------------------------------------------------------------------------------------------------


// one encryption round
#define ENC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh(ROL(R1, 8)); \
    R2 = ROR(R2 ^ (T1 + T0 + ctx->K[2*round+8]), 1); \
    R3 = ROL(R3, 1) ^ (2*T1 + T0 + ctx->K[2*round+9]);


void twofish_internal_encrypt(uint8_t PT[16], tf_context_t *ctx) {

    uint32_t R0, R1, R2, R3;
    uint32_t T0, T1;

    // load/byteswap/whiten input
    R3 = ctx->K[3] ^ le32toh(((uint32_t*)PT)[3]);
    R2 = ctx->K[2] ^ le32toh(((uint32_t*)PT)[2]);
    R1 = ctx->K[1] ^ le32toh(((uint32_t*)PT)[1]);
    R0 = ctx->K[0] ^ le32toh(((uint32_t*)PT)[0]);

    ENC_ROUND(R0, R1, R2, R3,  0);
    ENC_ROUND(R2, R3, R0, R1,  1);
    ENC_ROUND(R0, R1, R2, R3,  2);
    ENC_ROUND(R2, R3, R0, R1,  3);
    ENC_ROUND(R0, R1, R2, R3,  4);
    ENC_ROUND(R2, R3, R0, R1,  5);
    ENC_ROUND(R0, R1, R2, R3,  6);
    ENC_ROUND(R2, R3, R0, R1,  7);
    ENC_ROUND(R0, R1, R2, R3,  8);
    ENC_ROUND(R2, R3, R0, R1,  9);
    ENC_ROUND(R0, R1, R2, R3, 10);
    ENC_ROUND(R2, R3, R0, R1, 11);
    ENC_ROUND(R0, R1, R2, R3, 12);
    ENC_ROUND(R2, R3, R0, R1, 13);
    ENC_ROUND(R0, R1, R2, R3, 14);
    ENC_ROUND(R2, R3, R0, R1, 15);

    // whiten/byteswap/store output
    ((uint32_t*)PT)[3] = htole32(R1 ^ ctx->K[7]);
    ((uint32_t*)PT)[2] = htole32(R0 ^ ctx->K[6]);
    ((uint32_t*)PT)[1] = htole32(R3 ^ ctx->K[5]);
    ((uint32_t*)PT)[0] = htole32(R2 ^ ctx->K[4]);
}


// ----------------------------------------------------------------------------------------------------------------


// one decryption round
#define DEC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh(ROL(R1, 8)); \
    R2 = ROL(R2, 1) ^ (T0 + T1 + ctx->K[2*round+8]); \
    R3 = ROR(R3 ^ (T0 + 2*T1 + ctx->K[2*round+9]), 1);


void twofish_internal_decrypt(uint8_t PT[16], const uint8_t CT[16], tf_context_t *ctx) {

    uint32_t T0, T1;
    uint32_t R0, R1, R2, R3;

    // load/byteswap/whiten input
    R3 = ctx->K[7] ^ le32toh(((uint32_t*)CT)[3]);
    R2 = ctx->K[6] ^ le32toh(((uint32_t*)CT)[2]);
    R1 = ctx->K[5] ^ le32toh(((uint32_t*)CT)[1]);
    R0 = ctx->K[4] ^ le32toh(((uint32_t*)CT)[0]);

    DEC_ROUND(R0, R1, R2, R3, 15);
    DEC_ROUND(R2, R3, R0, R1, 14);
    DEC_ROUND(R0, R1, R2, R3, 13);
    DEC_ROUND(R2, R3, R0, R1, 12);
    DEC_ROUND(R0, R1, R2, R3, 11);
    DEC_ROUND(R2, R3, R0, R1, 10);
    DEC_ROUND(R0, R1, R2, R3,  9);
    DEC_ROUND(R2, R3, R0, R1,  8);
    DEC_ROUND(R0, R1, R2, R3,  7);
    DEC_ROUND(R2, R3, R0, R1,  6);
    DEC_ROUND(R0, R1, R2, R3,  5);
    DEC_ROUND(R2, R3, R0, R1,  4);
    DEC_ROUND(R0, R1, R2, R3,  3);
    DEC_ROUND(R2, R3, R0, R1,  2);
    DEC_ROUND(R0, R1, R2, R3,  1);
    DEC_ROUND(R2, R3, R0, R1,  0);

    // whiten/byteswap/store output
    ((uint32_t*)PT)[3] = htole32(R1 ^ ctx->K[3]);
    ((uint32_t*)PT)[2] = htole32(R0 ^ ctx->K[2]);
    ((uint32_t*)PT)[1] = htole32(R3 ^ ctx->K[1]);
    ((uint32_t*)PT)[0] = htole32(R2 ^ ctx->K[0]);
}


// -------------------------------------------------------------------------------------


// the key schedule routine
void keySched(const uint8_t M[], int N, uint32_t **S, uint32_t K[40], int *k) {

    uint32_t Mo[4], Me[4];
    int i, j;
    uint8_t vector[8];
    uint32_t A, B;

    *k = (N + 63) / 64;
    *S = (uint32_t*)malloc(sizeof(uint32_t) * (*k));

    for(i = 0; i < *k; i++) {
        Me[i] = le32toh(((uint32_t*)M)[2*i]);
        Mo[i] = le32toh(((uint32_t*)M)[2*i+1]);
    }

    for(i = 0; i < *k; i++) {
        for(j = 0; j < 4; j++)
            vector[j] = _b(Me[i], j);
        for(j = 0; j < 4; j++)
            vector[j+4] = _b(Mo[i], j);
        (*S)[(*k)-i-1] = RSMatrixMultiply(vector);
    }

    for(i = 0; i < 20; i++) {
        A = h(2*i*RHO, Me, *k);
        B = ROL(h(2*i*RHO + RHO, Mo, *k), 8);
        K[2*i] = A+B;
        K[2*i+1] = ROL(A + 2*B, 9);
    }
}


// ----------------------------------------------------------------------------------------------------------------


#define fix_xor(target, source) *(uint32_t*)&(target)[0] = *(uint32_t*)&(target)[0] ^ *(uint32_t*)&(source)[0]; *(uint32_t*)&(target)[4] = *(uint32_t*)&(target)[4] ^ *(uint32_t*)&(source)[4]; \
                                *(uint32_t*)&(target)[8] = *(uint32_t*)&(target)[8] ^ *(uint32_t*)&(source)[8]; *(uint32_t*)&(target)[12] = *(uint32_t*)&(target)[12] ^ *(uint32_t*)&(source)[12];

// ----------------------------------------------------------------------------------------------------------------


// public API


int tf_ecb_decrypt (unsigned char *out, const unsigned char *in, tf_context_t *ctx) {

    twofish_internal_decrypt(out, in, ctx);

    return TF_BLOCK_SIZE;
}


// not used
int tf_ecb_encrypt (unsigned char *out, const unsigned char *in, tf_context_t *ctx) {

    memcpy(out, in, TF_BLOCK_SIZE);
    twofish_internal_encrypt(out, ctx);

    return TF_BLOCK_SIZE;
}


int tf_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, tf_context_t *ctx) {

    uint8_t tmp[TF_BLOCK_SIZE];
    size_t i;
    size_t n;

    memcpy(tmp, iv, TF_BLOCK_SIZE);

    n = in_len / TF_BLOCK_SIZE;
    for(i = 0; i < n; i++) {
        fix_xor(tmp, &in[i * TF_BLOCK_SIZE]);
        twofish_internal_encrypt(tmp, ctx);
        memcpy(&out[i * TF_BLOCK_SIZE], tmp, TF_BLOCK_SIZE);
    }

    return n * TF_BLOCK_SIZE;
}


int tf_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, tf_context_t *ctx) {

    int n;                       /* number of blocks */
    /* int ret = (int)in_len & 15;  remainder, unused*/

    uint8_t ivec[TF_BLOCK_SIZE]; /* the ivec/old handling might be optimized if we */
    uint8_t old[TF_BLOCK_SIZE];  /* can be sure that in != out                     */

    memcpy(ivec, iv, TF_BLOCK_SIZE);

    // 3 parallel rails of twofish decryption
    for(n = in_len / TF_BLOCK_SIZE; n > 2; n -=3) {
        memcpy(old, in + 2 * TF_BLOCK_SIZE, TF_BLOCK_SIZE);

        uint32_t T0, T1;
        uint32_t Q0, Q1, Q2, Q3, R0, R1, R2, R3, S0, S1, S2, S3;

        // load/byteswap/whiten input/iv
        Q3 = ctx->K[7] ^ le32toh(((uint32_t*)in)[3]);
        Q2 = ctx->K[6] ^ le32toh(((uint32_t*)in)[2]);
        Q1 = ctx->K[5] ^ le32toh(((uint32_t*)in)[1]);
        Q0 = ctx->K[4] ^ le32toh(((uint32_t*)in)[0]);

        R3 = ctx->K[7] ^ le32toh(((uint32_t*)in)[7]);
        R2 = ctx->K[6] ^ le32toh(((uint32_t*)in)[6]);
        R1 = ctx->K[5] ^ le32toh(((uint32_t*)in)[5]);
        R0 = ctx->K[4] ^ le32toh(((uint32_t*)in)[4]);

        S3 = ctx->K[7] ^ le32toh(((uint32_t*)in)[11]);
        S2 = ctx->K[6] ^ le32toh(((uint32_t*)in)[10]);
        S1 = ctx->K[5] ^ le32toh(((uint32_t*)in)[9]);
        S0 = ctx->K[4] ^ le32toh(((uint32_t*)in)[8]);

        DEC_ROUND(Q0, Q1, Q2, Q3, 15); DEC_ROUND(R0, R1, R2, R3, 15); DEC_ROUND(S0, S1, S2, S3, 15);
        DEC_ROUND(Q2, Q3, Q0, Q1, 14); DEC_ROUND(R2, R3, R0, R1, 14); DEC_ROUND(S2, S3, S0, S1, 14);
        DEC_ROUND(Q0, Q1, Q2, Q3, 13); DEC_ROUND(R0, R1, R2, R3, 13); DEC_ROUND(S0, S1, S2, S3, 13);
        DEC_ROUND(Q2, Q3, Q0, Q1, 12); DEC_ROUND(R2, R3, R0, R1, 12); DEC_ROUND(S2, S3, S0, S1, 12);
        DEC_ROUND(Q0, Q1, Q2, Q3, 11); DEC_ROUND(R0, R1, R2, R3, 11); DEC_ROUND(S0, S1, S2, S3, 11);
        DEC_ROUND(Q2, Q3, Q0, Q1, 10); DEC_ROUND(R2, R3, R0, R1, 10); DEC_ROUND(S2, S3, S0, S1, 10);
        DEC_ROUND(Q0, Q1, Q2, Q3,  9); DEC_ROUND(R0, R1, R2, R3,  9); DEC_ROUND(S0, S1, S2, S3,  9);
        DEC_ROUND(Q2, Q3, Q0, Q1,  8); DEC_ROUND(R2, R3, R0, R1,  8); DEC_ROUND(S2, S3, S0, S1,  8);
        DEC_ROUND(Q0, Q1, Q2, Q3,  7); DEC_ROUND(R0, R1, R2, R3,  7); DEC_ROUND(S0, S1, S2, S3,  7);
        DEC_ROUND(Q2, Q3, Q0, Q1,  6); DEC_ROUND(R2, R3, R0, R1,  6); DEC_ROUND(S2, S3, S0, S1,  6);
        DEC_ROUND(Q0, Q1, Q2, Q3,  5); DEC_ROUND(R0, R1, R2, R3,  5); DEC_ROUND(S0, S1, S2, S3,  5);
        DEC_ROUND(Q2, Q3, Q0, Q1,  4); DEC_ROUND(R2, R3, R0, R1,  4); DEC_ROUND(S2, S3, S0, S1,  4);
        DEC_ROUND(Q0, Q1, Q2, Q3,  3); DEC_ROUND(R0, R1, R2, R3,  3); DEC_ROUND(S0, S1, S2, S3,  3);
        DEC_ROUND(Q2, Q3, Q0, Q1,  2); DEC_ROUND(R2, R3, R0, R1,  2); DEC_ROUND(S2, S3, S0, S1,  2);
        DEC_ROUND(Q0, Q1, Q2, Q3,  1); DEC_ROUND(R0, R1, R2, R3,  1); DEC_ROUND(S0, S1, S2, S3,  1);
        DEC_ROUND(Q2, Q3, Q0, Q1,  0); DEC_ROUND(R2, R3, R0, R1,  0); DEC_ROUND(S2, S3, S0, S1,  0);

        // whiten/byteswap/store output/iv
        ((uint32_t*)out)[11] = htole32(S1 ^ ctx->K[3] ^ ((uint32_t*)in)[7]);
        ((uint32_t*)out)[10] = htole32(S0 ^ ctx->K[2] ^ ((uint32_t*)in)[6]);
        ((uint32_t*)out)[9]  = htole32(S3 ^ ctx->K[1] ^ ((uint32_t*)in)[5]);
        ((uint32_t*)out)[8]  = htole32(S2 ^ ctx->K[0] ^ ((uint32_t*)in)[4]);

        ((uint32_t*)out)[7]  = htole32(R1 ^ ctx->K[3] ^ ((uint32_t*)in)[3]);
        ((uint32_t*)out)[6]  = htole32(R0 ^ ctx->K[2] ^ ((uint32_t*)in)[2]);
        ((uint32_t*)out)[5]  = htole32(R3 ^ ctx->K[1] ^ ((uint32_t*)in)[1]);
        ((uint32_t*)out)[4]  = htole32(R2 ^ ctx->K[0] ^ ((uint32_t*)in)[0]);

        ((uint32_t*)out)[3]  = htole32(Q1 ^ ctx->K[3] ^ ((uint32_t*)ivec)[3]);
        ((uint32_t*)out)[2]  = htole32(Q0 ^ ctx->K[2] ^ ((uint32_t*)ivec)[2]);
        ((uint32_t*)out)[1]  = htole32(Q3 ^ ctx->K[1] ^ ((uint32_t*)ivec)[1]);
        ((uint32_t*)out)[0]  = htole32(Q2 ^ ctx->K[0] ^ ((uint32_t*)ivec)[0]);

        in += 3 * TF_BLOCK_SIZE; out += 3 * TF_BLOCK_SIZE;

        memcpy(ivec, old, TF_BLOCK_SIZE);
    }

    // handle the two or less remaining block on a single rail
    for(; n != 0; n--) {
        uint32_t T0, T1;
        uint32_t Q0, Q1, Q2, Q3;

        memcpy(old, in, TF_BLOCK_SIZE);

        // load/byteswap/whiten input
        Q3 = ctx->K[7] ^ le32toh(((uint32_t*)in)[3]);
        Q2 = ctx->K[6] ^ le32toh(((uint32_t*)in)[2]);
        Q1 = ctx->K[5] ^ le32toh(((uint32_t*)in)[1]);
        Q0 = ctx->K[4] ^ le32toh(((uint32_t*)in)[0]);

        DEC_ROUND(Q0, Q1, Q2, Q3, 15);
        DEC_ROUND(Q2, Q3, Q0, Q1, 14);
        DEC_ROUND(Q0, Q1, Q2, Q3, 13);
        DEC_ROUND(Q2, Q3, Q0, Q1, 12);
        DEC_ROUND(Q0, Q1, Q2, Q3, 11);
        DEC_ROUND(Q2, Q3, Q0, Q1, 10);
        DEC_ROUND(Q0, Q1, Q2, Q3,  9);
        DEC_ROUND(Q2, Q3, Q0, Q1,  8);
        DEC_ROUND(Q0, Q1, Q2, Q3,  7);
        DEC_ROUND(Q2, Q3, Q0, Q1,  6);
        DEC_ROUND(Q0, Q1, Q2, Q3,  5);
        DEC_ROUND(Q2, Q3, Q0, Q1,  4);
        DEC_ROUND(Q0, Q1, Q2, Q3,  3);
        DEC_ROUND(Q2, Q3, Q0, Q1,  2);
        DEC_ROUND(Q0, Q1, Q2, Q3,  1);
        DEC_ROUND(Q2, Q3, Q0, Q1,  0);

        // load/byteswap/whiten output/iv
        ((uint32_t*)out)[3] = htole32(Q1 ^ ctx->K[3] ^ ((uint32_t*)ivec)[3]);
        ((uint32_t*)out)[2] = htole32(Q0 ^ ctx->K[2] ^ ((uint32_t*)ivec)[2]);
        ((uint32_t*)out)[1] = htole32(Q3 ^ ctx->K[1] ^ ((uint32_t*)ivec)[1]);
        ((uint32_t*)out)[0] = htole32(Q2 ^ ctx->K[0] ^ ((uint32_t*)ivec)[0]);

        in += TF_BLOCK_SIZE; out+= TF_BLOCK_SIZE;

        memcpy(ivec, old, TF_BLOCK_SIZE);
    }

    return n * TF_BLOCK_SIZE;
}


// by definition twofish can only accept key up to 256 bit
// we wont do any checking here and will assume user already
// know about it. twofish is undefined for key larger than 256 bit
int tf_init (const unsigned char *key, size_t key_size, tf_context_t **ctx) {

    int k;
    uint32_t *S;

    *ctx = calloc(1, sizeof(tf_context_t));
    if(!(*ctx)) {
        return -1;
    }

    (*ctx)->N = key_size;
    keySched(key, key_size, &S, (*ctx)->K, &k);
    fullKey(S, k, (*ctx)->QF);
    free(S); /* allocated in keySched(...) */

    return 0;
}


int tf_deinit (tf_context_t *ctx) {

    if(ctx) free(ctx);

    return 0;
}
