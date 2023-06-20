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


#ifndef TF_H
#define TF_H


#include <stdint.h>  // for uint32_t
#include <stdlib.h>  // for size_t


#define TF_BLOCK_SIZE     16
#define TF_IV_SIZE       (TF_BLOCK_SIZE)


typedef struct tf_context_t {
    int N;
    uint32_t K[40];
    uint32_t QF[4][256];
} tf_context_t;


int tf_ecb_decrypt (unsigned char *out, const unsigned char *in, tf_context_t *ctx);

int tf_ecb_encrypt (unsigned char *out, const unsigned char *in, tf_context_t *ctx);

int tf_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, tf_context_t *ctx);

int tf_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, tf_context_t *ctx);

int tf_init (const unsigned char *key, size_t key_size, tf_context_t **ctx);

int tf_deinit (tf_context_t *ctx);


#endif // TF_H
