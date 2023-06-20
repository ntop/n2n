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


#include <assert.h>    // for assert
#include <inttypes.h>  // for PRIx64
#include <stdint.h>    // for uint8_t
#include <stdio.h>     // for printf, fprintf, stderr, stdout, NULL
#include <stdlib.h>    // for exit
#include <string.h>    // for memcmp
#include "hexdump.h"   // for fhexdump
#include "minilzo.h"   // for lzo1x_1_compress, lzo1x_decompress, LZO1X_1_ME...
#include "n2n.h"       // for N2N_PKT_BUF_SIZE, TRACE_ERROR, traceEvent


/* heap allocation for compression as per lzo example doc */
#define HEAP_ALLOC(var,size) lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]
static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);


uint8_t PKT_CONTENT[]={
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};

static void init_compression_for_benchmark (void) {

    if(lzo_init() != LZO_E_OK) {
        traceEvent(TRACE_ERROR, "LZO compression init error");
        exit(1);
    }

#ifdef N2N_HAVE_ZSTD
    // zstd does not require initialization. if it were required, this would be a good place
#endif
}


static void deinit_compression_for_benchmark (void) {

    // lzo1x does not require de-initialization. if it were required, this would be a good place

#ifdef N2N_HAVE_ZSTD
    // zstd does not require de-initialization. if it were required, this would be a good place
#endif
}

void test_lzo1x () {
    char *test_name = "lzo1x";
    uint8_t compression_buffer[N2N_PKT_BUF_SIZE]; // size allows enough of a reserve required for compression
    lzo_uint compression_len = sizeof(compression_buffer);

    if(lzo1x_1_compress(PKT_CONTENT, sizeof(PKT_CONTENT), compression_buffer, &compression_len, wrkmem) != LZO_E_OK) {
        fprintf(stderr, "%s: compression error\n", test_name);
        exit(1);
    }

    assert(compression_len == 47);

    printf("%s: output size = 0x%" PRIx64 "\n", test_name, compression_len);
    fhexdump(0, compression_buffer, compression_len, stdout);

    uint8_t deflation_buffer[N2N_PKT_BUF_SIZE];
    lzo_uint deflated_len;
    lzo1x_decompress(compression_buffer, compression_len, deflation_buffer, &deflated_len, NULL);

    assert(deflated_len == sizeof(PKT_CONTENT));
    if(memcmp(PKT_CONTENT, deflation_buffer, deflated_len)!=0) {
        fprintf(stderr, "%s: round-trip buffer mismatch\n", test_name);
        exit(1);
    }

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_zstd () {
    char *test_name = "zstd";

#ifdef N2N_HAVE_ZSTD
    uint8_t compression_buffer[N2N_PKT_BUF_SIZE]; // size allows enough of a reserve required for compression
    lzo_uint compression_len = sizeof(compression_buffer);

    compression_len = N2N_PKT_BUF_SIZE;
    compression_len = ZSTD_compress(compression_buffer, compression_len, PKT_CONTENT, sizeof(PKT_CONTENT), ZSTD_COMPRESSION_LEVEL);
    if(ZSTD_isError(compression_len)) {
        fprintf(stderr, "%s: compression error\n", test_name);
        exit(1);
    }

    assert(compression_len == 33);

    printf("%s: output size = 0x%" PRIx64 "\n", test_name, compression_len);
    fhexdump(0, compression_buffer, compression_len, stdout);

    uint8_t deflation_buffer[N2N_PKT_BUF_SIZE];
    int64_t deflated_len = sizeof(deflation_buffer);
    deflated_len = (int32_t)ZSTD_decompress(deflation_buffer, deflated_len, compression_buffer, compression_len);
    if(ZSTD_isError(deflated_len)) {
        fprintf(stderr, "%s: decompression error '%s'\n",
                test_name, ZSTD_getErrorName(deflated_len));
        exit(1);
    }

    assert(deflated_len == sizeof(PKT_CONTENT));
    if(memcmp(PKT_CONTENT, deflation_buffer, deflated_len)!=0) {
        fprintf(stderr, "%s: round-trip buffer mismatch\n", test_name);
        exit(1);
    }

    fprintf(stderr, "%s: tested\n", test_name);
#else
    // FIXME - output dummy data to the stdout for easy comparison
    printf("zstd: output size = 0x21\n");
    printf("000: 28 b5 2f fd 60 00 01 bd  00 00 80 00 01 02 03 04   |( / `           |\n");
    printf("010: 05 06 07 08 09 0a 0b 0c  0d 0e 0f 01 00 da 47 9d   |              G |\n");
    printf("020: 4b                                                 |K|\n");

    fprintf(stderr, "%s: not compiled - dummy data output\n", test_name);
#endif
    printf("\n");
}


int main (int argc, char * argv[]) {

    /* Also for compression (init moved here for ciphers get run before in case of lzo init error) */
    init_compression_for_benchmark();

    printf("%s: input size = 0x%" PRIx64 "\n", "original", sizeof(PKT_CONTENT));
    fhexdump(0, PKT_CONTENT, sizeof(PKT_CONTENT), stdout);
    printf("\n");

    test_lzo1x();
    test_zstd();

    deinit_compression_for_benchmark();

    return 0;
}

