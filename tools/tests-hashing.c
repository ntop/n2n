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


#include <inttypes.h>  // for PRIx64, PRIx16, PRIx32
#include <stdint.h>    // for uint8_t, uint16_t, uint32_t, uint64_t
#include <stdio.h>     // for printf, fprintf, stderr, stdout
#include "n2n.h"
#include "hexdump.h"   // for fhexdump
#include "pearson.h"   // for pearson_hash_128, pearson_hash_16, pearson_has...


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

void test_pearson_16 (void *buf, unsigned int bufsize) {
    char *test_name = "pearson_hash_16";

    uint16_t hash = pearson_hash_16(buf, bufsize);

    printf("%s: output = 0x%" PRIx16 "\n", test_name, hash);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_pearson_32 (void *buf, unsigned int bufsize) {
    char *test_name = "pearson_hash_32";

    uint32_t hash = pearson_hash_32(buf, bufsize);

    printf("%s: output = 0x%" PRIx32 "\n", test_name, hash);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_pearson_64 (void *buf, unsigned int bufsize) {
    char *test_name = "pearson_hash_64";

    uint64_t hash = pearson_hash_64(buf, bufsize);

    printf("%s: output = 0x%" PRIx64 "\n", test_name, hash);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_pearson_128 (void *buf, unsigned int bufsize) {
    char *test_name = "pearson_hash_128";

    uint8_t hash[16];
    pearson_hash_128(hash, buf, bufsize);

    printf("%s: output:\n", test_name);
    fhexdump(0, hash, sizeof(hash), stdout);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_pearson_256 (void *buf, unsigned int bufsize) {
    char *test_name = "pearson_hash_256";

    uint8_t hash[32];
    pearson_hash_256(hash, buf, bufsize);

    printf("%s: output:\n", test_name);
    fhexdump(0, hash, sizeof(hash), stdout);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

int main (int argc, char * argv[]) {
    pearson_hash_init();

    char *test_name = "environment";
    printf("%s: input size = 0x%" PRIx64 "\n", test_name, sizeof(PKT_CONTENT));
    fhexdump(0, PKT_CONTENT, sizeof(PKT_CONTENT), stdout);
    printf("\n");

    test_pearson_256(PKT_CONTENT, sizeof(PKT_CONTENT));
    test_pearson_128(PKT_CONTENT, sizeof(PKT_CONTENT));
    test_pearson_64(PKT_CONTENT, sizeof(PKT_CONTENT));
    test_pearson_32(PKT_CONTENT, sizeof(PKT_CONTENT));
    test_pearson_16(PKT_CONTENT, sizeof(PKT_CONTENT));

    return 0;
}

