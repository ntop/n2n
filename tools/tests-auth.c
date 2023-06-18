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


#include <stdint.h>   // for uint8_t
#include <stdio.h>    // for printf, fprintf, stdout, stderr
#include <string.h>   // for memset
#include "auth.h"     // for ascii_to_bin, bin_to_ascii, generate_private_key
#include "hexdump.h"  // for fhexdump
#include "n2n.h"      // for n2n_private_public_key_t


uint8_t PKT_CONTENT1[]={
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
};

char *PKT_CONTENT2 = "00420mG51WS82GeB30qE3m";

void test_bin_to_ascii (void *buf, unsigned int bufsize) {
    char *test_name = "bin_to_ascii";
    char out[32];

    printf("%s: input size = 0x%x\n", test_name, bufsize);
    fhexdump(0, buf, bufsize, stdout);

    bin_to_ascii(out, buf, bufsize);

    printf("%s: output: %s\n", test_name, out);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_ascii_to_bin (char *buf) {
    char *test_name = "ascii_to_bin";
    uint8_t out[32];
    memset(out, 0, sizeof(out));

    printf("%s: input = %s\n", test_name, buf);

    ascii_to_bin(out, buf);
    // TODO:
    // - it would be nice if the function returned the bufsize,
    // - or took an allocation size as input

    printf("%s: output:\n", test_name);
    fhexdump(0, out, sizeof(out), stdout);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_generate_private_key (char *in, n2n_private_public_key_t prv) {
    char *test_name = "generate_private_key";

    printf("%s: input = %s\n", test_name, in);

    generate_private_key(prv, in);

    printf("%s: output:\n", test_name);
    fhexdump(0, prv, sizeof(n2n_private_public_key_t), stdout);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_generate_public_key (n2n_private_public_key_t prv, n2n_private_public_key_t pub) {
    char *test_name = "generate_public_key";

    printf("%s: input:\n", test_name);
    fhexdump(0, prv, sizeof(n2n_private_public_key_t), stdout);

    generate_public_key(pub, prv);

    printf("%s: output:\n", test_name);
    fhexdump(0, pub, sizeof(n2n_private_public_key_t), stdout);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_generate_shared_secret (n2n_private_public_key_t prv, n2n_private_public_key_t pub) {
    char *test_name = "generate_shared_secret";
    n2n_private_public_key_t out;

    printf("%s: input: prv\n", test_name);
    fhexdump(0, prv, sizeof(n2n_private_public_key_t), stdout);
    printf("%s: input: pub\n", test_name);
    fhexdump(0, pub, sizeof(n2n_private_public_key_t), stdout);

    generate_shared_secret(out, prv, pub);

    printf("%s: output:\n", test_name);
    fhexdump(0, out, sizeof(out), stdout);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

int main (int argc, char * argv[]) {

    test_bin_to_ascii(PKT_CONTENT1, sizeof(PKT_CONTENT1));
    test_ascii_to_bin(PKT_CONTENT2);

    n2n_private_public_key_t prv;
    memset(prv, 0, sizeof(prv));
    n2n_private_public_key_t pub;
    memset(pub, 0, sizeof(pub));

    test_generate_private_key(PKT_CONTENT2, prv);
    test_generate_public_key(prv, pub);
    test_generate_shared_secret(prv, pub);

    return 0;
}

