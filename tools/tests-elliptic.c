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


#include <stdio.h>       // for printf, fprintf, stdout, stderr
#include <string.h>      // for memset
#include "curve25519.h"  // for curve25519
#include "hexdump.h"     // for fhexdump


void test_curve25519 (unsigned char *pkt_input, unsigned char *key) {
    char *test_name = "curve25519";
    unsigned char pkt_output[32];

    curve25519(pkt_output, key, pkt_input);

    printf("%s: output\n", test_name);
    fhexdump(0, pkt_output, sizeof(pkt_output), stdout);

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

int main (int argc, char * argv[]) {
    char *test_name = "environment";

    unsigned char key[32];
    unsigned char pkt_input[32];

    memset(pkt_input, 0, 31);
    pkt_input[31] = 9;

    memset(key, 0x55, 32);

    printf("%s: input\n", test_name);
    fhexdump(0, pkt_input, sizeof(pkt_input), stdout);
    printf("%s: key\n", test_name);
    fhexdump(0, key, sizeof(key), stdout);
    printf("\n");

    test_curve25519(pkt_input, key);

    return 0;
}

