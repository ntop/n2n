/*
 * (C) 2007-21 - ntop.org and contributors
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


#include "n2n.h"


int main(int argc, char * argv[]) {

    uint8_t tmp[32];  /* 32 bytes buffer                             */
    uint8_t prv[32];  /* 32 bytes private key                        */
    uint8_t gen[32];  /* generator point '9' on curve                */
    uint8_t bin[32];  /* 32 bytes public key binary output buffer    */
    uint8_t asc[44];  /* 43 bytes + 0-terminator ascii string output */
    size_t i = 0;

    // exactly two parameters required
    if(argc != 3) {
        // error message to stderr to not interfere with batch usage
        fprintf(stderr, "\n"
                        "n2n-keygen tool\n\n"
                        "  usage:  n2n-keygen <username> <password>\n\n"
                        "          outputs a line to insert at supernode's community file for user-and-\n"
                        "          password authentication, please see doc/Authentication.md or the man\n"
                        "          pages for details\n\n");
        return 1;
    }

    // generator point '9' on curve
    memset(gen, 0, sizeof(gen)-1);
    gen[sizeof(gen)-1] = 9;

    // derive private key from username and password:
    // hash user name once, hash password twice (so password is bound
    // to username but username and password are not interchangeable),
    // finally xor the result
    pearson_hash_256(tmp, (uint8_t*)argv[1], strlen(argv[1]));
    pearson_hash_256(prv, (uint8_t*)argv[2], strlen(argv[2]));
    pearson_hash_256(prv, prv, sizeof(prv));
    for(i = 0; i < sizeof(prv); i++)
        prv[i] ^= tmp[i];

    // calculate the public key into binary output buffer
    curve25519(bin, prv, gen);

    // clear out the private key
    memset(prv, 0, sizeof(prv));

    // convert binary output to 6-bit-ascii string output
    bin_to_ascii(asc, bin, sizeof(bin));

    // output
    fprintf(stdout, "* %s %s\n", argv[1], asc);

    return 0;
}
