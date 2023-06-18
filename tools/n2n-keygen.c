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


#include <stdint.h>  // for uint8_t
#include <stdio.h>   // for fprintf, stdout, stderr
#include <string.h>  // for memset, strcmp
#include "auth.h"    // for bin_to_ascii, bind_private_key_to_username, gene...
#include "n2n.h"     // for n2n_private_public_key_t, N2N_USER_KEY_LINE_STARTER


int main(int argc, char * argv[]) {

    n2n_private_public_key_t prv;  /* 32 bytes private key                        */
    n2n_private_public_key_t bin;  /* 32 bytes public key binary output buffer    */
    char asc[44];               /* 43 bytes + 0-terminator ascii string output */
    uint8_t fed = 0;

    // exactly two parameters required
    if(argc != 3) {
        // error message to stderr to not interfere with batch usage
        fprintf(stderr, "\n"
                        "n2n-keygen tool\n\n"
                        "  usage:  n2n-keygen <username> <password>\n\n"
                        "     or   n2n-keygen -F <federation name>\n\n"
                        "          outputs a line to insert at supernode's community file for user-and-\n"
                        "          password authentication or a command line parameter with the public\n"
                        "          federation key for use at edge's command line, please refer to the\n"
                        "          doc/Authentication.md document or the man pages for more details\n\n");
        return 1;
    }

    // federation mode?
    if(strcmp(argv[1], "-F") == 0)
        fed = 1;

    // derive private key from username and password:
    // hash username once, hash password twice (so password is bound
    // to username but username and password are not interchangeable),
    // finally xor the result
    // in federation mode: only hash federation name, twice
    generate_private_key(prv, argv[2]);

    // hash user name only if required
    if(!fed) {
        bind_private_key_to_username(prv, argv[1]);
    }

    // calculate the public key into binary output buffer
    generate_public_key(bin, prv);

    // clear out the private key
    memset(prv, 0, sizeof(prv));

    // convert binary output to 6-bit-ascii string output
    bin_to_ascii(asc, bin, sizeof(bin));

    // output
    if(fed)
        fprintf(stdout, "-P %s\n", asc);
    else
        fprintf(stdout, "%c %s %s\n", N2N_USER_KEY_LINE_STARTER, argv[1], asc);

    return 0;
}
