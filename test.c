/**
 * (C) 2007-18 - ntop.org and contributors
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

#include "n2n.h"
#include "n2n_keyfile.h"
#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>

int main(int arc, const char * argv[] )
{
    int e;
    n2n_cipherspec_t specs[N2N_MAX_NUM_CIPHERSPECS];

    e = n2n_read_keyfile( specs, N2N_MAX_NUM_CIPHERSPECS, "keyctrl.conf" );

    if ( e < 0 )
    {
        perror( "Failed to read keyfile" );
    }
    else
    {
        fprintf( stderr, "Stored %d keys.\n", e );
    }

    return 0;
}
