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
