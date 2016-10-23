/* (c) 2009 Richard Andrews <andrews@ntop.org> */
/* Contributions from:
 *     - Jozef Kralik
 */

#include "n2n.h"
#include "n2n_keyfile.h"
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <string.h>


#ifdef WIN32
char *strsep( char **ppsz_string, const char *psz_delimiters )
{
    char *p;
    char *psz_string = *ppsz_string;
    if( !psz_string )
        return NULL;

    p = strpbrk( psz_string, psz_delimiters );
    if( !p )
    {
        *ppsz_string = NULL;
        return psz_string;
    }
    *p++ = '\0';

    *ppsz_string = p;
    return psz_string;
}
#endif


/* Parse hex nibbles in ascii until a non-nibble character is found. Nibble
 * characters are 0-9, a-f and A-F. 
 *
 * Return number of bytes parsed into keyBuf or a negative error code.
 */
ssize_t n2n_parse_hex( uint8_t * keyBuf, 
                       size_t keyLen, 
                       const char * textKey,
                       size_t textLen)
{
    ssize_t retval=0;
    uint8_t * pout=keyBuf;
    size_t octet=0;
    const char * textEnd;
    const char * pbeg;

    textEnd = textKey+textLen;
    pbeg=textKey;

    while ( ( pbeg + 1 < textEnd ) && ( retval < (ssize_t)keyLen ) )
    {
      if ( 1 != sscanf( pbeg, "%02x", (unsigned int*)&octet ) )
        {
            retval=-1;
            break;
        }

        *pout = (octet & 0xff);
        ++pout;
        ++retval;
        pbeg += 2;
    }

    return retval;
}


static int parseKeyLine( n2n_cipherspec_t * spec, 
                         const char * linein )
{
    /* parameters are separated by whitespace */
    char line[N2N_KEYFILE_LINESIZE];
    char * lp=line;
    const char * token;
    strncpy( line, linein, N2N_KEYFILE_LINESIZE );

    memset( spec, 0, sizeof( n2n_cipherspec_t ) );

    /* decode valid_from time */
    token = strsep( &lp, DELIMITERS );
    if ( !token ) { goto error; }
    spec->valid_from = atol(token);

    /* decode valid_until time */
    token = strsep( &lp, DELIMITERS );
    if ( !token ) { goto error; }
    spec->valid_until = atol(token);

    /* decode the transform number */
    token = strsep( &lp, DELIMITERS );
    if ( !token ) { goto error; }
    spec->t = atoi(token);

    /* The reset if opaque key data */
    token = strsep( &lp, DELIMITERS );
    if ( !token ) { goto error; }
    strncpy( (char *)spec->opaque, token, N2N_MAX_KEYSIZE );
    spec->opaque_size=strlen( (char *)spec->opaque);

    return 0;

error:
    return -1;
}


#define SEP "/"


int validCipherSpec( const n2n_cipherspec_t * k,
                     time_t now )
{
    if ( k->valid_until < k->valid_from ) { goto bad; }
    if ( k->valid_from > now ) { goto bad; }
    if ( k->valid_until < now ) { goto bad; }

    return 0;
    
bad:
    return -1;
}

/* Read key control file and return the number of specs stored or a negative
 * error code.
 *
 * As the specs are read in the from and until time values are compared to
 * present time. Only those keys which are valid are stored.
 */
int n2n_read_keyfile( n2n_cipherspec_t * specs,     /* fill out this array of cipherspecs */
                      size_t numspecs,              /* number of slots in the array. */
                      const char * ctrlfile_path )  /* path to control file */
{
    /* Each line contains one cipherspec. */

    int retval=0;
    FILE * fp=NULL;
    size_t idx=0;
    time_t now = time(NULL);

    traceEvent( TRACE_DEBUG, "Reading '%s'\n", ctrlfile_path );

    fp = fopen( ctrlfile_path, "r" );
    if ( fp )
    {
        /* Read the file a line a time with fgets. */
        char line[N2N_KEYFILE_LINESIZE];
        size_t lineNum=0;

        while ( idx < numspecs )
        {
            n2n_cipherspec_t * k = &(specs[idx]);
            fgets( line, N2N_KEYFILE_LINESIZE, fp );
            ++lineNum;

            if ( strlen(line) > 1 )
            {
                if ( 0 == parseKeyLine( k, line ) )
                {
                    if ( k->valid_until > now )
                    {
                        traceEvent( TRACE_INFO, " --> [%u] from %lu, until %lu, transform=%hu, data=%s\n", 
                                    idx, k->valid_from, k->valid_until, k->t, k->opaque );

                        ++retval;
                        ++idx;
                    }
                    else
                    {
                        traceEvent( TRACE_INFO, " --X [%u] from %lu, until %lu, transform=%hu, data=%s\n", 
                                    idx, k->valid_from, k->valid_until, k->t, k->opaque );

                    }
                }
                else
                {
                    traceEvent( TRACE_WARNING, "Failed to decode line %u\n", lineNum );
                }
            }

            if ( feof(fp) )
            {
                break;
            }

            line[0]=0; /* this line has been consumed */
        }

        fclose( fp);
        fp=NULL;
    }
    else
    {
        traceEvent( TRACE_ERROR, "Failed to open '%s'\n", ctrlfile_path );
        retval = -1;
    }

    return retval;
}
