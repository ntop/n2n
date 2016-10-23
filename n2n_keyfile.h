/* (c) 2009 Richard Andrews <andrews@ntop.org> */

/** Key files
 *
 *  Edge implements a very simple interface for getting instructions about
 *  rolling keys. 
 *
 *  Key definitions are written as individual files in <transform>/<sa>.key. The
 *  format of each key is a single line of hex nibbles as follows:
 *
 *  0102030405060708090a0b0c0d0e0f
 *
 *  Any external key exchange mechanism can receive the key data write it into
 *  the keyfiles.
 *
 *  To control which keys are active at what times the key control file is
 *  used. This is a single file which is periodically reread. It contains key
 *  definitions in chronological order with one line per key definition as
 *  follows:
 *
 *  <valid_from> <valid_until> <transform> <opaque>
 *
 *  edge reads the key control file periodically to get updates in policy. edge
 *  holds a number of keys in memory. Data can be decoded if it was encoded by
 *  any of the keys still in memory. By having at least 2 keys in memory it
 *  allows for clock skew and transmission delay when encoder and decoder roll
 *  keys at slightly different times. The amount of overlap in the valid time
 *  ranges provides the tolerance to timing skews in the system.
 *
 *  The keys have the same level of secrecy as any other user file. Existing
 *  UNIX permission systems can be used to provide access controls.
 *
 */

/** How Edge Uses The Key Schedule
 *
 *  Edge provides state space for a number of transform algorithms. Each
 *  transform uses its state space to store the SA information for its keys as
 *  found in the key file. When a packet is received the transform ID is in
 *  plain text. The packets is then sent to that transform for decoding. Each
 *  transform can store its SA numbers differently (or not at all). The
 *  transform code then finds the SA number, then finds the cipher (with key) in
 *  the state space and uses this to decode the packet.
 *
 *  To support this, as edge reads each key line, it passes it to the
 *  appropriate transform to parse the line and store the SA information in its
 *  state space.
 *
 *  When encoding a packet, edge has several transforms and potentially valid
 *  SAs to choose from. To keep track of which one to use for encoding edge does
 *  its own book-keeping as each key line is passed to the transform code: it
 *  stores a lookup of valid_from -> transform. When encoding a packet it then
 *  just calls the transform with the best valid_from in the table. The
 *  transform's own state space has all the SAs for its keys and the best of
 *  those is chosen.
 */

#if !defined( N2N_KEYFILE_H_ )
#define N2N_KEYFILE_H_


#include "n2n_wire.h"
#include <time.h>

#define N2N_MAX_KEYSIZE         256             /* bytes */
#define N2N_MAX_NUM_CIPHERSPECS 8
#define N2N_KEYPATH_SIZE        256
#define N2N_KEYFILE_LINESIZE    256

/** This structure stores an encryption cipher spec. */
struct n2n_cipherspec
{
    n2n_transform_t     t;                      /* N2N_TRANSFORM_ID_xxx for this spec. */
    time_t              valid_from;             /* Start using the key at this time. */
    time_t              valid_until;            /* Key is valid if time < valid_until. */
    uint16_t            opaque_size;            /* Size in bytes of key. */
    uint8_t             opaque[N2N_MAX_KEYSIZE];/* Key matter. */
};

typedef struct n2n_cipherspec n2n_cipherspec_t;


static const char * const DELIMITERS=" \t\n\r";


/** @return number of cipherspec items filled. */
int     n2n_read_keyfile( n2n_cipherspec_t * specs,     /* fill out this array of cipherspecs */
                          size_t numspecs,              /* number of slots in the array. */
                          const char * ctrlfile_path ); /* path to control file */

int     validCipherSpec( const n2n_cipherspec_t * k,
                         time_t now );

ssize_t  n2n_parse_hex( uint8_t * keyBuf, 
                        size_t keyMax, 
                        const char * textKey,
                        size_t textLen );

/*----------------------------------------------------------------------------*/

#endif /* #if !defined( N2N_KEYFILE_H_ ) */
