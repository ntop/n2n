# Cryptography in n2n

## Payload

### Overview

Payload encryption currently comes in four different flavors using ciphers of different origins. Supported ciphers are enabled using the indicated command line option:

- Twofish in CTS mode (`-A2`)
- AES in CBC mode (`-A3`)
- ChaCha20 (CTR) (`-A4`)
- SPECK in CTR mode (`-A5`)

To renounce encryption, `-A1` enables the so called `null_transform` transmitting all payload data unencryptedly.

The following chart might help to make a quick comparison and decide what cipher to use:

| Cipher | Mode | Block Size | Key Size         | IV length |Speed | Built-In | Origin |
| :---:  | :---:| :---:      | :---:            | :---:     |:---: | :---:    | ---    |
|Twofish | CTS  | 128 bits   | 256 bit          | 128 bit   | -..O | Y        | Bruce Schneier |
|AES     | CTS  | 128 bits   | 128, 192, 256 bit| 128 bit   | O..+ | N        | Joan Daemen, Vincent Rijmen, NSA-approved |
|ChaCha20| CTR  | Stream     | 256 bit          | 128 bit   | +..++| N        | Daniel J. Bernstein |
|SPECK   | CTR  | Stream     | 256 bit          | 128 bit   | ++   | Y        | NSA |

The two block ciphers Twofish and AES are used in CTS mode.

n2n has all four ciphers built-in as basic versions. Some of them optionally compile to faster versions by the means of available hardware support (AES-NI, SSE, AVX – please see the [Building document](./Building.md) for details. Depending on your platform, AES and ChaCha20 might also draw notable acceleration from optionally compiling with openSSL 1.1 support.

### Twofish

This implementation prepends a 128 bit random value to the plain text. Its size is adjustable by changing the `TF_PREAMBLE_SIZE` definition found in `src/transform_tf.c`. It defaults to TF_BLOCK_SIZE (== 16). As CTS uses underlying CBC mode, this basically has the same effect as a respectively shorter IV. However, this flexibility does not come for free as an additional block needs to be encrypted.

Twofish requires no padding as it employs a CBC/CTS scheme which can send out plaintext-length ciphertexts. The scheme however has a small flaw in handling messages shorter than one block, only low-level programmer might encounter this.

On Intel CPUs, Twofish usually is the slowest of the ciphers present. However, on Raspberry Pi 3B+, Twofish was observed to be faster than AES-CTS. Your mileage may vary. Cipher speed's can be compared running the `tools/n2n-benchmark` tool.

### AES

AES also prepends a random value to the plaintext. Its size is adjustable by changing the `AES_PREAMBLE_SIZE` definition found in `src/transform_aes.c`. It defaults to AES_BLOCK_SIZE (== 16). The AES scheme uses a CBC/CTS scheme which can send out plaintext-length ciphertexts as long as they are one block or more in length.

Apart from n2n's plain C implementation, Intel's AES-NI is supported – again, please have a look at the [Building document](./Building.md). In case of openSSL support its `evp_*` interface gets used which also offers hardware acceleration where available (SSE, AES-NI, …). It however is slower than the following stream ciphers because the CBC mode cannot compete with the optimized stream ciphers.

### ChaCha20

ChaCha20 was the first stream cipher supported by n2n.

In addition to the basic C implementation, an SSE version is offered. If compiled with openSSL support, ChaCha20 is provided via the `evp_*` interface. It is not used together with the Poly1305 message tag from the same author though. Whole packet's checksum will be handled in the header (see below).

The random full 128-bit IV is transmitted in plain.

ChaCha20 usually performs faster than AES-CTS.

### SPECK

SPECK is recommended by the NSA for offical use in case AES implementation is not feasible due to system constraints (performance, size, …). The block cipher is used in CTR mode making it a stream cipher. The random full 128-bit IV is transmitted in plain.

On modern Intel CPUs, SPECK performs even faster than openSSL's ChaCha20 as it takes advantage of SSE4 or AVX2 if available. On Raspberry's ARM CPU, it is second place behind ChaCha20 and before Twofish.

### Random Numbers

Throughout n2n, pseudo-random numbers are generated for several purposes, e.g. random MAC assignment and the IVs for use with the various ciphers. Regarding IVs, especially for using in the stream ciphers, the pseudo-random numbers shall be as collision-free as possible. n2n uses an implementation of XORSHIFT128+ which shows a periodicity of 2¹²⁸.

Its initialization relies on seeding with a value as random as possible. Various sources are tapped including a syscall to Linux' `SYS_getrandom` as well as Intels hardware random number generators `RDRND` and `RDSEED`, if available (compile using `-march=native`).

### Pearson Hashing

For general purpose hashing, n2n employs Pearson hashing as it offers variable hash sizes and is said not to be too "collidy". However, this is not a cryptographically secure hashing function which by the way is not required here: The hashing is never applied in a way that the hash shall prove the knowledge of a secret without showing the secret.

_Pearson hashing is tweakable by making your own permutation of the 256 byte table._ Here, the AES' s-box is used: Given appropriate hardware, a lookup could even be accelerated.

_Pearson hashing allows verification of parts of the hash only – just in case performance requirements would urge to do so._

## Header

### Overview

Packet's header consist of a COMMON section followed by a packet-type specific section, e.g. REGISTER, REGISTER_ACK, PACKET including the payload, REGISTER_SUPER, …

The COMMON section is built as follows:

```
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Version=3     ! TTL           ! Flags                         !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 ! Community                                                     :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 ! ... Community                                                 !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

In case of a PACKET-type, it is succeeded by the fields depicted below:

```
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 ! Source MAC Address                                            :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 :                               ! Destination MAC Address       :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
28 :                                                               !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
32 ! Socket Flags (v=IPv4)         ! Destination UDP Port          !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
36 ! Destination IPv4 Address                                      !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
40 ! Compress'n ID !  Transform ID ! Payload ...                   !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
44 !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
```
### Encryption

If enabled (`-H`), all fields but the payload (which is handled seperately as outlined above) get encrypted using SPECK in CTR mode. As packet headers need to be decryptable by the supernode and we do not want to add another key (to keep it a simple interface), the community name serves as key (keep it secret!) because it is already known to the supernode. The community name consists of up to 16 characters (well, 15 + `0x00`), so key size of 128 bit is a reasonable choice here.

The scheme applied tries to maintain compatibility with current packet format and works as follows:

- First line of 4 bytes (Version, TTL, Flags) goes to fifth line:  
```
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Community ...                                                 :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 ! ... Community                                                 !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 ! Version=3     ! TTL           ! Flags                         !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- To be able to identify a correctly decrpyted header later on, a magic number is stamped in fourth line starting at byte number 12. We use "n2n" string and add the header length to be able to stop header decryption right before an eventually following payload begins – in case of PACKET-type, header-length does not equal packet-length.

- The rest of the community field, namely the first 12 bytes, is reframed towards a 96-bit IV for the header encryption.  
```
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! IV ...                                                        :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 ! ... IV ...                                                    :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 ! ... IV                                                        :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 ! 24-bit Magic Number, "n2n" = 0x6E326E         ! Header Length !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 ! Version=3     ! TTL           ! Flags                         !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- As we use a stream cipher, the IV should be a nonce. The IV plays an additional role sketched later, see the following sections on checksum and replay protection. For use in header encryption and decryption, four bytes reading ASCII "n2n!" are appended to the 96-bit IV hereby internally making it a full 128-bit IV.

- To make a less predictable use of the key space – just think of the typically reset MSB of ASCII characters of community names – we actually use a hash of the community name as key.

- Encryption starts at byte number 12 and ends at header's end. It does not comprise the payload which eventually has its own encryption scheme as chosen with the `-A_` options.

Decryption checks all known communities (several in case of supernode, only one at edge) as keys. On success, the emerging magic number will reveal the correct community whose name will be copied back to the original fields allowing for regular packet handling. 

Thus, header encryption will only work with previously determined community names introduced to the supernode by `-c <path>` parameter. Also, it should be clear that header encryption is a per-community decision, i.e. all nodes and the supernode need to have it enabled. However, the supernode supports encrpyted and unencrypted communities in parallel, it determines their status online at arrival of the first packet. Use a fresh community name for encrypted communities; do not use a previously used one of former unecrpyted communities: their names were transmitted openly.

### Checksum

The whole packet including the eventually present payload is checksummed using a modified Person hashing. It might seem a little short compared to usual message tags of 96 up to 128 bit, especially when using a stream cipher which easily allows for bit-flips. So, the 16-bit checksum is filled up with 80 more bits to obtain a 96-bit pre-IV. This pre-IV gets encrypted using a single block-cipher step to get the pseudo-random looking IV. This way, the checksum resists targeted bit-flips (to header, payload, and IV) as any change to the whole 96-bit IV would render the header un-decryptable. Also, as explained below, the checksum comes along with a time stamp minimizing opportunities for random attacks.

The single block-cipher step employs SPECK because it is fast and it offers a 96-bit version. The key is derived from the header key – a hash of the hash.

The checksum gets verified by the edges and the supernode.

### Replay Protection

The aforementioned fill-up does not completely rely on random bits. A 52-bit time stamp displaying a microsecond-accuracy is encoded to the 96-bit pre-IV as well:

```
    012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345
   +------------------------------------------------------------------------------------------------+
   !     52-bit time stamp with microsecond-accuracy    ! 28 pseudo-random bits     !16-bit checksum!
   +------------------------------------------------------------------------------------------------+

```
Encrypting this pre-IV with a block cipher step will generate a pseudo-random looking IV which gets written to the packet and used for the header encryption.

Due to the time-stamp encoded, the IV will more likely be unique, close to a real nonce.

Upon receival, the time stamp as well as the checksum can be extracted from the IV by performing a 96-bit block-cipher decryption step. Verification of the time stamp happens in two steps:

- The (remote) time stamp is checked against the local clock. It may not deviate more than plus/minus 16 seconds. So, edges and supernode need to keep a somewhat current time. This limit can be adjusted by changing the `TIME_STAMP_FRAME` definition. It is time-zone indifferent as UTC is used.

- Valid (remote) time stamps get stored as "last valid time stamp" seen from each node (supernode and edges). So, a newly arriving packet's time stamp can be compared to the last valid one. It should be equal or higher. However, as UDP packets may overtake each other just by taking another path through the internet, they are allowed to be 160 millisecond earlier than the last valid one. This limit can be adjusted by changing the `TIME_STAMP_JITTER` definition.

The way the IV is used for replay protection and for checksumming makes enabled header encryption a prerequisite for these features.
