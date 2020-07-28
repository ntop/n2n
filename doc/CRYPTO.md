# Cryptography in n2n

## Payload

### Overview

Payload encryption currently comes in four different flavors from a variety of origins and all with their own specialities. Supported ciphers are enabled using the indicated command line option:

- Twofish in CBC mode (`-A2`)
- AES in CBC mode (`-A3`)
- ChaCha20 (CTR) (`-A4`)
- SPECK in CTR mode (`-A5`)

To renounce encryption, `-A1` enables the so called `null_transform` transmitting all payload data unencryptedly.

The following chart might help with a quick comparison and to make a decision on what cipher to use:

| Cipher | Mode | Block Size | Key Size         | IV length |Speed | Built-In | Origin |
| :---:  | :---:| :---:      | :---:            | :---:     |:---: | :---:    | ---    |
|Twofish | CBC  | 128 bits   | 128 bit (?)      | 32 bit    | -    | Y        | Bruce Schneier |
|AES     | CBC  | 128 bits   | 128, 192,256 bit | 64 bit    | O..+ | N        | Joan Daemen, Vincent Rijmen, NSA-approved |
|ChaCha20| CTR  | Stream     | 256 bit          | 128 bit   | +..++| N        | Daniel J. Bernstein |
|SPECK   | CTR  | Stream     | 256 bit          | 128 bit   | ++   | Y        | NSA |

As the two block ciphers Twofish and AES are used in CBC mode, they require a padding which results in encrypted payload sizes modulo the respective blocksize. Sizewise, this could be considered a disadvantage. On the other hand, stream ciphers need a longer initialization vector (IV) to be transmitted with the cipher.

Note that AES and ChaCha20 are available only if n2n is compiled with openSSL support. n2n will work well without them offering the respectively reduced choice of remaining built-in ciphers (Twofish, SPECK).

### Twofish

This implementation prepends a 32 bit random value to the plain text. In the `src/transform_tf.c` file, it is called `nonce`. In CBC mode, this basically has the same effect as a respectively shorter IV.

Padding to the last block happens by filling `0x00`-bytes and indicating their number as the last byte of the block. This could lead to up to 16 extra bytes.

Other than that, it is plain Twofish in CBC mode.

Twofish is the slowest of the ciphers present.

_We might try to find a faster implementation._

### AES

AES uses the standard way of an IV, but it does not neccessarily transmit the full IV along with the packets. The size of the transmitted part is adjustable by changing the `TRANSOP_AES_IV_SEED_SIZE` definition found in `src/transform_aes.c`. It defaults to 8 meaning that 8 bytes (of max 16) are transmitted. The remaining 8 bytes are fixed, key-derived material is used to fill up to full block size. For various reasons, a single AES-ECB encryption step is applied to these 16 bytes before they get used as regular IV for AES-CBCing the payload.

The padding scheme is the same as used with Twofish.

AES relies on openSSL's `evp_*` interface which also offers hardware acceleration where available (SSE, AES-NI, …). It however is slower than the following stream ciphers because the CBC mode cannot compete to the optimized stream ciphers; maybe AES-CTR being a stream cipher could.

_Current ideas are to bring CTS mode to AES in some future version, just to avoid unneccessary weight gains from padding. CTS mode works well starting with plain texts from one block plus. So, we might revert back to the Twofish-way of IV handling with a full block IV._

### ChaCha20

ChaCha20 was the first stream cipher supported by n2n.

It also relies on openSSL's `evp_*` interface. It does not use the Poly1305 message tag from the same author, though. Whole packet's checksum will be handled in the header, see below.

The random full 128-bit IV is transmitted in plain.

ChaCha20 usually performs faster than AES-CBC.

### SPECK

SPECK is recommended by the NSA for offical use in case AES implementation is not feasible due to system constraints (performance, size, …). The block cipher is used in CTR mode making it a stream cipher. The random full 128-bit IV is transmitted in plain.

On Intel CPUs, SPECK performs even faster than openSSL's ChaCha20 as it takes advantage of SSE4 or AVX2 if available (compile using `-march=native`). On Raspberry's ARM CPU, it is second place behind ChaCha20 and before AES-CBC.

_Also, multi-threading might accelerate this cipher on all CPUs with more than one core._

### Random Numbers

Throughout n2n, pseudo-random numbers are generated for several purposes, e.g. random MAC assignment and the IVs for use with the various ciphers. With a view to the IVs, especially for use in the stream ciphers, the pseudo-random numbers shall be as collision-free as possible. n2n uses an implementation of XORSHIFT128+ which shows a periodicity of 2¹²⁸.

Its initialization relies on seeding with a value as random as possible. Various sources are tapped including a syscall to Linux' `SYS_getrandom` as well as Intels hardware random number generators `RDRND` and `RDSEED`, if available (compile using `-march=native`).

### Pearson Hashing

For general purpose hashing, n2n employs Pearson hashing as it offers variable hash sizes and is said to not be too collidy. However, this is not a cryptographically secure hashing function which by the way is not required here: The hashing is never applied in a way that the hash shall proove the knowledge of a secret without showing the secret.

_Pearson hashing is tweakable by making your own permutation of the 256 byte table._

_Pearson hashing allows for verifying only parts of the hash – just in case performance requirements would urge to do so._

## Header

### Overview

Packet's header consist of a COMMON section followed by a packet-type specific section, e.g. REGISTER, REGISTER_ACK, PACKET including the payload, REGISTER_SUPER, …

The COMMON section is built as follows:

```
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Version=2     ! TTL           ! Flags                         !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 ! Community                                                     :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 ! ... Community ...                                             !
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
40 ! Transform ID                  ! Payload ...                   !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
44 !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
```
### Encryption

If enabled (`-H`), all fields but the payload (which is handled seperately as outlined above) get encrypted using SPECK in CTR mode. As packet headers need to be decryptable by the supernode and we do not want to add another key (to keep it a simple interface), the community name serves as key (keep it secret!) because it is already known to the supernode.

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
16 ! Version=2     ! TTL           ! Flags                         !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- To later be able to identify a correctly decrpyted header, a magic number is stamped in fourth line starting at byte number 12. We use "n2n" string and add the header length to later be able to stop header decryption right before an eventually following payload begins – in case of PACKET-type, header-length does not equal packet-length.

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
16 ! Version=2     ! TTL           ! Flags                         !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- As we use a stream cipher, the IV should be a nonce. The IV plays an additional role sketched later, see the following sections on checksum and replay protection. For use in header encryption and decryption, four bytes reading ASCII "n2n!" are appended to the 96-bit IV to internally make it a full 128-bit IV for use with 128-bit block size SPECK in CTR mode.

- To make a less predictable use of the key space – just think of usually reset MSB of ASCII characters of community names – we actually use a hash of the community name as key.

- Encryption starts at byte number 12 and ends at header's end. It does not comprise the payload which eventually has its own encryption scheme as chosen with the `-A_` options.

Decryption checks all known communities (several in case of supernode, only one at edge) as keys. On success, the emerging magic number will reveal the correct community whose name will be copied back to the original fiels allowing for regular packet handling. 

Thus, header encryption will only work with previously determined community names introduced to the supernode by `-c <path>` parameter. Also it should be clear that header encryption is a per-community decision, i.e. all nodes and the supernode need to have it enabled. However, the supernode supports encrpyted and unencrypted communities in parallel, it determines their status online at arrival of the first packet. Use a fresh community name for encrypted communities, do not use a previously used one of former unecrpyted communities, their names were transmitted openly.

### Checksum

The whole packet including the eventually present payload is checksummed using a modified Person hashing. It might seem a little short compared to usual message tags of 96 up to 128 bit, especially when using a stream cipher which easily allows for bit-flips. So, the 16-bit checksum is filled up with 80 more bits to obtain a 96-bit pre-IV. This pre-IV gets encrypted using a single block-cipher step to get the pseudo-random looking IV. This way, the checksum resists targeted bit-flips (to header, payload, and IV) as any change to the whole 96-bit IV would render the header un-decryptable.

The single block-cipher step employs SPECK because it is fast, always present as built-in and it offers a 96-bit version. The key is derived from the header key – a hash of the hash.

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

Due to the time-stamp encoded, the IV will more likely be unique, e.g. almost assuredly be unique, a real nonce.

Upon receival, the time stamp as well as the checksum can be extracted from the IV by performing a 96-bit block-cipher decryption step. Verification of the time stamp happens in two steps:

- The (remote) time stamp is checked against the local clock. It may not deviate more than plus/minus 16 seconds. So, edges and supernode need to keep a somewhat current time. This limit can be adjusted by changing the `TIME_STAMP_FRAME` definition. It is time-zone indifferent as UTC is used.

- Valid (remote) time stamps get stored as "last valid time stamp" seen from each node (supernode and edges). So, a newly arriving packet's time stamp can be compared to the last valid one. It should be equal or higher. However, as UDP packets may overtake each other just by taking another path through the internet, they are allowed to be 160 millisecond earlier than the last valid one. This limit can be adjusted by changing the `TIME_STAMP_JITTER` definition.

The way the IV is used for replay protection and for checksumming makes enabled header encryption a prerequisite for these features.
