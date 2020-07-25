# Cryptography in n2n

## Payload

### Overview

Payload encryption currently comes four in different flavors from a variety of origins and all with their own specialities. Supported ciphers are enabled using the indicated command line option:

- Twofish in CBC mode (`-A2`)
- AES in CBC mode (`-A3`)
- ChaCha20 (CTR) (`-A4`)
- SPECK in CTR mode (`-A5`)

To renounce encryption, `-A1` enables the so called `null_transform` transmitting all data unencrpytedly.

The following chart might help with a quick comparison and to make a decision on what cipher to use:

| Cipher | Mode | Block Size | Key Size         | IV length |Speed | Built-In | Origin |
| :---:  | :---:| :---:      | :---:            | :---:     |:---: | :---:    | ---    |
|Twofish | CBC  | 128 bits   | 128 bit (?)      | 32 bit    | -    | Y        | Bruce Schneier |
|AES     | CBC  | 128 bits   | 128, 192,256 bit | 64 bit    | O..+ | N        | Joan Daemen, Vincent Rijmen, NSA-approved |
|ChaCha20| CTR  | Stream     | 256 bit          | 128 bit   | +..++| N        | Daniel J. Bernstein |
|SPECK   | CTR  | Stream     | 256 bit          | 128 bit   | ++   | Y        | NSA |

As the two block ciphers Twofish and AES are used in CBC mode, they require a padding which results in encrypted payload sizes modulo the respective blocksize. Sizewise, this could be considered a disadvantage. On the other hand, stream ciphers need a longer initialization vector (IV) to be transmitted with the cipher.

Note that AES and ChaCha20 only are available if n2n is compiled with openSSL support while Twofish and SPECK always are available as built-ins.

### Twofish

This implementation prepends a 32 bit random value to the plain text. In the `src/transform_tf.c` file, it is called `nonce'. In CBC mode, this basically has the same effect as a respectively shorter IV.

Padding to the last block happens by filling `0x00`-bytes and indicating their number as the last byte of the block. This could lead to up to 16 extra bytes.

Other than that, it is plain Twofish in CBC mode.

Twofish is the slowest of the ciphers present.

_We might try to find a faster implementation._

### AES

AES uses the standard way of an IV, but it does not neccessarily transmits the full IV along with the packets. The size of the transmitted part is adjustable by changing the `TRANSOP_AES_IV_SEED_SIZE` definition found in `src/transform_aes.c`. It defaults to 8 meaning that 8 bytes (of max 16) are transmitted. The remaining 8 bytes are fixed, key-derived materiel is used to fill up to full block size. For vrious reasons, a single AES-ECB encryption step is applied to these 16 bytes before they get used as regular IV for AES-CBCing the payload.

The padding scheme is the same as used with Twofish.

AES relies on openSSL's `evp_*` interface which also offers hardware acceleration where available (SSE, AES-NI, …). It however is slower than the following stream ciphers because the CBC mode cannot compete to the optimized stream ciphers; maybe AES-CTR being a stream cipher could.

_Current ideas are to bring CTS mode to AES in some future version, just to avoid unneccessary weight gains from padding. CTS mode works well starting with plain texts from one block plus one byte. So, we might revert back to the Twofish-way of IV handling._

### ChaCha20

ChaCha20 was the first stream cipher supported by n2n.

It also relies on openSSL's `evp_*` interface. It does not use the Poly1305 message tag from the same author, though. Whole packet's checksum will be handled in the header, see below.

The random full 128-bit IV is transmitted in plain.

ChaCha20 usually performs faster than AES-CBC.

### SPECK

SPECK is recommend by the NSA for offical use in case AES implementation is not feasible due to system constraints (performance, size, …). The block cipher is used in CTR mode making it a stream cipher. The random full 128-bit IV is transmitted in plain.

On Intel CPUs, SPECK performs even faster than openSSL's ChaCha20 as it takes advantage of SSE4 or AVX2 if available. Though, on Raspberry's ARM CPU, it is second place behind ChaCha20 and before AES-CBC.

_An ARM specific optimized implementation (NEON?) is still missing. Also, multi-threading might accelerate this cipher on all CPUs with more than one core._

### Random Numbers

## Header

### Encryption

### Checksum

### Replay Protection