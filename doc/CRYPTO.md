# Cryptography in n2n

## Payload

### Overview

Payload encryption currently comes four in different flavors. Supported ciphers are enabled using the indicated command line option:

- Twofish in CBC mode (`-A2`)
- AES in CBC mode (`-A3`)
- ChaCha20 (CTR) (`-A4`)
- SPECK in CTR mode (`-A5`)

To renounce encryption, `-A1` enables the so called `null_transform` transmitting all data unencrpytedly.

The following quick comparing chart might help make a decision on what cipher to use:

| Cipher | Mode | Block Size | Key Size         | IV length |Speed | Built-In | Origin | 
| :---:  | :---:| :---:      | :---:            | :---:     |:---: | :---:    | ---    |
|Twofish | CBC  | 128 bits   | 128 bit (?)      | 32 bit    | -    | Y        | Bruce Schneier |
|AES     | CBC  | 128 bits   | 128, 192,256 bit | 64 bit    | O..+ | N        | Joan Daemen and Vincent Rijmen, NSA-approved |
|ChaCha20| CTR  | Stream     | 256 bit          | 128 bit   | +..++| N        | Daniel J. Bernstein |
|SPECK   | CTR  | Stream     | 256 bit          | 128 bit   | ++   | Y        | NSA |

As all block ciphers are used in CBC mode, they require a padding which results in encrypted payload sizes modulo the respective blocksize. Sizewise, this could be considered a disadvantage. On the other hand, stream ciphers need a longer initialization vector (IV) to be transmitted.

Note that AES and ChaCha20 only are available if n2n was compiled with openSSL support while Twofish and SPECK always are available as built-ins.

### Twofish

### AES

### ChaCha20

### SPECK

## Header

### Encryption

### Checksum

### Replay Protection