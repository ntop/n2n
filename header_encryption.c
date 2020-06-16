#include "header_encryption.h"

#include <string.h>

#include "n2n.h"
#include "random_numbers.h"
#include "pearson.h"
#include "portable_endian.h"


#include <stdio.h>


uint32_t packet_header_decrypt (uint8_t packet[], uint8_t packet_len,
			        char * community_name, he_context_t * ctx) {

	// assemble IV
	// the last four are ASCII "n2n!" and do not get overwritten
	uint8_t iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			   0x00, 0x00, 0x00, 0x00, 0x6E, 0x32, 0x6E, 0x21 };
	// the first 96 bits of the packet get padded with ASCII "n2n!"
	// to full 128 bit IV
	memcpy (iv, packet, 12);
	// alternatively, consider: pearson_hash_128 (iv, packet, 12);

	// try community name as possible key and check for magic bytes
	uint32_t magic = 0x6E326E00; // ="n2n_"
	uint32_t test_magic;
	// check for magic bytes and resonable value in header len field
	speck_he ((uint8_t*)&test_magic, &packet[12], 4, iv, (speck_context_t*)ctx);
	test_magic = be32toh (test_magic);
	if ( ((test_magic <<  8) == magic)
	  && ((test_magic >> 24) <= packet_len) // (test_masgic >> 24) is header_len
	   ) {
		speck_he (&packet[12], &packet[12], (test_magic >> 24) - 12, iv, (speck_context_t*)ctx);
		// restore original packet order
		memcpy (&packet[0], &packet[16], 4);
		memcpy (&packet[4], community_name, N2N_COMMUNITY_SIZE);
		return (1); // successful
	} else
		return (0); // unsuccessful
}


int32_t packet_header_decrypt_if_required (uint8_t packet[], uint16_t packet_len,
					   struct sn_community *communities) {

	if (packet_len < 20)
		return (-1);

	// first, check if header is unenrypted to put it into the fast-lane then

	// the following check is around 99.99962 percent reliable
	// it heavily relies on the structure of packet's common part
	// changes to wire.c:encode/decode_common need to go together with this code
	if ( (packet[19] == (uint8_t)0x00)	// null terminated community name
	  && (packet[00] == N2N_PKT_VERSION)	// correct packet version
//	  && (packet[01] <= N2N_DEFAULT_TTL) 	// reasonable TTL -- might interfere with hole-punching-related or cli passed higher values ?!
	  && ((be16toh (*(uint16_t*)&(packet[02])) & N2N_FLAGS_TYPE_MASK ) <= MSG_TYPE_MAX_TYPE  ) // message type
	  && ( be16toh (*(uint16_t*)&(packet[02])) < N2N_FLAGS_OPTIONS)	// flags
	   ) {

		// most probably unencrypted

		// TODO:
		// !!! make sure, no downgrading happens here !!!
		// NOT FOR DEFINETLY ENCRYPTED COMMUNITIES / NO DOWNGRADE, NO INJECTION

		return (HEADER_ENCRYPTION_NONE);
	} else {

		// most probably encrypted
		// cycle through the known communities (as keys) to eventually decrypt
		int32_t ret;
		struct sn_community *c, *tmp;
		HASH_ITER (hh, communities, c, tmp) {
			// skip the definitely unencrypted communities
			if (c->header_encryption == HEADER_ENCRYPTION_NONE)
				continue;
			if ( (ret = packet_header_decrypt (packet, packet_len, c->community, &(c->header_encryption_ctx))) ) {
				// set to 'encrypted'
				 c->header_encryption = HEADER_ENCRYPTION_ENABLED;
				// no need to test any further
				return (HEADER_ENCRYPTION_ENABLED);
			}
		}
		// no matching key/community
		return (-3);
	}
}


int32_t packet_header_encrypt (uint8_t packet[], uint8_t header_len, he_context_t * ctx) {

	if (header_len < 20)
		return (-1);

	memcpy (&packet[16], &packet[00], 4);

	uint8_t iv[16];
	((uint64_t*)iv)[0] = n2n_rand ();
	((uint64_t*)iv)[1] = n2n_rand ();

	const uint32_t magic = 0x006E326E;
	((uint32_t*)iv)[3] = htobe32 (magic);

	iv[12] = header_len;

	speck_he (&packet[12], &packet[12], header_len - 12, iv, (speck_context_t*)ctx);

	return (0);
}


void packet_header_setup_key (char * community_name, he_context_t * ctx) {

	uint8_t key[16];
	pearson_hash_128 (key, (uint8_t*)community_name, N2N_COMMUNITY_SIZE);

	speck_expand_key_he (key, ctx);
}
