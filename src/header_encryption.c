/**
 * (C) 2007-20 - ntop.org and contributors
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

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

/* ********************************************************************** */

uint32_t packet_header_decrypt (uint8_t packet[], uint16_t packet_len,
			        char * community_name, he_context_t * ctx) {

  // assemble IV
  // the last four are ASCII "n2n!" and do not get overwritten
  uint8_t iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x6E, 0x32, 0x6E, 0x21 };
  // the first 96 bits of the packet get padded with ASCII "n2n!"
  // to full 128 bit IV
  memcpy (iv, packet, 12);

  // try community name as possible key and check for magic bytes
  uint32_t magic = 0x6E326E00; // ="n2n_"
  uint32_t test_magic;
  // check for magic bytes and reasonable value in header len field
  // so, as a first step, decrypt 4 bytes only starting at byte 12
  speck_he ((uint8_t*)&test_magic, &packet[12], 4, iv, (speck_context_t*)ctx);
  test_magic = be32toh (test_magic);
  if( (((test_magic >> 8) <<  8) == magic)	// check the thre uppermost bytes
       && (((uint8_t)test_magic) <= packet_len) // lowest 8 bit of test_magic are header_len
       ) {
    // decrypt the complete header
    speck_he (&packet[12], &packet[12], (uint8_t)(test_magic) - 12, iv, (speck_context_t*)ctx);
    // restore original packet order
    memcpy (&packet[0], &packet[16], 4);
    memcpy (&packet[4], community_name, N2N_COMMUNITY_SIZE);
    return (1); // successful
  } else
    return (0); // unsuccessful
}

/* ********************************************************************** */

int32_t packet_header_encrypt (uint8_t packet[], uint8_t header_len, he_context_t * ctx,
                               he_context_t * ctx_iv, uint16_t checksum) {

  uint8_t iv[16];
  uint16_t *iv16 = (uint16_t*)&iv;
  uint32_t *iv32 = (uint32_t*)&iv;
  uint64_t *iv64 = (uint64_t*)&iv;
  const uint32_t magic = 0x6E326E21; // = ASCII "n2n!"

  if(header_len < 20) {
    traceEvent(TRACE_DEBUG, "packet_header_encrypt dropped a packet too short to be valid.");
    return (-1);
  }

  memcpy (&packet[16], &packet[00], 4);

  iv64[0] = n2n_rand ();
  iv16[4] = n2n_rand ();
  iv16[5] = htobe16 (checksum);
  iv32[3] = htobe32 (magic);
  // blend checksum into 96-bit IV
  speck_he_iv_encrypt (iv, (speck_context_t*)ctx_iv);

  memcpy (packet, iv, 16);
  packet[15] = header_len;

  speck_he (&packet[12], &packet[12], header_len - 12, iv, (speck_context_t*)ctx);
  return (0);
}

/* ********************************************************************** */

void packet_header_setup_key (const char * community_name, he_context_t ** ctx,
                                                           he_context_t ** ctx_iv) {

  uint8_t key[16];
  pearson_hash_128 (key, (uint8_t*)community_name, N2N_COMMUNITY_SIZE);

  *ctx = (he_context_t*)calloc(1, sizeof (speck_context_t));
  speck_expand_key_he (key, (speck_context_t*)*ctx);

  // hash again and use last 96 bit (skipping 4 bytes) as key for IV encryption
  // REMOVE as soon as checksum and replay protection get their own fields
  pearson_hash_128 (key, key, sizeof (key));
  *ctx_iv = (he_context_t*)calloc(1, sizeof (speck_context_t));
  speck_expand_key_he_iv (&key[4], (speck_context_t*)*ctx_iv);
}
