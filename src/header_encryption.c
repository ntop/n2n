/**
 * (C) 2007-21 - ntop.org and contributors
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


int packet_header_decrypt (uint8_t packet[], uint16_t packet_len,
                           char *community_name,
                           he_context_t *ctx, he_context_t *ctx_iv,
                           uint64_t *stamp) {

    // assemble IV
    // the last four are ASCII "n2n!" and do not get overwritten
    uint8_t iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x6E, 0x32, 0x6E, 0x21 };
    // the first 96 bits of the packet get padded with ASCII "n2n!" to full 128 bit IV
    memcpy(iv, packet, 12);

    // try community name as possible key and check for magic bytes "n2__"
    uint32_t magic = 0x6E320000;
    uint32_t test_magic;

    // check for magic
    // so, as a first step, decrypt 4 bytes only starting at byte 12
    speck_ctr((uint8_t*)&test_magic, &packet[12], 4, iv, (speck_context_t*)ctx);
    test_magic = be32toh(test_magic);

    //extract header length (lower 2 bytes)
    uint32_t header_len = test_magic - magic;

    if (header_len <= packet_len) {
        // decrypt the complete header
        speck_ctr(&packet[12], &packet[12], header_len - 12, iv, (speck_context_t*)ctx);

        // restore original packet order
        memcpy(&packet[0], &packet[16], 4);
        memcpy(&packet[4], community_name, N2N_COMMUNITY_SIZE);

        // extract time stamp (first 64 bit) and un-xor actual checksum (calculated here) from it
        // if payload was altered (different checksum than original), time stamp verification will fail
        speck_96_decrypt(iv, (speck_context_t*)ctx_iv);

        uint64_t checksum = pearson_hash_64(packet, packet_len);

        *stamp = be64toh(*(uint64_t*)iv) ^ checksum;

        // successful
        return 1;
    } else {

        // unsuccessful
        return 0;
    }
}


int packet_header_encrypt (uint8_t packet[], uint16_t header_len, uint16_t packet_len,
                           he_context_t *ctx, he_context_t *ctx_iv,
                           uint64_t stamp) {

    uint8_t iv[16];
    uint32_t *iv32 = (uint32_t*)&iv;
    uint64_t *iv64 = (uint64_t*)&iv;
    uint64_t checksum = 0;
    uint32_t magic = 0x6E320000; /* == ASCII "n2__" */
    magic += header_len;

    if(packet_len < 20) {
        traceEvent(TRACE_DEBUG, "packet_header_encrypt dropped a packet too short to be valid.");
        return -1;
    }
    // we trust in the caller assuring header_len <= packet_len

    checksum = pearson_hash_64(packet, packet_len);

    // re-order packet
    memcpy(&packet[16], &packet[00], 4);

    // add time stamp, checksum and magic bytes to form the pre-IV
    iv64[0] = htobe64(stamp ^ checksum);
    iv32[2] = n2n_rand();

    // encrypt this 96-bit pre-IV to IV
    speck_96_encrypt(iv, (speck_context_t*)ctx_iv);

    // place IV in packet (including magic number)
    iv32[3] = htobe32(magic);
    memcpy(packet, iv, 16);

    // replace magic number "n2__" by correct IV padding "n2n!"
    iv32[3] = htobe32(0x6E326E21);

    // encrypt
    speck_ctr(&packet[12], &packet[12], header_len - 12, iv, (speck_context_t*)ctx);

    return 0;
}


void packet_header_setup_key (const char *community_name,
                              he_context_t **ctx, he_context_t **ctx_iv) {

    uint8_t key[16];
    pearson_hash_128(key, (uint8_t*)community_name, N2N_COMMUNITY_SIZE);

    *ctx = (he_context_t*)calloc(1, sizeof (speck_context_t));
    speck_init((speck_context_t**)ctx, key, 128);

    // hash again and use last 96 bit (skipping 4 bytes) as key for IV encryption
    // REMOVE as soon as checksum and replay protection get their own fields
    pearson_hash_128(key, key, sizeof (key));
    *ctx_iv = (he_context_t*)calloc(1, sizeof (speck_context_t));
    speck_96_expand_key((speck_context_t*)*ctx_iv, &key[4]);
}
