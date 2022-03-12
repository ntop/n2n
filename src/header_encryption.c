/**
 * (C) 2007-22 - ntop.org and contributors
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

    // try community name as possible key and check for magic bytes "n2__"
    uint32_t magic = 0x6E320000;
    uint32_t test_magic;
    uint32_t checksum_high = 0;

    // check for magic
    // so, as a first step, decrypt last 4 bytes from where originally the community name would be
    speck_ctr((uint8_t*)&test_magic, &packet[16], 4, packet, (speck_context_t*)ctx);
    test_magic = be32toh(test_magic);

    //extract header length (lower 2 bytes)
    uint32_t header_len = test_magic - magic;

    if(header_len <= packet_len) {
        // decrypt the complete header
        speck_ctr(&packet[16], &packet[16], header_len - 16, packet, (speck_context_t*)ctx);

        // extract time stamp and un-xor actual checksum (calculated here) from it
        // if payload was altered (different checksum than original), time stamp verification will fail
        // use speck block cipher step (1 block == 128 bit == 16 bytes)
        speck_128_decrypt(packet, (speck_context_t*)ctx_iv);

        // extract the required data
        *stamp = be64toh(*(uint64_t*)&packet[4]);
        checksum_high = be32toh(*(uint32_t*)packet);

        // restore original packet order before calculating checksum
        memcpy(&packet[0], &packet[20], 4);
        memcpy(&packet[4], community_name, N2N_COMMUNITY_SIZE);
        uint64_t checksum = pearson_hash_64(packet, packet_len);

        if((checksum >> 32) != checksum_high) {
            traceEvent(TRACE_DEBUG, "packet_header_decrypt dropped a packet with invalid checksum.");

            // unsuccessful
            return 0;
        }

        *stamp = *stamp ^ (checksum << 32);

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

    uint32_t *p32 = (uint32_t*)packet;
    uint64_t *p64 = (uint64_t*)packet;
    uint64_t checksum = 0;
    uint32_t magic = 0x6E320000; /* == ASCII "n2__" */
    magic += header_len;

    if(packet_len < 24) {
        traceEvent(TRACE_DEBUG, "packet_header_encrypt dropped a packet too short to be valid.");
        return -1;
    }
    // we trust in the caller assuring header_len <= packet_len

    checksum = pearson_hash_64(packet, packet_len);

    // re-order packet
    p32[5] = p32[0];

    // add time stamp, checksum, and random to form the pre-IV
    p64[0] = htobe64(checksum);

    p32[1] = p32[1] ^ htobe32((uint32_t)(stamp >> 32));
    p32[2] = htobe32((uint32_t)stamp);

    p32[3] = n2n_rand();

    // encrypt this pre-IV to IV
    speck_128_encrypt(packet, (speck_context_t*)ctx_iv);

    // place IV plus magic in packet
    p32[4] = htobe32(magic);

    // encrypt, starting from magic
    speck_ctr(&packet[16], &packet[16], header_len - 16, packet, (speck_context_t*)ctx);

    return 0;
}


void packet_header_setup_key (const char *community_name,
                              he_context_t **ctx_static, he_context_t **ctx_dynamic,
                              he_context_t **ctx_iv_static, he_context_t **ctx_iv_dynamic) {

    uint8_t key[16];

    // for REGISTER_SUPER, REGISTER_SUPER_ACK, REGISTER_SUPER_NAK only;
    // for all other packets, same as static by default (changed by user/pw auth scheme
    // calling packet_header_change_dynamic_key later)

    pearson_hash_128(key, (uint8_t*)community_name, N2N_COMMUNITY_SIZE);

    if(!*ctx_static)
        *ctx_static = (he_context_t*)calloc(1, sizeof(speck_context_t));
    speck_init((speck_context_t**)ctx_static, key, 128);

    if(!*ctx_dynamic)
        *ctx_dynamic = (he_context_t*)calloc(1, sizeof(speck_context_t));
    speck_init((speck_context_t**)ctx_dynamic, key, 128);

    // hash again and use as key for IV encryption
    pearson_hash_128(key, key, sizeof(key));

    if(!*ctx_iv_static)
        *ctx_iv_static = (he_context_t*)calloc(1, sizeof(speck_context_t));
    speck_init((speck_context_t**)ctx_iv_static, key, 128);

    if(!*ctx_iv_dynamic)
        *ctx_iv_dynamic = (he_context_t*)calloc(1, sizeof(speck_context_t));
    speck_init((speck_context_t**)ctx_iv_dynamic, key, 128);
}


void packet_header_change_dynamic_key (uint8_t *key_dynamic,
                                       he_context_t **ctx_dynamic, he_context_t **ctx_iv_dynamic) {

    uint8_t key[16];
    pearson_hash_128(key, key_dynamic, N2N_AUTH_CHALLENGE_SIZE);

    // for REGISTER_SUPER, REGISTER_SUPER_ACK, REGISTER_SUPER_NAK only
    // for all other packets, same as static by default (changed by user/pw auth scheme)
    speck_init((speck_context_t**)ctx_dynamic, key, 128);

    // hash again and use as key for IV encryption
    // REMOVE as soon as checksum and replay protection get their own fields
    pearson_hash_128(key, key, sizeof(key));
    speck_init((speck_context_t**)ctx_iv_dynamic, key, 128);
}
