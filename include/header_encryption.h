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


uint32_t packet_header_decrypt (uint8_t packet[], uint16_t packet_len,
                                char * community_name, he_context_t * ctx);


int32_t packet_header_encrypt (uint8_t packet[], uint8_t header_len, he_context_t * ctx,
                               he_context_t * ctx_iv, uint16_t checksum);


void packet_header_setup_key (const char * community_name, he_context_t ** ctx,
                                                           he_context_t ** ctx_iv);

