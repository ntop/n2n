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

#include <stdint.h>


#include "n2n.h"
#include "speck.h"


/* Header encryption indicators */
#define HEADER_ENCRYPTION_UNKNOWN       0
#define HEADER_ENCRYPTION_NONE          1
#define HEADER_ENCRYPTION_ENABLED       2


uint32_t packet_header_decrypt (uint8_t packet[], uint8_t packet_len,
                                char * community_name, he_context_t * ctx);


int8_t packet_header_decrypt_if_required (uint8_t packet[], uint16_t packet_len,
                                          struct sn_community * communities);


int32_t packet_header_encrypt (uint8_t packet[], uint8_t header_len, he_context_t * ctx);


void packet_header_setup_key (char * community_name, he_context_t * ctx);
