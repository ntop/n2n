/*
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */


#ifndef AUTH_H
#define AUTH_H


#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t, uint32_t
#include "n2n.h"     // for n2n_private_public_key_t, n2n_community_t, N2N_A...


int bin_to_ascii (char *out, uint8_t *in, size_t in_len);

int ascii_to_bin (uint8_t *out, char *in);

int generate_private_key (n2n_private_public_key_t key, char *in);

int generate_public_key (n2n_private_public_key_t pub, n2n_private_public_key_t prv);

int generate_shared_secret (n2n_private_public_key_t shared, n2n_private_public_key_t prv, n2n_private_public_key_t pub);

int bind_private_key_to_username (n2n_private_public_key_t prv, char *username);

int calculate_dynamic_key (uint8_t out_key[N2N_AUTH_CHALLENGE_SIZE],
                           uint32_t key_time, n2n_community_t comm, n2n_community_t fed);


#endif
