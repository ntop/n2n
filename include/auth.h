/*
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */


#include "n2n.h"


#ifndef AUTH_H
#define AUTH_H


int bin_to_ascii (uint8_t *out, uint8_t *in, size_t in_len);

int ascii_to_bin (uint8_t *out, uint8_t *in);

int generate_private_key(n2n_private_public_key_t key, uint8_t *in);

int generate_public_key (n2n_private_public_key_t pub, n2n_private_public_key_t prv);

int generate_shared_secret (n2n_private_public_key_t shared, n2n_private_public_key_t prv, n2n_private_public_key_t pub);

int bind_private_key_to_username (n2n_private_public_key_t prv, uint8_t *username);


#endif
