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
#include <stddef.h>
#include <stdint.h>
#if defined (__SSSE3__) && defined (__AES__) // AES-NI & SSSE3 ----------------------------------------------------
#include <immintrin.h>
#endif // AES-NI & SSSE3 ------------------------------------------------------------------------------------------

void pearson_hash_256 (uint8_t *out, const uint8_t *in, size_t len);
void pearson_hash_128 (uint8_t *out, const uint8_t *in, size_t len);
uint64_t pearson_hash_64 (const uint8_t *in, size_t len);
uint32_t pearson_hash_32 (const uint8_t *in, size_t len);
uint16_t pearson_hash_16 (const uint8_t *in, size_t len);
void pearson_hash_init();
