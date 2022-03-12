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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include <stdio.h>

#include "n2n.h"
#include "hexdump.h"

void fhexdump(unsigned int display_addr, void *in, int size, FILE *stream) {
  uint8_t *p = in;

  while(size>0) {
    int i;

    fprintf(stream, "%03x: ", display_addr);

    for (i = 0; i < 16; i++) {
      if (i < size) {
	fprintf(stream, "%02x", p[i]);
      } else {
	fprintf(stream, "  ");
      }
      if (i==7) {
	fprintf(stream, "  ");
      } else {
	fprintf(stream, " ");
      }
    }
    fprintf(stream, "  |");

    for (i = 0; i < 16; i++) {
      if (i < size) {
	char ch = p[i];
	if (ch>=0x20 && ch<=0x7e) {
	  fprintf(stream, "%c", ch);
	} else {
	  fprintf(stream, " ");
	}
      }
    }
    fprintf(stream, "|\n");

    size -= 16;
    display_addr += 16;
    p += 16;
  }
}
