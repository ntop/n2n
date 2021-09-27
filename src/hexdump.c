
#include <stdio.h>

#include "n2n.h"
#include "hexdump.h"

void fhexdump(unsigned int display_addr, void *in, int size, FILE *stream) {
    uint8_t *p = in;

    while(size>0) {
        fprintf(stream, "%03x: ", display_addr);

        for (int i = 0; i < 16; i++) {
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

        for (int i = 0; i < 16; i++) {
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
