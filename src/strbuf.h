/*
 * Internal interface definitions for the strbuf abstrction
 *
 * This header is not part of the public library API and is thus not in
 * the public include folder
 */

#ifndef STRBUF_H
#define STRBUF_H 1

typedef struct strbuf {
    size_t size;
    char str[];
} strbuf_t;

// Initialise the strbuf pointer buf to point at the storage area p
// p must be a known sized object
#define STRBUF_INIT(buf,p) do { \
        buf = (void *)p; \
        buf->size = sizeof(*p) - sizeof(size_t); \
} while(0)


#endif
