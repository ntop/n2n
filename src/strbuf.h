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
// of size buflen
#define STRBUF_INIT(buf,p,buflen) do { \
        buf = (void *)p; \
        buf->size = buflen - sizeof(size_t); \
} while(0)


#endif
