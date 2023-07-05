#
# These examples are intended to show how to use the libn2n as an embedded
# service within other software.
#

EXAMPLES+=example_edge_embed_quick_edge_init
EXAMPLES+=example_edge_embed
EXAMPLES+=example_sn_embed

all: $(EXAMPLES)

CFLAGS+=-I../include
LDFLAGS+=-L../

example_edge_embed_quick_edge_init: ../libn2n.a
example_sn_embed: ../libn2n.a
example_edge_embed: ../libn2n.a

clean:
	rm -f $(EXAMPLES)
