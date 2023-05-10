#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

DEBUG?=-g3

HEADERS=$(wildcard include/*.h)
CFLAGS+=-I../include
LDLIBS+=-ln2n
LDLIBS+=$(LDLIBS_EXTRA)

ifeq ($(CONFIG_TARGET),mingw)
CFLAGS+=-I../win32
LDLIBS+=$(abspath ../win32/n2n_win32.a)
LDLIBS+=-lnetapi32 -lws2_32 -liphlpapi
endif
CFLAGS+=$(DEBUG)
LDFLAGS+=-L..

N2N_LIB=../libn2n.a

TOOLS=n2n-benchmark n2n-keygen n2n-route n2n-portfwd
TOOLS+=$(TOOLS_ADDITIONAL)

TESTS=tests-compress tests-elliptic tests-hashing tests-transform
TESTS+=tests-wire
TESTS+=tests-auth

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

n2n-benchmark.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-keygen.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-route.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-portfwd.o: $(N2N_LIB) $(HEADERS) ../config.mak

n2n-decode: n2n-decode.c $(N2N_LIB) $(HEADERS) ../config.mak
	$(CC) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -lpcap -o $@

# See comments in the topdir Makefile about how to generate coverage
# data.
gcov:
	gcov $(TOOLS) $(TESTS)

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL_PROG) $(TOOLS) $(SBINDIR)/
