#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

DEBUG?=-g3

HEADERS=$(wildcard include/*.h)
CFLAGS+=-I../include

ifneq (,$(findstring mingw,$(CONFIG_HOST_OS)))
CFLAGS+=-I../win32
endif
CFLAGS+=$(DEBUG)
LDFLAGS+=-L..

N2N_LIB=../libn2n.a

TOOLS=n2n-benchmark n2n-keygen n2n-route n2n-portfwd n2n-decode

TESTS=tests-compress tests-elliptic tests-hashing tests-transform
TESTS+=tests-wire
TESTS+=tests-auth

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

n2n-benchmark.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-keygen.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-route.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-portfwd.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-decode.o: $(N2N_LIB) $(HEADERS) ../config.mak

# See comments in the topdir Makefile about how to generate coverage
# data.
gcov:
	gcov $(TOOLS) $(TESTS)

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL_PROG) $(TOOLS) $(SBINDIR)/
