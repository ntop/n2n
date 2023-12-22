#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

DEBUG?=-g3

HEADERS=$(wildcard include/*.h)
CFLAGS+=-I../include

CFLAGS+=$(DEBUG)
LDFLAGS+=-L..

N2N_LIB=../libn2n.a

TOOLS+=n2n-benchmark$(EXE)
TOOLS+=n2n-keygen$(EXE)
TOOLS+=n2n-route$(EXE)
TOOLS+=n2n-portfwd$(EXE)
TOOLS+=n2n-decode$(EXE)

TESTS=tests-compress$(EXE)
TESTS+=tests-elliptic$(EXE)
TESTS+=tests-hashing$(EXE)
TESTS+=tests-transform$(EXE)
TESTS+=tests-wire$(EXE)
TESTS+=tests-auth$(EXE)

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

n2n-benchmark.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-keygen.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-route.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-portfwd.o: $(N2N_LIB) $(HEADERS) ../config.mak
n2n-decode.o: $(N2N_LIB) $(HEADERS) ../config.mak

ifneq (,$(findstring mingw,$(CONFIG_HOST_OS)))
# HACK for windows.
n2n-benchmark.exe: n2n-benchmark
n2n-keygen.exe: n2n-keygen
n2n-route.exe: n2n-route
n2n-portfwd.exe: n2n-portfwd
n2n-decode.exe: n2n-decode
tests-compress.exe: tests-compress
tests-elliptic.exe: tests-elliptic
tests-hashing.exe: tests-hashing
tests-transform.exe: tests-transform
tests-wire.exe: tests-wire
tests-auth.exe: tests-auth
endif

# See comments in the topdir Makefile about how to generate coverage
# data.
gcov:
	gcov $(TOOLS) $(TESTS)

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL_PROG) $(TOOLS) $(SBINDIR)/
