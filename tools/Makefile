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

# HACK for windows.
%.exe: %
	cp $< $@

# See comments in the topdir Makefile about how to generate coverage
# data.
gcov:
	gcov $(TOOLS) $(TESTS)

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL_PROG) $(TOOLS) $(SBINDIR)/
