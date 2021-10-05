#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

CFLAGS+=-I../include
LDFLAGS+=-L..

.PHONY: all clean install

all: n2n_win32.a

n2n_win32.a: getopt1.o getopt.o wintap.o
	$(AR) rcs $@ $+

clean:
	rm -rf n2n_win32.a *.o *.gcno *.gcda

install:
	true
