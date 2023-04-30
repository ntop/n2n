#!/bin/sh
#
# Specifically for windows, where installing autoconf looks suspiciously
# like boiling the ocean.

cat >config.mak <<EOF
CC=gcc
AR=ar
CFLAGS=$CFLAGS
LDFLAGS=$LDFLAGS
N2N_LIBS_EXTRA=$LDLIBS
EOF

sed \
    -e "s%@ADDITIONAL_TOOLS@%%g" \
    < tools/Makefile.in > tools/Makefile

cat <<EOF >include/config.h
#define PACKAGE_VERSION "FIXME"
#define PACKAGE_OSNAME "FIXME"
EOF
