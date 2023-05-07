#!/bin/sh
#
# Specifically for windows, where installing autoconf looks suspiciously
# like boiling the ocean.

cat >config.mak <<EOF
CC=gcc
AR=ar
CFLAGS=$CFLAGS -g -O2 -I./include
LDFLAGS=$LDFLAGS -L.
LDLIBS_EXTRA=$LDLIBS
EOF

cat >tools/config.mak <<EOF
TOOLS_ADDITIONAL=
EOF

cat <<EOF >include/config.h
#define PACKAGE_VERSION "FIXME"
#define PACKAGE_OSNAME "FIXME"
#define PACKAGE_BUILDDATE "$(date)"
EOF
