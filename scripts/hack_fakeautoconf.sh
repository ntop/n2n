#!/bin/sh
#
# Specifically for windows, where installing autoconf looks suspiciously
# like boiling the ocean.

sed \
    -e "s%@CC@%gcc%g" \
    -e "s%@AR@%ar%g" \
    -e "s%@CFLAGS@%$CFLAGS%g" \
    -e "s%@LDFLAGS@%$LDFLAGS%g" \
    -e "s%@N2N_LIBS@%$LDLIBS%g" \
    < Makefile.in > Makefile

sed \
    -e "s%@ADDITIONAL_TOOLS@%%g" \
    < tools/Makefile.in > tools/Makefile

cat <<EOF >include/config.h
#define PACKAGE_VERSION "FIXME"
#define PACKAGE_OSNAME "FIXME"
EOF
