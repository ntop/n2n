#!/bin/sh
#
# Specifically for windows, where installing autoconf looks suspiciously
# like boiling the ocean.

cat <<EOF >include/config.h.in
// Created by hack fake autoconf for windows
// not actually a config input
EOF

cat <<EOF >configure
#!/bin/sh
echo Created by hack fake autoconf for windows
echo not a confgure script
exit 1
EOF
chmod a+x configure

cat >config.mak <<EOF
CONFIG_HOST=x86_64-w64-mingw32
CC=gcc
AR=ar
WINDRES=windres
CFLAGS=$CFLAGS -g -O2
LDFLAGS=$LDFLAGS
LDLIBS_EXTRA=$LDLIBS
EOF

cat >tools/config.mak <<EOF
TOOLS_ADDITIONAL=
EOF

cat <<EOF >include/config.h
#define PACKAGE_VERSION "FIXME"
#define PACKAGE_BUILDDATE "$(date)"
EOF
