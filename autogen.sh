#!/usr/bin/env bash

# NOTE: update version in CMakeLists.txt after changing these
N2N_MAJOR="3"
N2N_MINOR="0"
N2N_PATCH="0"

N2N_VERSION_SHORT="$N2N_MAJOR.$N2N_MINOR.$N2N_PATCH"

cat configure.seed | sed \
    -e "s/@N2N_VERSION_SHORT@/$N2N_VERSION_SHORT/g" \
    > configure.ac

rm -f config.h config.h.in *~ Makefile configure #*

echo "Wait please..."
autoreconf -if
