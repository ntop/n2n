#!/usr/bin/env bash

# NOTE: update version in CMakeLists.txt after changing these
N2N_MAJOR="2"
N2N_MINOR="8"
N2N_PATCH="0"

N2N_VERSION_SHORT="$N2N_MAJOR.$N2N_MINOR.$N2N_PATCH"

cat configure.seed | sed \
    -e "s/@N2N_MAJOR@/$N2N_MAJOR/g" \
    -e "s/@N2N_MINOR@/$N2N_MINOR/g" \
    -e "s/@N2N_PATCH@/$N2N_PATCH/g" \
    -e "s/@N2N_VERSION_SHORT@/$N2N_VERSION_SHORT/g" \
    > configure.ac

rm -f config.h config.h.in *~ Makefile configure #*

echo "Wait please..."
autoreconf -if
./configure
