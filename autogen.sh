#!/usr/bin/env bash

N2N_VERSION_SHORT=$(cat VERSION)

cat configure.seed | sed \
    -e "s/@N2N_VERSION_SHORT@/$N2N_VERSION_SHORT/g" \
    > configure.ac

rm -f config.h config.h.in *~ Makefile configure #*

echo "Wait please..."
autoreconf -if
