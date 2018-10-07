#!/usr/bin/env bash

rm -f config.h config.h.in *~ Makefile configure #*

echo "Wait please..."
autoreconf -if
echo ""
echo "Now running ./configure"
./configure
