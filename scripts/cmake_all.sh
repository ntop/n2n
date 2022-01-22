#!/bin/bash
#
# Well, cmake might be approximately the same as ./configure && make, but it
# never rolls off the fingers as easily
#

if [ ! -f CMakeLists.txt ]; then
    echo ERROR: run this script from the TOPDIR
    exit 1
fi

OPTS=""
#OPTS+=-DN2N_OPTION_USE_ZSTD=ON

set -e

rm -rf build

cmake -E make_directory build
cd build

cmake $OPTS ..

cmake --build . --config Release

ctest
