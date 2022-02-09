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
#OPTS+=" -DN2N_OPTION_USE_PTHREAD=ON"
#OPTS+=" -DN2N_OPTION_USE_OPENSSL=ON"
#OPTS+=" -DN2N_OPTION_USE_CAPLIB=ON"
#OPTS+=" -DN2N_OPTION_USE_PCAPLIB=ON"
#OPTS+=" -DN2N_OPTION_USE_ZSTD=ON"
#OPTS+=" -DN2N_OPTION_USE_PORTMAPPING=ON"

#OPTS+=" -DOPENSSL_USE_STATIC_LIBS=true"

set -e

rm -rf build

cmake -E make_directory build
cd build

# Shell check wants me to use an array in this scenario.  Bourne shell
# arrays are my line in the sand showing that a script should not be
# written in such a horrible language.  Since it would be silly to rewrite
# a one-page wrapper script in python, we submit that this check is wrong.
# shellcheck disable=SC2086
cmake .. $OPTS

cmake --build . --config Release

ctest
