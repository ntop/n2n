#!/bin/sh
#
# Output the current version number
#

usage() {
    echo "Usage: $0 [short|hash]"
    echo
    echo "Determine the correct version number for the current build"
    exit 0
}

# We assume this script is in the TOPDIR/scripts directory and use that
# to find any other files we need
TOPDIR=$(dirname "$0")/..

VER_FILE_SHORT=$(cat "${TOPDIR}/VERSION")

if [ -d "$TOPDIR/.git" ]; then
    # If there is a .git directory in our TOPDIR, then this is assumed to be
    # real git checkout

    cd "$TOPDIR" || exit 1

    VER_GIT_SHORT=$(git describe --abbrev=0)

    if [ "$VER_FILE_SHORT" != "$VER_GIT_SHORT" ]; then
        echo "Error: VERSION file does not match tag version ($VER_FILE_SHORT != $VER_GIT_SHORT)"
        exit 1
    fi

    VER_SHORT="$VER_GIT_SHORT"
    VER_HASH=$(git rev-parse --short HEAD)
    VER=$(git describe --abbrev=7 --dirty)
else
    # If there is no .git directory in our TOPDIR, we fall back on relying on
    # the VERSION file

    VER_SHORT="$VER_FILE_SHORT"
    VER_HASH="HEAD"
    VER="$VER_FILE_SHORT"
fi

case "$1" in
    hash)
        echo "$VER_HASH"
        ;;
    short)
        echo "$VER_SHORT"
        ;;
    "")
        echo "$VER"
        ;;
    *)
        usage
        ;;
esac
