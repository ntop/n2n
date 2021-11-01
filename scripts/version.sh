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

VER_FILE_DIR=$(dirname "$0")/..
VER_FILE_SHORT=$(cat "${VER_FILE_DIR}/VERSION")

if git status >/dev/null; then
    VER_GIT_SHORT=$(git describe --abbrev=0)

    if [ "$VER_FILE_SHORT" != "$VER_GIT_SHORT" ]; then
        echo "Error: VERSION file does not match tag version ($VER_FILE_SHORT != $VER_GIT_SHORT)"
        exit 1
    fi

    VER_SHORT="$VER_GIT_SHORT"
    VER_HASH=$(git rev-parse --short HEAD)
    VER=$(git describe --abbrev=7 --dirty)
else
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
