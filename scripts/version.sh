#!/bin/sh
#
# Output the current version number
#

usage() {
    echo "Usage: $0 [short]"
    echo
    echo "Determine the correct version number for the current build"
    exit 0
}

# TODO: search for the top dir that contains the VERSION file?
VER_FILE_SHORT=$(cat VERSION)

if git status >/dev/null; then
    VER_GIT_SHORT=$(git describe --abbrev=0)
    VER_GIT=$(git describe --abbrev=7 --dirty)

    if [ "$VER_FILE_SHORT" != "$VER_GIT_SHORT" ]; then
        echo "Error: VERSION file does not match tag version ($VER_FILE_SHORT != $VER_GIT_SHORT)"
        exit 1
    fi

    VER_SHORT="$VER_GIT_SHORT"
    VER="$VER_GIT"
else
    VER_SHORT="$VER_FILE_SHORT"
    VER="$VER_FILE_SHORT"
fi

case "$1" in
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
