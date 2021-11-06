#!/bin/sh
#
# Run with the name of a test list file.
#
# This expects to find the tests in the tools dir or scripts dir and the
# expected results in the tests dir.

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR="."
[ -z "$BINDIR" ] && BINDIR="."
export TOPDIR
export BINDIR

if [ -z "$1" ]; then
    echo need test list filename
    exit 1
fi
TESTLIST="$1"
LISTDIR=$(dirname "$TESTLIST")

TESTS=$(sed -e "s/#.*//" "$TESTLIST")

# Actually run the tests
for i in $TESTS; do
    # Look in several places for the test program
    if [ -e "$BINDIR/$i" ]; then
        TEST="$BINDIR/$i"
    elif [ -e "$BINDIR/tools/$i" ]; then
        TEST="$BINDIR/tools/$i"
    elif [ -e "$LISTDIR/../scripts/$i" ]; then
        TEST="$LISTDIR/../scripts/$i"
    else
        echo "Could not find test $i"
        exit 1
    fi

    if [ ! -e "$LISTDIR/$i.expected" ]; then
        echo "Could not find testdata $LISTDIR/$i.expected"
        exit 1
    fi

    echo "$TEST >$LISTDIR/$i.out"
    set -e
    "$TEST" >"$LISTDIR/$i.out"
    cmp "$LISTDIR/$i.expected" "$LISTDIR/$i.out"
    set +e
done
