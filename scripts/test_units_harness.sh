#!/bin/sh
#
# This expects to find the tests in the tools dir and the expected results
# in the tests dir.

TESTS="
    tests-auth
    tests-compress
    tests-elliptic
    tests-hashing
    tests-transform
    tests-wire
"

TOOLSDIR=tools
TESTDATA=tests

# Allow both dirs be overidden
[ -n "$1" ] && TOOLSDIR="$1"
[ -n "$2" ] && TESTDATA="$2"

# Confirm we have all the tools and data
for i in $TESTS; do
    if [ ! -e "$TOOLSDIR/$i" ]; then
        echo "Could not find test $TOOLSDIR/$i"
        exit 1
    fi
    if [ ! -e "$TESTDATA/$i.expected" ]; then
        echo "Could not find testdata $TESTDATA/$i.expected"
        exit 1
    fi
done

# Actually run the tests
set -e
for i in $TESTS; do
    echo "$TOOLSDIR/$i >$TESTDATA/$i.out"
    "$TOOLSDIR/$i" >"$TESTDATA/$i.out"
    cmp "$TESTDATA/$i.expected" "$TESTDATA/$i.out"
done
