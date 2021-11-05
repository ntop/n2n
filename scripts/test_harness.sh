#!/bin/sh
#
# This expects to find the tests in the tools dir or scripts dir and the
# expected results in the tests dir.
#
# Run with the name(s) of the tests on the commandline

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR="."
[ -z "$BINDIR" ] && BINDIR="."
export TOPDIR
export BINDIR

if [ -d "$BINDIR/tools" ]; then
    TOOLSDIR="$BINDIR/tools"
else
    TOOLSDIR="$BINDIR"
fi

TESTS=$*

SCRIPTSDIR="$TOPDIR/scripts"
TESTDATA="$TOPDIR/tests"

# Confirm we have all the tools and data
for i in $TESTS; do
    if [ ! -e "$TOOLSDIR/$i" ] && [ ! -e "$SCRIPTSDIR/$i" ]; then
        echo "Could not find test $i"
        exit 1
    fi
    if [ ! -e "$TESTDATA/$i.expected" ]; then
        echo "Could not find testdata $TESTDATA/$i.expected"
        exit 1
    fi
done

# Actually run the tests
for i in $TESTS; do
    if [ -e "$TOOLSDIR/$i" ]; then
        TEST="$TOOLSDIR/$i"
    elif [ -e "$SCRIPTSDIR/$i" ]; then
        TEST="$SCRIPTSDIR/$i"
    fi

    echo "$TEST >$TESTDATA/$i.out"
    set -e
    "$TEST" >"$TESTDATA/$i.out"
    cmp "$TESTDATA/$i.expected" "$TESTDATA/$i.out"
    set +e
done
