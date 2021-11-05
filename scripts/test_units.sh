#!/bin/sh
#
# Run all the unit tests via the test harness

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR=.
[ -z "$BINDIR" ] && BINDIR=.
export TOPDIR
export BINDIR

TESTS="
    tests-auth
    tests-compress
    tests-elliptic
    tests-hashing
    tests-transform
    tests-wire
"

# shellcheck disable=SC2086
${TOPDIR}/scripts/test_harness.sh $TESTS
