#!/bin/sh
#
# Run all the integration tests via the test harness

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR=.
[ -z "$BINDIR" ] && BINDIR=.
export TOPDIR
export BINDIR

${TOPDIR}/scripts/test_harness.sh test_integration_supernode.sh
