#!/bin/sh
#
# Do some quick tests via the Json API against the edge
#

AUTH=n2n

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR=.
[ -z "$BINDIR" ] && BINDIR=.

docmd() {
    echo "###"
    "$@"
    echo
}

# start a supernode
docmd ${BINDIR}/supernode -v

# Start the edge in the background
docmd sudo ${BINDIR}/edge -l localhost:7654 -c test >/dev/null
# TODO:
# - send edge messages to stderr?

docmd ${TOPDIR}/scripts/n2n-ctl communities
docmd ${TOPDIR}/scripts/n2n-ctl packetstats
docmd ${TOPDIR}/scripts/n2n-ctl edges --raw

# TODO:
# docmd ${TOPDIR}/scripts/n2n-ctl supernodes --raw
# - need fixed mac address
# - need to mask out:
#   - version string
#   - last_seen timestamp
#   - uptime

docmd ${TOPDIR}/scripts/n2n-ctl verbose
docmd ${TOPDIR}/scripts/n2n-ctl --write verbose 1 2>/dev/null
echo $?
docmd ${TOPDIR}/scripts/n2n-ctl -k $AUTH --write verbose 1

# looks strange, but we are querying the state of the "stop" verb
docmd ${TOPDIR}/scripts/n2n-ctl stop

# stop them both
docmd ${TOPDIR}/scripts/n2n-ctl -k $AUTH --write stop
docmd ${TOPDIR}/scripts/n2n-ctl -t 5645 -k $AUTH --write stop

