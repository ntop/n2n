#!/bin/sh
#
# Do some quick tests via the Json API against the supernode
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

# start it running in the background
docmd ${BINDIR}/supernode -v

docmd ${TOPDIR}/scripts/n2n-ctl -t 5645 communities
docmd ${TOPDIR}/scripts/n2n-ctl -t 5645 packetstats
docmd ${TOPDIR}/scripts/n2n-ctl -t 5645 edges --raw

docmd ${TOPDIR}/scripts/n2n-ctl -t 5645 verbose
docmd ${TOPDIR}/scripts/n2n-ctl -t 5645 -k $AUTH --write verbose 1

# looks strange, but we are querying the state of the "stop" verb
docmd ${TOPDIR}/scripts/n2n-ctl -t 5645 stop

# stop it
docmd ${TOPDIR}/scripts/n2n-ctl -t 5645 -k $AUTH --write stop

