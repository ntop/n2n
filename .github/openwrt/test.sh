#!/bin/sh

case "$1" in
	"n2n-edge"|"n2n-supernode")
		eval "${1#n2n-}" | grep "$2"
		;;
	"n2n-tests")
		for test in $(grep -v '#' '/usr/bin/n2n-tests_units.list'); do
			eval "n2n-$test"
		done
		;;
esac
