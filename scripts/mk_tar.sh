#!/bin/bash

# This script makes a SRPM - a source RPM file which can be built into the
# appropriate distro specific RPM for any platform.
#
# To build the binary package:
# rpm -i n2n-<ver>.src.rpm
# rpmbuild -bb n2n.spec
#
# Look for the "Wrote:" line to see where the final RPM is.
#
# To run this script cd to the n2n directory and run it as follows
# scripts/mk_SRPMS.sh
#

set -e

function exit_fail()
{
    echo "$1"
    exit 1
}

PACKAGE="n2n"
PKG_VERSION="2.1.0"
PKG_AND_VERSION="${PACKAGE}-${PKG_VERSION}"

TEMPDIR="tmp"

SOURCE_MANIFEST="
README
edge.c
lzoconf.h
lzodefs.h
Makefile
minilzo.c
minilzo.h
n2n.c
n2n.h
n2n_keyfile.c
n2n_keyfile.h
n2n.spec
n2n_transforms.h
n2n_wire.h
sn.c
transform_aes.c
transform_null.c
transform_tf.c
tuntap_linux.c
tuntap_freebsd.c
tuntap_netbsd.c
tuntap_osx.c
twofish.c
twofish.h
version.c
wire.c
edge.8
supernode.1
n2n_v2.7
debian/changelog
debian/compat
debian/control
debian/copyright
debian/n2n-edge.docs
debian/n2n-edge.install
debian/n2n-supernode.install
debian/n2n-edge.manpages
debian/n2n-supernode.manpages
debian/README.Debian
debian/rules
"

BASE=`pwd`

for F in ${SOURCE_MANIFEST}; do
    test -e $F || exit_fail "Cannot find $F. Maybe you're in the wrong directory. Please execute from n2n directory."; >&2
done

echo "Found critical files. Proceeding." >&2

if [ -d ${TEMPDIR} ]; then
    echo "Removing ${TEMPDIR} directory"
    rm -rf ${TEMPDIR} >&2
fi

mkdir ${TEMPDIR} >&2

pushd ${TEMPDIR} >&2

echo "Creating staging directory ${PWD}/${PKG_AND_VERSION}" >&2

if [ -d ${PKG_AND_VERSION} ] ; then
    echo "Removing ${PKG_AND_VERSION} directory"
    rm -rf ${PKG_AND_VERSION} >&2
fi

mkdir ${PKG_AND_VERSION}

pushd ${BASE} >&2

echo "Copying in files" >&2
for F in ${SOURCE_MANIFEST}; do
    cp --parents -a $F ${TEMPDIR}/${PKG_AND_VERSION}/
done

popd >&2

TARFILE="${PKG_AND_VERSION}.tar.gz"
echo "Creating ${TARFILE}" >&2
tar czf ${BASE}/${TARFILE} ${PKG_AND_VERSION}

popd >&2

rm -rf ${TEMPDIR} >&2

echo ${BASE}/${TARFILE}
