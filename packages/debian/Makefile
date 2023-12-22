#
# Change it according to your setup
#
# Prerequisite: apt-get install devscripts
#
#
N2N_HOME=$(PWD)/../..
N2N_BUILD=${N2N_HOME}/packages/debian/n2n

include ${N2N_HOME}/config.mak

# TODO: continue to untangle the version generation
# we either should not need to override the config.mak here or
# should never set the version in config.mak and always calculate it
PACKAGE_VERSION := $(shell ${N2N_HOME}/scripts/version.sh)

all: clean pkg

pkg:
	make -C ../../
	if test -e "${N2N_BUILD}"; then /bin/rm -fr ${N2N_BUILD}; fi
	mkdir -p ${N2N_BUILD}/usr/sbin ${N2N_BUILD}/usr/share/man/man1 ${N2N_BUILD}/usr/share/man/man7 ${N2N_BUILD}/usr/share/man/man8
	mkdir -p ${N2N_BUILD}/usr/share/doc/n2n/examples
	install -m755 ../../supernode ${N2N_BUILD}/usr/sbin/
	install -m755 ../../edge ${N2N_BUILD}/usr/sbin/
	install -m644 ../../edge.8.gz ${N2N_BUILD}/usr/share/man/man8/
	install -m644 ../../supernode.1.gz ${N2N_BUILD}/usr/share/man/man1/
	install -m644 ../../n2n.7.gz ${N2N_BUILD}/usr/share/man/man7/
	install -m644 ../../community.list ${N2N_BUILD}/usr/share/doc/n2n/examples/
	install -m644 ../../doc/*.md ${N2N_BUILD}/usr/share/doc/n2n/
	@/bin/rm -f ../n2n*.deb
	DEBEMAIL=builder@example.com dch -v ${PACKAGE_VERSION} --no-auto-nmu Auto Build
	dpkg-buildpackage -rfakeroot -d -us -uc --host-type ${CONFIG_HOST}
	-dpkg-sig --sign builder -k D1EB60BE ../n2n_*deb
	@\rm -f ../n2n_*dsc ../n2n_*.gz ../n2n_*changes
	@/bin/mv ../n2n_*deb .
	@echo
	@echo "Package built."
	@/bin/ls n2n_*deb
	@echo "-------------------------------"
	-dpkg -I n2n_*deb
	-dpkg --contents n2n_*deb
	@echo "-------------------------------"

distclean:
	echo "dummy distclean"

install:
	echo "dummy install"

clean:
	rm -rf *~ *deb
