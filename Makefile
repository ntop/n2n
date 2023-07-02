# Our default make target
all:

export CC
export AR
export EXE
export CFLAGS
export LDFLAGS
export LDLIBS
export CONFIG_HOST_OS

-include config.mak

ifndef CONFIG_HOST
# TODO:
# dont error if we are installing build-deps or other non-compile action
$(error Please run ./configure)
endif

CFLAGS+=-I./include
LDFLAGS+=-L.

#Ultrasparc64 users experiencing SIGBUS should try the following gcc options
#(thanks to Robert Gibbon)
PLATOPTS_SPARC64=-mcpu=ultrasparc -pipe -fomit-frame-pointer -ffast-math -finline-functions -fweb -frename-registers -mapp-regs

OPENSSL_CFLAGS=$(shell pkg-config openssl; echo $$?)
ifeq ($(OPENSSL_CFLAGS), 0)
  CFLAGS+=$(shell pkg-config --cflags-only-I openssl)
endif

WARN=-Wall
CFLAGS+=$(DEBUG) $(OPTIMIZATION) $(WARN) $(OPTIONS) $(PLATOPTS)

# Quick sanity check on our build environment
UNAME_S := $(shell uname -s)
ifndef UNAME_S
# This could happen if the Makefile is unable to run "uname", which can
# happen if the shell has a bad path (or is the wrong shell)
$(error Could not run uname command, cannot continue)
endif

export MKDIR
export INSTALL
export INSTALL_PROG
export INSTALL_DOC
export SBINDIR

MKDIR=mkdir -p
INSTALL=install
INSTALL_PROG=$(INSTALL) -m755
INSTALL_DOC=$(INSTALL) -m644

# DESTDIR set in debian make system
PREFIX?=$(DESTDIR)/$(CONFIG_PREFIX)

SBINDIR=$(PREFIX)/sbin
MANDIR?=$(PREFIX)/share/man
MAN1DIR=$(MANDIR)/man1
MAN7DIR=$(MANDIR)/man7
MAN8DIR=$(MANDIR)/man8

N2N_LIB=libn2n.a
N2N_OBJS=\
	src/aes.o \
	src/auth.o \
	src/cc20.o \
	src/curve25519.o \
	src/edge_management.o \
	src/edge_utils.o \
	src/edge_utils_win32.o \
	src/header_encryption.o \
	src/hexdump.o \
	src/json.o \
	src/management.o \
	src/minilzo.o \
	src/n2n.o \
	src/n2n_port_mapping.o \
	src/n2n_regex.o \
	src/network_traffic_filter.o \
	src/pearson.o \
	src/random_numbers.o \
	src/sn_management.o \
	src/sn_selection.o \
	src/sn_utils.o \
	src/speck.o \
	src/tf.o \
	src/transform_aes.o \
	src/transform_cc20.o \
	src/transform_lzo.o \
	src/transform_null.o \
	src/transform_speck.o \
	src/transform_tf.o \
	src/transform_zstd.o \
	src/tuntap_freebsd.o \
	src/tuntap_linux.o \
	src/tuntap_netbsd.o \
	src/tuntap_osx.o \
	src/wire.o \

N2N_DEPS=$(wildcard include/*.h) $(wildcard src/*.c) config.mak

# As source files pass the linter, they can be added here (If all the source
# is passing the linter tests, this can be refactored)
LINT_CCODE=\
	include/curve25519.h \
	include/edge_utils_win32.h \
	include/header_encryption.h \
	include/hexdump.h \
	include/n2n_define.h \
	include/n2n_wire.h \
	include/network_traffic_filter.h \
	include/pearson.h \
	include/random_numbers.h \
	include/sn_selection.h \
	include/speck.h \
	include/tf.h \
	src/edge_management.c \
	src/edge_utils_win32.c \
	src/example_edge_embed_quick_edge_init.c \
	src/header_encryption.c \
	src/management.c \
	src/management.h \
	src/sn_management.c \
	src/sn_selection.c \
	src/strbuf.h \
	src/transform_cc20.c \
	src/transform_null.c \
	src/tuntap_freebsd.c \
	src/tuntap_linux.c \
	src/tuntap_netbsd.c \
	src/tuntap_osx.c \
	src/wire.c \
	tools/tests-auth.c \
	tools/tests-compress.c \
	tools/tests-elliptic.c \
	tools/tests-hashing.c \
	tools/tests-transform.c \
	tools/tests-wire.c \

LDLIBS+=-ln2n
ifneq (,$(findstring mingw,$(CONFIG_HOST_OS)))
LDLIBS+=$(abspath win32/n2n_win32.a)
endif
LDLIBS+=$(LDLIBS_EXTRA)

ifneq (,$(findstring mingw,$(CONFIG_HOST_OS)))
N2N_DEPS+=win32/n2n_win32.a
SUBDIRS+=win32
endif

APPS=edge$(EXE)
APPS+=supernode$(EXE)
APPS+=example_edge_embed_quick_edge_init$(EXE)
APPS+=example_edge_embed$(EXE)
APPS+=example_sn_embed$(EXE)

DOCS=edge.8.gz supernode.1.gz n2n.7.gz

# This is the list of Debian/Ubuntu packages that are needed during the build.
# Mostly of use in automated build systems.
BUILD_DEP:=\
	autoconf \
	build-essential \
	flake8 \
	gcovr \
	libcap-dev \
	libzstd-dev \
	shellcheck \
	uncrustify \
	yamllint \

SUBDIRS+=tools

COVERAGEDIR?=coverage

.PHONY: $(SUBDIRS)

.PHONY: all
all: version $(APPS) $(DOCS) $(SUBDIRS)

# This allows breaking the build if the version.sh script discovers
# any inconsistancies
.PHONY: version
version:
	@echo -n "Build for version: "
	@scripts/version.sh

tools: $(N2N_LIB)
	$(MAKE) -C $@

win32:
	$(MAKE) -C $@

win32/edge_rc.o: win32/edge.rc win32/edge.manifest
	$(WINDRES) win32/edge.rc -O coff -o win32/edge_rc.o

src/edge.o: $(N2N_DEPS)
src/supernode.o: $(N2N_DEPS)
src/example_edge_embed_quick_edge_init.o: $(N2N_DEPS)
src/example_sn_embed.o: $(N2N_DEPS)
src/example_edge_embed.o: $(N2N_DEPS)

src/edge: $(N2N_LIB)
src/supernode: $(N2N_LIB)
src/example_edge_embed_quick_edge_init: $(N2N_LIB)
src/example_sn_embed: $(N2N_LIB)
src/example_edge_embed: $(N2N_LIB)

ifneq (,$(findstring mingw,$(CONFIG_HOST_OS)))
src/edge: win32/edge_rc.o
src/edge.exe: src/edge
src/supernode.exe: src/supernode
src/example_edge_embed_quick_edge_init.exe: src/example_edge_embed_quick_edge_init
src/example_sn_embed.exe: src/example_sn_embed
src/example_edge_embed.exe: src/example_edge_embed
endif

%: src/%
	cp $< $@

%.gz : %
	gzip -n -c $< > $@

$(N2N_LIB): $(N2N_OBJS)
	$(AR) rcs $(N2N_LIB) $(N2N_OBJS)
#	$(RANLIB) $@

win32/n2n_win32.a: win32

.PHONY: test test.units test.integration
test: test.units test.integration

test.units: tools
	scripts/test_harness.sh tests/tests_units.list

test.integration: $(APPS)
	scripts/test_harness.sh tests/tests_integration.list

.PHONY: lint lint.python lint.ccode lint.shell lint.yaml
lint: lint.python lint.ccode lint.shell lint.yaml

lint.python:
	flake8 scripts/n2n-ctl scripts/n2n-httpd

lint.ccode:
	scripts/indent.sh $(LINT_CCODE)

lint.shell:
	shellcheck scripts/*.sh

lint.yaml:
	yamllint .

# To generate coverage information, run configure with
# CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="--coverage"
# and run the desired tests.  Ensure that package gcovr is installed
# and then run "make cover"
.PHONY: cover
cover:
	mkdir -p $(COVERAGEDIR)
	gcovr -s --html --html-details --output=$(COVERAGEDIR)/index.html

# Use coverage data to generate gcov text report files.
# Unfortunately, these end up in the wrong directory due to the
# makefile layout
# The steps to use this are similar to the "make cover" above
.PHONY: gcov
gcov:
	gcov $(N2N_OBJS)
	$(MAKE) -C tools gcov

# This is a convinent target to use during development or from a CI/CD system
.PHONY: build-dep

ifneq (,$(findstring darwin,$(CONFIG_HOST_OS)))
build-dep: build-dep-brew
else
build-dep: build-dep-dpkg
endif

.PHONY: build-dep-dpkg
build-dep-dpkg:
	sudo apt install $(BUILD_DEP)

.PHONY: build-dep-brew
build-dep-brew:
	brew install automake gcovr

.PHONY: clean
clean:
	rm -f src/edge.o src/supernode.o src/example_edge_embed.o src/example_edge_embed_quick_edge_init.o src/example_sn_embed.o
	rm -rf $(N2N_OBJS) $(N2N_LIB) $(APPS) $(DOCS) $(COVERAGEDIR)/ *.dSYM *~
	rm -f tests/*.out src/*.gcno src/*.gcda
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean; done

.PHONY: distclean
distclean:
	rm -f tests/*.out src/*.gcno src/*.gcda src/*.indent src/*.unc-backup*
	rm -rf autom4te.cache/
	rm -f config.log config.status configure include/config.h include/config.h.in
	rm -f doc/edge.8.gz doc/n2n.7.gz doc/supernode.1.gz
	rm -f packages/debian/config.log packages/debian/config.status
	rm -rf packages/debian/autom4te.cache/
	rm -f packages/rpm/config.log packages/rpm/config.status
	rm -f $(addprefix src/,$(APPS))

.PHONY: install
install: edge$(EXE) supernode$(EXE) edge.8.gz supernode.1.gz n2n.7.gz
	echo "MANDIR=$(MANDIR)"
	$(MKDIR) $(SBINDIR) $(MAN1DIR) $(MAN7DIR) $(MAN8DIR)
	$(INSTALL_PROG) supernode$(EXE) $(SBINDIR)/
	$(INSTALL_PROG) edge$(EXE) $(SBINDIR)/
	$(INSTALL_DOC) edge.8.gz $(MAN8DIR)/
	$(INSTALL_DOC) supernode.1.gz $(MAN1DIR)/
	$(INSTALL_DOC) n2n.7.gz $(MAN7DIR)/
	$(MAKE) -C tools install SBINDIR=$(abspath $(SBINDIR))

# Docker builder section
DOCKER_IMAGE_NAME=ntop/supernode
DOCKER_IMAGE_VERSION=$N2N_VERSION_SHORT
N2N_COMMIT_HASH=$(shell scripts/version.sh hash)

.PHONY: default steps build push
default: steps

steps:
	$(info This code appears to have been bitrotted since 2019 - please let us know if you are using it)
	if [ "$(TARGET_ARCHITECTURE)" = "arm32v7" ] || [ "$(TARGET_ARCHITECTURE)" = "" ]; then DOCKER_IMAGE_FILENAME="Dockerfile.arm32v7" DOCKER_IMAGE_TAGNAME=$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_VERSION)-arm32v7 make build; fi
	if [ "$(TARGET_ARCHITECTURE)" = "x86_64" ] || [ "$(TARGET_ARCHITECTURE)" = "" ]; then DOCKER_IMAGE_FILENAME="Dockerfile.x86_64" DOCKER_IMAGE_TAGNAME=$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_VERSION)-x86_64 make build; fi

build:
	$(eval OS := $(shell uname -s))
	$(eval ARCHITECTURE := $(shell export DOCKER_IMAGE_TAGNAME="$(DOCKER_IMAGE_TAGNAME)"; echo $$DOCKER_IMAGE_TAGNAME | grep -oe -.*))

	docker build --target builder --build-arg COMMIT_HASH=$(N2N_COMMIT_HASH) -t $(DOCKER_IMAGE_TAGNAME) -f image-platforms/$(DOCKER_IMAGE_FILENAME) .

	docker container create --name builder $(DOCKER_IMAGE_TAGNAME)
	if [ ! -d "./build" ]; then mkdir ./build; fi
	docker container cp builder:/usr/src/n2n/supernode ./build/supernode-$(OS)$(ARCHITECTURE)
	docker container cp builder:/usr/src/n2n/edge ./build/edge-$(OS)$(ARCHITECTURE)
	docker container rm -f builder

	docker build --build-arg COMMIT_HASH=$(N2N_COMMIT_HASH) -t $(DOCKER_IMAGE_TAGNAME) -f image-platforms/$(DOCKER_IMAGE_FILENAME) .
	docker tag $(DOCKER_IMAGE_TAGNAME) $(DOCKER_IMAGE_NAME):latest$(ARCHITECTURE)

push:
	if [ ! "$(TARGET_ARCHITECTURE)" = "" ]; then \
		docker push $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_VERSION)-$(TARGET_ARCHITECTURE); \
		docker push $(DOCKER_IMAGE_NAME):latest-$(TARGET_ARCHITECTURE); \
	else \
		echo "Please pass TARGET_ARCHITECTURE, see README.md."; \
	fi

# End Docker builder section
