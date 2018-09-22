
N2N_VERSION=2.5.0
N2N_OSNAME=$(shell uname -p)

########

CC?=gcc
DEBUG?=-g3
#OPTIMIZATION?=-O2
WARN?=-Wall -Wshadow -Wpointer-arith -Wmissing-declarations -Wnested-externs

#Ultrasparc64 users experiencing SIGBUS should try the following gcc options
#(thanks to Robert Gibbon)
PLATOPTS_SPARC64=-mcpu=ultrasparc -pipe -fomit-frame-pointer -ffast-math -finline-functions -fweb -frename-registers -mapp-regs

N2N_DEFINES=
N2N_OBJS_OPT=
LIBS_EDGE_OPT=

N2N_OPTION_AES?="yes"
#N2N_OPTION_AES=no

ifeq ($(N2N_OPTION_AES), "yes")
    N2N_DEFINES+=-DN2N_HAVE_AES
    LIBS_EDGE_OPT+=-lcrypto
endif

CFLAGS+=$(DEBUG) $(OPTIMIZATION) $(WARN) $(OPTIONS) $(PLATOPTS) $(N2N_DEFINES)

INSTALL=install
MKDIR=mkdir -p
OS := $(shell uname -s)

INSTALL_PROG=$(INSTALL) -m755
INSTALL_DOC=$(INSTALL) -m644

# DESTDIR set in debian make system
PREFIX?=$(DESTDIR)/usr
#BINDIR=$(PREFIX)/bin
ifeq ($(OS),Darwin)
SBINDIR=$(PREFIX)/local/sbin
else
SBINDIR=$(PREFIX)/sbin
endif

MANDIR?=$(PREFIX)/share/man
MAN1DIR=$(MANDIR)/man1
MAN7DIR=$(MANDIR)/man7
MAN8DIR=$(MANDIR)/man8

N2N_LIB=libn2n.a
N2N_OBJS=n2n.o n2n_keyfile.o wire.o minilzo.o twofish.o \
	 edge_utils.o \
         transform_null.o transform_tf.o transform_aes.o \
         tuntap_freebsd.o tuntap_netbsd.o tuntap_linux.o \
	 tuntap_osx.o version.o
LIBS_EDGE+=$(LIBS_EDGE_OPT)
LIBS_SN=

#For OpenSolaris (Solaris too?)
ifeq ($(shell uname), SunOS)
LIBS_EDGE+=-lsocket -lnsl
LIBS_SN+=-lsocket -lnsl
endif

APPS=edge
APPS+=supernode
APPS+=example_edge_embed

DOCS=edge.8.gz supernode.1.gz n2n.7.gz

all: $(APPS) $(DOCS) benchmark

edge: edge.c $(N2N_LIB) n2n_wire.h n2n.h Makefile
	$(CC) $(CFLAGS) edge.c $(N2N_LIB) $(LIBS_EDGE) -o edge

test: test.c $(N2N_LIB) n2n_wire.h n2n.h Makefile
	$(CC) $(CFLAGS) test.c $(N2N_LIB) $(LIBS_EDGE) -o test

supernode: sn.c $(N2N_LIB) n2n.h Makefile
	$(CC) $(CFLAGS) sn.c $(N2N_LIB) $(LIBS_SN) -o supernode

benchmark: benchmark.c $(N2N_LIB) n2n_wire.h n2n.h Makefile
	$(CC) $(CFLAGS) benchmark.c $(N2N_LIB) $(LIBS_SN) -o benchmark

example_edge_embed: example_edge_embed.c $(N2N_LIB) n2n.h
	$(CC) $(CFLAGS) example_edge_embed.c $(N2N_LIB) $(LIBS_EDGE) -o example_edge_embed

.c.o: n2n.h n2n_keyfile.h n2n_transforms.h n2n_wire.h twofish.h Makefile
	$(CC) $(CFLAGS) -c $<

%.gz : %
	gzip -c $< > $@

$(N2N_LIB): $(N2N_OBJS)
	ar rcs $(N2N_LIB) $(N2N_OBJS)
#	$(RANLIB) $@

version.o: Makefile
	$(CC) $(CFLAGS) -DN2N_VERSION='"$(N2N_VERSION)"' -DN2N_OSNAME='"$(N2N_OSNAME)"' -c version.c

clean:
	rm -rf $(N2N_OBJS) $(N2N_LIB) $(APPS) $(DOCS) test *.dSYM *~

install: edge supernode edge.8.gz supernode.1.gz n2n.7.gz
	echo "MANDIR=$(MANDIR)"
	$(MKDIR) $(SBINDIR) $(MAN1DIR) $(MAN7DIR) $(MAN8DIR)
	$(INSTALL_PROG) supernode $(SBINDIR)/
	$(INSTALL_PROG) edge $(SBINDIR)/
	$(INSTALL_DOC) edge.8.gz $(MAN8DIR)/
	$(INSTALL_DOC) supernode.1.gz $(MAN1DIR)/
	$(INSTALL_DOC) n2n.7.gz $(MAN7DIR)/

# Docker builder section
DOCKER_IMAGE_NAME=ntop/supernode
DOCKER_IMAGE_VERSION=$N2N_VERSION
N2N_COMMIT_HASH=21055550f3392235a1b41d71257e9dc9ead0dfa0

default: steps

steps:
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

.PHONY: steps build push
# End Docker builder section
