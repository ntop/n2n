DOCKER_IMAGE_NAME=supermock/supernode
DOCKER_IMAGE_VERSION=v2
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
.SILENT: