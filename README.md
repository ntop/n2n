# Supernode Docker Image (Image based on Debian)

## About the project

This repository is just a project builder (https://github.com/ntop/n2n), any problem should be reported to the source repository unless it is about building it. I have no link with the owners of the code I just set up a constructor, which also makes a supernode container available.

## Running the supernode image

```sh
$ docker run --rm -d -p 5645:5645/udp -p 7654:7654/udp supermock/supernode:[TAGNAME]
```

## Docker registry

- [DockerHub](https://hub.docker.com/r/supermock/supernode/)
- [DockerStore](https://store.docker.com/community/images/supermock/supernode/)

## Documentation

### 1. Build image and binaries

Use `make` command to build the images. Before starting the arm32v7 platform build, you need to run this registry, so you can perform a cross-build. Just follow the documentation: https://github.com/multiarch/qemu-user-static/blob/master/README.md

```sh
$ TARGET_ARCHITECTURE=[arm32v7, x86_64, (nothing to build all architectures)] make
```

### 2. Push it

Use `make push` command to push the image, TARGET_ARCHITECTURE is necessary.

```sh
$ TARGET_ARCHITECTURE=[arm32v7, x86_64] make push
```

### 3. Test it

Once the image is built, it's ready to run:

```sh
$ docker run --rm -d -p 5645:5645/udp -p 7654:7654/udp supermock/supernode:[TAGNAME]
```

## Contributions

Just download the code make your change and send a pull request explaining the purpose if it is a bug or an improvement and etc... After this will be analyzed to be approved. Note: If it is a major change, open a issue explaining what will be done so you do not waste your precious time developing something that will not be used. Make yourself at home!

## License 

MIT