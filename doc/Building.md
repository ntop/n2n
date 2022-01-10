# n2n on macOS

In order to use n2n on macOS, you first need to install support for TUN/TAP interfaces:

```bash
brew tap homebrew/cask
brew cask install tuntap
```

If you are on a modern version of macOS (i.e. Catalina), the commands above will ask you to enable the TUN/TAP kernel extension in System Preferences → Security & Privacy → General.

For more information refer to vendor documentation or the [Apple Technical Note](https://developer.apple.com/library/content/technotes/tn2459/_index.html).


# Build on Windows (Visual Studio)

## Requirements

In order to build on Windows the following tools should be installed:

- Visual Studio. For a minimal install, the command line only build tools can be
  downloaded and installed from https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2017.

- CMake (From https://cmake.org/download/)

  NOTE: You should always use the official cmake stable release as otherwise
  you may have issues finding libraries (e.g: the installed OpenSSL library).
  If you still have problems, you can try invoking it with `C:\Program Files\CMake\bin\cmake`.

- (optional) The OpenSSL library. Pre-built binaries can be downloaded from
  https://slproweb.com/products/Win32OpenSSL.html.
  The full version is required, i.e. not the "Light" version. The Win32
  version of it is usually required for a standard build.

  NOTE: In order to enable OpenSSL compilation, add the option
  `-DN2N_OPTION_USE_OPENSSL=ON` to the `cmake ..` command below.

  NOTE: To statically link OpenSSL, add the option
  `-DOPENSSL_USE_STATIC_LIBS=true` to the `cmake ..` command below.

NOTE: Sticking to this tool chain has historically meant that resulting
executables are more likely to be able to communicate with Linux or other
OS builds, however efforts are being made to address this concern.

## Build (CLI)

In order to build from the command line, open a terminal window change to
the directory where the git checkout of this repository is and run the
following commands:

The `libnatpmp` and `libminiupnp` have been moved to separated repositories.
So the very first time, you should run this command in the n2n directory to
install them:

```bash
git submodule update --init --recursive
```

Building using `cmake` works as follows:

```batch
cmake -E make_directory build
cd build

rem Append any options to the next line
cmake ..

cmake --build . --config Release
```

The compiled `.exe` files should now be available in the `build\Release` directory.

## Run

In order to run n2n, you will need the following:

- The TAP drivers should be installed into the system. They can be installed from
  http://build.openvpn.net/downloads/releases, search for "tap-windows".

- If OpenSSL has been linked dynamically, the corresponding `.dll` file should be available
  onto the target computer.

The `edge.exe` program reads the `edge.conf` file located into the current directory if no option is provided.

The `supernode.exe` program reads the `supernode.conf` file located into the current directory if no option is provided.

Example [edge.conf](../packages/etc/n2n/edge.conf.sample)
and [supernode.conf](../packages/etc/n2n/supernode.conf.sample) are available.

See `edge.exe --help` and `supernode.exe --help` for a full list of supported options.

# Build on Windows (MinGW)

These steps were tested on a fresh install of Windows 10 Pro with all patches
applied as of 2021-09-29.

- Install Chocolatey (Following instructions on https://chocolatey.org/install)
- from an admin cmd prompt
    - choco install git mingw make
- All the remaining commands must be run from inside a bash shell ("C:\Program Files\Git\usr\bin\bash.exe")
    - git clone $THIS_REPO
    - cd n2n
    - ./scripts/hack_fakeautoconf.sh
    - make
    - make test

Due to the hack used to replace autotools on windows, any build created this
way will currently have inaccurate build version numbers.

Note: MinGW builds have a history of incompatibility reports with other OS
builds, please see [#617](https://github.com/ntop/n2n/issues/617) and [#642](https://github.com/ntop/n2n/issues/642).
However, if the tests pass, you should have a high confidence that your build
will be compatible.

# General Building Options

[Build time Configuration](BuildConfig.md)

# Cross compiling on Linux

## Using the Makefiles and Autoconf

The Makefiles are all setup to allow cross compiling of this code.  You
will need to have the cross compiler, binutils and any additional libraries
desired installed for the target architecture.  Then you can run the `./configure`
with the appropriate CC and AR environment and the right `--host` option.

If compiling on Debian or Ubuntu, this can be as simple as the following example:

```
HOST_TRIPLET=arm-linux-gnueabi
sudo apt-get install binutils-$HOST_TRIPLET gcc-$HOST_TRIPLET
./autogen.sh
export CC=$HOST_TRIPLET-gcc
export AR=$HOST_TRIPLET-ar
./configure --host $HOST_TRIPLET
make
```

A good starting point to determine the host triplet for your destination platform
can be found by copying the `./config.guess` script to it and running it on the
destination.

This is not a good way to produce binaries for embedded environments (like OpenWRT)
as they will often use a different libc environment.

# N2N Packages

There are also some example package build recipes included with the source.

- [Debian](../packages/debian/README)
- [RPM](../packages/rpm)
- [OpenWRT](../packages/openwrt/README.md)
