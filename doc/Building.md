This document describes the process for compiling n2n in several different
scenarios.

There are some configuration options available during the build process,
which are documented in the [Build time Configuration](BuildConfig.md) page.

Also of use are the steps used for the automated Continuous Integration
process, which can be found in the [Github actions config file](../.github/workflows/tests.yml)

# Git submodules

If you are compiling with the UPnP libraries, it is possible that your
operating system or your build system do not include binaries for the
required libraries.

Using these libraries can cause issues with some build systems, so be
aware that not all combinations are supportable.

To make this scenario simpler, the required source code has been added
to this repository as git `submodules` which require one extra step to
complete their checkout.

So the very first time after cloning the n2n git repo, you should run
this command in the n2n directory to fetch the submodules:

```bash
git submodule update --init --recursive
```

# Build on macOS

In order to use n2n on macOS, you first need to install support for TUN/TAP interfaces:

```bash
brew tap homebrew/cask
brew cask install tuntap
```

If you are on a modern version of macOS (i.e. Catalina), the commands above will ask you to enable the TUN/TAP kernel extension in System Preferences → Security & Privacy → General.

For more information refer to vendor documentation or the [Apple Technical Note](https://developer.apple.com/library/content/technotes/tn2459/_index.html).

Note that on the newest MacOS versions and on Apple Silicon, there may be
increasing security restrictions in the OS that make installing the TUN/TAP
kernel extension difficult.  Alternative software implementations to avoid
these difficulties are being discussed for future n2n versions.

# Build on Windows

The following document some possible windows compile recipes.  Of them, the
MinGW build process is more tested as it is more friendly to open source
development.

## Visual Studio

### Requirements
In order to build with Vidual Studio on Windows the following tools should be installed:

- Visual Studio. For a minimal install, the command line only build tools can be
  downloaded and installed from https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2017.

- CMake (From https://cmake.org/download/)

  NOTE: You should always use the official cmake stable release as otherwise
  you may have issues finding libraries (e.g: the installed OpenSSL library).
  If you still have problems, you can try invoking it with `C:\Program Files\CMake\bin\cmake`.

- (optional) The OpenSSL library.  This optional library can be enabled as
  per the steps in the [Build time Configuration](BuildConfig.md)

  Pre-built OpenSSL binaries can be downloaded from
  https://slproweb.com/products/Win32OpenSSL.html.
  The full version is required, i.e. not the "Light" version. The Win32
  version of it is usually required for a standard build.

### CLI steps

In order to build from the command line, open a terminal window change to
the directory where the git checkout of this repository is and run the
following commands:

Building using `cmake` works as follows:

```batch
cmake -E make_directory build
cd build

rem Append any options to the next line
cmake ..

cmake --build . --config Release
```

The compiled `.exe` files should now be available in the `build\Release` directory.

## MinGW

These steps were tested on a fresh install of Windows 10 Pro with all patches
applied as of 2021-09-29.

- Install Chocolatey (Following instructions on https://chocolatey.org/install)
- from an admin cmd prompt
    - `choco install git mingw make`
- All the remaining commands must be run from inside a bash shell ("C:\Program Files\Git\usr\bin\bash.exe")
    - `git clone $THIS_REPO`
    - `cd n2n`
    - `./scripts/hack_fakeautoconf.sh`
    - `make`
    - `make test`

Due to limitations in the Windows environment, the normal autotools steps have
been emulated by the `hack_fakeautoconf` - This currently results in the
version number reported by the compiled software being inaccurate.

Note: MinGW builds have had a history of incompatibility reports with other OS
builds (for example [#617](https://github.com/ntop/n2n/issues/617) and [#642](https://github.com/ntop/n2n/issues/642))
However, if the tests pass, you should have a high confidence that your build
will be compatible.

## Run on Windows

In order to run n2n on Windows, you will need the following:

- The TAP drivers should be installed into the system. They can be installed from
  http://build.openvpn.net/downloads/releases, search for "tap-windows".

- If OpenSSL has been linked dynamically, the corresponding `.dll` file should be available
  onto the target computer.

The `edge.exe` program reads the `edge.conf` file located into the current directory if no option is provided.

The `supernode.exe` program reads the `supernode.conf` file located into the current directory if no option is provided.

Example [edge.conf](../packages/etc/n2n/edge.conf.sample)
and [supernode.conf](../packages/etc/n2n/supernode.conf.sample) are available.

See `edge.exe --help` and `supernode.exe --help` for a full list of supported options.

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
