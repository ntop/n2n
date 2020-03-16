# Build on Windows

## Requirements

In order to build on Windows the following tools should be installed:

- Visual Studio. For a minimal install, the command line only build tools can be
  downloaded and installed from https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2017
- Cmake
- (optional) The OpenSSL library. Prebuild binaries can be downloaded from https://slproweb.com/products/Win32OpenSSL.html .
  The full version is required (not the "Light" version). The Win32 version of it is usually required for a standard build.

  NOTE: in order to skip OpenSSL compilation, edit CMakeLists.txt and replace

  ```plaintext
  OPTION(N2N_OPTION_AES "USE AES" ON)
  with
  OPTION(N2N_OPTION_AES "USE AES" OFF)
  ```

  NOTE: to static link OpenSSL, add the `-DOPENSSL_USE_STATIC_LIBS=true` option to the cmake command

In order to run n2n:

- The TAP drivers should be installed into the system. They can be installed from
  http://build.openvpn.net/downloads/releases (search for "tap-windows")
- If OpenSSL has been linked dynamically, the corresponding .dll file should be available
  into the target computer

## Build (CLI)

In order to build from the command line, open a terminal window and run the following commands:

```batch
md build
cd build
cmake ..

MSBuild edge.vcxproj /t:Build /p:Configuration=Release
MSBuild supernode.vcxproj /t:Build /p:Configuration=Release
```

NOTE: if cmake has problems finding the installed OpenSSL library, try to download the official cmake and invoke it with:
`C:\Program Files\CMake\bin\cmake`

The compiled exe files should now be available under the Release directory.

## Run

The `edge.exe` program reads the `edge.conf` file located into the current directory if no option is provided.

Here is an example `edge.conf` file:

```plaintext
-c=mycommunity
-k=mysecretkey

# supernode IP address
-l=1.2.3.4:5678

# edge IP address
-a=192.168.100.1
```

The `supernode.exe` program reads the `supernode.conf` file located into the current directory if no option is provided.

Here is an example `supernode.conf` file:

```plaintext
-l=5678
```

See `edge.exe --help` and `supernode.exe --help` for a list of supported options.
