# Build project.
#
# The script assumes that it will be called from inside the project directory.
#
# Usage: .ci\build-project.ps1 [vcpkg-directory [build-directory-name]]
# - vcpkg-directory: Optional full path to Vcpkg directory. Default: $HOME\vcpkg
# - build-directory-name: Optional name of build directory. Default: build.
#                         Can only be set of vcpkg-directory is set as well.
#
# Example 1: .ci\build-project.ps1
# Example 2: .ci\build-project.ps1 $HOME\vcpkg-clang
# Example 3: .ci\build-project.ps1 $HOME\vcpkg-clang build-clang

$ErrorActionPreference="Stop"

$VCPKG_DIR=$args[0]
$BUILD_DIR=$args[1]

if ($null -eq $VCPKG_DIR) { $VCPKG_DIR="$HOME\vcpkg" }
if ($null -eq $BUILD_DIR) { $BUILD_DIR="build" }

# only pass toolchain file to CMake if Vcpkg is installed
if (Test-Path "$VCPKG_DIR" -PathType Container) {
    $TOOLCHAIN="$VCPKG_DIR\scripts\buildsystems\vcpkg.cmake"
} else {
    $TOOLCHAIN="False"
}

Write-Host "---- build-project.ps1 ----"
Write-Host "VCPKG_DIR: $VCPKG_DIR"
Write-Host "BUILD_DIR: $BUILD_DIR"
Write-Host "CMAKE_TOOLCHAIN_FILE: $TOOLCHAIN"
Write-Host "---------------------------"

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    New-Alias -Name cmake -Value "$Env:ProgramFiles\CMake\bin\cmake.exe"
}

New-Item -Name $BUILD_DIR -ItemType Directory
Push-Location $BUILD_DIR
$ErrorActionPreference = "Stop";
cmake -DCMAKE_BUILD_TYPE=Release -DVCPKG_TARGET_TRIPLET=x64-windows -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" ..
cmake --build . --config Release
if ($LASTEXITCODE) { Throw "BUILD FAILED!" }
Pop-Location